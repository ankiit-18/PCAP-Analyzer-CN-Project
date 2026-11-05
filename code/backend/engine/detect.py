"""Which protocols are present? Identification uses tshark's dissector chain (frame.protocols); it never guesses from port numbers."""
from __future__ import annotations

import re

import pandas as pd

from . import capture
from .base import BASE_PROTOS
from .context import Context

HANDLED = {"tcp": {"tcp"}, "udp": {"udp"}, "dns": {"dns"}, "http": {"http"}, "tls": {"tls", "ssl"}, "icmp": {"icmp", "icmpv6"}, "dhcp": {"dhcp", "bootp"}, "rtp": {"rtp"}}
LABELS = {"tcp": "TCP", "udp": "UDP", "dns": "DNS", "http": "HTTP", "tls": "TLS", "icmp": "ICMP / ICMPv6", "dhcp": "DHCP", "rtp": "RTP"}
ORDER = ["tcp", "udp", "dns", "http", "tls", "icmp", "dhcp", "rtp"]
_IGNORE = set(BASE_PROTOS) | {"media", "json", "xml", "image-gif", "image-jfif", "image-png", "data-text-lines", "text", "mime_multipart", "urlencoded-form", "tcp.segments"}


# Protocols that get a dedicated detail page. Every other protocol is still counted and charted on the overview (packets, bytes, share) but has no page.
DETAIL_PAGES = {"tcp", "udp", "dns", "tls", "x:quic", "x:arp"}

# Helper / sub-dissectors that are parts of other protocols (certificate fields, STUN probes, ...): they still appear in the overview's protocol
# distribution (tshark -z io,phs) but get no card or analysis page.
NOISE_PREFIXES = ("x509", "pkix", "pkcs", "cms", "ocsp", "ber", "der", "asn1", "stun")


def _is_noise(token: str) -> bool:
    return token.lower().startswith(NOISE_PREFIXES)


def _has(chain: pd.Series, tokens) -> pd.Series:
    return chain.str.contains(r"(?:^|:)(?:" + "|".join(re.escape(t) for t in tokens) + r")(?::|$)", regex=True)


def detect(ctx: Context) -> list[dict]:
    df = ctx.packets
    out = []
    for key in ORDER:
        # TCP/UDP: real segments/datagrams only (ICMP errors that embed a TCP/UDP header do not count)
        mask = df["is_tcp"] if key == "tcp" else df["is_udp"] if key == "udp" else _has(df["protocols"], HANDLED[key])
        if mask.any():
            out.append({"key": key, "label": LABELS[key], "packets": int(mask.sum()), "bytes": int(df.loc[mask, "length"].sum()), "heuristic": False})
    # RTP on bare UDP is only visible to Wireshark's heuristic dissector - checked once, only when UDP exists and no RTP was dissected
    if not any(d["key"] == "rtp" for d in out) and any(d["key"] == "udp" for d in out):
        try:
            s = capture.rtp_streams(ctx.ts, ctx.path, True)
            if len(s):
                ctx.heuristic_rtp = True
                out.append({"key": "rtp", "label": "RTP", "packets": int(s["packets"].sum()), "bytes": 0, "heuristic": True})
        except Exception:
            pass
    tokens = {}
    for chain in df["protocols"].drop_duplicates():
        for t in chain.split(":"):
            if t and t not in _IGNORE and not _is_noise(t) and not any(t in v for v in HANDLED.values()):
                tokens[t] = True
    for t in tokens:
        mask = _has(df["protocols"], [t])
        out.append({"key": f"x:{t}", "label": t.upper(), "packets": int(mask.sum()), "bytes": int(df.loc[mask, "length"].sum()), "heuristic": False, "other": True})
    total = max(len(df), 1)
    for d in out:
        d["pct_packets"] = round(100 * d["packets"] / total, 2)
        d["detail"] = d["key"] in DETAIL_PAGES
    return sorted(out, key=lambda d: (d.get("other", False), ORDER.index(d["key"]) if d["key"] in ORDER else 99, -d["packets"]))
