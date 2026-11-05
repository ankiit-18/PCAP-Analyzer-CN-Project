"""Capture validation and whole-capture statistics (always full-file, independent of the extraction limit)."""
from __future__ import annotations

import os
import re

import pandas as pd

from .config import Limits
from .errors import CaptureTooLarge, InvalidCapture
from .tshark import Tshark

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "pcap", b"\xa1\xb2\xc3\xd4": "pcap", b"\x4d\x3c\xb2\xa1": "pcap", b"\xa1\xb2\x3c\x4d": "pcap",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}


def validate_capture(path: str, limits: Limits | None = None) -> str:
    """'pcap' or 'pcapng'. Raises InvalidCapture / CaptureTooLarge with a user-facing message."""
    limits = limits or Limits()
    if not os.path.isfile(path):
        raise InvalidCapture(f"File not found: {os.path.basename(path)}")
    size = os.path.getsize(path)
    if size < 24:
        raise InvalidCapture("The file is empty or too small to be a valid capture (a pcap header alone is 24 bytes).")
    if limits.max_pcap_size_mb and size > limits.max_pcap_bytes:
        raise CaptureTooLarge(f"The capture is {size / 1048576:.1f} MB, above the {limits.max_pcap_size_mb} MB limit (MAX_PCAP_SIZE_MB).")
    with open(path, "rb") as f:
        kind = PCAP_MAGICS.get(f.read(4))
    if kind is None:
        raise InvalidCapture("Unsupported file: not a PCAP/PCAPNG capture. Export from Wireshark as .pcap or .pcapng "
                             "(compressed .gz/.zip files must be extracted first).")
    return kind


# ---- tshark -z statistics ------------------------------------------------------------------------------------
_TOK = re.compile(r"(\d[\d,]*(?:\.\d+)?)(?:\s+(bytes|kB|MB|GB|TB)\b)?")
_UNIT = {"bytes": 1, "kB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}


def _n(s):
    try:
        return float(str(s).replace(",", ""))
    except ValueError:
        return None


def _b(tok):
    return _n(tok[0]) * _UNIT.get(tok[1] or "bytes", 1)


def totals(ts: Tshark, path: str) -> dict:
    """tshark -z io,stat,0 : frames, bytes, duration for the WHOLE capture."""
    out = ts.stat(path, "io,stat,0")
    dur = re.search(r"Duration:\s*([\d.]+)", out)
    row = re.search(r"\|\s*[\d.]+\s*<>\s*[\d.]+\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", out)
    return {"packets": int(row.group(1)) if row else None, "bytes": int(row.group(2)) if row else None,
            "duration_s": float(dur.group(1)) if dur else None, "raw": out}


def hierarchy(ts: Tshark, path: str) -> tuple[pd.DataFrame, str]:
    raw = ts.stat(path, "io,phs")
    rows = []
    for line in raw.splitlines():
        m = re.match(r"^(\s*)(\S+)\s+frames:(\d+)\s+bytes:(\d+)", line)
        if m:
            rows.append({"depth": len(m.group(1)) // 2, "protocol": m.group(2), "frames": int(m.group(3)), "bytes": int(m.group(4))})
    df = pd.DataFrame(rows, columns=["depth", "protocol", "frames", "bytes"])
    if len(df):
        df["pct_frames"] = (100 * df["frames"] / df["frames"].max()).round(2)
        df["tree"] = ["    " * d + p for d, p in zip(df["depth"], df["protocol"])]
    return df, raw


def endpoints(ts: Tshark, path: str, kind: str = "ip") -> pd.DataFrame:
    """tshark -z endpoints,<ip|ipv6|tcp|udp>"""
    raw = ts.stat(path, f"endpoints,{kind}")
    rows = []
    for line in raw.splitlines():
        s = line.strip()
        m = re.match(r"^(\S+)\s+(\d[\d,]*.*)$", s)
        if not m or s.startswith(("Address", "Filter", "=", "|")):
            continue
        t = _TOK.findall(m.group(2))
        if len(t) >= 6:
            rows.append({"endpoint": m.group(1), "packets": int(_n(t[0][0])), "bytes": _b(t[1]), "tx_packets": int(_n(t[2][0])),
                         "tx_bytes": _b(t[3]), "rx_packets": int(_n(t[4][0])), "rx_bytes": _b(t[5])})
    return pd.DataFrame(rows, columns=["endpoint", "packets", "bytes", "tx_packets", "tx_bytes", "rx_packets", "rx_bytes"])


def conversations(ts: Tshark, path: str, kind: str = "ip") -> pd.DataFrame:
    """tshark -z conv,<ip|ipv6|tcp|udp>"""
    raw = ts.stat(path, f"conv,{kind}")
    rows = []
    for line in raw.splitlines():
        if "<->" not in line:
            continue
        left, right = line.split("<->", 1)
        parts = right.strip().split(None, 1)
        if len(parts) < 2:
            continue
        t = _TOK.findall(parts[1])
        if len(t) < 8:
            continue
        rows.append({"a": left.strip(), "b": parts[0], "frames_b_to_a": int(_n(t[0][0])), "bytes_b_to_a": _b(t[1]),
                     "frames_a_to_b": int(_n(t[2][0])), "bytes_a_to_b": _b(t[3]), "frames": int(_n(t[4][0])), "bytes": _b(t[5]),
                     "start_s": _n(t[6][0]), "duration_s": _n(t[7][0])})
    return pd.DataFrame(rows, columns=["a", "b", "frames_b_to_a", "bytes_b_to_a", "frames_a_to_b", "bytes_a_to_b", "frames", "bytes", "start_s", "duration_s"])


def rtp_streams(ts: Tshark, path: str, heuristic: bool = False) -> pd.DataFrame:
    raw = ts.stat(path, "rtp,streams", ["-o", "rtp.heuristic_rtp:TRUE"] if heuristic else None)
    rows = []
    pat = re.compile(r"^\s*([\d.]+)\s+([\d.]+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(0x[0-9A-Fa-f]+)\s+(\S+)\s+(\d+)\s+(-?\d+)\s*(?:\(([-\d.]+)%\))?\s+"
                     r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*(X)?")
    for line in raw.splitlines():
        m = pat.match(line)
        if m:
            g = m.groups()
            rows.append({"start_s": float(g[0]), "end_s": float(g[1]), "src": g[2], "sport": int(g[3]), "dst": g[4], "dport": int(g[5]), "ssrc": g[6],
                         "payload": g[7], "packets": int(g[8]), "lost": int(g[9]), "lost_pct": float(g[10]) if g[10] else 0.0,
                         "min_delta_ms": float(g[11]), "mean_delta_ms": float(g[12]), "max_delta_ms": float(g[13]),
                         "min_jitter_ms": float(g[14]), "mean_jitter_ms": float(g[15]), "max_jitter_ms": float(g[16]), "problems": bool(g[17])})
    return pd.DataFrame(rows)
