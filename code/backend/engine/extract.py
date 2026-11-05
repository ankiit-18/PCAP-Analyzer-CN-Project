"""Detailed per-packet extraction (one tshark -T fields pass) into a compact, typed DataFrame.

All TCP analysis flags come from Wireshark (`tcp.analysis.*`); TCP/IP header fields are dissected by tshark.
The pass is chunked (typed per chunk) and capped by MAX_EXTRACTED_PACKETS - see `Extraction.partial`.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from .tshark import Tshark
from .util import first, numeric, truthy

# Wireshark TCP-analysis flags used as "indicators" (names are stable API: frontend + JSON use them)
ANALYSIS = {
    "retransmission": "tcp.analysis.retransmission", "fast_retransmission": "tcp.analysis.fast_retransmission",
    "spurious_retransmission": "tcp.analysis.spurious_retransmission", "out_of_order": "tcp.analysis.out_of_order",
    "duplicate_ack": "tcp.analysis.duplicate_ack", "lost_segment": "tcp.analysis.lost_segment",
    "ack_lost_segment": "tcp.analysis.ack_lost_segment",
}
# further Wireshark TCP-analysis flags (flow control / keep-alive) - boolean columns only, not "indicator" tags
WINDOW_FLAGS = {
    "zero_window": "tcp.analysis.zero_window", "zero_window_probe": "tcp.analysis.zero_window_probe",
    "zero_window_probe_ack": "tcp.analysis.zero_window_probe_ack", "window_update": "tcp.analysis.window_update",
    "window_full": "tcp.analysis.window_full", "keep_alive": "tcp.analysis.keep_alive",
}

FIELDS = [
    ("no", "frame.number"), ("time", "frame.time_epoch"), ("rel_time", "frame.time_relative"), ("length", "frame.len"),
    ("protocols", "frame.protocols"),
    # IP layer
    ("ip_src", "ip.src"), ("ip_dst", "ip.dst"), ("ip6_src", "ipv6.src"), ("ip6_dst", "ipv6.dst"),
    ("ttl", "ip.ttl"), ("hlim", "ipv6.hlim"), ("ip_proto", "ip.proto"), ("ip6_nxt", "ipv6.nxt"), ("ip_hdr_len", "ip.hdr_len"), ("ip_len", "ip.len"),
    ("ip_id", "ip.id"), ("ip_flags", "ip.flags"), ("mf", "ip.flags.mf"), ("frag_off", "ip.frag_offset"), ("dscp", "ip.dsfield.dscp"),
    ("ecn", "ip.dsfield.ecn"), ("ip_csum", "ip.checksum.status"), ("ip6_plen", "ipv6.plen"), ("ip6_tclass", "ipv6.tclass"), ("ip6_flow", "ipv6.flow"),
    # transport
    ("tcp_sport", "tcp.srcport"), ("tcp_dport", "tcp.dstport"), ("tcp_stream", "tcp.stream"),
    ("udp_sport", "udp.srcport"), ("udp_dport", "udp.dstport"), ("udp_stream", "udp.stream"), ("udp_len", "udp.length"), ("udp_csum", "udp.checksum.status"),
    # TCP header
    ("syn", "tcp.flags.syn"), ("ack_flag", "tcp.flags.ack"), ("fin", "tcp.flags.fin"), ("rst", "tcp.flags.reset"), ("psh", "tcp.flags.push"),
    ("urg", "tcp.flags.urg"), ("ece", "tcp.flags.ece"), ("cwr", "tcp.flags.cwr"),
    ("seq", "tcp.seq"), ("ack", "tcp.ack"), ("tcp_len", "tcp.len"), ("win", "tcp.window_size"), ("win_raw", "tcp.window_size_value"),
    ("win_scalefactor", "tcp.window_size_scalefactor"),
    # TCP options
    ("mss", "tcp.options.mss_val"), ("wscale", "tcp.options.wscale.shift"), ("sack_perm", "tcp.options.sack_perm"),
    ("sack_le", "tcp.options.sack_le"), ("sack_re", "tcp.options.sack_re"), ("tsval", "tcp.options.timestamp.tsval"), ("tsecr", "tcp.options.timestamp.tsecr"),
    # Wireshark TCP analysis
    *[(k, v) for k, v in ANALYSIS.items()], *[(k, v) for k, v in WINDOW_FLAGS.items()],
    ("duplicate_ack_num", "tcp.analysis.duplicate_ack_num"), ("acks_frame", "tcp.analysis.acks_frame"), ("ack_rtt", "tcp.analysis.ack_rtt"),
    ("initial_rtt", "tcp.analysis.initial_rtt"), ("bytes_in_flight", "tcp.analysis.bytes_in_flight"),
    ("exp_msg", "_ws.expert.message"),
]

_BOOLS = ["syn", "ack_flag", "fin", "rst", "psh", "urg", "ece", "cwr", "mf", *ANALYSIS, *WINDOW_FLAGS]
_NUMS = ["seq", "ack", "tcp_len", "win", "win_raw", "win_scalefactor", "mss", "wscale", "tsval", "tsecr", "duplicate_ack_num", "acks_frame", "ack_rtt",
         "initial_rtt", "bytes_in_flight", "ttl", "hlim", "ip_proto", "ip6_nxt", "ip_hdr_len", "ip_len", "frag_off", "dscp", "ecn", "ip_csum", "ip6_plen",
         "udp_len", "udp_csum"]
_HEX = ["ip_id", "ip_flags", "ip6_tclass", "ip6_flow"]
_TCP_FLAG_NAMES = [("syn", "SYN"), ("fin", "FIN"), ("rst", "RST"), ("psh", "PSH"), ("urg", "URG"), ("ece", "ECE"), ("cwr", "CWR"), ("ack_flag", "ACK")]


def _hex_num(s: pd.Series) -> pd.Series:
    v = first(s)
    out = pd.to_numeric(v, errors="coerce")
    m = out.isna() & v.str.startswith("0x")
    if m.any():
        out[m] = v[m].map(lambda x: int(x, 16))
    return out


def convert(ch: pd.DataFrame) -> pd.DataFrame:
    """Raw string chunk -> typed chunk (keeps memory small)."""
    d = pd.DataFrame(index=ch.index)
    d["no"] = pd.to_numeric(ch["no"], errors="coerce").fillna(0).astype("int64")
    d["length"] = pd.to_numeric(ch["length"], errors="coerce").fillna(0).astype("int32")
    d["time"] = pd.to_numeric(ch["time"], errors="coerce")
    d["rel_time"] = pd.to_numeric(ch["rel_time"], errors="coerce")
    d["protocols"] = first(ch["protocols"])
    ip4, ip6 = first(ch["ip_src"]), first(ch["ip6_src"])
    d["src"] = ip4.where(ip4 != "", ip6)
    d["dst"] = first(ch["ip_dst"]).where(ip4 != "", first(ch["ip6_dst"]))
    # ICMP errors embed the offending packet's TCP/UDP header (and get a stream index too) - those are not TCP segments / UDP datagrams
    embedded = d["protocols"].str.contains(r"(?:^|:)icmp(?:v6)?(?::|$)", regex=True)
    d["is_tcp"] = (first(ch["tcp_stream"]) != "") & ~embedded
    d["is_udp"] = (first(ch["udp_stream"]) != "") & ~embedded
    sp = first(ch["tcp_sport"]).where(d["is_tcp"], first(ch["udp_sport"]))
    dp = first(ch["tcp_dport"]).where(d["is_tcp"], first(ch["udp_dport"]))
    d["sport"] = pd.to_numeric(sp, errors="coerce").fillna(0).astype("int32")
    d["dport"] = pd.to_numeric(dp, errors="coerce").fillna(0).astype("int32")
    d["tcp_stream"] = numeric(ch["tcp_stream"])
    d["udp_stream"] = numeric(ch["udp_stream"])
    for c in _NUMS:
        d[c] = numeric(ch[c]).astype("float64")
    for c in _HEX:
        d[c] = _hex_num(ch[c])
    for c in _BOOLS:
        d[c] = truthy(ch[c])
    d["sack_perm"] = ch["sack_perm"] != ""
    d["sack_le"] = ch["sack_le"]
    d["sack_re"] = ch["sack_re"]
    d["exp_msg"] = ch["exp_msg"].str.replace(";", " | ")
    flags = pd.Series("", index=ch.index)
    for col, name in _TCP_FLAG_NAMES:
        flags = flags + d[col].map({True: name + ",", False: ""})
    d["flags"] = flags.str.rstrip(",").where(d["is_tcp"], "")
    tags = pd.Series("", index=ch.index)
    for k in ANALYSIS:
        tags = tags + d[k].map({True: k + ",", False: ""})
    d["tags"] = tags.str.rstrip(",")
    return d


@dataclass
class Extraction:
    packets: pd.DataFrame
    total_packets: int | None       # whole capture (io,stat,0)
    processed: int                  # rows in `packets`
    partial: bool
    limit: int


def extract_packets(ts: Tshark, path: str, total_packets: int | None) -> Extraction:
    limit = ts.limits.max_extracted_packets
    cap = limit if (limit and (total_packets is None or total_packets > limit)) else 0
    df = ts.fields(path, None, FIELDS, max_packets=cap, chunk_fn=convert)
    if df.empty:
        from .errors import InvalidCapture
        raise InvalidCapture("tshark returned no packets - the capture may be empty, truncated or corrupt.")
    df = df.reset_index(drop=True)
    # direction of each TCP packet relative to the first packet of its stream
    tcp = df[df["is_tcp"]]
    df["direction"] = ""
    if len(tcp):
        key_first = tcp.groupby("tcp_stream", sort=False)[["src", "sport"]].first()
        fs = tcp["tcp_stream"].map(key_first["src"])
        fp = tcp["tcp_stream"].map(key_first["sport"])
        df.loc[tcp.index, "direction"] = np.where((tcp["src"] == fs) & (tcp["sport"] == fp), "fwd", "rev")
    partial = bool(cap) and (total_packets is None or len(df) < total_packets)
    return Extraction(df, total_packets, len(df), partial, cap)
