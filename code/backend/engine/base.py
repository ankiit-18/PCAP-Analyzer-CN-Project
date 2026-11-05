"""Filtered protocol passes: BASE columns (+ packet summary line) + analyzer-specific fields."""
from __future__ import annotations

import pandas as pd

from .context import Context
from .util import first

BASE = [("no", "frame.number"), ("time", "frame.time_epoch"), ("rel_time", "frame.time_relative"), ("length", "frame.len"),
        ("ip_src", "ip.src"), ("ip_dst", "ip.dst"), ("ip6_src", "ipv6.src"), ("ip6_dst", "ipv6.dst"),
        ("tcp_sport", "tcp.srcport"), ("tcp_dport", "tcp.dstport"), ("udp_sport", "udp.srcport"), ("udp_dport", "udp.dstport"),
        ("tcp_stream", "tcp.stream"), ("udp_stream", "udp.stream"), ("chain", "frame.protocols")]

# frame.protocols tokens that are plumbing rather than an "application protocol"
BASE_PROTOS = {"eth", "ethertype", "ip", "ipv6", "tcp", "udp", "vlan", "sll", "sll2", "null", "loop", "raw", "data", "frame", "icmp", "icmpv6",
               "ipv6.hopopts", "ipv6.dstopts", "ipv6.frag", "ipv6.routing", "ipcomp", "ah", "esp"}

_INFO = {}


def info_field(ctx: Context) -> str:
    """The packet-summary column is `_ws.col.info` (4.x) or `_ws.col.Info` (3.x) - pick whichever this tshark knows."""
    if "f" not in _INFO:
        _INFO["f"] = "_ws.col.info" if ctx.ts.has_field("_ws.col.info") else ("_ws.col.Info" if ctx.ts.has_field("_ws.col.Info") else "_ws.col.info")
    return _INFO["f"]


def load_base(ctx: Context, display_filter: str, extra=(), **kw) -> pd.DataFrame:
    cols = BASE + [("info", info_field(ctx))] + list(extra)
    df = ctx.load(display_filter, cols, **kw)
    if df.empty:
        for c in ("src", "dst", "stream", "app", "sport", "dport"):
            df[c] = pd.Series(dtype=str)
        return df
    for c in ("no", "length"):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
    for c in ("time", "rel_time"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
    for c in ("ip_src", "ip_dst", "ip6_src", "ip6_dst", "tcp_sport", "tcp_dport", "udp_sport", "udp_dport", "tcp_stream", "udp_stream", "chain"):
        df[c] = first(df[c])
    df["src"] = df["ip_src"].where(df["ip_src"] != "", df["ip6_src"])
    df["dst"] = df["ip_dst"].where(df["ip_dst"] != "", df["ip6_dst"])
    sp = df["tcp_sport"].where(df["tcp_sport"] != "", df["udp_sport"])
    dp = df["tcp_dport"].where(df["tcp_dport"] != "", df["udp_dport"])
    df["sport"] = pd.to_numeric(sp, errors="coerce").fillna(0).astype(int)
    df["dport"] = pd.to_numeric(dp, errors="coerce").fillna(0).astype(int)
    df["stream"] = ("tcp:" + df["tcp_stream"]).where(df["tcp_stream"] != "", ("udp:" + df["udp_stream"]).where(df["udp_stream"] != "", ""))
    df["app"] = df["chain"].apply(lambda c: next((p.upper() for p in reversed(c.split(":")) if p not in BASE_PROTOS), ""))
    return df
