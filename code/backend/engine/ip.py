"""
IP analysis (IPv4 + IPv6): endpoints / top talkers, transport-level conversations, header analysis, traffic over time, packet inspection.

IP-layer facts (addresses, TTL, DSCP, fragmentation ...) are dissected by tshark; ports and applications belong to the transport pages.
Endpoint and host-pair statistics come from `tshark -z endpoints,ip|ipv6` and `-z conv,ip|ipv6`. Conversation grouping, address categories and
distributions are aggregated by the engine ("derived"). No geolocation is attempted.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import capture
from .charts import chart, clean, counts_chart, histogram, metric, over_time, table, traffic_chart
from .context import Context
from .util import addr_category, first, pl, stats

IP_PROTO = {1: "ICMP", 2: "IGMP", 4: "IP-in-IP", 6: "TCP", 17: "UDP", 41: "IPv6 encap", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF",
            103: "PIM", 112: "VRRP", 132: "SCTP"}
ECN = {0: "Not-ECT", 1: "ECT(1)", 2: "ECT(0)", 3: "CE (congestion experienced)"}
PAGE_OF = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp", "ICMPV6": "icmp"}


def _l4(chain: pd.Series, proto_num: pd.Series) -> pd.Series:
    out = pd.Series("", index=chain.index)
    for tok, name in (("icmpv6", "ICMPv6"), ("icmp", "ICMP"), ("udp", "UDP"), ("tcp", "TCP")):
        m = chain.str.contains(rf"(?:^|:){tok}(?::|$)", regex=True)
        out = out.where(~m | (out != ""), name)
    other = proto_num.map(lambda n: IP_PROTO.get(int(n), f"proto {int(n)}") if n == n else "other")
    return out.where(out != "", other)


def ip_packets(ctx: Context) -> pd.DataFrame:
    """The IP packets of the extracted subset with derived IP columns used by the analysis and the packet filters."""
    df = ctx.packets
    d = df[df["src"] != ""].copy()
    d["version"] = np.where(d["protocols"].str.contains(r"(?:^|:)ipv6(?::|$)", regex=True), 6, 4)
    v6 = d["version"] == 6
    d["ttl_hlim"] = d["ttl"].where(~v6, d["hlim"])
    d["proto_num"] = d["ip_proto"].where(~v6, d["ip6_nxt"])
    d["l4"] = _l4(d["protocols"], d["proto_num"])
    flags = d["ip_flags"].fillna(0).astype(int)
    d["df_flag"] = (flags & 0x40) > 0
    d["fragmented"] = ((d["mf"] | (d["frag_off"].fillna(0) > 0)) & ~v6) | (v6 & d["protocols"].str.contains(r"(?:^|:)ipv6\.frag(?::|$)", regex=True))
    tclass = d["ip6_tclass"]
    d["dscp_val"] = d["dscp"].where(~v6, np.floor(tclass / 4) % 64)
    d["ecn_val"] = d["ecn"].where(~v6, tclass % 4)
    d["total_len"] = d["ip_len"].where(~v6, d["ip6_plen"] + 40)
    d["src_cat"] = d["src"].map(addr_category)
    d["dst_cat"] = d["dst"].map(addr_category)
    return d


def _canonical(d: pd.DataFrame) -> pd.DataFrame:
    """Canonical bidirectional key: (transport, endpoint A, endpoint B) with A < B. Unrelated conversations are never merged just because the
    IP pair is the same (ports are part of the key)."""
    a = d["src"].astype(str) + "|" + d["sport"].astype(str).str.zfill(5)
    b = d["dst"].astype(str) + "|" + d["dport"].astype(str).str.zfill(5)
    swap = a > b
    d = d.copy()
    d["ep_a"], d["ep_b"] = a.where(~swap, b), b.where(~swap, a)
    d["to_b"] = ~swap            # packet travels A -> B
    return d


def conversations(d: pd.DataFrame) -> pd.DataFrame:
    d = _canonical(d)
    g = d.groupby(["l4", "ep_a", "ep_b"], sort=False)
    out = g.agg(packets=("no", "size"), bytes=("length", "sum"), start_s=("rel_time", "min"), end_s=("rel_time", "max"), first_no=("no", "min"),
                tcp_stream=("tcp_stream", "first"), udp_stream=("udp_stream", "first")).reset_index()
    ab = d[d["to_b"]].groupby(["l4", "ep_a", "ep_b"]).agg(a_to_b_pkts=("no", "size"), a_to_b_bytes=("length", "sum"))
    ba = d[~d["to_b"]].groupby(["l4", "ep_a", "ep_b"]).agg(b_to_a_pkts=("no", "size"), b_to_a_bytes=("length", "sum"))
    out = out.join(ab, on=["l4", "ep_a", "ep_b"]).join(ba, on=["l4", "ep_a", "ep_b"])
    for c in ("a_to_b_pkts", "a_to_b_bytes", "b_to_a_pkts", "b_to_a_bytes"):
        out[c] = out[c].fillna(0).astype(int)
    out["ip_a"], out["port_a"] = out["ep_a"].str.split("|").str[0], out["ep_a"].str.split("|").str[1].astype(int)
    out["ip_b"], out["port_b"] = out["ep_b"].str.split("|").str[0], out["ep_b"].str.split("|").str[1].astype(int)
    out["duration_s"] = out["end_s"] - out["start_s"]
    dur = out["duration_s"].to_numpy()
    out["throughput_bps"] = np.where(dur > 0, out["bytes"] * 8 / np.where(dur > 0, dur, 1), np.nan)
    out["packets_per_s"] = np.where(dur > 0, out["packets"] / np.where(dur > 0, dur, 1), np.nan)
    out["page"] = out["l4"].str.upper().map(PAGE_OF).fillna("")
    out["flow"] = np.where(out["l4"] == "TCP", out["tcp_stream"], np.nan)
    out["port_a"] = out["port_a"].where(out["l4"].isin(["TCP", "UDP"]), np.nan)
    out["port_b"] = out["port_b"].where(out["l4"].isin(["TCP", "UDP"]), np.nan)
    out["pair"] = out["ip_a"] + " ⇄ " + out["ip_b"]
    return out.sort_values("bytes", ascending=False).reset_index(drop=True)


def endpoint_table(ctx: Context, d: pd.DataFrame) -> pd.DataFrame:
    ep = capture.endpoints(ctx.ts, ctx.path, "ip")
    if (d["version"] == 6).any():
        ep = pd.concat([ep, capture.endpoints(ctx.ts, ctx.path, "ipv6")], ignore_index=True)
    ep["family"] = np.where(ep["endpoint"].str.contains(":"), "IPv6", "IPv4")
    ep["category"] = ep["endpoint"].map(addr_category)
    # derived: protocols and services seen per endpoint (from the extracted subset)
    both = pd.concat([d[["src", "l4", "sport", "dport", "length"]].rename(columns={"src": "ip"}).assign(port=d["sport"]),
                      d[["dst", "l4", "sport", "dport", "length"]].rename(columns={"dst": "ip"}).assign(port=d["dport"])])
    protos = both.groupby("ip")["l4"].agg(lambda s: ", ".join(s.value_counts().head(4).index))
    ep["protocols"] = ep["endpoint"].map(protos).fillna("")
    return ep.sort_values("bytes", ascending=False).reset_index(drop=True)


def ip_detail(ctx: Context, addr: str) -> dict:
    """Everything about one IP address: protocol breakdown, services, peers, conversations, traffic over time."""
    d = ctx.scratch["ip_packets"]
    convs = ctx.scratch["ip_conversations"]
    tx, rx = d[d["src"] == addr], d[d["dst"] == addr]
    if tx.empty and rx.empty:
        return {}
    both = pd.concat([tx.assign(dir="tx"), rx.assign(dir="rx")])
    proto = both.groupby("l4").agg(packets=("no", "size"), bytes=("length", "sum")).sort_values("bytes", ascending=False).reset_index()
    port = both[both["l4"].isin(["TCP", "UDP"])].copy()
    port["service_port"] = np.where(port["dir"] == "tx", port["sport"], port["dport"])        # this host's own port
    port["remote_port"] = np.where(port["dir"] == "tx", port["dport"], port["sport"])
    port["server_port"] = port[["service_port", "remote_port"]].min(axis=1)
    svc = port.groupby(["l4", "server_port"]).agg(packets=("no", "size"), bytes=("length", "sum")).reset_index().sort_values("bytes", ascending=False).head(20)
    peers = pd.concat([tx.assign(peer=tx["dst"]), rx.assign(peer=rx["src"])]).groupby("peer").agg(
        packets=("no", "size"), bytes=("length", "sum")).sort_values("bytes", ascending=False).head(20).reset_index()
    mine = convs[(convs["ip_a"] == addr) | (convs["ip_b"] == addr)]
    tl = over_time("ipd_time", "Traffic over time (bytes)", both["rel_time"], weights=both["length"].to_numpy(), split=both["dir"].map({"tx": "sent", "rx": "received"}),
                   unit="bytes", name="bytes", tip="Bytes sent / received by this address")
    return {
        "address": addr, "family": "IPv6" if ":" in addr else "IPv4", "category": addr_category(addr),
        "packets_sent": int(len(tx)), "packets_received": int(len(rx)), "bytes_sent": int(tx["length"].sum()), "bytes_received": int(rx["length"].sum()),
        "first_seen_s": float(both["rel_time"].min()), "last_seen_s": float(both["rel_time"].max()),
        "protocols": proto, "services": svc, "peers": peers, "conversations": mine, "traffic": tl,
    }


def analyze(ctx: Context) -> tuple[dict, pd.DataFrame]:
    d = ip_packets(ctx)
    v4, v6 = d[d["version"] == 4], d[d["version"] == 6]
    convs = conversations(d)
    ep = endpoint_table(ctx, d)
    host_pairs = capture.conversations(ctx.ts, ctx.path, "ip")
    if len(v6):
        host_pairs = pd.concat([host_pairs, capture.conversations(ctx.ts, ctx.path, "ipv6")], ignore_index=True)
    host_pairs = host_pairs.sort_values("bytes", ascending=False)
    host_pairs["pair"] = host_pairs["a"] + " ⇄ " + host_pairs["b"]
    ctx.scratch["ip_packets"], ctx.scratch["ip_conversations"] = d, convs

    hosts = pd.concat([d["src"], d["dst"]]).dropna().unique()
    ttl = d["ttl_hlim"].dropna()
    frag = d[d["fragmented"]]
    ecn = d["ecn_val"].dropna().astype(int)
    cat_src = d.groupby("src_cat")["length"].sum().sort_values(ascending=False)
    cat_dst = d.groupby("dst_cat")["length"].sum().sort_values(ascending=False)
    by_l4 = d["l4"].value_counts()

    metrics = [
        metric("IP packets", int(len(d)), tip="Packets with an IPv4 or IPv6 header (in the analysed packet subset).", basis="observed"),
        metric("IPv4 packets", int(len(v4)), basis="observed"), metric("IPv6 packets", int(len(v6)), basis="observed"),
        metric("Unique IP hosts", int(len(hosts)), tip="Distinct source/destination addresses."),
        metric("IP host pairs", int(len(host_pairs)), tip="tshark -z conv,ip / conv,ipv6 - one row per pair of hosts.", basis="observed"),
        metric("Transport conversations", int(len(convs)), tip="Canonical bidirectional (IP pair + ports + transport protocol). Unrelated conversations between the same two hosts stay separate."),
        metric("TTL / hop-limit (average)", float(ttl.mean()) if len(ttl) else None, fmt="num1", tip="Mean of observed TTL (IPv4) and hop limit (IPv6).", why="No IP packets."),
        metric("Fragmented packets", int(len(frag)), tip="IPv4: More-Fragments flag or non-zero offset. IPv6: Fragment extension header.", basis="observed"),
    ]

    top_b = ep.head(10)
    top_p = ep.sort_values("packets", ascending=False).head(10)
    src_b = d.groupby("src")["length"].sum().sort_values(ascending=False).head(10)
    dst_b = d.groupby("dst")["length"].sum().sort_values(ascending=False).head(10)
    charts = {c["id"]: c for c in clean([
        chart("ipver", "IPv4 vs IPv6 (packets)", "pie", ["IPv4", "IPv6"], [{"name": "packets", "data": [int(len(v4)), int(len(v6))]}]),
        chart("ipcat", "Address categories (bytes, by source)", "pie", list(cat_src.index), [{"name": "bytes", "data": [int(x) for x in cat_src.values]}], unit="bytes",
              tip="Private (RFC 1918 / ULA), public, loopback, link-local, multicast, broadcast (255.255.255.255 only - subnet broadcast needs the netmask), shared CGNAT, reserved."),
        chart("ipcatd", "Address categories (bytes, by destination)", "pie", list(cat_dst.index), [{"name": "bytes", "data": [int(x) for x in cat_dst.values]}], unit="bytes"),
        chart("ipproto", "Transport / protocol carried by IP (packets)", "bar", list(by_l4.index), [{"name": "packets", "data": [int(x) for x in by_l4.values]}],
              tip="Derived from the dissected protocol chain; falls back to the IPv4 protocol / IPv6 next-header number."),
        chart("toptalk_b", "Top talkers by bytes", "barh", list(top_b["endpoint"]), [{"name": "bytes", "data": [float(x) for x in top_b["bytes"]]}], unit="bytes", tip="tshark -z endpoints,ip (and ipv6)"),
        chart("toptalk_p", "Top talkers by packets", "barh", list(top_p["endpoint"]), [{"name": "packets", "data": [int(x) for x in top_p["packets"]]}]),
        chart("topsrc", "Top source addresses (bytes sent)", "barh", list(src_b.index), [{"name": "bytes", "data": [int(x) for x in src_b.values]}], unit="bytes"),
        chart("topdst", "Top destination addresses (bytes received)", "barh", list(dst_b.index), [{"name": "bytes", "data": [int(x) for x in dst_b.values]}], unit="bytes"),
        histogram("ipttl_raw", "TTL / hop-limit distribution (observed values)", ttl, unit="hops", bins=16, x_label="TTL / hop limit"),
        chart("ipecn", "ECN field", "bar", [ECN.get(int(x), str(x)) for x in ecn.value_counts().sort_index().index], [{"name": "packets", "data": [int(v) for v in ecn.value_counts().sort_index().values]}],
              tip="Explicit Congestion Notification bits in the IP header.") if len(ecn) else None,
        histogram("ipsize", "Packet size distribution (bytes on the wire)", d["length"], unit="bytes", bins=20, x_label="bytes"),
        histogram("iphdr", "IPv4 header length (bytes)", v4["ip_hdr_len"], unit="bytes", bins=8, x_label="bytes") if len(v4) else None,
        over_time("iptime", "Traffic over time (bytes by protocol)", d["rel_time"], weights=d["length"].to_numpy(), split=d["l4"], unit="bytes", name="bytes", tip="Frame bytes per time bin, split by protocol"),
        traffic_chart(ctx.ts, ctx.path, "ip || ipv6", ctx.duration, "iptraffic", "Throughput over time (whole capture)"),
    ])}

    tables = {t["id"]: t for t in [
        table("endpoints", "IP endpoints", ep, [("endpoint", "Address", "text", False), ("family", "Family", "text", False), ("category", "Category", "text", False),
              ("packets", "Packets", "num", True), ("bytes", "Bytes", "bytes", True), ("tx_packets", "Sent pkts", "num", True), ("tx_bytes", "Sent bytes", "bytes", True),
              ("rx_packets", "Recv pkts", "num", True), ("rx_bytes", "Recv bytes", "bytes", True), ("protocols", "Protocols", "text", False)],
              tip="tshark -z endpoints,ip / ipv6 (Sent = packets whose source is this address). Click a row to inspect one address.", click="endpoint"),
        table("host_pairs", "IP host pairs", host_pairs, [("pair", "Hosts", "text", False), ("frames", "Packets", "num", True), ("bytes", "Bytes", "bytes", True),
              ("frames_a_to_b", "A→B pkts", "num", True), ("bytes_a_to_b", "A→B bytes", "bytes", True), ("frames_b_to_a", "B→A pkts", "num", True),
              ("bytes_b_to_a", "B→A bytes", "bytes", True), ("start_s", "Start (s)", "sec", True), ("duration_s", "Duration", "sec", True)], tip="tshark -z conv,ip / conv,ipv6 - all protocols between two hosts."),
        table("conversations", "Transport conversations", convs, [("ip_a", "Address A", "text", False), ("port_a", "Port A", "text", False), ("ip_b", "Address B", "text", False),
              ("port_b", "Port B", "text", False), ("l4", "Protocol", "text", False), ("packets", "Packets", "num", True), ("bytes", "Bytes", "bytes", True),
              ("a_to_b_pkts", "A→B pkts", "num", True), ("a_to_b_bytes", "A→B bytes", "bytes", True), ("b_to_a_pkts", "B→A pkts", "num", True), ("b_to_a_bytes", "B→A bytes", "bytes", True),
              ("duration_s", "Duration", "sec", True), ("throughput_bps", "Throughput", "bps", True), ("packets_per_s", "Pkts/s", "num1", True)],
              tip="Canonical bidirectional IP pair + ports + transport protocol. Click a row to open the matching TCP/UDP/ICMP page.", click="first_no", extra_keys=("page", "flow", "ip_a", "ip_b")),
    ]}
    if len(frag):
        fr = frag.assign(version_label=frag["version"].map({4: "IPv4", 6: "IPv6"}))[["no", "rel_time", "src", "dst", "version_label", "ip_id", "frag_off", "mf", "length"]]
        fr["mf"] = fr["mf"].map({True: "more fragments", False: "last/only"})
        tables["fragments"] = table("fragments", "Fragmentation events", fr, [("no", "Packet", "num", True), ("rel_time", "Time (s)", "sec", True), ("src", "Source", "text", False),
                                    ("dst", "Destination", "text", False), ("version_label", "Version", "text", False), ("ip_id", "Identification", "num", True),
                                    ("frag_off", "Offset", "num", True), ("mf", "MF", "text", False), ("length", "Length", "bytes", True)], click="no")

    sections = [
        {"id": "summary", "title": "Summary", "metrics": "all", "charts": ["ipver", "ipcat", "ipproto"]},
        {"id": "talkers", "title": "Top Talkers", "charts": ["toptalk_b", "toptalk_p", "topsrc", "topdst"], "tables": ["endpoints"]},
        {"id": "conversations", "title": "IP Conversations", "tables": ["conversations", "host_pairs"]},
        {"id": "headers", "title": "IPv4/IPv6 Header Analysis", "charts": ["ipttl_raw", "ipecn", "ipsize", "iphdr"], "tables": ["fragments"]},
        {"id": "traffic", "title": "Traffic Over Time", "charts": ["iptime", "iptraffic"]},
    ]
    cols = [("no", "#", "num", True), ("rel_time", "Time", "sec", True), ("src", "Source", "text", False), ("dst", "Destination", "text", False), ("version", "Ver", "num", True),
            ("l4", "Protocol", "text", False), ("ttl_hlim", "TTL/HL", "num", True), ("length", "Length", "bytes", True), ("ip_id", "IP ID", "num", True),
            ("df_flag", "DF", "text", False), ("fragmented", "Frag", "text", False), ("dscp_val", "DSCP", "num", True), ("ecn_val", "ECN", "num", True)]
    detail = {
        "key": "ip", "label": "IP Analysis", "filter": "ip || ipv6",
        "summary": f"{len(d):,} IP packets between {len(hosts):,} hosts ({len(v4):,} IPv4, {len(v6):,} IPv6) in {len(convs):,} transport conversations "
                   f"and {len(host_pairs):,} host pairs.",
        "card": [pl(len(hosts), "host"), pl(len(convs), "conversation"), f"{len(v4):,} IPv4 · {len(v6):,} IPv6"],
        "metrics": metrics, "charts": list(charts.values()), "tables": list(tables.values()), "sections": sections,
        "packet_columns": [{"key": k, "label": l, "fmt": f, "num": n} for k, l, f, n in cols],
        "packet_filters": [
            {"key": "src", "label": "Source IP", "type": "text"}, {"key": "dst", "label": "Destination IP", "type": "text"},
            {"key": "version", "label": "IP version", "type": "select", "options": ["4", "6"]}, {"key": "proto", "label": "Protocol", "type": "select", "options": sorted(d["l4"].unique())},
            {"key": "ttl_min", "label": "TTL ≥", "type": "number"}, {"key": "ttl_max", "label": "TTL ≤", "type": "number"},
            {"key": "fragmented", "label": "Fragmented only", "type": "bool"}, {"key": "dscp", "label": "DSCP", "type": "number"},
            {"key": "ecn", "label": "ECN", "type": "select", "options": ["0", "1", "2", "3"]}],
    }
    pk = d.assign(info=d["protocols"].str.replace("eth:ethertype:", "", regex=False))
    return detail, pk


def filter_packets(df: pd.DataFrame, f: dict) -> pd.DataFrame:
    """Apply the IP packet-inspection filters (f: key -> string value)."""
    if f.get("src"):
        df = df[df["src"] == f["src"].strip()]
    if f.get("dst"):
        df = df[df["dst"] == f["dst"].strip()]
    if f.get("version"):
        df = df[df["version"] == int(f["version"])]
    if f.get("proto"):
        df = df[df["l4"] == f["proto"]]
    if f.get("ttl_min"):
        df = df[df["ttl_hlim"] >= float(f["ttl_min"])]
    if f.get("ttl_max"):
        df = df[df["ttl_hlim"] <= float(f["ttl_max"])]
    if f.get("fragmented") in ("1", "true", "True"):
        df = df[df["fragmented"]]
    if f.get("dscp") not in (None, ""):
        df = df[df["dscp_val"] == float(f["dscp"])]
    if f.get("ecn") not in (None, ""):
        df = df[df["ecn_val"] == float(f["ecn"])]
    return df
