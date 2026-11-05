"""Wireshark/TShark cross-validation: re-measure key numbers with independent tshark commands and compare them with the engine.

Each row says WHERE the engine value comes from:
  dissected  - counted from a flag/field that tshark dissected (e.g. tcp.analysis.retransmission)
  aggregated - grouped / summed by the engine from dissected fields
  derived    - calculated by the engine (no direct Wireshark equivalent)
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pandas as pd

from . import capture
from .report import Report
from .tshark import Tshark

EXPLANATIONS = [
    "Capture truncation / partial analysis: when MAX_EXTRACTED_PACKETS applies, engine values cover the first N packets; reference counts that read the whole file (conversation tables) can differ.",
    "Missing handshake: without SYN/SYN-ACK window scaling, MSS, SACK and ECN negotiation are unknown, and Wireshark's own calculated window may differ from the engine's (marked 'uncertain').",
    "TShark version: field names, expert-info wording and TCP-analysis heuristics change between releases.",
    "Filtering scope: tshark -z statistics count the whole capture; per-packet counts use the packet subset that was extracted.",
    "Analysis heuristics: Wireshark labels retransmissions, out-of-order and lost segments heuristically; 'previous segment not captured' can be capture loss rather than network loss.",
    "One-sided or incomplete captures: RTT, window and option metrics need both directions and the handshake.",
]


def _m(detail: dict | None, label: str):
    for m in (detail or {}).get("metrics", []):
        if m["label"] == label and m.get("available"):
            return m["value"]
    return None


def cross_validate(r: Report, limits=None) -> dict:
    ts = Tshark(limits or r.ctx.limits)
    ts.start_clock()
    path, cap = r.ctx.path, r.ctx.max_packets
    df, t = r.packets, r.tcp
    tcp = df[df["is_tcp"]]
    ipk = r.ctx.scratch.get("ip_packets", pd.DataFrame())
    D = r.details
    count = lambda f, two=False: ts.count(path, f, two, cap)

    # (area, metric, engine value, basis, reference thunk, note)
    rows = [
        ("TCP", "TCP packets", int(len(tcp)), "aggregated", lambda: count("tcp.stream && !icmp && !icmpv6"), "Reference excludes ICMP errors that embed a TCP header."),
        ("TCP", "TCP flows (tcp.stream)", int(len(t.flows)), "aggregated", lambda: len(capture.conversations(ts, path, "tcp")), "Reference: tshark -z conv,tcp (whole capture)."),
        ("TCP", "Retransmissions (incl. fast)", r.summary["retransmissions"], "dissected", lambda: count("tcp.analysis.retransmission || tcp.analysis.fast_retransmission"), ""),
        ("TCP", "Fast retransmissions", int(tcp["fast_retransmission"].sum()), "dissected", lambda: count("tcp.analysis.fast_retransmission"), ""),
        ("TCP", "Spurious retransmissions", int(tcp["spurious_retransmission"].sum()), "dissected", lambda: count("tcp.analysis.spurious_retransmission"), ""),
        ("TCP", "Duplicate ACKs", int(tcp["duplicate_ack"].sum()), "dissected", lambda: count("tcp.analysis.duplicate_ack"), ""),
        ("TCP", "Out-of-order", int(tcp["out_of_order"].sum()), "dissected", lambda: count("tcp.analysis.out_of_order"), ""),
        ("TCP", "Lost-segment flags", int(tcp["lost_segment"].sum()), "dissected", lambda: count("tcp.analysis.lost_segment"), ""),
        ("TCP", "Zero-window events (Wireshark flag)", int(tcp["zero_window"].sum()), "dissected", lambda: count("tcp.analysis.zero_window"), ""),
        ("TCP", "Zero-window advertisements (engine: window field = 0)", int(((tcp["win_raw"] == 0) & ~tcp["syn"] & ~tcp["rst"]).sum()), "derived",
         lambda: count("tcp.window_size_value == 0 && tcp.flags.syn == 0 && tcp.flags.reset == 0"), "Engine reads the raw 16-bit window; reference filters the same condition."),
        ("TCP", "ACK-based RTT samples", int(len(t.rtt_ack)), "dissected", lambda: count("tcp.analysis.ack_rtt"), ""),
        ("TCP", "Handshake RTT samples", int(len(t.rtt_initial)), "dissected", lambda: count("tcp.analysis.initial_rtt"), ""),
        ("TCP options", "SYN packets with window scale", int((tcp["syn"] & tcp["wscale"].notna()).sum()), "dissected", lambda: count("tcp.flags.syn == 1 && tcp.options.wscale.shift"), ""),
        ("TCP options", "SYN packets with SACK-permitted", int((tcp["syn"] & tcp["sack_perm"]).sum()), "dissected", lambda: count("tcp.flags.syn == 1 && tcp.options.sack_perm"), ""),
        ("TCP options", "SYN packets with timestamps", int((tcp["syn"] & tcp["tsval"].notna()).sum()), "dissected", lambda: count("tcp.flags.syn == 1 && tcp.options.timestamp.tsval"), ""),
        ("TCP options", "SYN packets with MSS", int((tcp["syn"] & tcp["mss"].notna()).sum()), "dissected", lambda: count("tcp.flags.syn == 1 && tcp.options.mss_val"), ""),
        ("Window scaling", "Packets whose engine effective window differs from Wireshark's", int(((tcp["eff_win"] - tcp["win"]).abs() > 0.5)[tcp["eff_win"].notna() & tcp["win"].notna() & (tcp["win_status"] != "uncertain")].sum()),
         "derived", lambda: 0, "Expected 0 wherever the handshake was captured (status 'uncertain' packets are excluded)."),
        ("TCP", "Timestamp-echo RTT samples", int(len(t.rtt_ts)), "derived", lambda: None, "Engine-only method; Wireshark has no equivalent."),
        ("IP", "IP packets", int(len(ipk)), "aggregated", lambda: count("ip || ipv6"), ""),
        ("IP", "IPv4 endpoints", int(ipk[ipk["version"] == 4][["src", "dst"]].stack().nunique()) if len(ipk) else 0, "aggregated", lambda: len(capture.endpoints(ts, path, "ip")), "Reference: tshark -z endpoints,ip (whole capture)."),
        ("IP", "IPv4 host pairs", int(ipk[ipk["version"] == 4].assign(p=lambda d: d[["src", "dst"]].min(axis=1) + "|" + d[["src", "dst"]].max(axis=1))["p"].nunique()) if len(ipk) else 0, "aggregated",
         lambda: len(capture.conversations(ts, path, "ip")), "Reference: tshark -z conv,ip (whole capture)."),
        ("UDP", "UDP datagrams", int(df["is_udp"].sum()), "aggregated", lambda: count("udp.stream && !icmp && !icmpv6"), "Reference excludes ICMP errors that embed a UDP header."),
        ("UDP", "UDP conversations", int(len(D["udp"]["tables"][0]["rows"])) if "udp" in D and D["udp"]["tables"] and D["udp"]["tables"][0]["total"] == len(D["udp"]["tables"][0]["rows"])
         else (D["udp"]["tables"][0]["total"] if "udp" in D else 0), "aggregated", lambda: len(capture.conversations(ts, path, "udp")), "Reference: tshark -z conv,udp (whole capture)."),
        ("DNS", "DNS queries", _m(D.get("dns"), "Queries") or 0, "dissected", lambda: count("dns && dns.flags.response == 0"), ""),
        ("DNS", "DNS responses", _m(D.get("dns"), "Responses") or 0, "dissected", lambda: count("dns && dns.flags.response == 1"), ""),
        ("HTTP", "HTTP requests", _m(D.get("http"), "Requests") or 0, "dissected", lambda: count("http.request"), ""),
        ("HTTP", "HTTP responses", _m(D.get("http"), "Responses") or 0, "dissected", lambda: count("http.response"), ""),
        ("TLS", "ClientHello", _m(D.get("tls"), "TLS connections (ClientHello)") or 0, "aggregated", lambda: count("tls.handshake.type == 1"), "Engine counts connections; a retransmitted ClientHello would make the reference larger."),
        ("TLS", "ServerHello", _m(D.get("tls"), "ServerHello seen") or 0, "aggregated", lambda: count("tls.handshake.type == 2"), ""),
        ("DHCP", "DHCP messages", _m(D.get("dhcp"), "DHCP messages") or 0, "dissected", lambda: count("dhcp"), ""),
        ("ICMP", "ICMP + ICMPv6 messages", (_m(D.get("icmp"), "ICMP messages") or 0) + (_m(D.get("icmp"), "ICMPv6 messages") or 0), "dissected", lambda: count("icmp || icmpv6"), ""),
    ]

    def ref(row):
        try:
            return row[4]()
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        refs = list(pool.map(ref, rows))
    out = []
    for (area, metric, eng, basis, _, note), tsv in zip(rows, refs):
        diff = None if tsv is None else eng - tsv
        out.append({"area": area, "metric": metric, "engine": eng, "basis": basis, "tshark": tsv, "difference": diff,
                    "status": "no reference" if tsv is None else ("match" if diff == 0 else "differs"), "note": note})
    return {"rows": out, "explanations": EXPLANATIONS, "scope": "first %d packets" % cap if cap else "full capture",
            "summary": {"checked": sum(1 for o in out if o["tshark"] is not None), "matching": sum(1 for o in out if o["status"] == "match"),
                        "differing": sum(1 for o in out if o["status"] == "differs")}}
