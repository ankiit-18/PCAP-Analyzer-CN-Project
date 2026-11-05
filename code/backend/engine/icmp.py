"""ICMP and ICMPv6. Echo response time is ICMP echo timing and is never labelled TCP RTT."""
from __future__ import annotations

import pandas as pd

from .base import load_base
from .charts import chart, clean, counts_chart, histogram, metric, over_time, table
from .context import Context
from .util import first, numeric, pl, stats

ICMP4 = {0: "Echo reply", 3: "Destination unreachable", 4: "Source quench", 5: "Redirect", 8: "Echo request", 9: "Router advertisement", 10: "Router solicitation",
         11: "Time exceeded", 12: "Parameter problem", 13: "Timestamp request", 14: "Timestamp reply"}
ICMP6 = {1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded", 4: "Parameter problem", 128: "Echo request", 129: "Echo reply", 133: "Router solicitation",
         134: "Router advertisement", 135: "Neighbor solicitation", 136: "Neighbor advertisement", 137: "Redirect", 143: "MLDv2 report"}
ICMP4_ERR, ICMP6_ERR = {3, 4, 5, 11, 12}, {1, 2, 3, 4}
UNREACH = {0: "network", 1: "host", 2: "protocol", 3: "port", 4: "fragmentation needed", 5: "source route failed", 13: "administratively prohibited"}


def analyze(ctx: Context) -> tuple[dict, pd.DataFrame]:
    df = load_base(ctx, "icmp || icmpv6", [("t4", "icmp.type"), ("c4", "icmp.code"), ("t6", "icmpv6.type"), ("c6", "icmpv6.code"), ("ident", "icmp.ident"), ("seq", "icmp.seq"),
                                          ("resp_in", "icmp.resp_in"), ("no_resp", "icmp.no_resp"), ("rtt", "icmp.resptime"), ("id6", "icmpv6.echo.identifier"),
                                          ("seq6", "icmpv6.echo.sequence_number")], two_pass=True)
    df["v6"] = df["chain"].str.contains(r"(?:^|:)icmpv6(?::|$)", regex=True)
    df["type"] = pd.to_numeric(first(df["t4"].where(~df["v6"], df["t6"])), errors="coerce")
    df["code"] = pd.to_numeric(first(df["c4"].where(~df["v6"], df["c6"])), errors="coerce")
    df["family"] = df["v6"].map({True: "ICMPv6", False: "ICMP"})
    df["name"] = [(ICMP6 if v6 else ICMP4).get(int(t), f"type {int(t)}") if t == t else "" for v6, t in zip(df["v6"], df["type"])]
    df["is_error"] = [(int(t) in (ICMP6_ERR if v6 else ICMP4_ERR)) if t == t else False for v6, t in zip(df["v6"], df["type"])]
    df["detail"] = [UNREACH.get(int(c), f"code {int(c)}") if (t == 3 and not v6 and c == c) else "" for v6, t, c in zip(df["v6"], df["type"], df["code"])]
    req = df[((df["type"] == 8) & ~df["v6"]) | ((df["type"] == 128) & df["v6"])]
    rep = df[((df["type"] == 0) & ~df["v6"]) | ((df["type"] == 129) & df["v6"])]
    # IPv4: Wireshark's own matching (icmp.no_resp / icmp.resptime). IPv6: matched here by identifier + sequence (derived).
    df["rtt_ms"] = numeric(df["rtt"])
    pending, v6_rtt = {}, {}
    for x in df[df["v6"]].itertuples():
        k = (first(pd.Series([x.id6])).iloc[0], first(pd.Series([x.seq6])).iloc[0])
        if x.type == 128:
            pending[(k, x.src, x.dst)] = x.time
        elif x.type == 129:
            t0 = pending.pop((k, x.dst, x.src), None)
            if t0 is not None:
                v6_rtt[x.no] = (x.time - t0) * 1000
    for no, v in v6_rtt.items():
        df.loc[df["no"] == no, "rtt_ms"] = v
    unans = int(((first(req["no_resp"]) != "") & ~req["v6"]).sum()) + max(int(req["v6"].sum()) - len(v6_rtt), 0)
    rtt = stats(df["rtt_ms"])
    errors = df[df["is_error"]]
    err_names = (errors["name"] + errors["detail"].map(lambda d: f" ({d})" if d else "")) if len(errors) else pd.Series(dtype=str)
    by_type = df.assign(label=df["family"] + " " + df["name"]).groupby("label").agg(packets=("no", "size"), bytes=("length", "sum")).sort_values("packets", ascending=False).reset_index()

    metrics = [
        metric("ICMP messages", int((~df["v6"]).sum()), basis="observed"), metric("ICMPv6 messages", int(df["v6"].sum()), basis="observed", tip="Includes neighbor discovery."),
        metric("Total bytes", int(df["length"].sum()), fmt="bytes"),
        metric("Echo requests (ping)", int(len(req)), tip="ICMP type 8 / ICMPv6 type 128."), metric("Echo replies", int(len(rep)), tip="ICMP type 0 / ICMPv6 type 129."),
        metric("Unanswered echo requests", unans, tip="Requests with no reply seen (ICMPv4: Wireshark's matching; ICMPv6: matched by id+sequence)."),
        metric("Error messages", int(len(errors)), tip="Destination unreachable, time exceeded, redirect, parameter problem, packet too big, …"),
        metric("Echo response time min", rtt["min"] if rtt else None, fmt="ms", tip="ICMP echo response time (not TCP RTT).", why="No echo request/reply pairs."),
        metric("Echo response time average", rtt["avg"] if rtt else None, fmt="ms", why="No echo request/reply pairs."),
        metric("Echo response time max", rtt["max"] if rtt else None, fmt="ms", why="No echo request/reply pairs."),
        metric("Hosts involved", int(pd.concat([df["src"], df["dst"]]).replace("", pd.NA).dropna().nunique())),
    ]
    charts = {c["id"]: c for c in clean([
        over_time("icmp_time", "ICMP packets over time", df["rel_time"]),
        chart("icmp_types", "Message distribution (packets)", "bar", list(by_type["label"]), [{"name": "packets", "data": [int(x) for x in by_type["packets"]]}], tip="Type names per RFC 792 / RFC 4443."),
        chart("icmp_typeb", "Bytes per message type", "bar", list(by_type["label"]), [{"name": "bytes", "data": [int(x) for x in by_type["bytes"]]}], unit="bytes"),
        counts_chart("icmp_err", "Error messages", err_names, "barh") if len(errors) else None,
        histogram("icmp_rtt", "Echo response time distribution", df["rtt_ms"], unit="ms", x_label="ms"),
        counts_chart("icmp_src", "Top senders", df["src"], "barh"),
    ])}
    msgs = df.assign(time_s=df["rel_time"], kind=df["is_error"].map({True: "ERROR", False: ""}))[["no", "time_s", "family", "name", "detail", "kind", "src", "dst", "ident", "seq", "length", "rtt_ms"]].copy()
    msgs["ident"], msgs["seq"] = first(msgs["ident"]), first(msgs["seq"])
    tables = {"messages": table("messages", "ICMP messages", msgs, [("no", "Packet", "num", True), ("time_s", "Time (s)", "sec", True), ("family", "Proto", "text", False),
              ("name", "Message", "text", False), ("detail", "Detail", "text", False), ("kind", "", "text", False), ("src", "From", "text", False), ("dst", "To", "text", False),
              ("ident", "ID", "text", False), ("seq", "Seq", "text", False), ("length", "Bytes", "bytes", True), ("rtt_ms", "Response time", "ms", True)],
              tip="Every ICMP/ICMPv6 packet. Click a row to inspect it.", click="no")}
    sections = [{"id": "summary", "title": "Summary", "metrics": "all", "charts": ["icmp_types", "icmp_time"]},
                {"id": "echo", "title": "Echo & response time", "charts": ["icmp_rtt", "icmp_src"]},
                {"id": "errors", "title": "Errors", "charts": ["icmp_err", "icmp_typeb"]},
                {"id": "messages", "title": "Messages", "tables": ["messages"]}]
    detail = {
        "key": "icmp", "label": "ICMP / ICMPv6", "filter": "icmp || icmpv6",
        "summary": f"{len(df):,} ICMP/ICMPv6 messages: {len(req)} echo request(s), {len(rep)} repl{'y' if len(rep) == 1 else 'ies'}, {len(errors)} error message(s).",
        "card": [pl(len(df), "message"), pl(len(errors), "error"), f"echo avg {rtt['avg']:.1f} ms" if rtt else "no echo timing"],
        "insight": {"text": f"{pl(len(errors), 'ICMP error message')}" + (f" · {unans} unanswered ping(s)" if unans else ""), "tone": "bad" if len(errors) else "ok"},
        "metrics": metrics, "charts": list(charts.values()), "tables": list(tables.values()), "sections": sections,
        "notes": ["Echo response time is ICMP timing measured at the capture point - it is not a TCP RTT.", "ICMPv6 also carries neighbor discovery (replacing ARP)."],
    }
    return detail, df
