"""DNS: query/response matching (Wireshark's dns.response_in / dns.response_to), response time, failures, domains and types."""
from __future__ import annotations

import pandas as pd

from .base import load_base
from .charts import chart, clean, counts_chart, histogram, metric, over_time, table
from .context import Context
from .util import first, numeric, pl, stats, truthy

QTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def analyze(ctx: Context) -> tuple[dict, pd.DataFrame]:
    df = load_base(ctx, "dns", [("dns_id", "dns.id"), ("resp", "dns.flags.response"), ("qname", "dns.qry.name"), ("qtype", "dns.qry.type"), ("rcode", "dns.flags.rcode"),
                                ("dtime", "dns.time"), ("resp_in", "dns.response_in"), ("resp_to", "dns.response_to"), ("a", "dns.a"), ("aaaa", "dns.aaaa"), ("cname", "dns.cname")], two_pass=True)
    df["is_resp"] = truthy(df["resp"])
    df["qname1"] = first(df["qname"])
    df["qtype_name"] = numeric(df["qtype"]).map(lambda v: QTYPE.get(int(v), f"type {int(v)}") if v == v else "")
    df["rcode_name"] = numeric(df["rcode"]).map(lambda v: RCODE.get(int(v), f"rcode {int(v)}") if v == v else "")
    df["answers"] = (df["a"] + ";" + df["aaaa"] + ";" + df["cname"]).str.replace(r";+", ", ", regex=True).str.strip(", ")
    df["latency_ms"] = numeric(df["dtime"]) * 1000
    df["transaction_id"] = first(df["dns_id"])
    df["transport"] = df["chain"].apply(lambda c: "TCP" if ":tcp:" in c else ("UDP" if ":udp:" in c else ""))
    q, r = df[~df["is_resp"]], df[df["is_resp"]]
    resp_by_no = r.set_index("no")
    rows = []
    for x in q.itertuples():
        rn = pd.to_numeric(first(pd.Series([x.resp_in])), errors="coerce").iloc[0]
        rr = resp_by_no.loc[int(rn)] if rn == rn and int(rn) in resp_by_no.index else None
        rows.append({"query_no": x.no, "response_no": int(rn) if rr is not None else None, "time_s": x.rel_time, "transaction_id": x.transaction_id, "client": x.src, "server": x.dst,
                     "name": x.qname1, "type": x.qtype_name, "transport": x.transport, "rcode": rr["rcode_name"] if rr is not None else "", "answers": rr["answers"] if rr is not None else "",
                     "latency_ms": rr["latency_ms"] if rr is not None else None, "status": "Answered" if rr is not None else "No response"})
    for x in r[first(r["resp_to"]) == ""].itertuples():
        rows.append({"query_no": None, "response_no": x.no, "time_s": x.rel_time, "transaction_id": x.transaction_id, "client": x.dst, "server": x.src, "name": x.qname1, "type": x.qtype_name,
                     "transport": x.transport, "rcode": x.rcode_name, "answers": x.answers, "latency_ms": x.latency_ms, "status": "Response without query"})
    cols = ["query_no", "response_no", "time_s", "transaction_id", "client", "server", "name", "type", "transport", "rcode", "answers", "latency_ms", "status"]
    tx = pd.DataFrame(rows, columns=cols).sort_values("time_s")
    tx["click"] = tx["query_no"].fillna(tx["response_no"]).astype("Int64")
    unanswered = int((tx["status"] == "No response").sum())
    lat = stats(tx["latency_ms"])
    nx = int((tx["rcode"] == "NXDOMAIN").sum())
    metrics = [
        metric("Queries", int(len(q)), basis="observed"), metric("Responses", int(len(r)), basis="observed"),
        metric("Unanswered queries", unanswered, sub=f"{100 * unanswered / max(len(q), 1):.0f}% of queries",
               tip="Queries with no response (dns.response_in absent). Reliable only if the capture covers the whole exchange; it may also mean the capture ended early.", basis="observed"),
        metric("Response time min", lat["min"] if lat else None, fmt="ms", tip="dns.time: query → response, measured at the capture point.", why="No answered query/response pairs.", basis="observed"),
        metric("Response time average", lat["avg"] if lat else None, fmt="ms", why="No answered query/response pairs.", basis="observed"),
        metric("Response time p95", lat["p95"] if lat else None, fmt="ms", why="No answered query/response pairs."),
        metric("Response time max", lat["max"] if lat else None, fmt="ms", why="No answered query/response pairs.", basis="observed"),
        metric("Unique domains", int(q["qname1"].nunique())),
    ]
    lt = tx[tx["latency_ms"].notna()]
    charts = {c["id"]: c for c in clean([
        over_time("dns_time", "DNS packets over time", df["rel_time"]),
        counts_chart("dns_qtype", "Query types", q["qtype_name"], "bar", tip="A = IPv4 address, AAAA = IPv6, HTTPS/SVCB = service binding, PTR = reverse lookup, …"),
        counts_chart("dns_top", "Top queried domains", q["qname1"], "barh"),
        histogram("dns_lat", "Response time distribution", tx["latency_ms"], unit="ms", x_label="ms"),
        chart("dns_lat_time", "Response time per answered query", "line", series=[{"name": "ms", "data": [float(v) for v in lt["latency_ms"]]}], x=[float(v) for v in lt["time_s"]],
              unit="ms", x_label="time of query (s)", y_label="response time") if len(lt) else None,
    ])}
    tables = {"transactions": table("transactions", "DNS transactions", tx, [
        ("query_no", "Query #", "num", True), ("response_no", "Resp #", "num", True), ("time_s", "Time (s)", "sec", True), ("transaction_id", "Txn ID", "text", False),
        ("client", "Client", "text", False), ("server", "Server", "text", False), ("name", "Name", "text", False), ("type", "Type", "text", False), ("transport", "Transport", "text", False),
        ("rcode", "Result", "text", False), ("answers", "Answers", "text", False), ("latency_ms", "Response time", "ms", True), ("status", "Status", "text", False)],
        tip="One row per query, joined to its response by Wireshark. Click a row to inspect the packet.", click="click")}
    sections = [{"id": "summary", "title": "Summary", "metrics": "all", "charts": ["dns_time"]},
                {"id": "qr", "title": "Queries/Responses", "tables": ["transactions"]},
                {"id": "rt", "title": "Response Time", "charts": ["dns_lat", "dns_lat_time"]},
                {"id": "domains", "title": "Domains/Types", "charts": ["dns_top", "dns_qtype"]}]
    detail = {
        "key": "dns", "label": "DNS", "filter": "dns",
        "summary": f"{pl(len(q), 'query', 'queries')} and {pl(len(r), 'response')}; {unanswered} unanswered" + (f"; average response time {lat['avg']:.1f} ms." if lat else "."),
        "card": [pl(len(q), "query", "queries"), f"{unanswered} unanswered", f"avg {lat['avg']:.1f} ms" if lat else "response time n/a"],
        "insight": {"text": f"{unanswered} DNS quer{'y' if unanswered == 1 else 'ies'} with no response" + (f", {nx} NXDOMAIN" if nx else ""), "tone": "bad" if unanswered else "ok"},
        "metrics": metrics, "charts": list(charts.values()), "tables": list(tables.values()), "sections": sections,
        "notes": ["Response time is measured at the capture point, not at the client.", "An unanswered query can also mean the capture ended before the response arrived."],
    }
    return detail, df
