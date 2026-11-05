"""HTTP (unencrypted only). Query strings, cookies, authorization headers and bodies are NOT extracted or shown."""
from __future__ import annotations

import pandas as pd

from .base import load_base
from .charts import chart, clean, counts_chart, histogram, metric, over_time, table
from .context import Context
from .util import first, numeric, pl, stats


def _one(v) -> str:
    return first(pd.Series([v])).iloc[0]


def analyze(ctx: Context) -> tuple[dict, pd.DataFrame]:
    df = load_base(ctx, "http", [("method", "http.request.method"), ("uri", "http.request.uri"), ("host", "http.host"), ("code", "http.response.code"),
                                 ("phrase", "http.response.phrase"), ("ctype", "http.content_type"), ("clen", "http.content_length"), ("resp_in", "http.response_in"),
                                 ("htime", "http.time")], two_pass=True)
    df["method1"] = first(df["method"])
    df["code1"] = numeric(df["code"])
    req, resp = df[df["method1"] != ""], df[df["code1"].notna()]
    resp_by_no = resp.set_index("no")
    rows = []
    for x in req.itertuples():
        rn = pd.to_numeric(first(pd.Series([x.resp_in])), errors="coerce").iloc[0]
        rr = resp_by_no.loc[int(rn)] if rn == rn and int(rn) in resp_by_no.index else None
        path = _one(x.uri).split("?")[0]
        rows.append({"request_no": x.no, "response_no": int(rn) if rr is not None else None, "time_s": x.rel_time, "client": x.src, "server": f"{x.dst}:{x.dport}",
                     "method": x.method1, "host": _one(x.host), "path": path, "status": int(rr["code1"]) if rr is not None else None,
                     "phrase": _one(rr["phrase"]) if rr is not None else "", "content_type": _one(rr["ctype"]).split(";")[0] if rr is not None else "",
                     "request_bytes": float(numeric(pd.Series([x.clen])).iloc[0]) if _one(x.clen) != "" else None,
                     "response_bytes": float(numeric(pd.Series([rr["clen"]])).iloc[0]) if rr is not None and _one(rr["clen"]) != "" else None,
                     "time_ms": float(numeric(pd.Series([rr["htime"]])).iloc[0] * 1000) if rr is not None and _one(rr["htime"]) != "" else None})
    cols = ["request_no", "response_no", "time_s", "client", "server", "method", "host", "path", "status", "phrase", "content_type", "request_bytes", "response_bytes", "time_ms"]
    tx = pd.DataFrame(rows, columns=cols)
    tx["click"] = tx["request_no"]
    unanswered = int(tx["status"].isna().sum())
    cls = (resp["code1"] // 100).astype(int).astype(str) + "xx"
    err = int((resp["code1"] >= 400).sum())
    rt = stats(tx["time_ms"])
    declared = numeric(resp["clen"]).dropna()
    metrics = [
        metric("Requests", int(len(req)), basis="observed"), metric("Responses", int(len(resp)), basis="observed"),
        metric("Unanswered requests", unanswered, tip="Requests with no response seen (http.response_in absent)."),
        metric("Error responses (4xx/5xx)", err, sub=f"{100 * err / max(len(resp), 1):.0f}% of responses"),
        metric("Response time min", rt["min"] if rt else None, fmt="ms", tip="http.time: request → first response packet, at the capture point.", why="No answered requests.", basis="observed"),
        metric("Response time average", rt["avg"] if rt else None, fmt="ms", why="No answered requests.", basis="observed"),
        metric("Response time p95", rt["p95"] if rt else None, fmt="ms", why="No answered requests."), metric("Response time max", rt["max"] if rt else None, fmt="ms", why="No answered requests.", basis="observed"),
        metric("Hosts", int(first(req["host"]).replace("", pd.NA).dropna().nunique())),
        metric("Declared response size", float(declared.sum()) if len(declared) else None, fmt="bytes", tip="Sum of Content-Length headers (declared, not measured transfer).", why="No Content-Length headers (e.g. chunked responses)."),
        metric("Request body size", float(tx["request_bytes"].sum()) if tx["request_bytes"].notna().any() else None, fmt="bytes", tip="Sum of request Content-Length headers.", why="No request bodies with Content-Length."),
        metric("HTTPS / encrypted traffic", None, why="Only unencrypted HTTP is decoded. HTTPS appears under TLS with no visible URLs or bodies."),
    ]
    paths = tx.groupby("path").agg(requests=("request_no", "size"), avg_ms=("time_ms", "mean"), errors=("status", lambda s: int((s >= 400).sum()))).sort_values("requests", ascending=False).reset_index()
    codes = resp.assign(code=resp["code1"].astype(int)).groupby("code").agg(responses=("no", "size")).reset_index()
    codes["class"] = (codes["code"] // 100).astype(str) + "xx"
    charts = {c["id"]: c for c in clean([
        over_time("http_time", "HTTP packets over time", df["rel_time"]),
        chart("http_status", "Responses by status class", "bar", list(cls.value_counts().sort_index().index), [{"name": "responses", "data": [int(v) for v in cls.value_counts().sort_index().values]}],
              tip="2xx success · 3xx redirect · 4xx client error · 5xx server error") if len(cls) else None,
        counts_chart("http_codes", "Status codes", resp["code1"].dropna().astype(int).astype(str), "bar"),
        counts_chart("http_methods", "Methods", req["method1"], "pie"), counts_chart("http_hosts", "Top hosts", first(req["host"]), "barh"),
        counts_chart("http_paths", "Top paths (query strings removed)", tx["path"], "barh"),
        counts_chart("http_ctypes", "Content types", tx["content_type"], "pie"),
        histogram("http_rt", "Response time distribution", tx["time_ms"], unit="ms", x_label="ms"),
        over_time("http_req_time", "Requests over time", req["rel_time"], name="requests"),
    ])}
    tables = {"transactions": table("transactions", "HTTP transactions", tx, [
        ("request_no", "Req #", "num", True), ("response_no", "Resp #", "num", True), ("time_s", "Time (s)", "sec", True), ("client", "Client", "text", False), ("server", "Server", "text", False),
        ("method", "Method", "text", False), ("host", "Host", "text", False), ("path", "Path", "text", False), ("status", "Status", "text", False), ("phrase", "Reason", "text", False),
        ("content_type", "Content type", "text", False), ("request_bytes", "Req size", "bytes", True), ("response_bytes", "Resp size", "bytes", True), ("time_ms", "Response time", "ms", True)],
        tip="One row per request, joined to its response. Click a row to inspect the request packet.", click="click"),
        "paths": table("paths", "Paths", paths, [("path", "Path", "text", False), ("requests", "Requests", "num", True), ("avg_ms", "Avg response time", "ms", True), ("errors", "Errors", "num", True)]),
        "codes": table("codes", "Status codes", codes, [("code", "Code", "text", False), ("class", "Class", "text", False), ("responses", "Responses", "num", True)])}
    sections = [{"id": "summary", "title": "Summary", "metrics": "all", "charts": ["http_status", "http_methods", "http_rt"]},
                {"id": "rr", "title": "Requests/Responses", "charts": ["http_req_time"], "tables": ["transactions"]},
                {"id": "status", "title": "Status Codes", "charts": ["http_codes"], "tables": ["codes"]},
                {"id": "hosts", "title": "Hosts/Paths", "charts": ["http_hosts", "http_paths", "http_ctypes"], "tables": ["paths"]}]
    detail = {
        "key": "http", "label": "HTTP", "filter": "http",
        "summary": f"{pl(len(req), 'request')}, {pl(len(resp), 'response')} ({err} errors)" + (f"; average response time {rt['avg']:.1f} ms." if rt else "."),
        "card": [pl(len(req), "request"), pl(err, "error") + " (4xx/5xx)", f"avg {rt['avg']:.0f} ms" if rt else "response time n/a"],
        "insight": {"text": f"HTTP: {pl(err, 'error response')} out of {len(resp):,}" + (f"; {unanswered} unanswered" if unanswered else ""), "tone": "bad" if err else "ok"},
        "metrics": metrics, "charts": list(charts.values()), "tables": list(tables.values()), "sections": sections,
        "notes": ["Only plain-text HTTP is decoded.", "Query strings, cookies, authorization headers and bodies are deliberately not extracted.", "Response time is measured at the capture point."],
    }
    return detail, df
