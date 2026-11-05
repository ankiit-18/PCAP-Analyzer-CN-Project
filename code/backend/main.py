"""
FastAPI backend for the PCAP analyzer. All analysis lives in the `engine` package (TShark-based); this file only exposes it over HTTP.

  GET    /api/health
  POST   /api/upload                          upload + validate (.pcap/.pcapng, MAX_PCAP_SIZE_MB)
  POST   /api/analyze/{id}                    run the engine (limits: MAX_ANALYSIS_SECONDS, MAX_EXTRACTED_PACKETS)
  DELETE /api/reports/{id}

  GET    /api/reports/{id}                    TCP report (compatible with earlier versions) + warnings + analysis_metadata
  GET    /api/reports/{id}/overview           overview page: capture facts, distribution, protocol cards, highlights
  GET    /api/reports/{id}/export             the unified JSON report (?download=1 to save as a file)
  GET    /api/reports/{id}/validation         Wireshark/TShark cross-validation table

  GET    /api/reports/{id}/indicators         TCP indicators (all flows, or ?flow=N)
  GET    /api/reports/{id}/flows/{flow}       per-flow drill-down (stats + flagged packets)
  GET    /api/reports/{id}/flows/{flow}/packets
  GET    /api/reports/{id}/tcp/rtt|flow-control|congestion|options      (?flow=N optional)
  GET    /api/reports/{id}/tcp/packets        all-flow packet inspection (?flow=, ?cond=retransmission&cond=zero_window, paging)

  GET    /api/reports/{id}/protocols/{key}                detail page (ip udp dns http tls icmp dhcp rtp x:<other>)
  GET    /api/reports/{id}/protocols/{key}/packets        paged packets (?q=, IP filters f_src, f_dst, f_version, ...)
  GET    /api/reports/{id}/ip/{address}                   one IP address: protocols, services, peers, conversations, traffic
  GET    /api/reports/{id}/packets/{no}/decode            full Wireshark decode of one packet
"""
from __future__ import annotations

import os
import threading
import time
import uuid
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

import engine
from engine import ip as ip_mod, tcp_views as tv
from engine.capture import validate_capture
from engine.config import Limits
from engine.detect import DETAIL_PAGES
from engine.errors import EngineError
from engine.extract import ANALYSIS
from engine.tshark import Tshark
from engine.util import jsonable, pl, records, thin

BASE = Path(__file__).parent
DATA_DIR = BASE / "data"
DATA_DIR.mkdir(exist_ok=True)
LIMITS = Limits()
MAX_AGE_S = int(os.getenv("CAPTURE_TTL_HOURS", "24")) * 3600

app = FastAPI(title="PCAP Analyzer API", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])

SESSIONS: dict[str, dict] = {}
SLOTS = threading.Semaphore(2)          # at most two analyses at a time (each one runs several tshark processes)


@app.exception_handler(EngineError)
async def engine_error(_: Request, e: EngineError):
    return JSONResponse(status_code=e.status, content={"detail": str(e)})


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _cleanup_old() -> None:
    now = time.time()
    for p in DATA_DIR.glob("*.pcap*"):
        if now - p.stat().st_mtime > MAX_AGE_S:
            p.unlink(missing_ok=True)
    for sid in [s for s, v in SESSIONS.items() if now - v["created"] > MAX_AGE_S]:
        SESSIONS.pop(sid, None)


def _session(sid: str) -> dict:
    s = SESSIONS.get(sid)
    if not s:
        raise HTTPException(404, "Unknown capture id (the server may have restarted). Upload the file again.")
    return s


def _rep(sid: str) -> engine.Report:
    rep = _session(sid).get("report")
    if rep is None:
        raise HTTPException(409, "This capture has not been analyzed yet. Call POST /api/analyze/{id} first.")
    return rep


def _flow(rep: engine.Report, flow: int) -> None:
    if not tv.has_flow(rep, flow):
        raise HTTPException(404, f"TCP flow {flow} not found.")


def _tag_counts(findings: pd.DataFrame) -> dict[str, int]:
    out = {t: 0 for t in ANALYSIS}
    if len(findings):
        for t, n in findings["tags"].str.split(",").explode().value_counts().items():
            out[t] = int(n)
    return out


# --------------------------------------------------------------------------
# upload / analyze
# --------------------------------------------------------------------------
@app.get("/api/health")
def health():
    ts = Tshark(LIMITS)
    lim = {"max_upload_mb": LIMITS.max_pcap_size_mb, "max_analysis_seconds": LIMITS.max_analysis_seconds, "max_extracted_packets": LIMITS.max_extracted_packets}
    try:
        ts.require()
        return {"ok": True, "tshark": ts.version, "engine": engine.ENGINE_VERSION, **lim}
    except EngineError as e:
        return {"ok": False, "error": str(e), **lim}


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    _cleanup_old()
    sid = uuid.uuid4().hex[:12]
    suffix = ".pcapng" if (file.filename or "").lower().endswith("pcapng") else ".pcap"
    path = DATA_DIR / f"{sid}{suffix}"
    size = 0
    try:
        with open(path, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if LIMITS.max_pcap_size_mb and size > LIMITS.max_pcap_bytes:
                    raise HTTPException(413, f"The file is larger than the {LIMITS.max_pcap_size_mb} MB limit (MAX_PCAP_SIZE_MB).")
                out.write(chunk)
        kind = validate_capture(str(path), LIMITS)
    except (HTTPException, EngineError):
        path.unlink(missing_ok=True)
        raise
    except Exception as e:
        path.unlink(missing_ok=True)
        raise HTTPException(500, f"Upload failed: {e}")
    SESSIONS[sid] = {"path": str(path), "filename": file.filename, "size": size, "format": kind, "created": time.time(), "report": None}
    return {"id": sid, "filename": file.filename, "size": size, "format": kind}


@app.post("/api/analyze/{sid}")
def analyze(sid: str):
    s = _session(sid)
    t0 = time.time()
    with SLOTS:
        rep = engine.analyze(s["path"], LIMITS, filename=s["filename"])
    s["report"] = rep
    return {"id": sid, "elapsed_s": round(time.time() - t0, 2), "partial": rep.metadata["partial"], "warnings": len(rep.warnings)}


@app.delete("/api/reports/{sid}")
def delete(sid: str):
    s = SESSIONS.pop(sid, None)
    if s:
        Path(s["path"]).unlink(missing_ok=True)
    return {"deleted": bool(s)}


# --------------------------------------------------------------------------
# report / overview / export / validation
# --------------------------------------------------------------------------
@app.get("/api/reports/{sid}")
def get_report(sid: str):
    r = _rep(sid)
    rtt = thin(r.tcp.rtt_ack, LIMITS.sample_cap)
    return jsonable({
        "meta": r.meta, "summary": r.summary, "hierarchy": r.hierarchy, "endpoints": r.endpoints, "flows": r.tcp.flows,
        "rtt_samples": rtt.round(6), "rtt_total": int(len(r.tcp.rtt_ack)),
        "indicator_counts": _tag_counts(r.tcp.findings), "flagged_packets": int(len(r.tcp.findings)),
        "warnings": r.warnings, "analysis_metadata": r.metadata,
    })


# hierarchy protocol name -> detail page key (only these have a page)
_PAGE_OF = {"tcp": "tcp", "udp": "udp", "dns": "dns", "tls": "tls", "quic": "x:quic", "arp": "x:arp"}
# protocols that are analysed only to give a one-line summary on the overview (no page)
_SUMMARY_OF = {"http": "http", "icmp": "icmp", "dhcp": "dhcp", "bootp": "dhcp", "rtp": "rtp"}


@app.get("/api/reports/{sid}/overview")
def overview(sid: str):
    r = _rep(sid)
    s = _session(sid)
    sm, ipd, udpd = r.summary, r.details.get("ip"), r.details.get("udp")
    udp_conv = udpd["tables"][0]["total"] if udpd and udpd["tables"] else 0

    # cards (clickable, with a detail page): TCP, UDP, DNS, TLS, QUIC, ARP - only those present
    cards = []
    for d in r.detected:
        if not d.get("detail"):
            continue
        card, key = dict(d), d["key"]
        if key == "tcp":
            card["lines"] = [pl(sm["tcp_flows"], "flow"), pl(sm["retransmissions"], "retransmission"), pl(sm["flows_with_issues"], "flow") + " with issues"]
        elif key in r.details:
            card["lines"] = [x for x in r.details[key]["card"] if x]
        else:
            card["lines"] = [pl(d["packets"], "packet")] + ([pl(d["bytes"], "byte")] if d["bytes"] else [])
        cards.append(card)

    # every protocol in the capture (from tshark -z io,phs), names merged across layers; used for the charts and the "other protocols" list
    h = r.hierarchy[r.hierarchy["protocol"] != "frame"]
    dist = h.groupby("protocol").agg(packets=("frames", "sum"), bytes=("bytes", "sum")).sort_values("packets", ascending=False).reset_index()
    total = max(int(r.hierarchy["frames"].max()) if len(r.hierarchy) else 1, 1)
    for d in r.detected:                  # RTP found only by Wireshark's heuristic is not a dissected layer in io,phs - add it so it is still counted
        if d["key"] == "rtp" and "rtp" not in set(dist["protocol"]):
            dist.loc[len(dist)] = {"protocol": "rtp", "packets": d["packets"], "bytes": d["bytes"] or (int(r.views["rtp"]["length"].sum()) if "rtp" in r.views else 0)}
    dist = dist.sort_values("packets", ascending=False).reset_index(drop=True)
    dist["pct_packets"] = (100 * dist["packets"] / total).round(2)
    dist["page"] = dist["protocol"].map(_PAGE_OF)
    dist["summary"] = [[x for x in r.details[_SUMMARY_OF[p]]["card"] if x] if p in _SUMMARY_OF and _SUMMARY_OF[p] in r.details else [] for p in dist["protocol"]]
    dist["page"] = dist["page"].where(dist["page"].isin(DETAIL_PAGES) & dist["page"].isin([c["key"] for c in cards]), None)

    # highlights: clickable only when the protocol has a page
    insights = []
    if sm["tcp_flows"]:
        retx = sm["retransmissions"]
        insights.append({"page": "tcp", "tone": "bad" if retx or sm["flows_with_issues"] else "ok",
                         "text": f"{pl(retx, 'TCP retransmission')} · {sm['flows_with_issues']} of {sm['tcp_flows']} flows with issues"})
    for key, d in r.details.items():
        if key not in ("tcp", "ip") and d.get("insight"):
            insights.append({"page": key if key in DETAIL_PAGES else None, **d["insight"]})
    insights.sort(key=lambda i: {"bad": 0, "info": 1, "ok": 2}.get(i["tone"], 3))
    n_ep = next((m["value"] for m in (ipd or {}).get("metrics", []) if m["label"] == "Unique IP hosts" and m.get("available")), None)
    return jsonable({
        "capture": {"filename": s["filename"], "format": s["format"], "file_size": s["size"], "duration_s": sm["duration_s"], "packets": sm["packets"], "bytes": sm["bytes"],
                    "avg_packet_size": sm["avg_packet_size"], "packet_rate": sm["avg_pps"], "throughput_bps": sm["avg_throughput_bps"],
                    "protocol_count": len(dist), "endpoint_count": n_ep, "conversation_count": sm["tcp_flows"] + udp_conv,
                    "conversation_note": "TCP flows + UDP conversations (transport-layer). IP host pairs are on the IP Analysis page."},
        "hierarchy": r.hierarchy, "protocols": cards, "distribution": dist, "insights": insights[:6], "endpoints": r.endpoints.head(5),
        "ip": {"card": ipd["card"], "summary": ipd["summary"]} if ipd else None,
        "warnings": r.warnings, "analysis_metadata": r.metadata,
    })


@app.get("/api/reports/{sid}/export")
def export(sid: str, download: bool = False):
    data = engine.to_dict(_rep(sid))
    headers = {"Content-Disposition": 'attachment; filename="pcap_report.json"'} if download else {}
    return JSONResponse(content=data, headers=headers)


@app.get("/api/reports/{sid}/validation")
def validation(sid: str):
    s = _session(sid)
    r = _rep(sid)
    if s.get("validation") is None:
        s["validation"] = jsonable(engine.cross_validate(r, LIMITS))
    return s["validation"]


# --------------------------------------------------------------------------
# TCP
# --------------------------------------------------------------------------
@app.get("/api/reports/{sid}/indicators")
def indicators(sid: str, flow: int | None = Query(None)):
    r = _rep(sid)
    f = r.tcp.findings
    if flow is not None:
        _flow(r, flow)
        f = f[f["flow"] == flow]
    out = {"scope": "all" if flow is None else flow, "counts": _tag_counts(f), "flagged_packets": int(len(f)), "events": records(f.head(LIMITS.sample_cap).round(6)), "by_flow": []}
    if flow is None and len(f):
        by = f.assign(tag=f["tags"].str.split(",")).explode("tag").groupby(["flow", "tag"]).size().unstack(fill_value=0)
        by["total"] = by.sum(axis=1)
        out["by_flow"] = records(by.sort_values("total", ascending=False).head(15).reset_index())
    return jsonable(out)


@app.get("/api/reports/{sid}/flows/{flow}")
def flow_detail(sid: str, flow: int):
    r = _rep(sid)
    _flow(r, flow)
    g = r.packets[(r.packets["tcp_stream"] == flow) & r.packets["is_tcp"]]
    f = r.tcp.findings[r.tcp.findings["flow"] == flow]
    fl = r.tcp.flows[r.tcp.flows["flow"] == flow].iloc[0]
    return jsonable({
        "flow": fl.to_dict(), "counts": _tag_counts(f), "flagged_packets": int((g["tags"] != "").sum()), "findings": records(f.head(LIMITS.sample_cap).round(6)),
        "packets_total": int(len(g)), "role_known": bool(fl["role_known"]),
    })


@app.get("/api/reports/{sid}/flows/{flow}/packets")
def flow_packets(sid: str, flow: int, offset: int = 0, limit: int = Query(100, le=1000), flagged_only: bool = False):
    r = _rep(sid)
    _flow(r, flow)
    return jsonable(tv.packets(r, flow, [], offset, limit, only_flagged=flagged_only))


@app.get("/api/reports/{sid}/tcp/rtt")
def tcp_rtt(sid: str, flow: int | None = None):
    r = _rep(sid)
    if flow is not None:
        _flow(r, flow)
    return jsonable(tv.rtt(r, flow))


@app.get("/api/reports/{sid}/tcp/flow-control")
def tcp_flow_control(sid: str, flow: int | None = None):
    r = _rep(sid)
    if flow is not None:
        _flow(r, flow)
    return jsonable(tv.flow_control(r, flow))


@app.get("/api/reports/{sid}/tcp/congestion")
def tcp_congestion(sid: str, flow: int | None = None):
    r = _rep(sid)
    if flow is not None:
        _flow(r, flow)
    return tv.congestion(r, flow)


@app.get("/api/reports/{sid}/tcp/options")
def tcp_options(sid: str, flow: int | None = None):
    r = _rep(sid)
    if flow is not None:
        _flow(r, flow)
    return tv.options(r, flow)


@app.get("/api/reports/{sid}/tcp/packets")
def tcp_packets(sid: str, flow: int | None = None, cond: list[str] = Query(default=[]), offset: int = 0, limit: int = Query(100, le=1000)):
    r = _rep(sid)
    if flow is not None:
        _flow(r, flow)
    bad = [c for c in cond if c not in tv.COND]
    if bad:
        raise HTTPException(400, f"Unknown condition(s): {', '.join(bad)}. Valid: {', '.join(tv.COND)}")
    return jsonable(tv.packets(r, flow, cond, offset, limit))


# --------------------------------------------------------------------------
# protocol pages + IP + packet decode
# --------------------------------------------------------------------------
@app.get("/api/reports/{sid}/protocols/{key}")
def protocol_detail(sid: str, key: str):
    r = _rep(sid)
    if key not in DETAIL_PAGES and key != "ip":
        raise HTTPException(404, "There is no detail page for this protocol (detail pages: IP, TCP, UDP, DNS, TLS, QUIC, ARP). It is still counted on the overview.")
    d = r.protocol(key)
    if d is None:
        failed = next((w for w in r.warnings if w["code"] == f"analyzer_failed:{key}"), None)
        raise HTTPException(500 if failed else 404, failed["message"] if failed else f"Protocol '{key}' was not detected in this capture.")
    return jsonable(d)


@app.get("/api/reports/{sid}/protocols/{key}/packets")
def protocol_packets(sid: str, key: str, request: Request, offset: int = 0, limit: int = Query(100, le=1000), q: str = ""):
    r = _rep(sid)
    detail = protocol_detail(sid, key)
    df = r.views[key]
    if key == "ip":
        df = ip_mod.filter_packets(df, {k[2:]: v for k, v in request.query_params.items() if k.startswith("f_")})
    if q.strip():
        hay = df["src"].astype(str) + " " + df["dst"].astype(str)
        for extra in ("info", "app"):
            if extra in df.columns:
                hay = hay + " " + df[extra].astype(str)
        df = df[hay.str.lower().str.contains(q.strip().lower(), regex=False)]
    columns = detail.get("packet_columns")
    rename = {"no": "packet_no", "rel_time": "time_s"}
    cols = [c["key"] for c in columns] if columns else [c for c in ["no", "rel_time", "src", "sport", "dst", "dport", "length", "app", "info"] if c in df.columns]
    page = df.iloc[offset:offset + limit][cols].rename(columns=rename)
    return jsonable({"total": int(len(df)), "offset": offset, "rows": page, "columns": [{**c, "key": rename.get(c["key"], c["key"])} for c in columns] if columns else None})


@app.get("/api/reports/{sid}/ip/{address}")
def ip_address(sid: str, address: str):
    r = _rep(sid)
    if "ip" not in r.details:
        raise HTTPException(404, "No IP analysis available.")
    d = ip_mod.ip_detail(r.ctx, address)
    if not d:
        raise HTTPException(404, f"Address {address} was not seen in the analysed packets.")
    return jsonable(d)


@app.get("/api/reports/{sid}/packets/{no}/decode")
def packet_decode(sid: str, no: int):
    """Full Wireshark dissection of one packet (tshark -V -x). Two-pass so reassembled data is shown."""
    s = _session(sid)
    r = _rep(sid)
    out = r.ctx.ts.run(["-n", "-r", s["path"], "-2", "-Y", f"frame.number == {int(no)}", "-V", "-x"])
    if not out.strip():
        raise HTTPException(404, f"Packet {no} not found.")
    return {"packet": no, "text": out[:200_000], "truncated": len(out) > 200_000}


# --------------------------------------------------------------------------
# optionally serve the built frontend (npm run build -> frontend/dist)
# --------------------------------------------------------------------------
DIST = BASE.parent / "frontend" / "dist"
if DIST.is_dir():
    app.mount("/", StaticFiles(directory=DIST, html=True), name="frontend")
