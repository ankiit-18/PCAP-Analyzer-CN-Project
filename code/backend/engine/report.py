"""Orchestration + the unified report. `analyze()` is the single entry point used by the backend AND the notebooks."""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import pandas as pd

from . import capture, dhcp, dns, generic, http, icmp, ip, rtp, tcp as tcpmod, tls, udp
from .config import ENGINE_VERSION, Limits
from .context import Context
from .detect import detect
from .extract import extract_packets
from .tshark import Tshark
from .util import jsonable, records

ANALYZERS = {"ip": ip.analyze, "udp": udp.analyze, "dns": dns.analyze, "http": http.analyze, "tls": tls.analyze, "icmp": icmp.analyze, "dhcp": dhcp.analyze, "rtp": rtp.analyze}


@dataclass
class Report:
    meta: dict
    summary: dict
    hierarchy: pd.DataFrame
    endpoints: pd.DataFrame
    packets: pd.DataFrame
    tcp: tcpmod.TcpResult
    detected: list
    details: dict = field(default_factory=dict)          # key -> protocol page description
    views: dict = field(default_factory=dict)            # key -> packet DataFrame for packet inspection
    warnings: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    ctx: Context | None = None
    raw: dict = field(default_factory=dict)

    # ---- lazy generic protocols (ARP, NTP, QUIC, ...) ----------------------------------------------------------
    def protocol(self, key: str) -> dict | None:
        if key in self.details:
            return self.details[key]
        d = next((d for d in self.detected if d["key"] == key and d.get("other")), None)
        if d is None:
            return None
        self.details[key], self.views[key] = generic.analyze(self.ctx, key[2:], d["label"])
        return self.details[key]


def analyze(path: str, limits: Limits | None = None, progress=None, filename: str | None = None, tshark: Tshark | None = None) -> Report:
    """Validate and analyse a capture. Raises engine.errors.EngineError subclasses (message is safe to show users)."""
    say = progress or (lambda *_: None)
    limits = limits or Limits()
    ts = tshark or Tshark(limits)
    ts.require()
    t0 = time.monotonic()
    ts.start_clock()
    kind = capture.validate_capture(path, limits)

    say("1/5 capture totals, protocol hierarchy, IP endpoints (tshark -z)")
    totals = capture.totals(ts, path)
    hier, raw_phs = capture.hierarchy(ts, path)
    endpoints = capture.endpoints(ts, path, "ip")

    say("2/5 packet extraction (tshark -T fields)")
    ex = extract_packets(ts, path, totals["packets"])
    df = ex.packets

    say("3/5 TCP analysis")
    tcp_res = tcpmod.analyze(df)
    ctx = Context(ts=ts, path=path, limits=limits, packets=df, totals=totals, tcp=tcp_res, partial=ex.partial, max_packets=ex.limit if ex.partial else 0)

    say("4/5 protocol analyzers")
    detected = detect(ctx)
    keys = {d["key"] for d in detected}
    jobs = {"ip": ANALYZERS["ip"]}
    jobs.update({k: ANALYZERS[k] for k in ("udp", "dns", "http", "tls", "icmp", "dhcp", "rtp") if k in keys})
    details, views, warnings = {}, {}, []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = {k: pool.submit(fn, ctx) for k, fn in jobs.items()}
        for k, f in futs.items():
            try:
                details[k], views[k] = f.result()
            except Exception as e:                           # one failing analyzer must not break the whole report
                if type(e).__module__.startswith("engine") and hasattr(e, "status"):
                    raise
                warnings.append({"level": "error", "code": f"analyzer_failed:{k}", "message": f"The {k.upper()} analysis failed and is unavailable ({type(e).__name__}: {e})."})

    say("5/5 summary")
    s = tcp_res.summary
    dur = totals.get("duration_s") or 0.0
    summary = {
        "packets": totals["packets"] or len(df), "bytes": totals["bytes"] or int(df["length"].sum()), "duration_s": dur,
        "avg_packet_size": (totals["bytes"] / totals["packets"]) if totals["packets"] else None,
        "avg_throughput_bps": (totals["bytes"] * 8 / dur) if dur else None, "avg_pps": (totals["packets"] / dur) if dur else None,
        "tcp_packets": s.get("tcp_packets", 0), "tcp_flows": s.get("tcp_flows", 0), "flows": s.get("tcp_flows", 0),
        **{k: s.get(k) for k in ("retransmissions", "fast_retransmissions", "spurious_retransmissions", "out_of_order", "dup_acks", "seq_gaps", "lost_segments", "zero_windows", "resets",
                                "rtt_samples", "rtt_min_ms", "rtt_avg_ms", "rtt_p95_ms", "rtt_max_ms", "rtt_ts_samples", "rtt_ts_avg_ms", "flows_with_issues")},
    }
    for k in ("retransmissions", "out_of_order", "dup_acks", "seq_gaps", "flows_with_issues", "rtt_samples", "zero_windows", "resets"):
        summary[k] = summary[k] or 0

    if ex.partial:
        warnings.append({"level": "warning", "code": "partial_analysis", "message":
                         f"Partial analysis: packet-level metrics (flows, TCP analysis, protocol pages) use the first {ex.processed:,} of {totals['packets']:,} packets "
                         f"(MAX_EXTRACTED_PACKETS={ex.limit:,}). Capture totals, the protocol hierarchy and endpoint statistics cover the whole file."})
    if ts.unavailable:
        warnings.append({"level": "info", "code": "fields_unavailable", "message":
                         f"This tshark version does not provide {len(ts.unavailable)} field(s); related metrics are unavailable: {', '.join(sorted(ts.unavailable))}."})
    if not df["is_tcp"].any():
        warnings.append({"level": "info", "code": "no_tcp", "message": "This capture contains no TCP traffic, so the TCP pages have nothing to show."})

    meta = {"file": filename or os.path.basename(path), "format": kind, "file_size_bytes": os.path.getsize(path), "tshark": ts.version}
    metadata = {"engine_version": ENGINE_VERSION, "tshark_version": ts.version, "analysis_scope": "partial" if ex.partial else "full", "partial": ex.partial,
                "total_packets": totals["packets"], "packets_processed": ex.processed, "extraction_limit": ex.limit or None,
                "limits": {"max_pcap_size_mb": limits.max_pcap_size_mb, "max_analysis_seconds": limits.max_analysis_seconds, "max_extracted_packets": limits.max_extracted_packets},
                "elapsed_s": round(time.monotonic() - t0, 2), "unavailable_fields": sorted(ts.unavailable),
                "basis": {"observed": "dissected directly by tshark", "derived": "aggregated or calculated by the engine from observed fields", "inferred": "cautious interpretation, not proof"}}
    return Report(meta, summary, hier, endpoints, df, tcp_res, detected, details, views, warnings, metadata, ctx, {"totals": totals["raw"], "phs": raw_phs})


# --------------------------------------------------------------------------------------------------------------
# unified, JSON-safe report
# --------------------------------------------------------------------------------------------------------------
def _tcp_dict(r: Report) -> dict:
    t = r.tcp
    return {
        "summary": t.summary, "flows": t.flows, "findings": t.findings,
        "rtt": {"ack_based": t.rtt_ack, "handshake": t.rtt_initial, "timestamp_echo": t.rtt_ts},
        "options": t.options, "options_by_direction": t.options_dir, "flow_control": t.window_dir, "congestion_indicators": t.congestion,
    }


def to_dict(r: Report, include_tcp_details: bool = True) -> dict:
    """The unified report: compatible with earlier fields (meta, summary, protocol_hierarchy, endpoints, flows, findings, rtt_samples)
    plus protocols / tcp / ip / udp / icmp / dns / http / tls / dhcp / rtp / warnings / analysis_metadata. Never contains DataFrames."""
    t = r.tcp
    out = {
        "meta": r.meta, "summary": r.summary, "protocol_hierarchy": r.hierarchy, "endpoints": r.endpoints,
        "flows": t.flows, "findings": t.findings, "rtt_samples": t.rtt_ack,
        "protocols": r.detected,
        "tcp": _tcp_dict(r) if include_tcp_details else {"summary": t.summary},
        "warnings": r.warnings, "analysis_metadata": r.metadata,
    }
    for k in ("ip", "udp", "icmp", "dns", "http", "tls", "dhcp", "rtp"):
        out[k] = r.details.get(k)
    return jsonable(out)
