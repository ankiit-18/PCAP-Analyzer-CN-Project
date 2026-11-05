"""Per-flow / per-capture TCP views built from a Report (used by the API and the notebooks). All values are JSON-safe."""
from __future__ import annotations

import numpy as np
import pandas as pd

from .charts import bin_width, chart
from .report import Report
from .tcp import C2S, CAVEAT, S2C
from .util import jsonable, records, stats, thin

COND = {  # packet-table filter conditions -> boolean column / expression
    "retransmission": lambda d: d["retransmission"] | d["fast_retransmission"], "fast_retransmission": lambda d: d["fast_retransmission"],
    "spurious_retransmission": lambda d: d["spurious_retransmission"], "dup_ack": lambda d: d["duplicate_ack"], "out_of_order": lambda d: d["out_of_order"],
    "zero_window": lambda d: d["zero_window"] | ((d["win_raw"] == 0) & ~d["syn"] & ~d["rst"]), "zero_window_probe": lambda d: d["zero_window_probe"],
    "window_update": lambda d: d["window_update"], "window_full": lambda d: d["window_full"], "lost_segment": lambda d: d["lost_segment"] | d["ack_lost_segment"],
    "ecn": lambda d: d["ece"] | d["cwr"] | (d["ecn"] == 3),
}


def _tcp(r: Report, flow: int | None = None) -> pd.DataFrame:
    d = r.packets[r.packets["is_tcp"]]
    return d if flow is None else d[d["tcp_stream"] == flow]


def has_flow(r: Report, flow: int) -> bool:
    return len(r.tcp.flows) > 0 and bool((r.tcp.flows["flow"] == flow).any())


# ---- RTT (three separately labelled methods) -------------------------------------------------------------------
def rtt(r: Report, flow: int | None = None, cap: int = 20000) -> dict:
    t = r.tcp
    sel = (lambda d: d if flow is None else d[d["flow"] == flow])
    ack, ini, ts = sel(t.rtt_ack), sel(t.rtt_initial), sel(t.rtt_ts)
    st = lambda d: stats(d["rtt"] * 1000) if len(d) else None
    pts = lambda d, x="rel_time": [[round(float(a), 6), round(float(b) * 1000, 4), int(f)] for a, b, f in zip(d[x], d["rtt"], d["flow"])]
    methods = [
        {"id": "ack", "label": "ACK-based RTT", "basis": "observed", "field": "tcp.analysis.ack_rtt", "stats_ms": st(ack),
         "description": "Time from a data segment to the ACK that covers it (Wireshark). Retransmitted segments are excluded (Karn).", "points": pts(thin(ack, cap))},
        {"id": "timestamp", "label": "TCP timestamp-echo RTT", "basis": "derived", "field": "tcp.options.timestamp.tsval / tsecr", "stats_ms": st(ts),
         "description": "Engine-derived: a packet's TSval is matched with the first packet from the other side that echoes it in TSecr (direction-aware; TSval/TSecr=0 ignored; "
                        "each value used once; only flows with timestamps on both sides). Delayed ACKs can inflate samples.", "points": pts(thin(ts, cap))},
        {"id": "handshake", "label": "Initial (handshake) RTT", "basis": "observed", "field": "tcp.analysis.initial_rtt", "stats_ms": st(ini),
         "description": "SYN → SYN/ACK → ACK timing at the capture point (Wireshark). One value per flow whose handshake was captured.", "points": pts(ini)},
    ]
    for m in methods:
        m["available"] = m["stats_ms"] is not None
        if not m["available"]:
            m["reason"] = {"ack": "No data/ACK pairs that Wireshark could time (one-sided capture, or only retransmitted data).",
                           "timestamp": "TCP timestamps were not negotiated/observed in both directions, so timestamp-echo RTT cannot be calculated.",
                           "handshake": "The three-way handshake was not captured (flows start mid-stream)."}[m["id"]]
    return {"flow": flow, "methods": methods, "per_flow": records(_per_flow_rtt(r, flow)),
            "note": "The three methods measure different things and are never combined: ACK-based and timestamp-echo RTT describe the path between the capture point and one end."}


def _per_flow_rtt(r: Report, flow: int | None) -> pd.DataFrame:
    t = r.tcp
    f = t.flows if flow is None else t.flows[t.flows["flow"] == flow]
    if f.empty:
        return pd.DataFrame()
    ts = t.rtt_ts.groupby("flow")["rtt"].agg(ts_samples="count", ts_min_ms=lambda s: s.min() * 1e3, ts_avg_ms=lambda s: s.mean() * 1e3, ts_max_ms=lambda s: s.max() * 1e3,
                                              ts_std_ms=lambda s: s.std(ddof=0) * 1e3)
    out = f[["flow", "client", "server", "handshake_rtt_ms", "rtt_samples", "rtt_min_ms", "rtt_avg_ms", "rtt_max_ms", "rtt_std_ms"]].set_index("flow").join(ts).reset_index()
    out["ts_samples"] = out["ts_samples"].fillna(0).astype(int)
    return out


# ---- flow control ----------------------------------------------------------------------------------------------
def flow_control(r: Report, flow: int | None = None, cap: int = 5000) -> dict:
    wd = r.tcp.window_dir
    wd = wd if flow is None or wd.empty else wd[wd["flow"] == flow]
    out = {"flow": flow, "directions": records(wd),
           "note": "Advertised receive window (rwnd) is the receiver's flow-control limit. It is NOT the congestion window (cwnd), which a capture cannot show.",
           "series": None, "events": []}
    if flow is None:
        return out
    d = _tcp(r, flow)
    d = d[~d["syn"] & d["win_raw"].notna()]
    series = {}
    for role in (C2S, S2C):
        g = d[d["role"] == role]
        g = thin(g, cap, g["zero_window"] | g["window_update"])
        series[role] = {"raw": [[round(a, 6), float(b)] for a, b in zip(g["rel_time"], g["win_raw"])], "effective": [[round(a, 6), float(b)] for a, b in zip(g["rel_time"], g["eff_win"])],
                        "wireshark": [[round(a, 6), float(b)] for a, b in zip(g["rel_time"], g["win"].fillna(np.nan)) if b == b],
                        "status": g["win_status"].iloc[0] if len(g) else "", "direction": "client → server" if role == C2S else "server → client"}
    out["series"] = series
    ev = d[d["zero_window"] | d["zero_window_probe"] | d["zero_window_probe_ack"] | d["window_update"] | d["window_full"] | ((d["win_raw"] == 0))]
    kind = np.select([ev["zero_window"] | (ev["win_raw"] == 0), ev["zero_window_probe"], ev["zero_window_probe_ack"], ev["window_update"], ev["window_full"]],
                     ["zero window", "zero-window probe", "probe ACK", "window update", "window full"], "")
    out["events"] = records(ev.assign(kind=kind, direction_label=ev["role"].map({C2S: "client → server", S2C: "server → client"}))[["no", "rel_time", "direction_label", "kind", "eff_win", "win_status"]].rename(columns={"no": "packet_no"}))
    return out


# ---- congestion indicators -----------------------------------------------------------------------------------------
def congestion(r: Report, flow: int | None = None, cap: int = 5000) -> dict:
    c = r.tcp.congestion
    rows = c if flow is None or c.empty else c[c["flow"] == flow]
    d = _tcp(r, flow)
    out = {"flow": flow, "caveat": CAVEAT, "flows": jsonable(rows), "charts": [], "ecn_events": [], "assessment_counts": {}}
    if not rows.empty:
        out["assessment_counts"] = rows["assessment"].value_counts().to_dict()
    if d.empty:
        return out
    dur = float(d["rel_time"].max() - d["rel_time"].min()) or float(d["rel_time"].max()) or 1.0
    bw = bin_width(max(dur, 1e-3))
    t0 = float(d["rel_time"].min())
    idx = ((d["rel_time"] - t0) // bw).astype(int)
    n = int(idx.max()) + 1
    x = [round(t0 + i * bw, 6) for i in range(n)]
    per = lambda mask: [int(v) for v in idx[mask].value_counts().reindex(range(n), fill_value=0).sort_index().values]
    out["charts"].append(chart("cg_retx", "Retransmissions and duplicate ACKs over time", "line", series=[
        {"name": "retransmissions", "data": per(d["retransmission"] | d["fast_retransmission"])}, {"name": "duplicate ACKs", "data": per(d["duplicate_ack"])},
        {"name": "out-of-order", "data": per(d["out_of_order"])}], x=x, unit="count", tip=f"Wireshark flags per time bin (bin = {bw:g} s). Observed.", x_label="time (s)", y_label="packets"))
    thr = lambda mask: [round(float(v) * 8 / bw, 1) for v in d.loc[mask, "length"].groupby(idx[mask]).sum().reindex(range(n), fill_value=0).sort_index().values]
    out["charts"].append(chart("cg_thr", "Throughput over time", "line", series=[{"name": "client → server", "data": thr(d["role"] == C2S)}, {"name": "server → client", "data": thr(d["role"] == S2C)}],
                                x=x, unit="bps", tip=f"Frame bytes × 8 ÷ {bw:g} s (derived). Throughput dips can indicate loss recovery, but also idle application periods.", x_label="time (s)", y_label="bits per second"))
    bif = d[d["bytes_in_flight"].notna()]
    if len(bif):
        out["charts"].append({**chart("cg_bif", "Bytes in flight", "scatter", unit="bytes", tip="tcp.analysis.bytes_in_flight (Wireshark): unacknowledged data as seen at the capture point. This is NOT cwnd - it is bounded by cwnd and rwnd but not equal to either.",
                                      x_label="time (s)", y_label="bytes"),
                              "series": [{"name": ("client → server" if role == C2S else "server → client"), "points": [[round(a, 6), float(b)] for a, b in zip(thin(g, cap)["rel_time"], thin(g, cap)["bytes_in_flight"])]}
                                         for role, g in bif.groupby("role")]})
    t = r.tcp
    sel = (lambda df: df if flow is None else df[df["flow"] == flow])
    ack = sel(t.rtt_ack)
    series = []
    if len(ack):
        a = thin(ack, cap)
        series.append({"name": "ACK-based (observed)", "points": [[round(x_, 6), round(y * 1000, 4)] for x_, y in zip(a["rel_time"], a["rtt"])]})
    if series:
        out["charts"].append({**chart("cg_rtt", "RTT trend", "scatter", unit="ms", tip="RTT growth together with loss indicators can hint at queueing; on its own it proves nothing.", x_label="time (s)", y_label="RTT"), "series": series})
    ecn = d[(~d["syn"]) & (d["ece"] | d["cwr"] | (d["ecn"] == 3))]
    if len(ecn):
        kind = np.select([ecn["ecn"] == 3, ecn["ece"], ecn["cwr"]], ["CE-marked packet", "ECE echo", "CWR"], "")
        out["ecn_events"] = records(ecn.assign(kind=kind)[["no", "rel_time", "tcp_stream", "role", "kind"]].rename(columns={"no": "packet_no", "tcp_stream": "flow"}).head(2000))
        out["charts"].append(chart("cg_ecn", "ECN events over time", "line", series=[
            {"name": "CE-marked", "data": per(d["ecn"] == 3)}, {"name": "ECE echoes", "data": per(d["ece"] & ~d["syn"])}, {"name": "CWR", "data": per(d["cwr"] & ~d["syn"])}], x=x, unit="count",
            tip="CE = a router marked the packet; ECE = the receiver echoes it; CWR = the sender reports it reduced its rate. Observed header bits.", x_label="time (s)", y_label="packets"))
    return jsonable(out)


# ---- options -------------------------------------------------------------------------------------------------------
def options(r: Report, flow: int | None = None) -> dict:
    t = r.tcp
    o = t.options if flow is None or t.options.empty else t.options[t.options["flow"] == flow]
    od = t.options_dir if flow is None or t.options_dir.empty else t.options_dir[t.options_dir["flow"] == flow]
    return jsonable({"flow": flow, "flows": o, "by_direction": od,
                     "note": "Negotiated = both SYN and SYN/ACK carried the option. Without a captured handshake the negotiation result is unknown. "
                             "'Observed later' counts packets after the handshake (SACK blocks, timestamps)."})


# ---- packet table ------------------------------------------------------------------------------------------------
def _opts(row) -> str:
    parts = []
    if row.syn:
        if row.mss == row.mss: parts.append(f"MSS={int(row.mss)}")
        if row.wscale == row.wscale: parts.append(f"WS={int(row.wscale)}")
        if row.sack_perm: parts.append("SACK_PERM")
    if row.tsval == row.tsval or row.tsecr == row.tsecr:
        parts.append(f"TS(val={int(row.tsval) if row.tsval == row.tsval else '-'},ecr={int(row.tsecr) if row.tsecr == row.tsecr else '-'})")
    if row.sack_le:
        parts.append("SACK[" + "; ".join(f"{a}-{b}" for a, b in zip(row.sack_le.split(";"), row.sack_re.split(";"))) + "]")
    return " ".join(parts)


def packets(r: Report, flow: int | None = None, conds: list[str] | None = None, offset: int = 0, limit: int = 100, only_flagged: bool = False) -> dict:
    d = _tcp(r, flow)
    if only_flagged:
        d = d[d["tags"] != ""]
    wanted = [c for c in (conds or []) if c in COND]
    if wanted:                                   # a packet is shown if it matches ANY selected condition
        mask = pd.Series(False, index=d.index)
        for c in wanted:
            mask = mask | COND[c](d)
        d = d[mask]
    total = len(d)
    page = d.iloc[offset:offset + limit]
    cols = ["no", "time", "rel_time", "tcp_stream", "direction", "src", "sport", "dst", "dport", "flags", "seq", "ack", "tcp_len", "win_raw", "eff_win", "win_status", "length", "ack_rtt",
            "acks_frame", "tags", "exp_msg"]
    out = page[cols].rename(columns={"no": "packet_no", "time": "epoch", "rel_time": "time_s", "tcp_stream": "flow", "tcp_len": "payload", "win_raw": "window", "eff_win": "effective_window",
                                     "exp_msg": "wireshark_message"}).copy()
    out["options"] = [_opts(x) for x in page.itertuples()]
    out["flow"] = out["flow"].astype(int)
    return {"total": int(total), "offset": offset, "rows": records(out)}
