"""Per-flow / per-capture TCP views built from a Report (used by the API and the notebooks). All values are JSON-safe."""
from __future__ import annotations

import numpy as np
import pandas as pd

from .charts import bin_width, chart
from .report import Report
from .tcp import C2S, CAVEAT, S2C, retransmission_intervals
from .util import jsonable, records, stats, thin

COND = {  # packet-table filter conditions -> boolean column / expression
    "retransmission": lambda d: d["retransmission"] | d["fast_retransmission"], "fast_retransmission": lambda d: d["fast_retransmission"],
    "spurious_retransmission": lambda d: d["spurious_retransmission"], "dup_ack": lambda d: d["duplicate_ack"], "out_of_order": lambda d: d["out_of_order"],
    "zero_window": lambda d: d["zero_window"] | ((d["win_raw"] == 0) & ~d["syn"] & ~d["rst"]), "zero_window_probe": lambda d: d["zero_window_probe"],
    "window_update": lambda d: d["window_update"], "window_full": lambda d: d["window_full"],
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
           "series": None, "events": [], "fc": flow_control_events(r, flow)}
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


# ---- flow control events -----------------------------------------------------------------------------------------
FC_KINDS = ["Window scale", "Initial window", "Zero window", "Zero-window probe", "Zero-window probe ACK", "Window update", "Window full", "Window shrank"]


def flow_control_events(r: Report, flow: int | None = None, cap: int = 5000) -> dict:
    """Receiver flow-control events for one flow or the whole capture: zero windows (with how long the sender was blocked), probes, window updates, window full.
    Which packets they are comes from Wireshark's flags (observed); a zero window is also detected from the raw header field (window = 0, no SYN / RST);
    the stall durations and per-flow totals are derived by the engine. Flow control protects the receiver; it is not congestion control."""
    d = _tcp(r, flow).sort_values("no")
    d = d[d["win_raw"].notna()]
    empty = {"flow": flow, "events": [], "counts": {}, "stalls": [], "by_flow": [], "lanes": [], "truncated": False, "total_events": 0,
             "summary": {"events": 0, "stalls": 0, "total_stall_ms": 0.0, "longest_stall_ms": None, "flows_affected": 0, "still_closed": 0}}
    if d.empty:
        return empty
    who = lambda role: "client → server" if role == C2S else "server → client"
    z_flag, z_hdr = d["zero_window"], (d["win_raw"] == 0) & ~d["syn"] & ~d["rst"]
    masks = {"Zero window": z_flag | z_hdr, "Zero-window probe": d["zero_window_probe"], "Zero-window probe ACK": d["zero_window_probe_ack"],
             "Window update": d["window_update"], "Window full": d["window_full"]}

    # --- stalls: from the first zero window until the same side advertises a non-zero window again
    stalls = []
    zero_rows = d[masks["Zero window"]]
    if len(zero_rows):
        flows_with_zero = set(zero_rows["tcp_stream"].astype(int))
        for (f, role), g in d[d["tcp_stream"].isin(flows_with_zero) & ~d["syn"]].groupby(["tcp_stream", "role"]):
            zero = ((g["win_raw"] == 0) & ~g["rst"]).to_numpy() | g["zero_window"].to_numpy()
            if not zero.any():
                continue
            nos, times = g["no"].to_numpy(), g["time"].to_numpy()
            prev = np.concatenate([[False], zero[:-1]])
            for i in np.flatnonzero(zero & ~prev):                          # start of each zero-window period
                rest = np.flatnonzero(~zero[i + 1:])
                j = i + 1 + rest[0] if len(rest) else None
                end_t = times[j] if j is not None else float(d[d["tcp_stream"] == f]["time"].max())
                stalls.append({"flow": int(f), "sender": who(role), "start_no": int(nos[i]), "start_s": float(g["rel_time"].iloc[i]), "reopened_no": int(nos[j]) if j is not None else None,
                               "reopened_s": float(g["rel_time"].iloc[j]) if j is not None else None, "duration_ms": float((end_t - times[i]) * 1000), "reopened": j is not None,
                               "closed_packets": int(zero[i:(j if j is not None else len(zero))].sum())})
    stall_at = {(x["flow"], x["start_no"]): x for x in stalls}

    rows = []
    for kind, m in masks.items():
        for rec in d[m].itertuples():
            eff = rec.eff_win if pd.notna(rec.eff_win) else rec.win_raw
            via = "Wireshark flag" if (kind != "Zero window" or rec.zero_window) else "header field (window = 0)"
            if kind == "Zero window":
                st = stall_at.get((int(rec.tcp_stream), int(rec.no)))
                if st is None:
                    text = "Receiver still advertises a zero window"
                elif st["reopened"]:
                    text = f"Receiver advertised a zero window: the sender had to stop for {_dur(st['duration_ms'])} (until packet #{st['reopened_no']})"
                else:
                    text = f"Receiver advertised a zero window and it was still closed {_dur(st['duration_ms'])} later, at the end of the capture"
            elif kind == "Zero-window probe":
                text = "Sender probes the closed window to see whether it has reopened"
            elif kind == "Zero-window probe ACK":
                text = f"Receiver answers the probe; its window is {int(eff):,} bytes"
            elif kind == "Window update":
                text = f"Receiver's window grew to {int(eff):,} bytes: the sender may send again"
            else:
                bif = f" with {int(rec.bytes_in_flight):,} bytes in flight" if pd.notna(rec.bytes_in_flight) else ""
                text = f"Sender filled the receiver's window ({int(eff):,} bytes{bif}): it must wait for ACKs"
            rows.append({"packet_no": int(rec.no), "rel_time": float(rec.rel_time), "flow": int(rec.tcp_stream), "sender": who(rec.role), "event": kind,
                         "window": None if pd.isna(eff) else float(eff), "raw_window": float(rec.win_raw), "via": via, "details": text})
    # --- the receiver's window shrinks to a quarter of its earlier peak: the application is reading slowly and the buffer is filling (derived)
    live = d[~d["syn"] & d["eff_win"].notna()]
    if len(live):
        key = live["tcp_stream"].astype(int).astype(str) + live["role"]
        settled = live["eff_win"].where(live.groupby(key).cumcount() >= 5)                    # the first few advertisements are often a one-off initial value: not a peak
        cm = settled.groupby(key).cummax()
        low = (live["eff_win"] < 0.25 * cm) & (cm >= 16384) & (live["eff_win"] > 0)         # window = 0 is reported as a zero window, not here
        starts = live[low & ~low.groupby(key).shift(fill_value=False)]
        for rec in starts.head(1000).itertuples():
            g = live[(live["tcp_stream"] == rec.tcp_stream) & (live["role"] == rec.role) & (live["no"] > rec.no)]
            peak = float(cm.loc[rec.Index])
            back = g[g["eff_win"] >= 0.5 * peak]
            took = f"; it recovered to half its peak after {_dur((back['time'].iloc[0] - rec.time) * 1000)}" if len(back) else "; it had not recovered by the end of the capture"
            rows.append({"packet_no": int(rec.no), "rel_time": float(rec.rel_time), "flow": int(rec.tcp_stream), "sender": who(rec.role), "event": "Window shrank",
                         "window": float(rec.eff_win), "raw_window": float(rec.win_raw), "via": "derived from the advertised window",
                         "details": f"Receiver's window fell to {int(rec.eff_win):,} bytes, {100 * rec.eff_win / peak:.0f}% of its earlier peak ({int(peak):,}){took}"})
    # --- set-up facts for one flow: window scaling and the first advertised window of each side
    if flow is not None:
        wd = r.tcp.window_dir[r.tcp.window_dir["flow"] == flow]
        allp = _tcp(r, flow).sort_values("no")
        for rec in wd.itertuples():
            first = allp[allp["role"] == rec.role].head(1)
            if first.empty:
                continue
            sh = rec.scale_shift
            text = {"scaled": f"Window scaling in effect: the 16-bit window field is multiplied by 2^{int(sh)} = {2 ** int(sh):,}" if pd.notna(sh) else "Window scaling in effect",
                    "unscaled": "Window scaling is not in effect: this side's window cannot exceed 65,535 bytes",
                    "uncertain": "Handshake not captured: the window scale is unknown, so the effective window is uncertain"}.get(rec.scale_status, str(rec.scale_status))
            rows.append({"packet_no": int(first["no"].iloc[0]), "rel_time": float(first["rel_time"].iloc[0]), "flow": int(flow), "sender": rec.direction, "event": "Window scale",
                         "window": None, "raw_window": None, "via": "SYN options" if rec.scale_status != "uncertain" else "not captured", "details": text})
            nz = allp[(allp["role"] == rec.role) & ~allp["syn"] & allp["win_raw"].notna()].head(1)
            if len(nz):
                eff = nz["eff_win"].iloc[0] if pd.notna(nz["eff_win"].iloc[0]) else nz["win_raw"].iloc[0]
                rows.append({"packet_no": int(nz["no"].iloc[0]), "rel_time": float(nz["rel_time"].iloc[0]), "flow": int(flow), "sender": rec.direction, "event": "Initial window",
                             "window": float(eff), "raw_window": float(nz["win_raw"].iloc[0]), "via": "header field", "details": f"First window this side advertised: {int(eff):,} bytes"})
    if not rows:
        return {**empty, "summary": {**empty["summary"]}}
    ev = pd.DataFrame(rows).sort_values(["rel_time", "packet_no"]).reset_index(drop=True)
    counts = ev["event"].value_counts().to_dict()
    by_flow = []
    if flow is None:
        g = ev.groupby("flow")
        by = pd.DataFrame({"events": g.size(), **{k: ev[ev["event"] == k].groupby("flow").size() for k in FC_KINDS}}).fillna(0).astype(int)
        if stalls:
            sd = pd.DataFrame(stalls).groupby("flow").agg(stalls=("duration_ms", "size"), stalled_ms=("duration_ms", "sum"), longest_ms=("duration_ms", "max"))
            by = by.join(sd).fillna({"stalls": 0, "stalled_ms": 0.0})
        by_flow = records(by.sort_values("events", ascending=False).head(200).reset_index())
    dur = [x["duration_ms"] for x in stalls]
    return jsonable({"flow": flow, "events": records(ev.head(cap)), "counts": counts, "stalls": stalls[:500], "by_flow": by_flow, "lanes": [k for k in FC_KINDS if k in counts],
                     "truncated": bool(len(ev) > cap), "total_events": int(len(ev)),
                     "summary": {"events": int(len(ev)), "stalls": len(stalls), "total_stall_ms": float(sum(dur)), "longest_stall_ms": float(max(dur)) if dur else None,
                                 "flows_affected": int(ev["flow"].nunique()), "still_closed": int(sum(1 for x in stalls if not x["reopened"]))}})


# ---- congestion indicators -----------------------------------------------------------------------------------------
def _timeline(d: pd.DataFrame):
    """Shared time axis for the TCP timelines: (bin index per packet, number of bins, x values, bin width in seconds)."""
    dur = float(d["rel_time"].max() - d["rel_time"].min()) or float(d["rel_time"].max()) or 1.0
    bw = bin_width(max(dur, 1e-3))
    t0 = float(d["rel_time"].min())
    idx = ((d["rel_time"] - t0) // bw).astype(int)
    n = int(idx.max()) + 1
    return idx, n, [round(t0 + i * bw, 6) for i in range(n)], bw


def _throughput_chart(d: pd.DataFrame, idx, n: int, x: list, bw: float, id_: str) -> dict:
    """TCP bits per second per time bin: frame bytes x 8 / bin width, split by direction (client -> server, server -> client) plus the total."""
    def thr(mask):
        sums = d.loc[mask, "length"].groupby(idx[mask]).sum().reindex(range(n), fill_value=0).sort_index().values
        return [round(float(v) * 8 / bw, 1) for v in sums]
    everything = pd.Series(True, index=d.index)
    return chart(id_, "TCP throughput over time", "line",
                 series=[{"name": "client → server", "data": thr(d["role"] == C2S)}, {"name": "server → client", "data": thr(d["role"] == S2C)}, {"name": "total", "data": thr(everything)}],
                 x=x, unit="bps", x_label="time (s)", y_label="bits per second",
                 tip=f"Frame bytes × 8 ÷ {bw:g} s per time bin (derived). Dips can mean loss recovery, but also an idle application. "
                     "Direction: client = sender of the first SYN; if the handshake was not captured it is a best guess.")


def throughput(r: Report, flow: int | None = None) -> dict:
    """TCP throughput over time for the whole capture (flow=None) or one flow."""
    d = _tcp(r, flow)
    out = {"flow": flow, "charts": []}
    if d.empty:
        return out
    idx, n, x, bw = _timeline(d)
    out["charts"].append(_throughput_chart(d, idx, n, x, bw, "tcp_thr"))
    return jsonable(out)


# ---- retransmission intervals ----------------------------------------------------------------------------------
def _retx(r: Report) -> pd.DataFrame:
    """Per-retransmission intervals; computed once per report, on the first request (it is not needed by any other page)."""
    return r.tcp.retx


def retransmissions(r: Report, flow: int | None = None, cap: int = 20000, table_cap: int = 3000) -> dict:
    """How long each retransmission took (whole capture, or one flow). All values are derived.
    basis "original": exact time since the same bytes were first captured. basis "overtaken": the original was never captured, so this is how long after
    the segment that overtook the missing bytes they arrived (a lower bound on the true time since the original)."""
    ri = _retx(r)
    if flow is not None:
        ri = ri[ri["flow"] == flow]
    timed = ri[ri["interval_ms"].notna()]
    x = timed["interval_ms"]
    rtt = ri["handshake_rtt_ms"].dropna()
    is_true = lambda v: int((v == True).sum())                                      # noqa: E712 (column may hold NaN / bool objects)
    out = {
        "flow": flow, "total": int(len(ri)), "timed": int(len(timed)), "untimed": int(len(ri) - len(timed)),
        "exact": int((timed["basis"] == "original").sum()), "lower_bound": int((timed["basis"] == "overtaken").sum()),
        "stats_ms": ({"min": float(x.min()), "median": float(x.median()), "p95": float(x.quantile(0.95)), "max": float(x.max())} if len(x) else None),
        "faster_than_rtt": is_true(timed["faster_than_rtt"]), "rtt_known": int(timed["faster_than_rtt"].notna().sum()),
        "verdicts": {k: int((ri["verdict"] == k).sum()) for k in ("retransmission", "reordering", "duplicate", "undetermined")},
        "handshake_rtt_ms": float(rtt.iloc[0]) if flow is not None and len(rtt) else None,
        "points": [], "by_flow": [], "events": [],
        "note": ("Filled dots: the original transmission was captured, so the interval is exact (retransmission time minus the time the same bytes were first captured). "
                 "Hollow diamonds: the original was never captured (lost before the capture point, or sent before the capture started), so the interval is measured from the "
                 "first earlier segment that carried higher sequence numbers, the one that overtook the missing bytes. The original was sent before that segment, so the true "
                 "time since the original is at least this long."),
    }
    if len(timed):
        pts = thin(timed, cap)
        out["points"] = [[round(float(a), 6), float(b), int(n), int(f), str(k), int(t_), int(o), None if pd.isna(c) else bool(c), str(bs), str(v)]
                         for a, b, n, f, k, t_, o, c, bs, v in zip(pts["rel_time"], pts["interval_ms"], pts["packet_no"], pts["flow"], pts["kind"], pts["transmission"].fillna(0),
                                                                  pts["reference_no"], pts["faster_than_rtt"], pts["basis"], pts["verdict"])]
    if flow is None and len(ri):
        g = timed.groupby("flow")["interval_ms"]
        by = pd.DataFrame({"retransmissions": ri.groupby("flow").size()}).join(pd.DataFrame({
            "timed": g.size(), "exact": timed.groupby("flow")["basis"].apply(lambda v: int((v == "original").sum())),
            "min_ms": g.min(), "median_ms": g.median(), "p95_ms": g.quantile(0.95), "max_ms": g.max(),
            "faster_than_rtt": timed.groupby("flow")["faster_than_rtt"].apply(is_true)}))
        by["handshake_rtt_ms"] = ri.groupby("flow")["handshake_rtt_ms"].first()
        for k, name in (("retransmission", "likely_real"), ("reordering", "late_arrivals")):
            by[name] = ri[ri["verdict"] == k].groupby("flow").size().reindex(by.index).fillna(0).astype(int)
        out["by_flow"] = records(by.fillna({"timed": 0, "exact": 0, "faster_than_rtt": 0}).sort_values("retransmissions", ascending=False).head(500).reset_index())
    out["events"] = records(ri.sort_values("rel_time").head(table_cap).round(6))
    return jsonable(out)


# ---- TCP flow events ---------------------------------------------------------------------------------------------
LANES = ["Connection", "Data", "Retransmissions", "Reordering & duplicate ACKs", "Flow control", "ECN", "Closing"]


def _dur(ms: float) -> str:
    return f"{ms * 1000:.0f} µs" if ms < 1 else (f"{ms:.1f} ms" if ms < 1000 else f"{ms / 1000:.2f} s")


def flow_events(r: Report, flow: int, cap: int = 5000, idle_s: float = 1.0) -> dict:
    """The life of one TCP connection as a time-ordered list of events: connection set-up, first data, retransmissions (with their interval), reordering and
    duplicate ACKs, flow-control events, ECN marks, idle periods and the closing (FIN / RST). Wireshark's flags are observed; the grouping, the idle periods
    and the end state are derived by the engine."""
    d = _tcp(r, flow).sort_values("no")
    who = lambda role: "client → server" if role == C2S else "server → client"
    rows: list[dict] = []

    def add(sub: pd.DataFrame, lane: str, kind: str, text):
        for rec in sub.itertuples():
            rows.append({"packet_no": int(rec.no), "rel_time": float(rec.rel_time), "lane": lane, "event": kind, "direction": who(rec.role),
                         "details": text(rec) if callable(text) else text})

    if d.empty:
        return {"flow": flow, "events": [], "counts": {}, "summary": {}, "truncated": False, "lanes": []}

    # --- connection set-up
    add(d[d["syn"] & ~d["ack_flag"]], "Connection", "SYN", "Client asks to open the connection")
    add(d[d["syn"] & d["ack_flag"]], "Connection", "SYN-ACK", "Server accepts")
    ini = r.tcp.rtt_initial[r.tcp.rtt_initial["flow"] == flow]
    hs_ms = None
    if len(ini):
        hs_ms = float(ini["rtt"].iloc[0]) * 1000
        rows.append({"packet_no": int(ini["packet"].iloc[0]), "rel_time": float(ini["rel_time"].iloc[0]), "lane": "Connection", "event": "Handshake complete",
                     "direction": who(C2S), "details": f"Three-way handshake finished; handshake RTT {_dur(hs_ms)} (SYN to SYN-ACK)"})
    # --- first data in each direction, idle periods
    data = d[d["tcp_len"].fillna(0) > 0]
    add(data.drop_duplicates("role"), "Data", "First data", lambda x: f"First payload in this direction: {int(x.tcp_len)} bytes")
    gap = d["time"].diff()
    idle = d[gap >= idle_s].assign(gap=gap[gap >= idle_s]).sort_values("gap", ascending=False).head(50)
    add(idle, "Data", "Idle gap", lambda x: f"No packets for {x.gap:.2f} s before this one")
    # --- retransmissions, with the interval from the retransmission analysis
    ri = _retx(r)
    ri = ri[ri["flow"] == flow].set_index("packet_no")
    def retx_text(x):
        info = ri.loc[x.no] if x.no in ri.index else None
        if info is None or pd.isna(info["interval_ms"]):
            return "Retransmission (no earlier copy to measure against)"
        if info["basis"] == "original":
            return f"Sent again {_dur(info['interval_ms'])} after the original (packet #{int(info['reference_no'])})"
        return f"Original not captured; arrived {_dur(info['interval_ms'])} after packet #{int(info['reference_no'])}, which overtook it"
    # Wireshark flags anything below the highest sequence seen as a retransmission; we sort them by what they most likely are (see retransmission_intervals)
    VERDICT = {"retransmission": ("Retransmissions", "Retransmission", ""), "reordering": ("Reordering & duplicate ACKs", "Late arrival", " Wireshark calls it a retransmission, but it came back within one round trip, so it was most likely delayed, not resent."),
               "duplicate": ("Retransmissions", "Duplicate copy", " The same bytes were seen again within one round trip: most likely a duplicate copy, not a loss recovery."),
               "undetermined": ("Retransmissions", "Retransmission (unclassified)", " No handshake RTT to compare with, so it cannot be classified.")}
    flagged = d[d["retransmission"] | d["fast_retransmission"]]
    for rec in flagged.itertuples():
        v = ri.at[rec.no, "verdict"] if rec.no in ri.index else "undetermined"
        lane, name, why = VERDICT[v]
        if v == "retransmission" and rec.fast_retransmission:
            name = "Fast retransmission"
        rows.append({"packet_no": int(rec.no), "rel_time": float(rec.rel_time), "lane": lane, "event": name, "direction": who(rec.role), "details": retx_text(rec) + ("." + why if why else "")})
    add(d[d["spurious_retransmission"]], "Retransmissions", "Spurious retransmission", "Data that was already acknowledged was sent again")
    # --- reordering and duplicate ACKs (consecutive duplicate ACKs for the same number are one event)
    add(d[d["out_of_order"]], "Reordering & duplicate ACKs", "Out-of-order", lambda x: f"Segment with seq {int(x.seq) if pd.notna(x.seq) else '?'} arrived behind a higher sequence number")
    dup = d[d["duplicate_ack"]]
    if len(dup):
        run = ((dup["ack"] != dup["ack"].shift()) | (dup["role"] != dup["role"].shift())).cumsum()
        g = dup.groupby(run)
        runs = g.agg(no=("no", "first"), rel_time=("rel_time", "first"), role=("role", "first"), ack=("ack", "first"), n=("no", "size"), last=("rel_time", "last"))
        add(runs, "Reordering & duplicate ACKs", "Duplicate ACKs",
            lambda x: (f"{int(x.n)} duplicate ACKs for ack {int(x.ack)} within {_dur((x.last - x.rel_time) * 1000)}" if x.n > 1 else f"Duplicate ACK for ack {int(x.ack)}")
                      + (" (3 or more trigger a fast retransmit)" if x.n >= 3 else ""))
    # --- flow control
    for col, kind, text in (("zero_window", "Zero window", "Receiver advertised a zero window: the sender must stop"), ("zero_window_probe", "Zero-window probe", "Sender probes a closed window"),
                            ("zero_window_probe_ack", "Zero-window probe ACK", "Receiver answers the probe, still closed"), ("window_update", "Window update", "Receiver re-opened its window"),
                            ("window_full", "Window full", "Sender has filled the receiver's window"), ("keep_alive", "Keep-alive", "Keep-alive probe")):
        add(d[d[col]], "Flow control", kind, text)
    # --- ECN (the SYN flags only negotiate ECN)
    ns = d[~d["syn"]]
    add(ns[ns["ecn"] == 3], "ECN", "CE mark", "A router marked this packet as congested")
    add(ns[ns["ece"]], "ECN", "ECE echo", "Receiver echoes the congestion mark")
    add(ns[ns["cwr"]], "ECN", "CWR", "Sender reports it reduced its rate")
    # --- closing
    add(d[d["fin"]], "Closing", "FIN", "This side has finished sending")
    add(d[d["rst"]], "Closing", "RST", "Connection reset (abrupt close)")

    ev = pd.DataFrame(rows).sort_values(["packet_no", "event"]).reset_index(drop=True)
    counts = ev["event"].value_counts().to_dict()
    fins, rsts = d[d["fin"]]["role"].unique(), d[d["rst"]]["role"].unique()
    syn_seen, synack_seen = bool((d["syn"] & ~d["ack_flag"]).any()), bool((d["syn"] & d["ack_flag"]).any())
    state = ("reset by the " + ("client" if C2S in rsts else "server")) if len(rsts) else ("closed normally (FIN from both sides)" if len(fins) >= 2 else
             ("closing (FIN from one side only)" if len(fins) == 1 else "still open at the end of the capture"))
    summary = {"established": bool(len(ini)), "handshake_captured": syn_seen and synack_seen, "handshake_rtt_ms": hs_ms, "end_state": state,
               "first_s": float(d["rel_time"].min()), "last_s": float(d["rel_time"].max()), "duration_s": float(d["time"].max() - d["time"].min()), "packets": int(len(d)),
               "role_known": bool(r.tcp.flows[r.tcp.flows["flow"] == flow]["role_known"].iloc[0])}
    return jsonable({"flow": flow, "events": records(ev.head(cap)), "counts": counts, "summary": summary, "truncated": bool(len(ev) > cap), "total_events": int(len(ev)),
                     "lanes": [x for x in LANES if (ev["lane"] == x).any()]})


def congestion(r: Report, flow: int | None = None, cap: int = 5000) -> dict:
    c = r.tcp.congestion
    rows = c if flow is None or c.empty else c[c["flow"] == flow]
    d = _tcp(r, flow)
    out = {"flow": flow, "caveat": CAVEAT, "flows": jsonable(rows), "charts": [], "ecn_events": [], "assessment_counts": {}}
    if not rows.empty:
        out["assessment_counts"] = rows["assessment"].value_counts().to_dict()
    if d.empty:
        return out
    idx, n, x, bw = _timeline(d)
    per = lambda mask: [int(v) for v in idx[mask].value_counts().reindex(range(n), fill_value=0).sort_index().values]
    out["charts"].append(chart("cg_retx", "Retransmissions and duplicate ACKs over time", "line", series=[
        {"name": "retransmissions", "data": per(d["retransmission"] | d["fast_retransmission"])}, {"name": "duplicate ACKs", "data": per(d["duplicate_ack"])},
        {"name": "out-of-order", "data": per(d["out_of_order"])}], x=x, unit="count", tip=f"Wireshark flags per time bin (bin = {bw:g} s). Observed.", x_label="time (s)", y_label="packets"))
    out["charts"].append(_throughput_chart(d, idx, n, x, bw, "cg_thr"))
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
