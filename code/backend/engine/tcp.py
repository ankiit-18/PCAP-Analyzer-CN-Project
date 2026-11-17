"""
TCP analysis.

Basis of every number (see the `basis` field in metrics):
  observed  - dissected by tshark (tcp.analysis.* flags, ack_rtt, initial_rtt, header fields)
  derived   - aggregated or calculated by this engine from observed fields (flow tables, effective window, timestamp-echo RTT)
  inferred  - cautious interpretation (congestion indicators). NEVER presented as fact: cwnd is not visible in a passive capture.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .extract import ANALYSIS, WINDOW_FLAGS
from .util import stats

C2S, S2C = "c2s", "s2c"


@dataclass
class TcpResult:
    flows: pd.DataFrame = field(default_factory=pd.DataFrame)
    findings: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=["packet_no", "rel_time", "flow", "direction", "src", "sport", "dst", "dport", "seq", "ack", "flags", "tags", "wireshark_message"]))
    rtt_ack: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=["ack_packet", "rel_time", "flow", "direction", "rtt", "acks_frame"]))   # tcp.analysis.ack_rtt     (observed)
    rtt_initial: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=["packet", "rel_time", "flow", "rtt"]))                              # tcp.analysis.initial_rtt (observed), one row per flow
    rtt_ts: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=["flow", "packet", "rel_time", "rtt", "measured_toward"]))                # timestamp echo           (derived)
    options: pd.DataFrame = field(default_factory=pd.DataFrame)       # one row per flow
    options_dir: pd.DataFrame = field(default_factory=pd.DataFrame)   # one row per flow and direction
    window_dir: pd.DataFrame = field(default_factory=pd.DataFrame)    # one row per flow and direction
    congestion: pd.DataFrame = field(default_factory=pd.DataFrame)    # one row per flow (inferred assessment)
    retx: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=RETX_COLUMNS))      # one row per flagged retransmission, with interval and verdict (derived)
    summary: dict = field(default_factory=dict)


# --------------------------------------------------------------------------------------------------------------
# roles / direction
# --------------------------------------------------------------------------------------------------------------
def assign_roles(df: pd.DataFrame) -> pd.DataFrame:
    """Adds `role` (c2s / s2c) to TCP packets and makes `direction` = fwd for client→server.
    Client = sender of the first pure SYN. Without a captured SYN the first packet's sender is used and role_known=False."""
    tcp = df[df["is_tcp"]]
    df["role"] = ""
    if tcp.empty:
        return pd.DataFrame(columns=["tcp_stream", "client_ip", "client_port", "server_ip", "server_port", "role_known"]).set_index("tcp_stream")
    first_pkt = tcp.groupby("tcp_stream", sort=True)[["src", "sport", "dst", "dport"]].first()
    syn = tcp[tcp["syn"] & ~tcp["ack_flag"]].groupby("tcp_stream", sort=True)[["src", "sport", "dst", "dport"]].first()
    roles = first_pkt.copy()
    roles["role_known"] = False
    roles.loc[syn.index, ["src", "sport", "dst", "dport"]] = syn
    roles.loc[syn.index, "role_known"] = True
    roles.columns = ["client_ip", "client_port", "server_ip", "server_port", "role_known"]
    cip, cpt = tcp["tcp_stream"].map(roles["client_ip"]), tcp["tcp_stream"].map(roles["client_port"])
    is_c = (tcp["src"] == cip) & (tcp["sport"] == cpt)
    df.loc[tcp.index, "role"] = np.where(is_c, C2S, S2C)
    df.loc[tcp.index, "direction"] = np.where(is_c, "fwd", "rev")
    return roles


# --------------------------------------------------------------------------------------------------------------
# options + window scaling (3C, 3E)
# --------------------------------------------------------------------------------------------------------------
def _first_valid(s: pd.Series):
    s = s.dropna()
    return s.iloc[0] if len(s) else np.nan


def analyze_options_and_windows(df: pd.DataFrame, roles: pd.DataFrame):
    """Returns (options, options_dir, window_dir). Also adds `eff_win` and `win_status` columns to df (TCP rows)."""
    tcp = df[df["is_tcp"]]
    if tcp.empty:
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    syn = tcp[tcp["syn"]]
    per = syn.groupby(["tcp_stream", "role"]).agg(
        mss=("mss", _first_valid), wscale=("wscale", _first_valid), sack_perm=("sack_perm", "max"), ts=("tsval", lambda s: bool(s.notna().any())),
        ece=("ece", "max"), cwr=("cwr", "max"))
    idx = pd.MultiIndex.from_product([roles.index, [C2S, S2C]], names=["tcp_stream", "role"])
    per = per.reindex(idx)
    per["has_syn"] = per["ts"].notna()                       # NaN row = that side's SYN was not captured
    per[["sack_perm", "ts", "ece", "cwr"]] = per[["sack_perm", "ts", "ece", "cwr"]].fillna(False).astype(bool)

    # window-scale status per flow: RFC 7323 - scaling is in effect only if BOTH SYNs carried the option
    pf = per.unstack("role")
    both_syn = pf[("has_syn", C2S)].astype(bool) & pf[("has_syn", S2C)].astype(bool)
    wscale_neg = both_syn & pf[("wscale", C2S)].notna() & pf[("wscale", S2C)].notna()
    sack_neg = both_syn & pf[("sack_perm", C2S)] & pf[("sack_perm", S2C)]
    ts_neg = both_syn & pf[("ts", C2S)] & pf[("ts", S2C)]
    ecn_neg = both_syn & pf[("ece", C2S)] & pf[("cwr", C2S)] & pf[("ece", S2C)] & ~pf[("cwr", S2C)]

    # ---- effective window per packet -------------------------------------------------------------------------
    status = pd.Series("uncertain", index=per.index)
    for sid in roles.index:
        for r in (C2S, S2C):
            if both_syn.get(sid, False):
                status[(sid, r)] = "scaled" if wscale_neg.get(sid, False) else "unscaled"
    shift = per["wscale"].where(status == "scaled", 0.0).fillna(0.0)
    m = pd.DataFrame({"win_status": status, "shift": shift})
    j = tcp[["tcp_stream", "role"]].join(m, on=["tcp_stream", "role"])
    raw = tcp["win_raw"]
    eff = np.where(tcp["syn"], raw, raw * np.power(2.0, j["shift"].fillna(0).to_numpy()))
    df["eff_win"] = np.nan
    df["win_status"] = ""
    df.loc[tcp.index, "eff_win"] = eff
    df.loc[tcp.index, "win_status"] = np.where(tcp["syn"], "syn (never scaled)", j["win_status"].fillna("uncertain"))

    # ---- per-flow option table ------------------------------------------------------------------------------
    nonsyn = tcp[~tcp["syn"]]
    later = nonsyn.groupby(["tcp_stream", "role"]).agg(
        sack_blocks=("sack_le", lambda s: int((s != "").sum())), ts_later=("tsval", lambda s: int(s.notna().sum())),
        mss_later=("mss", lambda s: int(s.notna().sum())), ece_pkts=("ece", "sum"), cwr_pkts=("cwr", "sum"), ce_marks=("ecn", lambda s: int((s == 3).sum())))
    later = later.reindex(idx).fillna(0)
    rows_dir = []
    for (sid, r), p in per.iterrows():
        lt = later.loc[(sid, r)]
        rows_dir.append({"flow": int(sid), "direction": "client → server" if r == C2S else "server → client", "role": r, "handshake_packet_seen": bool(p["has_syn"]),
                         "mss": p["mss"] if p["has_syn"] else None, "wscale_shift": p["wscale"] if p["has_syn"] else None,
                         "wscale_factor": (2 ** p["wscale"]) if p["has_syn"] and pd.notna(p["wscale"]) else None,
                         "sack_permitted": bool(p["sack_perm"]) if p["has_syn"] else None, "timestamps": bool(p["ts"]) if p["has_syn"] else None,
                         "syn_ece": bool(p["ece"]) if p["has_syn"] else None, "syn_cwr": bool(p["cwr"]) if p["has_syn"] else None,
                         "window_scale_status": status[(sid, r)], "sack_block_packets": int(lt["sack_blocks"]), "timestamp_packets_later": int(lt["ts_later"]),
                         "mss_later_packets": int(lt["mss_later"]), "ece_packets": int(lt["ece_pkts"]), "cwr_packets": int(lt["cwr_pkts"]), "ce_marks": int(lt["ce_marks"])})
    options_dir = pd.DataFrame(rows_dir)

    def tri(series, sid):      # True / False, or None when the handshake was not captured (unknown)
        return bool(series.get(sid)) if both_syn.get(sid, False) else None

    rows = []
    for sid, rl in roles.iterrows():
        g = options_dir[options_dir["flow"] == int(sid)].set_index("role")
        rows.append({"flow": int(sid), "client": f"{rl['client_ip']}:{int(rl['client_port'])}", "server": f"{rl['server_ip']}:{int(rl['server_port'])}",
                     "handshake_captured": bool(both_syn.get(sid, False)),
                     "client_mss": g.loc[C2S, "mss"], "server_mss": g.loc[S2C, "mss"],
                     "client_wscale": g.loc[C2S, "wscale_shift"], "server_wscale": g.loc[S2C, "wscale_shift"], "wscale_negotiated": tri(wscale_neg, sid),
                     "sack_negotiated": tri(sack_neg, sid), "timestamps_negotiated": tri(ts_neg, sid), "ecn_negotiated": tri(ecn_neg, sid),
                     "sack_block_packets": int(g["sack_block_packets"].sum()), "timestamp_packets_later": int(g["timestamp_packets_later"].sum()),
                     "ece_packets": int(g["ece_packets"].sum()), "cwr_packets": int(g["cwr_packets"].sum()), "ce_marks": int(g["ce_marks"].sum())})
    options = pd.DataFrame(rows)

    # ---- per-flow, per-direction window summary --------------------------------------------------------------
    d = df[df["is_tcp"] & ~df["syn"] & df["win_raw"].notna()]
    rows = []
    for (sid, r), g in d.groupby(["tcp_stream", "role"]):
        o = options_dir[(options_dir["flow"] == int(sid)) & (options_dir["role"] == r)].iloc[0]
        e = g["eff_win"]
        engine_zero = int(((g["win_raw"] == 0) & ~g["rst"]).sum())
        rows.append({"flow": int(sid), "direction": o["direction"], "role": r, "scale_status": o["window_scale_status"], "scale_shift": o["wscale_shift"],
                     "packets": len(g), "window_min": float(e.min()), "window_avg": float(e.mean()), "window_max": float(e.max()), "window_last": float(e.iloc[-1]),
                     "zero_window_engine": engine_zero, "zero_window_wireshark": int(g["zero_window"].sum()), "zero_window_probes": int(g["zero_window_probe"].sum()),
                     "zero_window_probe_acks": int(g["zero_window_probe_ack"].sum()), "window_updates": int(g["window_update"].sum()), "window_full": int(g["window_full"].sum()),
                     "wireshark_window_avg": float(g["win"].mean()) if g["win"].notna().any() else None})
    window_dir = pd.DataFrame(rows)
    return options, options_dir, window_dir


# --------------------------------------------------------------------------------------------------------------
# RTT: timestamp-echo method (derived) - ACK-based and handshake RTT are Wireshark's own fields
# --------------------------------------------------------------------------------------------------------------
def timestamp_rtt(df: pd.DataFrame, options: pd.DataFrame) -> pd.DataFrame:
    """TCP timestamp-echo RTT, per flow.

    A packet from side X carrying TSval=v is noted the first time it is seen. The first later packet from the OTHER side Y that echoes
    TSecr=v closes the sample: RTT = t(Y's echo) − t(X's packet), both timestamps taken AT THE CAPTURE POINT, so the sample is the round trip
    between the capture point and Y. Values are not blindly subtracted: only matching echo pairs are used, TSecr=0 / TSval=0 are ignored,
    each TSval is used once, and flows without timestamps on both sides are skipped. Delayed ACKs can inflate samples."""
    tcp = df[df["is_tcp"] & (df["tsval"].notna() | df["tsecr"].notna())]
    out = []
    ok_flows = None
    if len(options):
        # timestamps negotiated, or (handshake not captured) timestamps visible in both directions
        both_dirs = tcp.groupby("tcp_stream")["role"].nunique()
        neg = options.set_index("flow")["timestamps_negotiated"]
        flag = lambda v: None if v is None or v != v else bool(v)
        ok_flows = {sid for sid in both_dirs.index if flag(neg.get(int(sid))) is True or (flag(neg.get(int(sid))) is None and both_dirs[sid] == 2)}
    for sid, g in tcp.groupby("tcp_stream"):
        if ok_flows is not None and sid not in ok_flows:
            continue
        first_seen = {C2S: {}, S2C: {}}
        used = {C2S: set(), S2C: set()}
        for no, t, rel, role, tsv, tse in zip(g["no"], g["time"], g["rel_time"], g["role"], g["tsval"], g["tsecr"]):
            if tsv == tsv and tsv > 0:
                first_seen[role].setdefault(tsv, t)
            if tse == tse and tse > 0:
                other = S2C if role == C2S else C2S
                t0 = first_seen[other].get(tse)
                if t0 is not None and tse not in used[other] and t >= t0:
                    used[other].add(tse)
                    out.append({"flow": int(sid), "packet": int(no), "rel_time": float(rel), "rtt": float(t - t0), "measured_toward": "server" if role == S2C else "client"})
    return pd.DataFrame(out, columns=["flow", "packet", "rel_time", "rtt", "measured_toward"])


# --------------------------------------------------------------------------------------------------------------
# flow table (3A)
# --------------------------------------------------------------------------------------------------------------
def build_flows(df: pd.DataFrame, roles: pd.DataFrame) -> pd.DataFrame:
    tcp = df[df["is_tcp"]]
    if tcp.empty:
        return pd.DataFrame()
    g = tcp.groupby("tcp_stream", sort=True)
    t_min, t_max = g["time"].min(), g["time"].max()
    dur = (t_max - t_min)
    f = pd.DataFrame({"flow": g.size().index.astype(int)})
    f = f.set_index("flow")
    f["client"] = [f"{roles.loc[s, 'client_ip']}:{int(roles.loc[s, 'client_port'])}" for s in roles.index]
    f["server"] = [f"{roles.loc[s, 'server_ip']}:{int(roles.loc[s, 'server_port'])}" for s in roles.index]
    f["role_known"] = roles["role_known"].to_numpy()
    f["packets"] = g.size().to_numpy()
    f["bytes"] = g["length"].sum().to_numpy().astype(int)
    f["payload_bytes"] = g["tcp_len"].sum().fillna(0).to_numpy().astype(int)
    f["start_s"] = g["rel_time"].min().to_numpy()
    f["duration_s"] = dur.to_numpy()
    d = dur.to_numpy()
    f["throughput_bps"] = np.where(d > 0, f["bytes"] * 8 / np.where(d > 0, d, 1), np.nan)
    f["packets_per_s"] = np.where(d > 0, f["packets"] / np.where(d > 0, d, 1), np.nan)
    f["avg_packet_size"] = f["bytes"] / f["packets"]
    for r, name in ((C2S, "c2s"), (S2C, "s2c")):
        sub = tcp[tcp["role"] == r].groupby("tcp_stream")
        pk, by, pl = sub.size(), sub["length"].sum(), sub["tcp_len"].sum()
        f[f"pkts_{name}"] = pk.reindex(roles.index).fillna(0).astype(int).to_numpy()
        f[f"bytes_{name}"] = by.reindex(roles.index).fillna(0).astype(int).to_numpy()
        f[f"payload_{name}"] = pl.reindex(roles.index).fillna(0).astype(int).to_numpy()
        f[f"throughput_{name}_bps"] = np.where(d > 0, f[f"bytes_{name}"] * 8 / np.where(d > 0, d, 1), np.nan)
    cnt = lambda col: tcp.groupby("tcp_stream")[col].sum().reindex(roles.index).fillna(0).astype(int).to_numpy()
    f["retransmissions"] = (tcp.assign(_r=tcp["retransmission"] | tcp["fast_retransmission"]).groupby("tcp_stream")["_r"].sum().reindex(roles.index).fillna(0).astype(int).to_numpy())
    f["fast_retransmissions"] = cnt("fast_retransmission")
    f["spurious_retransmissions"] = cnt("spurious_retransmission")
    f["out_of_order"] = cnt("out_of_order")
    f["dup_acks"] = cnt("duplicate_ack")
    f["zero_windows"] = cnt("zero_window")
    f["resets"] = cnt("rst")
    r = tcp["ack_rtt"].dropna()
    rg = tcp[tcp["ack_rtt"].notna()].groupby("tcp_stream")["ack_rtt"]
    ra = rg.agg(["count", "min", "mean", "max", "std"]).reindex(roles.index)
    f["rtt_samples"] = ra["count"].fillna(0).astype(int).to_numpy()
    for src, dst in (("min", "rtt_min_ms"), ("mean", "rtt_avg_ms"), ("max", "rtt_max_ms")):
        f[dst] = (ra[src] * 1e3).to_numpy()
    f["rtt_std_ms"] = (ra["std"].fillna(0) * 1e3).where(ra["count"] > 1).to_numpy()
    f["handshake_rtt_ms"] = (tcp[tcp["initial_rtt"].notna()].groupby("tcp_stream")["initial_rtt"].first().reindex(roles.index) * 1e3).to_numpy()
    syn = tcp[tcp["syn"] & ~tcp["ack_flag"]].groupby("tcp_stream").size().reindex(roles.index).fillna(0) > 0
    synack = tcp[tcp["syn"] & tcp["ack_flag"]].groupby("tcp_stream").size().reindex(roles.index).fillna(0) > 0
    f["handshake_seen"] = (syn & synack).to_numpy()
    f["issues"] = f["retransmissions"] + f["out_of_order"]
    return f.reset_index()


def build_findings(df: pd.DataFrame) -> pd.DataFrame:
    f = df[df["is_tcp"] & (df["tags"] != "")][["no", "rel_time", "tcp_stream", "direction", "src", "sport", "dst", "dport", "seq", "ack", "flags", "tags", "exp_msg"]]
    f = f.rename(columns={"no": "packet_no", "tcp_stream": "flow", "exp_msg": "wireshark_message"})
    f["flow"] = f["flow"].astype(int)
    return f.reset_index(drop=True)


# --------------------------------------------------------------------------------------------------------------
# retransmission intervals: how long after the original transmission did each retransmission happen?   (derived)
# --------------------------------------------------------------------------------------------------------------
RETX_COLUMNS = ["packet_no", "flow", "rel_time", "direction", "seq", "length", "kind", "transmission", "original_no", "since_original_ms",
                "previous_no", "since_previous_ms", "overtaken_by_no", "late_after_ms", "interval_ms", "basis", "reference_no", "handshake_rtt_ms", "faster_than_rtt", "verdict"]


VERDICT_LABEL = {"retransmission": "Likely retransmission", "reordering": "Likely reordering (late arrival)", "duplicate": "Likely duplicate copy",
                 "undetermined": "Undetermined"}


def dup_ack_bursts(df: pd.DataFrame) -> pd.Series:
    """Per flow: number of runs of 3 or more duplicate ACKs for the same ACK number from the same side. That is TCP's own fast-retransmit trigger;
    a single duplicate ACK is just as often a sign of reordering."""
    t = df[df["is_tcp"] & df["duplicate_ack"]].sort_values(["tcp_stream", "no"])
    if t.empty:
        return pd.Series(dtype=int)
    run = ((t["tcp_stream"] != t["tcp_stream"].shift()) | (t["role"] != t["role"].shift()) | (t["ack"] != t["ack"].shift())).cumsum()
    sizes = t.groupby(run).agg(flow=("tcp_stream", "first"), n=("no", "size"))
    return sizes[sizes["n"] >= 3].groupby("flow").size()


def retransmission_intervals(df: pd.DataFrame, handshake_rtt_s: dict | None = None) -> pd.DataFrame:
    """One row per packet that Wireshark flagged as a retransmission (or fast retransmission).

    The original is found by us, not by Wireshark: the earlier captured packet of the same connection and direction that carried the very same
    bytes (same sequence number, same length, same SYN/FIN flags). Then
        since_original = time(retransmission) - time(first transmission)      (what the "time interval of the retransmission" means)
        since_previous = time(retransmission) - time(the transmission right before it)   (differs from the above on the 2nd, 3rd ... retry)
    `transmission` is 2 for the first retransmission, 3 for the second retry, and so on.

    Where no matching original was captured (lost before the capture point, sent before the capture started, or the segment was re-cut) we use the
    next best thing: the first earlier packet of the same connection and direction that carries HIGHER sequence numbers, i.e. the segment that
    overtook the missing bytes and opened the hole. `late_after_ms` = how long after that segment the missing bytes showed up. The original was sent
    before the overtaking segment, so the true time since the original is at least this long (a lower bound). `interval_ms` is the exact value when
    the original was captured, else this lower bound; `basis` says which ("original" / "overtaken").
    `verdict` (inferred) says what the packet most likely is: "retransmission" (interval of at least one handshake RTT), "reordering" (original not
    captured and the packet arrived within one RTT of the segment that overtook it: a late arrival), "duplicate" (original captured but the copy came
    within one RTT: a duplicate copy), or "undetermined" (no interval or no handshake RTT to compare with).
    `faster_than_rtt` (inferred) is True when the
    interval is shorter than the connection's handshake RTT: a retransmission triggered by loss needs at least about one round trip of
    feedback, so such a repeat is more likely a duplicate or a reordered copy than a loss recovery."""
    out = pd.DataFrame(columns=RETX_COLUMNS)
    t = df[df["is_tcp"]]
    if t.empty:
        return out
    flagged = (t["retransmission"] | t["fast_retransmission"]).fillna(False)
    if not flagged.any():
        return out
    key = ["tcp_stream", "direction", "seq", "tcp_len", "syn", "fin"]
    seg = t[(t["tcp_len"].fillna(0) > 0) | t["syn"] | t["fin"]][["no", "time", "retransmission", "fast_retransmission"] + key].copy()
    seg["tcp_len"] = seg["tcp_len"].fillna(0)
    wanted = seg[(seg["retransmission"] | seg["fast_retransmission"]).fillna(False)][key].drop_duplicates()   # only segments that were retransmitted
    cand = seg.merge(wanted, on=key, how="inner").sort_values("no")
    g = cand.groupby(key, sort=False)
    cand["transmission"] = g.cumcount() + 1
    cand["original_no"], cand["original_t"] = g["no"].transform("first"), g["time"].transform("first")
    cand["previous_no"], cand["previous_t"] = g["no"].shift(), g["time"].shift()
    info = cand.set_index("no")[["transmission", "original_no", "original_t", "previous_no", "previous_t"]]

    f = t[flagged][["no", "rel_time", "time", "tcp_stream", "direction", "seq", "tcp_len", "fast_retransmission"]].copy()
    f = f.join(info, on="no")
    has_orig = f["transmission"].fillna(1) > 1                       # transmission 1 = this is the first captured copy: its original is not in the capture
    since_o = ((f["time"] - f["original_t"]) * 1000).where(has_orig)
    since_p = ((f["time"] - f["previous_t"]) * 1000).where(has_orig)
    since_o, since_p = since_o.where(since_o >= 0), since_p.where(since_p >= 0)       # negative = capture timestamps out of order; not a real interval
    res = pd.DataFrame({
        "packet_no": f["no"].astype(int), "flow": f["tcp_stream"].astype(int), "rel_time": f["rel_time"], "direction": f["direction"], "seq": f["seq"],
        "length": f["tcp_len"].fillna(0).astype(int), "kind": np.where(f["fast_retransmission"], "fast retransmission", "retransmission"),
        "transmission": f["transmission"].where(has_orig), "original_no": f["original_no"].where(has_orig), "since_original_ms": since_o,
        "previous_no": f["previous_no"].where(has_orig), "since_previous_ms": since_p})
    # --- no captured original: time since the segment that overtook the missing bytes (lower bound) ---
    res["overtaken_by_no"], res["late_after_ms"] = np.nan, np.nan
    todo = res[res["since_original_ms"].isna()]
    if len(todo):
        ft = f.set_index("no")
        data = t[t["tcp_len"].fillna(0) > 0][["no", "time", "tcp_stream", "direction", "seq"]]
        need = pd.MultiIndex.from_frame(todo[["flow", "direction"]].drop_duplicates())
        data = data[pd.MultiIndex.from_arrays([data["tcp_stream"].astype(int), data["direction"]]).isin(need)]
        groups = {k: (g["no"].to_numpy(), g["time"].to_numpy(), g["seq"].to_numpy()) for k, g in data.sort_values("no").groupby([data["tcp_stream"].astype(int), "direction"])}
        for i, row in todo.iterrows():
            arr = groups.get((row["flow"], row["direction"]))
            if arr is None or pd.isna(row["seq"]):
                continue
            nos, times, seqs = arr
            pos = int(np.searchsorted(nos, row["packet_no"]))                    # data segments captured before this retransmission
            hit = np.flatnonzero(seqs[:pos] > row["seq"])
            if len(hit):
                j = hit[0]
                late = (float(ft.at[row["packet_no"], "time"]) - float(times[j])) * 1000
                if late >= 0:
                    res.at[i, "overtaken_by_no"], res.at[i, "late_after_ms"] = float(nos[j]), late
    res["interval_ms"] = res["since_original_ms"].fillna(res["late_after_ms"])
    res["basis"] = np.where(res["since_original_ms"].notna(), "original", np.where(res["late_after_ms"].notna(), "overtaken", None))
    res["reference_no"] = res["original_no"].fillna(res["overtaken_by_no"])
    rtt_ms = res["flow"].map({int(k): float(v) * 1000 for k, v in (handshake_rtt_s or {}).items()})
    res["handshake_rtt_ms"] = rtt_ms
    res["faster_than_rtt"] = (res["interval_ms"] < rtt_ms).where(res["interval_ms"].notna() & rtt_ms.notna())
    # What is this packet most likely? Wireshark calls anything below the highest sequence number seen a "retransmission", even a segment that was merely
    # delayed. A real retransmission needs about one round trip of feedback, so we compare the interval with the flow's handshake RTT. (inferred)
    known = res["faster_than_rtt"].notna()
    res["verdict"] = np.select(
        [~known, res["faster_than_rtt"] == False, (res["faster_than_rtt"] == True) & (res["basis"] == "original"), (res["faster_than_rtt"] == True) & (res["basis"] == "overtaken")],  # noqa: E712
        ["undetermined", "retransmission", "duplicate", "reordering"], "undetermined")
    return res.reset_index(drop=True)


# --------------------------------------------------------------------------------------------------------------
# congestion indicators (3D) - INFERRED, cautious
# --------------------------------------------------------------------------------------------------------------
CAVEAT = ("Inferred from passive observations. The sender's congestion window (cwnd) is internal to the sender and is not visible in a capture; "
          "retransmissions and duplicate ACKs alone do not prove congestion.")


def _burst(g: pd.DataFrame) -> tuple[float | None, float | None]:
    """Peak packets in any 10 ms bin and peak / mean over the flow's active bins (burstiness)."""
    if len(g) < 20:
        return None, None
    b = (g["rel_time"] // 0.01).astype(int).value_counts()
    return float(b.max()), float(b.max() / b.mean())


def assess_flow(row: dict) -> tuple[str, list[dict]]:
    ev = []
    data_pk = max(row["data_packets"], 1)
    # Loss needs a retransmission that really waited (>= 1 round trip) or TCP's own trigger (3 duplicate ACKs in a row). Wireshark's "retransmission" flag alone is not
    # enough: it also marks segments that were only reordered. Retransmissions we cannot classify (no handshake RTT) still count, to stay on the cautious side.
    loss = row["retransmissions_likely"] > 0 or row["retx_undetermined"] > 0 or row["dup_ack_bursts"] > 0
    reorder = (row["out_of_order"] > 0 or row["reordered_late"] > 0 or row["duplicate_copies"] > 0) and not loss
    rwnd = row["zero_windows"] > 0 or row["window_full"] > 0
    rtt_inflation = row["rtt_ratio"] is not None and row["rtt_ratio"] >= 2 and row["rtt_ratio_samples"] >= 10
    ecn = row["ce_marks"] > 0 or (row["ecn_negotiated"] is True and row["ece_packets"] > 0)
    if row["retransmissions"]:
        ev.append({"basis": "observed", "text": f"{row['retransmissions']} packet(s) flagged as retransmissions by Wireshark ({100 * row['retransmissions'] / data_pk:.1f}% of data packets), "
                                                f"{row['fast_retransmissions']} fast, {row['spurious_retransmissions']} spurious"})
        ev.append({"basis": "derived", "text": f"Of those: {row['retransmissions_likely']} likely real (took at least one round trip), {row['reordered_late']} late arrivals (reordering), "
                                               f"{row['duplicate_copies']} duplicate copies, {row['retx_undetermined']} undetermined"})
    if row["dup_acks"]:
        ev.append({"basis": "observed", "text": f"{row['dup_acks']} duplicate ACK(s), {row['dup_ack_bursts']} run(s) of 3 or more for the same number"})
    if row["out_of_order"]:
        ev.append({"basis": "observed", "text": f"{row['out_of_order']} out-of-order segment(s)"})
    if rtt_inflation:
        ev.append({"basis": "derived", "text": f"RTT rose to {row['rtt_ratio_p95_ms']:.1f} ms (p95) vs {row['rtt_ratio_min_ms']:.1f} ms minimum ({row['rtt_ratio']:.1f}×) for ACKs of the "
                                               f"{row['rtt_ratio_dir']} data – could be queueing or ACK delay"})
    if rwnd:
        ev.append({"basis": "observed", "text": f"{row['zero_windows']} zero-window and {row['window_full']} window-full event(s) – receiver flow control"})
    if ecn:
        ev.append({"basis": "observed", "text": f"ECN: {row['ce_marks']} CE-marked packet(s), {row['ece_packets']} ECE echo(es)"})
    if row["data_packets"] < 20 and not (loss or ecn or rwnd):
        return "Insufficient evidence (very little data in this flow)", ev
    if ecn:
        label = "Possible congestion-related symptoms (explicit ECN signal observed)"
    elif loss and rtt_inflation:
        label = "Possible congestion-related symptoms (loss indicators together with RTT inflation)"
    elif loss:
        label = "Possible loss or reordering (not enough evidence to call it congestion)"
    elif reorder:
        label = "Possible packet reordering"
    elif rwnd:
        label = "Possible receiver flow-control limitation"
    elif rtt_inflation:
        label = "RTT variation without loss indicators (cause unknown)"
    else:
        label = "No congestion indicators observed"
    return label, ev


def build_congestion(df: pd.DataFrame, flows: pd.DataFrame, options: pd.DataFrame, window_dir: pd.DataFrame) -> pd.DataFrame:
    if flows.empty:
        return pd.DataFrame()
    tcp = df[df["is_tcp"]]
    opt = options.set_index("flow") if len(options) else pd.DataFrame()
    fl = flows.set_index("flow")
    rows = []
    for sid, g in tcp.groupby("tcp_stream"):
        sid = int(sid)
        fr = fl.loc[sid]
        gd = g[~g["syn"]]                      # ECN/CWR on SYN packets is negotiation, not congestion signalling
        rtt = g["ack_rtt"].dropna() * 1e3
        # RTT inflation is judged per direction of the ACKs, and only for real network round trips: with a capture on one end, ACKs for the other
        # side's data are produced on the capturing machine and come back in microseconds (below 1 ms), which would make any ratio meaningless
        infl = None
        for dirn, gg in g[g["ack_rtt"].notna()].groupby("direction"):
            x = gg["ack_rtt"] * 1e3
            if len(x) >= 10 and x.min() >= 1.0:
                ratio = float(x.quantile(0.95) / x.min())
                if infl is None or ratio > infl["ratio"]:
                    infl = {"ratio": ratio, "min": float(x.min()), "p95": float(x.quantile(0.95)), "n": int(len(x)), "dir": "client's" if dirn == "fwd" else "server's"}
        bif = g["bytes_in_flight"].dropna()
        peak, burst = _burst(g)
        row = {"flow": sid, "client": fr["client"], "server": fr["server"], "data_packets": int((g["tcp_len"] > 0).sum()),
               "retransmissions": int(fr["retransmissions"]), "fast_retransmissions": int(fr["fast_retransmissions"]), "spurious_retransmissions": int(fr["spurious_retransmissions"]),
               "dup_acks": int(fr["dup_acks"]), "out_of_order": int(fr["out_of_order"]), "dup_ack_bursts": int(fr["dup_ack_bursts"]),
               "retransmissions_likely": int(fr["retransmissions_likely"]), "reordered_late": int(fr["reordered_late"]), "duplicate_copies": int(fr["duplicate_copies"]),
               "retx_undetermined": int(fr["retx_undetermined"]),
               "zero_windows": int(g["zero_window"].sum()), "window_full": int(g["window_full"].sum()),
               "rtt_samples": int(len(rtt)), "rtt_min_ms": float(rtt.min()) if len(rtt) else None, "rtt_p95_ms": float(rtt.quantile(0.95)) if len(rtt) else None,
               "rtt_ratio": infl["ratio"] if infl else None, "rtt_ratio_min_ms": infl["min"] if infl else None, "rtt_ratio_p95_ms": infl["p95"] if infl else None,
               "rtt_ratio_samples": infl["n"] if infl else 0, "rtt_ratio_dir": infl["dir"] if infl else None,
               "bytes_in_flight_max": float(bif.max()) if len(bif) else None, "bytes_in_flight_avg": float(bif.mean()) if len(bif) else None,
               "ece_packets": int(gd["ece"].sum()), "cwr_packets": int(gd["cwr"].sum()), "ce_marks": int((gd["ecn"] == 3).sum()),
               "ecn_negotiated": (opt.loc[sid, "ecn_negotiated"] if sid in getattr(opt, "index", []) else None),
               "peak_packets_per_10ms": peak, "burstiness": burst}
        label, ev = assess_flow(row)
        row.update({"assessment": label, "evidence": ev, "retransmission_pct": 100 * row["retransmissions"] / max(row["data_packets"], 1)})
        rows.append(row)
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------------------------------------------
# orchestrator
# --------------------------------------------------------------------------------------------------------------
def analyze(df: pd.DataFrame, enabled: bool = True) -> TcpResult:
    """Adds role / direction / eff_win / win_status columns to `df` and returns every TCP table. enabled=False (TCP not in the protocol scope) skips the work."""
    res = TcpResult()
    for col, default in (("role", ""), ("eff_win", np.nan), ("win_status", "")):      # columns the packet views rely on, even without TCP
        if col not in df.columns:
            df[col] = default
    if not enabled or not df["is_tcp"].any():
        return res
    roles = assign_roles(df)
    res.options, res.options_dir, res.window_dir = analyze_options_and_windows(df, roles)
    res.flows = build_flows(df, roles)
    res.findings = build_findings(df)
    tcp = df[df["is_tcp"]]
    res.rtt_ack = tcp[tcp["ack_rtt"].notna()][["no", "rel_time", "tcp_stream", "direction", "ack_rtt", "acks_frame"]].rename(
        columns={"no": "ack_packet", "tcp_stream": "flow", "ack_rtt": "rtt"}).reset_index(drop=True)
    res.rtt_ack["flow"] = res.rtt_ack["flow"].astype(int)
    # Wireshark puts initial_rtt (SYN -> SYN-ACK) on EVERY packet after the handshake, but it is one measurement per connection:
    # keep only the first packet of each flow (the one that completes the handshake), so samples = flows
    res.rtt_initial = tcp[tcp["initial_rtt"].notna()].sort_values("no").drop_duplicates("tcp_stream")[["no", "rel_time", "tcp_stream", "initial_rtt"]].rename(
        columns={"no": "packet", "tcp_stream": "flow", "initial_rtt": "rtt"}).reset_index(drop=True)
    res.rtt_initial["flow"] = res.rtt_initial["flow"].astype(int)
    res.rtt_ts = timestamp_rtt(df, res.options)
    # classify every flagged retransmission once (real retransmission vs late arrival vs duplicate) and count it per flow
    res.retx = retransmission_intervals(df, res.rtt_initial.groupby("flow")["rtt"].first().to_dict() if len(res.rtt_initial) else {})
    per = res.retx.groupby(["flow", "verdict"]).size().unstack(fill_value=0).reindex(columns=["retransmission", "reordering", "duplicate", "undetermined"], fill_value=0) if len(res.retx) else pd.DataFrame(columns=["retransmission", "reordering", "duplicate", "undetermined"])
    for col, name in (("retransmission", "retransmissions_likely"), ("reordering", "reordered_late"), ("duplicate", "duplicate_copies"), ("undetermined", "retx_undetermined")):
        res.flows[name] = res.flows["flow"].map(per[col]).fillna(0).astype(int)
    res.flows["dup_ack_bursts"] = res.flows["flow"].map(dup_ack_bursts(df)).fillna(0).astype(int)
    res.congestion = build_congestion(df, res.flows, res.options, res.window_dir)

    n = lambda c: int(tcp[c].sum())
    ack = stats(res.rtt_ack["rtt"] * 1e3) if len(res.rtt_ack) else None
    ts = stats(res.rtt_ts["rtt"] * 1e3) if len(res.rtt_ts) else None
    res.summary = {
        "tcp_packets": int(len(tcp)), "tcp_flows": int(len(res.flows)),
        "retransmissions": int((tcp["retransmission"] | tcp["fast_retransmission"]).sum()), "fast_retransmissions": n("fast_retransmission"),
        "spurious_retransmissions": n("spurious_retransmission"), "out_of_order": n("out_of_order"), "dup_acks": n("duplicate_ack"),
        "zero_windows": n("zero_window"), "resets": n("rst"),
        "likely_retransmissions": int(res.flows["retransmissions_likely"].sum()), "late_arrivals": int(res.flows["reordered_late"].sum()),
        "duplicate_copies": int(res.flows["duplicate_copies"].sum()), "retx_undetermined": int(res.flows["retx_undetermined"].sum()),
        "dup_ack_bursts": int(res.flows["dup_ack_bursts"].sum()),
        "rtt_samples": ack["count"] if ack else 0, "rtt_min_ms": ack["min"] if ack else None, "rtt_avg_ms": ack["avg"] if ack else None,
        "rtt_p95_ms": ack["p95"] if ack else None, "rtt_max_ms": ack["max"] if ack else None,
        "rtt_ts_samples": ts["count"] if ts else 0, "rtt_ts_avg_ms": ts["avg"] if ts else None,
        "flows_with_issues": int((res.flows["issues"] > 0).sum()),
    }
    return res
