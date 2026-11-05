"""RTP. Loss / jitter come from Wireshark's RTP analysis (RFC 3550 jitter) - generic UDP timing is never used as RTP jitter.
Sequence-number checks (expected vs received, reordering, duplicates) are derived here from the dissected RTP fields."""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import capture
from .base import load_base
from .charts import chart, clean, metric, over_time, table
from .context import Context
from .util import numeric, pl


def _unwrap(seq: np.ndarray) -> np.ndarray:
    """16-bit RTP sequence numbers -> monotonic integers (handles wrap-around)."""
    out = np.empty(len(seq), dtype=np.int64)
    cycles, prev = 0, None
    for i, s in enumerate(seq):
        if prev is not None and s < prev - 32768:
            cycles += 1
        elif prev is not None and s > prev + 32768 and cycles > 0:
            cycles -= 1
        out[i] = s + 65536 * cycles
        prev = s
    return out


def stream_checks(p: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for key, g in p.groupby(["src", "sport", "dst", "dport", "ssrc"], sort=False):
        g = g.sort_values("no")
        u = _unwrap(g["seq"].astype(int).to_numpy())
        running = np.maximum.accumulate(u)
        reordered = int((u < np.concatenate([[u[0]], running[:-1]])).sum())
        dup = int(len(u) - len(set(u.tolist())))
        expected = int(u.max() - u.min() + 1)
        d = g["time"].diff().dropna() * 1000
        rows.append({"src": key[0], "sport": key[1], "dst": key[2], "dport": key[3], "ssrc": key[4], "received": int(len(u)), "expected": expected,
                     "lost_estimate": max(expected - (len(u) - dup), 0), "reordered": reordered, "duplicates": dup,
                     "iat_mean_ms": float(d.mean()) if len(d) else None, "iat_std_ms": float(d.std(ddof=0)) if len(d) else None, "iat_max_ms": float(d.max()) if len(d) else None})
    return pd.DataFrame(rows)


def analyze(ctx: Context) -> tuple[dict, pd.DataFrame]:
    heur = ctx.heuristic_rtp
    streams = capture.rtp_streams(ctx.ts, ctx.path, heur)
    df = load_base(ctx, "rtp", [("ssrc", "rtp.ssrc"), ("rseq", "rtp.seq"), ("rts", "rtp.timestamp"), ("pt", "rtp.p_type")], heuristic_rtp=heur)
    df["seq"] = numeric(df["rseq"])
    df["ssrc"] = df["ssrc"].str.split(";").str[0]
    df["rtp_ts"] = numeric(df["rts"])
    chk = stream_checks(df.dropna(subset=["seq"])) if len(df) else pd.DataFrame()
    if len(streams) and len(chk):
        streams = streams.merge(chk, on=["src", "sport", "dst", "dport", "ssrc"], how="left")
    total = int(streams["packets"].sum()) if len(streams) else 0
    lost = int(streams["lost"].sum()) if len(streams) else 0
    metrics = [
        metric("RTP streams", int(len(streams)), tip="tshark -z rtp,streams - one stream per SSRC and 5-tuple.", basis="observed"), metric("RTP packets", total, basis="observed"),
        metric("Lost packets (Wireshark)", lost if len(streams) else None, tip="Wireshark's count from gaps in RTP sequence numbers.", why="No RTP streams.", basis="observed"),
        metric("Loss rate", (100 * lost / max(total + lost, 1)) if len(streams) else None, fmt="pct", tip="lost ÷ (received + lost).", why="No RTP streams."),
        metric("Lost packets (engine estimate)", int(chk["lost_estimate"].sum()) if len(chk) else None, tip="expected (max seq − min seq + 1) minus received, derived from the dissected sequence numbers.", why="No per-packet RTP data."),
        metric("Reordered packets", int(chk["reordered"].sum()) if len(chk) else None, tip="Packets whose sequence number is lower than one already seen.", why="No per-packet RTP data."),
        metric("Duplicate packets", int(chk["duplicates"].sum()) if len(chk) else None, why="No per-packet RTP data."),
        metric("Max jitter (RFC 3550)", float(streams["max_jitter_ms"].max()) if len(streams) else None, fmt="ms", tip="Interarrival jitter as defined by RFC 3550, computed by Wireshark.", why="No RTP streams.", basis="observed"),
        metric("Mean jitter (RFC 3550)", float(streams["mean_jitter_ms"].mean()) if len(streams) else None, fmt="ms", why="No RTP streams.", basis="observed"),
        metric("Streams flagged with problems", int(streams["problems"].sum()) if len(streams) else None, tip="Wireshark's 'Problems?' column.", basis="observed"),
        metric("Voice quality (MOS / R-factor)", None, why="Not provided by tshark statistics (Wireshark's RTP Player/Analysis dialog computes it interactively)."),
    ]
    lab = [f"{r.src}:{r.sport}→{r.dst}:{r.dport}" for r in streams.itertuples()] if len(streams) else []
    charts = {c["id"]: c for c in clean([
        chart("rtp_jit", "Jitter per stream (RFC 3550, ms)", "bar", lab, [{"name": "mean jitter", "data": [float(v) for v in streams["mean_jitter_ms"]]},
                                                                      {"name": "max jitter", "data": [float(v) for v in streams["max_jitter_ms"]]}], unit="ms") if len(streams) else None,
        chart("rtp_loss", "Lost packets per stream", "bar", lab, [{"name": "lost (Wireshark)", "data": [int(v) for v in streams["lost"]]}]) if len(streams) else None,
        chart("rtp_iat", "Packet inter-arrival time per stream (ms)", "bar", lab, [{"name": "mean", "data": [float(v or 0) for v in streams.get("iat_mean_ms", [])]},
              {"name": "max", "data": [float(v or 0) for v in streams.get("iat_max_ms", [])]}], unit="ms", tip="Generic arrival spacing; RTP jitter is the separate RFC 3550 value above.") if len(streams) and "iat_mean_ms" in streams else None,
        over_time("rtp_time", "RTP packets over time", df["rel_time"]) if len(df) else None,
    ])}
    cols = [("src", "Source", "text", False), ("sport", "Port", "text", False), ("dst", "Destination", "text", False), ("dport", "Port", "text", False), ("ssrc", "SSRC", "text", False),
            ("payload", "Payload type", "text", False), ("packets", "Packets", "num", True), ("lost", "Lost", "num", True), ("lost_pct", "Lost %", "pct", True),
            ("mean_delta_ms", "Mean Δ", "ms", True), ("max_delta_ms", "Max Δ", "ms", True), ("mean_jitter_ms", "Mean jitter", "ms", True), ("max_jitter_ms", "Max jitter", "ms", True)]
    if len(streams) and "reordered" in streams:
        cols += [("expected", "Expected", "num", True), ("reordered", "Reordered", "num", True), ("duplicates", "Duplicates", "num", True)]
    cols.append(("problems", "Problems", "text", False))
    tables = {"streams": table("streams", "RTP streams", streams, cols, tip="tshark -z rtp,streams plus sequence checks from the dissected RTP fields.")} if len(streams) else {}
    sections = [{"id": "summary", "title": "Summary", "metrics": "all", "charts": ["rtp_loss", "rtp_time"]}, {"id": "streams", "title": "Streams", "tables": ["streams"]},
                {"id": "timing", "title": "Timing & Jitter", "charts": ["rtp_jit", "rtp_iat"]}]
    notes = ["RTP is recognised automatically only when signalling (SIP/SDP) is in the capture."]
    if heur:
        notes.append("These streams were found with Wireshark's RTP heuristic (bare UDP that looks like RTP) - verify before relying on them.")
    detail = {
        "key": "rtp", "label": "RTP", "filter": "rtp" + (" (heuristic)" if heur else ""),
        "summary": f"{pl(len(streams), 'RTP stream')}, {pl(total, 'packet')}, {lost} lost" + (" - detected heuristically." if heur else "."),
        "card": [pl(len(streams), "stream"), pl(total, "packet"), f"{lost} lost"],
        "insight": {"text": f"RTP: {lost} lost packet(s) across {pl(len(streams), 'stream')}", "tone": "bad" if lost else "ok"},
        "metrics": metrics, "charts": list(charts.values()), "tables": list(tables.values()), "sections": sections, "notes": notes,
    }
    return detail, df
