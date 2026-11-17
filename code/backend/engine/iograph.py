"""Wireshark-style I/O graph: packets, bytes or bits per second over time, for the packets of one protocol view.

Computed by the engine from the packet table (frame length and capture time), so every value is *derived*. The user can change the interval, the
measure and how the traffic is split into lines (nothing / application protocol / conversation), like the controls of Wireshark's I/O Graphs window.
"""
from __future__ import annotations

import math

import numpy as np
import pandas as pd

from .charts import bin_width, chart

INTERVALS_S = [0.001, 0.01, 0.1, 1.0, 10.0, 60.0, 600.0]        # selectable bin widths (Wireshark offers the same 1 ms ... 10 min)
MEASURES = {"packets": ("packets per second", "count", 1.0), "bytes": ("bytes per second", "bytes", 1.0), "bits": ("bits per second", "bps", 8.0)}
SPLITS = ("none", "app", "conversation")


def _nice(x: float) -> float:
    """Round up to 1, 2 or 5 x 10^k."""
    e = 10 ** math.floor(math.log10(x))
    for m in (1, 2, 5, 10):
        if m * e >= x:
            return m * e
    return 10 * e


def _labels(df: pd.DataFrame, split: str) -> pd.Series | None:
    if split == "app":
        return df["app"].astype(str).replace("", "unrecognised") if "app" in df else None
    if split == "conversation" and "udp_stream" in df:
        first = df.groupby("udp_stream")[["src", "sport", "dst", "dport"]].first()
        name = first["src"].astype(str) + ":" + first["sport"].astype(str) + " → " + first["dst"].astype(str) + ":" + first["dport"].astype(str)
        return df["udp_stream"].map(name).fillna("unknown")
    return None


def io_graph(df: pd.DataFrame, interval: float | None = None, measure: str = "packets", split: str = "none", name: str = "UDP",
             max_bins: int = 20000, top: int = 6) -> dict:
    """interval=None -> automatic. Returns {"chart": <chart spec>, "interval_s", "auto", "measure", "split", "bins", "peak", "peak_at_s", "average", "packets", "bytes", ...}."""
    measure = measure if measure in MEASURES else "packets"
    split = split if split in SPLITS else "none"
    t = pd.to_numeric(df.get("rel_time"), errors="coerce")
    ok = t.notna()
    df, t = df[ok], t[ok]
    base = {"measure": measure, "split": split, "available_intervals_s": INTERVALS_S, "chart": None}
    if df.empty:
        return {**base, "interval_s": None, "auto": True, "bins": 0, "packets": 0, "bytes": 0}

    origin = min(0.0, float(t.min()))                          # like Wireshark the axis starts at the start of the capture
    last = float(t.max())
    span = max(last - origin, 1e-9)
    auto = interval is None or interval <= 0
    iv = bin_width(span, 100) if auto else float(interval)
    if span / iv + 1 > max_bins:                               # too many points for a browser: widen the interval and say so
        iv = _nice(span / max_bins)
    n = int((last - origin) // iv) + 1
    idx = ((t - origin) // iv).astype(int).to_numpy()
    label, unit, factor = MEASURES[measure]
    w = (np.ones(len(df)) if measure == "packets" else pd.to_numeric(df["length"], errors="coerce").fillna(0).to_numpy()) * factor
    rate = lambda mask: [round(float(v) / iv, 3) for v in np.bincount(idx[mask], weights=w[mask], minlength=n)]
    everything = np.ones(len(df), dtype=bool)
    total = np.array(rate(everything))

    series = []
    lab = _labels(df, split)
    if lab is None:
        series.append({"name": name, "data": total.tolist()})
    else:
        lab = lab.reset_index(drop=True)
        order = pd.Series(w).groupby(lab).sum().sort_values(ascending=False)
        keep = list(order.index[:top])
        for k in keep:
            series.append({"name": str(k), "data": rate((lab == k).to_numpy())})
        if len(order) > top:
            series.append({"name": f"other ({len(order) - top})", "data": rate((~lab.isin(keep)).to_numpy())})

    peak_i = int(total.argmax())
    x = [round(origin + i * iv, 6) for i in range(n)]
    spec = chart("io_graph", f"{name} I/O graph", "line", series=series, x=x, unit=unit, x_label="time (s)", y_label=label,
                 tip=f"{label} in {iv:g} s intervals, from frame length and capture time (derived).")
    return {
        **base, "chart": spec, "interval_s": iv, "auto": bool(auto), "bins": n, "packets": int(len(df)), "bytes": int(pd.to_numeric(df["length"], errors="coerce").fillna(0).sum()),
        "peak": float(total[peak_i]), "peak_at_s": float(x[peak_i]), "average": float(w.sum() / max(span, iv)) if span > 0 else float(w.sum() / iv),
        "widened": bool(not auto and abs(iv - float(interval)) > 1e-12), "requested_interval_s": None if auto else float(interval),
    }
