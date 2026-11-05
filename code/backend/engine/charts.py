"""Builders for the declarative page description shared by every analyzer (and rendered by the frontend / notebooks).

  metric(...)   one number; value=None -> {"available": False, "reason": ...}  (unavailable is never reported as 0)
  table(...)    {"id","title","columns":[{key,label,fmt,num}],"rows":[...],"total"}
  chart(...)    {"id","title","type": bar|barh|pie|line, ...}
Every metric carries `basis`: observed (dissected by tshark), derived (aggregated / calculated by the engine) or inferred (interpretation).
"""
from __future__ import annotations

import re

import pandas as pd

from .config import Limits
from .util import records


def metric(label, value, fmt="num", tip="", why=None, sub=None, basis="derived"):
    if value is None or (isinstance(value, float) and value != value):
        return {"label": label, "available": False, "reason": why or "Cannot be calculated from this capture.", "tip": tip, "basis": basis}
    m = {"label": label, "available": True, "value": value, "fmt": fmt, "tip": tip, "basis": basis}
    if sub:
        m["sub"] = sub
    return m


def table(id_, title, df: pd.DataFrame, columns, tip="", click=None, row_cap: int = Limits().row_cap, extra_keys=()):
    cols = [{"key": k, "label": l, "fmt": f, "num": n} for k, l, f, n in columns]
    keep = [c[0] for c in columns] + [k for k in ([click] if click else []) + list(extra_keys) if k not in [c[0] for c in columns]]
    return {"id": id_, "title": title, "tip": tip, "columns": cols, "rows": records(df.head(row_cap)[keep]), "total": int(len(df)), "click": click}


def chart(id_, title, type_, labels=None, series=None, unit="count", tip="", x_label="", y_label="", x=None):
    c = {"id": id_, "title": title, "type": type_, "unit": unit, "tip": tip, "xLabel": x_label, "yLabel": y_label, "series": series or []}
    if labels is not None:
        c["labels"] = [str(l) for l in labels]
    if x is not None:
        c["x"] = x
    return c


def counts_chart(id_, title, values: pd.Series, type_="bar", top=12, tip="", unit="count"):
    v = values.astype(str)
    vc = v[v != ""].value_counts().head(top)
    if vc.empty:
        return None
    return chart(id_, title, type_, list(vc.index), [{"name": title, "data": [int(x) for x in vc.values]}], unit=unit, tip=tip)


def histogram(id_, title, values, unit="ms", bins=20, tip="", x_label=None):
    v = pd.to_numeric(pd.Series(values), errors="coerce").dropna()
    if v.empty:
        return None
    lo, hi = float(v.min()), float(v.max())
    if hi == lo:
        return chart(id_, title, "bar", [f"{lo:.2f}"], [{"name": "samples", "data": [int(len(v))]}], tip=tip, x_label=x_label or unit, y_label="samples")
    w = (hi - lo) / bins
    idx = ((v - lo) // w).clip(upper=bins - 1).astype(int)
    counts = idx.value_counts().reindex(range(bins), fill_value=0).sort_index()
    return chart(id_, title, "bar", [f"{lo + i * w:.2f}" for i in range(bins)], [{"name": "samples", "data": [int(c) for c in counts.values]}],
                 tip=tip, x_label=x_label or unit, y_label="samples")


_STEPS = [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 300, 600, 1800, 3600]


def bin_width(duration: float, target: int = 100) -> float:
    return next((s for s in _STEPS if max(duration, 1e-6) / s <= target), 3600)


def over_time(id_, title, times, bins=60, tip="", name="packets", weights=None, unit="count", split=None):
    """Counts (or summed `weights`) per time bin. `split` = Series of category labels -> one series each."""
    t = pd.to_numeric(pd.Series(times), errors="coerce")
    ok = t.notna()
    if not ok.any():
        return None
    t = t[ok]
    dur = max(float(t.max()), 1e-6)
    bw = bin_width(dur, bins)
    idx = (t // bw).astype(int)
    n = int(dur // bw) + 1
    w = pd.Series(weights, index=times.index if hasattr(times, "index") else None)[ok] if weights is not None else None
    if split is not None:
        cats = pd.Series(split)[ok]
        series = []
        for c in cats.value_counts().index[:8]:
            m = cats == c
            s = (w[m] if w is not None else pd.Series(1, index=idx[m].index)).groupby(idx[m]).sum().reindex(range(n), fill_value=0)
            series.append({"name": str(c), "data": [float(v) for v in s.values]})
    else:
        s = (w.groupby(idx).sum() if w is not None else idx.value_counts()).reindex(range(n), fill_value=0).sort_index()
        series = [{"name": name, "data": [float(v) for v in s.values]}]
    return chart(id_, title, "line", series=series, x=[round(i * bw, 6) for i in range(n)], unit=unit, tip=f"{tip} (bin = {bw:g} s)".strip(),
                 x_label="time (s)", y_label=name)


def traffic_chart(ts, path, flt, duration, id_="traffic", title="Traffic over time"):
    """bits/s over time from `tshark -z io,stat,<interval>,<filter>` (observed by tshark)."""
    bw = bin_width(duration)
    try:
        raw = ts.stat(path, f"io,stat,{bw:g},{flt}")
    except Exception:
        return None
    t, by = [], []
    for line in raw.splitlines():
        m = re.match(r"^\|\s*([\d.]+)\s*<>\s*([\d.]+|Dur)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", line)
        if m:
            t.append(float(m.group(1)))
            by.append(int(m.group(4)))
    if not t:
        return None
    return chart(id_, title, "line", series=[{"name": "bits/s", "data": [round(b * 8 / bw, 1) for b in by]}], x=t, unit="bps",
                 tip=f"tshark -z io,stat,{bw:g},{flt}  (frame bytes × 8 ÷ interval)", x_label="time (s)", y_label="bits per second")


def clean(charts):
    return [c for c in charts if c]
