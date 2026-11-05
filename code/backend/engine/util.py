"""Small shared helpers: numeric conversion, missing values, address handling, JSON-safe serialisation."""
from __future__ import annotations

import ipaddress
import json
import math

import numpy as np
import pandas as pd


# ---- tshark field values (strings, ';'-joined when a field repeats) -----------------------------------------
def first(s: pd.Series) -> pd.Series:
    return s.str.split(";", n=1).str[0]


def truthy(s: pd.Series) -> pd.Series:
    return s.str.lower().str.contains(r"(?:^|;)(?:1|true)(?:;|$)", regex=True)


def numeric(s: pd.Series) -> pd.Series:
    """First value of each cell as a float (NaN when missing)."""
    return pd.to_numeric(first(s), errors="coerce")


def to_int(v):
    """'0x0304' / '17' / '17;6' -> int, None when missing."""
    try:
        return int(str(v).split(";")[0], 0)
    except (ValueError, TypeError):
        return None


def values(v) -> list[str]:
    return [x for x in str(v).split(";") if x != ""]


# ---- statistics -------------------------------------------------------------------------------------------
def stats(series) -> dict | None:
    s = pd.to_numeric(pd.Series(series), errors="coerce").dropna()
    if s.empty:
        return None
    return {"count": int(len(s)), "min": float(s.min()), "avg": float(s.mean()), "std": float(s.std(ddof=0)),
            "p95": float(s.quantile(0.95)), "max": float(s.max())}


def pl(n, word: str, plural: str | None = None) -> str:
    return f"{n:,} {word if n == 1 else (plural or word + 's')}"


# ---- addresses --------------------------------------------------------------------------------------------
def addr_category(a: str) -> str:
    """Correct address-range logic (stdlib ipaddress). Subnet-directed broadcast cannot be known without the netmask."""
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return "other"
    if str(ip) == "255.255.255.255":
        return "broadcast"
    if ip.is_multicast:
        return "multicast"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_private:
        return "private"
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "shared (CGNAT)"
    if ip.is_global:
        return "public"
    return "reserved"


# ---- JSON-safe serialisation (NaN / inf -> null, numpy -> python, DataFrames never leak) -----------------------
def jsonable(o):
    if o is None or isinstance(o, (str, bool)):
        return o
    if isinstance(o, (np.bool_,)):
        return bool(o)
    if isinstance(o, (int, np.integer)):
        return int(o)
    if isinstance(o, (float, np.floating)):
        f = float(o)
        return f if math.isfinite(f) else None
    if isinstance(o, pd.DataFrame):
        return jsonable(json.loads(o.to_json(orient="records")))
    if isinstance(o, pd.Series):
        return jsonable(o.tolist())
    if isinstance(o, dict):
        return {str(k): jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [jsonable(v) for v in o]
    if isinstance(o, (pd.Timestamp, np.datetime64)):
        return str(o)
    if o is pd.NA or o is pd.NaT:
        return None
    return str(o)


def records(df: pd.DataFrame) -> list[dict]:
    return json.loads(df.to_json(orient="records"))


def thin(df: pd.DataFrame, limit: int, keep: pd.Series | None = None) -> pd.DataFrame:
    """Down-sample a table for charts but always keep the rows flagged by `keep`."""
    if len(df) <= limit:
        return df
    keep = keep if keep is not None else pd.Series(False, index=df.index)
    rest = df[~keep]
    step = max(1, len(rest) // max(1, limit - int(keep.sum())))
    return pd.concat([df[keep], rest.iloc[::step]]).sort_index()
