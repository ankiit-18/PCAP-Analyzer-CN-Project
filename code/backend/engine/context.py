"""Shared state handed to every analyzer."""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .config import Limits
from .tcp import TcpResult
from .tshark import Tshark


@dataclass
class Context:
    ts: Tshark
    path: str
    limits: Limits
    packets: pd.DataFrame                 # extracted packets (possibly a subset - see `partial`)
    totals: dict                          # whole-capture totals from tshark -z io,stat,0
    tcp: TcpResult
    partial: bool = False
    max_packets: int = 0                  # 0 = no cap; else every detailed pass reads only the first N packets
    heuristic_rtp: bool = False
    scratch: dict = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return float(self.totals.get("duration_s") or 0.0)

    def load(self, display_filter: str, cols, **kw) -> pd.DataFrame:
        """Protocol-specific `-T fields` pass over the same packet subset as the main extraction."""
        kw.setdefault("max_packets", self.max_packets)
        return self.ts.fields(self.path, display_filter, cols, **kw)
