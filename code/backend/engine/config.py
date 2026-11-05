"""Central configuration. Every tunable lives here (0 = no limit; all three limits are OFF by default) and can be overridden with an environment variable
(or by passing a Limits object to engine.analyze) - nothing else in the code base hard-codes these values."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Limits:
    max_pcap_size_mb: int = field(default_factory=lambda: _int("MAX_PCAP_SIZE_MB", 0))
    max_analysis_seconds: int = field(default_factory=lambda: _int("MAX_ANALYSIS_SECONDS", 0))
    max_extracted_packets: int = field(default_factory=lambda: _int("MAX_EXTRACTED_PACKETS", 0))   # 0 = unlimited
    row_cap: int = 3000          # rows returned per table in a response
    sample_cap: int = 20000      # chart points returned per series

    @property
    def max_pcap_bytes(self) -> int:
        """0 = no size limit."""
        return self.max_pcap_size_mb * 1024 * 1024


ENGINE_VERSION = "2.0"
