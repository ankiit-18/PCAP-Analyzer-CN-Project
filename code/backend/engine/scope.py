"""Protocol scope: analyse only the protocols the user picked instead of the whole capture.

Why: every analyser costs at least one full pass over the capture and one DataFrame in RAM. For large captures the user usually cares about one
protocol, so a scoped run
  * asks tshark for statistics and packet rows only for the selected traffic (a display filter),
  * skips every analyser that was not selected, and
  * reads all the whole-capture statistics in ONE tshark pass instead of three.
tshark still has to read the file once (a display filter cannot skip reading), but memory and the number of passes drop with the scope.
"""
from __future__ import annotations

from .errors import EngineError

# scope key -> tshark display filter for that protocol
FILTERS = {"tcp": "tcp", "udp": "udp", "dns": "dns", "tls": "tls", "quic": "quic", "arp": "arp", "ip": "ip || ipv6"}
ALL = tuple(FILTERS)

# detected-protocol key (engine.detect) -> scope key that has to be selected for its page to be built
PAGE_SCOPE = {"tcp": "tcp", "udp": "udp", "dns": "dns", "tls": "tls", "x:quic": "quic", "x:arp": "arp"}

LABELS = {"tcp": "TCP", "udp": "UDP", "dns": "DNS", "tls": "TLS", "quic": "QUIC", "arp": "ARP", "ip": "IP"}


class BadScope(EngineError):
    status = 400


def normalise(protocols) -> frozenset[str] | None:
    """None = everything (default). Accepts None, 'all', 'tcp,udp' or an iterable of names. Raises BadScope for unknown names."""
    if protocols is None:
        return None
    if isinstance(protocols, str):
        protocols = [p for p in protocols.replace(";", ",").split(",")]
    names = {str(p).strip().lower() for p in protocols if str(p).strip()}
    if not names or "all" in names or names >= set(ALL):
        return None
    unknown = names - set(ALL)
    if unknown:
        raise BadScope(f"Unknown protocol(s): {', '.join(sorted(unknown))}. Choose from: {', '.join(ALL)}, or all.")
    return frozenset(names)


def display_filter(scope: frozenset[str] | None) -> str | None:
    """tshark display filter that keeps only the selected traffic (None = no filter)."""
    if scope is None:
        return None
    return " || ".join(f"({FILTERS[k]})" for k in ALL if k in scope)


def label(scope: frozenset[str] | None) -> str:
    return "all protocols" if scope is None else ", ".join(LABELS[k] for k in ALL if k in scope)
