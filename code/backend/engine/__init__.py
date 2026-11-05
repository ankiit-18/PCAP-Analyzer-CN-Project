"""PCAP analysis engine (TShark-based). One implementation shared by the backend API and the notebooks.

    from engine import analyze, to_dict
    report = analyze("capture.pcap")          # engine.errors.EngineError subclasses carry user-facing messages
    data = to_dict(report)                    # unified, JSON-safe report
"""
from .config import ENGINE_VERSION, Limits
from .errors import AnalysisTimeout, CaptureTooLarge, EngineError, InvalidCapture, TsharkMissing
from .report import Report, analyze, to_dict
from .validate import cross_validate

__all__ = ["analyze", "to_dict", "cross_validate", "Report", "Limits", "ENGINE_VERSION", "EngineError", "InvalidCapture", "CaptureTooLarge", "AnalysisTimeout", "TsharkMissing"]
