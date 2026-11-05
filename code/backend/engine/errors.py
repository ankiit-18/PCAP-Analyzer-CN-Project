"""User-facing errors. `str(e)` is always safe to show in the UI."""


class EngineError(Exception):
    """Base class; the message is written for end users."""
    status = 422


class TsharkMissing(EngineError):
    status = 503


class InvalidCapture(EngineError):
    status = 400


class CaptureTooLarge(EngineError):
    status = 413


class AnalysisTimeout(EngineError):
    status = 504
