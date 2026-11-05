"""The ONLY place that builds and runs tshark commands.

* every command is bounded by MAX_ANALYSIS_SECONDS (when configured)
* `fields()` runs one `-T fields` pass, skips fields this tshark version does not know (recorded in `unavailable`)
  and can parse the output in chunks so memory stays bounded
"""
from __future__ import annotations

import io
import shutil
import subprocess
import tempfile
import threading
import time

import pandas as pd

from .config import Limits
from .errors import AnalysisTimeout, EngineError, InvalidCapture, TsharkMissing

_ENV = {"LC_ALL": "C"}


class Tshark:
    def __init__(self, limits: Limits | None = None, binary: str | None = None):
        self.limits = limits or Limits()
        self.binary = binary or shutil.which("tshark")
        self.unavailable: set[str] = set()
        self._deadline: float | None = None
        self._fields: set[str] | None = None
        self._fields_loaded = False
        self._version: str | None = None
        self._lock = threading.Lock()

    # ---- environment ----------------------------------------------------------------------------------------
    def require(self) -> str:
        if not self.binary:
            raise TsharkMissing("TShark is not installed or not on the PATH. Install it (macOS: brew install wireshark · "
                                "Debian/Ubuntu: sudo apt install tshark · Colab: !apt-get install -y tshark) and restart.")
        return self.binary

    @property
    def version(self) -> str:
        if self._version is None:
            out = subprocess.run([self.require(), "-v"], capture_output=True, text=True).stdout
            self._version = out.splitlines()[0] if out else "unknown"
        return self._version

    def start_clock(self) -> None:
        """Start the analysis time budget (no-op when MAX_ANALYSIS_SECONDS = 0, i.e. unlimited)."""
        self._deadline = time.monotonic() + self.limits.max_analysis_seconds if self.limits.max_analysis_seconds else None

    def _remaining(self) -> float | None:
        if self._deadline is None:
            return None                                   # no time limit
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise AnalysisTimeout(f"Analysis stopped: it exceeded the {self.limits.max_analysis_seconds}s limit (MAX_ANALYSIS_SECONDS). "
                                  f"Try a smaller capture or raise the limit.")
        return left

    # ---- running ---------------------------------------------------------------------------------------------
    def run(self, args: list[str], allow_fail: bool = False) -> str:
        """Run tshark and return stdout (text)."""
        self.require()
        try:
            r = subprocess.run([self.binary, *args], capture_output=True, text=True, timeout=self._remaining(), env={**__import__("os").environ, **_ENV})
        except subprocess.TimeoutExpired:
            raise AnalysisTimeout(f"Analysis stopped: a tshark command exceeded the {self.limits.max_analysis_seconds}s limit (MAX_ANALYSIS_SECONDS).")
        if r.returncode != 0 and not allow_fail and not r.stdout.strip():
            raise InvalidCapture(f"tshark could not read this capture: {r.stderr.strip()[:300] or 'unknown error'}")
        return r.stdout

    def stat(self, path: str, spec: str, extra: list[str] | None = None) -> str:
        """tshark -q -z <spec>  (conv, endpoints, io,stat, io,phs, rtp,streams ...)"""
        return self.run(["-n", "-r", path, *(extra or []), "-q", "-z", spec])

    def available_fields(self) -> set[str] | None:
        """All field names this tshark knows (None if it cannot be determined -> assume everything exists)."""
        if not self._fields_loaded:
            self._fields_loaded = True
            try:
                out = subprocess.run([self.require(), "-G", "fields"], capture_output=True, text=True, timeout=60).stdout
                self._fields = {p[2] for p in (l.split("\t") for l in out.splitlines() if l.startswith(("F\t", "P\t"))) if len(p) > 2}   # F = field, P = protocol/presence
            except Exception:
                self._fields = None
        return self._fields

    def has_field(self, name: str) -> bool:
        av = self.available_fields()
        return av is None or name in av

    # ---- field extraction ------------------------------------------------------------------------------------
    def fields(self, path: str, display_filter: str | None, cols: list[tuple[str, str]], *, two_pass: bool = False, max_packets: int = 0,
               heuristic_rtp: bool = False, chunk_fn=None, chunksize: int = 200_000) -> pd.DataFrame:
        """One `tshark -T fields` pass. `cols` = [(column_name, tshark_field)]. Unknown fields become empty columns."""
        self.require()
        use = [(n, f) for n, f in cols if self.has_field(f)]
        for n, f in cols:
            if not self.has_field(f):
                self.unavailable.add(f)
        names = [n for n, _ in use]
        cmd = ["-n", "-r", path]
        if heuristic_rtp:
            cmd += ["-o", "rtp.heuristic_rtp:TRUE"]
        if two_pass:
            cmd += ["-2"]
        if max_packets:
            cmd += ["-c", str(max_packets)]
        if display_filter:
            cmd += ["-Y", display_filter]
        cmd += ["-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=;", "-E", "quote=n"]
        for _, f in use:
            cmd += ["-e", f]

        timeout = self._remaining()
        err = tempfile.TemporaryFile()
        proc = subprocess.Popen([self.binary, *cmd], stdout=subprocess.PIPE, stderr=err, text=True, bufsize=1 << 20, env={**__import__("os").environ, **_ENV})
        timed_out = threading.Event()

        def _kill():
            timed_out.set()
            proc.kill()
        timer = threading.Timer(timeout, _kill) if timeout else None
        if timer:
            timer.start()
        frames: list[pd.DataFrame] = []
        try:
            try:
                reader = pd.read_csv(proc.stdout, sep="\t", dtype=str, keep_default_na=False, names=names, header=0, quoting=3, chunksize=chunksize)
                for ch in reader:
                    for n, f in cols:                       # fields unknown to this tshark -> empty column
                        if n not in ch.columns:
                            ch[n] = ""
                    frames.append(chunk_fn(ch) if chunk_fn else ch)
            except pd.errors.EmptyDataError:
                pass
            proc.wait()
        finally:
            if timer:
                timer.cancel()
        if timed_out.is_set():
            raise AnalysisTimeout(f"Analysis stopped: a tshark pass exceeded the {self.limits.max_analysis_seconds}s limit (MAX_ANALYSIS_SECONDS).")
        if proc.returncode not in (0, None) and not frames:
            err.seek(0)
            msg = err.read().decode(errors="replace").strip()[:300]
            raise InvalidCapture(f"tshark could not read this capture: {msg or 'unknown error'}")
        err.close()
        if not frames:
            empty = pd.DataFrame({n: pd.Series(dtype=str) for n, _ in cols})
            return chunk_fn(empty) if chunk_fn else empty
        return pd.concat(frames, ignore_index=True) if len(frames) > 1 else frames[0]

    def count(self, path: str, display_filter: str, two_pass: bool = False, max_packets: int = 0) -> int:
        """Number of packets matching a display filter (streams the output, constant memory)."""
        self.require()
        cmd = ["-n", "-r", path] + (["-c", str(max_packets)] if max_packets else []) + (["-2"] if two_pass else []) + ["-Y", display_filter, "-T", "fields", "-e", "frame.number"]
        proc = subprocess.Popen([self.binary, *cmd], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        left = self._remaining()
        timer = threading.Timer(left, proc.kill) if left else None
        if timer:
            timer.start()
        try:
            n = sum(1 for _ in proc.stdout)
            proc.wait()
        finally:
            if timer:
                timer.cancel()
        return n
