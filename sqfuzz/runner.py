"""Run fuzz inputs against the ASan verify runner, one process per input.

AddressSanitizer aborts the process on the first memory error, so we spawn one
``verify_one`` process per input. Each result is classified as:

    accept         verifier returned 0
    reject         verifier returned non-zero (malformed but safely rejected)
    asan_crash     AddressSanitizer reported a memory error (parsed for the
                   crashing source file:line and the out-of-bounds read size)
    error          harness-level error (e.g. wrong-sized public key)

This reproduces open upstream issue #23 (memory-safety of the verifier's fixed
-size decode when the caller-declared signature length is short); it is not a
vulnerability scan.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from .mutate import TestInput

# ---------------------------------------------------------------------------
# AddressSanitizer report parsing
# ---------------------------------------------------------------------------

_RE_ERRTYPE = re.compile(r"AddressSanitizer:\s+([a-z0-9\-]+)")
_RE_ACCESS = re.compile(r"\b(READ|WRITE) of size (\d+)\b")
# SUMMARY: AddressSanitizer: heap-buffer-overflow <file>:<line> in <func>
_RE_SUMMARY = re.compile(
    r"SUMMARY:\s+AddressSanitizer:\s+\S+\s+(\S+?):(\d+)\s+in\s+(\S+)"
)
# A stack frame carrying a source location, e.g.
#     #1 0x... in sqisign_lvl1_ref_signature_from_bytes encode_verification.c:207
_RE_FRAME = re.compile(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+(\S+?):(\d+)")


@dataclass(frozen=True)
class AsanReport:
    error_type: str            # e.g. "heap-buffer-overflow"
    access: Optional[str]      # "READ" | "WRITE" | None
    oob_size: Optional[int]    # size of the offending access
    source: Optional[str]      # "file.c:line" (basename), from SUMMARY
    function: Optional[str]    # crashing function name


def parse_asan(text: str) -> Optional[AsanReport]:
    """Parse an AddressSanitizer report out of *text* (stderr). Returns None if
    no ASan error is present."""
    if "AddressSanitizer:" not in text:
        return None
    m_err = _RE_ERRTYPE.search(text)
    error_type = m_err.group(1) if m_err else "unknown"

    access = oob_size = None
    m_acc = _RE_ACCESS.search(text)
    if m_acc:
        access = m_acc.group(1)
        oob_size = int(m_acc.group(2))

    source = function = None
    m_sum = _RE_SUMMARY.search(text)
    if m_sum:
        source = f"{_basename(m_sum.group(1))}:{m_sum.group(2)}"
        function = m_sum.group(3)
    else:
        # Fall back to the first stack frame that is in SQIsign code (skip the
        # ASan runtime memcpy/memset interceptor frames).
        for fn, fpath, line in _RE_FRAME.findall(text):
            if "__asan" in fn or "libclang_rt" in fpath:
                continue
            source = f"{_basename(fpath)}:{line}"
            function = fn
            break
    return AsanReport(error_type, access, oob_size, source, function)


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


# ---------------------------------------------------------------------------
# Result model and process runner
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Result:
    input: TestInput
    kind: str                      # accept | reject | asan_crash | error
    report: Optional[AsanReport] = None
    exit_code: Optional[int] = None
    stdout: str = ""

    @property
    def source(self) -> Optional[str]:
        return self.report.source if self.report else None


# A "runner" is any callable (pk_hex, msg_hex, sig_hex) -> (stdout, stderr,
# exit_code). This lets tests substitute a pure-Python stub with no C build.
RunnerFn = Callable[[str, str, str], tuple[str, str, int]]


def subprocess_runner(binary: str | Path, timeout: float = 60.0) -> RunnerFn:
    """A RunnerFn that invokes the compiled ``verify_one`` binary once per
    input, passing the hex triple on argv."""
    binary = str(binary)
    env = dict(os.environ)
    # Keep ASan output deterministic and on stderr; we do not care about leaks
    # here (the process aborts on the memory error we are studying).
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:log_to_stderr=1"

    def run(pk_hex: str, msg_hex: str, sig_hex: str) -> tuple[str, str, int]:
        proc = subprocess.run(
            [binary, pk_hex, msg_hex or "-", sig_hex],
            capture_output=True, text=True, env=env, timeout=timeout,
        )
        return proc.stdout, proc.stderr, proc.returncode

    return run


def _verdict(stdout: str) -> str:
    """The verifier's verdict is the LAST non-empty line of stdout. The
    reference prints ``warning: ...`` diagnostics to stdout ahead of the
    verdict on malformed-but-safely-rejected inputs, so we cannot match the
    whole of stdout."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line:
            return line
    return ""


def classify(inp: TestInput, stdout: str, stderr: str, exit_code: int) -> Result:
    report = parse_asan(stderr)
    if report is not None:
        return Result(inp, "asan_crash", report, exit_code, _verdict(stdout))
    verdict = _verdict(stdout)
    if verdict == "accept":
        return Result(inp, "accept", None, exit_code, verdict)
    if verdict == "reject":
        return Result(inp, "reject", None, exit_code, verdict)
    return Result(inp, "error", None, exit_code, verdict)


def run_one(runner: RunnerFn, pk_hex: str, msg_hex: str, inp: TestInput) -> Result:
    stdout, stderr, code = runner(pk_hex, msg_hex, inp.sig.hex())
    return classify(inp, stdout, stderr, code)


def run_batch(runner: RunnerFn, pk_hex: str, msg_hex: str,
              inputs: Iterable[TestInput],
              progress: Optional[Callable[[int], None]] = None) -> list[Result]:
    results: list[Result] = []
    for i, inp in enumerate(inputs):
        results.append(run_one(runner, pk_hex, msg_hex, inp))
        if progress is not None:
            progress(i + 1)
    return results


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

@dataclass
class Counts:
    accept: int = 0
    reject: int = 0
    asan_crash: int = 0
    error: int = 0

    def add(self, kind: str) -> None:
        setattr(self, kind, getattr(self, kind) + 1)

    def as_dict(self) -> dict:
        return {"accept": self.accept, "reject": self.reject,
                "asan_crash": self.asan_crash, "error": self.error}


def tally(results: Iterable[Result]) -> Counts:
    c = Counts()
    for r in results:
        c.add(r.kind)
    return c
