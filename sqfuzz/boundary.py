"""The signature length-boundary sweep (Finding 1 / open upstream issue #23).

For a valid seed signature we submit every length 0 .. CRYPTO_BYTES-1 (truncated
prefixes) plus a range of oversized lengths, and record for each length whether
the verifier crashed under AddressSanitizer, and if so the crashing source line
and out-of-bounds read size. Exact length (CRYPTO_BYTES) and oversized lengths
are expected NOT to crash.

The result is descriptive data about a public, non-production reference at a
fixed commit -- an independent reproduction of an already-open, team
-acknowledged robustness issue, not a vulnerability report.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Callable, Optional

from . import layout, mutate
from .runner import RunnerFn, run_one


@dataclass
class LengthResult:
    length: int
    kind: str                      # asan_crash | accept | reject | error
    crashes: bool
    source: Optional[str]          # "file.c:line"
    oob_size: Optional[int]
    access: Optional[str]          # READ | WRITE
    error_type: Optional[str]      # e.g. heap-buffer-overflow
    field: Optional[str]           # the field whose decode was executing
    strategy: str                  # truncate | oversize

    def as_dict(self) -> dict:
        return asdict(self)


def sweep(runner: RunnerFn, level: str, pk_hex: str, msg_hex: str, sig: bytes,
          oversize_max: Optional[int] = None,
          progress: Optional[Callable[[int, int], None]] = None) -> list[LengthResult]:
    """Run the full length sweep and return one LengthResult per length."""
    cb = layout.crypto_bytes(level)
    inputs = list(mutate.truncations(sig, level, oversize_max=oversize_max))
    # Also include the exact-length input (CRYPTO_BYTES) as a control.
    from .mutate import TestInput
    inputs.append(TestInput(sig, "exact", str(cb)))
    inputs.sort(key=lambda t: int(t.detail))

    out: list[LengthResult] = []
    total = len(inputs)
    for i, inp in enumerate(inputs):
        r = run_one(runner, pk_hex, msg_hex, inp)
        length = len(inp.sig)
        crashes = r.kind == "asan_crash"
        rep = r.report
        fld = layout.field_at(level, length) if length < cb else None
        out.append(LengthResult(
            length=length,
            kind=r.kind,
            crashes=crashes,
            source=rep.source if rep else None,
            oob_size=rep.oob_size if rep else None,
            access=rep.access if rep else None,
            error_type=rep.error_type if rep else None,
            field=fld.name if fld else None,
            strategy=inp.strategy,
        ))
        if progress is not None:
            progress(i + 1, total)
    return out


def summarize(results: list[LengthResult], level: str) -> dict:
    """Roll the per-length results up into the committed JSON structure."""
    cb = layout.crypto_bytes(level)
    crashing = [r for r in results if r.crashes]
    undersized = [r for r in results if r.length < cb]
    undersized_crash = [r for r in undersized if r.crashes]

    # source line -> {count, lengths}
    by_source: dict[str, dict] = {}
    for r in crashing:
        src = r.source or "unknown"
        entry = by_source.setdefault(src, {"count": 0, "lengths": [], "field": r.field})
        entry["count"] += 1
        entry["lengths"].append(r.length)

    exact = next((r for r in results if r.length == cb), None)
    oversized = [r for r in results if r.length > cb]

    return {
        "level": level,
        "crypto_bytes": cb,
        "n_undersized": len(undersized),
        "n_undersized_crash": len(undersized_crash),
        "all_undersized_crash": len(undersized) > 0 and len(undersized_crash) == len(undersized),
        "exact_length_crashes": bool(exact and exact.crashes),
        "exact_length_kind": exact.kind if exact else None,
        "n_oversized": len(oversized),
        "n_oversized_crash": sum(1 for r in oversized if r.crashes),
        "oversized_kinds": sorted({r.kind for r in oversized}),
        "crash_sources": by_source,
        "per_length": [r.as_dict() for r in results],
    }
