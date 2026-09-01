"""Human-readable rendering of sweep and fuzz results (plain text tables)."""

from __future__ import annotations

from .boundary import LengthResult


def boundary_table(summary: dict) -> str:
    """Render the length-boundary summary as a compact source-line table."""
    lines = []
    lvl = summary["level"]
    cb = summary["crypto_bytes"]
    lines.append(f"Length-boundary sweep — {lvl} (CRYPTO_BYTES={cb})")
    lines.append(
        f"  undersized lengths crashing: "
        f"{summary['n_undersized_crash']}/{summary['n_undersized']}"
        f"  (all crash: {summary['all_undersized_crash']})"
    )
    lines.append(
        f"  exact length ({cb}): {summary['exact_length_kind']}"
        f" (crashes: {summary['exact_length_crashes']})"
    )
    lines.append(
        f"  oversized ({summary['n_oversized']} tested): "
        f"kinds={summary['oversized_kinds']}, crashes={summary['n_oversized_crash']}"
    )
    lines.append("")
    lines.append("  crash source line              field            count  length range")
    lines.append("  " + "-" * 68)
    # Sort sources by their minimum crashing length.
    items = sorted(summary["crash_sources"].items(),
                   key=lambda kv: min(kv[1]["lengths"]))
    for src, info in items:
        lens = info["lengths"]
        rng = f"{min(lens)}..{max(lens)}"
        fld = info.get("field") or "-"
        lines.append(f"  {src:<30} {fld:<16} {info['count']:>5}  {rng}")
    return "\n".join(lines)


def fuzz_table(summary: dict) -> str:
    """Render the correct-length fuzz summary."""
    lines = []
    lines.append(f"Correct-length fuzz — {summary['level']} "
                 f"(CRYPTO_BYTES={summary['crypto_bytes']}, seed={summary['seed']})")
    lines.append("  strategy      n      accept  reject  asan_crash  error")
    lines.append("  " + "-" * 56)
    for strat, c in summary["strategies"].items():
        lines.append(
            f"  {strat:<12} {c['n']:>5}  {c['accept']:>6}  {c['reject']:>6}"
            f"  {c['asan_crash']:>10}  {c['error']:>5}"
        )
    tot = summary["totals"]
    lines.append("  " + "-" * 56)
    lines.append(
        f"  {'TOTAL':<12} {tot['n']:>5}  {tot['accept']:>6}  {tot['reject']:>6}"
        f"  {tot['asan_crash']:>10}  {tot['error']:>5}"
    )
    lines.append("")
    lines.append(f"  memory-safety findings on correct-length inputs: "
                 f"{tot['asan_crash']}")
    return "\n".join(lines)
