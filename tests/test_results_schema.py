"""Schema regression for the committed results JSON.

These validate both the structure produced by the summarizers (via the stub, so
no C build is needed) and, when present, the committed results in results/.
"""

import json
from pathlib import Path

import pytest

from sqfuzz import boundary, layout
from tests.stub import make_stub

RESULTS = Path(__file__).parent.parent / "results"

BOUNDARY_KEYS = {
    "level", "crypto_bytes", "n_undersized", "n_undersized_crash",
    "all_undersized_crash", "exact_length_crashes", "exact_length_kind",
    "n_oversized", "n_oversized_crash", "oversized_kinds", "crash_sources",
    "per_length",
}
PER_LENGTH_KEYS = {
    "length", "kind", "crashes", "source", "oob_size", "access",
    "error_type", "field", "strategy",
}


def test_boundary_summary_schema_from_stub():
    level = "lvl1"
    valid = bytes((i * 3 + 2) & 0xFF for i in range(layout.crypto_bytes(level)))
    results = boundary.sweep(make_stub(level, valid), level, "pk", "msg", valid,
                             oversize_max=4)
    summary = boundary.summarize(results, level)
    assert BOUNDARY_KEYS <= set(summary)
    for row in summary["per_length"]:
        assert PER_LENGTH_KEYS == set(row)


@pytest.mark.parametrize("level", ["lvl1", "lvl3", "lvl5"])
def test_committed_boundary_results_if_present(level):
    p = RESULTS / f"boundary-{level}.json"
    if not p.exists():
        pytest.skip(f"{p} not generated in this environment")
    data = json.loads(p.read_text())
    assert BOUNDARY_KEYS <= set(data)
    assert data["level"] == level
    assert data["crypto_bytes"] == layout.crypto_bytes(level)
    # The headline: every undersized length crashes, exact + oversized do not.
    assert data["all_undersized_crash"] is True
    assert data["n_undersized_crash"] == data["crypto_bytes"]
    assert data["exact_length_crashes"] is False
    assert data["n_oversized_crash"] == 0


def test_committed_fuzz_results_if_present():
    p = RESULTS / "correct-length-fuzz.json"
    if not p.exists():
        pytest.skip("correct-length-fuzz.json not generated in this environment")
    data = json.loads(p.read_text())
    for level, summary in data.items():
        assert {"level", "strategies", "totals"} <= set(summary)
        tot = summary["totals"]
        # the negative result: zero memory-safety findings on correct-length
        assert tot["asan_crash"] == 0
        assert tot["accept"] == 0  # none of the random/malformed inputs verify
