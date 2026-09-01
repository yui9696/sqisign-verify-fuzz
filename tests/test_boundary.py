from sqfuzz import boundary, layout
from tests.stub import make_stub


def _valid(level):
    return bytes((i * 5 + 1) & 0xFF for i in range(layout.crypto_bytes(level)))


def test_sweep_all_undersized_crash_stub():
    for level in layout.LEVELS:
        cb = layout.crypto_bytes(level)
        valid = _valid(level)
        stub = make_stub(level, valid)
        results = boundary.sweep(stub, level, "pk", "msg", valid, oversize_max=8)
        summary = boundary.summarize(results, level)
        assert summary["n_undersized"] == cb
        assert summary["n_undersized_crash"] == cb
        assert summary["all_undersized_crash"] is True
        assert summary["exact_length_crashes"] is False
        assert summary["exact_length_kind"] == "accept"
        assert summary["n_oversized"] == 8
        assert summary["n_oversized_crash"] == 0
        assert summary["oversized_kinds"] == ["accept"]


def test_sweep_source_line_structure_lvl1():
    level = "lvl1"
    valid = _valid(level)
    stub = make_stub(level, valid)
    results = boundary.sweep(stub, level, "pk", "msg", valid, oversize_max=2)
    summary = boundary.summarize(results, level)
    src = summary["crash_sources"]
    # encode_verification lines are real and shared; the E_aux region is a
    # synthetic fp2-decode line in the stub.
    assert "encode_verification.c:207" in src        # mat[1][0]
    assert src["encode_verification.c:207"]["lengths"] == list(range(98, 114))
    assert "encode_verification.c:199" in src        # backtracking (1 length)
    assert src["encode_verification.c:199"]["count"] == 1
    assert src["fp2_decode.c:1"]["count"] == 64      # E_aux_A region


def test_per_length_records_have_fields():
    level = "lvl1"
    valid = _valid(level)
    stub = make_stub(level, valid)
    results = boundary.sweep(stub, level, "pk", "msg", valid, oversize_max=1)
    bylen = {r.length: r for r in results}
    assert bylen[100].field == "mat[1][0]"
    assert bylen[100].crashes is True
    assert bylen[148].crashes is False
    assert bylen[149].kind == "accept"
