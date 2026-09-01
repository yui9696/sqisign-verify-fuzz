from pathlib import Path

from sqfuzz import runner
from sqfuzz.mutate import TestInput

FIX = Path(__file__).parent / "fixtures"


def test_parse_real_encode207_sample():
    text = (FIX / "asan_encode207.txt").read_text()
    rep = runner.parse_asan(text)
    assert rep is not None
    assert rep.error_type == "heap-buffer-overflow"
    assert rep.access == "READ"
    assert rep.oob_size == 16
    assert rep.source == "encode_verification.c:207"
    assert rep.function.endswith("signature_from_bytes")


def test_parse_real_fp_decode_sample():
    text = (FIX / "asan_fp_decode.txt").read_text()
    rep = runner.parse_asan(text)
    assert rep is not None
    assert rep.source == "fp_p5248_64.c:689"
    assert rep.access == "READ"
    assert rep.oob_size == 1
    assert rep.function.endswith("fp_decode")


def test_parse_none_when_no_asan():
    assert runner.parse_asan("accept\n") is None
    assert runner.parse_asan("warning: something\nreject\n") is None


def test_summary_fallback_to_frame(monkeypatch):
    # A report with no SUMMARY line should fall back to the first SQIsign frame,
    # skipping the ASan runtime frames.
    text = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
        "READ of size 8 at 0x1 thread T0\n"
        "    #0 0x1 in __asan_memcpy+0x400 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x1)\n"
        "    #1 0x2 in sqisign_lvl1_ref_signature_from_bytes encode_verification.c:213\n"
    )
    rep = runner.parse_asan(text)
    assert rep.source == "encode_verification.c:213"
    assert rep.oob_size == 8


def _ti(n=148):
    return TestInput(b"\x00" * n, "x", str(n))


def test_classify_asan_crash():
    text = (FIX / "asan_encode207.txt").read_text()
    r = runner.classify(_ti(100), "", text, -6)
    assert r.kind == "asan_crash"
    assert r.source == "encode_verification.c:207"


def test_classify_reject_with_warning_prefix():
    # the reference prints warnings to stdout ahead of the verdict
    stdout = "warning: kernel does not have order ...\nreject\n"
    r = runner.classify(_ti(), stdout, "", 1)
    assert r.kind == "reject"


def test_classify_accept_and_error():
    assert runner.classify(_ti(), "accept\n", "", 0).kind == "accept"
    assert runner.classify(_ti(), "pk_wrong_size(3!=65)\n", "", 3).kind == "error"
