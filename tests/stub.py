"""A pure-Python stub RunnerFn that models the reference verifier's *length*
behaviour, so the test-suite exercises the whole pipeline (mutator -> runner ->
classifier -> boundary summarizer) with NO C build and NO AddressSanitizer.

It deliberately mirrors the three observed behaviours:
  * len < CRYPTO_BYTES  -> heap-buffer-overflow READ (synthetic ASan report,
    with the real encode_verification.c line for the field that is decoding, and
    a synthetic fp2-decode line for the E_aux_A region)
  * len == CRYPTO_BYTES -> accept if it is the valid seed, else reject
  * len  > CRYPTO_BYTES -> accept if it starts with the valid seed (trailing
    bytes ignored), else reject
"""

from __future__ import annotations

from sqfuzz import layout

_ASAN_TEMPLATE = """\
=================================================================
==4242==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60b000000000 at pc 0x0001 bp 0x0002 sp 0x0003
READ of size {size} at 0x60b000000000 thread T0
    #0 0x0001 in __asan_memcpy+0x400 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3b1f8)
    #1 0x0002 in sqisign_{lv}_ref_signature_from_bytes {source}
    #2 0x0003 in sqisign_{lv}_ref_sqisign_verify sqisign.c:101
    #3 0x0004 in run verify_one.c:63
SUMMARY: AddressSanitizer: heap-buffer-overflow {source} in sqisign_{lv}_ref_signature_from_bytes
"""


def _asan_text(level: str, length: int) -> str:
    f = layout.field_at(level, length)
    if f is None:
        raise AssertionError(length)
    if f.name == "E_aux_A":
        source = "fp2_decode.c:1"   # synthetic; the real file name is prime-specific
        size = 1
    else:
        source = layout.ENCODE_SOURCE[f.name]
        size = layout.expected_read_size(level, length) or 1
    return _ASAN_TEMPLATE.format(size=size, source=source, lv=level)


def make_stub(level: str, valid_sig: bytes):
    """Return a RunnerFn (pk_hex, msg_hex, sig_hex) -> (stdout, stderr, code)."""
    cb = layout.crypto_bytes(level)

    def run(pk_hex: str, msg_hex: str, sig_hex: str):
        sig = bytes.fromhex(sig_hex) if sig_hex else b""
        n = len(sig)
        if n < cb:
            return "", _asan_text(level, n), -6
        if n == cb:
            return ("accept\n", "", 0) if sig == valid_sig else ("reject\n", "", 1)
        # oversized: reference reads only the first cb bytes
        if sig[:cb] == valid_sig:
            return "accept\n", "", 0
        return "reject\n", "", 1

    return run
