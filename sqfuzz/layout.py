"""Per-level SQIsign signature byte layout, as data.

The signature encoding is defined by ``signature_to_bytes`` /
``signature_from_bytes`` in the reference file
``src/verification/ref/lvlx/encode_verification.c`` (shared across levels), plus
the level-specific field element encoder ``fp2_from_bytes``.

Field order (all levels)::

    E_aux_A            fp2 element   (64 / 96 / 128 bytes)
    backtracking       1 byte
    two_resp_length    1 byte
    mat[0][0]          nbytes        (16 / 25 / 32 bytes)
    mat[0][1]          nbytes
    mat[1][0]          nbytes
    mat[1][1]          nbytes
    chall_coeff        SECURITY_BITS/8  (16 / 24 / 32 bytes)
    hint_aux           1 byte
    hint_chall         1 byte

The reference ``sqisign_verify`` ignores ``siglen`` and decodes a *fixed*
``CRYPTO_BYTES`` from the caller's buffer. When the buffer is shorter than
``CRYPTO_BYTES`` the decode reads past its end -- the memory-safety behaviour
this harness reproduces (open upstream issue #23). The mapping below records,
for a given truncation length, which field's decode step is reading when the
buffer ends, and the exact reference source line that appears in the
AddressSanitizer report for that step.

This is descriptive data about a public, non-production reference; it is not a
vulnerability description. See docs/findings.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Level parameters
# ---------------------------------------------------------------------------

# CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES, fp2 element size, matrix-entry size,
# SECURITY_BITS. Taken from src/nistapi/lvlN/api.h and the reference encoders.
_PARAMS = {
    "lvl1": dict(crypto_bytes=148, pk_bytes=65, e_aux=64, mat=16, sec_bits=128),
    "lvl3": dict(crypto_bytes=224, pk_bytes=97, e_aux=96, mat=25, sec_bits=192),
    "lvl5": dict(crypto_bytes=292, pk_bytes=129, e_aux=128, mat=32, sec_bits=256),
}

LEVELS = tuple(_PARAMS.keys())

# The KAT file basename per level (the modulus bit-count appears in the name).
KAT_BASENAME = {
    "lvl1": "PQCsignKAT_353_SQIsign_lvl1.rsp",
    "lvl3": "PQCsignKAT_529_SQIsign_lvl3.rsp",
    "lvl5": "PQCsignKAT_701_SQIsign_lvl5.rsp",
}

# Reference source line (verbatim from the ASan report) that is executing when
# a truncated buffer ends inside each named field. The encode_verification.c
# lines are shared across all levels (the file lives in .../lvlx/). The E_aux_A
# field is decoded by the level-specific fp2 element decoder, whose file name
# depends on the prime, so it is resolved from the actual ASan output at run
# time and only marked here as the fp2-decode region.
ENCODE_SOURCE = {
    "backtracking": "encode_verification.c:199",
    "two_resp_length": "encode_verification.c:200",
    "mat[0][0]": "encode_verification.c:203",
    "mat[0][1]": "encode_verification.c:205",
    "mat[1][0]": "encode_verification.c:207",
    "mat[1][1]": "encode_verification.c:209",
    "chall_coeff": "encode_verification.c:213",
    "hint_aux": "encode_verification.c:216",
    "hint_chall": "encode_verification.c:217",
}

# Whether the decode step for a field is a single-byte read (`*enc++`) or a
# bulk `decode_digits` memcpy. This determines the ASan "READ of size N".
_SINGLE_BYTE = {"backtracking", "two_resp_length", "hint_aux", "hint_chall"}


@dataclass(frozen=True)
class Field:
    name: str
    offset: int
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size


def fields(level: str) -> list[Field]:
    """Ordered list of signature fields with byte offsets for *level*."""
    p = _PARAMS[level]
    spec = [
        ("E_aux_A", p["e_aux"]),
        ("backtracking", 1),
        ("two_resp_length", 1),
        ("mat[0][0]", p["mat"]),
        ("mat[0][1]", p["mat"]),
        ("mat[1][0]", p["mat"]),
        ("mat[1][1]", p["mat"]),
        ("chall_coeff", p["sec_bits"] // 8),
        ("hint_aux", 1),
        ("hint_chall", 1),
    ]
    out, off = [], 0
    for name, size in spec:
        out.append(Field(name, off, size))
        off += size
    assert off == p["crypto_bytes"], (level, off, p["crypto_bytes"])
    return out


def crypto_bytes(level: str) -> int:
    return _PARAMS[level]["crypto_bytes"]


def pk_bytes(level: str) -> int:
    return _PARAMS[level]["pk_bytes"]


def field_at(level: str, byte_index: int) -> Optional[Field]:
    """Field whose byte range contains *byte_index* (the field whose decode is
    executing when a buffer truncated to that length overruns), or None if the
    index is at/after CRYPTO_BYTES."""
    for f in fields(level):
        if f.offset <= byte_index < f.end:
            return f
    return None


def field_by_name(level: str, name: str) -> Field:
    for f in fields(level):
        if f.name == name:
            return f
    raise KeyError(name)


def expected_read_size(level: str, byte_index: int) -> Optional[int]:
    """The AddressSanitizer 'READ of size N' expected when a buffer of length
    *byte_index* is decoded: 1 for the single-byte `*enc++` fields, the field
    size for the `decode_digits` bulk reads. None past CRYPTO_BYTES.

    (The fp2 E_aux_A decoder reads element-wise; its exact per-length size is
    taken from the real ASan output rather than predicted here.)
    """
    f = field_at(level, byte_index)
    if f is None:
        return None
    if f.name in _SINGLE_BYTE:
        return 1
    if f.name == "E_aux_A":
        return None  # determined empirically
    return f.size
