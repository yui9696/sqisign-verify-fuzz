"""Structure-aware, deterministic mutator for SQIsign signatures.

Given a valid signature (as bytes) the mutator produces three families of test
inputs, all reproducibly derived from a seed:

  * ``truncations`` -- every length 0 .. CRYPTO_BYTES-1, plus a set of oversized
    lengths (valid signature with trailing bytes appended). This is the dataset
    for the length-boundary sweep (Finding 1 / open issue #23).
  * ``field_mutations`` -- keep the length exactly CRYPTO_BYTES but randomize a
    named field or region. Used for the correct-length robustness fuzz.
  * ``random_correct_length`` -- fully random buffers of exactly CRYPTO_BYTES.

All randomness comes from ``random.Random(seed)`` so a given seed reproduces
the same inputs on any machine.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Iterator

from . import layout


@dataclass(frozen=True)
class TestInput:
    """One fuzz input: the raw signature bytes plus provenance metadata."""

    __test__ = False  # not a pytest test class despite the name

    sig: bytes
    strategy: str  # "truncate" | "oversize" | "field" | "random"
    detail: str    # e.g. length, field name


def _hexbytes(h: str) -> bytes:
    return bytes.fromhex(h)


def truncations(sig: bytes, level: str, oversize_step: int = 1,
                oversize_max: int | None = None) -> Iterator[TestInput]:
    """Yield every truncation length 0..CB-1 and a range of oversized lengths.

    Oversized inputs are the valid signature with deterministic filler bytes
    (0xAB) appended, up to ``oversize_max`` extra bytes (default CB).
    """
    cb = layout.crypto_bytes(level)
    assert len(sig) == cb, (len(sig), cb)
    for n in range(0, cb):
        yield TestInput(sig[:n], "truncate", str(n))
    extra_max = cb if oversize_max is None else oversize_max
    for extra in range(1, extra_max + 1, oversize_step):
        yield TestInput(sig + b"\xab" * extra, "oversize", str(cb + extra))


def field_mutations(sig: bytes, level: str, n: int, rng: random.Random) -> Iterator[TestInput]:
    """Yield *n* correct-length inputs each with one named field/region
    randomized (length stays exactly CRYPTO_BYTES)."""
    cb = layout.crypto_bytes(level)
    assert len(sig) == cb
    flds = layout.fields(level)
    for _ in range(n):
        f = rng.choice(flds)
        buf = bytearray(sig)
        for i in range(f.offset, f.end):
            buf[i] = rng.randrange(256)
        yield TestInput(bytes(buf), "field", f.name)


def mat_entry_mutations(sig: bytes, level: str, n: int, rng: random.Random) -> Iterator[TestInput]:
    """Yield *n* correct-length inputs with the four matrix entries randomized
    (the deep-verification stress used for the negative result)."""
    cb = layout.crypto_bytes(level)
    mat_fields = [f for f in layout.fields(level) if f.name.startswith("mat")]
    lo = min(f.offset for f in mat_fields)
    hi = max(f.end for f in mat_fields)
    for _ in range(n):
        buf = bytearray(sig)
        for i in range(lo, hi):
            buf[i] = rng.randrange(256)
        yield TestInput(bytes(buf), "field", "mat[*][*]")


def e_aux_mutations(sig: bytes, level: str, n: int, rng: random.Random) -> Iterator[TestInput]:
    """Yield *n* correct-length inputs with the E_aux_A curve encoding
    randomized."""
    f = layout.field_by_name(level, "E_aux_A")
    for _ in range(n):
        buf = bytearray(sig)
        for i in range(f.offset, f.end):
            buf[i] = rng.randrange(256)
        yield TestInput(bytes(buf), "field", "E_aux_A")


def random_correct_length(level: str, n: int, rng: random.Random) -> Iterator[TestInput]:
    """Yield *n* fully random buffers of exactly CRYPTO_BYTES."""
    cb = layout.crypto_bytes(level)
    for _ in range(n):
        buf = bytes(rng.randrange(256) for _ in range(cb))
        yield TestInput(buf, "random", "random")


def correct_length_batch(sig: bytes, level: str, n_each: int, seed: int) -> dict[str, list[TestInput]]:
    """Build the three correct-length strategies used for the negative result:
    fully-random, matrix-entry-randomized, E_aux_A-randomized. Deterministic."""
    rng = random.Random(seed)
    return {
        "random": list(random_correct_length(level, n_each, rng)),
        "mat_entry": list(mat_entry_mutations(sig, level, n_each, rng)),
        "e_aux": list(e_aux_mutations(sig, level, n_each, rng)),
    }
