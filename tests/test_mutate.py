import random

from sqfuzz import layout, mutate


def _valid(level):
    # a deterministic stand-in "valid" signature of the right length
    return bytes((i * 7 + 3) & 0xFF for i in range(layout.crypto_bytes(level)))


def test_truncation_lengths_cover_all():
    level = "lvl1"
    cb = layout.crypto_bytes(level)
    ts = list(mutate.truncations(_valid(level), level, oversize_max=4))
    trunc = [t for t in ts if t.strategy == "truncate"]
    over = [t for t in ts if t.strategy == "oversize"]
    assert [len(t.sig) for t in trunc] == list(range(0, cb))
    assert [len(t.sig) for t in over] == [cb + 1, cb + 2, cb + 3, cb + 4]
    # oversized preserves the valid prefix
    assert over[0].sig[:cb] == _valid(level)


def test_field_mutation_stays_in_length():
    level = "lvl1"
    cb = layout.crypto_bytes(level)
    rng = random.Random(1)
    for ti in mutate.field_mutations(_valid(level), level, 20, rng):
        assert len(ti.sig) == cb
        assert ti.strategy == "field"


def test_field_mutation_changes_only_named_field_region():
    level = "lvl1"
    base = _valid(level)
    rng = random.Random(123)
    ti = next(mutate.e_aux_mutations(base, level, 1, rng))
    f = layout.field_by_name(level, "E_aux_A")
    # bytes outside E_aux_A are untouched
    assert ti.sig[f.end:] == base[f.end:]


def test_determinism_same_seed():
    level = "lvl1"
    base = _valid(level)
    a = mutate.correct_length_batch(base, level, 25, seed=7)
    b = mutate.correct_length_batch(base, level, 25, seed=7)
    for strat in a:
        assert [t.sig for t in a[strat]] == [t.sig for t in b[strat]]


def test_determinism_different_seed_differs():
    level = "lvl1"
    base = _valid(level)
    a = mutate.correct_length_batch(base, level, 25, seed=1)
    b = mutate.correct_length_batch(base, level, 25, seed=2)
    assert [t.sig for t in a["random"]] != [t.sig for t in b["random"]]


def test_random_correct_length_size():
    rng = random.Random(0)
    for level in layout.LEVELS:
        for ti in mutate.random_correct_length(level, 5, rng):
            assert len(ti.sig) == layout.crypto_bytes(level)
