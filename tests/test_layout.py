from sqfuzz import layout


def test_offsets_sum_to_crypto_bytes():
    for level in layout.LEVELS:
        flds = layout.fields(level)
        assert flds[0].offset == 0
        # contiguous, no gaps
        for a, b in zip(flds, flds[1:]):
            assert a.end == b.offset
        assert flds[-1].end == layout.crypto_bytes(level)


def test_known_sizes():
    assert layout.crypto_bytes("lvl1") == 148
    assert layout.crypto_bytes("lvl3") == 224
    assert layout.crypto_bytes("lvl5") == 292
    assert layout.pk_bytes("lvl1") == 65
    e = layout.field_by_name("lvl1", "E_aux_A")
    assert (e.offset, e.size) == (0, 64)


def test_field_at_boundaries_lvl1():
    # first byte after E_aux_A (offset 64) is backtracking
    assert layout.field_at("lvl1", 63).name == "E_aux_A"
    assert layout.field_at("lvl1", 64).name == "backtracking"
    assert layout.field_at("lvl1", 65).name == "two_resp_length"
    # the 100-byte reproducer ends inside mat[1][0]
    assert layout.field_at("lvl1", 100).name == "mat[1][0]"
    assert layout.field_at("lvl1", 147).name == "hint_chall"
    # at/after CRYPTO_BYTES -> None
    assert layout.field_at("lvl1", 148) is None


def test_expected_read_size():
    # single-byte *enc++ fields
    assert layout.expected_read_size("lvl1", 64) == 1     # backtracking
    assert layout.expected_read_size("lvl1", 147) == 1    # hint_chall
    # decode_digits bulk reads
    assert layout.expected_read_size("lvl1", 100) == 16   # mat[1][0]
    assert layout.expected_read_size("lvl3", 100) == 25   # mat entry lvl3
    # E_aux region is empirical -> None
    assert layout.expected_read_size("lvl1", 10) is None
