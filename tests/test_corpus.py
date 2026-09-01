from sqfuzz import corpus, layout

# A tiny synthetic KAT record (not real vectors): a 148-byte signature followed
# by a 3-byte message make up `sm`; pk is 65 bytes. Values are arbitrary hex.
_SIG = "AB" * 148
_MSG = "010203"
_PK = "CD" * 65
_RSP = f"""# SQIsign_lvl1

count = 0
seed = 00
mlen = 3
msg = {_MSG}
pk = {_PK}
sk = 00
smlen = 151
sm = {_SIG}{_MSG}

count = 1
seed = 00
mlen = 3
msg = {_MSG}
pk = {_PK}
sk = 00
smlen = 151
sm = {_SIG}{_MSG}
"""


def test_parse_rsp_and_seed(tmp_path):
    p = tmp_path / "PQCsignKAT_353_SQIsign_lvl1.rsp"
    p.write_text(_RSP)
    seeds = corpus.seeds_from_kat(p, "lvl1")
    assert len(seeds) == 2
    s = seeds[0]
    assert len(s.sig_hex) == layout.crypto_bytes("lvl1") * 2
    assert s.sig_hex == _SIG
    assert s.pk_hex == _PK
    assert s.msg_hex == _MSG.upper()
    assert s.level == "lvl1"


def test_seed_limit(tmp_path):
    p = tmp_path / "PQCsignKAT_353_SQIsign_lvl1.rsp"
    p.write_text(_RSP)
    assert len(corpus.seeds_from_kat(p, "lvl1", limit=1)) == 1


def test_find_kat_basename(tmp_path):
    (tmp_path / layout.KAT_BASENAME["lvl3"]).write_text("")
    assert corpus.find_kat(tmp_path, "lvl3").name == layout.KAT_BASENAME["lvl3"]
