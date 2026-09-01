"""Seed-corpus construction from the reference KAT (Known Answer Test) vectors.

A KAT ``.rsp`` record contains a message ``msg``, a public key ``pk`` and a
signed message ``sm`` (signature concatenated with the message). A valid
signature is the first ``CRYPTO_BYTES`` of ``sm``. We keep the (pk, msg, sig)
triple: pk and msg are needed so the reference actually reaches the signature
decode and verification path.

The KAT files are Apache-2.0 material owned by the SQIsign team and are NOT
redistributed in this repository (see NOTICE); the user supplies a path to
their own reference checkout's ``KAT/`` directory.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from . import layout


@dataclass(frozen=True)
class Seed:
    level: str
    count: int  # KAT record index
    pk_hex: str
    msg_hex: str
    sig_hex: str  # exactly CRYPTO_BYTES, hex-encoded

    def to_json(self) -> dict:
        return asdict(self)


def _parse_rsp(text: str) -> list[dict]:
    """Parse a NIST KAT .rsp file into a list of {count,msg,pk,sm,...} dicts."""
    records, cur = [], {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if key == "count":
            if cur:
                records.append(cur)
            cur = {"count": int(val)}
        else:
            cur[key] = val
    if cur:
        records.append(cur)
    return records


def seeds_from_kat(kat_path: str | Path, level: str, limit: int | None = None) -> list[Seed]:
    """Read up to *limit* seeds from a KAT .rsp file for *level*."""
    text = Path(kat_path).read_text()
    cb_hex = layout.crypto_bytes(level) * 2
    pk_hex_len = layout.pk_bytes(level) * 2
    out: list[Seed] = []
    for rec in _parse_rsp(text):
        sm = rec.get("sm")
        pk = rec.get("pk")
        msg = rec.get("msg", "")
        if not sm or not pk:
            continue
        sig = sm[:cb_hex]
        if len(sig) != cb_hex or len(pk) != pk_hex_len:
            continue
        out.append(Seed(level, rec["count"], pk.upper(), msg.upper(), sig.upper()))
        if limit is not None and len(out) >= limit:
            break
    return out


def find_kat(kat_dir: str | Path, level: str) -> Path:
    """Locate the KAT .rsp file for *level* under *kat_dir*."""
    p = Path(kat_dir) / layout.KAT_BASENAME[level]
    if not p.exists():
        raise FileNotFoundError(
            f"KAT file for {level} not found at {p}. Point --kat-dir at your "
            f"reference checkout's KAT/ directory."
        )
    return p


def write_corpus(seeds: list[Seed], out_path: str | Path) -> None:
    Path(out_path).write_text(json.dumps([s.to_json() for s in seeds], indent=2))
