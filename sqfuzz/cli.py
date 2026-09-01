"""Command-line interface for the SQIsign verification fuzz harness.

Subcommands:
    build       invoke harness/build.sh (build reference under ASan + verify_one)
    corpus      build a seed corpus from KAT vectors
    boundary    length-boundary sweep (Finding 1 / open issue #23)
    fuzz        structure-aware correct-length fuzz (the negative result)
    repro       emit the minimal undersized reproducer + its ASan trace

Nothing here presents a vulnerability: this reproduces the already-open,
team-acknowledged robustness issue #23 in a non-production reference, and
provides the fuzzing tooling upstream issue #15 asked for.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from . import boundary, corpus, layout, mutate, report
from .runner import RunnerFn, subprocess_runner, run_one, tally

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUILD = REPO_ROOT / "harness" / "build"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _default_bin(level: str) -> Path:
    return DEFAULT_BUILD / f"verify_one_{level}"


def _resolve_bin(args) -> Path:
    b = Path(args.bin) if args.bin else _default_bin(args.level)
    if not b.exists():
        sys.exit(
            f"error: verify runner not found: {b}\n"
            f"Build it first:  sqisign-verify-fuzz build --src <reference-checkout>\n"
            f"or pass --bin <path to verify_one_{args.level}>."
        )
    return b


def _load_seed(args) -> corpus.Seed:
    kat = corpus.find_kat(args.kat_dir, args.level)
    seeds = corpus.seeds_from_kat(kat, args.level, limit=args.seed_index + 1)
    if len(seeds) <= args.seed_index:
        sys.exit(f"error: KAT has fewer than {args.seed_index + 1} usable records")
    return seeds[args.seed_index]


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------

def cmd_build(args) -> int:
    script = REPO_ROOT / "harness" / "build.sh"
    env = dict(os.environ)
    if args.src:
        env["SQISIGN_SRC"] = str(Path(args.src).resolve())
    if args.levels:
        env["LEVELS"] = " ".join(args.levels)
    _stderr(f"running {script}")
    return subprocess.call(["bash", str(script)], env=env)


def cmd_corpus(args) -> int:
    seeds = []
    for level in (args.levels or list(layout.LEVELS)):
        try:
            kat = corpus.find_kat(args.kat_dir, level)
        except FileNotFoundError as e:
            _stderr(f"skip {level}: {e}")
            continue
        s = corpus.seeds_from_kat(kat, level, limit=args.limit)
        _stderr(f"{level}: {len(s)} seeds")
        seeds.extend(s)
    if args.out:
        corpus.write_corpus(seeds, args.out)
        _stderr(f"wrote {len(seeds)} seeds -> {args.out}")
    else:
        print(json.dumps([s.to_json() for s in seeds], indent=2))
    return 0


def cmd_boundary(args) -> int:
    binary = _resolve_bin(args)
    seed = _load_seed(args)
    runner = subprocess_runner(binary)
    sig = bytes.fromhex(seed.sig_hex)

    def prog(i, total):
        if i % 25 == 0 or i == total:
            _stderr(f"  sweep {i}/{total}")

    _stderr(f"length-boundary sweep {args.level} using KAT record #{seed.count}")
    results = boundary.sweep(runner, args.level, seed.pk_hex, seed.msg_hex, sig,
                             oversize_max=args.oversize_max, progress=prog)
    summary = boundary.summarize(results, args.level)
    summary["seed_index"] = args.seed_index
    summary["kat_record"] = seed.count
    summary["binary"] = binary.name

    print(report.boundary_table(summary))
    out = args.out or (REPO_ROOT / "results" / f"boundary-{args.level}.json")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(summary, indent=2))
    _stderr(f"wrote {out}")
    return 0


def cmd_fuzz(args) -> int:
    binary = _resolve_bin(args)
    seed = _load_seed(args)
    runner = subprocess_runner(binary)
    sig = bytes.fromhex(seed.sig_hex)
    n_each = args.n

    batch = mutate.correct_length_batch(sig, args.level, n_each, args.seed)
    strategies = {}
    totals = {"n": 0, "accept": 0, "reject": 0, "asan_crash": 0, "error": 0}
    for strat, inputs in batch.items():
        _stderr(f"  fuzzing {strat}: {len(inputs)} inputs")
        results = [run_one(runner, seed.pk_hex, seed.msg_hex, inp) for inp in inputs]
        c = tally(results).as_dict()
        c["n"] = len(inputs)
        strategies[strat] = c
        for k in totals:
            totals[k] += c[k] if k != "n" else c["n"]
        # capture any crashing example verbatim (should be none)
        crashes = [r for r in results if r.kind == "asan_crash"]
        if crashes:
            strategies[strat]["example_crash"] = {
                "sig_hex": crashes[0].input.sig.hex(),
                "source": crashes[0].source,
            }

    summary = {
        "level": args.level,
        "crypto_bytes": layout.crypto_bytes(args.level),
        "seed": args.seed,
        "n_each": n_each,
        "kat_record": seed.count,
        "binary": binary.name,
        "strategies": strategies,
        "totals": totals,
    }
    print(report.fuzz_table(summary))
    out = args.out or (REPO_ROOT / "results" / "correct-length-fuzz.json")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    # merge per-level into a single file if it already exists
    merged = {}
    if Path(out).exists() and not args.overwrite:
        try:
            merged = json.loads(Path(out).read_text())
        except json.JSONDecodeError:
            merged = {}
    merged[args.level] = summary
    Path(out).write_text(json.dumps(merged, indent=2))
    _stderr(f"wrote {out}")
    return 0


def cmd_repro(args) -> int:
    binary = _resolve_bin(args)
    seed = _load_seed(args)
    sig = bytes.fromhex(seed.sig_hex)
    cb = layout.crypto_bytes(args.level)
    prefix = args.prefix_bytes
    if prefix >= cb:
        sys.exit(f"error: --prefix-bytes must be < CRYPTO_BYTES ({cb})")
    trunc = sig[:prefix]

    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:log_to_stderr=1"
    proc = subprocess.run(
        [str(binary), seed.pk_hex, seed.msg_hex or "-", trunc.hex()],
        capture_output=True, text=True, env=env, timeout=60,
    )
    from .runner import parse_asan
    rep = parse_asan(proc.stderr)

    fld = layout.field_at(args.level, prefix)
    header = [
        "SQIsign verification robustness — minimal undersized reproducer",
        "",
        "This is an INDEPENDENT REPRODUCTION of the already-open, team-acknowledged",
        "upstream issue #23 (heap out-of-bounds READ when the verifier fixed-size-",
        "decodes a signature shorter than CRYPTO_BYTES). It is NOT a vulnerability",
        "disclosure, NOT a 0-day, NOT an exploit. The reference is explicitly not",
        "production-ready (upstream issue #3) and not constant-time (spec §7).",
        "",
        f"level            : {args.level}",
        f"CRYPTO_BYTES     : {cb}",
        f"reproducer length: {prefix} bytes (a {prefix}-byte prefix of a valid signature)",
        f"buffer ends in   : field {fld.name if fld else '?'}",
        f"crash source     : {rep.source if rep else 'NO CRASH'}",
        f"access / size    : {rep.access if rep else '-'} / "
        f"{rep.oob_size if rep else '-'}",
        f"verify_one exit  : {proc.returncode}",
        "",
        "input (hex):",
        f"  pk  = {seed.pk_hex}",
        f"  msg = {seed.msg_hex}",
        f"  sig = {trunc.hex()}",
        "",
        "verbatim AddressSanitizer report:",
        "-" * 72,
    ]
    text = "\n".join(header) + "\n" + proc.stderr.rstrip() + "\n"
    print(text)
    out = args.out or (REPO_ROOT / "results" / "minimal-repro.txt")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(text)
    _stderr(f"wrote {out}")
    return 0


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sqisign-verify-fuzz",
        description="AddressSanitizer verification-robustness fuzz harness for "
                    "SQIsign (independent reproduction of open upstream issue #23).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pb = sub.add_parser("build", help="build reference under ASan + verify_one")
    pb.add_argument("--src", help="existing reference checkout (skips clone)")
    pb.add_argument("--levels", nargs="+", choices=layout.LEVELS)
    pb.set_defaults(func=cmd_build)

    pc = sub.add_parser("corpus", help="build seed corpus from KAT vectors")
    pc.add_argument("--kat-dir", required=True)
    pc.add_argument("--levels", nargs="+", choices=layout.LEVELS)
    pc.add_argument("--limit", type=int, default=1)
    pc.add_argument("--out")
    pc.set_defaults(func=cmd_corpus)

    def add_common(sp):
        sp.add_argument("--level", required=True, choices=layout.LEVELS)
        sp.add_argument("--kat-dir", required=True)
        sp.add_argument("--bin", help="path to verify_one binary")
        sp.add_argument("--seed-index", type=int, default=0,
                        help="which KAT record to use as the valid seed")

    ps = sub.add_parser("boundary", help="length-boundary sweep (issue #23)")
    add_common(ps)
    ps.add_argument("--oversize-max", type=int, default=None,
                    help="max extra bytes for oversized tests (default CRYPTO_BYTES)")
    ps.add_argument("--out")
    ps.set_defaults(func=cmd_boundary)

    pf = sub.add_parser("fuzz", help="correct-length structure-aware fuzz")
    add_common(pf)
    pf.add_argument("--n", type=int, default=2000, help="inputs per strategy")
    pf.add_argument("--seed", type=int, default=0)
    pf.add_argument("--out")
    pf.add_argument("--overwrite", action="store_true")
    pf.set_defaults(func=cmd_fuzz)

    pr = sub.add_parser("repro", help="minimal undersized reproducer + ASan trace")
    add_common(pr)
    pr.add_argument("--prefix-bytes", type=int, default=100)
    pr.add_argument("--out")
    pr.set_defaults(func=cmd_repro)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
