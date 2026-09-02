# sqisign-verify-fuzz

An **AddressSanitizer verification-robustness fuzz harness** for the
[SQIsign](https://sqisign.org) reference implementation (NIST additional-signatures,
isogeny-based). It builds the reference verifier under ASan, ships a KAT-seeded
corpus and a structure-aware mutator, sweeps the signature-length boundary, and
reports memory-safety behaviour with minimal reproducers.

---

## ⚠️ What this is — and what it is NOT (read this first)

> **This project INDEPENDENTLY REPRODUCES an already-public, OPEN,
> team-acknowledged robustness issue. It is NOT a discovery, NOT a 0-day, NOT a
> vulnerability disclosure, NOT an exploit, and NOT an attack.**
>
> - The undersized-signature heap out-of-bounds **read** reproduced here was
>   **first reported by [TheDarkLightX](https://github.com/TheDarkLightX)** in the
>   MIT-licensed repo **`sqisign-verification-boundary`**, and is tracked as the
>   **OPEN upstream issue #23** (opened 2026-08-13). **The SQIsign team
>   acknowledged it and scheduled the fix for the round-3 release.** Full credit
>   for the original report goes to TheDarkLightX and the SQIsign team.
> - The SQIsign reference implementation is **explicitly not production-ready**
>   (De Feo, upstream issue #3) and **not constant-time** (spec §7). The
>   behaviour studied here is a **robustness property of a reference, on one
>   machine, at one commit** — exactly what a reference is for.
> - An ASan report of an out-of-bounds **read** of adjacent heap in
>   *verification* is **not evidence of an exploitable vulnerability**. No memory
>   is written, no secret is involved (verification is public-data only), and
>   nothing here is claimed to "break" SQIsign.
>
> Throughout this repository the words *vulnerability*, *exploit*, *0-day*, and
> *attack* appear **only** inside disclaimers like this one, stating that this is
> **not** one of those. The findings are described as **robustness / memory-safety
> findings** and as a **reproduction of open issue #23**.

The **primary contribution** is the **working fuzz tooling the project lacks**:
upstream **issue #15** records that, as of Feb 2026, there was essentially no
fuzzing of SQIsign; an AFL harness was invited but the offered PR never landed,
and the shipped `apps/fuzz_verify.c` reads a corpus from a `testcases/` directory
that is not in the repository, so it cannot run out of the box. This harness
runs today against your own build, plus it adds a **precise per-truncation-length
source mapping** and a **reassuring negative result** for correct-length inputs.

This is the robustness/fuzzing sibling of the author's
**`sqisign-conformance`** (correctness) and **`sqisign-verify-cost`** (cost)
repositories, and it reuses the same philosophy: *drive the reference as an
oracle, keep all analysis in dependency-free stdlib Python.*

---

## The three findings

All reproduced on Apple Silicon (arm64, macOS), reference commit `dd133d7`, built
`Debug + -fsanitize=address`. Your numbers should match; if they differ, trust
your own run.

### Finding 1 — undersized signatures → heap out-of-bounds READ (reproduces open #23)

`sqisign_verify` **ignores its `siglen` argument** and fixed-size-decodes
`CRYPTO_BYTES` from the caller's buffer (148 / 224 / 292 at L1 / L3 / L5). So a
signature buffer *shorter* than `CRYPTO_BYTES` is read past its end.

**Every** length `0 .. CRYPTO_BYTES-1` triggers an ASan heap-buffer-overflow
read. The **exact** length and any **oversized** length do **not**. The crashing
source line is exactly determined by which field's decode is reading when the
buffer ends:

| level | undersized lengths crashing | E_aux_A region source |
|-------|-----------------------------|-----------------------|
| lvl1  | **148 / 148**               | `fp_p5248_64.c:689`   |
| lvl3  | **224 / 224**               | `fp_p65376_64.c:764`  |
| lvl5  | **292 / 292**               | `fp_p27500_64.c:856`  |

Once the buffer passes `E_aux_A`, the crash walks through the shared decoder
`encode_verification.c` field by field (lines 199, 200, 203, 205, 207, 209, 213,
216, 217). See [`docs/findings.md`](docs/findings.md) for the full per-length
table and [`docs/mechanism.md`](docs/mechanism.md) for why each length crashes
where it does.

**Minimal reproducer (lvl1):** a 100-byte prefix of a valid signature →
```
heap-buffer-overflow READ of size 16 at encode_verification.c:207
  in signature_from_bytes  <-  sqisign_verify (sqisign.c:101)
```
(full ASan trace in [`results/minimal-repro.txt`](results/minimal-repro.txt)).

### Finding 2 — oversized signatures → accepted (trailing bytes ignored)

A valid 148-byte signature with garbage appended (lengths 149…) still verifies:
the verifier reads only `CRYPTO_BYTES` and ignores the rest. This is a
malleability, consistent with SQIsign **not** claiming SUF-CMA (cf.
`sqisign-conformance`). **It is not a break.**

### Finding 3 — correct-length inputs are robust (negative result)

12,000 correct-length malformed inputs (lvl1 6000, lvl3 3000, lvl5 3000), fuzzed
under ASan across three strategies (fully random / matrix-entries randomized /
`E_aux_A` curve encoding randomized): **zero** memory-safety findings, **all**
safely rejected.
The memory-safety issue is specifically **length handling**, not the deep
verification logic, which robustly rejects malformed data. (See
[`results/correct-length-fuzz.json`](results/correct-length-fuzz.json).)

---

## Mitigation — and it shipped

The fix is a **length check before the fixed-size decode**: reject when
`siglen != CRYPTO_BYTES` (rejecting `siglen < CRYPTO_BYTES` removes the
out-of-bounds read; requiring exact equality also removes the trailing-byte
malleability). The SQIsign team stated this was coming in the round-3 release.

**It did.** Round 3 (2026-09-01, `6d01770`, tag `nist-v3`) has exactly that, in
`src/sqisign.c`, ahead of `signature_from_bytes` in both entry points:

```c
sqisign_verify(...)   if (siglen != SIGNATURE_BYTES)  return -1;
sqisign_open(...)     if (smlen  <  SIGNATURE_BYTES)  { *mlen = 0; return -1; }
```

Measured against it (ref build, macOS 26.1 / Apple Silicon, 100 KAT vectors per parameter
set, all three sets): **4200 negative cases — undersized by 1/2/16/64 bytes, declared
length past the buffer, bytes appended — none accepted**, every valid vector still
accepted, and under `CMAKE_BUILD_TYPE=ASAN` **zero AddressSanitizer findings**.

Rebuilding the identical round-3 tree with only the `sqisign_verify` length check
compiled out brings the original behaviour straight back:

```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 16
    #1 sqisign_p324_3_ref_signature_from_bytes
    #2 sqisign_p324_3_ref_sqisign_verify
```

so the shipped guard is what closes it, rather than something downstream happening to
fail first. Reported upstream on issue #23; data and harness in `sqisign-round3-lab`.

---

## Build and run (against your own reference checkout)

Requirements: a C toolchain with AddressSanitizer (clang), `cmake`, `gmp`,
Python ≥ 3.11. On macOS the build passes `-Wno-macro-redefined` (upstream open
issue #12).

```bash
# 1. Build the reference under ASan and link the per-input verify runner.
#    Clones github.com/SQISign/the-sqisign at dd133d7, or point at your checkout:
./harness/build.sh                     # or: SQISIGN_SRC=/path/to/the-sqisign ./harness/build.sh
#    -> harness/build/verify_one_lvl1 (and lvl3/lvl5)

# 2. Length-boundary sweep (Finding 1). --kat-dir is your checkout's KAT/.
export KAT=/path/to/the-sqisign/KAT
PYTHONPATH=. python -m sqfuzz boundary --level lvl1 --kat-dir "$KAT"

# 3. Correct-length structure-aware fuzz (Finding 3).
PYTHONPATH=. python -m sqfuzz fuzz --level lvl1 --kat-dir "$KAT" --n 2000 --seed 0

# 4. Minimal undersized reproducer + verbatim ASan trace.
PYTHONPATH=. python -m sqfuzz repro --level lvl1 --kat-dir "$KAT"
```

Or, after `pip install -e .`, use the `sqisign-verify-fuzz` console script.

Because ASan **aborts the process** on the first memory error, the harness runs
**one input per process** so every crash is attributable to a single input; the
Python runner parses the ASan report for the crashing `file.c:line` and the
out-of-bounds read size.

---

## How it is organized

```
harness/     build.sh (ASan reference + verify_one) and verify_one.c (1 input/process)
sqfuzz/      layout.py  corpus.py  mutate.py  runner.py  boundary.py  report.py  cli.py
results/     committed JSON + minimal reproducer from the author's run
docs/        findings.md, mechanism.md
tests/       pytest suite — runs against a pure-Python stub (no C build, no ASan)
```

---

## Honest limitations

- **One machine, one implementation, one commit.** Results are from Apple Silicon
  arm64 / macOS, the `ref` build at `dd133d7`. Source line numbers and
  out-of-bounds read sizes are specific to that build.
- **ASan is not a proof of exploitability.** Finding 1 is an out-of-bounds
  **read** of adjacent heap during *verification* of public data. It is a
  memory-safety / robustness finding, not a demonstrated exploit, and this repo
  makes no exploitability claim.
- **This reproduces, it does not discover.** The issue is already public (open
  #23) and already acknowledged with a planned fix; credit is TheDarkLightX's and
  the SQIsign team's.
- **The reference is not production code.** It is explicitly not production-ready
  (issue #3) and not constant-time (spec §7).
- **Verification path only.** Keygen and signing are out of scope.
- **Single input per process.** Required by ASan's abort-on-error; throughput is
  bounded by process spawn, not by the mutator.
- **The negative result is empirical**, over the sampled correct-length inputs and
  seeds used; it is evidence of robustness, not a proof that no correct-length
  input can ever misbehave.

---

## Prior art & context

- **TheDarkLightX / `sqisign-verification-boundary`** — the original report of the
  undersized-signature boundary behaviour (MIT). Full credit for the finding.
- **Upstream issue #23** (open, 2026-08-13) — the acknowledged tracking issue;
  fix planned for round 3.
- **Upstream issue #15** — the "there is essentially no fuzzing" thread that
  invited an AFL harness; the tooling this repo provides.
- **Upstream issue #12** — the macOS `-Wno-macro-redefined` build workaround.
- **Upstream issue #3** — "not production-ready" (De Feo).
- **SQIsign specification, §7** — "not constant-time".
- Sibling repos: **`sqisign-conformance`** (correctness oracle) and
  **`sqisign-verify-cost`** (verification cost).

## License

MIT © 2026 Moe Tabei. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The reference
source and its KAT vectors are Apache-2.0 material owned by the SQIsign team and
are **not** redistributed here.
