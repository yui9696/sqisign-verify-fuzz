# Findings

> ## This is a reproduction, not a disclosure
>
> Everything below **independently reproduces the already-public, OPEN,
> team-acknowledged upstream issue #23** (undersized-signature heap
> out-of-bounds read in the verifier), **first reported by
> [TheDarkLightX](https://github.com/TheDarkLightX)** in the MIT repo
> `sqisign-verification-boundary`. The SQIsign team acknowledged it and
> scheduled the fix for the round-3 release. **It is NOT a discovery, NOT a
> 0-day, NOT a vulnerability disclosure, NOT an exploit, NOT an attack.** The
> reference is explicitly not production-ready (upstream issue #3) and not
> constant-time (spec §7). Finding 1 is an out-of-bounds *read* of adjacent
> heap during verification of public data; no exploitability is claimed. The
> words *vulnerability / exploit / 0-day / attack* appear here only to say this
> is **not** one of them.

**Environment.** Apple Silicon arm64, macOS. Reference `github.com/SQISign/the-sqisign`
at commit `dd133d7`, built `Debug` with `-fsanitize=address -fno-omit-frame-pointer -g`
(and `-Wno-macro-redefined`, upstream issue #12). One verification per process;
crashes attributed by parsing the AddressSanitizer report. Numbers are from the
author's run — reproduce them with `sqisign-verify-fuzz` against your own build.

---

## Finding 1 — undersized signatures: heap out-of-bounds READ (reproduces open #23)

`sqisign_verify` ignores its `siglen` argument and fixed-size-decodes
`CRYPTO_BYTES` (148 / 224 / 292 at L1 / L3 / L5). Every length
`0 ... CRYPTO_BYTES-1` reads past the end of the caller's buffer and is caught by
ASan; the exact length and every oversized length do not crash.

| level | CRYPTO_BYTES | undersized lengths crashing | exact-length | oversized |
|-------|-------------:|:---------------------------:|:------------:|:---------:|
| lvl1  | 148          | **148 / 148**               | accept       | accept    |
| lvl3  | 224          | **224 / 224**               | accept       | accept    |
| lvl5  | 292          | **292 / 292**               | accept       | accept    |

The crashing source line is set by which field's decode is executing when the
buffer ends (see [`mechanism.md`](mechanism.md)). Per-length source mapping,
verbatim from the sweeps in [`../results`](../results):

### lvl1 (`results/boundary-lvl1.json`)

| length range | field            | crash source                | read size |
|--------------|------------------|-----------------------------|:---------:|
| 0 ... 63     | `E_aux_A`        | `fp_p5248_64.c:689`         | 1         |
| 64           | `backtracking`   | `encode_verification.c:199` | 1         |
| 65           | `two_resp_length`| `encode_verification.c:200` | 1         |
| 66 ... 81    | `mat[0][0]`      | `encode_verification.c:203` | 16        |
| 82 ... 97    | `mat[0][1]`      | `encode_verification.c:205` | 16        |
| 98 ... 113   | `mat[1][0]`      | `encode_verification.c:207` | 16        |
| 114 ... 129  | `mat[1][1]`      | `encode_verification.c:209` | 16        |
| 130 ... 145  | `chall_coeff`    | `encode_verification.c:213` | 16        |
| 146          | `hint_aux`       | `encode_verification.c:216` | 1         |
| 147          | `hint_chall`     | `encode_verification.c:217` | 1         |

### lvl3 (`results/boundary-lvl3.json`)

`E_aux_A` region (0 ... 95) -> `fp_p65376_64.c:764`; then `encode_verification.c`
lines 199 (96), 200 (97), 203 (98-122), 205 (123-147), 207 (148-172),
209 (173-197), 213 (198-221), 216 (222), 217 (223). Matrix/chall reads are 25 /
24 bytes.

### lvl5 (`results/boundary-lvl5.json`)

`E_aux_A` region (0 ... 127) -> `fp_p27500_64.c:856`; then `encode_verification.c`
lines 199 (128), 200 (129), 203 (130-161), 205 (162-193), 207 (194-225),
209 (226-257), 213 (258-289), 216 (290), 217 (291). Matrix/chall reads are 32
bytes.

This maps the aggregate observation in issue #23 to the **exact decode step per
truncation point** across all three security levels.

**Minimal reproducer (lvl1).** A 100-byte prefix of a valid signature ends inside
`mat[1][0]`:

```
heap-buffer-overflow READ of size 16 at encode_verification.c:207
  in signature_from_bytes  <-  sqisign_verify (sqisign.c:101)
```

The exact input and verbatim ASan stack are in
[`../results/minimal-repro.txt`](../results/minimal-repro.txt), reproducible with
`sqisign-verify-fuzz repro --level lvl1`.

---

## Finding 2 — oversized signatures: accepted (non-strict length)

A valid signature with trailing bytes appended (lengths `CRYPTO_BYTES+1 ...`) is
**accepted**: the verifier reads only `CRYPTO_BYTES` and ignores the rest. In the
sweeps, every oversized length tested returned `accept`. This is a malleability,
consistent with SQIsign **not** claiming SUF-CMA (cf. `sqisign-conformance`,
ePrint 2026/1305). **Not a break.**

---

## Finding 3 — correct-length inputs are robust (negative result)

| level | inputs (per strategy × 3) | accept | reject | asan_crash | error |
|-------|--------------------------:|:------:|:------:|:----------:|:-----:|
| lvl1  | 6000 (2000 × 3)           | 0      | 6000   | **0**      | 0     |
| lvl3  | 3000 (1000 × 3)           | 0      | 3000   | **0**      | 0     |
| lvl5  | 3000 (1000 × 3)           | 0      | 3000   | **0**      | 0     |
| **total** | **12000**             | **0**  | **12000** | **0**   | **0** |

Correct-length (`CRYPTO_BYTES`) malformed inputs were fuzzed under ASan across
three deterministic strategies (seed 0):

- **random** — fully random buffers of exactly `CRYPTO_BYTES`;
- **mat_entry** — a valid signature with the four matrix-entry regions randomized;
- **e_aux** — a valid signature with the `E_aux_A` curve encoding randomized.

Result: **zero memory-safety findings; every input safely rejected.** The
memory-safety issue is specifically **length handling**, not the deep
verification logic, which robustly rejects malformed data (often after emitting
its own `warning:` diagnostics before the `reject` verdict). Data in
[`../results/correct-length-fuzz.json`](../results/correct-length-fuzz.json).

---

## Mitigation

A **length check before the fixed-size decode**: reject when `siglen != CRYPTO_BYTES`.

- `siglen < CRYPTO_BYTES` -> removes the out-of-bounds read (Finding 1).
- requiring exact equality -> also removes the trailing-byte malleability (Finding 2).

The SQIsign team has stated this is planned for the round-3 release. Adding it
upstream would turn every crashing length in the tables above into a clean
rejection, and this harness can be re-run to confirm.

---

## What would change these numbers

Source line numbers and read sizes are tied to the `ref` build at `dd133d7` on
this platform. A different commit, a different `SQISIGN_BUILD_TYPE`, or a
compiler that vectorizes `decode_digits` differently could shift line numbers or
read sizes; the **structure** (all undersized lengths crash, exact + oversized do
not, crash walks the fields in decode order) is what to expect to persist until
the upstream length check lands.
