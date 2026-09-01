# Mechanism: why each truncation length crashes where it does

> Reminder: this describes a public, non-production reference (explicitly not
> production-ready, upstream issue #3; not constant-time, spec §7) and
> independently reproduces the already-open, team-acknowledged robustness issue
> #23. It is not a vulnerability report.

## The decode path

`sqisign_verify` (in `src/sqisign.c`) is, in essence:

```c
int sqisign_verify(const unsigned char *m, unsigned long long mlen,
                   const unsigned char *sig, unsigned long long siglen,
                   const unsigned char *pk) {
    public_key_t pkt = {0};
    signature_t  sigt;
    public_key_from_bytes(&pkt, pk);
    signature_from_bytes(&sigt, sig);          // <-- siglen is never consulted
    return !protocols_verify(&sigt, &pkt, m, mlen);
}
```

The `siglen` parameter is **never read**. `signature_from_bytes`
(`src/verification/ref/lvlx/encode_verification.c`) decodes a **fixed**
`CRYPTO_BYTES` worth of fields from `sig`, regardless of how many bytes the
caller actually provided:

```c
void signature_from_bytes(signature_t *sig, const byte_t *enc) {
    enc = fp2_from_bytes(&sig->E_aux_A, enc);                 // E_aux_A
    sig->backtracking     = *enc++;                            // line 199
    sig->two_resp_length  = *enc++;                            // line 200
    size_t nbytes = (SQIsign_response_length + 9) / 8;
    decode_digits(sig->mat_Bchall_can_to_B_chall[0][0], enc, nbytes, ...);  // 203
    enc += nbytes;
    decode_digits(sig->mat_Bchall_can_to_B_chall[0][1], enc, nbytes, ...);  // 205
    enc += nbytes;
    decode_digits(sig->mat_Bchall_can_to_B_chall[1][0], enc, nbytes, ...);  // 207
    enc += nbytes;
    decode_digits(sig->mat_Bchall_can_to_B_chall[1][1], enc, nbytes, ...);  // 209
    enc += nbytes;
    nbytes = SECURITY_BITS / 8;
    decode_digits(sig->chall_coeff, enc, nbytes, ...);         // line 213
    enc += nbytes;
    sig->hint_aux   = *enc++;                                  // line 216
    sig->hint_chall = *enc++;                                  // line 217
}
```

When the harness allocates the signature buffer at **exactly** the caller-declared
length (`verify_one.c` does `malloc(siglen)`), a short buffer means one of these
reads runs off the end. AddressSanitizer flags the first such read and aborts.

## Field offsets

The decode consumes fields in a fixed order. With `E` = fp2 element size,
`M` = matrix-entry size, `C` = `SECURITY_BITS/8`:

| field            | lvl1 size | lvl3 size | lvl5 size | reader                     |
|------------------|-----------|-----------|-----------|----------------------------|
| `E_aux_A`        | 64 (E)    | 96        | 128       | `fp2_from_bytes` (prime-specific fp) |
| `backtracking`   | 1         | 1         | 1         | `*enc++` (line 199)        |
| `two_resp_length`| 1         | 1         | 1         | `*enc++` (line 200)        |
| `mat[0][0]`      | 16 (M)    | 25        | 32        | `decode_digits` (line 203) |
| `mat[0][1]`      | 16        | 25        | 32        | `decode_digits` (line 205) |
| `mat[1][0]`      | 16        | 25        | 32        | `decode_digits` (line 207) |
| `mat[1][1]`      | 16        | 25        | 32        | `decode_digits` (line 209) |
| `chall_coeff`    | 16 (C)    | 24        | 32        | `decode_digits` (line 213) |
| `hint_aux`       | 1         | 1         | 1         | `*enc++` (line 216)        |
| `hint_chall`     | 1         | 1         | 1         | `*enc++` (line 217)        |
| **total**        | **148**   | **224**   | **292**   | = `CRYPTO_BYTES`           |

These offsets are encoded as data in [`sqfuzz/layout.py`](../sqfuzz/layout.py).

## Why length L crashes at a specific line

For a buffer of length `L < CRYPTO_BYTES`, valid indices are `0 .. L-1`. The
decode reads fields strictly in order, so every field entirely before `L` decodes
fine; the crash happens on the **first read that touches index ≥ L** — i.e. the
field whose byte range contains index `L`. `layout.field_at(level, L)` returns
exactly that field.

Two read shapes appear in the AddressSanitizer "READ of size N":

- **Single-byte reads** (`*enc++` for `backtracking`, `two_resp_length`,
  `hint_aux`, `hint_chall`) → **READ of size 1**.
- **Bulk reads** (`decode_digits`, which `memcpy`s `nbytes` at once for the four
  matrix entries and `chall_coeff`) → **READ of size = field size** (e.g. 16 at
  lvl1). This is why the lvl1 100-byte reproducer, which ends inside `mat[1][0]`
  (offset 98, size 16), reports **READ of size 16 at encode_verification.c:207**.
- The **`E_aux_A`** region is decoded element-wise by the prime-specific
  `fp2_from_bytes` / `fp_decode`; its per-length read size is small and is taken
  from the actual ASan output rather than predicted.

The worked lvl1 map (from [`results/boundary-lvl1.json`](../results/boundary-lvl1.json)):

| truncation length range | field           | crash source                |
|-------------------------|-----------------|-----------------------------|
| 0 … 63                  | `E_aux_A`       | `fp_p5248_64.c:689`         |
| 64                      | `backtracking`  | `encode_verification.c:199` |
| 65                      | `two_resp_length`| `encode_verification.c:200`|
| 66 … 81                 | `mat[0][0]`     | `encode_verification.c:203` |
| 82 … 97                 | `mat[0][1]`     | `encode_verification.c:205` |
| 98 … 113                | `mat[1][0]`     | `encode_verification.c:207` |
| 114 … 129               | `mat[1][1]`     | `encode_verification.c:209` |
| 130 … 145               | `chall_coeff`   | `encode_verification.c:213` |
| 146                     | `hint_aux`      | `encode_verification.c:216` |
| 147                     | `hint_chall`    | `encode_verification.c:217` |
| 148 (exact)             | —               | no crash (accepts)          |
| 149 … (oversized)       | —               | no crash (accepts, trailing bytes ignored) |

`encode_verification.c` lives under `.../lvlx/` and is shared across all levels,
so lines 199–217 are identical for lvl1/lvl3/lvl5; only the `E_aux_A` fp file
name changes with the prime.
