/* verify_one.c — single-input SQIsign verification runner for the fuzz harness.
 *
 * Reads ONE input, calls sqisign_verify once, prints "accept" or "reject",
 * and exits. It deliberately does ONE verification per process so that when
 * AddressSanitizer detects a memory error it aborts THIS process and the crash
 * is attributable to exactly one input (see harness/build.sh and the README:
 * this is a reproduction of the already-open upstream robustness issue #23, not
 * a discovery or a vulnerability).
 *
 * Input formats (either works):
 *   1. argv:  verify_one <pk_hex> <msg_hex> <sig_hex>
 *   2. stdin: a single line "<pk_hex> <msg_hex> <sig_hex>"
 * In both cases a field equal to "-" denotes an empty byte string.
 *
 * Output (stdout):
 *   "accept"                       verification returned 0
 *   "reject"                       verification returned non-zero
 *   "pk_wrong_size(<got>!=<exp>)"  public key length is out of the API contract
 *   "error_hex" / "error_input"    malformed invocation
 *
 * On an AddressSanitizer memory error the process aborts (SIGABRT) with the
 * ASan report on stderr; the Python runner classifies that as an asan_crash and
 * parses the crashing source line and the out-of-bounds read size.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sig.h>
#include "api.h"

static int hex2bin(const char *hex, unsigned char **out, size_t *outlen) {
    if (strcmp(hex, "-") == 0) { *out = malloc(1); *outlen = 0; return 0; }
    size_t n = strlen(hex);
    if (n % 2) return -1;
    *outlen = n / 2;
    /* Allocate EXACTLY outlen bytes (never a padded buffer) so that a decode
     * reading past the declared signature length is caught by ASan. */
    *out = malloc(*outlen ? *outlen : 1);
    if (!*out) return -1;
    for (size_t i = 0; i < *outlen; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        (*out)[i] = (unsigned char)b;
    }
    return 0;
}

static int run(const char *pkh, const char *msgh, const char *sigh) {
    unsigned char *pk = NULL, *msg = NULL, *sig = NULL;
    size_t pklen = 0, msglen = 0, siglen = 0;
    if (hex2bin(pkh, &pk, &pklen) || hex2bin(msgh, &msg, &msglen) ||
        hex2bin(sigh, &sig, &siglen)) {
        printf("error_hex\n"); free(pk); free(msg); free(sig); return 2;
    }
    /* The reference API takes a fixed-size public key buffer; a wrong-sized pk
     * is out of contract, so report it rather than invoking UB on the pk side.
     * The signature buffer is intentionally left exact so the length-handling
     * behaviour under study is exercised faithfully. */
    if (pklen != CRYPTO_PUBLICKEYBYTES) {
        printf("pk_wrong_size(%zu!=%d)\n", pklen, CRYPTO_PUBLICKEYBYTES);
        free(pk); free(msg); free(sig); return 3;
    }
    int rc = sqisign_verify(msg, (unsigned long long)msglen, sig,
                            (unsigned long long)siglen, pk);
    printf("%s\n", rc == 0 ? "accept" : "reject");
    fflush(stdout);
    free(pk); free(msg); free(sig);
    return rc == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc == 4) {
        return run(argv[1], argv[2], argv[3]);
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t len = getline(&line, &cap, stdin);
    if (len <= 0) { free(line); printf("error_input\n"); return 2; }
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = 0;
    char *pkh = strtok(line, " \t");
    char *msgh = strtok(NULL, " \t");
    char *sigh = strtok(NULL, " \t");
    if (!pkh || !msgh || !sigh) { free(line); printf("error_input\n"); return 2; }
    int rc = run(pkh, msgh, sigh);
    free(line);
    return rc;
}
