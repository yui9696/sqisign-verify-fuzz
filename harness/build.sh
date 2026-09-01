#!/usr/bin/env bash
#
# build.sh — build the SQIsign reference verifier under AddressSanitizer and
# link a single-input verification runner (verify_one) for each requested level.
#
# WHAT THIS IS (read docs/findings.md and the README first):
#   This harness INDEPENDENTLY REPRODUCES the already-open, team-acknowledged
#   upstream robustness issue #23 (first reported by TheDarkLightX in the MIT
#   repo sqisign-verification-boundary) and provides the fuzzing tooling that
#   upstream issue #15 asked for and that never landed. It is NOT a discovery,
#   NOT a vulnerability disclosure, NOT an exploit. The reference is explicitly
#   "not production-ready" (upstream issue #3) and "not constant-time" (spec §7).
#
# HOW ASan CHANGES THE HARNESS DESIGN:
#   AddressSanitizer aborts the process (SIGABRT, exit 134) on the FIRST memory
#   error and prints its report to stderr. So the runner verifies exactly ONE
#   input per process: a crash is then attributable to that single input, and
#   the Python runner (sqfuzz/runner.py) parses the ASan report for the crashing
#   "file.c:line" and the out-of-bounds read size.
#
# IDEMPOTENT: re-running rebuilds only what is missing. Every command is echoed.
#
# Environment overrides:
#   SQISIGN_SRC   path to an existing reference checkout (skips the clone)
#   SQISIGN_REF   git commit to check out when cloning (default dd133d7)
#   GMP_PREFIX    GMP install prefix (default: `brew --prefix gmp` or /usr/local)
#   LEVELS        space-separated levels to build (default "lvl1 lvl3 lvl5")
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQISIGN_REF="${SQISIGN_REF:-dd133d7aca576c361a270c8e6434832535b42ecc}"
SQISIGN_URL="https://github.com/SQISign/the-sqisign.git"
SQISIGN_SRC="${SQISIGN_SRC:-$HERE/the-sqisign}"
BUILD="$HERE/build"
LEVELS="${LEVELS:-lvl1 lvl3 lvl5}"

run() { echo "+ $*" >&2; "$@"; }

# --- GMP prefix ------------------------------------------------------------
if [ -z "${GMP_PREFIX:-}" ]; then
  if command -v brew >/dev/null 2>&1 && brew --prefix gmp >/dev/null 2>&1; then
    GMP_PREFIX="$(brew --prefix gmp)"
  elif [ -d /usr/local/include ] && [ -f /usr/local/include/gmp.h ]; then
    GMP_PREFIX="/usr/local"
  else
    GMP_PREFIX="/usr"
  fi
fi
echo "GMP_PREFIX = $GMP_PREFIX" >&2

# --- 1. obtain the reference source ---------------------------------------
if [ ! -d "$SQISIGN_SRC/.git" ] && [ ! -f "$SQISIGN_SRC/CMakeLists.txt" ]; then
  echo "== cloning reference into $SQISIGN_SRC ==" >&2
  run git clone "$SQISIGN_URL" "$SQISIGN_SRC"
  run git -C "$SQISIGN_SRC" checkout "$SQISIGN_REF"
else
  echo "== using existing reference at $SQISIGN_SRC ==" >&2
fi

# --- 2. configure + build the reference under ASan ------------------------
ASAN_SRC_BUILD="$SQISIGN_SRC/build-asan"
if [ ! -f "$ASAN_SRC_BUILD/src/libsqisign_lvl1_test.a" ]; then
  echo "== configuring reference (Debug + AddressSanitizer) ==" >&2
  # -Wno-macro-redefined is required on macOS/clang (upstream open issue #12).
  # ASan builds produce the "_test"-suffixed archives we link below.
  run cmake -S "$SQISIGN_SRC" -B "$ASAN_SRC_BUILD" \
    -DSQISIGN_BUILD_TYPE=ref \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-Wno-macro-redefined -fsanitize=address -fno-omit-frame-pointer -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address"
  echo "== building reference libraries ==" >&2
  run cmake --build "$ASAN_SRC_BUILD" -j
else
  echo "== reference ASan libraries already built ==" >&2
fi

B="$ASAN_SRC_BUILD/src"

# --- 3. link verify_one per level -----------------------------------------
# Static archives are ordered high-level -> low-level so ld64 (which does not
# iterate archives like GNU --start-group) resolves every symbol in one pass.
mkdir -p "$BUILD"
level_num() { case "$1" in lvl1) echo 1;; lvl3) echo 3;; lvl5) echo 5;; *) echo "?";; esac; }

for LV in $LEVELS; do
  N="$(level_num "$LV")"
  OUT="$BUILD/verify_one_$LV"
  echo "== linking $OUT ==" >&2
  LIBS=(
    "$B/libsqisign_${LV}_test.a"
    "$B/signature/ref/$LV/libsqisign_signature_${LV}.a"
    "$B/verification/ref/$LV/libsqisign_verification_${LV}.a"
    "$B/id2iso/ref/$LV/libsqisign_id2iso_${LV}.a"
    "$B/hd/ref/$LV/libsqisign_hd_${LV}.a"
    "$B/ec/ref/$LV/libsqisign_ec_${LV}.a"
    "$B/gf/ref/$LV/libsqisign_gf_${LV}.a"
    "$B/precomp/ref/$LV/libsqisign_precomp_${LV}.a"
    "$B/quaternion/ref/generic/libsqisign_quaternion_generic.a"
    "$B/mp/ref/generic/libsqisign_mp_generic.a"
    "$B/common/generic/libsqisign_common_test.a"
  )
  missing=0
  for l in "${LIBS[@]}"; do
    [ -f "$l" ] || { echo "  missing archive: $l" >&2; missing=1; }
  done
  if [ "$missing" -ne 0 ]; then
    echo "  skipping $LV (reference libraries for this level were not built)" >&2
    continue
  fi
  run clang \
    -DSQISIGN_VARIANT="$LV" -DSQISIGN_BUILD_TYPE_REF \
    -fsanitize=address -fno-omit-frame-pointer -g \
    -I"$SQISIGN_SRC/include" -I"$SQISIGN_SRC/src/nistapi/$LV" -I"$GMP_PREFIX/include" \
    "$HERE/verify_one.c" \
    "${LIBS[@]}" \
    -L"$GMP_PREFIX/lib" -lgmp \
    -o "$OUT"
  echo "  built $OUT" >&2
done

echo "== done. verify_one binaries in $BUILD ==" >&2
ls -la "$BUILD" >&2 || true
