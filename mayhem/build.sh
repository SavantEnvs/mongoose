#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Mongoose is a single-translation-unit library: every harness #includes mongoose.c, so compiling
# the harness with $SANITIZER_FLAGS instruments the whole fuzzed library.
CFLAGS_FUZZ="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS"

# Leak detection off at build time (docs/rules/c.md).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o /tmp/lsan_off.o

# fuzz: test/fuzz.c, fuzz_tls: test/fuzz_tls.c (both in-tree upstream harnesses);
# fuzz_netdriver_http: mayhem/fuzz_netdriver_http.c (libFuzzer port of the OSS-Fuzz honggfuzz harness).
build_harness() {
  local name="$1" src="$2"
  $CC $CFLAGS_FUZZ $LIB_FUZZING_ENGINE -I"$SRC" -I"$SRC/test" "$src" /tmp/lsan_off.o -o "/mayhem/$name"
  $CC $CFLAGS_FUZZ "$STANDALONE_FUZZ_MAIN" -I"$SRC" -I"$SRC/test" "$src" /tmp/lsan_off.o -o "/mayhem/$name-standalone"
}
build_harness fuzz "$SRC/test/fuzz.c"
build_harness fuzz_tls "$SRC/test/fuzz_tls.c"
build_harness fuzz_netdriver_http "$SRC/mayhem/fuzz_netdriver_http.c"

# Upstream unit test (test/unit_test.c) with the project's NORMAL flags (no sanitizers).
# LOCALHOST_ONLY skips the SNTP/MQTT/HTTP-client tests that need the internet; IPv6 off because
# the unit test binds [::1], which container networks often lack.
mkdir -p "$SRC/mayhem/build-test"
cd "$SRC/test"
$CC -O1 -g -I. -pthread pack.c -o "$SRC/mayhem/build-test/pack"
"$SRC/mayhem/build-test/pack" Makefile data/ssi.h fuzz.c data/a.txt data/range.txt data/ca.pem certs/ca.crt certs/server.crt \
  certs/server.key certs/client.key certs/client.crt > "$SRC/mayhem/build-test/packed_fs.c"
$CC -O1 -g $COVERAGE_FLAGS -I. -pthread \
  -DMG_MAX_HTTP_HEADERS=7 -DMG_ENABLE_LINES -DMG_ENABLE_SSI=1 -DMG_ENABLE_ASSERT=1 \
  -DMG_ENABLE_IPV6=0 -DMG_ENABLE_MDASH=1 -DLOCALHOST_ONLY \
  mongoose.c unit_test.c "$SRC/mayhem/build-test/packed_fs.c" $COVERAGE_FLAGS -o "$SRC/mayhem/build-test/unit_test"
