#!/usr/bin/env bash
# Non-invasive smoke checks for a GNU Linux ChainCheck release binary.
# Does not alter host, network, or user configuration.
set -euo pipefail

usage() {
  echo "Usage: $0 <artifact-path> [checksum-sidecar]" >&2
  exit 2
}

[[ $# -eq 1 || $# -eq 2 ]] || usage

artifact=$1
checksum=${2-}

if [[ "$artifact" != /* ]]; then
  artifact="$(pwd)/$artifact"
fi
if [[ -n "$checksum" && "$checksum" != /* ]]; then
  checksum="$(pwd)/$checksum"
fi

fail() {
  echo "Error: $*" >&2
  exit 1
}

[[ -f "$artifact" ]] || fail "artifact does not exist: $artifact"
[[ -x "$artifact" ]] || fail "artifact is not executable: $artifact"

host_arch=$(uname -m)
case "$host_arch" in
  x86_64 | amd64) expected_arch=x86_64 ;;
  aarch64 | arm64) expected_arch=aarch64 ;;
  *) fail "unsupported host architecture: $host_arch" ;;
esac

identity=""
if command -v readelf >/dev/null 2>&1; then
  identity=$(readelf -h "$artifact" 2>/dev/null || true)
  echo "$identity" | grep -q 'ELF' || fail "readelf did not report an ELF header"
  echo "$identity" | grep -Eq 'Class:[[:space:]]+ELF64' || fail "artifact is not ELF64"
  case "$expected_arch" in
    x86_64)
      echo "$identity" | grep -Eq 'Machine:[[:space:]]+(Advanced Micro Devices X86-64|X86-64)' \
        || fail "artifact machine is not x86-64"
      ;;
    aarch64)
      echo "$identity" | grep -Eq 'Machine:[[:space:]]+AArch64' \
        || fail "artifact machine is not AArch64"
      ;;
  esac
elif command -v file >/dev/null 2>&1; then
  identity=$(file -b "$artifact" 2>/dev/null || true)
  echo "$identity" | grep -q 'ELF' || fail "file(1) did not report ELF: $identity"
  echo "$identity" | grep -Eq '64-bit' || fail "artifact is not 64-bit: $identity"
  case "$expected_arch" in
    x86_64)
      echo "$identity" | grep -Eq 'x86-64|x86_64' || fail "artifact is not x86-64: $identity"
      ;;
    aarch64)
      echo "$identity" | grep -Eq 'aarch64|ARM aarch64' || fail "artifact is not aarch64: $identity"
      ;;
  esac
else
  fail "neither readelf nor file is available to check artifact identity"
fi

if command -v readelf >/dev/null 2>&1; then
  readelf -l "$artifact" 2>/dev/null | grep -q 'Requesting program interpreter' \
    || fail "artifact does not look dynamically linked (no program interpreter)"
fi

if command -v ldd >/dev/null 2>&1; then
  ldd_out=$(ldd "$artifact" 2>/dev/null || true)
  if echo "$ldd_out" | grep -qi libpython; then
    fail "artifact unexpectedly links libpython"
  fi
fi

workdir=$(mktemp -d "${TMPDIR:-/tmp}/chaincheck-smoke.XXXXXX")
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

run_isolated() {
  # Process-local PATH only; does not export into the parent environment.
  (cd "$workdir" && env PATH="/usr/bin:/bin" "$artifact" "$@")
}

help_out=$(run_isolated --help) || fail "--help exited non-zero"
echo "$help_out" | grep -q 'chaincheck --self-test' || fail "--help output missing expected usage"

self_out=$(run_isolated --self-test) || fail "--self-test exited non-zero"
echo "$self_out" | grep -q 'SELF-TEST ONLY' || fail "--self-test missing SELF-TEST ONLY marker"
echo "$self_out" | grep -q 'self-test passed' || fail "--self-test did not report success"

if [[ -n "$checksum" ]]; then
  [[ -f "$checksum" ]] || fail "checksum sidecar does not exist: $checksum"
  (
    cd "$(dirname "$checksum")"
    sha256sum -c "$(basename "$checksum")"
  ) || fail "checksum verification failed"
fi

echo "smoke-release-artifact: ok $(basename "$artifact")"
