#!/usr/bin/env bash
# Build ChainCheck from source and install the binary.
# Does not download a prebuilt release, edit PATH, or use sudo.
set -euo pipefail

REPO_URL="${CHAINCHECK_REPO:-https://github.com/ldbiz/chaincheck.git}"
BIN_DIR="${CHAINCHECK_BIN_DIR:-$HOME/.local/bin}"
REF="${CHAINCHECK_REF:-}"

fail() {
  echo "Error: $*" >&2
  exit 1
}

os=$(uname -s)
case "$os" in
  Linux) ;;
  *) fail "ChainCheck supports Linux/WSL only; got $os" ;;
esac

host_arch=$(uname -m)
case "$host_arch" in
  x86_64 | amd64 | aarch64 | arm64) ;;
  *) fail "unsupported host architecture: $host_arch" ;;
esac

command -v git >/dev/null 2>&1 || fail "git is required"
if ! command -v cargo >/dev/null 2>&1; then
  fail "cargo is not installed. Install Rust from https://rustup.rs and retry."
fi

src=""
script_src="${BASH_SOURCE[0]:-}"
if [[ -n "$script_src" && -f "$script_src" &&
      "$script_src" != /dev/fd/* &&
      "$script_src" != /proc/self/fd/* &&
      "$script_src" != /dev/stdin ]]; then
  script_dir=$(cd "$(dirname "$script_src")" && pwd)
  candidate=$(cd "$script_dir/.." && pwd)
  if [[ -f "$candidate/Cargo.toml" && -f "$candidate/src/main.rs" ]] &&
     grep -q '^name = "chaincheck"' "$candidate/Cargo.toml"; then
    src=$candidate
  fi
fi

if [[ -z "$src" ]]; then
  src=$(mktemp -d "${TMPDIR:-/tmp}/chaincheck-install.XXXXXX")
  cleanup() { rm -rf "$src"; }
  trap cleanup EXIT
  clone_args=(--depth 1)
  if [[ -n "$REF" ]]; then
    clone_args+=(--branch "$REF")
  fi
  git clone "${clone_args[@]}" "$REPO_URL" "$src"
fi

(
  cd "$src"
  cargo build --locked --release
)

mkdir -p "$BIN_DIR"
install -m 755 "$src/target/release/chaincheck" "$BIN_DIR/chaincheck"

echo "Installed $BIN_DIR/chaincheck"
case ":$PATH:" in
  *:"$BIN_DIR":*) ;;
  *)
    echo "Note: $BIN_DIR is not on PATH. Add it yourself or invoke $BIN_DIR/chaincheck by path."
    ;;
esac
