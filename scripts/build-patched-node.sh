#!/usr/bin/env bash
#
# Build the Babilonia-patched bitcoind (BIP324 decoy send/recv: senddecoy/getdecoys RPCs).
#
# Strategy (see docs/DEPLOYMENT.md): we do NOT vendor Bitcoin Core. We pin an upstream release
# tag and apply a small (~130-line) patch. This keeps the repo tiny and the patch reviewable.
#
# Usage:
#   scripts/build-patched-node.sh
#   BITCOIN_TAG=v29.3 BITCOIN_SRC=~/.cache/babilonia/bitcoin scripts/build-patched-node.sh
#
# On success it prints the binary path and the BABILONIA_BITCOIND export to use it.
set -euo pipefail

BITCOIN_TAG="${BITCOIN_TAG:-v29.3}"
BITCOIN_SRC="${BITCOIN_SRC:-$HOME/.cache/babilonia/bitcoin}"
BITCOIN_URL="${BITCOIN_URL:-https://github.com/bitcoin/bitcoin.git}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCH="$REPO_ROOT/patches/bip324-decoy.patch"
[ -f "$PATCH" ] || { echo "error: patch not found at $PATCH" >&2; exit 1; }

# macOS: make Homebrew tools/libs discoverable.
CMAKE_PREFIX_ARG=()
if [ -d /opt/homebrew/bin ]; then
    export PATH="/opt/homebrew/bin:$PATH"
    CMAKE_PREFIX_ARG=(-DCMAKE_PREFIX_PATH=/opt/homebrew)
fi

# Dependency check (don't auto-install — just point the way).
missing=()
for tool in git cmake pkg-config; do command -v "$tool" >/dev/null 2>&1 || missing+=("$tool"); done
if [ "${#missing[@]}" -gt 0 ]; then
    echo "error: missing build tools: ${missing[*]}" >&2
    if [ "$(uname)" = "Darwin" ]; then
        echo "  install with: brew install cmake pkgconf boost" >&2
    else
        echo "  install with: sudo apt install -y git cmake pkgconf libboost-dev libevent-dev libsqlite3-dev" >&2
    fi
    exit 1
fi

jobs="$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

echo "==> Bitcoin Core $BITCOIN_TAG  ->  $BITCOIN_SRC  (jobs=$jobs)"

# Clone once (blobless: fast, keeps tags); otherwise reuse and ensure the tag is present.
if [ ! -d "$BITCOIN_SRC/.git" ]; then
    mkdir -p "$(dirname "$BITCOIN_SRC")"
    git clone --filter=blob:none "$BITCOIN_URL" "$BITCOIN_SRC"
else
    git -C "$BITCOIN_SRC" fetch --tags --quiet origin
fi

# Reset to a clean checkout at the pinned tag (idempotent: discards any prior patch), then apply.
# Building from the exact tag keeps the peer-visible user-agent stock (/Satoshi:<tag>/).
git -C "$BITCOIN_SRC" checkout -f --quiet "$BITCOIN_TAG"
git -C "$BITCOIN_SRC" clean -fdq src
echo "==> applying $(basename "$PATCH")"
git -C "$BITCOIN_SRC" apply "$PATCH"

# Configure + build just the daemon and cli.
cmake -S "$BITCOIN_SRC" -B "$BITCOIN_SRC/build" \
    "${CMAKE_PREFIX_ARG[@]}" \
    -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF -DBUILD_GUI=OFF >/dev/null
cmake --build "$BITCOIN_SRC/build" --target bitcoind bitcoin-cli -j"$jobs"

BIN="$BITCOIN_SRC/build/bin/bitcoind"
[ -x "$BIN" ] || { echo "error: build did not produce $BIN" >&2; exit 1; }
echo
echo "==> built: $BIN"
"$BIN" --version | head -1
echo
echo "Point Babilonia at it:"
echo "    export BABILONIA_BITCOIND=$BIN"
