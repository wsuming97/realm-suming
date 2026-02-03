#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PANEL_SCRIPT="${ROOT_DIR}/panel.sh"
OUT_DIR="${ROOT_DIR}/dist"
WORK_DIR="$(mktemp -d)"

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

if [ ! -f "$PANEL_SCRIPT" ]; then
    echo "panel.sh not found: $PANEL_SCRIPT"
    exit 1
fi

extract_block() {
    local marker="$1"
    local out="$2"
    awk -v marker="$marker" '
    $0 ~ marker { in=1; next }
    in && $0=="EOF" { exit }
    in { print }
    ' "$PANEL_SCRIPT" > "$out"
}

mkdir -p "$WORK_DIR/src"
extract_block "^cat > Cargo.toml << 'EOF'$" "$WORK_DIR/Cargo.toml"
extract_block "^cat > src/main.rs << 'EOF'$" "$WORK_DIR/src/main.rs"

if [ ! -s "$WORK_DIR/Cargo.toml" ] || [ ! -s "$WORK_DIR/src/main.rs" ]; then
    echo "Failed to extract Rust sources from panel.sh"
    exit 1
fi

cd "$WORK_DIR"

CARGO_CMD="${CARGO_CMD:-cargo}"
TARGET="${RUST_TARGET:-}"
if [ -n "$TARGET" ]; then
    "$CARGO_CMD" build --release --target "$TARGET"
    BIN_PATH="target/$TARGET/release/realm-panel"
else
    "$CARGO_CMD" build --release
    BIN_PATH="target/release/realm-panel"
fi

if [ ! -f "$BIN_PATH" ]; then
    echo "Build failed, realm-panel not found at $BIN_PATH"
    exit 1
fi

ARCH_NAME=""
case "${TARGET:-$(uname -m)}" in
    x86_64*|amd64*) ARCH_NAME="amd" ;;
    aarch64*|arm64*) ARCH_NAME="arm" ;;
    *) ARCH_NAME="${ARCH_OVERRIDE:-unknown}" ;;
esac

mkdir -p "$OUT_DIR"
cp "$BIN_PATH" "$WORK_DIR/realm-panel"
tar -czf "$OUT_DIR/realm-panel-${ARCH_NAME}.tar.gz" -C "$WORK_DIR" realm-panel

echo "Release package created:"
echo "  $OUT_DIR/realm-panel-${ARCH_NAME}.tar.gz"
