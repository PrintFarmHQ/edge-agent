#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
SRC_DIR="$SCRIPT_DIR/src"
OUT_DIR="$SCRIPT_DIR/../cmd/edge-agent/webui_dist"
ASSETS_DIR="$OUT_DIR/assets"

mkdir -p "$ASSETS_DIR"

# Copy and minify HTML (strip leading whitespace, blank lines)
sed 's/^[[:space:]]*//' "$SRC_DIR/index.html" | sed '/^$/d' > "$OUT_DIR/index.html"

# Copy and minify CSS (strip leading whitespace, blank lines, single-line comments)
sed 's/^[[:space:]]*//' "$SRC_DIR/styles.css" | sed '/^$/d' > "$ASSETS_DIR/app.css"

# Copy and minify JS (strip leading whitespace, blank lines)
sed 's/^[[:space:]]*//' "$SRC_DIR/app.js" | sed '/^$/d' > "$ASSETS_DIR/app.js"

# Copy static assets (logo)
cp "$SRC_DIR/assets/logo.png" "$ASSETS_DIR/logo.png"

echo "Build complete -> $OUT_DIR"
du -sh "$OUT_DIR"
