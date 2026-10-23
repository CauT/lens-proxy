#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/.build/json-viewer-tests"
mkdir -p "$OUT" "$ROOT/.build/ModuleCache"
SOURCES=("$ROOT/Sources/Lens/JSONDocument.swift" "$ROOT/Sources/Lens/BodyFormatting.swift" "$ROOT/Sources/Lens/MultipartFormatting.swift")
for CASE in json_document_smoke body_format_smoke multipart_format_smoke; do
  swiftc -swift-version 5 -O -parse-as-library -module-cache-path "$ROOT/.build/ModuleCache" \
    "${SOURCES[@]}" "$ROOT/tests/$CASE.swift" -o "$OUT/$CASE"
  "$OUT/$CASE"
done
swiftc -swift-version 5 -O -parse-as-library -module-cache-path "$ROOT/.build/ModuleCache" \
  -framework AppKit -framework SwiftUI "$ROOT/Sources/Lens/JSONDocument.swift" \
  "$ROOT/Sources/Lens/BodyTextView.swift" "$ROOT/tests/body_text_layout_smoke.swift" -o "$OUT/body_text_layout_smoke"
"$OUT/body_text_layout_smoke"
