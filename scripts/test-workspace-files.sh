#!/bin/bash
set -euo pipefail
LENS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LENS_RESOURCES="${1:-$LENS_ROOT/Lens.app/Contents/Resources}"
LENS_OUT="$LENS_ROOT/.build/workspace-file-tests"
if [[ ! -x "$LENS_RESOURCES/python/bin/python3" || ! -f "$LENS_RESOURCES/engine/engine.py" ]]; then
  echo "Pass a built Lens.app Contents/Resources directory." >&2
  exit 1
fi
mkdir -p "$LENS_OUT" "$LENS_ROOT/.build/ModuleCache"
LENS_SOURCES=()
for LENS_SOURCE in "$LENS_ROOT"/Sources/Lens/*.swift; do
  if [[ "$(basename "$LENS_SOURCE")" != LensApp.swift ]]; then
    LENS_SOURCES+=("$LENS_SOURCE")
  fi
done
swiftc -swift-version 5 -parse-as-library -enable-testing -emit-module -emit-library \
  -module-name LensNative -module-cache-path "$LENS_ROOT/.build/ModuleCache" \
  -framework SwiftUI -framework AppKit "${LENS_SOURCES[@]}" \
  -o "$LENS_OUT/libLensNative.dylib" -emit-module-path "$LENS_OUT/LensNative.swiftmodule"
for LENS_TEST in workspace_file_store_smoke session_lifecycle_store_smoke quit_store_smoke clear_store_smoke startup_store_smoke; do
  LENS_TEST_SOURCE="$LENS_ROOT/tests/$LENS_TEST.swift"
  if [[ "$LENS_TEST" != workspace_file_store_smoke ]]; then
    /usr/bin/python3 - "$LENS_TEST_SOURCE" "$LENS_OUT/$LENS_TEST.swift" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[2]).write_text('@testable import LensNative\n' + Path(sys.argv[1]).read_text())
PY
    LENS_TEST_SOURCE="$LENS_OUT/$LENS_TEST.swift"
  fi
  swiftc -swift-version 5 -parse-as-library -module-cache-path "$LENS_ROOT/.build/ModuleCache" \
    -I "$LENS_OUT" -L "$LENS_OUT" -lLensNative -Xlinker -rpath -Xlinker "$LENS_OUT" \
    "$LENS_TEST_SOURCE" -o "$LENS_OUT/$LENS_TEST"
  if [[ "$LENS_TEST" == workspace_file_store_smoke ]]; then
    LENS_RUN="$(mktemp -d "$LENS_OUT/run.XXXXXX")"
    "$LENS_OUT/$LENS_TEST" "$LENS_RESOURCES" "$LENS_RUN"
  elif [[ "$LENS_TEST" == startup_store_smoke ]]; then
    LENS_STARTUP_PORT="$("$LENS_RESOURCES/python/bin/python3" -B -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
    "$LENS_OUT/$LENS_TEST" "$LENS_RESOURCES" "$LENS_STARTUP_PORT"
  else
    "$LENS_OUT/$LENS_TEST" "$LENS_RESOURCES"
  fi
done
