#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ ! -x "$ROOT/.runtime/bin/python" ]]; then
  echo "Prepare the pinned runtime with scripts/bootstrap.sh first." >&2
  exit 1
fi
mkdir -p "$ROOT/.build/ModuleCache"
swiftc -swift-version 5 -parse-as-library -target "$(uname -m)-apple-macosx14.0" \
  -module-cache-path "$ROOT/.build/ModuleCache" \
  -framework Foundation -framework Network -framework Security \
  "$ROOT/tests/apple-proxy-client/AppleProxyProbe.swift" \
  "$ROOT/tests/apple-proxy-client/MacMain.swift" -o "$ROOT/.build/apple-proxy-client"
export LENS_APPLE_PROXY_PROBE="$ROOT/.build/apple-proxy-client"
exec "$ROOT/.runtime/bin/python" -m unittest discover -s "$ROOT/tests" -p test_apple_proxy_client.py -v
