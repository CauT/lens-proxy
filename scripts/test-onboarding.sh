#!/bin/bash
set -euo pipefail
LENS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LENS_RESOURCES="${1:-$LENS_ROOT/Lens.app/Contents/Resources}"
: "${LENS_TEST_LAN_ADDRESS:?Select an IPv4 address assigned to the test Mac}"
LENS_OUT="$LENS_ROOT/.build/onboarding-tests"
mkdir -p "$LENS_OUT" "$LENS_ROOT/.build/ModuleCache"
LENS_SOURCES=()
for LENS_SOURCE in "$LENS_ROOT"/Sources/Lens/*.swift; do
  if [[ "$(basename "$LENS_SOURCE")" != LensApp.swift ]]; then LENS_SOURCES+=("$LENS_SOURCE"); fi
done
swiftc -swift-version 5 -parse-as-library -enable-testing -emit-module -emit-library \
  -module-name LensNative -module-cache-path "$LENS_ROOT/.build/ModuleCache" \
  -framework SwiftUI -framework AppKit "${LENS_SOURCES[@]}" \
  -o "$LENS_OUT/libLensNative.dylib" -emit-module-path "$LENS_OUT/LensNative.swiftmodule"
swiftc -swift-version 5 -parse-as-library -module-cache-path "$LENS_ROOT/.build/ModuleCache" \
  -I "$LENS_OUT" -L "$LENS_OUT" -lLensNative -Xlinker -rpath -Xlinker "$LENS_OUT" \
  "$LENS_ROOT/tests/onboarding_store_smoke.swift" -o "$LENS_OUT/onboarding-store-smoke"
PYTHONPATH="$LENS_RESOURCES/site-packages:$LENS_ROOT/tests" "$LENS_RESOURCES/python/bin/python3" -B - \
  "$LENS_RESOURCES" "$LENS_OUT/onboarding-store-smoke" "$LENS_TEST_LAN_ADDRESS" <<'PY'
import socket, subprocess, sys, tempfile
from pathlib import Path
from test_e2e import certificate_fixture, start_fixture

with tempfile.TemporaryDirectory(prefix='lens-onboarding-origin-') as folder:
    ca, cert, key = certificate_fixture(Path(folder), 'onboarding')
    server, _ = start_fixture('Onboarding HTTPS', cert, key)
    try:
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        subprocess.run([sys.argv[2], sys.argv[1], sys.argv[3], str(port), str(ca),
                        f'https://127.0.0.1:{server.server_port}/onboarding-https'], check=True, timeout=120)
    finally:
        server.shutdown(); server.server_close()
PY
