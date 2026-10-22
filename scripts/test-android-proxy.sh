#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
: "${LENS_ANDROID_ADB:?Select the adb executable}"
: "${LENS_ANDROID_SERIAL:?Select the test emulator serial}"
: "${LENS_TEST_LAN_ADDRESS:?Select an assigned test-Mac IPv4 address}"
port="${LENS_ANDROID_ADB_PORT:-5038}"
name="$("$LENS_ANDROID_ADB" -P "$port" -s "$LENS_ANDROID_SERIAL" shell getprop ro.boot.qemu.avd_name)"
if [[ "$name" != 'LensProxyAcceptance_20261017' ]]; then
  printf 'Refusing to replace APK on a non-owned emulator: %s\n' "$name" >&2
  exit 1
fi
"$LENS_ANDROID_ADB" -P "$port" -s "$LENS_ANDROID_SERIAL" install -r -t "$root/.build/android-proxy-client/probe.apk"
"${LENS_TEST_PYTHON:-$root/.runtime/bin/python}" -m unittest discover -s "$root/tests" -p test_android_proxy_client.py -v
