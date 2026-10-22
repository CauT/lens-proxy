#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
sdk="${LENS_ANDROID_SDK:?Set LENS_ANDROID_SDK to an existing Android SDK}"
java="${LENS_ANDROID_JAVA_HOME:?Set LENS_ANDROID_JAVA_HOME to a JDK 17 home}"
tools="$sdk/build-tools/35.0.0"
platform="${LENS_ANDROID_PLATFORM_JAR:-$sdk/platforms/android-30/android.jar}"
for executable in "$java/bin/javac" "$java/bin/java" "$java/bin/jar" "$java/bin/keytool" "$tools/aapt2" "$tools/zipalign" "$tools/apksigner"; do
  if [[ ! -x "$executable" ]]; then
    printf 'Missing selected Android build tool: %s\n' "$executable" >&2
    exit 1
  fi
done
for input in "$platform" "$tools/lib/d8.jar"; do
  if [[ ! -r "$input" ]]; then
    printf 'Missing selected Android build input: %s\n' "$input" >&2
    exit 1
  fi
done
out="$root/.build/android-proxy-client"
mkdir -p "$out/classes" "$out/dex"
"$java/bin/javac" --release 8 -classpath "$platform" -d "$out/classes" "$root/tests/android-proxy-client/MainActivity.java"
"$java/bin/java" -cp "$tools/lib/d8.jar" com.android.tools.r8.D8 --min-api 26 --lib "$platform" --output "$out/dex" "$out/classes/io/lens/proxyprobe/MainActivity.class"
"$tools/aapt2" link -I "$platform" --manifest "$root/tests/android-proxy-client/AndroidManifest.xml" -o "$out/unsigned.apk"
"$java/bin/jar" uf "$out/unsigned.apk" -C "$out/dex" classes.dex
if [[ ! -f "$out/test-key.p12" ]]; then
  "$java/bin/keytool" -genkeypair -keystore "$out/test-key.p12" -storepass android -keypass android -alias lens-test -dname 'CN=Lens local test only' -keyalg RSA -validity 30
fi
"$tools/zipalign" -f 4 "$out/unsigned.apk" "$out/aligned.apk"
JAVA_HOME="$java" "$tools/apksigner" sign --ks "$out/test-key.p12" --ks-pass pass:android --out "$out/probe.apk" "$out/aligned.apk"
JAVA_HOME="$java" "$tools/apksigner" verify "$out/probe.apk"
printf '%s\n' "$out/probe.apk"
