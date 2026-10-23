# DMG and release workflow

Build from a clean checkpoint, preserve previous outputs and record the candidate
identity. Local builds are ad-hoc signed. A DMG does not add Apple distribution trust.

```sh
bash scripts/build-app.sh
/usr/bin/python3 -B scripts/package-dmg.py Lens.app \
  .build/delivery/Lens-0.2.4-macOS-arm64-development.dmg --development-only
```

The packager creates a compressed read-only HFS+ image with Lens.app and an
Applications shortcut. It checks the image checksum, mounts read-only, compares
all app bytes/modes/symlinks, verifies strict deep signatures, copies the mounted
app into a fresh directory and verifies again. Existing output names are refused.
Failed unmounts retain the owned working directory. The verification JSON records
SHA-256, size, tree digest and `gatekeeper_ready: false` for development output.

Publish development artifacts only as **prereleases**, clearly marked experimental
and not notarized. Include SHA256SUMS, verification report, OS/CPU requirements,
executed acceptance and limitations. Do not disable Gatekeeper or remove a user's
download quarantine to obtain a pass. ZIP packaging remains in `package-app.py`.

For a stable release, obtain Developer ID Application signing and approved Apple
notarization credentials. Sign nested native code inside out with an appropriate
Hardened Runtime setup and secure timestamp. Verify the actual runtime/helper,
submit for notarization, inspect logs, staple and validate. Then omit
`--development-only`: the packager requires Developer ID, stapler and Gatekeeper
before/after mounting and copying. Complete clean-Mac browser-download, drag
installation, launch, capture and cleanup acceptance before claiming stable.
Never commit signing credentials.

[Apple distribution guide](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution).
