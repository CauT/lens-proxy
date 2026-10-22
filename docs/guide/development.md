# Development

Requires macOS 14+, Apple Command Line Tools and uv. Run
`bash scripts/bootstrap.sh`, then `bash scripts/build-app.sh`.
Bootstrap prepares pinned Python 3.13.12 and `engine/requirements.lock` inside the
checkout. It does not install Homebrew, Java, Node or full Xcode.

`Sources/Lens/` owns SwiftUI and the JSONL bridge. `engine/` orchestrates mitmproxy.
`Sources/PeerIdentity/` reads process start identities only. The app bundles its
runtime, packages and helper and works outside the checkout.

`VERSION` owns the version. Optional `LENS_BUILD_NUMBER` sets the numeric build;
`LENS_APP_OUTPUT` chooses a separate candidate. Build targets the host CPU and
macOS 14. Intel needs its own acceptance; the first binary is arm64 only.

```sh
PYTHONPATH=engine .runtime/bin/python -B -m unittest discover -s engine -v
.runtime/bin/python -B -m unittest discover -s tests -p test_e2e.py -v
.runtime/bin/python -B -m unittest discover -s tests -p test_packaging.py -v
```

Wire tests use owned loopback origins and temporary CAs, preserving host routing
and trust. Device lanes need an explicitly selected environment; skips are not
passes. Select a built engine with `LENS_TEST_ENGINE` and bundled dependencies
with `PYTHONPATH`. CI runs on macOS; its result does not establish physical-device
or notarized-download acceptance.

Before delivery, normally open the final packaged app, generate controlled
traffic, inspect visible Request/Response headers and body, then verify Stop/Quit
and cleanup. Record the actual artifact identity. Test counts alone are insufficient.

Lens originated in MIT-licensed REA. Standalone `SOURCE_PROVENANCE.json` records
the exported source hashes. Private captures, CA keys, evidence, SDKs, caches and
unrelated REA code are excluded. Charles was a workflow reference; its code and
artwork are not included. Preserve third-party licenses when changing dependencies.
