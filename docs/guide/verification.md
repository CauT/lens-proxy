# Current verification scope

The main branch is 0.2.4 development source. Published 0.2.3 downloads do not
include its visual JSON reader or English onboarding changes.

## Executed checks

- Lossless JSON model: seven smoke groups cover source order, duplicate members,
  exact numeric/string lexemes, Unicode, RFC 6901 pointers, errors and bounds.
- Shared body and multipart format checks: 17 and 32 groups passed.
- Full optimized native application build and strict deep signature passed.
- Packaged-engine onboarding integration exercised LAN HTTP/HTTPS, certificate
  bootstrap, inspectable details and owned shutdown without host proxy access.
- Actual build 7 windows verified Request/Response trees, search, next-match
  navigation, selected-value/pointer copy, duplicate ambiguity and short-body
  Pretty/Source. The English Get Started window and Android/iPhone steps were
  inspected. Controlled traffic used normal gzip negotiation.
- Development DMG checks passed read-only mount, copied app byte/mode/symlink
  equality, absence of AppleDouble metadata and strict deep signature.

## Open acceptance

Build 7 showed clipped characters at the right edge of a wrapped long JSON line.
Build 8 changes the scroll view's ownership of wrapped viewport width. An
isolated AppKit geometry check passes, but also passes on the earlier code; it
does not reproduce the hosted SwiftUI issue or establish the visible fix.

Final build 8 window acceptance remains open: long-line wrapping/horizontal
scrolling, Response Source, previous-match navigation, malformed/truncated
fallback and Stop/Quit cleanup must be checked with newly generated requests.
No final visual acceptance or stable-release readiness is claimed.

Ad-hoc integrity does not establish Developer ID signing, notarization,
Gatekeeper/download installation, Intel compatibility or physical-device HTTPS
trust. Existing proxy/VPN routing and certificate trust were not changed during
the controlled checks. Unicode fixtures remain in the tests as escape sequences
to keep source text English while preserving the tested bytes and values.
