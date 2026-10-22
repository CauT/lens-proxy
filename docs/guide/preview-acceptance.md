# 0.2.3 preview acceptance

Verified on macOS / Apple Silicon, 2026-10-22. This is an experimental prerelease,
not a stable or Apple-notarized distribution.

App executable SHA-256:
`1f2a2fe83f9cbd003596de094608695ec389e92d0d2c35d8d79ca0eeb2603924`.
DMG SHA-256:
`73b1c7f38b24095b4540712eb5dc6c4337e060c75cb694cef667f811fe7b1af4`.
Version 0.2.3, build 5, arm64, minimum macOS 14.

| Check | Result / scope |
| --- | --- |
| Native standalone build | Passed; helper and license no longer require the REA parent checkout |
| Engine semantics | 340 passed, 11.774 s; initial sandbox denied loopback binds, final permitted run passed |
| Packaged wire workflows | 13 passed, 4.144 s, real loopback HTTP/TLS with controlled origins |
| Packaged process attribution | 5 passed, 6.869 s, real owned clients and process-start identities |
| ZIP/DMG regression suite | 7 passed, 19.635 s, including bad-signature/metadata rejection and preservation of previous outputs |
| Final DMG | Checksum verified; read-only mounted app and fresh copied app exactly match source and pass strict deep signature checks |
| Actual desktop UI | Normal launch of this candidate with an existing manual-client profile; controlled HTTP POST; visible Request headers/JSON and Response headers/JSON verified; real screenshots retained |
| Guide | Device chooser and Android instructions inspected; opening them did not change host routing |
| Stop/Quit | Stop retained details across row changes; Save and Quit wrote the controlled workspace; candidate and engine exited and listener was released |
| Host connection | Existing HTTP/HTTPS/SOCKS proxy endpoints unchanged; no host proxy, VPN or CA-trust writes |
| Source clone / hosted CI | See GitHub Actions for the independently exported repository; local checks above are not a hosted-CI claim |
| Fresh-profile ordinary Mac routing | Not exercised in this release run; system proxy takeover is explicit and requires user setup |
| Android/iOS physical devices | Not exercised in this release run; earlier fixture/browser tests do not establish these devices |
| Gatekeeper / notarized download | Unverified / unavailable: no Developer ID identity or Apple notarization; ad-hoc integrity only |

Screenshots contain only synthetic localhost demo traffic. No screenshots of
Charles, private captures, certificates or investigation dumps are distributed.
The reported Android browser certificate failure is not claimed fixed here.
