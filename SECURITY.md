# Security

Inspect only traffic you are authorized to inspect. HTTPS interception requires
the client's explicit trust in a local CA. An enabled LAN proxy is reachable by
any device with network access to that address; disable it after use.

Never post private CA keys, tokens, passwords or unredacted captures. Use GitHub
**Security → Report a vulnerability** if enabled. Otherwise open a minimal issue
asking for a private contact channel without publishing exploit details.
Only the current preview is maintained; no response SLA is promised.

The first DMG is ad-hoc signed and not notarized. Package integrity and Apple's
distribution trust are separate checks; read release notes before installing.
