# Third-party notices

Lens application and bridge code are MIT-licensed code in this repository.
`engine/upstream_tls.py` adapts the TLS receive loop from mitmproxy 12.2.1,
copyright (c) 2013 Aldo Cortesi, under MIT; its complete notice is in that source.
`engine/routing.py` adapts the fresh DNS-routed connection construction from the
same version of mitmproxy's `HttpLayer.get_connection`. Its license notice follows:

Copyright (c) 2013, Aldo Cortesi. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

The remaining application and bridge code is original.
No Charles implementation or visual assets are included.

The local application bundles CPython 3.13.12 from python-build-standalone
(https://github.com/astral-sh/python-build-standalone). Its distribution includes
its license and the licenses for its runtime dependencies under Resources/python.
Python is PSF-licensed; its bundled libraries retain their own license terms.

The following installed distributions are copied unchanged to Resources/site-packages.
Their .dist-info metadata and license files are included with the app. This table
identifies the actual locked build dependencies; consult each bundled license for
its complete terms. Source package index: https://pypi.org/.

| Distribution | Version | Declared license |
| --- | --- | --- |
| aioquic | 1.2.0 | BSD-3-Clause |
| anyio | 4.15.1 | MIT |
| argon2-cffi | 25.1.0 | MIT |
| argon2-cffi-bindings | 26.1.0 | MIT |
| asgiref | 3.10.0 | BSD-3-Clause |
| attrs | 26.1.0 | MIT |
| bcrypt | 5.0.0 | Apache-2.0 |
| blinker | 1.9.0 | See bundled distribution metadata |
| brotli | 1.2.0 | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| click | 8.5.0 | BSD-3-Clause |
| cryptography | 46.0.7 | Apache-2.0 OR BSD-3-Clause |
| Flask | 3.1.2 | BSD-3-Clause |
| h11 | 0.16.0 | MIT |
| h2 | 4.3.0 | See bundled distribution license files |
| hpack | 4.2.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httpx | 0.28.1 | BSD-3-Clause |
| hyperframe | 6.1.0 | See bundled distribution license files |
| idna | 3.20 | BSD-3-Clause |
| itsdangerous | 2.2.0 | See bundled distribution metadata |
| Jinja2 | 3.1.6 | See bundled distribution metadata |
| kaitaistruct | 0.11 | MIT |
| ldap3 | 2.9.1 | LGPL v3 |
| MarkupSafe | 3.0.4 | BSD-3-Clause |
| mitmproxy | 12.2.1 | See bundled distribution license files |
| mitmproxy-macos | 0.12.11 | MIT |
| mitmproxy_rs | 0.12.11 | See bundled distribution metadata |
| msgpack | 1.1.2 | Apache-2.0 |
| publicsuffix2 | 2.20191221 | MIT and MPL-2.0 |
| pyasn1 | 0.6.4 | BSD-2-Clause |
| pyasn1_modules | 0.4.2 | BSD |
| pycparser | 3.11 | BSD-3-Clause |
| pylsqpack | 0.3.24 | BSD-3-Clause |
| pyOpenSSL | 25.3.0 | Apache License, Version 2.0 |
| pyparsing | 3.2.5 | MIT |
| pyperclip | 1.11.0 | BSD |
| regex | 2026.2.19 | Apache-2.0 AND CNRI-Python |
| ruamel.yaml | 0.18.16 | MIT license |
| ruamel.yaml.clib | 0.2.15 | MIT |
| service-identity | 24.2.0 | MIT |
| sortedcontainers | 2.4.0 | Apache 2.0 |
| tornado | 6.5.2 | Apache-2.0 |
| typing_extensions | 4.16.0 | PSF-2.0 |
| urwid | 3.0.3 | LGPL-2.1-only |
| wcwidth | 0.9.2 | See bundled distribution metadata |
| Werkzeug | 3.1.9 | BSD-3-Clause |
| wsproto | 1.2.0 | MIT License |
| zstandard | 0.25.0 | BSD-3-Clause |
