"""Owned, fixed-path HTTP setup page and public-CA bootstrap; no private keys."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from mitmproxy import http


PAGE = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connected to Lens</title><style>
body{font:17px/1.65 system-ui,sans-serif;margin:0;background:#f4f6fa;color:#182334}
main{max-width:620px;margin:32px auto;padding:24px;background:white;border-radius:18px}
h1{font-size:28px;color:#087748}h2{font-size:21px}code{overflow-wrap:anywhere;font-size:13px}
a.download{display:inline-block;padding:12px 20px;background:#145ceb;color:white;border-radius:10px;text-decoration:none}
details{margin-top:18px}small{color:#526176}</style><main>
<h1 id="lens-connected">✓ Connected to Lens</h1>
<p>This HTTP request passed through the Lens proxy. On your Mac, find <code>http://lens.invalid/</code> in the traffic list.</p>
<h2>Next: Set up HTTPS inspection</h2>
<p>Compare this CA SHA-256 fingerprint with the one shown in Lens on your Mac before downloading and installing the certificate.</p>
<p><code>__SHA256__</code></p><a class="download" href="/certificate.cer">Download Lens CA</a>
<details open><summary>Android</summary><p>In Settings, find Install a certificate / CA certificate and install the downloaded file.
The certificate may be named mitmproxy, and menus vary by device. Some apps do not trust user CAs and need their developer to configure debug CA trust.</p></details>
<details><summary>iPhone / iPad</summary><p>Download the certificate in Safari. Install the profile in Settings → General → VPN &amp; Device Management,
then enable full trust for the root in General → About → Certificate Trust Settings. Installing the profile alone is not enough.</p></details>
<h2>Verify the capture</h2><p>Open an HTTPS page or target app. In Lens on your Mac, select the request and inspect both Request and Response headers and bodies.
A CONNECT tunnel alone does not prove HTTPS decryption. This HTTP page cannot confirm that the certificate is installed or trusted.</p>
<small>Apps that pin certificates or ignore the Wi-Fi proxy may reject inspection. When finished, set the device Wi-Fi proxy to None / Off and remove any test certificates you no longer use.</small>
</main></html>"""


def response(path, public_certificate):
    if path not in ("/", "/certificate.cer"):
        return http.Response.make(404, b"Use http://lens.invalid/ for Lens setup")
    try:
        certificate = x509.load_pem_x509_certificate(public_certificate.read_bytes())
    except (OSError, ValueError):
        return http.Response.make(503, b"Lens public CA certificate is unavailable")
    headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    if path == "/certificate.cer":
        headers.update({"Content-Type": "application/x-x509-ca-cert",
                        "Content-Disposition": 'attachment; filename="Lens-CA.cer"'})
        return http.Response.make(200, certificate.public_bytes(Encoding.DER), headers)
    headers.update({"Content-Type": "text/html; charset=utf-8",
                    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
    return http.Response.make(200, PAGE.replace("__SHA256__", certificate.fingerprint(hashes.SHA256()).hex()).encode(), headers)
