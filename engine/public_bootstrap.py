"""Owned, fixed-path HTTP setup page and public-CA bootstrap; no private keys."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from mitmproxy import http


PAGE = """<!doctype html>
<html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>已连接 Lens</title><style>
body{font:17px/1.65 system-ui,sans-serif;margin:0;background:#f4f6fa;color:#182334}
main{max-width:620px;margin:32px auto;padding:24px;background:white;border-radius:18px}
h1{font-size:28px;color:#087748}h2{font-size:21px}code{overflow-wrap:anywhere;font-size:13px}
a.download{display:inline-block;padding:12px 20px;background:#145ceb;color:white;border-radius:10px;text-decoration:none}
details{margin-top:18px}small{color:#526176}</style><main>
<h1 id="lens-connected">✓ 已连接 Lens</h1>
<p>这条 HTTP 请求已通过 Lens 代理。现在回到 Mac，可在请求列表中找到 <code>http://lens.invalid/</code>。</p>
<h2>下一步：开启 HTTPS 明文抓包</h2>
<p>先与 Mac 上 Lens 显示的 CA SHA-256 指纹逐字核对，再下载、安装证书。</p>
<p><code>__SHA256__</code></p><a class="download" href="/certificate.cer">下载 Lens CA</a>
<details open><summary>Android</summary><p>在系统设置中找到“安装证书 / CA 证书”，安装刚下载的文件。
证书名称可能是 mitmproxy，菜单因手机品牌而异。部分 App 不信任用户 CA，需要其开发者配置调试证书信任。</p></details>
<details><summary>iPhone / iPad</summary><p>用 Safari 下载证书，到“设置 → 通用 → VPN 与设备管理”安装描述文件，
再到“通用 → 关于本机 → 证书信任设置”开启该根证书的完全信任。只安装描述文件还不够。</p></details>
<h2>如何确认成功</h2><p>打开一个 HTTPS 网页或目标 App，在 Mac 的 Lens 中选择请求，分别查看 Request 和 Response 的头部与正文。
仅出现 CONNECT 隧道不代表 HTTPS 已解密。此 HTTP 页面不能证明证书已安装或受信任。</p>
<small>证书固定或不使用 Wi-Fi 代理的 App 可能无法抓包。结束测试后，将手机 Wi-Fi 代理改回“无 / 关闭”，并移除不再使用的测试证书。</small>
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
