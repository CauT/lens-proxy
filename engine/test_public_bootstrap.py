"""Public bootstrap path/error boundaries; real certificate bytes use the LAN lane."""
import unittest
from public_bootstrap import response


class PublicBootstrap(unittest.TestCase):
    def test_unknown_paths_never_read_a_certificate_or_private_file(self):
        class NoRead:
            def read_bytes(self):
                raise AssertionError("Unknown bootstrap paths must not read files")
        for path in ("/mitmproxy-ca.pem", "/../mitmproxy-ca.pem", "/certificate.cer?file=private", "/unknown"):
            with self.subTest(path=path):
                self.assertEqual(response(path, NoRead()).status_code, 404)

    def test_missing_and_malformed_public_ca_fail_without_disclosing_file_details(self):
        class Missing:
            def read_bytes(self):
                raise OSError("fixture file detail must not leak")
        class Malformed:
            def read_bytes(self):
                return b"not a certificate"
        for path in ("/", "/certificate.cer"):
            for source in (Missing(), Malformed()):
                with self.subTest(path=path, source=type(source).__name__):
                    result = response(path, source)
                    self.assertEqual(result.status_code, 503)
                    self.assertEqual(result.content, b"Lens public CA certificate is unavailable")
