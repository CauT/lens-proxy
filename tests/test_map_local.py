"""Map Local through the real JSONL owner, proxy sockets and HTTP/TLS origins."""
import base64
import os
from pathlib import Path
import socket
import ssl
import tempfile
import unittest

import httpx
from test_e2e import EngineHarness, certificate_fixture, start_fixture


class MapLocalAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="lens-map-local-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        ca, cert, key = certificate_fixture(cls.directory, "local")
        cls.origins = []
        for name, certificate, private_key in (("http", None, None), ("https", cert, key)):
            server, _ = start_fixture(name, certificate, private_key)
            cls.addClassCleanup(server.server_close)
            cls.addClassCleanup(server.shutdown)
            cls.origins.append(server)
        cls.http = f"http://127.0.0.1:{cls.origins[0].server_port}"
        cls.https = f"https://localhost:{cls.origins[1].server_port}"
        cls.engine = EngineHarness(cls.directory, ca)
        cls.addClassCleanup(cls.engine.close)
        cls.context = ssl.create_default_context(cafile=cls.engine.ready["ca_cert"])

    def setUp(self):
        self.temporary_files = tempfile.TemporaryDirectory(dir=self.directory)
        self.addCleanup(self.temporary_files.cleanup)
        self.root = Path(self.temporary_files.name)
        self.engine.configure([])
        self.engine.command("clear")
        for origin in self.origins:
            origin.history.clear()

    def client(self):
        return httpx.Client(proxy=self.engine.proxy, verify=self.context, trust_env=False, timeout=5)

    def mapping(self, pattern, path=None):
        return {"kind": "map_local", "match": pattern, "value": str(path or self.root)}

    def test_directory_mount_query_mime_binary_and_complete_capture(self):
        (self.root / "nested").mkdir()
        payload = bytes(range(256)) * 9000  # Beyond the inspector's 2 MiB preview.
        (self.root / "nested" / "\u4e2d\u6587 space.bin").write_bytes(payload)
        (self.root / "app.css").write_bytes(b"body { color: red; }")
        self.engine.configure([self.mapping("http*://*/assets/*")])
        with self.client() as client:
            for origin in (self.http, self.https):
                url = origin + "/assets/nested/%E4%B8%AD%E6%96%87%20space.bin?v=2&name=ignored"
                response = client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.content, payload)
                self.assertEqual(response.headers["Content-Type"], "application/octet-stream")
                flow = self.engine.flow(url)
                exported = self.engine.command("export_body", id=flow["id"], side="response")[1]
                self.assertEqual(base64.b64decode(exported["base64"]), payload)
                css = client.get(origin + "/assets/app.css?cache=1")
                self.assertEqual(css.headers["Content-Type"], "text/css")
                self.assertEqual(css.content, b"body { color: red; }")
                head = client.head(origin + "/assets/app.css?cache=2")
                self.assertEqual(head.status_code, 200)
                self.assertEqual(head.content, b"")
                self.assertEqual(int(head.headers["Content-Length"]), len(css.content))
        self.assertTrue(all(not origin.history for origin in self.origins))

    def test_extension_glob_exact_file_and_live_replacement(self):
        (self.root / "nested").mkdir()
        css = self.root / "nested" / "app.css"
        css.write_bytes(b"first")
        self.engine.configure([self.mapping(self.http + "/*.css")])
        with self.client() as client:
            self.assertEqual(client.get(self.http + "/nested/app.css?bust=1").content, b"first")
            css.write_bytes(b"second")
            self.assertEqual(client.get(self.http + "/nested/app.css?bust=2").content, b"second")
            self.engine.configure([self.mapping(self.http + "/mount/app.css", self.root / "nested")])
            self.assertEqual(client.get(self.http + "/mount/app.css?exact=1").content, b"second")
            self.engine.configure([self.mapping(self.http + "/one", css)])
            self.assertEqual(client.get(self.http + "/one?query=is-ignored").content, b"second")
            # Explicit single-file symlinks keep caller-selected semantics.
            link = self.root / "chosen.css"
            link.symlink_to(css)
            self.engine.configure([self.mapping(self.http + "/one", link)])
            self.assertEqual(client.get(self.http + "/one").content, b"second")

    def test_missing_file_directory_and_mount_root_fall_back_with_original_request(self):
        self.engine.configure([self.mapping(self.http + "/assets/*"),
                               {"kind": "rewrite_request_header", "match": "*", "name": "X-After-Miss", "value": "yes"}])
        (self.root / "directory").mkdir()
        (self.root / "regular.txt").write_bytes(b"not a directory")
        with self.client() as client:
            for path in ("/assets/", "/assets/directory", "/assets/regular.txt/", "/assets/missing.bin?x=1&x=2"):
                response = client.post(self.http + path, content=b"original body")
                self.assertEqual(response.headers["X-Fixture"], "http")
                self.assertEqual(response.json()["path"], path)
                self.assertEqual(base64.b64decode(response.json()["body"]), b"original body")
                self.assertIn(["X-After-Miss", "yes"], response.json()["headers"])
            # A missing single-file target also falls through and can appear later.
            target = self.root / "later.txt"
            self.engine.configure([self.mapping(self.http + "/later", target)])
            self.assertEqual(client.get(self.http + "/later").headers["X-Fixture"], "http")
            target.write_bytes(b"created later")
            self.assertEqual(client.get(self.http + "/later").content, b"created later")

    def test_miss_does_not_erase_previous_mapping_and_response_rules_still_apply(self):
        selected = self.root / "selected.txt"
        selected.write_bytes(b"original")
        self.engine.configure([self.mapping(self.http + "/*", selected),
                               self.mapping(self.http + "/*", self.root / "missing"),
                               {"kind": "rewrite_response_body", "match": "*", "name": "original", "value": "rewritten"}])
        with self.client() as client:
            self.assertEqual(client.get(self.http + "/resource").content, b"rewritten")
        self.assertEqual(self.origins[0].history, [])

    def test_traversal_encoded_separators_and_malformed_paths_are_explicit_errors(self):
        secret = self.root.parent / "outside-secret.txt"
        secret.write_bytes(b"must never be exposed")
        self.addCleanup(secret.unlink)
        self.engine.configure([self.mapping(self.http + "/assets/*")])
        for tail in ("../outside-secret.txt", "%2e%2e/outside-secret.txt", "%2Foutside-secret.txt",
                     "%5coutside-secret.txt", "%00.txt", "%FF.txt", "bad%ZZ.txt"):
            with self.subTest(tail=tail), socket.create_connection(("127.0.0.1", self.engine.port), timeout=3) as connection:
                url = self.http + "/assets/" + tail
                connection.sendall(f"GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{self.origins[0].server_port}\r\nConnection: close\r\n\r\n".encode())
                with connection.makefile("rb") as stream:
                    data = stream.read()
                self.assertTrue(data.startswith(b"HTTP/1.1 502"), data[:200])
                self.assertNotIn(secret.read_bytes(), data)
        self.assertEqual(self.origins[0].history, [])

    def test_descendant_symlinks_cannot_escape_but_selected_directory_link_works(self):
        outside = self.root.parent / "outside.txt"
        outside.write_bytes(b"outside secret")
        self.addCleanup(outside.unlink)
        (self.root / "escape.txt").symlink_to(outside)
        (self.root / "escape-directory").symlink_to(self.root.parent, target_is_directory=True)
        (self.root / "inside.txt").write_bytes(b"inside")
        self.engine.configure([self.mapping(self.http + "/assets/*")])
        with self.client() as client:
            self.assertEqual(client.get(self.http + "/assets/escape.txt").status_code, 502)
            response = client.get(self.http + "/assets/escape-directory/outside.txt")
            self.assertNotEqual(response.content, outside.read_bytes())
            alias = self.root.parent / "selected-root-link"
            alias.symlink_to(self.root, target_is_directory=True)
            self.addCleanup(alias.unlink)
            self.engine.configure([self.mapping(self.http + "/assets/*", alias)])
            self.assertEqual(client.get(self.http + "/assets/inside.txt").content, b"inside")

    def test_fifo_and_oversize_are_bounded_errors_and_configuration_is_atomic(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        large = self.root / "large.bin"
        with large.open("wb") as stream:
            stream.truncate(32 * 1024 * 1024 + 1)
        self.engine.configure([self.mapping(self.http + "/*")])
        with self.client() as client:
            for path in ("pipe", "large.bin"):
                self.assertEqual(client.get(self.http + "/" + path).status_code, 502)
            valid = self.root / "valid.txt"
            valid.write_bytes(b"still configured")
            for path in ("", "relative.txt", "file:///tmp/file", "/tmp/with\0nul"):
                with self.subTest(path=path), self.assertRaisesRegex(AssertionError, "absolute file or directory path"):
                    self.engine.configure([{"kind": "map_local", "match": "*", "value": path}])
            self.assertEqual(client.get(self.http + "/valid.txt").content, b"still configured")
        self.assertEqual(self.origins[0].history, [])


if __name__ == "__main__":
    unittest.main()
