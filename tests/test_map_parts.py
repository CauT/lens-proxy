"""Real HTTP/strict-TLS/H2 acceptance for individually selected destinations."""
import base64
from concurrent.futures import ThreadPoolExecutor
from test_map_remote import MapRemoteFixture


class MapPartsAcceptance(MapRemoteFixture):
    @staticmethod
    def parts(**fields):
        return {'kind': 'map_remote', 'match': '*', 'value': '', 'path_mode': 'relative', 'map_destination': fields}

    def test_path_only_keeps_protocol_host_port_and_actual_tls_identity(self):
        self.engine.configure([self.parts(path='/dev/')])
        for base, h2 in ((self.http, False), (self.https, False), (self.https, True)):
            with self.subTest(base=base, h2=h2), self.client(http2=h2) as client:
                response = client.get(base + '/old%2f?q=%2F&x=&')
                self.assertEqual(response.status_code, 200, response.text)
                record = response.json(); self.assert_target(record, b'/dev/old%2f?q=%2F&x=&')
                self.assertEqual(record['host'], base.split('://')[1])
                self.assertEqual(record['sni'], 'localhost' if base.startswith('https') else None)
                self.assertEqual(response.http_version, 'HTTP/2' if h2 else 'HTTP/1.1')

    def test_protocol_only_preserves_selected_original_port_in_both_directions(self):
        self.engine.configure([self.parts(scheme='https')])
        with self.client() as client:
            response = client.get(f'http://localhost:{self.secure.server_port}/upgrade?x=1')
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()['sni'], 'localhost')
            self.assertEqual(response.json()['host'], f'localhost:{self.secure.server_port}')
        self.engine.configure([self.parts(scheme='http')])
        with self.client(http2=True) as client:
            response = client.get(f'https://127.0.0.1:{self.origin.server_port}/downgrade?')
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()['sni'], None)
            self.assertEqual(response.json()['host'], f'127.0.0.1:{self.origin.server_port}')

    def test_port_only_changes_actual_origin_without_changing_host_path_or_query(self):
        other = self.start_origin()
        before = len(self.origin.history)
        self.engine.configure([self.parts(port=str(other.server_port))])
        with self.client() as client:
            response = client.get(self.http + '/port-only?k=%2f&&')
            self.assertEqual(response.status_code, 200, response.text)
            self.assert_target(response.json(), b'/port-only?k=%2f&&')
            self.assertEqual(response.json()['host'], f'127.0.0.1:{other.server_port}')
        self.assertEqual(len(other.history), 1); self.assertEqual(len(self.origin.history), before)

    def test_query_selection_and_blank_authority_preserve_raw_target_and_host_fields(self):
        for fields, expected in (({}, b'/raw\xff?x=%2f&&'),
                                 ({'query_mode': 'replace', 'query': 'k=%2F&k='}, b'/raw\xff?k=%2F&k='),
                                 ({'query_mode': 'replace'}, b'/raw\xff?')):
            self.engine.configure([{'kind': 'dns_spoof', 'match': '*', 'value': '127.0.0.1'}, self.parts(**fields)])
            host = f'MiXeD.EXAMPLE:{self.origin.server_port}'
            record = self.raw_request(b'/raw\xff?x=%2f&&', host=host.encode())
            self.assert_target(record, expected); self.assertEqual(record['host'], host)

    def test_invalid_partial_destination_keeps_accepted_configuration_and_held_generation(self):
        accepted = self.parts(path='/accepted.txt')
        self.engine.configure([accepted])
        for fields in ({'host': 'http://bad'}, {'port': True}, {'query_mode': 'future'}, {'path': 'relative'}, {'scheme': 'ftp'}):
            with self.subTest(fields=fields), self.assertRaisesRegex(AssertionError, 'failed'):
                self.engine.configure([self.parts(**fields)])
        with self.client() as client:
            response = client.get(self.http + '/selected')
            self.assertEqual(response.status_code, 200); self.assert_target(response.json(), b'/accepted.txt')
        original = self.http + '/held'
        self.engine.configure([{'kind': 'breakpoint_request', 'match': original, 'timeout_seconds': 30}, accepted])
        def request():
            with self.client() as client: return client.get(original)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(request)
            paused = self.engine.flow(original, state='paused')
            self.engine.configure([self.parts(path='/later.txt')])
            self.engine.command('resume', id=paused['id'], pause_id=paused['pause_id'], stage='request', action='discard')
            response = pending.result(timeout=5)
        self.assert_target(response.json(), b'/accepted.txt')

    def test_idna2008_host_routes_to_owned_ip_without_an_external_dns_lookup(self):
        self.engine.configure([{'kind': 'dns_spoof', 'match': '*', 'value': '127.0.0.1'}, self.parts(host='faß.test')])
        with self.client() as client:
            response = client.get(self.http + '/idna-host')
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()['host'], f'xn--fa-hia.test:{self.origin.server_port}')
        flow = self.captured(self.http + '/idna-host')
        self.assertEqual(flow['dns_address'], '127.0.0.1')
