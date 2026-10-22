"""Real URL access policy, upstream isolation, edits and historical provenance."""
from concurrent.futures import ThreadPoolExecutor
import copy
from pathlib import Path
import ssl
import tempfile
import unittest
import uuid

import httpx
from test_e2e import EngineHarness, start_fixture
from test_network_features import certificates


class AccessListAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='lens-access-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        ca, leaves = certificates(cls.directory)
        cert, key = leaves[0]
        cls.origin, _ = start_fixture('access HTTP')
        cls.secure, _ = start_fixture('access HTTPS', cert, key)
        for server in (cls.origin, cls.secure):
            cls.addClassCleanup(server.server_close); cls.addClassCleanup(server.shutdown)
        cls.engine = EngineHarness(cls.directory, ca)
        cls.addClassCleanup(cls.engine.close)
        cls.context = ssl.create_default_context(cafile=cls.engine.ready['ca_cert'])
        cls.http = f'http://127.0.0.1:{cls.origin.server_port}'
        cls.https = f'https://localhost:{cls.secure.server_port}'

    def setUp(self):
        self.configure({})
        self.engine.command('recording', enabled=True)
        self.engine.command('clear')

    def configure(self, policy, rules=(), ssl_hosts='*'):
        return self.engine.command('configure', access_policy=policy, rules=list(rules), ssl_hosts=ssl_hosts)[1]

    def client(self):
        return httpx.Client(proxy=self.engine.proxy, verify=self.context, trust_env=False, timeout=8)

    def url(self, path):
        return self.http + '/' + path + '-' + uuid.uuid4().hex

    def assert_not_forwarded(self, url, origin=None):
        path = httpx.URL(url).raw_path.decode()
        self.assertFalse(any(item['path'] == path for item in (origin or self.origin).history))

    def test_disabled_lists_and_allow_empty_live_transition_keep_bootstrap_reachable(self):
        url = self.url('default')
        self.configure({'block': ['*'], 'allow': []})
        with self.client() as client:
            self.assertEqual(client.get(url).status_code, 200)
            self.configure({'allow_enabled': True, 'allow': []})
            denied = self.url('denied')
            self.assertEqual(client.get(denied).status_code, 403)
            bootstrap = client.get('http://lens.invalid/certificate.cer')
            self.assertEqual(bootstrap.status_code, 200)
            self.assertGreater(len(bootstrap.content), 100)
            self.configure({'allow_enabled': True, 'allow': [self.http + '/*']})
            self.assertEqual(client.post(self.url('allowed'), content=b'\x00\xffbody').status_code, 200)
        self.assert_not_forwarded(denied)
        fact = self.engine.flow(denied)['access_decision']
        self.assertEqual((fact['reason'], fact['pattern']), ('allow_miss', None))

    def test_block_wins_before_ordered_mappings_breakpoints_and_response_rewrite(self):
        url = self.url('conflict')
        path = self.directory / 'local.bin'; path.write_bytes(b'local bypass')
        rules = [{'kind': 'map_local', 'match': '*', 'value': str(path)},
                 {'kind': 'breakpoint_request', 'match': '*'},
                 {'kind': 'rewrite_response_header', 'match': '*', 'name': 'X-Bypass', 'value': 'bad'}]
        self.configure({'block_enabled': True, 'block': [url], 'allow_enabled': True, 'allow': ['*']}, rules)
        with self.client() as client:
            reply = client.get(url)
        self.assertEqual(reply.status_code, 403)
        self.assertEqual(reply.content, b'Blocked by Lens access list')
        self.assertNotIn('X-Bypass', reply.headers)
        self.assertEqual(self.engine.flow(url)['access_decision']['reason'], 'block_match')
        self.assert_not_forwarded(url)

    def test_mapping_checks_original_and_every_effective_destination(self):
        original = self.url('original')
        target_base, final_base = self.http + '/mapped', self.http + '/safe'
        target = target_base + httpx.URL(original).path
        final = final_base + httpx.URL(target).path
        rules = [{'kind': 'map_remote', 'match': '*', 'value': target_base},
                 {'kind': 'map_remote', 'match': '*', 'value': final_base}]
        # A later safe mapping cannot conceal an earlier blocked destination.
        self.configure({'block_enabled': True, 'block': [target]}, rules)
        with self.client() as client:
            self.assertEqual(client.get(original).status_code, 403)
        fact = self.engine.flow(target)['access_decision']
        self.assertEqual(fact['matched_url'], target)
        for url in (original, target, final): self.assert_not_forwarded(url)
        # Allowing just the original URL cannot authorize a mapped destination.
        self.configure({'allow_enabled': True, 'allow': [original]}, rules[:1])
        with self.client() as client:
            self.assertEqual(client.get(original).status_code, 403)
        latest = [e['flow'] for e in self.engine.events if e.get('event') == 'flow' and e['flow']['url'] == target][-1]
        self.assertEqual((latest['access_decision']['reason'], latest['access_decision']['matched_url']), ('allow_miss', target))
        self.configure({'allow_enabled': True, 'allow': [original, target]}, rules[:1])
        with self.client() as client:
            self.assertEqual(client.get(original).status_code, 200)
        self.assert_not_forwarded(original)

    def test_paused_mapping_uses_request_policy_snapshot_and_cannot_bypass_destination(self):
        original = self.url('paused')
        base = self.http + '/edited'
        edited = base + httpx.URL(original).path
        rules = [{'kind': 'breakpoint_request', 'match': original},
                 {'kind': 'map_remote', 'match': original, 'value': base}]
        self.configure({'block_enabled': True, 'block': [edited]}, rules)
        def request():
            with self.client() as client: return client.get(original)
        with ThreadPoolExecutor(max_workers=1) as worker:
            pending = worker.submit(request)
            paused = self.engine.flow(original, 'paused')
            # A concurrent policy update affects new requests. This request
            # retains the policy under which its initial URL was admitted.
            self.configure({})
            self.engine.command('resume', id=paused['id'], action='continue')
            self.assertEqual(pending.result(timeout=8).status_code, 403)
        self.assert_not_forwarded(original); self.assert_not_forwarded(edited)
        self.assertEqual(self.engine.flow(edited)['access_decision']['matched_url'], edited)
        with self.client() as client: self.assertEqual(client.get(edited).status_code, 200)

    def test_close_action_records_error_and_har_roundtrip_while_invalid_import_is_atomic(self):
        url = self.url('close')
        self.configure({'block_enabled': True, 'block': [url], 'action': 'close'})
        with self.client() as client:
            with self.assertRaises(httpx.TransportError): client.get(url)
        flow = self.engine.flow(url, 'error')
        fact = flow['access_decision']
        self.assertEqual(fact['action'], 'close'); self.assertIsNone(flow['status'])
        self.assert_not_forwarded(url)
        har = self.engine.command('export_har')[1]
        self.assertEqual(har['log']['entries'][0]['_lensAccessDecision'], fact)
        path = self.directory / 'access.har'
        self.engine.command('save_har', path=str(path))
        self.engine.command('clear'); self.engine.command('load_har', path=str(path))
        self.assertEqual(self.engine.command('export_har')[1], har)
        malformed = copy.deepcopy(har)
        malformed['log']['entries'][0]['_lensAccessDecision']['reason'] = 'invented'
        with self.assertRaises(AssertionError): self.engine.command('import_har', har=malformed)
        self.assertEqual(self.engine.command('export_har')[1], har)
        contradictory = copy.deepcopy(har)
        contradictory['log']['entries'][0]['_lensAccessDecision'].update(matched_url='http://unrelated.invalid/', pattern='*')
        with self.assertRaises(AssertionError): self.engine.command('import_har', har=contradictory)
        self.assertEqual(self.engine.command('export_har')[1], har)
        contradictory = copy.deepcopy(har)
        contradictory['log']['entries'][0]['_lensAccessDecision']['action'] = 'respond'
        with self.assertRaises(AssertionError): self.engine.command('import_har', har=contradictory)
        self.assertEqual(self.engine.command('export_har')[1], har)
        historical = copy.deepcopy(har)
        del historical['log']['entries'][0]['_lensAccessDecision']
        self.engine.command('clear'); self.engine.command('import_har', har=historical)
        self.assertIsNone(next(e['flow']['access_decision'] for e in reversed(self.engine.events)
                               if e.get('event') == 'flow' and e['flow'].get('imported')))

    def test_https_visible_request_is_blocked_but_opaque_tunnel_is_explicitly_outside_scope(self):
        url = self.https + '/https-access-' + uuid.uuid4().hex
        self.configure({'block_enabled': True, 'block': ['https://*']})
        with self.client() as client: self.assertEqual(client.get(url).status_code, 403)
        self.assert_not_forwarded(url, self.secure)
        self.assertEqual(self.engine.flow(url)['access_decision']['reason'], 'block_match')
        # Tunneling leaves request URLs unavailable. Trust the actual origin CA,
        # not Lens's CA, and verify the real origin still receives this request.
        self.configure({'block_enabled': True, 'block': ['*']}, ssl_hosts='')
        ca = self.directory / 'origin-ca.pem'
        context = ssl.create_default_context(cafile=ca)
        with httpx.Client(proxy=self.engine.proxy, verify=context, trust_env=False, timeout=8) as client:
            self.assertEqual(client.get(url + '-opaque').status_code, 200)
        self.assertTrue(any(item['path'].endswith('-opaque') for item in self.secure.history))

    def test_http2_abort_is_a_stream_reset_and_403_remains_a_normal_response(self):
        url = self.https + "/h2-denied-" + uuid.uuid4().hex
        with httpx.Client(proxy=self.engine.proxy, verify=self.context, trust_env=False, timeout=8, http2=True) as client:
            reply = client.get(url + "-allowed")
            self.assertEqual(reply.http_version, "HTTP/2")
            self.configure({"block_enabled": True, "block": [url], "action": "close"})
            with self.assertRaises(httpx.RemoteProtocolError) as failure:
                client.get(url)
            self.assertIn("StreamReset", str(failure.exception))
            self.assertEqual(self.engine.flow(url, 'error')['access_decision']['action'], 'close')
            self.configure({"block_enabled": True, "block": [url]})
            reply = client.get(url)
            self.assertEqual((reply.status_code, reply.http_version), (403, "HTTP/2"))
        self.assert_not_forwarded(url, self.secure)

    def test_invalid_live_configuration_preserves_last_policy_and_rules(self):
        url = self.url('atomic')
        self.configure({'block_enabled': True, 'block': [url]})
        before = self.engine.command('access_policy_status')[1]
        with self.assertRaises(AssertionError):
            self.configure({'allow_enabled': 'false'}, [{'kind': 'map_remote', 'match': '*', 'value': self.http}])
        self.assertEqual(self.engine.command('access_policy_status')[1], before)
        with self.client() as client: self.assertEqual(client.get(url).status_code, 403)
        self.assert_not_forwarded(url)

    def test_compose_replay_and_paused_recording_still_enforce_policy(self):
        url = self.url('compose')
        self.configure({'block_enabled': True, 'block': [url]})
        identifier, _ = self.engine.command('compose', method='GET', url=url)
        self.engine.wait(lambda e: e.get('event') == 'request_finished' and e.get('command_id') == identifier)
        captured = self.engine.flow(url)
        self.assertEqual(captured['status'], 403)
        after = len(self.engine.events)
        self.engine.command('replay', id=captured['id'])
        replay = self.engine.flow(url, after=after)
        self.assertTrue(replay['replayed']); self.assertEqual(replay['status'], 403)
        self.engine.command('recording', enabled=False)
        with self.client() as client: self.assertEqual(client.get(url).status_code, 403)
        self.assert_not_forwarded(url)
