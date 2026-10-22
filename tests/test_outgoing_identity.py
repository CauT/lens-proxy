"""Real pre-recognition cancellation and one-flow request correlation."""
import base64
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

import httpx

from test_e2e import EngineHarness, certificate_fixture, start_fixture, ROOT


HEADER = 'X-Lens-Internal-Replay'


class OutgoingIdentityAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='lens-outgoing-identity-')
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.ca, cert, key = certificate_fixture(cls.directory, 'trusted')
        cls.origins = []
        for secure in (False, True):
            origin, worker = start_fixture('identity-owned', cert if secure else None, key if secure else None)
            cls.addClassCleanup(worker.join)
            cls.addClassCleanup(origin.server_close)
            cls.addClassCleanup(origin.shutdown)
            cls.origins.append(origin)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=self.directory)
        self.addCleanup(temporary.cleanup)
        owner = os.environ.get('LENS_TEST_ENGINE', str(ROOT / 'engine/engine.py'))
        with patch.dict(os.environ, {'LENS_TEST_ENGINE': str(ROOT / 'tests/fixtures/late_outgoing_engine.py'),
                                     'LENS_LATE_ENGINE': owner}):
            self.engine = EngineHarness(Path(temporary.name), self.ca)
        self.addCleanup(self.engine.close)
        self.addCleanup(self.release)
        context = ssl.create_default_context(cafile=self.engine.ready['ca_cert'])
        self.client = httpx.Client(proxy=self.engine.proxy, verify=context, trust_env=False, timeout=10)
        self.addCleanup(self.client.close)
        self.engine.configure([])

    def release(self):
        if self.engine.process.poll() is None:
            self.engine.command('probe_release')

    def url(self, secure, path):
        return f'{"https" if secure else "http"}://127.0.0.1:{self.origins[int(secure)].server_port}{path}'

    def source(self, secure=False):
        url = self.url(secure, '/late')
        after = len(self.engine.events)
        self.assertEqual(self.client.post(url, content=b'whole source\0\xff').status_code, 200)
        return self.engine.flow(url, after=after)

    def barrier(self, secure=False):
        self.assertEqual(self.client.get(self.url(secure, '/barrier')).status_code, 200)

    def cancelled_before_recognition(self, secure):
        source = self.source(secure)
        origin = self.origins[int(secure)]
        with origin.history_lock:
            before = len(origin.history)
        self.engine.command('probe_arm', path='/late', phase='before')
        after = len(self.engine.events)
        _, job = self.engine.command('repeat', id=source['id'], count=1, concurrency=1)
        entered = self.engine.wait(lambda e: e.get('event') == 'probe_entered', after=after)
        self.assertTrue(any(name.lower() == HEADER.lower() for name, _ in entered['fields']))
        self.engine.command('cancel_repeat', job_id=job['job_id'])
        finished = self.engine.wait(lambda e: e.get('event') == 'repeat_done' and e.get('job_id') == job['job_id'], after=after)
        self.assertEqual((finished['completed'], finished['failed'], finished['cancelled']), (0, 0, 1))
        self.assertEqual(self.engine.command('probe_pending')[1], {'pending': 0, 'bound': 0})
        self.engine.command('probe_release', id=entered['id'])
        completed = self.engine.wait(lambda e: e.get('event') == 'probe_completed' and e['id'] == entered['id'], after=after)
        self.assertFalse(any(name.lower() == HEADER.lower() for name, _ in completed['fields']))
        self.assertTrue(completed['replayed'])
        self.assertEqual(completed['error'], 'Connection killed.')
        detail = self.engine.command('detail', id=entered['id'])[1]
        self.assertFalse(any(name.lower() == HEADER.lower() for name, _ in detail['request_headers']))
        self.barrier(secure)
        with origin.history_lock:
            self.assertEqual([row['path'] for row in origin.history[before:]], ['/barrier'])
        # A subsequent owner still reaches the origin and retains provenance.
        self.engine.command('probe_arm', path='/late', phase='after')
        after = len(self.engine.events)
        identity, _ = self.engine.command('replay', id=source['id'])
        self.engine.wait(lambda e: e.get('event') == 'probe_entered', after=after)
        self.engine.command('probe_release')
        result = self.engine.wait(lambda e: e.get('event') == 'request_finished' and e.get('command_id') == identity, after=after)
        detail = self.engine.command('detail', id=result['flow_id'])[1]
        self.assertEqual(detail['request_operation']['source_id'], source['id'])
        self.assertEqual(self.engine.command('probe_pending')[1]['pending'], 0)

    def test_cancelled_before_http_request_hook(self):
        self.cancelled_before_recognition(False)

    def test_cancelled_before_strict_tls_request_hook(self):
        self.cancelled_before_recognition(True)

    def test_owned_duplicate_rejected_while_bound_and_after_release(self):
        source = self.source()
        # Capture the actual wire identity before recognition, then bind the
        # original without releasing its sender by pausing in a real rule.
        self.engine.configure([{'enabled': True, 'match': self.url(False, '/late'), 'kind': 'breakpoint_request', 'timeout_seconds': 30}])
        self.engine.command('probe_arm', path='/late', phase='before')
        after = len(self.engine.events)
        identifier, _ = self.engine.command('replay', id=source['id'])
        entered = self.engine.wait(lambda e: e.get('event') == 'probe_entered', after=after)
        token = next(value for name, value in entered['fields'] if name.lower() == HEADER.lower())
        def reject(headers):
            start = len(self.engine.events)
            with self.assertRaises(httpx.RemoteProtocolError):
                self.client.post(self.url(False, '/duplicate'), headers=headers, content=b'must not send')
            rejected = self.engine.wait(lambda e: e.get('event') == 'flow' and e['flow'].get('url', '').endswith('/duplicate') and e['flow'].get('state') == 'error', after=start)['flow']
            self.assertTrue(rejected['replayed'])
            return self.engine.command('detail', id=rejected['id'])[1]
        # Reject multiple owned fields while the real token is still valid and
        # unbound. Merely choosing the first one would steal the real owner.
        self.assertEqual(self.engine.command('probe_pending')[1], {'pending': 1, 'bound': 0})
        foreign = [(b'x-lens-internal-replay', b'caller-\xff'), (b'X-LENS-INTERNAL-REPLAY', b'caller-second')]
        headers = [foreign[0], (HEADER, token), foreign[1], (HEADER, token)]
        detail = reject(headers)
        retained = [(base64.b64decode(name), base64.b64decode(value)) for name, value in detail['request_headers_base64']]
        self.assertEqual([(name, value) for name, value in retained if name.lower() == HEADER.lower().encode()], foreign)
        self.assertEqual(self.engine.command('probe_pending')[1], {'pending': 1, 'bound': 0})
        self.engine.command('probe_release')
        paused = self.engine.wait(lambda e: e.get('event') == 'flow' and e['flow'].get('id') == entered['id'] and e['flow'].get('state') == 'paused', after=after)['flow']
        self.assertEqual(self.engine.command('probe_pending')[1], {'pending': 1, 'bound': 1})
        self.engine.configure([])
        origin = self.origins[0]
        with origin.history_lock:
            before = len(origin.history)
        for phase in ('bound', 'released', 'multiple'):
            if phase == 'released':
                self.engine.command('resume', id=paused['id'], pause_id=paused['pause_id'], stage='request', action='continue')
                self.engine.wait(lambda e: e.get('event') == 'request_finished' and e.get('command_id') == identifier, after=after)
                self.assertEqual(self.engine.command('probe_pending')[1]['pending'], 0)
            headers = [(HEADER, token)] * (2 if phase == 'multiple' else 1)
            with self.subTest(phase=phase):
                detail = reject(headers)
                self.assertFalse(any(name.lower() == HEADER.lower() for name, _ in detail['request_headers']))
        self.barrier()
        with origin.history_lock:
            self.assertEqual([row['path'] for row in origin.history[before:]], ['/late', '/barrier'])

    def test_foreign_and_malformed_same_named_duplicate_headers_remain_source_values(self):
        import sys
        # The other instance's proof must remain ordinary caller data.
        owner = Path(os.environ.get('LENS_TEST_ENGINE', str(ROOT / 'engine/engine.py'))).resolve().parent
        sys.path.insert(0, str(owner))
        try:
            from outgoing import RequestTokens
            foreign = RequestTokens().new()
        finally:
            sys.path.remove(str(owner))
        values = [foreign, '0' * 64, 'malformed', '\xff']
        fields = [(HEADER.lower() if index % 2 else HEADER, value.encode('latin1')) for index, value in enumerate(values)]
        start = len(self.engine.events)
        response = self.client.post(self.url(False, '/foreign'), headers=fields, content=b'foreign unchanged')
        self.assertEqual(response.status_code, 200)
        flow = self.engine.flow(self.url(False, '/foreign'), after=start)
        self.assertFalse(flow['replayed'])
        detail = self.engine.command('detail', id=flow['id'])[1]
        raw = [(base64.b64decode(name), base64.b64decode(value)) for name, value in detail['request_headers_base64']]
        self.assertEqual([(name, value) for name, value in raw if name.lower() == HEADER.lower().encode()],
                         [(name.encode('ascii'), value) for name, value in fields])
        self.assertEqual([value.encode('utf-8', 'surrogateescape') for name, value in detail['request_headers'] if name.lower() == HEADER.lower()],
                         [value.encode('latin1') for value in values])
        with self.origins[0].history_lock:
            actual = self.origins[0].history[-1]
        self.assertEqual([value for name, value in actual['headers'] if name.lower() == HEADER.lower()], values)


if __name__ == '__main__':
    unittest.main()
