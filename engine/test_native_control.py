import base64
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from mitmproxy import http
from mitmproxy.test import tflow

import engine
from engine import Lens, detail
from native_json import encode_native_message
from outgoing import request_fingerprint


class NativeControlSourceBoundary(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.lens = Lens(None, Path('/tmp'), 8890)

    async def asyncTearDown(self):
        await self.lens.close()

    def test_detail_exposes_source_bytes_independently_of_surrogate_display(self):
        flow = tflow.tflow(resp=True)
        flow.request.data.method = b'G\xffT'
        flow.request.data.path = b'/raw\xff?q=\xfe'
        flow.request.headers.add('X-Raw', b'\xff')
        flow.response.headers.add('Content-Type', b'text/plain; raw=\xff')
        flow.response.data.reason = b'Origin\xff'
        result = detail(flow)
        self.assertEqual(base64.b64decode(result['request_method_base64']), b'G\xffT')
        self.assertEqual(base64.b64decode(result['request_target_base64']), b'/raw\xff?q=\xfe')
        self.assertEqual(base64.b64decode(result['request_url_base64']),
                         engine.request_url(flow.request, pretty=False).encode('utf-8', 'surrogateescape'))
        self.assertIsNone(result['request_url_unavailable_reason'])
        self.assertEqual(result['request_port'], flow.request.port)
        self.assertEqual(result['request_target_form'], flow.request.first_line_format)
        fields = [(base64.b64decode(k), base64.b64decode(v)) for k, v in result['request_headers_base64']]
        self.assertEqual(fields, list(flow.request.headers.fields))
        self.assertEqual(base64.b64decode(result['response_reason_base64']), b'Origin\xff')
        self.assertEqual(result['response_reason'], 'Originÿ')
        envelope = json.loads(encode_native_message({'event': 'result', 'value': result}))
        self.assertEqual(envelope['message']['value']['method'], r'G\udcffT')
        self.assertTrue(envelope['source_text'])
        self.assertEqual(flow.request.data.path, b'/raw\xff?q=\xfe')

    def test_unavailable_routed_url_does_not_hide_other_details_and_asterisk_is_explicit(self):
        flow = tflow.tflow(resp=True)
        flow.request.data.host = '\ud800.test'
        result = detail(flow)
        self.assertIsNone(result['request_url_base64'])
        self.assertIn('unavailable', result['request_url_unavailable_reason'])
        self.assertEqual(result['request_headers_base64'], [[base64.b64encode(k).decode(), base64.b64encode(v).decode()]
                                                          for k, v in flow.request.headers.fields])
        json.loads(encode_native_message({'event': 'result', 'value': result}))
        flow.request.data.host = 'example.test'
        flow.request.data.path = b'*'
        self.assertEqual(detail(flow)['request_target_form'], 'asterisk')
        self.assertEqual(base64.b64decode(detail(flow)['request_target_base64']), b'*')

    async def test_request_body_export_fingerprint_guards_source_before_body_allocation(self):
        flow = tflow.tflow(resp=True)
        flow.request.raw_content = b'whole source\0\xff'
        self.lens.flows[flow.id] = flow
        fingerprint = request_fingerprint(flow.request)
        command = {'command': 'export_body', 'id': flow.id, 'side': 'request', 'decoded': False,
                   'request_fingerprint': fingerprint}
        result = await self.lens.command(command)
        self.assertEqual(base64.b64decode(result['base64']), flow.request.raw_content)
        flow.request.headers.add('X-New', 'changed since detail')
        with patch.object(engine.base64, 'b64encode', side_effect=AssertionError('stale body allocated')):
            with self.assertRaisesRegex(ValueError, 'source request changed'):
                await self.lens.command(command)
        with self.assertRaisesRegex(ValueError, 'only valid for request'):
            await self.lens.command({**command, 'side': 'response'})
        legacy = await self.lens.command({key: value for key, value in command.items() if key != 'request_fingerprint'})
        self.assertEqual(base64.b64decode(legacy['base64']), flow.request.raw_content)

    def test_emit_is_opt_in_and_legacy_message_remains_exact(self):
        message = {'event': 'result', 'command_id': 'identity', 'value': {'raw': '\udcff', 'é': 'metadata'}}
        for native in (False, True):
            output = io.StringIO()
            with patch.object(engine, 'NATIVE_JSON', native), contextlib.redirect_stdout(output):
                engine.emit(message['event'], **{k: v for k, v in message.items() if k != 'event'})
            self.assertEqual(output.getvalue().count('\n'), 1)
            result = json.loads(output.getvalue())
            if native:
                self.assertEqual(result['native_json'], 1)
                self.assertEqual(result['message']['value']['raw'], r'\udcff')
                self.assertEqual(len(result['source_text']), 2)
            else:
                self.assertEqual(output.getvalue(), json.dumps(message, ensure_ascii=True, allow_nan=False) + '\n')
                self.assertEqual(result, message)


if __name__ == '__main__':
    unittest.main()
