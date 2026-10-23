import base64
import gzip
import unittest
from unittest.mock import patch

from mitmproxy import http
from mitmproxy.test import tflow

import http_headers
from http_headers import headers_base64, prepare_headers
from message_edit import prepare_request_edit, prepare_response_edit


def encoded(fields):
    return [[base64.b64encode(name).decode('ascii'), base64.b64encode(value).decode('ascii')] for name, value in fields]


class HTTPHeaderByteBoundary(unittest.TestCase):
    def test_text_and_base64_inputs_share_raw_validation_and_duplicate_order(self):
        fields = [(b'X-Raw', b'\xff'), (b'X-Dup', b'one'), (b'X-Dup', '\u4e2d\u6587'.encode())]
        text = [[name.decode('ascii'), value.decode('utf-8', 'surrogateescape')] for name, value in fields]
        self.assertEqual(prepare_headers(text).fields, tuple(fields))
        raw = prepare_headers(encoded(fields), encoded=True)
        self.assertEqual(raw.fields, tuple(fields))
        self.assertEqual(headers_base64(raw), encoded(fields))
        source = http.Request.make('POST', 'https://example.test/', b'')
        source.raw_content = gzip.compress(b'full body', mtime=123)
        source.headers['Content-Encoding'] = 'gzip'
        original = source.get_state()
        prepared = prepare_request_edit(source, {'headers_base64': encoded([*fields, (b'Content-Encoding', b'gzip')])})
        self.assertEqual(prepared.message.headers.fields[:3], tuple(fields))
        self.assertEqual(prepared.message.raw_content, source.raw_content)
        self.assertEqual(source.get_state(), original)
        self.assertIs(prepare_request_edit(source, {}).message, source)

    def test_canonical_base64_and_late_invalid_fields_leave_source_unchanged(self):
        source = tflow.tflow().request
        original = source.get_state()
        for fields in ([["WC1SYXc=", "YR=="]], [["WC1SYXc=", "YWJ="]],
                       [["WC1SYXc=", "YQ==\n"]], encoded([(b'X-Good', b'ok'), (b'X-Bad', b'line\r\ninjection')]),
                       encoded([(b'X-Bad', b'zero\0')]), encoded([(b'X:\xff', b'value')]),
                       encoded([(b'Host', b'foreign')]), encoded([(b'Content-Length', b'1')]),
                       encoded([(b'Transfer-Encoding', b'chunked')])):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                prepare_request_edit(source, {'method': 'PUT', 'headers_base64': fields})
            self.assertEqual(source.get_state(), original)
        with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
            prepare_request_edit(source, {'headers': [], 'headers_base64': []})

    def test_complete_header_budget_is_admitted_before_text_or_base64_allocations(self):
        for fields, representation in ((encoded([(b'X', b'x' * 65532)]), True),
                                       ([['X', 'é' * 32767]], False),
                                       (encoded([(b'X', b'x')] * 1025), True)):
            with self.subTest(encoded=representation), \
                 patch.object(http_headers.base64, 'b64decode', side_effect=AssertionError('early decode')), \
                 patch.object(http_headers, 'wire_text', side_effect=AssertionError('early encode')):
                with self.assertRaises(ValueError):
                    prepare_headers(fields, encoded=representation)
        fitting = prepare_headers(encoded([(b'X', b'\xff' * 65531)]), encoded=True)
        self.assertEqual(len(fitting.fields[0][1]), 65531)

    def test_reason_bytes_are_distinct_from_latin1_display_and_preserve_keep(self):
        response = http.Response.make(200, b'body')
        response.data.reason = b'Original\xff'
        original = response.get_state()
        keep = prepare_response_edit(response, {}, request_method='GET', frontend_method='GET')
        self.assertIs(keep.message, response)
        self.assertEqual(response.reason, 'Originalÿ')
        prepared = prepare_response_edit(response, {'reason_base64': base64.b64encode(b'Edited\x80\xff').decode()},
                                         request_method='GET', frontend_method='GET')
        self.assertEqual(prepared.message.data.reason, b'Edited\x80\xff')
        self.assertEqual(prepared.message.raw_content, b'body')
        self.assertEqual(response.get_state(), original)
        for fields in ({'reason': 'text', 'reason_base64': ''}, {'reason_base64': 'YR=='},
                       {'reason_base64': base64.b64encode(b'bad\r\nreason').decode()},
                       {'reason_base64': base64.b64encode(b'zero\0').decode()}):
            with self.assertRaises(ValueError):
                prepare_response_edit(response, fields, request_method='GET', frontend_method='GET')
            self.assertEqual(response.get_state(), original)


if __name__ == '__main__':
    unittest.main()
