import copy
import unittest
from mitmproxy.test import tflow
from mitmproxy import http
from http_method import parse_method, normalize_response, import_framing, request_method


class MethodSemantics(unittest.TestCase):
    def test_method_token_validation_preserves_case(self):
        for value in ('HEAD', 'POST', 'Custom-Method', 'head'):
            self.assertEqual(parse_method(value), value)
            self.assertEqual(request_method(http.Request.make(value, 'http://example.test/')), value)
        for value in ('', 'GET POST', 'bad\r\n', '中文', None):
            with self.assertRaises(ValueError): parse_method(value)

    def test_head_conversion_retains_prior_framing_and_is_idempotent(self):
        flow = tflow.tflow(resp=True)
        flow.request.method = 'HEAD'; flow.metadata['lens_frontend_method'] = 'POST'
        flow.response.raw_content = b''
        flow.response.headers['content-length'] = '90'
        flow.response.headers['transfer-encoding'] = 'chunked'
        normalize_response(flow)
        self.assertEqual(flow.response.headers.get_all('content-length'), ['0'])
        self.assertNotIn('transfer-encoding', flow.response.headers)
        facts = flow.metadata['lens_method_framing']
        self.assertEqual((facts['source_content_length'], facts['source_transfer_encoding']), (['90'], ['chunked']))
        before = copy.deepcopy(flow.metadata)
        normalize_response(flow)
        self.assertEqual(flow.metadata, before)

    def test_ordinary_head_and_no_body_status_keep_their_existing_semantics(self):
        for frontend, upstream, status in [('HEAD', 'HEAD', 200), ('POST', 'GET', 200), ('POST', 'HEAD', 204), ('POST', 'HEAD', 304)]:
            flow = tflow.tflow(resp=True)
            flow.request.method = upstream; flow.metadata['lens_frontend_method'] = frontend
            flow.response.status_code = status; flow.response.raw_content = b''
            flow.response.headers['content-length'] = '90'
            normalize_response(flow)
            self.assertEqual(flow.response.headers['content-length'], '90')
            self.assertNotIn('lens_method_framing', flow.metadata)

    def test_invalid_framing_facts_cannot_be_treated_as_observed(self):
        good = dict(frontend_method='POST', effective_method='HEAD', source_content_length=['90'], source_transfer_encoding=[])
        self.assertEqual(import_framing(good), good)
        for changes in ({'frontend_method':'HEAD'}, {'effective_method':'POST'}, {'source_content_length':'90'},
                        {'source_transfer_encoding':['bad\n']}, {'source_content_length':['x'*65536]}, {'extra':True}):
            with self.assertRaises(ValueError): import_framing({**good, **changes})

    def test_synthetic_payload_and_unknown_body_are_not_empty_head_evidence(self):
        for body in (b'local response', None):
            flow = tflow.tflow(resp=True)
            flow.request.method = 'HEAD'; flow.metadata['lens_frontend_method'] = 'POST'
            flow.response.raw_content = body
            before = copy.deepcopy(flow.metadata), list(flow.response.headers.fields)
            normalize_response(flow)
            self.assertEqual((flow.metadata, list(flow.response.headers.fields)), before)
