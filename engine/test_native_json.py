import base64
import copy
import json
import unittest
from unittest.mock import patch

import native_json
from native_json import encode_native_message


def source_string(record):
    encoded = record['utf8_surrogatepass_base64']
    raw = base64.b64decode(encoded, validate=True)
    if base64.b64encode(raw).decode('ascii') != encoded:
        raise AssertionError('Noncanonical Base64')
    return raw.decode('utf-8', 'surrogatepass')


def restore(envelope):
    result = copy.deepcopy(envelope['message'])
    # Producers list parent key records before descendants, so reversing keeps
    # projected paths reachable until all of that key's descendants are restored.
    for record in reversed(envelope['source_text']):
        path, source = record['path'], source_string(record)
        if not path:
            if record['kind'] != 'value':
                raise AssertionError('Root cannot be an object member name')
            result = source
            continue
        parent = result
        for component in path[:-1]:
            parent = parent[component]
        if record['kind'] == 'key':
            parent[source] = parent.pop(path[-1])
        else:
            parent[path[-1]] = source
    return result


class NativeJSONBoundary(unittest.TestCase):
    def encode(self, message, **kwargs):
        text = encode_native_message(message, **kwargs)
        self.assertTrue(text.isascii())
        self.assertFalse(text.endswith('\n'))
        result = json.loads(text)
        self.assertEqual(set(result), {'native_json', 'message', 'source_text'})
        self.assertEqual(result['native_json'], 1)
        return text, result

    def test_normal_unicode_payload_is_unchanged_and_does_not_copy_large_body(self):
        message = {'event': 'result', 'value': {'body': 'ordinary body\n' * 65536,
                   'unicode': '汉字😀é e\u0301', 'literal': r'\udcff', 'controls': '\0\x1f\x7f"\\'}}
        original_dumps = json.dumps
        with patch.object(native_json, '_project', side_effect=AssertionError('ordinary body copied')), \
             patch.object(native_json.base64, 'b64encode', side_effect=AssertionError('ordinary body encoded')), \
             patch.object(native_json.json, 'dumps', wraps=original_dumps) as dumps:
            text, result = self.encode(message)
        self.assertEqual(dumps.call_count, 1)
        self.assertIs(dumps.call_args.args[0]['message'], message)
        self.assertEqual(result['message'], message)
        self.assertEqual(result['source_text'], [])
        self.assertEqual(len(text), len(text.encode('ascii')))

    def test_all_surrogate_code_points_are_visible_and_exactly_recoverable(self):
        original = 'before:' + ''.join(chr(code) for code in range(0xD800, 0xE000)) + ':after😀'
        message = {'event': 'result', 'value': {'raw': original}}
        _, result = self.encode(message)
        displayed = result['message']['value']['raw']
        self.assertEqual(displayed, 'before:' + ''.join(f'\\u{code:04x}' for code in range(0xD800, 0xE000)) + ':after😀')
        self.assertEqual(len(result['source_text']), 1)
        self.assertEqual(result['source_text'][0]['path'], ['value', 'raw'])
        self.assertEqual(result['source_text'][0]['kind'], 'value')
        self.assertEqual(source_string(result['source_text'][0]), original)
        self.assertEqual(restore(result), message)
        self.assertIs(message['value']['raw'], original)

    def test_literal_surrogate_pair_is_distinct_from_astral_scalar_and_visible_escape(self):
        pair, astral, literal = '\ud83d\ude00', '\U0001f600', r'\ud83d\ude00'
        original = {'pair': pair, 'astral': astral, 'literal': literal}
        _, result = self.encode(original)
        self.assertEqual(result['message'], {'pair': literal, 'astral': astral, 'literal': literal})
        self.assertEqual([record['path'] for record in result['source_text']], [['pair']])
        self.assertEqual(source_string(result['source_text'][0]), pair)
        self.assertNotEqual(pair.encode('utf-8', 'surrogatepass'), astral.encode('utf-8'))
        self.assertEqual(restore(result), original)
        _, root = self.encode(pair)
        self.assertEqual(root['source_text'][0]['path'], [])
        self.assertEqual(restore(root), pair)

    def test_non_ascii_keys_avoid_normalization_and_generated_name_collisions(self):
        original = {'__lens_native_key_0': 'reserved zero', 'é': {'e\u0301': '\udcff'},
                    'e\u0301': 'decomposed', '__lens_native_key_1': 'reserved one', '\ud800': 'high surrogate key',
                    'ASCII\0key': 'unchanged'}
        _, result = self.encode(original)
        projected = result['message']
        self.assertEqual(projected['__lens_native_key_0'], 'reserved zero')
        self.assertEqual(projected['__lens_native_key_1'], 'reserved one')
        self.assertEqual(projected['ASCII\0key'], 'unchanged')
        self.assertTrue(all(key.isascii() for key in projected))
        self.assertEqual(len(projected), len(original))
        key_records = [record for record in result['source_text'] if record['kind'] == 'key']
        self.assertEqual({source_string(record) for record in key_records}, {'é', 'e\u0301', '\ud800'})
        self.assertEqual(restore(result), original)

    def test_annotations_follow_projected_arrays_and_preserve_unknown_metadata(self):
        original = {'event': 'result', 'value': {'unknown': [{'☃': ['\udc80', {'path': '\udfff'}]}],
                    'source_text': [{'path': ['not a transport tag'], 'kind': 'value'}],
                    'native_json': 99, 'number': -123, 'finite': -0.25, 'flags': [True, False, None]}}
        _, result = self.encode(original)
        records = result['source_text']
        self.assertEqual(records[0]['path'][:3], ['value', 'unknown', 0])
        self.assertEqual(records[1]['path'][-1], 0)
        self.assertEqual(restore(result), original)
        self.assertEqual(result['message']['value']['source_text'], original['value']['source_text'])

    def test_exact_limit_and_rejection_precede_projection_base64_and_full_json(self):
        for original in ({'value': '\udcff' * 1000}, {'é' * 1000: 'source key'},
                         {'value': [0, '\ud800', -0.25, '"\\\n😀']}):
            text = encode_native_message(original)
            self.assertEqual(encode_native_message(original, max_bytes=len(text)), text)
        original = {'raw': '\udcff' * 1000}
        limit = len(encode_native_message(original)) - 1
        with patch.object(native_json, '_project', side_effect=AssertionError('projection before admission')), \
             patch.object(native_json.base64, 'b64encode', side_effect=AssertionError('Base64 before admission')), \
             patch.object(native_json.json, 'dumps', side_effect=AssertionError('full JSON before admission')):
            with self.assertRaisesRegex(ValueError, 'byte budget'):
                encode_native_message(original, max_bytes=limit)
        with patch.object(native_json.json, 'dumps', side_effect=AssertionError('huge decimal allocation')):
            with self.assertRaisesRegex(ValueError, 'byte budget'):
                encode_native_message(1 << 1000000, max_bytes=100)

    def test_invalid_values_cycles_and_nonfinite_numbers_fail_without_output(self):
        cyclic_list = []; cyclic_list.append(cyclic_list)
        cyclic_dict = {}; cyclic_dict['self'] = cyclic_dict
        for original in ({1: 'non-string key'}, {b'bytes': 'non-string key'}, {'value': b'bytes'},
                         {'value': {'set'}}, {'value': float('nan')}, {'value': float('inf')},
                         {'value': -float('inf')}, cyclic_list, cyclic_dict):
            with self.subTest(type=type(original)), self.assertRaises(ValueError), \
                 patch.object(native_json.base64, 'b64encode', side_effect=AssertionError('invalid input encoded')):
                encode_native_message(original)
        for budget in (True, -1, 1.0, None):
            with self.assertRaises(ValueError):
                encode_native_message({}, max_bytes=budget)
        with self.assertRaisesRegex(ValueError, 'byte budget'):
            encode_native_message({}, max_bytes=0)

    def test_shared_acyclic_values_are_encoded_at_each_actual_path(self):
        shared = {'x': '\udcff'}
        message = {'one': shared, 'two': [shared]}
        _, result = self.encode(message)
        self.assertEqual([record['path'] for record in result['source_text']], [['one', 'x'], ['two', 0, 'x']])
        self.assertEqual(restore(result), message)
        # Repeated source annotations reuse one admitted encoding allocation.
        original = native_json.base64.b64encode
        with patch.object(native_json.base64, 'b64encode', wraps=original) as encoder:
            encode_native_message(message)
        self.assertEqual(encoder.call_count, 1)

    def test_excessive_nesting_is_an_explicit_resource_error(self):
        message = 'leaf'
        for _ in range(2000):
            message = [message]
        with self.assertRaisesRegex(ValueError, 'nesting'), \
             patch.object(native_json.base64, 'b64encode', side_effect=AssertionError('deep input encoded')):
            encode_native_message(message)


if __name__ == '__main__':
    unittest.main()
