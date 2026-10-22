"""Range admission happens before endpoint expansion or listener ownership."""
import unittest
from unittest.mock import patch

from forwarding import parse_forwards


class ForwardingRanges(unittest.TestCase):
    def test_closed_range_maps_by_offset_and_preserves_selected_host_spelling(self):
        selected = {'listen_port': 31000, 'listen_port_end': 31002,
                    'target_host': 'EXAMPLE.test.', 'target_port': 41000}
        for transport in ('TCP', 'UDP'):
            with self.subTest(transport=transport):
                result = parse_forwards([selected], [], transport)
                self.assertEqual([(row.listen_port, row.target_port) for row in result],
                                 [(31000, 41000), (31001, 41001), (31002, 41002)])
                self.assertTrue(all(row.target_host == 'EXAMPLE.test.' and row.dial_host == 'example.test' for row in result))
                single = {key: value for key, value in selected.items() if key != 'listen_port_end'}
                explicit = {**single, 'listen_port_end': single['listen_port']}
                self.assertEqual(parse_forwards([single], [], transport), parse_forwards([explicit], [], transport))

    def test_resource_and_port_bounds_precede_host_parsing_and_expansion(self):
        base = {'listen_port': 31000, 'listen_port_end': 31031,
                'target_host': 'example.test', 'target_port': 65504}
        self.assertEqual(len(parse_forwards([base], [])), 32)
        # Invalid numeric/resource choices are rejected before interpreting host
        # text, including a huge interval and aggregate expansion from two rows.
        invalid = [
            [{**base, 'listen_port_end': 65535}],
            [{**base, 'target_port': 65505}],
            [{**base, 'listen_port_end': 30999}],
        ]
        for field in ('listen_port', 'listen_port_end', 'target_port'):
            invalid.extend([{**base, field: value}] for value in (True, None, '31001', 0, 65536))
        for rows in invalid:
            with self.subTest(rows=rows), patch('forwarding.canonical_host', side_effect=AssertionError('must preflight')):
                with self.assertRaises(ValueError): parse_forwards(rows, [])
        with self.assertRaisesRegex(ValueError, 'at most 32 listener'):
            parse_forwards([{**base, 'listen_port_end': 31016},
                            {**base, 'listen_port': 32000, 'listen_port_end': 32015}], [])

    def test_overlap_checks_every_expanded_port_without_mutating_caller_occupancy(self):
        base = {'listen_port': 31000, 'listen_port_end': 31002,
                'target_host': 'example.test', 'target_port': 41000}
        occupied = [31001]
        with self.assertRaisesRegex(ValueError, 'distinct TCP ports'):
            parse_forwards([base], occupied)
        self.assertEqual(occupied, [31001])
        for transport in ('TCP', 'UDP'):
            for following in ({**base, 'listen_port': 31002, 'listen_port_end': 31003},
                              {**base, 'listen_port': 31001, 'listen_port_end': 31001}):
                with self.subTest(transport=transport, following=following):
                    with self.assertRaisesRegex(ValueError, 'distinct'):
                        parse_forwards([base, following], [], transport)


if __name__ == '__main__':
    unittest.main()
