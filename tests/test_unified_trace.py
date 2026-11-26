import random
import struct
import unittest
from unittest.mock import patch

from rapidtriage.artifacts.unified_trace import parse_trace
from tests.unified_trace_fixture import BOOT, CACHE, MAIN, chunk, make_trace


def resolve(kind, uuid, address):
    templates = {
        ('uuidtext', MAIN, 0x100): '%{public}s / %{private}s',
        ('uuidtext', MAIN, 0x120): 'activity',
        ('dsc', CACHE, 0x200): 'begin',
        ('uuidtext', MAIN, 0x140): 'value %u',
    }
    return templates.get((kind, uuid, address), ''), 'synthetic-process' if uuid == MAIN else ''


def decode(data, resolver=resolve):
    return list(parse_trace(data, resolver, lambda boot, ticks: ''))


class UnifiedTraceTests(unittest.TestCase):
    def test_real_wire_layout_four_kinds(self):
        data = make_trace()
        events = list(parse_trace(data, resolve, lambda boot, tick: f'{boot}:{tick}'))
        self.assertEqual([r['event_type'] for r in events], ['log', 'activity', 'signpost', 'trace'])
        self.assertEqual([r['message'] for r in events], ['ok / <private>', 'activity', 'begin', 'value 123'])
        self.assertEqual([r['continuous_time'] for r in events], list(range(1001, 1005)))
        self.assertEqual([r['timestamp'] for r in events], [f'{BOOT}:{t}' for t in range(1001, 1005)])
        self.assertEqual([data[r['offset']] for r in events], [4, 2, 6, 3])
        self.assertTrue(all(r['process'] == 'synthetic-process' and r['pid'] == 42 for r in events))
        self.assertEqual((events[0]['subsystem'], events[2]['category']), ('example.synthetic', 'fixture'))
        self.assertEqual((events[1]['activity_id'], events[2]['signpost_id']), (55, 99))
        self.assertNotIn('hidden', repr(events))

    def test_missing_sidecars_preserve_raw_ticks_without_wall_clock(self):
        rows = decode(make_trace(), lambda *_: ('', ''))
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(r['message_status'] == 'missing-format' and 'timestamp' not in r for r in rows))
        self.assertEqual(rows[2]['continuous_time'], 1003)

    def test_private_descriptor_is_always_redacted_and_unknown_conversions_fail_closed(self):
        data = bytearray(make_trace())
        offset = decode(data)[0]['offset']
        data[offset + 24 + 6 + 2] = 0x21
        self.assertEqual(decode(data)[0]['message'], '<private> / <private>')
        unsafe = lambda *args: ('%*s %{private}s', '') if args[-1] == 0x100 else resolve(*args)
        first = decode(data, unsafe)[0]
        self.assertEqual((first['message'], first['message_status']), ('', 'unsupported-format-conversion'))

    def test_corrupt_bodies_are_counted_once_per_chunk(self):
        data = bytearray(make_trace())
        rows = decode(data)
        data[rows[0]['offset'] + 24 + 6 + 2 + 2:rows[0]['offset'] + 24 + 6 + 2 + 4] = b'\xff\xff'
        struct.pack_into('<H', data, rows[2]['offset'] + 22, 0xffff)
        diagnostics = [r for r in decode(data) if 'diagnostic' in r]
        self.assertEqual([d['offset'] for d in diagnostics], [rows[0]['offset'], rows[2]['offset']])
        self.assertEqual(sum(d['damaged_chunk_count'] for d in diagnostics), 1)

    def test_compressed_and_malformed_chunksets_allow_later_records(self):
        compressed = chunk(0x600d, b'bv41' + struct.pack('<II', 6, 7) + b'\x60abcdefbv4$')
        bad = chunk(0x600d, b'bv4-' + struct.pack('<I', 50))
        rows = decode(compressed + bad + make_trace())
        self.assertEqual([(r['diagnostic'], r['offset']) for r in rows[:2]],
                         [('compressed-unsupported', 0), ('damaged-chunkset', len(compressed))])
        self.assertEqual(len(rows[2:]), 4)
        self.assertEqual(rows[-1]['message'], 'value 123')

    def test_frame_footer_and_lengths(self):
        for body in (b'bv4-' + struct.pack('<I', 0), b'bv4-' + struct.pack('<I', 0) + b'end!',
                     b'bv41' + struct.pack('<II', 4, 99) + b'abcdbv4$',
                     b'bv41' + struct.pack('<II', 4, 4) + b'abcdBAD!'):
            with self.subTest(body=body):
                result, = decode(chunk(0x600d, body))
                self.assertEqual(result, {'diagnostic': 'damaged-chunkset', 'offset': 0, 'damaged_chunk_count': 1})

    def test_alignment_and_nonzero_remnant_are_cited(self):
        data = bytearray(make_trace())
        last = decode(data)[-1]
        data[last['offset']] = 0
        remnant = decode(data)[-1]
        self.assertEqual(remnant['diagnostic'], 'unparsed-firehose-remnant')
        self.assertEqual(remnant['offset'], last['offset'])
        data[last['offset']:last['offset'] + remnant['length']] = bytes(remnant['length'])
        self.assertEqual(len(decode(data)), 3)
        # Remove one byte of the enclosing chunkset's terminal alignment.
        self.assertEqual(decode(data[:-1])[-1]['diagnostic'], 'damaged-chunk-padding')

    def test_message_bound_applies_to_assembled_output(self):
        with patch('rapidtriage.artifacts.unified_trace.MAX_TEXT', 24):
            def resolver(kind, uuid, address):
                if address == 0x100:
                    return 'padding of 16 = %s%s', ''
                return resolve(kind, uuid, address)
            event = decode(make_trace(), resolver)[0]
            self.assertEqual((event['message'], event['message_status']), ('padding of 16 = okhidden', 'rendered'))
        with patch('rapidtriage.artifacts.unified_trace.MAX_TEXT', 23):
            event = decode(make_trace(), resolver)[0]
            self.assertEqual((event['message'], event['message_status']), ('', 'unsupported-message-length'))

    def test_malformed_catalog_clears_previous_process_mapping(self):
        data = make_trace()
        split = data.index(struct.pack('<II', 0x600d, 0))
        rows = decode(data[:split] + chunk(0x600b, bytes(5)) + data[split:])
        self.assertEqual(rows[0]['diagnostic'], 'damaged-catalog')
        self.assertTrue(all(r['pid'] is None and r['message_status'] == 'missing-format' for r in rows[1:]))

    def test_limits_cite_first_omitted_unit(self):
        data = make_trace()
        expected = decode(data)
        with patch('rapidtriage.artifacts.unified_trace.MAX_ROWS', 2):
            self.assertEqual(decode(data)[-1], {'diagnostic': 'trace-row-limit', 'offset': expected[2]['offset']})
        with patch('rapidtriage.artifacts.unified_trace.MAX_CHUNKS', 3):
            self.assertEqual(decode(data)[-1]['diagnostic'], 'chunk-limit')
        with patch('rapidtriage.artifacts.unified_trace.MAX_TRACE_BYTES', len(data) - 1):
            self.assertEqual(decode(data), [{'diagnostic': 'trace-byte-limit', 'offset': 0}])

    def test_deterministic_truncations_and_bit_damage(self):
        data, rng = make_trace(), random.Random(71)
        for stop in range(len(data)):
            rows = decode(data[:stop])
            self.assertTrue(all(0 <= r['offset'] <= stop for r in rows))
        for _ in range(300):
            damaged = bytearray(data)
            for _ in range(1 + rng.randrange(6)):
                damaged[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
            rows = decode(damaged)
            self.assertTrue(all(0 <= r['offset'] < len(data) for r in rows))
