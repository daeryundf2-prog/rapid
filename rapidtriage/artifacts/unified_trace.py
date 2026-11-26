"""Offline tracev3 decoder. All reported offsets refer to physical input bytes."""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from io import StringIO

MAX_TRACE_BYTES = 64 * 1024 * 1024
MAX_CHUNKS = 8192
MAX_ROWS = 10_000
MAX_TEXT = 4096
KINDS = {2: 'activity', 3: 'trace', 4: 'log', 6: 'signpost'}


def _damaged(reason, offset, *, chunk_offset=None):
    row = {'diagnostic': reason, 'offset': offset, 'damaged_chunk_count': 1}
    if chunk_offset is not None:
        row['chunk_offset'] = chunk_offset
    return row


class _Cursor:
    """Read only inside the current record or subsection."""
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, size):
        end = self.pos + size
        if end > len(self.data):
            raise ValueError('truncated-record')
        start, self.pos = self.pos, end
        return self.data[start:end]

    def integer(self, size):
        return int.from_bytes(self.take(size), 'little')


@dataclass
class _Process:
    main: str = ''
    cache: str = ''
    pid: int | None = None
    labels: dict = field(default_factory=dict)


def _catalog(data):
    strings, processes, count, subchunks = struct.unpack_from('<4H', data)
    if strings % 16 or not 0 <= strings <= processes <= subchunks <= len(data) - 24:
        raise ValueError('catalog-offset')
    uuids = [data[pos:pos + 16].hex() for pos in range(24, 24 + strings, 16)]
    table = bytes(data[24 + strings:24 + processes])
    reader = _Cursor(data[24 + processes:24 + subchunks])
    labels = {}

    def label(offset):
        if offset not in labels:
            end = table.find(b'\0', offset, offset + MAX_TEXT + 1)
            if end < 0:
                raise ValueError('catalog-label')
            labels[offset] = table[offset:end].decode('utf-8')
        return labels[offset]

    result = {}
    for _ in range(count):
        _, _, main, cache, proc1, proc2, pid, _, _, libraries, _ = struct.unpack(
            '<4HQ6I', reader.take(40))
        reader.take(16 * libraries)
        num_labels = reader.integer(4)
        reader.take(4)
        mappings = {}
        for ident, sub, cat in struct.iter_unpack('<3H', reader.take(6 * num_labels)):
            mappings[ident] = (label(sub), label(cat))
        reader.take((-6 * num_labels) % 8)
        result[proc1, proc2] = _Process(uuids[main] if main < len(uuids) else '',
                                        uuids[cache] if cache < len(uuids) else '', pid, mappings)
    # Validate the trailing descriptors without retaining their index arrays.
    descriptors = struct.unpack_from('<H', data, 8)[0]
    reader = _Cursor(data[24 + subchunks:])
    for _ in range(descriptors):
        reader.take(24)
        indexes = reader.integer(4)
        reader.take(2 * indexes)
        offsets = reader.integer(4)
        reader.take(2 * offsets + (-2 * (indexes + offsets)) % 8)
    return result


def _boot_uuid(data):
    if len(data) < 40:
        raise ValueError('header-prefix')
    pos = 40
    boot_uuid = ''
    # The known header fits in 208 bytes. Bound extension traversal separately
    # from the top-level/inner chunk counter.
    if len(data) > 4096:
        raise ValueError('header-size')
    while pos < len(data):
        tag, size = struct.unpack_from('<II', data, pos)
        pos += 8
        if pos + size > len(data):
            raise ValueError('header-section')
        if tag == 0x6102:
            if size < 16:
                raise ValueError('boot-section')
            boot_uuid = data[pos:pos + 16].hex()
        pos += size
    if not boot_uuid:
        raise ValueError('missing-boot-id')
    return boot_uuid


def _items(data, trace):
    if not len(data):
        return []
    if trace:
        count = data[-1]
        if len(data) < 1 + count:
            raise ValueError('trace-argument-count')
        reader = _Cursor(data[:len(data) - 1 - count])
        sizes = data[len(reader.data):-1]
        if len(reader.data) != sum(sizes) or any(n not in (1, 2, 4, 8) for n in sizes):
            raise ValueError('trace-argument-size')
        return [('int', reader.take(n)) for n in sizes]

    reader = _Cursor(data)
    reader.take(1)  # aggregate argument flags
    count = reader.integer(1)
    values = []
    for _ in range(count):
        kind, size = reader.take(2)
        if kind in (0x00, 0x02) and size in (1, 2, 4, 8):
            values.append(('int', reader.take(size)))
        elif kind in (0x20, 0x22, 0x40, 0x42) and size == 4:
            values.append(('range', struct.unpack('<HH', reader.take(4))))
        elif kind in (0x01, 0x21, 0x31, 0x41, 0x81) and size == 4:
            # Private descriptors address another area. Never dereference them.
            reader.take(4)
            values.append(('private', None))
        else:
            raise NotImplementedError('argument-type')
    pool = data[reader.pos:]
    for index, (kind, value) in enumerate(values):
        if kind == 'range':
            offset, size = value
            if offset + size > len(pool):
                raise ValueError('argument-range')
            values[index] = ('text', pool[offset:offset + size])
    return values


# Only consume conversions we can interpret. Guessing the argument position
# after an unknown conversion could disclose an argument marked private.
_CONVERSION = re.compile(r'%(?:%|(?:\{([^}]{1,64})\})?(?:hh|ll|[hlztj])?([diuoxXps@c]))')


def _render(template, args):
    output = StringIO()
    cursor, arg = 0, 0

    def append(text):
        if output.tell() + len(text) > MAX_TEXT:
            raise NotImplementedError('message-length')
        output.write(text)
    while (start := template.find('%', cursor)) >= 0:
        append(template[cursor:start])
        match = _CONVERSION.match(template, start)
        if not match:
            raise NotImplementedError('format-conversion')
        cursor = match.end()
        if match[0] == '%%':
            append('%')
            continue
        annotation, conv = match.groups()
        if annotation not in (None, 'public', 'private', 'sensitive'):
            raise NotImplementedError('format-annotation')
        if arg >= len(args):
            if annotation in ('private', 'sensitive'):
                append('<private>')
                arg += 1
                continue
            raise ValueError('missing-argument')
        kind, value = args[arg]
        arg += 1
        if annotation in ('private', 'sensitive') or kind == 'private':
            append('<private>')
        elif kind == 'text' and conv in ('s', '@'):
            append(bytes(value[:MAX_TEXT + 1]).partition(b'\0')[0].decode('utf-8', 'replace'))
        elif kind == 'int' and conv in 'diuoxXpc':
            number = int.from_bytes(value, 'little', signed=conv in 'di')
            if conv == 'c':
                append(chr(number & 0xff))
            elif conv == 'p':
                append(hex(number))
            else:
                append(format(number, conv if conv in 'oxX' else 'd'))
        else:
            raise NotImplementedError('argument-conversion')
    append(template[cursor:])
    return output.getvalue()


def _message(row, proc, kind, level, flags, address, body, resolve):
    # Each activity type uses the same bits for different optional fields.
    # With an unfamiliar layout we can still cite the entry header, but cannot
    # establish which payload bytes are public arguments.
    allowed_flags = {2: 0x027f, 3: 0x000e, 4: 0x1f6f, 6: 0x9f6f}
    if flags & ~allowed_flags[kind]:
        raise NotImplementedError('entry-flags')
    reader = _Cursor(body)
    if kind == 2 and level != 3:
        row['activity_id'] = reader.integer(4)
        reader.take(4)
    if kind == 2 and flags & 0x10:
        reader.take(8)
    if kind != 3 and flags & 1:
        row['current_activity_id'] = reader.integer(4)
        reader.take(4)
    if kind != 3 and flags & 0x40:
        reader.take(4)
    if kind == 2 and flags & 0x200:
        row['other_activity_id'] = reader.integer(4)
        reader.take(4)
    if kind in (4, 6) and flags & 0x100:
        reader.take(4)
    reader.take(4)  # code location
    mode = flags & 0xE
    source, uuid = 'uuidtext', proc.main
    if mode == 0xA and kind != 3:
        uuid = reader.take(16).hex()
    elif mode == 4 and not flags & 0x20 and kind != 3:
        source, uuid = 'dsc', proc.cache
    elif mode != 2:
        raise NotImplementedError('formatter-mode')

    if kind in (4, 6) and flags & 0x200:
        key = reader.integer(2)
        row['subsystem'], row['category'] = proc.labels.get(key, ('', ''))
    if kind == 6:
        row['signpost_id'] = reader.integer(8)
    if kind in (4, 6) and flags & 0x400:
        reader.take(1)
    if kind in (4, 6) and flags & 0x800:
        raise NotImplementedError('oversize-arguments')
    if kind == 6 and flags & 0x8000:
        row['signpost_name_offset'] = reader.integer(4)
    if flags & 0x1000:
        raise NotImplementedError('context-arguments')
    if address & 0x80000000:
        raise NotImplementedError('dynamic-format')
    row['format_source'] = source
    row['format_uuid'] = uuid
    template, _ = resolve(source, uuid, address) if uuid else ('', '')
    if not template:
        row['message_status'] = 'missing-format'
        return
    if len(template) > MAX_TEXT:
        raise NotImplementedError('message-length')
    row['message'] = _render(template, _items(body[reader.pos:], kind == 3))
    row['message_status'] = 'rendered'


def _firehose(data, offset, processes, boot, resolve, wall_time):
    try:
        proc1, proc2, size, base = struct.unpack_from('<QI4xH6xQ', data)
        if not 16 <= size <= len(data) - 16:
            raise ValueError('public-size')
    except (struct.error, ValueError):
        yield _damaged('damaged-firehose', offset - 16)
        return
    proc = processes.get((proc1, proc2), _Process())
    process = resolve('uuidtext', proc.main, -1)[1] if proc.main else ''
    # The public region starts at the size field. The private region is never read.
    public, pos = data[:16 + size], 32
    while pos < len(public) and public[pos]:
        start = pos
        try:
            kind, level, flags, address, thread, low, high, length = struct.unpack_from(
                '<BBHIQIHH', public, start)
            end = start + 24 + length
            if end > len(public):
                raise ValueError('entry-size')
        except (struct.error, ValueError):
            yield _damaged('damaged-entry', offset + start, chunk_offset=offset - 16)
            return
        pos = end
        while pos < min(len(public), end + (-length) % 8) and public[pos] == 0:
            pos += 1
        if kind not in KINDS:
            yield {'diagnostic': 'unsupported-entry', 'offset': offset + start, 'entry_type': kind}
            continue
        ticks = base + (high << 32) + low
        row = {'event_type': KINDS[kind], 'log_type': level, 'thread_id': thread,
               'offset': offset + start, 'length': end - start,
               'continuous_time': ticks, 'boot_uuid': boot, 'pid': proc.pid,
               'process': process, 'process_uuid': proc.main,
               'subsystem': '', 'category': '', 'format_offset': address, 'message': ''}
        if boot and (timestamp := wall_time(boot, ticks)):
            row['timestamp'] = timestamp
        try:
            _message(row, proc, kind, level, flags, address, public[start + 24:end], resolve)
        except NotImplementedError as exc:
            row['message_status'] = f'unsupported-{exc}'
        except (ValueError, struct.error):
            row['message_status'] = 'damaged-entry'
            yield _damaged('damaged-entry', offset + start, chunk_offset=offset - 16)
        yield row
    if pos < len(public) and any(public[pos:]):
        # Type zero marks remnant data. Report its extent, never interpret or
        # emit the leftover bytes (they may belong to a different entry).
        yield {'diagnostic': 'unparsed-firehose-remnant', 'offset': offset + pos,
               'length': len(public) - pos}


def _chunks(data, base, budget):
    pos = 0
    while pos < len(data):
        start = base + pos
        if budget[0] == 0:
            yield None, None, start, {'diagnostic': 'chunk-limit', 'offset': start}
            return
        budget[0] -= 1
        if len(data) - pos < 16:
            yield None, None, start, _damaged('damaged-chunk-header', start)
            return
        tag, _, length = struct.unpack_from('<IIQ', data, pos)
        end = pos + 16 + length
        if end > len(data):
            yield None, None, start, _damaged('damaged-chunk-size', start)
            return
        yield tag, data[pos + 16:end], start, None
        pos = end + (-length) % 8
        if pos > len(data) or any(data[end:pos]):
            yield None, None, start, _damaged('damaged-chunk-padding', base + end, chunk_offset=start)
            return


def _decode(data, resolve, wall_time):
    processes, boot = {}, ''
    budget = [MAX_CHUNKS]
    for tag, body, offset, error in _chunks(memoryview(data), 0, budget):
        if error:
            yield error
        elif tag == 0x1000:
            processes, boot = {}, ''
            try:
                boot = _boot_uuid(body)
            except (ValueError, struct.error):
                yield _damaged('damaged-header', offset)
        elif tag == 0x600b:
            processes = {}
            try:
                processes = _catalog(body)
            except (ValueError, struct.error):
                yield _damaged('damaged-catalog', offset)
        elif tag == 0x600d:
            if len(body) < 8:
                yield _damaged('damaged-chunkset', offset)
                continue
            magic = bytes(body[:4])
            size = struct.unpack_from('<I', body, 4)[0]
            if magic == b'bv41':
                if (len(body) < 16 or struct.unpack_from('<I', body, 8)[0] != len(body) - 16
                        or body[-4:] != b'bv4$'):
                    yield _damaged('damaged-chunkset', offset)
                else:
                    yield {'diagnostic': 'compressed-unsupported', 'codec': 'lz4', 'offset': offset}
                continue
            if magic != b'bv4-':
                yield {'diagnostic': 'unsupported-chunkset', 'offset': offset}
                continue
            trailer = body[8 + size:]
            if size != len(body) - 12 or trailer != b'bv4$':
                yield _damaged('damaged-chunkset', offset)
                continue
            for inner, payload, location, error in _chunks(body[8:8 + size], offset + 24, budget):
                if error:
                    yield error
                    if error['diagnostic'] == 'chunk-limit':
                        return
                elif inner == 0x6001:
                    yield from _firehose(payload, location + 16, processes, boot, resolve, wall_time)
                else:
                    yield {'diagnostic': 'unsupported-inner-chunk', 'offset': location, 'chunk_tag': inner}
        else:
            yield {'diagnostic': 'unsupported-chunk', 'offset': offset, 'chunk_tag': tag}


def parse_trace(data: bytes, resolve, wall_time):
    """Yield independently citable events and diagnostics for one bounded trace."""
    if len(data) > MAX_TRACE_BYTES:
        yield {'diagnostic': 'trace-byte-limit', 'offset': 0}
        return
    if not data:
        yield _damaged('damaged-chunk-header', 0)
        return
    damaged_chunks = set()
    for index, row in enumerate(_decode(data, resolve, wall_time)):
        if index >= MAX_ROWS:
            yield {'diagnostic': 'trace-row-limit', 'offset': row['offset']}
            return
        if 'damaged_chunk_count' in row:
            origin = row.get('chunk_offset', row['offset'])
            row['damaged_chunk_count'] = int(origin not in damaged_chunks)
            damaged_chunks.add(origin)
        yield row
