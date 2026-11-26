"""Build a deterministic tracev3 stream from little-endian wire fields."""

from struct import pack

BOOT = '11' * 16
MAIN = '22' * 16
CACHE = '33' * 16


def aligned(data):
    return data + bytes(-len(data) % 8)


def chunk(tag, body, subtype=0):
    return aligned(pack('<IIQ', tag, subtype, len(body)) + body)


def entry(kind, level, flags, address, delta, body):
    return aligned(pack('<BBHIQIHH', kind, level, flags, address, 7, delta, 0, len(body)) + body)


def make_trace(private=b''):
    """Four entries (log/activity/signpost/trace) in one uncompressed chunkset.

    `private` fills the Firehose tail that the private-data offset reserves.
    """
    header = (pack('<II', 125, 3) + bytes(32) + pack('<IIQ', 0x6100, 8, 1000)
              + pack('<II', 0x6101, 56) + bytes(56) + pack('<II', 0x6102, 24)
              + bytes.fromhex(BOOT) + bytes(8) + pack('<II', 0x6103, 48) + bytes(48))
    uuids = bytes.fromhex(MAIN + CACHE)
    labels = aligned(b'example.synthetic\0fixture\0')
    process = (pack('<4HQ6I', 0, 0, 0, 1, 17, 3, 42, 501, 0, 0, 0)
               + pack('<II', 1, 0) + aligned(pack('<HHH', 7, 0, 18)))
    # Two public descriptors; the format annotation on the second mandates redaction.
    items = (pack('<BB', 0x22, 2) + pack('<BBHH', 0x22, 4, 0, 3)
             + pack('<BBHH', 0x22, 4, 3, 7) + b'ok\0hidden\0')
    records = b''.join((
        entry(4, 1, 0x202, 0x100, 1, pack('<IH', 0, 7) + items),
        entry(2, 1, 2, 0x120, 2, pack('<III', 55, 0x80000000, 0)),
        entry(6, 0x81, 0x204, 0x200, 3, pack('<IHQ', 0, 7, 99)),
        entry(3, 0, 2, 0x140, 4, pack('<IIBB', 0, 123, 4, 1)),
    ))
    firehose = chunk(0x6001, pack('<QI4xHH4xQ', 17, 3, 16 + len(records), 0x1000 - len(private), 1000)
                     + records + private)
    catalog = (pack('<8HQ', 32, 32 + len(labels), 1, 32 + len(labels) + len(process),
                    1, 0, 0, 0, 1000) + uuids + labels + process
               + pack('<QQIIII', 1001, 1004, len(firehose), 0x100, 0, 0))
    return (chunk(0x1000, header, 0x11) + chunk(0x600b, catalog, 0x11)
            + chunk(0x600d, b'bv4-' + pack('<I', len(firehose)) + firehose + b'bv4$'))
