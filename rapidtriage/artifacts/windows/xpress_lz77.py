"""Pure-Python plain LZ77 ("XPRESS", COMPRESSION_FORMAT_XPRESS) decompressor, [MS-XCA] §2.3-2.4.

Used for Windows 8+ hibernation compression sets that are not
Huffman-coded. The stream is 32-bit little-endian flag words (most
significant bit first: 0 = literal byte, 1 = match) interleaved with the
literal bytes and 16-bit match tokens (low 3 bits = length - 3, high 13 bits
= offset - 1). A length of 7 is extended by a shared half byte, then by a
byte, a u16 and a u32, exactly as the specification's pseudo-code.

Bounded like ``xpress_huffman``: the caller states the expected output size,
which must not exceed ``MAX_OUTPUT_BYTES``; truncated input or a match that
points before the start of the output raises ``XpressLz77Error``.
"""

from __future__ import annotations

MAX_OUTPUT_BYTES = 16 * 1024 * 1024


class XpressLz77Error(ValueError):
    """The plain LZ77 stream is malformed or truncated."""


def decompress(data: bytes, output_size: int) -> bytes:
    """Decompress ``data`` into exactly ``output_size`` bytes or raise ``XpressLz77Error``."""
    if output_size < 0 or output_size > MAX_OUTPUT_BYTES:
        raise XpressLz77Error(
            f"declared output size {output_size} exceeds limit {MAX_OUTPUT_BYTES}"
        )
    size = len(data)
    out = bytearray()
    position = 0
    flags = 0
    flag_count = 0
    last_half_byte = 0

    def take(count: int) -> int:
        nonlocal position
        if position + count > size:
            raise XpressLz77Error("plain LZ77 stream ended early")
        value = int.from_bytes(data[position : position + count], "little")
        position += count
        return value

    while len(out) < output_size:
        if flag_count == 0:
            flags = take(4)
            flag_count = 32
        flag_count -= 1
        if not flags & (1 << flag_count):
            out.append(take(1))
            continue
        token = take(2)
        length = token & 7
        offset = (token >> 3) + 1
        if length == 7:
            if last_half_byte == 0:
                if position >= size:
                    raise XpressLz77Error("plain LZ77 stream ended early")
                length = data[position] & 0x0F
                last_half_byte = position
                position += 1
            else:
                length = data[last_half_byte] >> 4
                last_half_byte = 0
            if length == 15:
                length = take(1)
                if length == 255:
                    length = take(2)
                    if length == 0:
                        length = take(4)
                    if length < 15 + 7:
                        raise XpressLz77Error("extended match length is too small")
                    length -= 15 + 7
                length += 15
            length += 7
        length += 3
        start = len(out) - offset
        if start < 0:
            raise XpressLz77Error("match offset points before the start of the output")
        length = min(length, output_size - len(out))
        if offset >= length:
            out += out[start : start + length]
        else:
            period = bytes(out[start:])
            out += (period * (length // offset + 1))[:length]
    return bytes(out)
