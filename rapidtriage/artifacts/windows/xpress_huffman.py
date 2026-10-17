"""Pure-Python LZ77+Huffman ("XPRESS Huffman") decompressor, [MS-XCA] §2.1-2.2.

Used for Windows 10/11 MAM-compressed Prefetch files (``MAM\\x04``). The
stream is a sequence of blocks, each producing up to 65,536 output bytes:
a 256-byte table of 512 four-bit code lengths (symbol ``2i`` in the low
nibble of byte ``i``), then a bit stream read as little-endian 16-bit words
(most significant bit first). Symbols 0-255 are literals; 256-511 encode a
match: low nibble = length - 3 (15 = extended by one byte, 255 = by a u16,
0 = by a u32), high nibble = offset bit count.

Bounded: the caller states the expected output size, which must not exceed
``MAX_OUTPUT_BYTES`` (validated before any allocation); every decoded symbol
emits at least one byte, so a corrupt stream ends in ``XpressHuffmanError``
(never an endless loop); malformed code-length tables (over-subscribed,
empty, or a code that is not in the table) are rejected.
"""

from __future__ import annotations

MAX_OUTPUT_BYTES = 16 * 1024 * 1024
BLOCK_OUTPUT_BYTES = 65536
TABLE_BYTES = 256
SYMBOL_COUNT = 512
MAX_CODE_BITS = 15
# The decoder pre-reads up to 32 bits, so a well-formed stream may end a few
# bytes before the reader's last refill; more than this is truncation.
MAX_OVERREAD_BYTES = 4


class XpressHuffmanError(ValueError):
    """The compressed stream or its Huffman table is malformed."""


def build_decoding_table(table: bytes) -> list[int]:
    """512 code lengths -> 2**15 lookup of ``symbol << 4 | length`` (canonical Huffman).

    Raises on an empty or over-subscribed table; entries of an incomplete
    table stay ``-1`` (a code that hits them is rejected while decoding).
    """
    if len(table) < TABLE_BYTES:
        raise XpressHuffmanError("Huffman 표가 256바이트보다 짧습니다")
    lengths = [0] * SYMBOL_COUNT
    for index in range(TABLE_BYTES):
        value = table[index]
        lengths[2 * index] = value & 0x0F
        lengths[2 * index + 1] = value >> 4
    decoding = [-1] * (1 << MAX_CODE_BITS)
    code = 0
    used = 0
    for bits in range(1, MAX_CODE_BITS + 1):
        span = 1 << (MAX_CODE_BITS - bits)
        for symbol in range(SYMBOL_COUNT):
            if lengths[symbol] != bits:
                continue
            start = code * span
            if start + span > len(decoding):
                raise XpressHuffmanError("Huffman 표의 부호 공간이 초과되었습니다(손상된 길이 표)")
            decoding[start : start + span] = [symbol << 4 | bits] * span
            code += 1
            used += 1
        code <<= 1
    if not used:
        raise XpressHuffmanError("Huffman 표에 부호가 하나도 없습니다")
    return decoding


def decompress(data: bytes, output_size: int) -> bytes:
    """Decompress ``data`` into exactly ``output_size`` bytes or raise ``XpressHuffmanError``."""
    if output_size < 0 or output_size > MAX_OUTPUT_BYTES:
        raise XpressHuffmanError(f"선언된 해제 크기 {output_size}가 상한 {MAX_OUTPUT_BYTES}를 벗어납니다")
    size = len(data)
    out = bytearray()
    position = 0
    while len(out) < output_size:
        if position + TABLE_BYTES > size:
            raise XpressHuffmanError("블록의 Huffman 표가 입력 끝을 넘습니다")
        decoding = build_decoding_table(data[position : position + TABLE_BYTES])
        position += TABLE_BYTES
        overread = 0

        def word() -> int:
            nonlocal position, overread
            if position + 2 <= size:
                value = data[position] | data[position + 1] << 8
            else:
                overread += 2
                if overread > MAX_OVERREAD_BYTES:
                    raise XpressHuffmanError("압축 스트림이 예상보다 일찍 끝났습니다")
                value = data[position] if position < size else 0
            position += 2
            return value

        def byte() -> int:
            nonlocal position
            if position >= size:
                raise XpressHuffmanError("일치 길이 바이트가 입력 끝을 넘습니다")
            value = data[position]
            position += 1
            return value

        bits = (word() << 16) | word()
        extra = 16
        block_end = min(len(out) + BLOCK_OUTPUT_BYTES, output_size)
        while len(out) < block_end:
            entry = decoding[bits >> (32 - MAX_CODE_BITS)]
            if entry < 0:
                raise XpressHuffmanError("Huffman 표에 없는 부호입니다")
            length_bits = entry & 0x0F
            symbol = entry >> 4
            bits = (bits << length_bits) & 0xFFFFFFFF
            extra -= length_bits
            if extra < 0:
                bits |= word() << -extra
                extra += 16
            if symbol < 256:
                out.append(symbol)
                continue
            symbol -= 256
            match_length = symbol & 0x0F
            offset_bits = symbol >> 4
            if match_length == 15:
                match_length = byte()
                if match_length == 255:
                    match_length = byte() | byte() << 8
                    if match_length == 0:
                        match_length = byte() | byte() << 8 | byte() << 16 | byte() << 24
                    if match_length < 15:
                        raise XpressHuffmanError("확장 일치 길이가 15보다 작습니다")
                    match_length -= 15
                match_length += 15
            match_length += 3
            offset = ((bits >> (32 - offset_bits)) if offset_bits else 0) + (1 << offset_bits)
            bits = (bits << offset_bits) & 0xFFFFFFFF
            extra -= offset_bits
            if extra < 0:
                bits |= word() << -extra
                extra += 16
            start = len(out) - offset
            if start < 0:
                raise XpressHuffmanError("일치 오프셋이 출력 시작보다 앞을 가리킵니다")
            if len(out) + match_length > output_size:
                match_length = output_size - len(out)
            if offset >= match_length:
                out += out[start : start + match_length]
            else:
                for index in range(match_length):
                    out.append(out[start + index])
    return bytes(out)
