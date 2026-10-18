"""Tiny LZ77+Huffman ("XPRESS Huffman", [MS-XCA] §2.1) encoder for synthetic test fixtures.

Not a production compressor: greedy hash-chain-free matching, one Huffman
table per 64 KiB output block, length-limited (15-bit) canonical codes built
from symbol frequencies (``flat=True`` uses 9 bits for all 512 symbols).
The word/byte interleaving mirrors the decoder: bits fill 16-bit
little-endian words that are reserved ahead of extra match-length bytes, so
``rapidtriage.artifacts.windows.xpress_huffman.decompress`` (and ntdll's
``RtlDecompressBufferEx``) read the stream back.
"""

from __future__ import annotations

import heapq
import struct

BLOCK = 65536
MIN_MATCH = 3


def tokenize(block: bytes, history: bytes, *, max_offset: int = 65535) -> list[tuple[int, int, int]]:
    """``(symbol, length, offset)`` tokens: literal ``(byte, 0, 0)`` or match ``(-1, length, offset)``."""
    data = history + block
    start = len(history)
    index: dict[bytes, int] = {}
    for position in range(max(0, start - max_offset), start - 2):
        index[data[position : position + 3]] = position
    tokens: list[tuple[int, int, int]] = []
    position = start
    while position < len(data):
        key = data[position : position + 3]
        candidate = index.get(key) if len(key) == 3 else None
        if candidate is not None and 0 < position - candidate <= max_offset:
            length = 0
            while position + length < len(data) and data[candidate + length] == data[position + length]:
                length += 1
            if length >= MIN_MATCH:
                tokens.append((-1, length, position - candidate))
                for step in range(length):
                    if position + step + 3 <= len(data):
                        index[data[position + step : position + step + 3]] = position + step
                position += length
                continue
        tokens.append((data[position], 0, 0))
        if len(key) == 3:
            index[key] = position
        position += 1
    return tokens


def match_symbol(length: int, offset: int) -> tuple[int, int]:
    offset_bits = offset.bit_length() - 1
    length_code = min(length - MIN_MATCH, 15)
    return 256 + (offset_bits << 4 | length_code), offset_bits


def code_lengths(frequencies: list[int], *, flat: bool) -> list[int]:
    if flat:
        return [9] * 512
    freqs = list(frequencies)
    while True:
        used = [symbol for symbol in range(512) if freqs[symbol]]
        if len(used) == 1:
            lengths = [0] * 512
            lengths[used[0]] = 1
            return lengths
        heap: list[tuple[int, int, list[int]]] = [(freqs[symbol], symbol, [symbol]) for symbol in used]
        heapq.heapify(heap)
        depth = [0] * 512
        counter = 512
        while len(heap) > 1:
            weight_a, _, members_a = heapq.heappop(heap)
            weight_b, _, members_b = heapq.heappop(heap)
            for symbol in members_a + members_b:
                depth[symbol] += 1
            heapq.heappush(heap, (weight_a + weight_b, counter, members_a + members_b))
            counter += 1
        if max(depth) <= 15:
            return depth
        freqs = [(value + 1) // 2 if value else 0 for value in freqs]


def canonical_codes(lengths: list[int]) -> list[int]:
    codes = [0] * 512
    code = 0
    for bits in range(1, 16):
        for symbol in range(512):
            if lengths[symbol] == bits:
                codes[symbol] = code
                code += 1
        code <<= 1
    return codes


class _BlockWriter:
    def __init__(self, out: bytearray) -> None:
        self.out = out
        self.words: list[int] = []  # output positions of reserved 16-bit words
        self.bit_count = 0
        self._reserve(2)

    def _reserve(self, count: int) -> None:
        for _ in range(count):
            self.words.append(len(self.out))
            self.out += b"\x00\x00"

    def bits(self, value: int, count: int) -> None:
        for shift in range(count - 1, -1, -1):
            bit = (value >> shift) & 1
            word = self.bit_count // 16
            if bit:
                position = self.words[word]
                current = self.out[position] | self.out[position + 1] << 8
                current |= 1 << (15 - self.bit_count % 16)
                self.out[position : position + 2] = struct.pack("<H", current)
            self.bit_count += 1
        needed = max(2, -(-self.bit_count // 16) + 1)
        if needed > len(self.words):
            self._reserve(needed - len(self.words))

    def raw(self, data: bytes) -> None:
        self.out += data


def compress(data: bytes, *, flat: bool = False, force_u32_lengths: bool = False) -> bytes:
    out = bytearray()
    for block_start in range(0, len(data), BLOCK):
        block = data[block_start : block_start + BLOCK]
        tokens = tokenize(block, data[max(0, block_start - 65535) : block_start])
        frequencies = [0] * 512
        for symbol, length, offset in tokens:
            frequencies[symbol if symbol >= 0 else match_symbol(length, offset)[0]] += 1
        lengths = code_lengths(frequencies, flat=flat)
        codes = canonical_codes(lengths)
        out += bytes(lengths[2 * i] | lengths[2 * i + 1] << 4 for i in range(256))
        writer = _BlockWriter(out)
        for symbol, length, offset in tokens:
            if symbol >= 0:
                writer.bits(codes[symbol], lengths[symbol])
                continue
            code_symbol, offset_bits = match_symbol(length, offset)
            writer.bits(codes[code_symbol], lengths[code_symbol])
            if length - MIN_MATCH >= 15:
                extra = length - MIN_MATCH
                if force_u32_lengths:
                    writer.raw(b"\xff" + struct.pack("<HI", 0, extra))
                elif extra - 15 < 255:
                    writer.raw(bytes([extra - 15]))
                else:
                    writer.raw(b"\xff" + struct.pack("<H", extra))
            writer.bits(offset - (1 << offset_bits), offset_bits)
    return bytes(out)


def mam(data: bytes, **options: bool) -> bytes:
    """``MAM\\x04`` container (XPRESS Huffman, no CRC) around ``compress(data)``."""
    return b"MAM\x04" + struct.pack("<I", len(data)) + compress(data, **options)
