"""Pure-Python AES (FIPS-197) in CBC mode without padding.

Standard-library only (project runtime policy). Used where a parser already
holds the key material and needs a small amount of AES: PDF AESV2/V3 strings
(``doc_text``) and the KakaoTalk PC legacy page cipher (first-block key check,
bounded page decryption when no OpenSSL binary is on PATH). Throughput is in
the order of 1 MB/s, so callers bound the input size.
"""

from __future__ import annotations

BLOCK_SIZE = 16


def _build_tables() -> tuple[list[int], list[int], tuple[list[int], ...], tuple[list[int], ...]]:
    sbox = [0] * 256
    inverse = [0] * 256
    p = q = 1
    while True:
        # p *= 3, q /= 3 in GF(2^8)
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        value = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4)
        value = (value ^ 0x63) & 0xFF
        sbox[p] = value
        inverse[value] = p
        if p == 1:
            break
    sbox[0] = 0x63
    inverse[0x63] = 0

    def mul(a: int, b: int) -> int:
        result = 0
        while b:
            if b & 1:
                result ^= a
            a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1
            b >>= 1
        return result

    def rotations(base: list[int]) -> tuple[list[int], ...]:
        return (
            base,
            [((value >> 8) | (value << 24)) & 0xFFFFFFFF for value in base],
            [((value >> 16) | (value << 16)) & 0xFFFFFFFF for value in base],
            [((value >> 24) | (value << 8)) & 0xFFFFFFFF for value in base],
        )

    te0 = [0] * 256
    td0 = [0] * 256
    for index in range(256):
        s = sbox[index]
        te0[index] = (mul(s, 2) << 24) | (s << 16) | (s << 8) | mul(s, 3)
        r = inverse[index]
        td0[index] = (mul(r, 14) << 24) | (mul(r, 9) << 16) | (mul(r, 13) << 8) | mul(r, 11)
    return sbox, inverse, rotations(te0), rotations(td0)


SBOX, INV_SBOX, TE, TD = _build_tables()


def _sub_word(word: int) -> int:
    return (SBOX[word >> 24] << 24) | (SBOX[(word >> 16) & 0xFF] << 16) | (SBOX[(word >> 8) & 0xFF] << 8) | SBOX[word & 0xFF]


def encrypt_round_keys(key: bytes) -> list[list[int]]:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    nk = len(key) // 4
    rounds = nk + 6
    words = [int.from_bytes(key[4 * i : 4 * i + 4], "big") for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        temp = words[i - 1]
        if i % nk == 0:
            temp = _sub_word(((temp << 8) | (temp >> 24)) & 0xFFFFFFFF) ^ (rcon << 24)
            rcon = ((rcon << 1) ^ 0x1B) & 0xFF if rcon & 0x80 else rcon << 1
        elif nk > 6 and i % nk == 4:
            temp = _sub_word(temp)
        words.append(words[i - nk] ^ temp)
    return [words[4 * r : 4 * r + 4] for r in range(rounds + 1)]


def decrypt_round_keys(key: bytes) -> list[list[int]]:
    """Round keys of the equivalent inverse cipher (InvMixColumns applied to the middle rounds)."""
    round_keys = list(reversed(encrypt_round_keys(key)))
    td0, td1, td2, td3 = TD
    for r in range(1, len(round_keys) - 1):
        round_keys[r] = [
            td0[SBOX[word >> 24]] ^ td1[SBOX[(word >> 16) & 0xFF]] ^ td2[SBOX[(word >> 8) & 0xFF]] ^ td3[SBOX[word & 0xFF]]
            for word in round_keys[r]
        ]
    return round_keys


def _encrypt_words(round_keys: list[list[int]], s0: int, s1: int, s2: int, s3: int) -> tuple[int, int, int, int]:
    te0, te1, te2, te3 = TE
    k = round_keys[0]
    s0 ^= k[0]
    s1 ^= k[1]
    s2 ^= k[2]
    s3 ^= k[3]
    rounds = len(round_keys) - 1
    for r in range(1, rounds):
        k = round_keys[r]
        t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xFF] ^ te2[(s2 >> 8) & 0xFF] ^ te3[s3 & 0xFF] ^ k[0]
        t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xFF] ^ te2[(s3 >> 8) & 0xFF] ^ te3[s0 & 0xFF] ^ k[1]
        t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xFF] ^ te2[(s0 >> 8) & 0xFF] ^ te3[s1 & 0xFF] ^ k[2]
        t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xFF] ^ te2[(s1 >> 8) & 0xFF] ^ te3[s2 & 0xFF] ^ k[3]
        s0, s1, s2, s3 = t0, t1, t2, t3
    k = round_keys[rounds]
    out = []
    for index, (a, b, c, d) in enumerate(((s0, s1, s2, s3), (s1, s2, s3, s0), (s2, s3, s0, s1), (s3, s0, s1, s2))):
        out.append(((SBOX[a >> 24] << 24) | (SBOX[(b >> 16) & 0xFF] << 16) | (SBOX[(c >> 8) & 0xFF] << 8) | SBOX[d & 0xFF]) ^ k[index])
    return out[0], out[1], out[2], out[3]


def _decrypt_words(round_keys: list[list[int]], s0: int, s1: int, s2: int, s3: int) -> tuple[int, int, int, int]:
    td0, td1, td2, td3 = TD
    k = round_keys[0]
    s0 ^= k[0]
    s1 ^= k[1]
    s2 ^= k[2]
    s3 ^= k[3]
    rounds = len(round_keys) - 1
    for r in range(1, rounds):
        k = round_keys[r]
        t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xFF] ^ td2[(s2 >> 8) & 0xFF] ^ td3[s1 & 0xFF] ^ k[0]
        t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xFF] ^ td2[(s3 >> 8) & 0xFF] ^ td3[s2 & 0xFF] ^ k[1]
        t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xFF] ^ td2[(s0 >> 8) & 0xFF] ^ td3[s3 & 0xFF] ^ k[2]
        t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xFF] ^ td2[(s1 >> 8) & 0xFF] ^ td3[s0 & 0xFF] ^ k[3]
        s0, s1, s2, s3 = t0, t1, t2, t3
    k = round_keys[rounds]
    out = []
    for index, (a, b, c, d) in enumerate(((s0, s3, s2, s1), (s1, s0, s3, s2), (s2, s1, s0, s3), (s3, s2, s1, s0))):
        out.append(
            ((INV_SBOX[a >> 24] << 24) | (INV_SBOX[(b >> 16) & 0xFF] << 16) | (INV_SBOX[(c >> 8) & 0xFF] << 8) | INV_SBOX[d & 0xFF])
            ^ k[index]
        )
    return out[0], out[1], out[2], out[3]


def _check(iv: bytes, data: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("AES-CBC IV must be 16 bytes")
    if len(data) % BLOCK_SIZE:
        raise ValueError("AES-CBC input must be a multiple of 16 bytes (no padding)")


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CBC encryption of block-aligned ``data`` (no padding)."""
    _check(iv, data)
    round_keys = encrypt_round_keys(key)
    out = bytearray()
    previous = int.from_bytes(iv, "big")
    for offset in range(0, len(data), BLOCK_SIZE):
        block = int.from_bytes(data[offset : offset + BLOCK_SIZE], "big") ^ previous
        words = _encrypt_words(
            round_keys, block >> 96, (block >> 64) & 0xFFFFFFFF, (block >> 32) & 0xFFFFFFFF, block & 0xFFFFFFFF
        )
        previous = (words[0] << 96) | (words[1] << 64) | (words[2] << 32) | words[3]
        out += previous.to_bytes(BLOCK_SIZE, "big")
    return bytes(out)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes, *, round_keys: list[list[int]] | None = None) -> bytes:
    """AES-CBC decryption of block-aligned ``data`` (no padding is removed)."""
    _check(iv, data)
    keys = round_keys if round_keys is not None else decrypt_round_keys(key)
    out = bytearray()
    previous = int.from_bytes(iv, "big")
    for offset in range(0, len(data), BLOCK_SIZE):
        cipher = int.from_bytes(data[offset : offset + BLOCK_SIZE], "big")
        words = _decrypt_words(
            keys, cipher >> 96, (cipher >> 64) & 0xFFFFFFFF, (cipher >> 32) & 0xFFFFFFFF, cipher & 0xFFFFFFFF
        )
        plain = ((words[0] << 96) | (words[1] << 64) | (words[2] << 32) | words[3]) ^ previous
        out += plain.to_bytes(BLOCK_SIZE, "big")
        previous = cipher
    return bytes(out)
