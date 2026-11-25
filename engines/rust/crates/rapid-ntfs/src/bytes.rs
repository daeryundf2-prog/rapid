/// `int_from(blob, offset, size)` of filesystem.py: little-endian unsigned, 0 when out of bounds.
pub fn int_from(blob: &[u8], offset: usize, size: usize) -> u64 {
    match offset.checked_add(size) {
        Some(end) if end <= blob.len() => blob[offset..end]
            .iter()
            .rev()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
        _ => 0,
    }
}

pub fn int_from_u128(blob: &[u8], offset: usize, size: usize) -> u128 {
    match offset.checked_add(size) {
        Some(end) if end <= blob.len() => blob[offset..end]
            .iter()
            .rev()
            .fold(0u128, |acc, byte| (acc << 8) | u128::from(*byte)),
        _ => 0,
    }
}

pub fn u16_at(blob: &[u8], offset: usize) -> usize {
    int_from(blob, offset, 2) as usize
}

pub fn u32_at(blob: &[u8], offset: usize) -> u64 {
    int_from(blob, offset, 4)
}

pub fn u64_at(blob: &[u8], offset: usize) -> u64 {
    int_from(blob, offset, 8)
}

fn utf16_units(blob: &[u8]) -> impl Iterator<Item = u16> + '_ {
    blob.chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
}

/// Python `blob.decode("utf-16le", errors="ignore")`.
pub fn utf16_ignore(blob: &[u8]) -> String {
    char::decode_utf16(utf16_units(blob))
        .filter_map(Result::ok)
        .collect()
}

/// Python `blob.decode("utf-16le")` (strict); `None` where Python raises.
pub fn utf16_strict(blob: &[u8]) -> Option<String> {
    if !blob.len().is_multiple_of(2) {
        return None;
    }
    char::decode_utf16(utf16_units(blob))
        .collect::<Result<String, _>>()
        .ok()
}

pub fn hex(blob: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(blob.len() * 2);
    for byte in blob {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0F)] as char);
    }
    out
}

pub fn find(blob: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= blob.len() || needle.is_empty() {
        return None;
    }
    let first = needle[0];
    let mut start = from;
    while start + needle.len() <= blob.len() {
        let hit = start
            + blob[start..=blob.len() - needle.len()]
                .iter()
                .position(|byte| *byte == first)?;
        if &blob[hit..hit + needle.len()] == needle {
            return Some(hit);
        }
        start = hit + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_from_is_zero_out_of_bounds() {
        assert_eq!(int_from(&[1, 2], 0, 2), 0x0201);
        assert_eq!(int_from(&[1, 2], 1, 2), 0);
        assert_eq!(int_from(&[1, 2], usize::MAX, 2), 0);
    }

    #[test]
    fn utf16_decoders_match_python_error_modes() {
        let lone_surrogate = [0x41, 0x00, 0x00, 0xD8, 0x42, 0x00];
        assert_eq!(utf16_ignore(&lone_surrogate), "AB");
        assert_eq!(utf16_strict(&lone_surrogate), None);
        assert_eq!(utf16_ignore(&[0x41, 0x00, 0x42]), "A");
        assert_eq!(utf16_strict(&[0x41, 0x00, 0x42]), None);
        assert_eq!(utf16_strict(&[0x41, 0x00]).as_deref(), Some("A"));
    }

    #[test]
    fn find_scans_from_offset() {
        assert_eq!(find(b"xxFILEFILE", b"FILE", 0), Some(2));
        assert_eq!(find(b"xxFILEFILE", b"FILE", 3), Some(6));
        assert_eq!(find(b"xxFILEFILE", b"FILE", 7), None);
    }
}
