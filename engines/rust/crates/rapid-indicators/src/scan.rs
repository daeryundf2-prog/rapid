//! Candidate matchers for Python's `URL_RE`, `IP_RE` and `HASH_RE` on ASCII text.
//!
//! Every function assumes ASCII input: callers route any scalar with a
//! non-ASCII character to Python, so Unicode `\w`, `\d`, `\s`, `\b` and
//! case folding never have to be reproduced here.

pub const URL: u32 = 0;
pub const IP: u32 = 1;
pub const HASH: u32 = 2;

fn word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Python `str.isspace()` restricted to ASCII.
pub fn python_space(byte: u8) -> bool {
    matches!(byte, b'\t'..=b'\r' | 0x1c..=0x20)
}

fn url_delimiter(byte: u8) -> bool {
    python_space(byte)
        || matches!(
            byte,
            b'[' | b']' | b'(' | b')' | b'{' | b'}' | b'"' | b'\'' | b'<' | b'>'
        )
}

pub fn urls(text: &[u8], mut emit: impl FnMut(usize, usize)) {
    let mut start = 0;
    while start + 7 < text.len() {
        if !text[start..start + 4].eq_ignore_ascii_case(b"http") {
            start += 1;
            continue;
        }
        let colon = start + 4 + usize::from(text[start + 4].eq_ignore_ascii_case(&b's'));
        if !text[colon..].starts_with(b"://") {
            start += 1;
            continue;
        }
        let body = colon + 3;
        let mut end = body;
        while end < text.len() && !url_delimiter(text[end]) {
            end += 1;
        }
        if end > body {
            emit(start, end);
        }
        start = end;
    }
}

fn ipv4_end(text: &[u8], mut pos: usize) -> Option<usize> {
    for group in 0..4 {
        let start = pos;
        while pos - start < 3 && text.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        if start == pos {
            return None;
        }
        if group < 3 {
            if text.get(pos) != Some(&b'.') {
                return None;
            }
            pos += 1;
        }
    }
    if text.get(pos).is_some_and(|&byte| word(byte)) {
        return None;
    }
    Some(pos)
}

pub fn ips(text: &[u8], mut emit: impl FnMut(usize, usize)) {
    if !text.contains(&b'.') {
        return;
    }
    let mut pos = 0;
    while pos < text.len() {
        if text[pos].is_ascii_digit() && (pos == 0 || !word(text[pos - 1])) {
            if let Some(end) = ipv4_end(text, pos) {
                emit(pos, end);
                pos = end;
                continue;
            }
        }
        pos += 1;
    }
}

pub fn hashes(text: &[u8], mut emit: impl FnMut(usize, usize)) {
    if text.len() < 32 {
        return;
    }
    let mut pos = 0;
    while pos < text.len() {
        if !word(text[pos]) {
            pos += 1;
            continue;
        }
        // Bounding both ends with \b requires the entire word to be hex.
        let start = pos;
        while pos < text.len() && word(text[pos]) {
            pos += 1;
        }
        if matches!(pos - start, 32 | 40 | 64) && text[start..pos].iter().all(u8::is_ascii_hexdigit)
        {
            emit(start, pos);
        }
    }
}

/// Append `[family, start, end]` for every candidate, URL then IPv4 then hash.
pub fn candidates(text: &[u8], spans: &mut Vec<[u32; 3]>) {
    // Callers cap scalars far below u32::MAX, so the casts cannot truncate.
    urls(text, |s, e| spans.push([URL, s as u32, e as u32]));
    ips(text, |s, e| spans.push([IP, s as u32, e as u32]));
    hashes(text, |s, e| spans.push([HASH, s as u32, e as u32]));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_use_python_delimiters_and_preserve_embedded_nul() {
        for byte in 0u8..=127 {
            let mut text = b"xHtTpS://a".to_vec();
            text.push(byte);
            text.push(b'b');
            let mut matches = Vec::new();
            urls(&text, |s, e| matches.push((s, e)));
            let delimiters = b" \t\n\x0b\x0c\r\x1c\x1d\x1e\x1f[](){}\"'<>";
            let end = if delimiters.contains(&byte) { 10 } else { 12 };
            assert_eq!(matches, [(1, end)], "byte {byte}");
        }
        let mut matches = Vec::new();
        urls(b"http:// https:// http://a/http://b", |s, e| {
            matches.push((s, e))
        });
        assert_eq!(matches, [(17, 34)]);
    }

    #[test]
    fn ips_retry_at_each_word_boundary_and_never_overlap_within_family() {
        let text = b"_1.2.3.4.5 1.22.333.4444.5 1.2.3.4.5.6.7.8 9.8.7.6x";
        let mut matches = Vec::new();
        ips(text, |s, e| matches.push(&text[s..e]));
        assert_eq!(matches, [b"2.3.4.5", b"1.2.3.4", b"5.6.7.8"]);
    }

    #[test]
    fn hash_alternatives_require_two_word_boundaries() {
        for n in [31, 32, 33, 39, 40, 41, 63, 64, 65] {
            let hex = "aE01".repeat(17);
            let text = format!("_{} !{}-{}g", &hex[..n], &hex[..n], &hex[..n]);
            let mut matches = Vec::new();
            hashes(text.as_bytes(), |s, e| matches.push(e - s));
            assert_eq!(
                matches.as_slice(),
                if matches!(n, 32 | 40 | 64) {
                    vec![n]
                } else {
                    vec![]
                }
            );
        }
    }

    #[test]
    fn candidates_are_grouped_by_family() {
        let mut spans = Vec::new();
        candidates(
            b"0.0.0.0 HTTP://1.2.3.4/0123456789abcdef0123456789abcdef",
            &mut spans,
        );
        assert_eq!(
            spans,
            [[URL, 8, 55], [IP, 0, 7], [IP, 15, 22], [HASH, 23, 55]]
        );
    }
}
