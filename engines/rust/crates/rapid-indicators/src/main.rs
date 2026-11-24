use std::io::{self, BufRead, BufReader, BufWriter, Write};

const MAGIC: &[u8; 6] = b"RIND1\n";
const MAX_SCALAR_LENGTH: usize = 4096;

fn word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn url_delimiter(byte: u8) -> bool {
    // Python str.isspace() also includes the four ASCII information separators.
    matches!(byte, b'\t'..=b'\r' | 0x1c..=0x20 | b'[' | b']' | b'(' | b')'
        | b'{' | b'}' | b'"' | b'\'' | b'<' | b'>')
}

fn urls(text: &[u8], mut emit: impl FnMut(usize, usize)) {
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

fn ips(text: &[u8], mut emit: impl FnMut(usize, usize)) {
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

fn hashes(text: &[u8], mut emit: impl FnMut(usize, usize)) {
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

fn write_record(out: &mut impl Write, record: [u32; 4]) -> io::Result<()> {
    for value in record {
        out.write_all(&value.to_le_bytes())?;
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn run(mut input: impl BufRead, mut out: impl Write) -> io::Result<()> {
    let mut header = [0; MAGIC.len()];
    input.read_exact(&mut header)?;
    if &header != MAGIC {
        return Err(invalid("invalid indicator batch header"));
    }
    out.write_all(MAGIC)?;
    let mut row = 0u32;
    let mut buffer = [0; MAX_SCALAR_LENGTH];
    let mut hits = Vec::new();
    while !input.fill_buf()?.is_empty() {
        let mut length = [0; 4];
        input.read_exact(&mut length)?;
        let text = buffer
            .get_mut(..u32::from_le_bytes(length) as usize)
            .ok_or_else(|| invalid("oversized indicator scalar"))?;
        input.read_exact(text)?;
        if !text.is_ascii() {
            return Err(invalid("non-ASCII indicator scalar"));
        }
        urls(text, |s, e| hits.push([row, 0, s as u32, e as u32]));
        ips(text, |s, e| hits.push([row, 1, s as u32, e as u32]));
        hashes(text, |s, e| hits.push([row, 2, s as u32, e as u32]));
        for hit in hits.drain(..) {
            write_record(&mut out, hit)?;
        }
        row = row.checked_add(1).ok_or_else(|| invalid("too many rows"))?;
    }
    write_record(&mut out, [row, 3, 0, 0])?;
    out.flush()
}

fn main() -> io::Result<()> {
    run(
        BufReader::new(io::stdin().lock()),
        BufWriter::new(io::stdout().lock()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(rows: &[&[u8]]) -> Vec<u8> {
        let mut input = MAGIC.to_vec();
        for row in rows {
            input.extend_from_slice(&(row.len() as u32).to_le_bytes());
            input.extend_from_slice(row);
        }
        input
    }

    #[test]
    fn consumes_whole_batch_and_emits_family_order_and_end_record() {
        let text = b"0.0.0.0 HTTP://1.2.3.4/0123456789abcdef0123456789abcdef";
        let input = batch(&[b"", text, b"no matches"]);
        let mut reply = Vec::new();
        run(input.as_slice(), &mut reply).unwrap();
        assert_eq!(&reply[..6], MAGIC);
        let expected: [[u32; 4]; 5] = [
            [1, 0, 8, 55],
            [1, 1, 0, 7],
            [1, 1, 15, 22],
            [1, 2, 23, 55],
            [3, 3, 0, 0],
        ];
        let bytes: Vec<_> = expected
            .into_iter()
            .flatten()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert_eq!(&reply[6..], bytes);
    }

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
    fn rejects_truncated_oversized_and_non_ascii_frames() {
        let mut short_length = MAGIC.to_vec();
        short_length.push(0);
        let mut short_scalar = batch(&[b"x"]);
        short_scalar.pop();
        for bad in [
            b"BADHDR".to_vec(),
            short_length,
            short_scalar,
            batch(&[&[0; MAX_SCALAR_LENGTH + 1]]),
            batch(&[&[0xff]]),
        ] {
            assert!(run(bad.as_slice(), io::sink()).is_err());
        }
    }
}
