//! Candidate scanner for `rapidtriage.core.indicator_kernel`.
//!
//! `rapid-indicators` scans one batch of ASCII scalars from stdin;
//! `rapid-indicators jsonl PATH` scans a JSONL artifact record stream with
//! the field policy read from stdin.

mod json;
mod jsonl;
mod scan;

use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;

const MAGIC: &[u8; 6] = b"RIND2\n";
const MAX_SCALAR_LENGTH: usize = 4096;
const MAX_ROWS: usize = 1 << 16;
const END_FAMILY: u32 = 3;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_u32(input: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Request: `MAGIC`, `u32` row count, `u32` lengths, concatenated ASCII text.
/// Reply: `MAGIC`, `[row, family, start, end]` per candidate, then
/// `[rows, END_FAMILY, 0, 0]`.
fn batch(mut input: impl Read, mut out: impl Write) -> io::Result<()> {
    let mut header = [0; MAGIC.len()];
    input.read_exact(&mut header)?;
    if &header != MAGIC {
        return Err(invalid("invalid indicator batch header"));
    }
    let rows = read_u32(&mut input)? as usize;
    if rows > MAX_ROWS {
        return Err(invalid("too many indicator scalars"));
    }
    let mut lengths = vec![0u8; rows * 4];
    input.read_exact(&mut lengths)?;
    let (lengths, _) = lengths.as_chunks::<4>();
    let mut text = vec![0; MAX_SCALAR_LENGTH];
    let mut spans = Vec::new();
    let mut reply = MAGIC.to_vec();
    for (row, length) in lengths.iter().enumerate() {
        let text = text
            .get_mut(..u32::from_le_bytes(*length) as usize)
            .ok_or_else(|| invalid("oversized indicator scalar"))?;
        input.read_exact(text)?;
        if !text.is_ascii() {
            return Err(invalid("non-ASCII indicator scalar"));
        }
        spans.clear();
        scan::candidates(text, &mut spans);
        for [family, start, end] in &spans {
            for value in [row as u32, *family, *start, *end] {
                reply.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    if input.read(&mut [0; 1])? != 0 {
        return Err(invalid("trailing indicator batch bytes"));
    }
    for value in [rows as u32, END_FAMILY, 0, 0] {
        reply.extend_from_slice(&value.to_le_bytes());
    }
    out.write_all(&reply)?;
    out.flush()
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let stdout = BufWriter::with_capacity(1 << 20, io::stdout().lock());
    match args.as_slice() {
        [] => batch(io::stdin().lock(), stdout),
        [mode, path] if mode == "jsonl" => {
            jsonl::run(&PathBuf::from(path), io::stdin().lock(), stdout)
        }
        _ => Err(invalid("usage: rapid-indicators [jsonl PATH]")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(rows: &[&[u8]]) -> Vec<u8> {
        let mut input = MAGIC.to_vec();
        input.extend_from_slice(&(rows.len() as u32).to_le_bytes());
        for row in rows {
            input.extend_from_slice(&(row.len() as u32).to_le_bytes());
        }
        for row in rows {
            input.extend_from_slice(row);
        }
        input
    }

    #[test]
    fn consumes_whole_batch_and_emits_family_order_and_end_record() {
        let text = b"0.0.0.0 HTTP://1.2.3.4/0123456789abcdef0123456789abcdef";
        let mut reply = Vec::new();
        batch(request(&[b"", text, b"no matches"]).as_slice(), &mut reply).unwrap();
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
    fn rejects_truncated_oversized_trailing_and_non_ascii_frames() {
        let mut short_lengths = MAGIC.to_vec();
        short_lengths.extend_from_slice(&2u32.to_le_bytes());
        short_lengths.extend_from_slice(&[1, 0, 0, 0]);
        let mut short_scalar = request(&[b"x"]);
        short_scalar.pop();
        let mut trailing = request(&[b"x"]);
        trailing.push(b'y');
        let mut too_many = MAGIC.to_vec();
        too_many.extend_from_slice(&(MAX_ROWS as u32 + 1).to_le_bytes());
        for bad in [
            b"BADHDR".to_vec(),
            MAGIC[..3].to_vec(),
            short_lengths,
            short_scalar,
            trailing,
            too_many,
            request(&[&[b'a'; MAX_SCALAR_LENGTH + 1]]),
            request(&[&[0xff]]),
        ] {
            assert!(batch(bad.as_slice(), io::sink()).is_err());
        }
        let mut reply = Vec::new();
        batch(
            request(&[&[b'a'; MAX_SCALAR_LENGTH]]).as_slice(),
            &mut reply,
        )
        .unwrap();
        assert_eq!(reply.len(), MAGIC.len() + 16);
    }
}
