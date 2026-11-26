//! Native scan of a JSONL artifact record stream.
//!
//! Mirrors `iter_jsonl_items` + `iter_payload_records(expand=False)` +
//! `iter_scalar_contexts` for rows inside the exact subset described in
//! `json.rs`, and sends every other line to Python verbatim. Python supplies
//! the field policy tables so it stays the single source of truth.
//!
//! Reply: `MAGIC`, then frames (`u32` length + records). Records are `HIT`
//! (an ASCII scalar with candidate spans), `PYTHON_SCALAR` (a non-ASCII
//! scalar that may hold a candidate; Python runs its regexes on it), `LINE`
//! (a raw line Python decodes and scans) and `CHECKPOINT`, which ends each
//! frame and is where Python resumes after a failure. The last frame is `END`.

use crate::json::{self, Value};
use crate::scan::{self, python_space};
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, Write};
use std::path::Path;

pub const MAGIC: &[u8; 7] = b"RINDJ1\n";
const HIT: u8 = 0;
const LINE: u8 = 1;
const CHECKPOINT: u8 = 2;
const END: u8 = 3;
const PYTHON_SCALAR: u8 = 4;
const END_COMPLETE: u32 = 0;
/// Python reads the whole file itself (it is not valid UTF-8).
const END_DELEGATED: u32 = 1;
const FRAME_BYTES: usize = 1 << 20;
const FRAME_LINES: u64 = 4096;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_u32(input: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_strings(input: &mut impl Read) -> io::Result<Vec<Vec<u8>>> {
    let count = read_u32(input)?;
    if count > 4096 {
        return Err(invalid("oversized policy table"));
    }
    (0..count)
        .map(|_| {
            let length = read_u32(input)?;
            if length > 4096 {
                return Err(invalid("oversized policy entry"));
            }
            let mut text = vec![0; length as usize];
            input.read_exact(&mut text)?;
            Ok(text)
        })
        .collect()
}

/// Field policy from `rapidtriage.core.indicators`.
pub struct Policy {
    max_scalar: usize,
    excluded_types: HashSet<Vec<u8>>,
    subtree_keys: HashSet<Vec<u8>>,
    subtree_suffixes: Vec<Vec<u8>>,
    subtree_prefixes: Vec<Vec<u8>>,
    leaf_keys: HashSet<Vec<u8>>,
    evidence_hash_keys: HashSet<Vec<u8>>,
    leaf_suffixes: Vec<Vec<u8>>,
    context_keys: Vec<Vec<u8>>,
}

impl Policy {
    pub fn read(mut input: impl Read) -> io::Result<Self> {
        let mut magic = [0; MAGIC.len()];
        input.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(invalid("invalid policy header"));
        }
        let max_scalar = read_u32(&mut input)? as usize;
        let mut table = || read_strings(&mut input);
        let set = |items: Vec<Vec<u8>>| items.into_iter().collect::<HashSet<_>>();
        let policy = Self {
            max_scalar,
            excluded_types: set(table()?),
            subtree_keys: set(table()?),
            subtree_suffixes: table()?,
            subtree_prefixes: table()?,
            leaf_keys: set(table()?),
            evidence_hash_keys: set(table()?),
            leaf_suffixes: table()?,
            context_keys: table()?,
        };
        let mut rest = [0; 1];
        if input.read(&mut rest)? != 0 {
            return Err(invalid("trailing policy bytes"));
        }
        Ok(policy)
    }

    /// `is_provenance_subtree`.
    fn subtree(&self, key: &[u8]) -> bool {
        self.subtree_keys.contains(key)
            || self.subtree_suffixes.iter().any(|end| key.ends_with(end))
            || self
                .subtree_prefixes
                .iter()
                .any(|start| key.starts_with(start))
    }

    /// `is_provenance_leaf`; the regex `(a|b)$` also matches before a final newline.
    fn leaf(&self, key: &[u8]) -> bool {
        if self.leaf_keys.contains(key) {
            return true;
        }
        if self.evidence_hash_keys.contains(key) {
            return false;
        }
        let trimmed = key.strip_suffix(b"\n");
        self.leaf_suffixes
            .iter()
            .any(|end| key.ends_with(end) || trimmed.is_some_and(|key| key.ends_with(end)))
    }
}

/// Python `str(value)` for a JSON scalar; `None` for containers and null.
fn scalar_text<'v>(value: &'v Value) -> Option<&'v [u8]> {
    match value {
        Value::Str(text) => Some(text),
        Value::Int(b"-0") => Some(b"0"),
        Value::Int(digits) => Some(digits),
        Value::Bool(true) => Some(b"True"),
        Value::Bool(false) => Some(b"False"),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn member<'m, 'a>(members: &'m [(Cow<'a, [u8]>, Value<'a>)], key: &[u8]) -> Option<&'m Value<'a>> {
    members
        .iter()
        .find(|(name, _)| name.as_ref() == key)
        .map(|(_, value)| value)
}

fn has_key(value: &Value, key: &[u8]) -> bool {
    match value {
        Value::Object(members) => members
            .iter()
            .any(|(name, child)| name.as_ref() == key || has_key(child, key)),
        Value::Array(items) => items.iter().any(|child| has_key(child, key)),
        _ => false,
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ()> {
    put_u32(out, u32::try_from(bytes.len()).map_err(drop)?);
    out.extend_from_slice(bytes);
    Ok(())
}

/// One row's traversal. `Err(())` means "send the raw line to Python".
struct Walker<'p> {
    policy: &'p Policy,
    index: u64,
    pointer: Vec<u8>,
    spans: Vec<[u32; 3]>,
    out: Vec<u8>,
    scalars: u64,
}

impl Walker<'_> {
    fn push_key(&mut self, key: &[u8]) {
        self.pointer.push(b'/');
        for &byte in key {
            match byte {
                b'~' => self.pointer.extend_from_slice(b"~0"),
                b'/' => self.pointer.extend_from_slice(b"~1"),
                _ => self.pointer.push(byte),
            }
        }
    }

    /// `context_from_mapping`: present, non-empty fields in policy order.
    fn context(&self, members: &[(Cow<[u8]>, Value)]) -> Result<Vec<u8>, ()> {
        let mut encoded = Vec::new();
        let mut count = 0;
        for (slot, key) in self.policy.context_keys.iter().enumerate() {
            let text = match member(members, key) {
                None | Some(Value::Null) => continue,
                // `str()` of a container is its repr: leave it to Python.
                Some(Value::Array(_) | Value::Object(_)) => return Err(()),
                Some(value) => scalar_text(value).ok_or(())?,
            };
            if text.is_empty() {
                continue;
            }
            put_u32(&mut encoded, slot as u32);
            put_bytes(&mut encoded, text)?;
            count += 1;
        }
        let mut framed = Vec::with_capacity(encoded.len() + 4);
        put_u32(&mut framed, count);
        framed.extend_from_slice(&encoded);
        Ok(framed)
    }

    fn object(&mut self, members: &[(Cow<[u8]>, Value)]) -> Result<(), ()> {
        let mut context: Option<Vec<u8>> = None;
        for (key, value) in members {
            let depth = self.pointer.len();
            self.push_key(key);
            match value {
                Value::Object(children) => {
                    if !self.policy.subtree(key) {
                        self.object(children)?;
                    }
                }
                Value::Array(items) => {
                    if !self.policy.subtree(key) {
                        self.array(items)?;
                    }
                }
                Value::Null => {}
                scalar => {
                    let text = scalar_text(scalar).ok_or(())?;
                    if !self.policy.leaf(key) && !text.is_empty() {
                        self.scalar(text, members, &mut context)?;
                    }
                }
            }
            self.pointer.truncate(depth);
        }
        Ok(())
    }

    fn array(&mut self, items: &[Value]) -> Result<(), ()> {
        for (index, item) in items.iter().enumerate() {
            let depth = self.pointer.len();
            match item {
                Value::Object(children) => {
                    self.pointer
                        .extend_from_slice(format!("/{index}").as_bytes());
                    self.object(children)?;
                }
                Value::Array(nested) => {
                    self.pointer
                        .extend_from_slice(format!("/{index}").as_bytes());
                    self.array(nested)?;
                }
                // `iter_scalar_contexts` ignores list scalars.
                _ => {}
            }
            self.pointer.truncate(depth);
        }
        Ok(())
    }

    fn scalar(
        &mut self,
        text: &[u8],
        members: &[(Cow<[u8]>, Value)],
        context: &mut Option<Vec<u8>>,
    ) -> Result<(), ()> {
        let tag = if text.is_ascii() {
            if text.len() > self.policy.max_scalar {
                return Ok(());
            }
            self.scalars += 1;
            self.spans.clear();
            scan::candidates(text, &mut self.spans);
            if self.spans.is_empty() {
                return Ok(());
            }
            HIT
        } else {
            if characters(text) > self.policy.max_scalar {
                return Ok(());
            }
            // Unicode classes and offsets stay with Python's regexes,
            // unless no candidate of any family can occur.
            if !may_match(text) {
                self.scalars += 1;
                return Ok(());
            }
            PYTHON_SCALAR
        };
        if context.is_none() {
            *context = Some(self.context(members)?);
        }
        self.hit(tag, text, context.as_deref().unwrap_or_default())
    }

    /// A `HIT` with spans, or a `PYTHON_SCALAR` that Python matches itself.
    fn hit(&mut self, tag: u8, text: &[u8], context: &[u8]) -> Result<(), ()> {
        self.out.push(tag);
        put_u64(&mut self.out, self.index);
        let pointer = std::mem::take(&mut self.pointer);
        let written = put_bytes(&mut self.out, &pointer);
        self.pointer = pointer;
        written?;
        put_bytes(&mut self.out, text)?;
        self.out.extend_from_slice(context);
        if tag == HIT {
            put_u32(&mut self.out, self.spans.len() as u32);
            for span in &self.spans {
                for value in span {
                    put_u32(&mut self.out, *value);
                }
            }
        }
        Ok(())
    }
}

/// Python `len()` of valid UTF-8: one per non-continuation byte.
fn characters(text: &[u8]) -> usize {
    text.iter().filter(|&&byte| byte & 0xc0 != 0x80).count()
}

/// Necessary conditions for any `URL_RE`, `IP_RE` or `HASH_RE` match, whatever
/// Unicode semantics apply: a literal `://`, three literal dots, or 32
/// consecutive ASCII hex digits (the hash class is not case-folded).
fn may_match(text: &[u8]) -> bool {
    if text.windows(3).any(|window| window == b"://") {
        return true;
    }
    if text.iter().filter(|&&byte| byte == b'.').count() >= 3 {
        return true;
    }
    let mut run = 0;
    text.iter().any(|byte| {
        run = if byte.is_ascii_hexdigit() { run + 1 } else { 0 };
        run >= 32
    })
}

/// `str(row.get("artifact_type") or "")`, or `None` when that is a repr.
fn artifact_type<'v>(members: &'v [(Cow<[u8]>, Value)]) -> Option<&'v [u8]> {
    match member(members, b"artifact_type") {
        None | Some(Value::Null | Value::Bool(false)) => Some(b""),
        Some(Value::Int(b"0" | b"-0")) => Some(b""),
        Some(Value::Array(items)) if items.is_empty() => Some(b""),
        Some(Value::Object(members)) if members.is_empty() => Some(b""),
        Some(Value::Array(_) | Value::Object(_)) => None,
        Some(value) => scalar_text(value),
    }
}

enum Row {
    /// Excluded type, or every candidate was emitted natively.
    Native(u64),
    /// Python must decode and scan this row.
    Python,
}

fn scan_row(
    policy: &Policy,
    walker: &mut Walker,
    members: &[(Cow<[u8]>, Value)],
    line: &[u8],
) -> Row {
    // Every outcome, including an excluded row, starts from an empty reply.
    walker.out.clear();
    let Some(kind) = artifact_type(members) else {
        return Row::Python;
    };
    if policy.excluded_types.contains(kind) {
        return Row::Native(0);
    }
    if members
        .iter()
        .any(|(name, child)| name.as_ref() == b"ioc_hits" || has_key(child, b"ioc_hits"))
    {
        return Row::Python;
    }
    walker.scalars = 0;
    walker.pointer.clear();
    walker
        .pointer
        .extend_from_slice(format!("/artifacts/{}", walker.index).as_bytes());
    // Bound the reply: a row whose citations would dwarf its own text goes to Python.
    match walker.object(members) {
        Ok(()) if walker.out.len() <= 4 * line.len() + 65536 => Row::Native(walker.scalars),
        _ => Row::Python,
    }
}

/// Split like Python's universal-newline text mode: `\n`, `\r\n` or `\r`.
fn next_line(
    input: &mut impl BufRead,
    segment: &mut Vec<u8>,
    start: &mut usize,
) -> io::Result<Option<(usize, usize, usize)>> {
    if *start >= segment.len() {
        segment.clear();
        *start = 0;
        if input.read_until(b'\n', segment)? == 0 {
            return Ok(None);
        }
    }
    let rest = &segment[*start..];
    let begin = *start;
    match rest.iter().position(|&byte| byte == b'\n' || byte == b'\r') {
        None => {
            *start = segment.len();
            Ok(Some((begin, segment.len(), 0)))
        }
        Some(at) => {
            let terminator = if rest[at] == b'\r' && rest.get(at + 1) == Some(&b'\n') {
                2
            } else {
                1
            };
            *start = begin + at + terminator;
            Ok(Some((begin, begin + at, terminator)))
        }
    }
}

fn starts_object(line: &[u8]) -> bool {
    line.iter().find(|&&byte| !matches!(byte, b' ' | b'\t')) == Some(&b'{')
}

fn frame(out: &mut impl Write, records: &mut Vec<u8>) -> io::Result<()> {
    let length = u32::try_from(records.len()).map_err(|_| invalid("oversized frame"))?;
    out.write_all(&length.to_le_bytes())?;
    out.write_all(records)?;
    records.clear();
    Ok(())
}

fn end(out: &mut impl Write, status: u32, total: u64) -> io::Result<()> {
    let mut records = vec![END];
    put_u32(&mut records, status);
    put_u64(&mut records, total);
    frame(out, &mut records)
}

pub fn scan(policy: &Policy, mut input: impl BufRead, mut out: impl Write) -> io::Result<()> {
    out.write_all(MAGIC)?;
    let mut walker = Walker {
        policy,
        index: 0,
        pointer: Vec::new(),
        spans: Vec::new(),
        out: Vec::new(),
        scalars: 0,
    };
    let (mut segment, mut start) = (Vec::new(), 0);
    let (mut offset, mut line_number, mut frame_lines, mut scalars) = (0u64, 0u64, 0u64, 0u64);
    let mut records = Vec::new();
    while let Some((begin, stop, terminator)) = next_line(&mut input, &mut segment, &mut start)? {
        line_number += 1;
        frame_lines += 1;
        offset += (stop - begin + terminator) as u64;
        let line = &segment[begin..stop];
        // Python's `str.strip()` also removes Unicode spaces; such lines fail
        // to parse here and go to Python with every other unparsed line.
        let row = if line.iter().all(|&byte| python_space(byte)) {
            Some(Row::Native(0)) // blank: skipped without a row index
        } else {
            match json::parse(line) {
                Some(Value::Object(members)) => {
                    let row = scan_row(policy, &mut walker, &members, line);
                    if let Row::Native(count) = row {
                        records.extend_from_slice(&walker.out);
                        scalars += count;
                        walker.index += 1;
                    }
                    Some(row)
                }
                Some(_) => Some(Row::Native(0)), // valid non-object: skipped
                None => None,
            }
        };
        if !matches!(row, Some(Row::Native(_))) {
            let object = starts_object(line);
            records.push(LINE);
            put_u64(&mut records, line_number);
            put_u64(&mut records, if object { walker.index + 1 } else { 0 });
            put_u32(&mut records, u32::from(terminator > 0));
            put_bytes(&mut records, line).map_err(|()| invalid("oversized line"))?;
            walker.index += u64::from(object);
        }
        if records.len() >= FRAME_BYTES || frame_lines >= FRAME_LINES {
            checkpoint(
                &mut out,
                &mut records,
                offset,
                line_number,
                walker.index,
                scalars,
            )?;
            (frame_lines, scalars) = (0, 0);
        }
    }
    checkpoint(
        &mut out,
        &mut records,
        offset,
        line_number,
        walker.index,
        scalars,
    )?;
    end(&mut out, END_COMPLETE, offset)?;
    out.flush()
}

fn checkpoint(
    out: &mut impl Write,
    records: &mut Vec<u8>,
    offset: u64,
    line: u64,
    index: u64,
    scalars: u64,
) -> io::Result<()> {
    records.push(CHECKPOINT);
    for value in [offset, line, index, scalars] {
        put_u64(records, value);
    }
    frame(out, records)
}

/// Python's `open(..., encoding="utf-8")` raises on invalid UTF-8; such a
/// file is delegated whole so Python raises the same error itself.
fn valid_utf8(mut file: impl Read) -> io::Result<bool> {
    let mut buffer = vec![0; 1 << 20];
    let mut carry = 0;
    loop {
        let read = file.read(&mut buffer[carry..])?;
        if read == 0 {
            return Ok(carry == 0);
        }
        let filled = carry + read;
        carry = match std::str::from_utf8(&buffer[..filled]) {
            Ok(_) => 0,
            Err(error) if error.error_len().is_none() => {
                buffer.copy_within(error.valid_up_to()..filled, 0);
                filled - error.valid_up_to()
            }
            Err(_) => return Ok(false),
        };
    }
}

pub fn run(path: &Path, config: impl Read, mut out: impl Write) -> io::Result<()> {
    let policy = Policy::read(config)?;
    let mut file = File::open(path)?;
    if !valid_utf8(&mut file)? {
        out.write_all(MAGIC)?;
        end(&mut out, END_DELEGATED, 0)?;
        return out.flush();
    }
    file.rewind()?;
    scan(&policy, BufReader::with_capacity(1 << 20, file), out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(out: &mut Vec<u8>, items: &[&str]) {
        put_u32(out, items.len() as u32);
        for item in items {
            put_bytes(out, item.as_bytes()).unwrap();
        }
    }

    fn policy() -> Policy {
        let mut config = MAGIC.to_vec();
        put_u32(&mut config, 64);
        strings(&mut config, &["registry-hive-cell"]);
        strings(&mut config, &["citations"]);
        strings(&mut config, &["_manifest"]);
        strings(&mut config, &["source_hash"]);
        strings(&mut config, &["output"]);
        strings(&mut config, &["sha256"]);
        strings(&mut config, &["_sha256"]);
        strings(&mut config, &["path", "kind"]);
        Policy::read(config.as_slice()).unwrap()
    }

    #[derive(Debug, PartialEq)]
    enum Record {
        Hit(u64, String, String, Vec<(u32, String)>, Vec<[u32; 3]>),
        Line(u64, u64, u32, String),
        PyScalar(u64, String, String, Vec<(u32, String)>),
        Checkpoint([u64; 4]),
        End(u32, u64),
    }

    struct Cursor<'a>(&'a [u8]);

    impl Cursor<'_> {
        fn take(&mut self, n: usize) -> Vec<u8> {
            let (head, tail) = self.0.split_at(n);
            self.0 = tail;
            head.to_vec()
        }
        fn u32(&mut self) -> u32 {
            u32::from_le_bytes(self.take(4).try_into().unwrap())
        }
        fn u64(&mut self) -> u64 {
            u64::from_le_bytes(self.take(8).try_into().unwrap())
        }
        fn text(&mut self) -> String {
            let length = self.u32() as usize;
            String::from_utf8_lossy(&self.take(length)).into_owned()
        }
    }

    fn decode(reply: &[u8]) -> Vec<Record> {
        assert_eq!(&reply[..MAGIC.len()], MAGIC);
        let mut rest = Cursor(&reply[MAGIC.len()..]);
        let mut records = Vec::new();
        loop {
            let length = rest.u32() as usize;
            let body = rest.take(length);
            let mut cursor = Cursor(&body);
            loop {
                let record = match cursor.take(1)[0] {
                    HIT => {
                        let index = cursor.u64();
                        let pointer = cursor.text();
                        let text = cursor.text();
                        let context = (0..cursor.u32())
                            .map(|_| (cursor.u32(), cursor.text()))
                            .collect();
                        let spans = (0..cursor.u32())
                            .map(|_| [cursor.u32(), cursor.u32(), cursor.u32()])
                            .collect();
                        Record::Hit(index, pointer, text, context, spans)
                    }
                    PYTHON_SCALAR => {
                        let index = cursor.u64();
                        let pointer = cursor.text();
                        let text = cursor.text();
                        let context = (0..cursor.u32())
                            .map(|_| (cursor.u32(), cursor.text()))
                            .collect();
                        Record::PyScalar(index, pointer, text, context)
                    }
                    LINE => Record::Line(cursor.u64(), cursor.u64(), cursor.u32(), cursor.text()),
                    CHECKPOINT => {
                        Record::Checkpoint([cursor.u64(), cursor.u64(), cursor.u64(), cursor.u64()])
                    }
                    END => Record::End(cursor.u32(), cursor.u64()),
                    tag => panic!("tag {tag}"),
                };
                let last = matches!(record, Record::Checkpoint(_) | Record::End(..));
                records.push(record);
                if last {
                    break;
                }
            }
            assert!(cursor.0.is_empty());
            if matches!(records.last(), Some(Record::End(..))) {
                assert!(rest.0.is_empty());
                return records;
            }
        }
    }

    fn scan_text(text: &[u8]) -> Vec<Record> {
        let mut reply = Vec::new();
        scan(&policy(), text, &mut reply).unwrap();
        decode(&reply)
    }

    #[test]
    fn mirrors_python_traversal_and_routes_the_rest_verbatim() {
        let input = concat!(
            "{\"path\":\"p\",\"kind\":7,\"a/~b\":\"see 10.0.0.1\",\"output\":\"10.0.0.2\",\"n\":null,",
            "\"x_sha256\":\"10.0.0.3\",\"citations\":{\"u\":\"10.0.0.4\"},\"l\":[\"10.0.0.5\",{\"v\":\"10.0.0.6\"}]}\r\n",
            " \t\x0c\r",
            "[1,2]\n",
            "{\"f\":1.5,\"u\":\"10.0.0.7\"}\r",
            "{\"artifact_type\":\"registry-hive-cell\",\"u\":\"10.0.0.8\",\"ioc_hits\":[]}\n",
            "{\"deep\":{\"ioc_hits\":[]}}\n",
            "{\"path\":{\"x\":1},\"u\":\"10.0.0.9\"}\n",
            "{\"path\":{\"x\":1},\"u\":\"none\",\"b\":true,\"z\":-0}\n",
            "\"\u{e9}\"\n",
            "{bad\n",
            "{\"x_sha256\\n\":\"10.0.0.10\",\"t\":\"\u{e9} 1.2.3.4\",\"k\":\"\u{d55c} a.b\"}",
        );
        let records = scan_text(input.as_bytes());
        let context = vec![(0, "p".to_string()), (1, "7".to_string())];
        assert_eq!(
            records,
            [
                Record::Hit(
                    0,
                    "/artifacts/0/a~1~0b".into(),
                    "see 10.0.0.1".into(),
                    context.clone(),
                    vec![[1, 4, 12]]
                ),
                Record::Hit(
                    0,
                    "/artifacts/0/l/1/v".into(),
                    "10.0.0.6".into(),
                    vec![],
                    vec![[1, 0, 8]]
                ),
                Record::Line(4, 2, 1, "{\"f\":1.5,\"u\":\"10.0.0.7\"}".into()),
                Record::Line(6, 4, 1, "{\"deep\":{\"ioc_hits\":[]}}".into()),
                Record::Line(7, 5, 1, "{\"path\":{\"x\":1},\"u\":\"10.0.0.9\"}".into()),
                Record::Line(10, 7, 1, "{bad".into()),
                Record::PyScalar(7, "/artifacts/7/t".into(), "\u{e9} 1.2.3.4".into(), vec![]),
                Record::Checkpoint([input.len() as u64, 11, 8, 9]),
                Record::End(END_COMPLETE, input.len() as u64),
            ]
        );
    }

    #[test]
    fn provenance_leaf_suffix_also_matches_before_a_final_newline() {
        let records =
            scan_text(b"{\"x_sha256\\n\":\"10.0.0.10\",\"y_sha256\\n\\n\":\"10.0.0.11\"}");
        assert_eq!(
            records[0],
            Record::Hit(
                0,
                "/artifacts/0/y_sha256\n\n".into(),
                "10.0.0.11".into(),
                vec![],
                vec![[1, 0, 9]]
            )
        );
    }

    #[test]
    fn frames_checkpoint_every_frame_lines_and_handles_empty_input() {
        let input = "{}\n".repeat(FRAME_LINES as usize + 1);
        let records = scan_text(input.as_bytes());
        assert_eq!(
            records,
            [
                Record::Checkpoint([3 * FRAME_LINES, FRAME_LINES, FRAME_LINES, 0]),
                Record::Checkpoint([3 * FRAME_LINES + 3, FRAME_LINES + 1, FRAME_LINES + 1, 0]),
                Record::End(END_COMPLETE, 3 * FRAME_LINES + 3),
            ]
        );
        assert_eq!(
            scan_text(b""),
            [Record::Checkpoint([0; 4]), Record::End(END_COMPLETE, 0)]
        );
    }

    #[test]
    fn scalar_limit_and_python_string_conversion() {
        let long = format!("{{\"a\":\"1.2.3.4 {}\",\"b\":\"1.2.3.4 {}\",\"c\":true,\"d\":12345678901234567890123456789012}}", "x".repeat(56), "x".repeat(57));
        let records = scan_text(long.as_bytes());
        assert_eq!(records.len(), 4);
        assert!(matches!(&records[0], Record::Hit(_, pointer, ..) if pointer == "/artifacts/0/a"));
        assert!(
            matches!(&records[1], Record::Hit(_, pointer, _, _, spans) if pointer == "/artifacts/0/d" && spans == &[[2, 0, 32]])
        );
        assert_eq!(records[2], Record::Checkpoint([long.len() as u64, 1, 1, 3]));
    }

    #[test]
    fn non_ascii_scalars_go_to_python_only_when_a_candidate_is_possible() {
        let fits = format!("{}://", "\u{e9}".repeat(61));
        let over = format!("{}://", "\u{e9}".repeat(62));
        let line = format!(
            "{{\"a\":\"{fits}\",\"b\":\"{over}\",\"c\":\"\\uD55C 1.2.3\",\"d\":\"\u{d55c} {}\",\"e\":\"\u{d55c}.a.b.c\"}}",
            "aB".repeat(16)
        );
        let records = scan_text(line.as_bytes());
        let pointers: Vec<_> = records
            .iter()
            .filter_map(|record| match record {
                Record::PyScalar(_, pointer, ..) => Some(pointer.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            pointers,
            ["/artifacts/0/a", "/artifacts/0/d", "/artifacts/0/e"]
        );
        assert_eq!(records[3], Record::Checkpoint([line.len() as u64, 1, 1, 1]));
        assert!(may_match(b"\xc3\xa9://"));
        assert!(!may_match(format!("{}g", "a".repeat(31)).as_bytes()));
        assert!(may_match("a".repeat(32).as_bytes()));
    }

    #[test]
    fn utf8_validation_matches_python_decoding() {
        let chunk = 1 << 20;
        let mut split = vec![b'a'; chunk - 1];
        split.extend_from_slice("\u{d55c}".as_bytes());
        assert!(valid_utf8(split.as_slice()).unwrap());
        for bad in [&b"\xff"[..], b"\xed\xa0\x80", b"\xc0\x80", b"ok\xe2\x82"] {
            assert!(!valid_utf8(bad).unwrap());
        }
    }

    #[test]
    fn rejects_malformed_policy() {
        let mut config = policy_bytes();
        config.push(0);
        assert!(Policy::read(config.as_slice()).is_err());
        assert!(Policy::read(&b"RINDJ1\n"[..]).is_err());
        assert!(Policy::read(&b"BADHDR!"[..]).is_err());
    }

    fn policy_bytes() -> Vec<u8> {
        let mut config = MAGIC.to_vec();
        put_u32(&mut config, 64);
        for _ in 0..8 {
            strings(&mut config, &[]);
        }
        assert!(Policy::read(config.as_slice()).is_ok());
        config
    }
}
