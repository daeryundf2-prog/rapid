//! Strict parser for the subset of JSON that Python's `json.loads` decodes
//! to exactly the same values. The input must be valid UTF-8; strings come
//! back as UTF-8 bytes.
//!
//! `None` means "not provably identical": the caller hands the raw line to
//! Python, which then decodes it (or raises) with its own rules. Outside the
//! subset are floats and `NaN`/`Infinity`, `\u` escapes of unpaired
//! surrogates (Python keeps them; UTF-8 cannot), raw control characters,
//! integers longer than Python's minimum digit limit, duplicate object keys
//! (Python keeps the first position and the last value), and nesting deeper
//! than `MAX_DEPTH`.

use std::borrow::Cow;

pub const MAX_DEPTH: usize = 128;
/// `sys.set_int_max_str_digits` cannot go below 640, so shorter integers
/// always decode and convert with `str()`.
const MAX_INT_DIGITS: usize = 640;

#[derive(Debug, PartialEq)]
pub enum Value<'a> {
    Null,
    Bool(bool),
    /// Canonical JSON integer text, sign included.
    Int(&'a [u8]),
    Str(Cow<'a, [u8]>),
    Array(Vec<Value<'a>>),
    Object(Vec<(Cow<'a, [u8]>, Value<'a>)>),
}

pub fn parse(text: &[u8]) -> Option<Value<'_>> {
    let mut parser = Parser { text, pos: 0 };
    parser.ws();
    let value = parser.value(0)?;
    parser.ws();
    (parser.pos == text.len()).then_some(value)
}

struct Parser<'a> {
    text: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while matches!(self.text.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.pos).copied()
    }

    fn value(&mut self, depth: usize) -> Option<Value<'a>> {
        match self.peek()? {
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'"' => self.string().map(Value::Str),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'-' | b'0'..=b'9' => self.int(),
            _ => None,
        }
    }

    fn literal(&mut self, word: &[u8], value: Value<'a>) -> Option<Value<'a>> {
        self.text[self.pos..].starts_with(word).then(|| {
            self.pos += word.len();
            value
        })
    }

    fn int(&mut self) -> Option<Value<'a>> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits = self.pos;
        match self.peek()? {
            b'0' => self.pos += 1,
            b'1'..=b'9' => {
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return None,
        }
        if self.pos - digits > MAX_INT_DIGITS || matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return None;
        }
        Some(Value::Int(&self.text[start..self.pos]))
    }

    fn string(&mut self) -> Option<Cow<'a, [u8]>> {
        self.pos += 1;
        let mut run = self.pos;
        let mut owned: Option<Vec<u8>> = None;
        loop {
            match self.peek()? {
                b'"' => {
                    let tail = &self.text[run..self.pos];
                    self.pos += 1;
                    return Some(match owned {
                        None => Cow::Borrowed(tail),
                        Some(mut decoded) => {
                            decoded.extend_from_slice(tail);
                            Cow::Owned(decoded)
                        }
                    });
                }
                b'\\' => {
                    let decoded = owned.get_or_insert_with(Vec::new);
                    decoded.extend_from_slice(&self.text[run..self.pos]);
                    let simple = match self.text.get(self.pos + 1)? {
                        b'"' => b'"',
                        b'\\' => b'\\',
                        b'/' => b'/',
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'u' => {
                            let (character, length) = self.unicode_escape()?;
                            let mut utf8 = [0; 4];
                            decoded.extend_from_slice(character.encode_utf8(&mut utf8).as_bytes());
                            self.pos += length;
                            run = self.pos;
                            continue;
                        }
                        _ => return None,
                    };
                    decoded.push(simple);
                    self.pos += 2;
                    run = self.pos;
                }
                // Python's strict decoder rejects raw control characters.
                0..=0x1f => return None,
                _ => self.pos += 1,
            }
        }
    }

    fn hex4(&self, at: usize) -> Option<u32> {
        let digits = self.text.get(at..at + 4)?;
        digits.iter().try_fold(0, |value, &digit| {
            Some(value * 16 + char::from(digit).to_digit(16)?)
        })
    }

    /// `\uXXXX` (or a surrogate pair) at `self.pos`: the character and the
    /// escape length. Unpaired surrogates stay with Python.
    fn unicode_escape(&self) -> Option<(char, usize)> {
        let unit = self.hex4(self.pos + 2)?;
        match unit {
            0xd800..=0xdbff => {
                if self.text.get(self.pos + 6..self.pos + 8)? != b"\\u" {
                    return None;
                }
                let low = self.hex4(self.pos + 8)?;
                if !(0xdc00..=0xdfff).contains(&low) {
                    return None;
                }
                Some((
                    char::from_u32(0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00))?,
                    12,
                ))
            }
            0xdc00..=0xdfff => None,
            _ => Some((char::from_u32(unit)?, 6)),
        }
    }

    fn array(&mut self, depth: usize) -> Option<Value<'a>> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.pos += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Some(Value::Array(items));
        }
        loop {
            items.push(self.value(depth)?);
            self.ws();
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                    self.ws();
                }
                b']' => {
                    self.pos += 1;
                    return Some(Value::Array(items));
                }
                _ => return None,
            }
        }
    }

    fn object(&mut self, depth: usize) -> Option<Value<'a>> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.pos += 1;
        let mut members: Vec<(Cow<'a, [u8]>, Value<'a>)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Some(Value::Object(members));
        }
        loop {
            if self.peek()? != b'"' {
                return None;
            }
            let key = self.string()?;
            self.ws();
            if self.peek()? != b':' {
                return None;
            }
            self.pos += 1;
            self.ws();
            let value = self.value(depth)?;
            members.push((key, value));
            self.ws();
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                    self.ws();
                }
                b'}' => {
                    self.pos += 1;
                    break;
                }
                _ => return None,
            }
        }
        if has_duplicate_keys(&members) {
            return None;
        }
        Some(Value::Object(members))
    }
}

fn has_duplicate_keys(members: &[(Cow<'_, [u8]>, Value<'_>)]) -> bool {
    if members.len() <= 16 {
        return members
            .iter()
            .enumerate()
            .any(|(i, (key, _))| members[..i].iter().any(|(other, _)| other == key));
    }
    let mut keys: Vec<&[u8]> = members.iter().map(|(key, _)| key.as_ref()).collect();
    keys.sort_unstable();
    keys.windows(2).any(|pair| pair[0] == pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_exact_subset() {
        let value = parse(br#" {"a\/b": [1, -0, true, null, {"x": "q\"\\\b\f\n\r\t"}], "": {}} "#);
        let Some(Value::Object(members)) = value else {
            panic!("object expected");
        };
        assert_eq!(members[0].0.as_ref(), b"a/b");
        let Value::Array(items) = &members[0].1 else {
            panic!("array expected");
        };
        assert_eq!(items[0], Value::Int(b"1"));
        assert_eq!(items[1], Value::Int(b"-0"));
        let Value::Object(inner) = &items[4] else {
            panic!("object expected");
        };
        assert_eq!(
            inner[0].1,
            Value::Str(Cow::Borrowed(b"q\"\\\x08\x0c\n\r\t"))
        );
    }

    #[test]
    fn decodes_utf8_and_unicode_escapes_like_python() {
        let text = "\"\u{e9}\\u00e9\\u0041\\uD83D\\uDE00\\u0000\u{1f600}\"";
        assert_eq!(
            parse(text.as_bytes()),
            Some(Value::Str(Cow::Owned(
                "\u{e9}\u{e9}A\u{1f600}\0\u{1f600}".into()
            )))
        );
    }

    #[test]
    fn leaves_everything_else_to_python() {
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        let long_int = "9".repeat(MAX_INT_DIGITS + 1);
        let cases: [&[u8]; 26] = [
            b"",
            b"{",
            b"{\"a\":1,}",
            b"[1,]",
            b"{\"a\" 1}",
            b"{\"a\":1}x",
            b"{\"a\":1.0}",
            b"{\"a\":1e3}",
            b"{\"a\":NaN}",
            b"{\"a\":-Infinity}",
            b"{\"a\":01}",
            b"{\"a\":-}",
            b"{\"a\":\"\\ud800\"}",
            b"{\"a\":\"\\udc00\\ud800\"}",
            b"{\"a\":\"\\ud800\\u0041\"}",
            b"{\"a\":\"\\ud800x\"}",
            b"{\"a\":\"\\u00g1\"}",
            b"{\"a\":\"\\u00e\"}",
            b"{\"a\":\"\\x\"}",
            b"{\"a\":\"\t\"}",
            "\u{a0}{}".as_bytes(),
            b"{\"a\":1,\"a\":2}",
            b"{\"a\":tru}",
            b"\x0c{}",
            deep.as_bytes(),
            long_int.as_bytes(),
        ];
        for case in cases {
            assert_eq!(parse(case), None, "{}", String::from_utf8_lossy(case));
        }
        let mut many: Vec<String> = (0..40).map(|i| format!("\"k{i}\":{i}")).collect();
        assert!(parse(format!("{{{}}}", many.join(",")).as_bytes()).is_some());
        many.push("\"k3\":0".into());
        assert_eq!(parse(format!("{{{}}}", many.join(",")).as_bytes()), None);
        let deepest = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(deepest.as_bytes()).is_some());
    }
}
