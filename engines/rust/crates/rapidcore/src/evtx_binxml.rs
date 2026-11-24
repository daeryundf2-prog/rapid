// Chunk BinXML decoder for EVTX records — a line-for-line port of the Python
// `EvtxChunkDecoder` / `extract_evtx_event_fields` / `render_evtx_element_xml`
// in rapidtriage/artifacts/windows/eventlog.py (decoder version
// "evtx-chunk-binxml-decoder-v2").
//
// The Python decoder is the reference: every decoded value text, dict order,
// template/name cache effect, token budget and error message must match it so
// the rows built from either decoder are identical. Inputs where Rust cannot
// reproduce Python byte-for-byte (lone-surrogate character references,
// non-ASCII ANSI strings that Python decodes as cp949, element trees deep
// enough to approach Python's recursion limit) return `Unsupported`; the
// Python bridge then decodes that chunk with the Python decoder.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::hash::{BuildHasherDefault, Hasher};
use std::rc::Rc;

pub const DECODER_VERSION: &str = "evtx-chunk-binxml-decoder-v2";
const RECORD_HEADER_SIZE: i64 = 24;
const MAX_DEPTH: u32 = 12;
const MAX_TOKENS: u32 = 200_000;
const MAX_SUBSTITUTIONS: u32 = 4096;
/// Element nesting above this is handed to the Python decoder (whose own
/// recursion limit decides the outcome there).
const MAX_NESTING: u32 = 200;
const XML_PREVIEW_LIMIT: usize = 4000;

#[derive(Debug, Clone, PartialEq)]
pub enum DecodeError {
    /// Python `EvtxDecodeError(message)`.
    Decode(String),
    /// Python `IndexError(message)` (bytes index past the chunk end).
    Index(String),
    /// Not reproducible in Rust; decode with the Python decoder instead.
    Unsupported(&'static str),
}

type Res<T> = Result<T, DecodeError>;

fn decode_err<T>(message: String) -> Res<T> {
    Err(DecodeError::Decode(message))
}

/// Python-side `EvtxValue.raw` (only the shape that reaches rows matters:
/// `TimeCreated` is used as FILETIME when it is an int).
#[derive(Debug, Clone)]
pub enum Raw {
    None,
    Int(i64),
    UInt(u64),
    Float(f64),
    Bool(bool),
    Str(String),
    /// The raw value is the value text itself (strings, GUID/SID/SYSTEMTIME text).
    Text,
    List(Vec<String>),
    Nested(Rc<Vec<Item>>),
}

#[derive(Debug)]
pub struct Value {
    pub text: String,
    pub raw: Raw,
    pub value_type: u8,
}

type ValueRef = Rc<Value>;

fn value(text: String, raw: Raw, value_type: u8) -> ValueRef {
    Rc::new(Value {
        text,
        raw,
        value_type,
    })
}

#[derive(Debug, Clone)]
pub enum Item {
    Elem(Rc<Element>),
    Val(ValueRef),
}

#[derive(Debug)]
pub struct Element {
    pub name: Rc<str>,
    pub attrs: Vec<(Rc<str>, ValueRef)>,
    pub children: Vec<Item>,
}

impl Element {
    fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find_map(|item| match item {
            Item::Elem(element) if &*element.name == name => Some(&**element),
            _ => None,
        })
    }

    fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|item| match item {
            Item::Elem(element) => Some(&**element),
            Item::Val(_) => None,
        })
    }

    fn attr(&self, name: &str) -> Option<&ValueRef> {
        self.attrs
            .iter()
            .find(|(key, _)| &**key == name)
            .map(|(_, value)| value)
    }

    fn text_value(&self) -> ValueRef {
        let values: Vec<&ValueRef> = self
            .children
            .iter()
            .filter_map(|item| match item {
                Item::Val(value) => Some(value),
                Item::Elem(_) => None,
            })
            .collect();
        if values.len() == 1 {
            return Rc::clone(values[0]);
        }
        let text: String = values.iter().map(|item| item.text.as_str()).collect();
        value(text, Raw::None, if values.is_empty() { 0x00 } else { 0x01 })
    }
}

#[derive(Debug)]
enum TemplateNode {
    Elem(TemplateElement),
    Val(ValueRef),
    /// Substitution index (its declared value type is not used for rendering).
    Sub(u16),
    Instance(Rc<Vec<Item>>, i64, u32),
}

#[derive(Debug)]
struct TemplateElement {
    name: Rc<str>,
    attrs: Vec<(Rc<str>, Vec<TemplateNode>)>,
    children: Vec<TemplateNode>,
}

impl TemplateElement {
    fn new(name: Rc<str>) -> Self {
        Self {
            name,
            attrs: Vec::new(),
            children: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SequenceItem {
    pub name: String,
    pub value: String,
    pub path: String,
    pub section: &'static str,
    pub value_type: Cow<'static, str>,
}

/// `decode_record` output (Python `decoded` dict without `root`). The
/// `event_data` dict is `event_data_sequence` as name -> value (names are
/// unique), so it is not stored twice.
#[derive(Debug)]
pub struct DecodedRecord {
    pub system_fields: Vec<(&'static str, String)>,
    pub system_raw: Vec<(&'static str, Raw)>,
    pub event_data_sequence: Vec<SequenceItem>,
    pub event_data_source: &'static str,
    pub root_name: String,
    pub template_offsets: Vec<i64>,
    pub substitution_count: u64,
    pub rendered_xml: Option<String>,
}

/// Chunk offsets are already well spread; SipHash is wasted on them.
#[derive(Default)]
struct OffsetHasher(u64);

impl Hasher for OffsetHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0.rotate_left(5) ^ u64::from(*byte)).wrapping_mul(0x517C_C1B7_2722_0A95);
        }
    }

    fn write_i64(&mut self, value: i64) {
        self.0 = (value as u64).wrapping_mul(0x517C_C1B7_2722_0A95);
    }
}

type OffsetMap<V> = HashMap<i64, V, BuildHasherDefault<OffsetHasher>>;

pub struct ChunkDecoder {
    chunk: Vec<u8>,
    names: OffsetMap<(Rc<str>, i64)>,
    templates: OffsetMap<(Rc<Vec<TemplateNode>>, i64)>,
    pub template_parse_count: u64,
    tokens: u32,
    nesting: u32,
}

const FIXED_VALUE_SIZES: [(u8, i64); 16] = [
    (0x03, 1),
    (0x04, 1),
    (0x05, 2),
    (0x06, 2),
    (0x07, 4),
    (0x08, 4),
    (0x09, 8),
    (0x0A, 8),
    (0x0B, 4),
    (0x0C, 8),
    (0x0D, 4),
    (0x0F, 16),
    (0x11, 8),
    (0x12, 16),
    (0x14, 4),
    (0x15, 8),
];

fn fixed_size(value_type: u8) -> Option<i64> {
    FIXED_VALUE_SIZES
        .iter()
        .find(|(kind, _)| *kind == value_type)
        .map(|(_, size)| *size)
}

fn is_int_type(value_type: u8) -> bool {
    (0x03..=0x0A).contains(&value_type)
}

fn le_uint(data: &[u8]) -> u64 {
    data.iter()
        .take(8)
        .rev()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte))
}

fn int_value(data: &[u8], value_type: u8) -> Raw {
    match value_type {
        0x03 => Raw::Int(i64::from(data[0] as i8)),
        0x04 => Raw::Int(i64::from(data[0])),
        0x05 => Raw::Int(i64::from(i16::from_le_bytes([data[0], data[1]]))),
        0x06 => Raw::Int(i64::from(u16::from_le_bytes([data[0], data[1]]))),
        0x07 => Raw::Int(i64::from(i32::from_le_bytes([
            data[0], data[1], data[2], data[3],
        ]))),
        0x08 => Raw::Int(i64::from(u32::from_le_bytes([
            data[0], data[1], data[2], data[3],
        ]))),
        0x09 => Raw::Int(i64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]))),
        _ => Raw::UInt(le_uint(&data[..8])),
    }
}

fn raw_int_text(raw: &Raw) -> String {
    match raw {
        Raw::Int(number) => number.to_string(),
        Raw::UInt(number) => number.to_string(),
        _ => String::new(),
    }
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn push_hex(out: &mut String, data: &[u8], digits: &[u8; 16]) {
    for byte in data {
        out.push(char::from(digits[usize::from(byte >> 4)]));
        out.push(char::from(digits[usize::from(byte & 0x0F)]));
    }
}

fn hex_lower(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    push_hex(&mut out, data, HEX_LOWER);
    out
}

fn hex_upper(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    push_hex(&mut out, data, HEX_UPPER);
    out
}

/// Python `bytes.decode("utf-16le", errors="replace")` (even-length input).
fn utf16_lossy(data: &[u8]) -> String {
    if data
        .chunks_exact(2)
        .all(|pair| pair[1] == 0 && pair[0] < 0x80)
    {
        return data
            .iter()
            .step_by(2)
            .map(|byte| char::from(*byte))
            .collect();
    }
    let mut out = String::with_capacity(data.len() / 2 * 3);
    let units = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    for item in char::decode_utf16(units) {
        out.push(item.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    out
}

/// `_evtx_utf16_text`: drop an odd trailing byte, decode, strip trailing NULs.
fn utf16_text(data: &[u8]) -> String {
    let even = &data[..data.len() - data.len() % 2];
    let mut text = utf16_lossy(even);
    let trimmed = text.trim_end_matches('\0').len();
    text.truncate(trimmed);
    text
}

/// `_evtx_ansi_text` for ASCII input; Python decodes other bytes as cp949.
fn ansi_text(data: &[u8]) -> Res<String> {
    let end = data
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |i| i + 1);
    let stripped = &data[..end];
    if !stripped.is_ascii() {
        return Err(DecodeError::Unsupported("non-ascii-ansi-string"));
    }
    Ok(stripped.iter().map(|byte| char::from(*byte)).collect())
}

fn guid_text(data: &[u8]) -> String {
    let mut out = String::with_capacity(38);
    out.push('{');
    push_hex(&mut out, &[data[3], data[2], data[1], data[0]], HEX_UPPER);
    out.push('-');
    push_hex(&mut out, &[data[5], data[4]], HEX_UPPER);
    out.push('-');
    push_hex(&mut out, &[data[7], data[6]], HEX_UPPER);
    out.push('-');
    push_hex(&mut out, &data[8..10], HEX_UPPER);
    out.push('-');
    push_hex(&mut out, &data[10..16], HEX_UPPER);
    out.push('}');
    out
}

/// Python `sid_to_string`.
pub fn sid_to_string(data: &[u8]) -> String {
    if data.len() < 8 {
        return hex_lower(data);
    }
    let count = usize::from(data[1]);
    if data.len() < 8 + count * 4 {
        return hex_lower(data);
    }
    let authority = data[2..8]
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    let mut out = format!("S-{}-{authority}", data[0]);
    for index in 0..count {
        let start = 8 + index * 4;
        let sub = u32::from_le_bytes([
            data[start],
            data[start + 1],
            data[start + 2],
            data[start + 3],
        ]);
        let _ = write!(out, "-{sub}");
    }
    out
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Python `filetime_to_iso_100ns`: 7-digit fraction, "" past year 9999.
pub fn filetime_to_iso_100ns(value: u64) -> String {
    if value == 0 {
        return String::new();
    }
    let seconds = (value / 10_000_000) as i64;
    let remainder = value % 10_000_000;
    let days = seconds / 86_400;
    let in_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days_from_civil(1601, 1, 1) + days);
    if year > 9999 {
        return String::new();
    }
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{remainder:07}Z",
        in_day / 3600,
        in_day % 3600 / 60,
        in_day % 60
    )
}

fn is_leap(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Python `_evtx_systemtime_text` (16 bytes): invalid dates render as hex.
fn systemtime_text(data: &[u8]) -> String {
    let field = |index: usize| u16::from_le_bytes([data[index * 2], data[index * 2 + 1]]);
    let (year, month, day) = (field(0), field(1), field(3));
    let (hour, minute, second, millisecond) = (field(4), field(5), field(6), field(7));
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    };
    let valid = (1..=9999).contains(&year)
        && (1..=month_days).contains(&day)
        && hour < 24
        && minute < 60
        && second < 60;
    if !valid {
        return hex_lower(&data[..16]);
    }
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millisecond:03}Z")
}

/// Python `repr(float)` (shortest round-trip, exponent outside 1e-4..1e16).
pub fn python_float_repr(number: f64) -> String {
    if number.is_nan() {
        return "nan".to_string();
    }
    if number.is_infinite() {
        return if number > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    let sign = if number.is_sign_negative() { "-" } else { "" };
    if number == 0.0 {
        return format!("{sign}0.0");
    }
    let scientific = format!("{:e}", number.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let decpt = exponent.parse::<i32>().unwrap_or(0) + 1;
    if decpt <= -4 || decpt > 16 {
        let exp = decpt - 1;
        let (head, tail) = digits.split_at(1);
        let fraction = if tail.is_empty() {
            String::new()
        } else {
            format!(".{tail}")
        };
        let exp_sign = if exp < 0 { '-' } else { '+' };
        return format!("{sign}{head}{fraction}e{exp_sign}{:02}", exp.abs());
    }
    let length = digits.len() as i32;
    if decpt <= 0 {
        format!("{sign}0.{}{digits}", "0".repeat((-decpt) as usize))
    } else if decpt < length {
        let (left, right) = digits.split_at(decpt as usize);
        format!("{sign}{left}.{right}")
    } else {
        format!("{sign}{digits}{}.0", "0".repeat((decpt - length) as usize))
    }
}

/// Python `_evtx_real_text`.
fn real_text(number: f64) -> String {
    let text = python_float_repr(number);
    match text.strip_suffix(".0") {
        Some(stripped) => stripped.to_string(),
        None => text,
    }
}

fn scalar_from_bytes(data: &[u8], item_type: u8) -> String {
    match item_type {
        kind if is_int_type(kind) => raw_int_text(&int_value(data, kind)),
        0x0B => real_text(f64::from(f32::from_le_bytes([
            data[0], data[1], data[2], data[3],
        ]))),
        0x0C => real_text(f64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]))),
        0x0D => if data.iter().any(|byte| *byte != 0) {
            "true"
        } else {
            "false"
        }
        .to_string(),
        0x0F => guid_text(data),
        0x11 => filetime_to_iso_100ns(le_uint(data)),
        0x12 => systemtime_text(data),
        0x10 | 0x14 | 0x15 => format!("0x{:x}", le_uint(data)),
        _ => hex_upper(data),
    }
}

fn array_value(data: &[u8], item_type: u8) -> Res<ValueRef> {
    let array_type = 0x80 | item_type;
    let items: Vec<String> = match item_type {
        0x01 => {
            if data.is_empty() {
                Vec::new()
            } else {
                let mut parts: Vec<String> =
                    utf16_text(data).split('\0').map(str::to_string).collect();
                if parts.last().is_some_and(String::is_empty) {
                    parts.pop();
                }
                parts
            }
        }
        0x02 => {
            if data.is_empty() {
                Vec::new()
            } else {
                let end = data
                    .iter()
                    .rposition(|byte| *byte != 0)
                    .map_or(0, |i| i + 1);
                data[..end]
                    .split(|byte| *byte == 0)
                    .map(ansi_text)
                    .collect::<Res<Vec<_>>>()?
            }
        }
        0x13 => {
            let mut items = Vec::new();
            let mut cursor = 0usize;
            while cursor + 8 <= data.len() {
                let length = 8 + usize::from(data[cursor + 1]) * 4;
                items.push(sid_to_string(
                    &data[cursor..(cursor + length).min(data.len())],
                ));
                cursor += length;
            }
            let text = items.join(", ");
            return Ok(value(text, Raw::List(items), array_type));
        }
        _ => {
            let width = if item_type == 0x10 {
                if data.len().is_multiple_of(8) {
                    8
                } else {
                    4
                }
            } else {
                fixed_size(item_type).unwrap_or(0) as usize
            };
            if width == 0 {
                return Ok(value(
                    hex_upper(data),
                    Raw::Str(hex_lower(data)),
                    array_type,
                ));
            }
            data.chunks_exact(width)
                .map(|item| scalar_from_bytes(item, item_type))
                .collect()
        }
    };
    let text = items.join(", ");
    Ok(value(text, Raw::List(items), array_type))
}

/// `EvtxChunkDecoder.value` for every type except nested BinXml (0x21).
fn value_from_bytes(data: &[u8], value_type: u8, offset: i64) -> Res<ValueRef> {
    let len = data.len();
    Ok(match value_type {
        0x00 => value(String::new(), Raw::None, 0x00),
        0x01 => value(utf16_text(data), Raw::Text, 0x01),
        0x02 => value(ansi_text(data)?, Raw::Text, 0x02),
        kind if is_int_type(kind) => {
            let width = fixed_size(kind).unwrap_or(0) as usize;
            if len < width {
                return decode_err(format!("short integer value @{offset}"));
            }
            let raw = int_value(data, kind);
            value(raw_int_text(&raw), raw, kind)
        }
        0x0B if len >= 4 => {
            let number = f64::from(f32::from_le_bytes([data[0], data[1], data[2], data[3]]));
            value(real_text(number), Raw::Float(number), value_type)
        }
        0x0C if len >= 8 => {
            let number = f64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]));
            value(real_text(number), Raw::Float(number), value_type)
        }
        0x0D if len > 0 => {
            let flag = data.iter().take(4).any(|byte| *byte != 0);
            value(
                if flag { "true" } else { "false" }.to_string(),
                Raw::Bool(flag),
                value_type,
            )
        }
        0x0F if len >= 16 => value(guid_text(&data[..16]), Raw::Text, value_type),
        0x10 => {
            let number = le_uint(data);
            value(format!("0x{number:x}"), Raw::UInt(number), value_type)
        }
        0x11 if len >= 8 => {
            let filetime = le_uint(data);
            value(
                filetime_to_iso_100ns(filetime),
                Raw::UInt(filetime),
                value_type,
            )
        }
        0x12 if len >= 16 => value(systemtime_text(&data[..16]), Raw::Text, value_type),
        0x13 => value(sid_to_string(data), Raw::Text, value_type),
        0x14 if len >= 4 => {
            let number = le_uint(&data[..4]);
            value(format!("0x{number:x}"), Raw::UInt(number), value_type)
        }
        0x15 if len >= 8 => {
            let number = le_uint(data);
            value(format!("0x{number:x}"), Raw::UInt(number), value_type)
        }
        kind if kind & 0x80 != 0 => return array_value(data, kind & 0x7F),
        _ => value(hex_upper(data), Raw::Str(hex_lower(data)), value_type),
    })
}

/// Python `binxml_value_type_name`.
pub fn value_type_name(value_type: u8) -> Cow<'static, str> {
    fn base(kind: u8) -> Option<&'static str> {
        Some(match kind {
            0x00 => "NullType",
            0x01 => "StringType",
            0x02 => "AnsiStringType",
            0x03 => "Int8Type",
            0x04 => "UInt8Type",
            0x05 => "Int16Type",
            0x06 => "UInt16Type",
            0x07 => "Int32Type",
            0x08 => "UInt32Type",
            0x09 => "Int64Type",
            0x0A => "UInt64Type",
            0x0B => "Real32Type",
            0x0C => "Real64Type",
            0x0D => "BoolType",
            0x0E => "BinaryType",
            0x0F => "GuidType",
            0x10 => "SizeTType",
            0x11 => "FileTimeType",
            0x12 => "SysTimeType",
            0x13 => "SidType",
            0x14 => "HexInt32Type",
            0x15 => "HexInt64Type",
            0x21 => "BinXmlType",
            _ => return None,
        })
    }
    if let Some(name) = base(value_type) {
        return Cow::Borrowed(name);
    }
    if value_type & 0x80 != 0 {
        if let Some(name) = base(value_type & 0x7F) {
            return Cow::Owned(format!("{name}Array"));
        }
    }
    Cow::Owned(format!("UnknownType0x{value_type:02x}"))
}

fn entity_text(name: &str) -> String {
    match name {
        "amp" => "&".to_string(),
        "lt" => "<".to_string(),
        "gt" => ">".to_string(),
        "quot" => "\"".to_string(),
        "apos" => "'".to_string(),
        _ => format!("&{name};"),
    }
}

fn push_node(stack: &mut [TemplateElement], in_attr: bool, node: TemplateNode) {
    let top = stack.last_mut().expect("parse stack keeps its root");
    match top.attrs.last_mut() {
        Some((_, parts)) if in_attr => parts.push(node),
        _ => top.children.push(node),
    }
}

fn close_top(stack: &mut Vec<TemplateElement>) {
    if stack.len() > 1 {
        let element = stack.pop().expect("checked length");
        if let Some(parent) = stack.last_mut() {
            parent.children.push(TemplateNode::Elem(element));
        }
    }
}

impl ChunkDecoder {
    pub fn new(chunk: Vec<u8>) -> Self {
        Self {
            chunk,
            names: OffsetMap::default(),
            templates: OffsetMap::default(),
            template_parse_count: 0,
            tokens: 0,
            nesting: 0,
        }
    }

    fn len(&self) -> i64 {
        self.chunk.len() as i64
    }

    fn u16_at(&self, offset: i64) -> Res<i64> {
        if offset < 0 || offset + 2 > self.len() {
            return decode_err(format!("u16 out of bounds @{offset}"));
        }
        let index = offset as usize;
        Ok(i64::from(u16::from_le_bytes([
            self.chunk[index],
            self.chunk[index + 1],
        ])))
    }

    fn u32_at(&self, offset: i64) -> Res<i64> {
        if offset < 0 || offset + 4 > self.len() {
            return decode_err(format!("u32 out of bounds @{offset}"));
        }
        let index = offset as usize;
        Ok(i64::from(u32::from_le_bytes([
            self.chunk[index],
            self.chunk[index + 1],
            self.chunk[index + 2],
            self.chunk[index + 3],
        ])))
    }

    fn byte_at(&self, offset: i64) -> Res<u8> {
        if offset < 0 || offset >= self.len() {
            return Err(DecodeError::Index("index out of range".to_string()));
        }
        Ok(self.chunk[offset as usize])
    }

    fn name(&mut self, offset: i64) -> Res<(Rc<str>, i64)> {
        if let Some((name, length)) = self.names.get(&offset) {
            return Ok((Rc::clone(name), *length));
        }
        let count = self.u16_at(offset + 6)?;
        let start = offset + 8;
        let end = start + count * 2;
        if end + 2 > self.len() {
            return decode_err(format!("name out of bounds @{offset}"));
        }
        let name: Rc<str> = Rc::from(utf16_lossy(&self.chunk[start as usize..end as usize]));
        let length = 8 + count * 2 + 2;
        self.names.insert(offset, (Rc::clone(&name), length));
        Ok((name, length))
    }

    fn value(&mut self, offset: i64, size: i64, value_type: u8, depth: u32) -> Res<ValueRef> {
        let end = offset + size;
        if size < 0 || end > self.len() {
            return decode_err(format!("value out of bounds @{offset}+{size}"));
        }
        if value_type != 0x21 {
            return value_from_bytes(
                &self.chunk[offset as usize..end as usize],
                value_type,
                offset,
            );
        }
        if depth >= MAX_DEPTH {
            return decode_err("nested BinXml too deep".to_string());
        }
        let nested = match self.parse(offset, end, depth + 1, true) {
            Ok((nodes, _)) => self.instantiate(&nodes, &[], depth + 1),
            Err(error) => Err(error),
        };
        match nested {
            Ok(items) => Ok(value(
                String::new(),
                Raw::Nested(Rc::new(items)),
                value_type,
            )),
            Err(DecodeError::Decode(_)) => Ok(value(
                hex_upper(&self.chunk[offset as usize..end as usize]),
                Raw::None,
                value_type,
            )),
            Err(other) => Err(other),
        }
    }

    fn parse(
        &mut self,
        mut pos: i64,
        end: i64,
        depth: u32,
        stop_after_instance: bool,
    ) -> Res<(Vec<TemplateNode>, i64)> {
        let end = end.min(self.len());
        let mut stack = vec![TemplateElement::new(Rc::from(""))];
        let mut in_attr = false;
        while pos < end {
            self.tokens += 1;
            if self.tokens > MAX_TOKENS {
                return decode_err("token budget exhausted".to_string());
            }
            let token = self.chunk[pos as usize];
            match token & 0x0F {
                0x00 => {
                    pos += 1;
                    break;
                }
                0x0F => pos += 4,
                0x01 => {
                    let name_offset = self.u32_at(pos + 7)?;
                    let mut after = pos + 11;
                    let (name, name_length) = self.name(name_offset)?;
                    if name_offset == after {
                        after += name_length;
                    }
                    if token & 0x40 != 0 {
                        after += 4;
                    }
                    stack.push(TemplateElement::new(name));
                    in_attr = false;
                    pos = after;
                }
                0x06 => {
                    let name_offset = self.u32_at(pos + 1)?;
                    let mut after = pos + 5;
                    let (name, name_length) = self.name(name_offset)?;
                    if name_offset == after {
                        after += name_length;
                    }
                    if let Some(top) = stack.last_mut() {
                        top.attrs.push((name, Vec::new()));
                    }
                    in_attr = true;
                    pos = after;
                }
                0x02 => {
                    in_attr = false;
                    pos += 1;
                }
                0x03 | 0x04 => {
                    in_attr = false;
                    close_top(&mut stack);
                    pos += 1;
                }
                0x05 => {
                    let value_type = if pos + 1 < end {
                        self.chunk[(pos + 1) as usize]
                    } else {
                        0
                    };
                    let (value_offset, size, next) = if value_type == 0x01 {
                        let count = self.u16_at(pos + 2)?;
                        (pos + 4, count * 2, pos + 4 + count * 2)
                    } else if let Some(size) = fixed_size(value_type) {
                        (pos + 2, size, pos + 2 + size)
                    } else if value_type == 0x13 {
                        let subs = if pos + 3 < end {
                            i64::from(self.chunk[(pos + 3) as usize]) * 4
                        } else {
                            0
                        };
                        (pos + 2, 8 + subs, pos + 2 + 8 + subs)
                    } else {
                        let count = self.u16_at(pos + 2)?;
                        (pos + 4, count, pos + 4 + count)
                    };
                    let item = self.value(value_offset, size, value_type, depth)?;
                    push_node(&mut stack, in_attr, TemplateNode::Val(item));
                    pos = next;
                }
                0x07 => {
                    let count = self.u16_at(pos + 1)?;
                    let item = self.value(pos + 3, count * 2, 0x01, depth)?;
                    push_node(&mut stack, in_attr, TemplateNode::Val(item));
                    pos += 3 + count * 2;
                }
                0x08 => {
                    let code_point = self.u16_at(pos + 1)?;
                    let character = char::from_u32(code_point as u32)
                        .ok_or(DecodeError::Unsupported("surrogate-character-reference"))?;
                    let item = value(character.to_string(), Raw::Int(code_point), 0x01);
                    push_node(&mut stack, in_attr, TemplateNode::Val(item));
                    pos += 3;
                }
                0x09 => {
                    let name_offset = self.u32_at(pos + 1)?;
                    let mut after = pos + 5;
                    let (name, name_length) = self.name(name_offset)?;
                    if name_offset == after {
                        after += name_length;
                    }
                    let item = value(entity_text(&name), Raw::Str(name.to_string()), 0x01);
                    push_node(&mut stack, in_attr, TemplateNode::Val(item));
                    pos = after;
                }
                0x0A => {
                    let name_offset = self.u32_at(pos + 1)?;
                    let mut after = pos + 5;
                    let (_, name_length) = self.name(name_offset)?;
                    if name_offset == after {
                        after += name_length;
                    }
                    pos = after;
                }
                0x0B => {
                    let count = self.u16_at(pos + 1)?;
                    pos += 3 + count * 2;
                }
                0x0C => {
                    let (instance, next) = self.template_instance(pos, depth)?;
                    push_node(&mut stack, in_attr, instance);
                    pos = next;
                    if stop_after_instance && stack.len() == 1 {
                        break;
                    }
                }
                // 0x0D normal / 0x0E optional substitution (every nibble is handled).
                kind => {
                    if pos + 4 > end {
                        return decode_err(format!("truncated substitution @{pos}"));
                    }
                    let index = self.u16_at(pos + 1)? as u16;
                    debug_assert!(kind == 0x0D || kind == 0x0E);
                    push_node(&mut stack, in_attr, TemplateNode::Sub(index));
                    pos += 4;
                }
            }
        }
        while stack.len() > 1 {
            close_top(&mut stack);
        }
        let root = stack.pop().expect("parse stack keeps its root");
        Ok((root.children, pos))
    }

    fn template(&mut self, template_offset: i64, depth: u32) -> Res<(Rc<Vec<TemplateNode>>, i64)> {
        if let Some((nodes, length)) = self.templates.get(&template_offset) {
            return Ok((Rc::clone(nodes), *length));
        }
        let data_length = self.u32_at(template_offset + 20)?;
        let body = template_offset + 24;
        if data_length <= 0 || body + data_length > self.len() {
            return decode_err(format!("template out of bounds @{template_offset}"));
        }
        let (nodes, _) = self.parse(body, body + data_length, depth, false)?;
        let nodes = Rc::new(nodes);
        self.templates
            .insert(template_offset, (Rc::clone(&nodes), data_length));
        self.template_parse_count += 1;
        Ok((nodes, data_length))
    }

    fn template_instance(&mut self, pos: i64, depth: u32) -> Res<(TemplateNode, i64)> {
        let template_offset = self.u32_at(pos + 6)?;
        let mut cursor = pos + 10;
        let (nodes, data_length) = self.template(template_offset, depth)?;
        if template_offset == cursor {
            cursor = template_offset + 24 + data_length;
        }
        let count = self.u32_at(cursor)?;
        if count > i64::from(MAX_SUBSTITUTIONS) {
            return decode_err(format!("substitution count {count} @{cursor}"));
        }
        cursor += 4;
        let mut descriptors = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let size = self.u16_at(cursor)?;
            let value_type = self.byte_at(cursor + 2)?;
            descriptors.push((size, value_type));
            cursor += 4;
        }
        let mut values = Vec::with_capacity(descriptors.len());
        for (size, value_type) in descriptors {
            values.push(self.value(cursor, size, value_type, depth)?);
            cursor += size;
        }
        let items = self.instantiate(&nodes, &values, depth)?;
        Ok((
            TemplateNode::Instance(Rc::new(items), template_offset, count as u32),
            cursor,
        ))
    }

    fn instantiate(
        &mut self,
        nodes: &[TemplateNode],
        values: &[ValueRef],
        depth: u32,
    ) -> Res<Vec<Item>> {
        self.nesting += 1;
        let result = if self.nesting > MAX_NESTING {
            Err(DecodeError::Unsupported("element-nesting-too-deep"))
        } else {
            self.instantiate_nodes(nodes, values, depth)
        };
        self.nesting -= 1;
        result
    }

    fn instantiate_nodes(
        &mut self,
        nodes: &[TemplateNode],
        values: &[ValueRef],
        depth: u32,
    ) -> Res<Vec<Item>> {
        let mut output = Vec::with_capacity(nodes.len());
        for node in nodes {
            if let TemplateNode::Elem(template) = node {
                let mut attrs = Vec::with_capacity(template.attrs.len());
                for (name, parts) in &template.attrs {
                    let mut resolved: Vec<ValueRef> = Vec::new();
                    let mut items = Vec::new();
                    for part in parts {
                        resolve_into(part, values, &mut items);
                    }
                    for item in items {
                        match item {
                            Item::Val(found) => resolved.push(found),
                            Item::Elem(element) => resolved.push(value(
                                flatten_text(&element.children).join(" "),
                                Raw::None,
                                0x01,
                            )),
                        }
                    }
                    let attribute = match resolved.len() {
                        // Optional/NULL substitution: the attribute is not rendered.
                        0 => continue,
                        1 => resolved.pop().expect("one value"),
                        _ => value(
                            resolved.iter().map(|item| item.text.as_str()).collect(),
                            Raw::None,
                            0x01,
                        ),
                    };
                    attrs.push((Rc::clone(name), attribute));
                }
                let children = self.instantiate(&template.children, values, depth)?;
                output.push(Item::Elem(Rc::new(Element {
                    name: Rc::clone(&template.name),
                    attrs,
                    children,
                })));
            } else {
                resolve_into(node, values, &mut output);
            }
        }
        Ok(output)
    }

    /// Decode one record (`record_offset`/`record_size` chunk-relative).
    pub fn decode_record(
        &mut self,
        record_offset: i64,
        record_size: i64,
        render_xml: bool,
    ) -> Res<DecodedRecord> {
        self.tokens = 0;
        self.nesting = 0;
        let body_start = record_offset + RECORD_HEADER_SIZE;
        let body_end = record_offset + record_size - 4;
        let (nodes, _) = self.parse(body_start, body_end, 0, true)?;
        let mut template_offsets = Vec::new();
        let mut substitution_count = 0u64;
        for node in &nodes {
            if let TemplateNode::Instance(_, offset, count) = node {
                template_offsets.push(*offset);
                substitution_count += u64::from(*count);
            }
        }
        let items = self.instantiate(&nodes, &[], 0)?;
        let root = items
            .into_iter()
            .find_map(|item| match item {
                Item::Elem(element) => Some(element),
                Item::Val(_) => None,
            })
            .ok_or_else(|| DecodeError::Decode("record has no root element".to_string()))?;
        if tree_depth_exceeds(&root, MAX_NESTING) {
            return Err(DecodeError::Unsupported("element-nesting-too-deep"));
        }
        let mut decoded = extract_event_fields(&root);
        decoded.template_offsets = template_offsets;
        decoded.substitution_count = substitution_count;
        if render_xml {
            decoded.rendered_xml = Some(render_element_xml(&root, XML_PREVIEW_LIMIT));
        }
        Ok(decoded)
    }
}

fn resolve_into(node: &TemplateNode, values: &[ValueRef], output: &mut Vec<Item>) {
    match node {
        TemplateNode::Sub(index) => {
            let Some(found) = values.get(usize::from(*index)) else {
                return;
            };
            if found.value_type == 0x00 {
                return;
            }
            if found.value_type == 0x21 {
                if let Raw::Nested(items) = &found.raw {
                    output.extend(items.iter().cloned());
                    return;
                }
            }
            output.push(Item::Val(Rc::clone(found)));
        }
        TemplateNode::Instance(items, _, _) => output.extend(items.iter().cloned()),
        TemplateNode::Val(found) => output.push(Item::Val(Rc::clone(found))),
        // Python passes a template element through `_resolve` unchanged; it is
        // neither a value nor an element, so attribute resolution skips it.
        TemplateNode::Elem(_) => {}
    }
}

/// `EvtxValue.raw` as an owned value (strings carry their text).
fn owned_raw(found: &Value) -> Raw {
    match &found.raw {
        Raw::Text => Raw::Str(found.text.clone()),
        other => other.clone(),
    }
}

fn flatten_text(items: &[Item]) -> Vec<String> {
    let mut texts = Vec::new();
    for item in items {
        match item {
            Item::Val(found) => {
                if !found.text.is_empty() {
                    texts.push(found.text.clone());
                }
            }
            Item::Elem(element) => texts.extend(flatten_text(&element.children)),
        }
    }
    texts
}

fn tree_depth_exceeds(element: &Element, budget: u32) -> bool {
    if budget == 0 {
        return true;
    }
    element
        .elements()
        .any(|child| tree_depth_exceeds(child, budget - 1))
}

fn system_text_field(name: &str) -> Option<&'static str> {
    Some(match name {
        "EventID" => "EventID",
        "Version" => "Version",
        "Level" => "Level",
        "Task" => "Task",
        "Opcode" => "Opcode",
        "Keywords" => "Keywords",
        "EventRecordID" => "EventRecordID",
        "Channel" => "Channel",
        "Computer" => "Computer",
        "ProviderName" => "ProviderName",
        _ => return None,
    })
}

fn system_attribute_field(element: &str, attribute: &str) -> Option<&'static str> {
    Some(match (element, attribute) {
        ("Provider", "Name") => "ProviderName",
        ("Provider", "Guid") => "ProviderGuid",
        ("Provider", "EventSourceName") => "ProviderEventSourceName",
        ("EventID", "Qualifiers") => "EventIDQualifiers",
        ("TimeCreated", "SystemTime") => "TimeCreated",
        ("Correlation", "ActivityID") => "CorrelationActivityID",
        ("Correlation", "RelatedActivityID") => "CorrelationRelatedActivityID",
        ("Execution", "ProcessID") => "ProcessID",
        ("Execution", "ThreadID") => "ThreadID",
        ("Execution", "ProcessorID") => "ProcessorID",
        ("Execution", "SessionID") => "SessionID",
        ("Execution", "KernelTime") => "KernelTime",
        ("Execution", "UserTime") => "UserTime",
        ("Execution", "ProcessorTime") => "ProcessorTime",
        ("Security", "UserID") => "UserID",
        _ => return None,
    })
}

/// Insert-or-overwrite keeping first-insertion order (Python dict semantics).
fn dict_set<V>(entries: &mut Vec<(&'static str, V)>, key: &'static str, item: V) {
    match entries.iter_mut().find(|(existing, _)| *existing == key) {
        Some(entry) => entry.1 = item,
        None => entries.push((key, item)),
    }
}

fn leaf_fields(element: &Element, output: &mut Vec<(String, ValueRef)>) {
    let mut children = element.elements().peekable();
    if children.peek().is_none() {
        output.push((element.name.to_string(), element.text_value()));
        return;
    }
    for child in children {
        leaf_fields(child, output);
    }
}

/// Python `extract_evtx_event_fields`.
fn extract_event_fields(event: &Element) -> DecodedRecord {
    let mut system_fields: Vec<(&'static str, String)> = Vec::new();
    let mut system_raw: Vec<(&'static str, Raw)> = Vec::new();
    if let Some(system) = event.child("System") {
        for element in system.elements() {
            if let Some(text_key) = system_text_field(&element.name) {
                let found = element.text_value();
                let present = system_fields.iter().any(|(key, _)| *key == text_key);
                if !found.text.is_empty() || !present {
                    dict_set(&mut system_fields, text_key, found.text.clone());
                    dict_set(&mut system_raw, text_key, owned_raw(&found));
                }
            }
            for (attribute, found) in &element.attrs {
                if let Some(key) = system_attribute_field(&element.name, attribute) {
                    dict_set(&mut system_fields, key, found.text.clone());
                    dict_set(&mut system_raw, key, owned_raw(found));
                }
            }
        }
    }
    // Unique EventData names (the `event_data` dict keys).
    let mut taken: HashSet<String> = HashSet::new();
    let mut sequence: Vec<SequenceItem> = Vec::new();
    let mut source: &'static str = "";
    for section_name in [
        "EventData",
        "UserData",
        "ProcessingErrorData",
        "DebugData",
        "BinaryEventData",
    ] {
        let Some(section) = event.child(section_name) else {
            continue;
        };
        if source.is_empty() {
            source = section_name;
        }
        let mut pairs: Vec<(String, ValueRef, String)> = Vec::new();
        if section_name == "EventData" {
            let mut unnamed = 0;
            for child in section.elements() {
                if &*child.name == "Data" {
                    let key = match child.attr("Name") {
                        Some(name) if !name.text.is_empty() => name.text.clone(),
                        _ => {
                            unnamed += 1;
                            format!("data_{unnamed}")
                        }
                    };
                    let path = format!("Event/EventData/Data[{key}]");
                    pairs.push((key, child.text_value(), path));
                } else {
                    let mut leaves = Vec::new();
                    leaf_fields(child, &mut leaves);
                    pairs.extend(leaves.into_iter().map(|(name, found)| {
                        let path = format!("Event/EventData/{name}");
                        (name, found, path)
                    }));
                }
            }
        } else {
            let mut leaves = Vec::new();
            for child in section.elements() {
                leaf_fields(child, &mut leaves);
            }
            if section.elements().next().is_none() {
                leaves.push((section_name.to_string(), section.text_value()));
            }
            pairs.extend(leaves.into_iter().map(|(name, found)| {
                let path = format!("Event/{section_name}/{name}");
                (name, found, path)
            }));
        }
        for (key, found, path) in pairs {
            let unique = if taken.contains(&key) {
                let mut index = 2;
                while taken.contains(&format!("{key}_{index}")) {
                    index += 1;
                }
                format!("{key}_{index}")
            } else {
                key
            };
            taken.insert(unique.clone());
            sequence.push(SequenceItem {
                name: unique,
                value: found.text.clone(),
                path,
                section: section_name,
                value_type: value_type_name(found.value_type),
            });
        }
    }
    DecodedRecord {
        system_fields,
        system_raw,
        // event_data is derived from the sequence (see DecodedRecord).
        event_data_sequence: sequence,
        event_data_source: source,
        root_name: event.name.to_string(),
        template_offsets: Vec::new(),
        substitution_count: 0,
        rendered_xml: None,
    }
}

/// Python `html.escape(text, quote)`.
fn html_escape(text: &str, quote: bool, out: &mut String) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if quote => out.push_str("&quot;"),
            '\'' if quote => out.push_str("&#x27;"),
            _ => out.push(character),
        }
    }
}

struct XmlWriter {
    out: String,
    chars: usize,
    limit: usize,
}

impl XmlWriter {
    /// Append and report whether the output is still under the limit.
    fn emit(&mut self, text: &str) -> bool {
        self.out.push_str(text);
        self.chars += text.chars().count();
        self.chars < self.limit
    }

    fn walk(&mut self, node: &Element) -> bool {
        let mut open = String::with_capacity(node.name.len() + 2);
        open.push('<');
        open.push_str(&node.name);
        for (name, found) in &node.attrs {
            open.push(' ');
            open.push_str(name);
            open.push_str("=\"");
            html_escape(&found.text, true, &mut open);
            open.push('"');
        }
        if node.children.is_empty() {
            open.push_str("/>");
            return self.emit(&open);
        }
        open.push('>');
        if !self.emit(&open) {
            return false;
        }
        for child in &node.children {
            match child {
                Item::Elem(element) => {
                    if !self.walk(element) {
                        return false;
                    }
                }
                Item::Val(found) => {
                    let mut escaped = String::with_capacity(found.text.len());
                    html_escape(&found.text, false, &mut escaped);
                    if !self.emit(&escaped) {
                        return false;
                    }
                }
            }
        }
        self.emit(&format!("</{}>", node.name))
    }
}

/// Python `render_evtx_element_xml` (first `limit` characters).
fn render_element_xml(element: &Element, limit: usize) -> String {
    let mut writer = XmlWriter {
        out: String::new(),
        chars: 0,
        limit,
    };
    writer.walk(element);
    if writer.chars > limit {
        if let Some((cut, _)) = writer.out.char_indices().nth(limit) {
            writer.out.truncate(cut);
        }
    }
    writer.out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_node(name: &str) -> Vec<u8> {
        let mut out = vec![0u8; 6];
        out.extend_from_slice(&(name.encode_utf16().count() as u16).to_le_bytes());
        for unit in name.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&[0, 0]);
        out
    }

    /// `<Event><System><Channel>Security</Channel></System><EventData>
    /// <Data Name="A">x</Data></EventData></Event>` as inline tokens.
    fn sample_chunk() -> (Vec<u8>, i64, i64) {
        let mut chunk = vec![0u8; 512];
        let record = chunk.len();
        chunk.extend_from_slice(b"**\0\0");
        chunk.extend_from_slice(&[0u8; 20]);
        chunk.extend_from_slice(&[0x0F, 0x01, 0x01, 0x00]);
        let open = |chunk: &mut Vec<u8>, name: &str, attrs: bool| {
            let start = chunk.len() as u32;
            chunk.push(if attrs { 0x41 } else { 0x01 });
            chunk.extend_from_slice(&[0xFF, 0xFF, 0, 0, 0, 0]);
            chunk.extend_from_slice(&(start + 11).to_le_bytes());
            chunk.extend_from_slice(&name_node(name));
            if attrs {
                chunk.extend_from_slice(&[0, 0, 0, 0]);
            }
        };
        let text = |chunk: &mut Vec<u8>, value: &str| {
            chunk.extend_from_slice(&[0x05, 0x01]);
            chunk.extend_from_slice(&(value.encode_utf16().count() as u16).to_le_bytes());
            for unit in value.encode_utf16() {
                chunk.extend_from_slice(&unit.to_le_bytes());
            }
        };
        open(&mut chunk, "Event", false);
        chunk.push(0x02);
        open(&mut chunk, "System", false);
        chunk.push(0x02);
        open(&mut chunk, "Channel", false);
        chunk.push(0x02);
        text(&mut chunk, "Security");
        chunk.push(0x04);
        chunk.push(0x04);
        open(&mut chunk, "EventData", false);
        chunk.push(0x02);
        open(&mut chunk, "Data", true);
        let attr_start = chunk.len() as u32;
        chunk.push(0x06);
        chunk.extend_from_slice(&(attr_start + 5).to_le_bytes());
        chunk.extend_from_slice(&name_node("Name"));
        text(&mut chunk, "A");
        chunk.push(0x02);
        text(&mut chunk, "x<&");
        chunk.push(0x04);
        chunk.push(0x04);
        chunk.push(0x04);
        chunk.push(0x00);
        let size = (chunk.len() - record + 4) as u32;
        chunk.extend_from_slice(&size.to_le_bytes());
        chunk[record + 4..record + 8].copy_from_slice(&size.to_le_bytes());
        chunk.resize(65536, 0);
        (chunk, record as i64, i64::from(size))
    }

    #[test]
    fn decodes_inline_record() {
        let (chunk, offset, size) = sample_chunk();
        let mut decoder = ChunkDecoder::new(chunk);
        let decoded = decoder.decode_record(offset, size, true).unwrap();
        assert_eq!(
            decoded.system_fields,
            vec![("Channel", "Security".to_string())]
        );
        assert_eq!(decoded.event_data_sequence.len(), 1);
        assert_eq!(decoded.event_data_sequence[0].name, "A");
        assert_eq!(decoded.event_data_sequence[0].value, "x<&");
        assert_eq!(decoded.event_data_source, "EventData");
        assert_eq!(
            decoded.event_data_sequence[0].path,
            "Event/EventData/Data[A]"
        );
        assert_eq!(
            decoded.rendered_xml.as_deref(),
            Some("<Event><System><Channel>Security</Channel></System><EventData><Data Name=\"A\">x&lt;&amp;</Data></EventData></Event>")
        );
    }

    #[test]
    fn truncated_record_reports_python_error_text() {
        let (chunk, offset, _) = sample_chunk();
        let mut decoder = ChunkDecoder::new(chunk);
        // Body ends inside the first element header: u32 name offset read is
        // still in the chunk, so parsing stops without a root element.
        let error = decoder.decode_record(offset, 30, false).unwrap_err();
        assert_eq!(
            error,
            DecodeError::Decode("record has no root element".to_string())
        );
    }

    #[test]
    fn float_repr_matches_python() {
        let cases = [
            (0.1, "0.1"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (-2.5, "-2.5"),
            (f64::from(0.1f32), "0.10000000149011612"),
            (123456789.0, "123456789.0"),
            (1.5e-300, "1.5e-300"),
            (-0.0, "-0.0"),
        ];
        for (number, expected) in cases {
            assert_eq!(python_float_repr(number), expected, "{number}");
        }
        assert_eq!(real_text(3.0), "3");
    }

    #[test]
    fn filetime_keeps_seven_digits() {
        assert_eq!(
            filetime_to_iso_100ns(133_928_514_891_234_567),
            "2025-05-27T20:31:29.1234567Z"
        );
        assert_eq!(
            filetime_to_iso_100ns(2_650_467_743_999_999_999),
            "9999-12-31T23:59:59.9999999Z"
        );
        assert_eq!(filetime_to_iso_100ns(2_650_467_744_000_000_000), "");
        assert_eq!(filetime_to_iso_100ns(u64::MAX), "");
        assert_eq!(filetime_to_iso_100ns(1), "1601-01-01T00:00:00.0000001Z");
    }

    #[test]
    fn sid_and_type_names() {
        let raw = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(sid_to_string(&raw), "S-1-5-18");
        assert_eq!(value_type_name(0x81), "StringTypeArray");
        assert_eq!(value_type_name(0x7F), "UnknownType0x7f");
    }
}
