//! Text and time helpers that reproduce CPython's behaviour byte for byte, so names, string
//! values and timestamps equal what `rapidtriage.artifacts.windows.registry` produces.

const REPLACEMENT: char = '\u{FFFD}';

fn utf16_units(raw: &[u8]) -> impl Iterator<Item = u16> + '_ {
    raw.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
}

/// `bytes.decode("utf-16-le", errors="replace")` (or `errors="ignore"` when `replace` is false).
///
/// CPython reports an unpaired surrogate as one error per code unit, except a high surrogate in
/// the final code unit, whose error range runs to the end of the input (swallowing an odd
/// trailing byte); an odd trailing byte on its own is one more error.
pub fn decode_utf16le(raw: &[u8], replace: bool) -> String {
    let units: Vec<u16> = utf16_units(raw).collect();
    let mut text = String::with_capacity(units.len());
    let mut index = 0;
    let mut trailing_byte_consumed = false;
    while index < units.len() {
        let unit = units[index];
        match unit {
            0xD800..=0xDBFF => {
                if index + 1 == units.len() {
                    if replace {
                        text.push(REPLACEMENT);
                    }
                    trailing_byte_consumed = true;
                    index += 1;
                    continue;
                }
                let next = units[index + 1];
                if (0xDC00..=0xDFFF).contains(&next) {
                    let code =
                        0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(next) - 0xDC00);
                    text.push(char::from_u32(code).unwrap_or(REPLACEMENT));
                    index += 2;
                } else {
                    if replace {
                        text.push(REPLACEMENT);
                    }
                    index += 1;
                }
            }
            0xDC00..=0xDFFF => {
                if replace {
                    text.push(REPLACEMENT);
                }
                index += 1;
            }
            _ => {
                text.push(char::from_u32(u32::from(unit)).unwrap_or(REPLACEMENT));
                index += 1;
            }
        }
    }
    if raw.len() % 2 == 1 && !trailing_byte_consumed && replace {
        text.push(REPLACEMENT);
    }
    text
}

/// `bytes.decode("latin-1")`.
pub fn decode_latin1(raw: &[u8]) -> String {
    raw.iter().map(|&byte| char::from(byte)).collect()
}

fn is_strip_char(ch: char) -> bool {
    matches!(ch, '\0' | '\r' | '\n' | '\t' | ' ')
}

/// `str.strip("\x00\r\n\t ")`.
pub fn strip_registry(text: &str) -> &str {
    text.trim_matches(is_strip_char)
}

/// `decode_utf16le_string`: UTF-16LE with errors ignored, then stripped.
pub fn decode_utf16le_stripped(raw: &[u8]) -> String {
    strip_registry(&decode_utf16le(raw, false)).to_string()
}

/// `decode_native_registry_name`: Latin-1 for compressed names, UTF-16LE (replace) otherwise.
pub fn decode_native_name(raw: &[u8], compressed: bool) -> (String, &'static str) {
    if compressed {
        (decode_latin1(raw), "latin-1")
    } else {
        (decode_utf16le(raw, true), "utf-16le")
    }
}

/// `decode_registry_cell_name` used for free (deleted) cell candidates.
pub fn decode_cell_name(raw: &[u8], compressed: bool) -> (String, &'static str) {
    if raw.is_empty() {
        return (String::new(), "");
    }
    if compressed {
        return (strip_registry(&decode_latin1(raw)).to_string(), "latin-1");
    }
    let decoded = decode_utf16le_stripped(raw);
    if !decoded.is_empty() {
        return (decoded, "utf-16le");
    }
    (
        strip_registry(&decode_latin1(raw)).to_string(),
        "latin-1-fallback",
    )
}

/// `is_plausible_registry_cell_name`.
pub fn is_plausible_cell_name(name: &str) -> bool {
    if name.is_empty() || name.chars().count() > 260 {
        return false;
    }
    let has_word = name.chars().any(|ch| {
        ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '_' | '.' | '$' | '%' | '{' | '}' | '(' | ')' | ' ' | '-'
            )
    });
    has_word && !name.chars().any(|ch| (ch as u32) < 32)
}

/// `decode_registry_sz`: cut at the first aligned NUL code unit, then UTF-16LE (replace).
pub fn decode_registry_sz(raw: &[u8]) -> String {
    let even = &raw[..raw.len() - raw.len() % 2];
    let end = even
        .as_chunks::<2>()
        .0
        .iter()
        .position(|pair| *pair == [0, 0])
        .map_or(even.len(), |index| index * 2);
    decode_utf16le(&even[..end], true)
}

/// REG_MULTI_SZ: UTF-16LE (replace) over the even prefix, split on NUL, empty items dropped.
pub fn decode_registry_multi_sz(raw: &[u8]) -> Vec<String> {
    let even = &raw[..raw.len() - raw.len() % 2];
    decode_utf16le(even, true)
        .split('\0')
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// `registry_value_type_name`.
pub fn value_type_name(value_type: u32) -> String {
    let name = match value_type {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        other => return format!("REG_TYPE_{other}"),
    };
    name.to_string()
}

const TICKS_PER_SECOND: u64 = 10_000_000;
const SECONDS_PER_DAY: i64 = 86_400;

/// Days from 1970-01-01 to the given proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn filetime_epoch_days() -> i64 {
    days_from_civil(1601, 1, 1)
}

/// Largest FILETIME the Python path renders: 9999-12-31T23:59:59 exactly.
pub fn filetime_max_ticks() -> u64 {
    let days = days_from_civil(9999, 12, 31) - filetime_epoch_days();
    (days * SECONDS_PER_DAY + 86_399) as u64 * TICKS_PER_SECOND
}

/// `filetime_to_iso_ticks`: ISO-8601 UTC with all seven 100 ns digits (none for whole seconds);
/// empty for 0 or anything past 9999-12-31T23:59:59.
pub fn filetime_to_iso_ticks(ticks: u64) -> String {
    if ticks == 0 || ticks > filetime_max_ticks() {
        return String::new();
    }
    let seconds = (ticks / TICKS_PER_SECOND) as i64;
    let fraction = ticks % TICKS_PER_SECOND;
    let days = seconds.div_euclid(SECONDS_PER_DAY);
    let second_of_day = seconds.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(filetime_epoch_days() + days);
    let mut text = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        second_of_day / 3600,
        (second_of_day % 3600) / 60,
        second_of_day % 60
    );
    if fraction != 0 {
        text.push_str(&format!(".{fraction:07}"));
    }
    text.push_str("+00:00");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(text: &[u16]) -> Vec<u8> {
        text.iter().flat_map(|unit| unit.to_le_bytes()).collect()
    }

    #[test]
    fn utf16_replace_matches_cpython_error_ranges() {
        let fffd = '\u{FFFD}';
        assert_eq!(decode_utf16le(b"A\x00B", true), format!("A{fffd}"));
        assert_eq!(decode_utf16le(b"A\x00\x00\xd8", true), format!("A{fffd}"));
        assert_eq!(decode_utf16le(b"A\x00\x00\xd8B", true), format!("A{fffd}"));
        assert_eq!(decode_utf16le(b"\x00\xd8A\x00", true), format!("{fffd}A"));
        assert_eq!(decode_utf16le(b"\x00\xdcA", true), format!("{fffd}{fffd}"));
        assert_eq!(
            decode_utf16le(b"\x00\xd8\x00\xdcZ", true),
            format!("\u{10000}{fffd}")
        );
        assert_eq!(
            decode_utf16le(b"\x00\xd8\x00\xd8", true),
            format!("{fffd}{fffd}")
        );
        assert_eq!(decode_utf16le(b"\x00\xdcA", false), "");
        assert_eq!(decode_utf16le(&units(&[0xD55C, 0xAE00]), true), "한글");
    }

    #[test]
    fn registry_sz_stops_at_first_aligned_nul() {
        assert_eq!(decode_registry_sz(&units(&[0x41, 0x42, 0, 0x43])), "AB");
        assert_eq!(decode_registry_sz(b"A\x00\x00B\x00"), "A\u{4200}");
        assert_eq!(
            decode_registry_multi_sz(&units(&[0x41, 0, 0, 0x42, 0, 0])),
            vec!["A".to_string(), "B".to_string()]
        );
    }

    #[test]
    fn filetime_rendering_keeps_100ns_ticks() {
        assert_eq!(filetime_to_iso_ticks(0), "");
        assert_eq!(
            filetime_to_iso_ticks(1),
            "1601-01-01T00:00:00.0000001+00:00"
        );
        assert_eq!(
            filetime_to_iso_ticks(116_444_736_000_000_000),
            "1970-01-01T00:00:00+00:00"
        );
        assert_eq!(
            filetime_to_iso_ticks(133_930_492_691_655_237),
            "2025-05-30T03:27:49.1655237+00:00"
        );
        assert_eq!(
            filetime_to_iso_ticks(filetime_max_ticks()),
            "9999-12-31T23:59:59+00:00"
        );
        assert_eq!(filetime_to_iso_ticks(filetime_max_ticks() + 1), "");
    }

    #[test]
    fn cell_names_follow_python_plausibility() {
        assert!(is_plausible_cell_name("Run"));
        assert!(!is_plausible_cell_name("한글"));
        assert!(!is_plausible_cell_name("bad\u{1}name"));
        assert!(!is_plausible_cell_name(&"a".repeat(261)));
        assert_eq!(
            decode_cell_name(b"\0 Key\r\n", true),
            ("Key".to_string(), "latin-1")
        );
        assert_eq!(
            decode_cell_name(b"\x00\xdc", false),
            ("\u{dc}".to_string(), "latin-1-fallback")
        );
    }
}
