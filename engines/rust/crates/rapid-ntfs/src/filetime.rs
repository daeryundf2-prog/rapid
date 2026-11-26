pub const FILETIME_OUT_OF_RANGE_ISO: &str = "9999-12-31T23:59:59.999999+00:00";

const TICKS_PER_SECOND: u64 = 10_000_000;

// Howard Hinnant's days_from_civil / civil_from_days (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
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

fn epoch_days() -> i64 {
    days_from_civil(1601, 1, 1)
}

/// `_FILETIME_TICKS_MAX` of filesystem.py: 9999-12-31T23:59:59.999999 in ticks, microsecond-floored.
pub fn filetime_ticks_max() -> u64 {
    let days = (days_from_civil(9999, 12, 31) - epoch_days()) as u64;
    ((days * 86_400 + 86_399) * 1_000_000 + 999_999) * 10
}

/// `filetime_to_iso` of filesystem.py: `""` for 0, the out-of-range marker past
/// year 9999, else `datetime.isoformat()` text (microseconds; the 100 ns digit is
/// dropped there and kept by callers in the raw tick value).
pub fn filetime_to_iso(value: u64) -> String {
    if value == 0 {
        return String::new();
    }
    if value > filetime_ticks_max() {
        return FILETIME_OUT_OF_RANGE_ISO.to_string();
    }
    let seconds = value / TICKS_PER_SECOND;
    let microseconds = (value % TICKS_PER_SECOND) / 10;
    let days = (seconds / 86_400) as i64;
    let second_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(epoch_days() + days);
    let (hour, minute, second) = (
        second_of_day / 3600,
        (second_of_day / 60) % 60,
        second_of_day % 60,
    );
    if microseconds == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{microseconds:06}+00:00")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_filetimes_match_python_isoformat() {
        assert_eq!(filetime_to_iso(0), "");
        assert_eq!(filetime_to_iso(1), "1601-01-01T00:00:00+00:00");
        assert_eq!(
            filetime_to_iso(116_444_736_000_000_000),
            "1970-01-01T00:00:00+00:00"
        );
        assert_eq!(
            filetime_to_iso(133_485_408_000_000_007),
            "2024-01-01T00:00:00+00:00"
        );
        assert_eq!(
            filetime_to_iso(133_485_408_001_234_567),
            "2024-01-01T00:00:00.123456+00:00"
        );
        assert_eq!(
            filetime_to_iso(0x7FFF_FFFF_FFFF_FFFF),
            FILETIME_OUT_OF_RANGE_ISO
        );
    }

    #[test]
    fn ticks_max_is_the_last_representable_microsecond() {
        let max = filetime_ticks_max();
        assert_eq!(filetime_to_iso(max), "9999-12-31T23:59:59.999999+00:00");
        assert_eq!(filetime_to_iso(max + 1), FILETIME_OUT_OF_RANGE_ISO);
        assert_eq!(max, 2_650_467_743_999_999_990);
    }
}
