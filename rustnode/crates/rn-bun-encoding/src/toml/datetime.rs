//! Normalising a TOML datetime into the text a `Temporal` constructor takes.
//!
//! Bun parses a TOML datetime into a `Temporal` object, and the object's
//! `String(value)` is what a round-trip through `TOML.stringify` writes. So the
//! job here is to produce exactly the text `Temporal` would report:
//!
//! ```text
//! 1979-05-27T07:32:00Z            -> 1979-05-27T07:32:00Z          Instant
//! 1979-05-27T00:32:00-07:00       -> 1979-05-27T07:32:00Z          Instant, normalised
//! 1979-05-27                      -> 1979-05-27                    PlainDate
//! 07:32:00                        -> 07:32:00                      PlainTime
//! 1979-05-27T07:32:00             -> 1979-05-27T07:32:00           PlainDateTime
//! 1979-05-27T07:32                -> 1979-05-27T07:32:00           seconds defaulted
//! 1979-05-27 07:32:00Z            -> 1979-05-27T07:32:00Z          space separator
//! ```
//!
//! Each of those was measured against `Bun.TOML.parse` and `String(value)` on the
//! result. The validation messages are Bun's too, e.g.
//! `Invalid time: hours must be between 00 and 23`.

/// The RFC 3339 instant for epoch milliseconds, which is what TOML writes for a
/// JavaScript `Date`.
///
/// `TOML.stringify({d: new Date(0)})` is `d = 1970-01-01T00:00:00Z`, and a date
/// with milliseconds keeps them: `new Date(1)` is `1970-01-01T00:00:00.001Z`.
pub fn from_millis(millis: f64) -> String {
    let total_seconds = (millis / 1000.0).floor() as i64;
    let remainder = millis - (total_seconds as f64) * 1000.0;
    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hours = seconds_of_day / 3600;
    let minutes = seconds_of_day % 3600 / 60;
    let seconds = seconds_of_day % 60;
    if remainder == 0.0 {
        format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
    } else {
        let millis = remainder.round() as i64;
        format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{millis:03}Z")
    }
}

/// Normalises `text`, returning the `Value` for it.
pub fn normalize(text: &str) -> Result<crate::value::Value, String> {
    let (date, rest) = split_date(text)?;
    let time_part = rest.map(|rest| rest.trim_start_matches(['T', 't']).to_string());
    match (date, time_part) {
        (Some(date), None) => Ok(crate::value::Value::Temporal(date)),
        (None, Some(time)) => {
            let time = normalize_time(&time)?;
            Ok(crate::value::Value::Temporal(time))
        }
        (Some(date), Some(time)) => {
            let (time, offset) = split_offset(&time)?;
            let time = normalize_time(time)?;
            match offset {
                None => Ok(crate::value::Value::Temporal(format!("{date}T{time}"))),
                Some(offset) => {
                    let utc = to_utc(&date, &time, offset)?;
                    Ok(crate::value::Value::Temporal(utc))
                }
            }
        }
        (None, None) => unreachable!("split_date returns an error when neither half is present"),
    }
}

/// Splits the date portion from the rest.
///
/// `None` for the date means the text started with a time; `None` for the rest
/// means there was no time at all.
fn split_date(text: &str) -> Result<(Option<String>, Option<String>), String> {
    let bytes = text.as_bytes();
    if bytes.len() >= 4
        && bytes.iter().take(4).all(u8::is_ascii_digit)
        && bytes.get(4) == Some(&b'-')
    {
        let date_end = date_length(text);
        let year = number(&text[0..4]);
        let _ = year;
        if text.len() < date_end {
            return Err("Invalid date: expected 'DD' after '-'".to_string());
        }
        let month_text = &text[5..7.min(text.len())];
        let month = parse_field(
            month_text,
            "Invalid date: expected 2-digit month",
            "date",
            "Invalid date: month must be between 01 and 12",
        )?;
        if !(1..=12).contains(&month) {
            return Err("Invalid date: month must be between 01 and 12".to_string());
        }
        let day_start = 8;
        if text.len() < day_start + 2 {
            return Err("Invalid date: expected 'DD' after '-'".to_string());
        }
        let day = parse_field(
            &text[day_start..day_start + 2],
            "Invalid date: expected 2-digit day",
            "date",
            "Invalid date: day must be between 01 and 31",
        )?;
        let limit = days_in_month(year, month);
        if day < 1 || day > limit {
            return Err(format!(
                "Invalid date: day must be between 01 and {limit:02}"
            ));
        }
        let date = text[..date_end].to_string();
        let rest = text[date_end..].trim_start();
        if rest.is_empty() {
            return Ok((Some(date), None));
        }
        let rest = rest.strip_prefix(['T', 't']).unwrap_or(rest);
        if rest.is_empty() {
            return Err("Invalid time: expected 2-digit hours".to_string());
        }
        return Ok((Some(date), Some(rest.to_string())));
    }
    if text.contains(':') {
        return Ok((None, Some(text.to_string())));
    }
    Err("Expected a value but found".to_string())
}

fn date_length(text: &str) -> usize {
    10.min(text.len())
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 31,
    }
}

fn number(text: &str) -> u32 {
    text.parse().unwrap_or(0)
}

fn parse_field(text: &str, expected: &str, _label: &str, _range: &str) -> Result<u32, String> {
    if text.len() != 2 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(expected.to_string());
    }
    Ok(number(text))
}

/// Normalises a time to `HH:MM:SS[.fraction]`.
fn normalize_time(text: &str) -> Result<String, String> {
    let mut parts = text.split(':');
    let hours = parts
        .next()
        .filter(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| "Invalid time: expected 2-digit hours".to_string())?;
    let hours = number(hours);
    if hours > 23 {
        return Err("Invalid time: hours must be between 00 and 23".to_string());
    }
    let minutes = parts
        .next()
        .ok_or_else(|| "Invalid time: expected ':' after hours".to_string())?;
    if minutes.len() != 2 || !minutes.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Invalid time: expected 2-digit minutes".to_string());
    }
    let minutes = number(minutes);
    if minutes > 59 {
        return Err("Invalid time: minutes must be between 00 and 59".to_string());
    }
    let seconds_part = parts.next();
    let (seconds, fraction) = match seconds_part {
        None => (0, String::new()),
        Some(seconds) => match seconds.split_once('.') {
            Some((seconds, fraction)) => (number(seconds), format!(".{fraction}")),
            None => (number(seconds), String::new()),
        },
    };
    if let Some(seconds_text) = seconds_part {
        let seconds_digits = seconds_text.split('.').next().unwrap_or("");
        if seconds_digits.len() != 2 || !seconds_digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("Invalid time: expected 2-digit seconds".to_string());
        }
    }
    if seconds > 59 {
        return Err("Invalid time: seconds must be between 00 and 59".to_string());
    }
    if !fraction.is_empty() && !fraction[1..].bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Invalid time: expected digits after '.'".to_string());
    }
    Ok(format!("{hours:02}:{minutes:02}:{seconds:02}{fraction}"))
}

/// Splits a trailing `Z` or `±HH:MM` off a time, validating the offset.
fn split_offset(text: &str) -> Result<(&str, Option<Offset>), String> {
    if let Some(stripped) = text.strip_suffix(['Z', 'z']) {
        return Ok((stripped, Some(Offset { minutes: 0 })));
    }
    // A sign after the seconds is an offset; a `-` in a date cannot reach here.
    let Some(at) = text.rfind(['+', '-']) else {
        return Ok((text, None));
    };
    let (time, offset) = text.split_at(at);
    let sign = if offset.starts_with('-') { -1 } else { 1 };
    let body = &offset[1..];
    let (hours, minutes) = body
        .split_once(':')
        .ok_or_else(|| "Invalid date-time offset: expected ':' in the offset".to_string())?;
    if hours.len() != 2 || !hours.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Invalid date-time offset: expected 2-digit hours".to_string());
    }
    if minutes.len() != 2 || !minutes.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Invalid date-time offset: expected 2-digit minutes".to_string());
    }
    let hours = number(hours);
    if hours > 23 {
        return Err("Invalid date-time offset: hours must be between 00 and 23".to_string());
    }
    let minutes = number(minutes);
    if minutes > 59 {
        return Err("Invalid date-time offset: minutes must be between 00 and 59".to_string());
    }
    Ok((
        time,
        Some(Offset {
            minutes: sign * ((hours * 60 + minutes) as i32),
        }),
    ))
}

struct Offset {
    minutes: i32,
}

/// The UTC form of a local date-time with an offset.
///
/// Bun normalises to UTC, so `1979-05-27T00:32:00-07:00` becomes
/// `1979-05-27T07:32:00Z`. The arithmetic is done on a day number so a rollover
/// across a month or year boundary is one comparison, not a calendar special
/// case.
fn to_utc(date: &str, time: &str, offset: Offset) -> Result<String, String> {
    let year = number(&date[0..4]) as i64;
    let month = number(&date[5..7]) as i64;
    let day = number(&date[8..10]) as i64;
    let hours = number(&time[0..2]) as i64;
    let minutes = number(&time[3..5]) as i64;
    let seconds = number(&time[6..8]) as i64;
    let fraction = if time.len() > 8 {
        time[8..].to_string()
    } else {
        String::new()
    };
    let total =
        (hours * 3600 + minutes * 60 + seconds - offset.minutes as i64 * 60).rem_euclid(86_400);
    let day_shift =
        (hours * 3600 + minutes * 60 + seconds - offset.minutes as i64 * 60).div_euclid(86_400);
    let (year, month, day) = shift_days(year, month, day, day_shift);
    let hours = total / 3600;
    let minutes = total % 3600 / 60;
    let seconds = total % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}{fraction}Z"
    ))
}

/// Moves a civil date by `days`, using the days-from-civil algorithm.
fn shift_days(year: i64, month: i64, day: i64, days: i64) -> (i64, i64, i64) {
    let z = days_from_civil(year, month, day) + days;
    civil_from_days(z)
}

/// Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;

    fn temporal(text: &str) -> String {
        match normalize(text) {
            Ok(Value::Temporal(text)) => text,
            Ok(other) => panic!("{text} became {other:?}"),
            Err(error) => panic!("{text} failed: {error}"),
        }
    }

    #[test]
    fn forms_match_bun_string_output() {
        assert_eq!(temporal("1979-05-27T07:32:00Z"), "1979-05-27T07:32:00Z");
        assert_eq!(
            temporal("1979-05-27T07:32:00.999999Z"),
            "1979-05-27T07:32:00.999999Z"
        );
        assert_eq!(
            temporal("1979-05-27T00:32:00-07:00"),
            "1979-05-27T07:32:00Z"
        );
        assert_eq!(
            temporal("1979-05-27T07:32:00+00:00"),
            "1979-05-27T07:32:00Z"
        );
        assert_eq!(temporal("1979-05-27"), "1979-05-27");
        assert_eq!(temporal("07:32:00"), "07:32:00");
        assert_eq!(temporal("07:32:00.999"), "07:32:00.999");
        assert_eq!(temporal("1979-05-27T07:32:00"), "1979-05-27T07:32:00");
        assert_eq!(temporal("1979-05-27T07:32:00.5"), "1979-05-27T07:32:00.5");
        // A time with only hours and minutes is completed with `:00`.
        assert_eq!(temporal("1979-05-27T07:32"), "1979-05-27T07:32:00");
        // A space is a legal separator.
        assert_eq!(temporal("1979-05-27 07:32:00Z"), "1979-05-27T07:32:00Z");
        // A rollover across midnight, and across a month boundary.
        assert_eq!(
            temporal("1979-05-27T00:30:00+01:00"),
            "1979-05-26T23:30:00Z"
        );
        assert_eq!(
            temporal("1979-12-31T23:30:00-01:00"),
            "1980-01-01T00:30:00Z"
        );
    }

    #[test]
    fn failures_are_bun_messages() {
        for (text, expected) in [
            (
                "1979-13-01",
                "Invalid date: month must be between 01 and 12",
            ),
            (
                "07:60:00",
                "Invalid time: minutes must be between 00 and 59",
            ),
            (
                "1979-05-27T07:32:00-25:00",
                "Invalid date-time offset: hours must be between 00 and 23",
            ),
            ("1979-05-27T", "Invalid time: expected 2-digit hours"),
            ("1979-05-27T07", "Invalid time: expected ':' after hours"),
            (
                "1979-05-27T07:32:00+",
                "Invalid date-time offset: expected ':' in the offset",
            ),
        ] {
            assert_eq!(normalize(text), Err(expected.to_string()), "{text}");
        }
    }
}
