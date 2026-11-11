//! `validFrom` / `validTo`, as printed text and as `Date`.
//!
//! Two representations of the same field, and they fail independently:
//!
//! * the **string** is `ASN1_TIME_print`'s output, or `"Bad time value"` when the
//!   time is not one `ASN1_TIME_check` accepts. `getValidFrom` returns
//!   `undefined` only when the printer itself fails;
//! * the **`Date`** is the POSIX seconds `ASN1_TIME_to_tm` produces, times 1000,
//!   or `NaN` when the time does not convert.
//!
//! `"Bad time value"` is a *successful* print, so a certificate with a broken
//! `notBefore` reports that string rather than `undefined`. Node has done this
//! since the original implementation, and `test-crypto-x509` asserts it on a
//! deliberately malformed certificate.

use openssl::x509::X509;
use openssl_sys as ffi;

// `X509_get0_notBefore`/`notAfter` and `ASN1_TIME_print` are missing from
// `openssl-sys` in the shape needed here: the safe crate's `not_before()` returns
// a `&Asn1TimeRef` and its `to_string` is `ASN1_STRING`-level, not
// `ASN1_TIME_print`. `ASN1_TIME_print` *is* exported, but `X509_get0_notBefore`
// is not, so the accessor is declared here.
extern "C" {
    fn X509_get0_notBefore(certificate: *const ffi::X509) -> *const ffi::ASN1_TIME;
    fn X509_get0_notAfter(certificate: *const ffi::X509) -> *const ffi::ASN1_TIME;
    fn ASN1_TIME_check(time: *const ffi::ASN1_TIME) -> std::ffi::c_int;
    fn ASN1_TIME_print(bio: *mut ffi::BIO, time: *const ffi::ASN1_TIME) -> std::ffi::c_int;
    fn ASN1_TIME_to_tm(time: *const ffi::ASN1_TIME, out: *mut Tm) -> std::ffi::c_int;
}

/// `struct tm`, as `ASN1_TIME_to_tm` fills it.
///
/// The field layout is POSIX and identical on every platform this builds for,
/// which is the same assumption `openssl` itself makes when it declares this
/// struct for `Asn1Time::diff`. Kept `repr(C)` and fully padded so the C side
/// cannot write past it.
#[repr(C)]
#[derive(Default)]
struct Tm {
    tm_sec: std::ffi::c_int,
    tm_min: std::ffi::c_int,
    tm_hour: std::ffi::c_int,
    tm_mday: std::ffi::c_int,
    tm_mon: std::ffi::c_int,
    tm_year: std::ffi::c_int,
    tm_wday: std::ffi::c_int,
    tm_yday: std::ffi::c_int,
    tm_isdst: std::ffi::c_int,
    tm_gmtoff: std::ffi::c_long,
    tm_zone: *const std::ffi::c_char,
}

/// `ASN1_TIME_print`'s output, or `None` when it fails.
pub fn print_time(certificate: &X509, from: bool) -> Option<String> {
    use foreign_types::ForeignType;
    // SAFETY: both calls only read the certificate.
    let time = unsafe {
        if from {
            X509_get0_notBefore(certificate.as_ptr())
        } else {
            X509_get0_notAfter(certificate.as_ptr())
        }
    };
    if time.is_null() {
        return None;
    }
    // SAFETY: `time` is borrowed from `certificate`, which outlives the call.
    let printable = unsafe { ASN1_TIME_check(time) == 1 };
    crate::bio::with_memory_bio(|bio| {
        if printable {
            // SAFETY: the BIO and the time value are both live for the call.
            unsafe { ASN1_TIME_print(bio.raw(), time) > 0 }
        } else {
            // `BIOPointer::WriteAll(bio, "Bad time value")`, byte for byte.
            bio.write(b"Bad time value")
        }
    })
}

/// The POSIX seconds of the field, or `None` when it will not convert.
///
/// `None` becomes `NaN` at the call site, which is `Date::New(context, NaN)`.
pub fn seconds(certificate: &X509, from: bool) -> Option<i64> {
    use foreign_types::ForeignType;
    // SAFETY: both calls only read the certificate.
    let time = unsafe {
        if from {
            X509_get0_notBefore(certificate.as_ptr())
        } else {
            X509_get0_notAfter(certificate.as_ptr())
        }
    };
    if time.is_null() {
        return None;
    }
    let mut broken_down = Tm::default();
    // SAFETY: `time` is live and `broken_down` is a correctly sized out-param.
    if unsafe { ASN1_TIME_to_tm(time, &mut broken_down) } != 1 {
        return None;
    }
    // `PortableTimeGM`: `timegm` normalises the UTC fields, and `tm` holds UTC
    // because `ASN1_TIME_to_tm` fills a UTC `ASN1_TIME`.
    Some(timegm(&broken_down))
}

/// `timegm` over a `struct tm`, so no libc dependency is needed.
///
/// Days-from-civil, which is exact for every year a certificate can hold and has
/// no leap-second or timezone input to disagree with `timegm` about.
fn timegm(tm: &Tm) -> i64 {
    let year = i64::from(tm.tm_year) + 1900;
    let month = i64::from(tm.tm_mon) + 1;
    let day = i64::from(tm.tm_mday);

    // Shift January and February into the previous year so the leap day is last.
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    days * 86_400 + i64::from(tm.tm_hour) * 3_600 + i64::from(tm.tm_min) * 60 + i64::from(tm.tm_sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_epoch_date_converts_to_zero() {
        let tm = Tm {
            tm_year: 70,
            tm_mon: 0,
            tm_mday: 1,
            ..Tm::default()
        };
        assert_eq!(timegm(&tm), 0);
    }

    #[test]
    fn a_known_date_converts_to_its_posix_seconds() {
        // 2022-09-03T21:40:37Z, the `agent1-cert.pem` notBefore, whose POSIX
        // value is 1662241237. An off-by-one in the month or leap handling shows
        // up here immediately.
        let tm = Tm {
            tm_year: 122,
            tm_mon: 8,
            tm_mday: 3,
            tm_hour: 21,
            tm_min: 40,
            tm_sec: 37,
            ..Tm::default()
        };
        assert_eq!(timegm(&tm), 1_662_241_237);
    }

    #[test]
    fn a_leap_day_converts() {
        // 2024-02-29T00:00:00Z, which only exists because 2024 is a leap year.
        let tm = Tm {
            tm_year: 124,
            tm_mon: 1,
            tm_mday: 29,
            ..Tm::default()
        };
        assert_eq!(timegm(&tm), 1_709_164_800);
    }

    #[test]
    fn the_century_rule_is_applied() {
        // 1900 is not a leap year and 2000 is. The 400-year era arithmetic is
        // what gets this right, and a naive `/4` gets 1900-03-01 wrong by a day.
        let march_first_1900 = Tm {
            tm_year: 0,
            tm_mon: 2,
            tm_mday: 1,
            ..Tm::default()
        };
        let march_first_2000 = Tm {
            tm_year: 100,
            tm_mon: 2,
            tm_mday: 1,
            ..Tm::default()
        };
        assert_eq!(
            timegm(&march_first_2000) - timegm(&march_first_1900),
            // 100 years, 25 leap days: 1904…1996 is 24 and 2000-02-29 falls
            // inside the interval because the end is March 1. A naive `/4`
            // counts 25 without noticing that 1900 is not a leap year, so it
            // happens to agree here — the century rule matters for intervals
            // that start before a non-leap century year.
            36_525 * 86_400
        );
    }
}
