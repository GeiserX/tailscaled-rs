//! Go's `time.Duration` grammar — the parser and the formatter, in one place.
//!
//! Two independent ports of the Go standard library's `src/time/format.go` live here because two
//! unrelated surfaces need Go's exact duration semantics:
//!
//! - [`parse_go_duration`] is `time.ParseDuration`. `tnet cert --min-validity` takes a Go duration
//!   (Go reaches it through `fs.DurationVar` in `cmd/tailscale/cli/cert.go`), and the system-policy
//!   file validates its `DurationValue` settings with it (Go `source.readPolicySettingValue`).
//! - [`format_go_duration`] is `Duration.String()`. The `syspolicy list` table prints a policy value
//!   with Go's `%v`, and for a duration setting that is `Duration.String()` — so `"60m"` in the
//!   policy file must render as `1h0m0s`, exactly as `tailscale syspolicy list` renders it.
//!
//! Both are pure functions over `i64` nanoseconds (Go's `time.Duration` representation), so both are
//! unit-testable without a clock, a file, or a daemon.

/// Parse a Go duration string — `300ms`, `-1.5h`, `2h45m`, `0` — into nanoseconds, the way Go's
/// `time.ParseDuration` does (`src/time/format.go` in the Go standard library, reached from
/// `cmd/tailscale/cli/cert.go`'s `fs.DurationVar`). A duration is a possibly signed sequence of
/// decimal numbers each with a unit suffix; valid units are `ns`, `us` (or `µs`/`μs`), `ms`, `s`,
/// `m` and `h`.
///
/// The error strings are Go's, so a mistyped flag reads the same as it would from `tailscale`:
/// `time: missing unit in duration "1"`, `time: unknown unit "d" in duration "1d"`, and
/// `time: invalid duration "abc"` for everything else (including overflow past Go's i64-nanosecond
/// range). The system-policy file surfaces those same strings when a `DurationValue` setting fails
/// to validate, because Go's `readPolicySettingValue` hands the raw string to `time.ParseDuration`
/// and reports whatever it returns. Pure → unit-testable.
pub fn parse_go_duration(input: &str) -> Result<i64, String> {
    // Go quotes the offending text with %q; the values here are flag arguments (no exotic escapes to
    // reproduce), so a plain double-quoting matches what Go prints.
    fn quoted(s: &str) -> String {
        format!("{s:?}")
    }
    let invalid = |s: &str| format!("time: invalid duration {}", quoted(s));

    let orig = input;
    let mut s = input;
    let mut neg = false;
    if let Some(first) = s.as_bytes().first()
        && (*first == b'-' || *first == b'+')
    {
        neg = *first == b'-';
        s = &s[1..];
    }
    // Special case: a bare "0" is zero with no unit.
    if s == "0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(invalid(orig));
    }

    // Nanoseconds accumulated so far. Go accumulates in a u64 and range-checks against 1<<63 as it
    // goes, so the same arithmetic is done here.
    let mut total: u64 = 0;
    while !s.is_empty() {
        // The next character must start a number: [0-9.].
        let first = s.as_bytes()[0];
        if !(first == b'.' || first.is_ascii_digit()) {
            return Err(invalid(orig));
        }
        // Integer part.
        let before = s.len();
        let (mut v, rest) = leading_int(s).ok_or_else(|| invalid(orig))?;
        s = rest;
        let had_int = before != s.len();
        // Optional fraction.
        let mut frac: u64 = 0;
        let mut scale: f64 = 1.0;
        let mut had_frac = false;
        if s.as_bytes().first() == Some(&b'.') {
            s = &s[1..];
            let before = s.len();
            let (f, sc, rest) = leading_fraction(s);
            frac = f;
            scale = sc;
            s = rest;
            had_frac = before != s.len();
        }
        if !had_int && !had_frac {
            return Err(invalid(orig));
        }
        // The unit runs until the next digit or '.'. Those are ASCII, and a multi-byte unit (`µs`)
        // has no ASCII bytes, so this byte scan always lands on a char boundary.
        let end = s
            .as_bytes()
            .iter()
            .position(|c| *c == b'.' || c.is_ascii_digit())
            .unwrap_or(s.len());
        if end == 0 {
            return Err(format!("time: missing unit in duration {}", quoted(orig)));
        }
        let unit_name = &s[..end];
        s = &s[end..];
        let unit: u64 = match unit_name {
            "ns" => 1,
            "us" | "µs" | "\u{03bc}s" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 3_600 * 1_000_000_000,
            other => {
                return Err(format!(
                    "time: unknown unit {} in duration {}",
                    quoted(other),
                    quoted(orig)
                ));
            }
        };
        if v > (1u64 << 63) / unit {
            return Err(invalid(orig)); // Overflow.
        }
        v *= unit;
        if frac > 0 {
            // Go's float round-trip for the fractional part; the scale is a power of ten.
            v += (frac as f64 * (unit as f64 / scale)) as u64;
            if v > 1u64 << 63 {
                return Err(invalid(orig));
            }
        }
        total = total.checked_add(v).ok_or_else(|| invalid(orig))?;
        if total > 1u64 << 63 {
            return Err(invalid(orig));
        }
    }
    if neg {
        // Go negates after building the magnitude; the extreme case (exactly 1<<63) is i64::MIN,
        // which wraps in exactly the same way there.
        return Ok((total as i64).wrapping_neg());
    }
    if total > (1u64 << 63) - 1 {
        return Err(invalid(orig));
    }
    Ok(total as i64)
}

/// Consume the leading run of decimal digits, returning its value and the rest of the string — Go's
/// `leadingInt`. `None` on overflow past `i64::MAX` nanoseconds, which the caller reports as an
/// invalid duration (Go's own behavior).
fn leading_int(s: &str) -> Option<(u64, &str)> {
    let mut value: u64 = 0;
    let mut idx = 0;
    for (i, c) in s.bytes().enumerate() {
        if !c.is_ascii_digit() {
            idx = i;
            break;
        }
        // Go's two overflow guards, in Go's order and with Go's thresholds.
        if value > (1u64 << 63) / 10 {
            return None;
        }
        value = value * 10 + u64::from(c - b'0');
        if value > 1u64 << 63 {
            return None;
        }
        idx = i + 1;
    }
    Some((value, &s[idx..]))
}

/// Consume the leading run of decimal digits as a fraction, returning the digits' value, the power of
/// ten to divide it by, and the rest of the string — Go's `leadingFraction`. Digits past the point
/// where the value would overflow are consumed but ignored (again Go's behavior: they cannot change
/// the result at nanosecond resolution).
fn leading_fraction(s: &str) -> (u64, f64, &str) {
    let mut value: u64 = 0;
    let mut scale: f64 = 1.0;
    let mut overflow = false;
    let mut idx = 0;
    for (i, c) in s.bytes().enumerate() {
        if !c.is_ascii_digit() {
            idx = i;
            break;
        }
        idx = i + 1;
        if overflow {
            continue;
        }
        if value > ((1u64 << 63) - 1) / 10 {
            // Keep consuming digits, but stop accumulating.
            overflow = true;
            continue;
        }
        let next = value * 10 + u64::from(c - b'0');
        if next > 1u64 << 63 {
            overflow = true;
            continue;
        }
        value = next;
        scale *= 10.0;
    }
    (value, scale, &s[idx..])
}

/// Nanoseconds in one second, microsecond and millisecond — Go's `time.Second`, `time.Microsecond`
/// and `time.Millisecond` as raw `time.Duration` counts, named so the sub-second branch of
/// [`format_go_duration`] reads like Go's.
const SECOND: u64 = 1_000_000_000;
const MICROSECOND: u64 = 1_000;
const MILLISECOND: u64 = 1_000_000;

/// Render nanoseconds the way Go's `Duration.String()` does — `0s`, `1h0m0s`, `1.5s`, `500ms`,
/// `1.2µs`, `-2m3.4s` — a port of `func (d Duration) format` in `src/time/format.go`.
///
/// The rules that make it Go's and not a general "humanize duration": a duration of at least one
/// second is always written `[Xh][Ym]Z.FFFs` with **every** lower unit present (so one hour is
/// `1h0m0s`, never `1h`) and stops at hours (days vary in length); a shorter one picks the largest
/// unit that keeps the integer part non-zero (`ns`, `µs` — the micro SIGN `U+00B5`, not the Greek
/// letter — or `ms`); a zero duration is `0s`; fractional digits are emitted only as far as the last
/// non-zero digit, and the decimal point is dropped with them.
///
/// This is what a `DurationValue` policy setting shows in the `syspolicy list` Value column, since
/// Go's `printPolicySettings` prints the resolved value with `%v` and `time.Duration` is a
/// `fmt.Stringer`. Pure → unit-testable.
pub fn format_go_duration(d: i64) -> String {
    // Go builds the text right-to-left into a fixed 32-byte array. We push the same bytes in the
    // same order into a Vec and reverse once at the end, which is the same layout without the
    // index arithmetic (and cannot underflow a buffer).
    let neg = d < 0;
    // Go: `u := uint64(d); if neg { u = -u }`. The wrapping negation reproduces Go's behavior for
    // `i64::MIN`, whose magnitude does not fit in an i64 (both end up at exactly 1<<63).
    let mut u = d as u64;
    if neg {
        u = u.wrapping_neg();
    }
    let mut buf: Vec<u8> = Vec::with_capacity(32);

    if u < SECOND {
        // Sub-second: a single unit, chosen so the integer part is non-zero.
        buf.push(b's');
        if u == 0 {
            // Go's special case: the whole rendering is "0s" (no unit prefix, no fraction).
            return "0s".to_string();
        }
        let prec = if u < MICROSECOND {
            buf.push(b'n');
            0
        } else if u < MILLISECOND {
            // "µ" is U+00B5, two UTF-8 bytes (0xC2 0xB5); pushed reversed like every other byte, so
            // the final `reverse()` restores the correct order.
            buf.push(0xb5);
            buf.push(0xc2);
            3
        } else {
            buf.push(b'm');
            6
        };
        u = fmt_frac(&mut buf, u, prec);
        fmt_int(&mut buf, u);
    } else {
        // A second or more: seconds (with up to 9 fractional digits), then minutes, then hours.
        buf.push(b's');
        u = fmt_frac(&mut buf, u, 9);
        // `u` is now whole seconds.
        fmt_int(&mut buf, u % 60);
        u /= 60;
        if u > 0 {
            // `u` is now whole minutes.
            buf.push(b'm');
            fmt_int(&mut buf, u % 60);
            u /= 60;
            if u > 0 {
                // `u` is now whole hours. Go stops here: days are not a fixed length.
                buf.push(b'h');
                fmt_int(&mut buf, u);
            }
        }
    }

    if neg {
        buf.push(b'-');
    }
    buf.reverse();
    // Every byte pushed above is either ASCII or the two bytes of "µ" in order, so this is UTF-8.
    String::from_utf8(buf).expect("format_go_duration emits ASCII plus a well-formed U+00B5")
}

/// Emit the fractional part of `v` with at most `prec` digits and return the remaining integer part
/// — Go's `fmtFrac`. Trailing zeros (and, when every digit is zero, the decimal point itself) are
/// omitted, which is why `1.0040s` round-trips to `1.004s`. Bytes are pushed least-significant-first
/// into the reversed buffer, exactly matching Go's right-to-left writes.
fn fmt_frac(buf: &mut Vec<u8>, mut v: u64, prec: u32) -> u64 {
    let mut printing = false;
    for _ in 0..prec {
        let digit = v % 10;
        printing = printing || digit != 0;
        if printing {
            buf.push(b'0' + digit as u8);
        }
        v /= 10;
    }
    if printing {
        buf.push(b'.');
    }
    v
}

/// Emit `v` in decimal — Go's `fmtInt`, including its zero case (which writes a single `0` rather
/// than nothing). Least-significant digit first, into the reversed buffer.
fn fmt_int(buf: &mut Vec<u8>, mut v: u64) {
    if v == 0 {
        buf.push(b'0');
        return;
    }
    while v > 0 {
        buf.push(b'0' + (v % 10) as u8);
        v /= 10;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cases from the Go standard library's `TestDurationString`-adjacent table in
    /// `src/time/time_test.go`, plus the shapes a policy file actually carries (`24h`, `60m`).
    #[test]
    fn format_matches_go_duration_string() {
        let ns = 1i64;
        let us = 1_000 * ns;
        let ms = 1_000 * us;
        let sec = 1_000 * ms;
        let min = 60 * sec;
        let hour = 60 * min;

        // Zero and the sub-second units.
        assert_eq!(format_go_duration(0), "0s");
        assert_eq!(format_go_duration(ns), "1ns");
        assert_eq!(format_go_duration(1100 * ns), "1.1µs");
        assert_eq!(format_go_duration(2200 * us), "2.2ms");
        assert_eq!(format_go_duration(100 * ms), "100ms");
        // A second or more always spells out every lower unit.
        assert_eq!(format_go_duration(sec), "1s");
        assert_eq!(format_go_duration(3300 * ms), "3.3s");
        assert_eq!(format_go_duration(4 * min + 5 * sec), "4m5s");
        assert_eq!(format_go_duration(4 * min + 5001 * ms), "4m5.001s");
        assert_eq!(
            format_go_duration(5 * hour + 6 * min + 7001 * ms),
            "5h6m7.001s"
        );
        assert_eq!(format_go_duration(8 * min + ns), "8m0.000000001s");
        // The two shapes an admin is most likely to write in a policy file.
        assert_eq!(format_go_duration(24 * hour), "24h0m0s");
        assert_eq!(format_go_duration(60 * min), "1h0m0s");
        // Negatives keep the sign in front of the whole rendering.
        assert_eq!(format_go_duration(-(2 * min + 3400 * ms)), "-2m3.4s");
        assert_eq!(format_go_duration(-1), "-1ns");
        // The extreme Go can represent — `i64::MIN` has no positive counterpart, and Go prints the
        // wrapped magnitude rather than overflowing.
        assert_eq!(format_go_duration(i64::MAX), "2562047h47m16.854775807s");
        assert_eq!(format_go_duration(i64::MIN), "-2562047h47m16.854775808s");
    }

    /// The parser and the formatter are two halves of the same grammar, so what one accepts the
    /// other must render back — the property that makes `"60m"` in a policy file print as `1h0m0s`.
    #[test]
    fn parse_then_format_round_trips_through_gos_canonical_spelling() {
        for (input, canonical) in [
            ("0", "0s"),
            ("60m", "1h0m0s"),
            ("24h", "24h0m0s"),
            ("1.5h", "1h30m0s"),
            ("300ms", "300ms"),
            ("-2m3.4s", "-2m3.4s"),
            ("1478s", "24m38s"),
        ] {
            let nanos = parse_go_duration(input).expect("the case should be a valid Go duration");
            assert_eq!(
                format_go_duration(nanos),
                canonical,
                "{input:?} should render as Go's canonical {canonical:?}"
            );
        }
    }
}
