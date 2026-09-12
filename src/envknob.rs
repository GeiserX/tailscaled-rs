//! The on-disk environment file an operator sets administrative envknobs in — Go
//! `envknob.ApplyDiskConfig` / `applyKeyValueEnv` (`envknob/envknob.go`).
//!
//! Go's `tailscaled` calls `envknob.ApplyDiskConfig()` at the very top of `main`, before a single
//! flag is registered: it reads a `tailscaled-env.txt` of `KEY=value` lines and applies them to the
//! daemon's **own** environment, so every later `envknob` read sees them. That file is the answer to
//! a question a service manager does not always answer: *where does an operator put an environment
//! variable for a daemon they do not launch by hand?*
//!
//! This daemon has the same question and, until now, only half an answer. It honours administrative
//! envknobs — `TS_DISABLE_SSH_SERVER` ([`crate::featureknob`]) and `TS_DISABLE_PORTMAPPER`
//! ([`crate::portmap`]) — and on Linux the packaged systemd unit carries the seam Go's does
//! (`EnvironmentFile=-/etc/default/tailnetd`). On macOS the launchd plist has an
//! `EnvironmentVariables` dict, but that plist is embedded in the binary with `include_str!` and
//! rewritten by `tnet install` ([`crate::ipn::install`]), so anything an operator adds to it is lost
//! on the next install. There was no file the daemon reads that the installer does not own. This
//! module is that file.
//!
//! ## The path, and the platforms
//!
//! Go's `getPlatformEnvFiles` returns `%ProgramData%\Tailscale\tailscaled-env.txt` on Windows, a
//! list on darwin (`/etc/tailscale/tailscaled-env.txt` for a non-sandboxed `tailscaled`, plus
//! `$HOME/tailscaled-env.txt` and a working-directory-relative `tailscaled-env.txt` for the
//! sandboxed GUI builds), and **nothing** on ordinary Linux — deliberately, because
//! `/etc/default/tailscaled` already does the job through the service manager.
//!
//! Ported here as one path on macOS and nothing anywhere else:
//!
//! - **macOS: [`MACOS_ENV_FILE`]** (`/etc/tailnetd/tailnetd-env.txt`). Go's `/etc/tailscale` is
//!   another project's directory and this fork does not write to it; the daemon already names its
//!   Linux seam `/etc/default/tailnetd`, so the macOS one is named after the same daemon. The two
//!   `$HOME`/cwd entries in Go's darwin list belong to the sandboxed `Tailscale.app` GUI build,
//!   which has no counterpart here (see [`crate::featureknob`], which declines the same build's SSH
//!   arm for the same reason) — and a *system* daemon that picked up environment from the current
//!   working directory would be a privilege-escalation seam, not a convenience. Declined
//!   deliberately.
//! - **Linux: nothing**, exactly as in Go, and for exactly Go's reason — the packaged unit's
//!   `EnvironmentFile=-/etc/default/tailnetd` is already the supported seam, and a second one would
//!   mean two files that disagree.
//! - **Windows: nothing.** Go's entry exists because `tailscaled` is a Windows *service*; this fork
//!   installs a systemd unit or a launchd job and `tnet install` refuses every other OS, so there is
//!   no Windows daemon for the file to configure. Declined deliberately, not missed.
//!
//! ## What the parser does, and where it refuses
//!
//! [`parse_key_value_env`] is Go's `applyKeyValueEnv` line for line: trim the line, skip it if it is
//! blank or starts with `#`, cut at the **first** `=`, trim both halves, `strconv.Unquote` a value
//! that starts with a double quote, and refuse the whole file with `invalid value in line %q` if
//! that unquote fails. [`unquote_go_string`] is the double-quoted arm of Go's `strconv.Unquote`,
//! escapes and all, because the refusal is the point: an env file that half-applies leaves a daemon
//! running under an environment nobody wrote.
//!
//! Two deliberate deviations from Go, both in the direction of refusing rather than continuing:
//!
//! - **The file is parsed in full before anything is applied.** Go `Setenv`s as it scans, so a bad
//!   line on line 9 leaves lines 1–8 applied. Here the parse either yields every assignment or none.
//! - **A parse failure is fatal at startup**, not stashed. Go keeps it in `applyDiskConfigErr` for
//!   `ApplyDiskConfigError()` to hand to the health tracker, which turns an administrator's typo
//!   into a health warning. This fork has no health tracker yet, so stashing the error would mean
//!   nothing ever reads it — i.e. silence, which is the failure mode the Go code exists to prevent.
//!   Refusing at startup is the honest interim, and the error names the **line number** as well as
//!   the line so the operator can go straight to it. When the health tracker lands, the caller in
//!   `tailnetd` is the one line that has to change.
//!
//! Everything except [`apply_disk_config`] and [`load_env_file`] is pure, so the parser and the path
//! choice are unit-testable on any host without touching the process environment.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

/// The macOS operator env file — this fork's `tailscaled-env.txt`, under this daemon's own name.
///
/// Documented next to the launchd job that needs it
/// (`packaging/launchd/cloud.tailscaled-rs.tailnetd.plist` and `packaging/README.md`); the plist's
/// own `EnvironmentVariables` dict is install-owned and rewritten by `tnet install`, this file is
/// not.
pub const MACOS_ENV_FILE: &str = "/etc/tailnetd/tailnetd-env.txt";

/// [`MACOS_ENV_FILE`] as the one-element list [`platform_env_files`] hands back on macOS.
const MACOS_ENV_FILES: [&str; 1] = [MACOS_ENV_FILE];

/// The env files to try, in order, on host OS `os` (`std::env::consts::OS` spelling) — Go
/// `getPlatformEnvFiles`.
///
/// Empty means "this platform has no env file", which is a supported answer, not a gap: it is what
/// Go returns on ordinary Linux. See the module docs for why each platform gets what it gets.
pub fn platform_env_files(os: &str) -> &'static [&'static str] {
    match os {
        "macos" => &MACOS_ENV_FILES,
        _ => &[],
    }
}

/// One `KEY=value` assignment read out of an env file.
///
/// The value is bytes, not a `String`, because Go's `strconv.Unquote` can produce arbitrary bytes
/// (`\xff`, `\377`) and a unix environment can hold them. It reaches the process environment through
/// an `OsString`, so a value Go would have accepted is not refused here for not being UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The variable name: everything before the first `=`, trimmed.
    pub key: String,
    /// The value: everything after the first `=`, trimmed, and unquoted when it began with `"`.
    pub value: Vec<u8>,
}

/// Why an env file was refused. Carries the offending line and its 1-based number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line number, so an operator can open the file at the fault.
    pub line_number: usize,
    /// The offending line, trimmed — Go's `%q` argument.
    pub line: String,
    /// What was wrong with it.
    pub kind: ParseErrorKind,
}

/// The two ways a line can be refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A double-quoted value that `strconv.Unquote` rejects — Go's only refusal here. Go renders the
    /// cause as `strconv.ErrSyntax`'s `invalid syntax`, which is the one error `Unquote` returns.
    InvalidValue,
    /// A NUL byte in the key or the value. Go's `os.Setenv` returns `EINVAL` for this and
    /// `envknob.Setenv` discards the error; Rust's `std::env::set_var` **panics**, so the choice is
    /// between refusing the file and aborting the daemon with a panic message. Refuse, and say so.
    NulByte,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            // Go: fmt.Errorf("invalid value in line %q: %v", line, err), where err is always
            // strconv.ErrSyntax. The line number is this fork's addition.
            ParseErrorKind::InvalidValue => write!(
                f,
                "line {}: invalid value in line {:?}: invalid syntax",
                self.line_number, self.line
            ),
            ParseErrorKind::NulByte => write!(
                f,
                "line {}: invalid NUL byte in line {:?}",
                self.line_number, self.line
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Go `applyKeyValueEnv`, minus the `Setenv`: parse `contents` into the assignments it asks for.
///
/// Returns **every** assignment or **none** — see the module docs on why this does not apply as it
/// goes. Lines that are blank, comment (`#`) or have no `=` at all are skipped silently, as Go skips
/// them; an empty key (a line that is just `=…`) is skipped too, since there is no such variable to
/// set.
pub fn parse_key_value_env(contents: &str) -> Result<Vec<Assignment>, ParseError> {
    let mut out = Vec::new();
    for (i, raw) in contents.lines().enumerate() {
        let line_number = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Go: strings.Cut(line, "=") — the FIRST `=`, so a value may contain more of them.
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        let value = if value.starts_with('"') {
            unquote_go_string(value).map_err(|()| ParseError {
                line_number,
                line: line.to_string(),
                kind: ParseErrorKind::InvalidValue,
            })?
        } else {
            value.as_bytes().to_vec()
        };
        if key.as_bytes().contains(&0) || value.contains(&0) {
            return Err(ParseError {
                line_number,
                line: line.to_string(),
                kind: ParseErrorKind::NulByte,
            });
        }
        out.push(Assignment {
            key: key.to_string(),
            value,
        });
    }
    Ok(out)
}

/// The double-quoted arm of Go `strconv.Unquote`, returning the bytes of the literal `s`.
///
/// `s` is the trimmed value, which the caller has already established starts with `"`. Go requires
/// the literal to be *complete* — same quote at both ends, no raw newline inside, no unescaped
/// quote, every escape valid — and returns `strconv.ErrSyntax` for anything else, which is why the
/// error here carries no detail: there is only one.
///
/// Escapes are Go's `unquoteChar`: `\a \b \f \n \r \t \v \\ \"`, `\xHH` (one raw byte), `\nnn`
/// (exactly three octal digits, `<= 255`, one raw byte), `\uHHHH` and `\UHHHHHHHH` (a rune, UTF-8
/// encoded, rejected if it is not a valid rune — surrogates and anything above U+10FFFF). `\'` is an
/// error inside a double-quoted literal, as it is in Go.
fn unquote_go_string(s: &str) -> Result<Vec<u8>, ()> {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[bytes.len() - 1] != b'"' {
        return Err(());
    }
    let inner = &s[1..s.len() - 1];
    if inner.contains('\n') {
        return Err(());
    }
    let mut out = Vec::with_capacity(inner.len());
    let mut rest = inner;
    while !rest.is_empty() {
        let consumed = unquote_char(rest, &mut out)?;
        rest = &rest[consumed..];
    }
    Ok(out)
}

/// One character of a double-quoted Go literal — Go `unquoteChar` with `quote == '"'`. Appends the
/// decoded bytes to `out` and returns how many bytes of `s` it consumed.
fn unquote_char(s: &str, out: &mut Vec<u8>) -> Result<usize, ()> {
    let bytes = s.as_bytes();
    match bytes[0] {
        // An unescaped closing quote inside the literal: Go's first "easy case" error.
        b'"' => return Err(()),
        // Not an escape: copy the character through (a multibyte rune copies whole).
        c if c != b'\\' => {
            let len = s.chars().next().map(char::len_utf8).ok_or(())?;
            out.extend_from_slice(&bytes[..len]);
            return Ok(len);
        }
        _ => {}
    }
    if bytes.len() < 2 {
        return Err(());
    }
    // The one-byte escapes. `\'` is deliberately NOT among them: Go's `case '\'', '"'` accepts the
    // escaped quote only when it matches the quote we are inside, which here is always `"`.
    let one_byte = match bytes[1] {
        b'a' => Some(0x07),
        b'b' => Some(0x08),
        b'f' => Some(0x0c),
        b'n' => Some(b'\n'),
        b'r' => Some(b'\r'),
        b't' => Some(b'\t'),
        b'v' => Some(0x0b),
        b'\\' => Some(b'\\'),
        b'"' => Some(b'"'),
        _ => None,
    };
    if let Some(v) = one_byte {
        out.push(v);
        return Ok(2);
    }
    match bytes[1] {
        // Hex / unicode escapes: exactly n digits. `\x` is one raw BYTE (it may be invalid UTF-8 on
        // its own, which is legal in Go); `\u`/`\U` are runes and must be valid ones.
        c @ (b'x' | b'u' | b'U') => {
            let n = match c {
                b'x' => 2,
                b'u' => 4,
                _ => 8,
            };
            let digits = s.get(2..2 + n).ok_or(())?;
            // Checked per digit first: `from_str_radix` would accept a leading `+`/`-`, which Go's
            // `unhex` does not.
            if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(());
            }
            let v = u32::from_str_radix(digits, 16).map_err(|_| ())?;
            if c == b'x' {
                out.push(v as u8);
            } else {
                // Go: utf8.ValidRune — rejects surrogate halves and anything above U+10FFFF, which
                // is exactly what char::from_u32 rejects.
                let ch = char::from_u32(v).ok_or(())?;
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            Ok(2 + n)
        }
        // Octal: exactly three digits INCLUDING this one, value <= 255, one raw byte.
        b'0'..=b'7' => {
            let digits = s.get(1..4).ok_or(())?;
            if !digits.bytes().all(|b| b.is_ascii_digit() && b < b'8') {
                return Err(());
            }
            let v = u32::from_str_radix(digits, 8).map_err(|_| ())?;
            if v > 255 {
                return Err(());
            }
            out.push(v as u8);
            Ok(4)
        }
        _ => Err(()),
    }
}

/// Read and parse one env file. `Ok(None)` means the file is not there, which is the normal case and
/// never an error (Go skips a missing entry and moves on to the next).
///
/// The error is already operator-facing: it carries Go's `error parsing <path>:` prefix, so the
/// caller can print it as-is.
///
/// The file itself must be UTF-8 (an env file is text an administrator typed). Go scans bytes, but
/// its `strconv.Unquote` replaces an invalid raw byte with U+FFFD rather than preserving it, so
/// nothing is lost by refusing the file outright and saying which one it was. Escapes that *produce*
/// non-UTF-8 bytes (`\xff`) are unaffected — see [`Assignment::value`].
pub fn load_env_file(path: &Path) -> Result<Option<Vec<Assignment>>, anyhow::Error> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // Go's ApplyDiskConfig wraps every failure the same way, including the read itself.
        Err(e) => {
            return Err(anyhow::anyhow!("error parsing {}: {e}", path.display()));
        }
    };
    let assignments = parse_key_value_env(&contents)
        .map_err(|e| anyhow::anyhow!("error parsing {}: {e}", path.display()))?;
    Ok(Some(assignments))
}

/// What [`apply_disk_config`] applied, for the one startup log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The file the assignments came from.
    pub path: PathBuf,
    /// The variable names that were set, in file order — names only: a value may be a secret.
    pub keys: Vec<String>,
}

/// Go `envknob.ApplyDiskConfig`: find this platform's env file, apply it to **our own** environment,
/// and report what was applied.
///
/// `Ok(None)` = this platform has no env file, or it has one and the operator has not created it.
/// The error is fatal by intent — see the module docs on why a parse failure refuses the daemon
/// rather than being stashed for a health tracker that does not exist yet.
///
/// # Safety / ordering
///
/// This mutates the process environment, so it must run **before any other thread exists** —
/// `tailnetd` calls it from a synchronous `main`, before the tokio runtime is built. Calling it from
/// a running daemon would race every `std::env::var` in the process.
pub fn apply_disk_config() -> Result<Option<Applied>, anyhow::Error> {
    for name in platform_env_files(std::env::consts::OS) {
        let path = Path::new(name);
        let Some(assignments) = load_env_file(path)? else {
            continue;
        };
        let keys = assignments.iter().map(|a| a.key.clone()).collect();
        for Assignment { key, value } in assignments {
            // SAFETY: called from `main` before the tokio runtime (and so any other thread) exists,
            // which is the documented contract above. `key` is non-empty, contains no `=` (the line
            // was cut at the first one) and neither half contains a NUL — `parse_key_value_env`
            // refuses all three, which are exactly `set_var`'s panic conditions.
            unsafe { std::env::set_var(&key, os_value(value)) };
        }
        return Ok(Some(Applied {
            path: path.to_path_buf(),
            keys,
        }));
    }
    Ok(None)
}

/// A parsed value as the OS spells it. On unix the bytes go through untouched, so a `\xff` Go would
/// have set is set here too; off unix (where [`platform_env_files`] is empty, so this is unreachable)
/// the bytes are read as UTF-8 lossily rather than growing a second representation.
fn os_value(value: Vec<u8>) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(value)
    }
    #[cfg(not(unix))]
    {
        OsString::from(String::from_utf8_lossy(&value).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the expected assignment list compactly.
    fn assigns(pairs: &[(&str, &[u8])]) -> Vec<Assignment> {
        pairs
            .iter()
            .map(|(k, v)| Assignment {
                key: (*k).to_string(),
                value: v.to_vec(),
            })
            .collect()
    }

    #[test]
    fn platform_list_is_macos_only() {
        // macOS is the platform with the gap: its launchd plist is install-owned, so the env file is
        // the only operator seam. Linux deliberately has none (the systemd unit's
        // `EnvironmentFile=-/etc/default/tailnetd` is it, exactly as Go leaves Linux empty), and no
        // other platform has a daemon this fork installs.
        assert_eq!(platform_env_files("macos"), &[MACOS_ENV_FILE]);
        assert!(platform_env_files("linux").is_empty());
        assert!(platform_env_files("windows").is_empty());
        assert!(platform_env_files("freebsd").is_empty());
    }

    #[test]
    fn env_file_is_under_this_daemons_own_directory() {
        // Not Go's /etc/tailscale — that is another project's directory, and this daemon already
        // names its Linux seam after itself (/etc/default/tailnetd).
        assert_eq!(MACOS_ENV_FILE, "/etc/tailnetd/tailnetd-env.txt");
        assert!(!MACOS_ENV_FILE.contains("tailscale"));
    }

    #[test]
    fn parses_plain_lines_and_skips_blanks_and_comments() {
        // Go's applyKeyValueEnv: trim, skip blank and `#` lines, cut at the first `=`, trim both
        // halves.
        let got = parse_key_value_env(
            "\n  \n# a comment\n   # indented comment\nTS_DISABLE_SSH_SERVER=1\n  TS_DISABLE_PORTMAPPER = true  \n",
        )
        .expect("valid file");
        assert_eq!(
            got,
            assigns(&[
                ("TS_DISABLE_SSH_SERVER", b"1"),
                ("TS_DISABLE_PORTMAPPER", b"true"),
            ])
        );
    }

    #[test]
    fn cuts_at_the_first_equals_only() {
        // A value may contain `=` (a URL query, a base64 pad); only the first one separates.
        let got = parse_key_value_env("TS_DEBUG=a=b=c\n").expect("valid file");
        assert_eq!(got, assigns(&[("TS_DEBUG", b"a=b=c")]));
    }

    #[test]
    fn skips_lines_without_an_equals_and_lines_with_an_empty_key() {
        // Go `strings.Cut` reports no separator → skip; an empty key names no variable → skip. Both
        // are silent in Go, and neither invalidates the rest of the file.
        let got = parse_key_value_env("not an assignment\n=value\n   =value\nTS_OK=1\n")
            .expect("valid file");
        assert_eq!(got, assigns(&[("TS_OK", b"1")]));
    }

    #[test]
    fn keeps_an_empty_value() {
        // `KEY=` sets the variable to the empty string; it is not the same as leaving it unset, and
        // Go does not skip it.
        let got = parse_key_value_env("TS_DEBUG=\n").expect("valid file");
        assert_eq!(got, assigns(&[("TS_DEBUG", b"")]));
    }

    #[test]
    fn unquotes_a_double_quoted_value() {
        // A quoted value is how an operator keeps leading/trailing spaces and `#` through the trim.
        let got = parse_key_value_env("TS_DEBUG=\"  spaced # value  \"\n").expect("valid file");
        assert_eq!(got, assigns(&[("TS_DEBUG", b"  spaced # value  ")]));
    }

    #[test]
    fn unquote_handles_gos_escape_set() {
        let got = parse_key_value_env(
            "A=\"tab\\there\"\nB=\"q\\\"uote\"\nC=\"back\\\\slash\"\nD=\"\\x41\\101\"\nE=\"\\u00e9\"\nF=\"\\U0001F600\"\n",
        )
        .expect("valid file");
        assert_eq!(
            got,
            assigns(&[
                ("A", b"tab\there"),
                ("B", b"q\"uote"),
                ("C", b"back\\slash"),
                // \x41 and \101 are both 'A'.
                ("D", b"AA"),
                // A rune escape is UTF-8 encoded, not a raw byte.
                ("E", "é".as_bytes()),
                ("F", "😀".as_bytes()),
            ])
        );
    }

    #[test]
    fn unquote_keeps_a_raw_byte_escape_that_is_not_utf8() {
        // Go's Unquote yields bytes, and `\xff` alone is not valid UTF-8. Refusing it here would be
        // a refusal Go does not have, so the value is carried as bytes all the way to `set_var`.
        let got = parse_key_value_env("TS_DEBUG=\"\\xff\"\n").expect("valid file");
        assert_eq!(got, assigns(&[("TS_DEBUG", &[0xff])]));
    }

    #[test]
    fn refuses_an_unterminated_quoted_value_with_the_line_and_number() {
        // THE refusal Go has: `strconv.Unquote` fails, the whole file is rejected. The line number is
        // this fork's addition — the error is printed at startup instead of being stashed for a
        // health tracker, so it has to be enough to find the fault with.
        let err = parse_key_value_env("TS_OK=1\n\nTS_DEBUG=\"unterminated\n").expect_err("refused");
        assert_eq!(err.kind, ParseErrorKind::InvalidValue);
        assert_eq!(err.line_number, 3);
        assert_eq!(err.line, "TS_DEBUG=\"unterminated");
        assert_eq!(
            err.to_string(),
            "line 3: invalid value in line \"TS_DEBUG=\\\"unterminated\": invalid syntax"
        );
    }

    #[test]
    fn refuses_every_escape_go_refuses() {
        // Each of these is `strconv.ErrSyntax` in Go: an unknown escape, a `\'` inside a
        // double-quoted literal, a short hex escape, a non-octal digit in an octal escape, an octal
        // value above 255, a surrogate half, a rune above U+10FFFF, an unescaped inner quote, and a
        // trailing lone backslash.
        for bad in [
            "K=\"\\q\"",
            "K=\"\\'\"",
            "K=\"\\xF\"",
            "K=\"\\08\"",
            "K=\"\\777\"",
            "K=\"\\ud800\"",
            "K=\"\\U00110000\"",
            "K=\"in\"ner\"",
            "K=\"trailing\\\"",
        ] {
            let err = parse_key_value_env(bad)
                .err()
                .unwrap_or_else(|| panic!("expected {bad:?} to be refused"));
            assert_eq!(
                err.kind,
                ParseErrorKind::InvalidValue,
                "{bad:?} must be refused as an invalid value"
            );
            assert_eq!(err.line, bad);
        }
    }

    #[test]
    fn refuses_a_nul_byte_rather_than_panicking_in_set_var() {
        // Go's os.Setenv returns EINVAL and envknob discards it; Rust's set_var panics, so the file
        // is refused with a message instead of the daemon aborting.
        let err = parse_key_value_env("TS_DEBUG=\"a\\x00b\"\n").expect_err("refused");
        assert_eq!(err.kind, ParseErrorKind::NulByte);
        assert_eq!(err.line_number, 1);
    }

    #[test]
    fn an_unquoted_value_is_taken_verbatim() {
        // Only a value that STARTS with a quote is unquoted; a bare backslash in an unquoted value is
        // a backslash, not a broken escape (a Windows-style path must not be refused).
        let got = parse_key_value_env("TS_DEBUG=C:\\not\\an\\escape\n").expect("valid file");
        assert_eq!(got, assigns(&[("TS_DEBUG", b"C:\\not\\an\\escape")]));
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        // The normal case on almost every host: no file, no assignments, no complaint.
        let path = std::env::temp_dir().join(format!(
            "tailnetd-envfile-absent-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        assert_eq!(load_env_file(&path).expect("absent file is Ok"), None);
    }

    #[test]
    fn load_env_file_reads_parses_and_names_the_path_on_refusal() {
        // The read+parse path a real host takes, against a real file — including the operator-facing
        // wrapping, which must name the file (Go: "error parsing %s: %w") as well as the line.
        let path = std::env::temp_dir().join(format!(
            "tailnetd-envfile-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, "# knobs\nTS_DISABLE_SSH_SERVER=1\n").expect("write env file");
        let got = load_env_file(&path).expect("valid file");
        assert_eq!(got, Some(assigns(&[("TS_DISABLE_SSH_SERVER", b"1")])));

        std::fs::write(&path, "TS_DISABLE_SSH_SERVER=\"1\n").expect("write bad env file");
        let err = load_env_file(&path).expect_err("refused").to_string();
        let _ = std::fs::remove_file(&path);
        assert!(
            err.starts_with(&format!("error parsing {}: ", path.display())),
            "error must name the file it refused: {err}"
        );
        assert!(
            err.contains("line 1: invalid value in line"),
            "error must name the line: {err}"
        );
    }
}
