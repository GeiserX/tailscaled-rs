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
//! ## The `TS_DEBUG_ENV_FILE` override
//!
//! Go reads `TS_DEBUG_ENV_FILE` **before** `getPlatformEnvFiles`, and a file named there that cannot
//! be opened is an error rather than a miss that falls through to the platform list. Ported as it
//! stands ([`TS_DEBUG_ENV_FILE`]), and it is the thing that gives Linux — where
//! [`platform_env_files`] is deliberately empty — any env file at all, which is exactly its role
//! upstream. It is not a new privilege seam: whoever can set that variable already controls the
//! daemon's entire environment, which is strictly more than the file can express. The
//! *cwd*-relative entry in Go's darwin list is a different thing and is still declined above,
//! because that one is reachable without setting anything.
//!
//! ## What the parser does, and where it refuses
//!
//! [`parse_key_value_env`] is Go's `applyKeyValueEnv` line for line: trim the line, skip it if it is
//! blank or starts with `#`, cut at the **first** `=`, trim both halves, `strconv.Unquote` a value
//! that starts with a double quote, and stop the scan with `invalid value in line %q` if that
//! unquote fails. [`unquote_go_string`] is the double-quoted arm of Go's `strconv.Unquote`, escapes
//! and all.
//!
//! Go `Setenv`s each assignment *as it scans*, so the scan has three outcomes at once and
//! [`ParsedEnv`] keeps all three:
//!
//! - **`assignments`** — the lines the scan reached and could set, in file order. A line below a
//!   refusal is not among them, because Go returns at the refusal and never reaches it either.
//! - **`refusal`** — the line that stopped the scan, if any. The lines **above** it stay applied,
//!   exactly as in Go: a `TS_DISABLE_SSH_SERVER=1` on line 1 takes effect even if line 9 is a typo.
//!   The message adds the line number to Go's, so an operator reading one log line can open the file
//!   at the fault.
//! - **`skipped`** — a key or value holding a NUL byte. Go's `os.Setenv` returns `EINVAL` for it and
//!   `envknob.Setenv` discards that error, so the line does not apply and the scan carries on;
//!   Rust's `std::env::set_var` **panics** instead, so the line is dropped here before it can get
//!   that far. Same end state as Go, reached without aborting the process.
//!
//! One deliberate deviation, and it only adds words: Go drops a NUL line silently, this fork carries
//! it out as a problem for the daemon to log. Nothing Go applies is refused here, and nothing Go
//! refuses is applied.
//!
//! ## A malformed file does not stop the daemon
//!
//! Go's `tailscaled` calls `envknob.ApplyDiskConfig()` for its effect and discards the result; the
//! error is stashed in `applyDiskConfigErr`, and `run` reports it with
//! `log.Printf("Error reading environment config: %v", err)` after which the daemon starts normally.
//! This fork does the same. The problems ride out of [`apply_disk_config`] in [`Applied::problems`]
//! and `tailnetd` prints one line for each from where Go's `run` prints its — after the flag parse,
//! so `--help` stays quiet, and before `--cleanup`, so a cleanup run still says it. They are carried
//! rather than printed here because [`apply_disk_config`] runs before clap: a message from this
//! module would beat `--help` to the terminal.
//!
//! An earlier revision exited instead, reasoning that a stashed error nothing reads is silence. The
//! log line is what removes that reason, and it removes it without the cost: an optional file with
//! one typo in it must not be why a mesh node fails to come back after a reboot, because the
//! operator who would fix the typo is the one who just lost their route to the host.
//!
//! Everything except [`apply_disk_config`] and [`load_disk_config`] is pure, and `load_disk_config`
//! takes both the override and the platform list as arguments, so every branch here is testable on
//! any host without touching the process environment.

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

/// The environment variable that names an env file explicitly, ahead of [`platform_env_files`] —
/// Go `ApplyDiskConfig`'s `os.Getenv("TS_DEBUG_ENV_FILE")`.
///
/// Kept under Go's own spelling, not renamed after this daemon: an operator reaching for it is
/// following `tailscaled` documentation or a habit, and a variable that exists under a different
/// name is a variable that silently does nothing.
pub const TS_DEBUG_ENV_FILE: &str = "TS_DEBUG_ENV_FILE";

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

/// The two ways a line can fail to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A double-quoted value that `strconv.Unquote` rejects — Go's only refusal here, and the one
    /// that ends the scan. Go renders the cause as `strconv.ErrSyntax`'s `invalid syntax`, which is
    /// the one error `Unquote` returns.
    InvalidValue,
    /// A NUL byte in the key or the value, which skips the line and lets the scan continue. Go's
    /// `os.Setenv` returns `EINVAL` for this and `envknob.Setenv` discards the error, so the line is
    /// simply not set; Rust's `std::env::set_var` **panics**, so the line has to be dropped before
    /// it reaches it. Same outcome, without taking the daemon down on the way.
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

/// What one scan of an env file produced — Go `applyKeyValueEnv`'s effect and its return value,
/// separated so the caller can do the applying.
///
/// Go has all three of these at once: the `Setenv` calls it already made, the line it returned an
/// error on, and the lines its `Setenv` quietly declined. See the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedEnv {
    /// The assignments to apply, in file order: every line the scan reached and could set.
    pub assignments: Vec<Assignment>,
    /// Lines dropped without stopping the scan — a key or value with a NUL byte in it.
    pub skipped: Vec<ParseError>,
    /// The line that ended the scan, if one did. Everything in `assignments` is from above it.
    pub refusal: Option<ParseError>,
}

/// Go `applyKeyValueEnv`, minus the `Setenv`: scan `contents` and report what it asks for.
///
/// Lines that are blank, comment (`#`) or have no `=` at all are skipped silently, as Go skips them;
/// an empty key (a line that is just `=…`) is skipped too, since there is no such variable to set.
/// An unquotable value stops the scan — the lines already gathered are the ones Go would have
/// applied before it returned.
pub fn parse_key_value_env(contents: &str) -> ParsedEnv {
    let mut parsed = ParsedEnv::default();
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
            match unquote_go_string(value) {
                Ok(v) => v,
                // Go returns here, so the scan ends and the lines below are never applied.
                Err(()) => {
                    parsed.refusal = Some(ParseError {
                        line_number,
                        line: line.to_string(),
                        kind: ParseErrorKind::InvalidValue,
                    });
                    break;
                }
            }
        } else {
            value.as_bytes().to_vec()
        };
        // Go hands this to `os.Setenv`, gets EINVAL and throws it away; the rest of the file still
        // applies. Drop the line and keep going — `set_var` would panic on it.
        if key.as_bytes().contains(&0) || value.contains(&0) {
            parsed.skipped.push(ParseError {
                line_number,
                line: line.to_string(),
                kind: ParseErrorKind::NulByte,
            });
            continue;
        }
        parsed.assignments.push(Assignment {
            key: key.to_string(),
            value,
        });
    }
    parsed
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

/// One env file, read and scanned: what it asks the process environment to be, and what in it could
/// not be honoured.
///
/// `path` is `None` only when no file was read at all — the normal case on Linux, where
/// [`platform_env_files`] is empty, and on any host whose file does not exist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DiskConfig {
    path: Option<PathBuf>,
    assignments: Vec<Assignment>,
    problems: Vec<String>,
}

/// Scan one file's `contents` and phrase whatever did not apply the way an operator needs to read it
/// — Go wraps the scan's error as `error parsing %s: %w`, and the file name is half of what makes
/// the message actionable.
fn scan_file(path: &Path, contents: &str) -> DiskConfig {
    let ParsedEnv {
        assignments,
        skipped,
        refusal,
    } = parse_key_value_env(contents);
    let mut problems: Vec<String> = skipped
        .iter()
        .map(|e| {
            format!(
                "error parsing {}: {e} (line skipped; the rest of the file applied)",
                path.display()
            )
        })
        .collect();
    if let Some(e) = &refusal {
        problems.push(format!(
            "error parsing {}: {e} (that line and every line below it was not applied)",
            path.display()
        ));
    }
    DiskConfig {
        path: Some(path.to_path_buf()),
        assignments,
        problems,
    }
}

/// Go `ApplyDiskConfig`'s file selection and scan, minus the `Setenv`: read the first env file that
/// exists and report what it asks for.
///
/// `explicit` is [`TS_DEBUG_ENV_FILE`]'s value, and takes the whole decision when it is set: Go
/// returns straight after it, so a file named there that cannot be opened is a problem and **not** a
/// miss that falls through to `files`. `files` is [`platform_env_files`] for the running host; a
/// missing entry is skipped, as Go skips `os.IsNotExist`.
///
/// Both are arguments rather than reads of the process state so that every branch is testable
/// without mutating the environment of the test process.
///
/// The file itself must be UTF-8 (an env file is text an administrator typed). Go scans bytes, but
/// its `strconv.Unquote` replaces an invalid raw byte with U+FFFD rather than preserving it, so
/// nothing is lost by reporting the file instead of guessing at it. Escapes that *produce* non-UTF-8
/// bytes (`\xff`) are unaffected — see [`Assignment::value`].
fn load_disk_config(explicit: Option<&Path>, files: &[&str]) -> DiskConfig {
    if let Some(path) = explicit {
        return match std::fs::read_to_string(path) {
            Ok(contents) => scan_file(path, &contents),
            // Go: fmt.Errorf("error opening explicitly configured TS_DEBUG_ENV_FILE: %w", err),
            // wrapped by the deferred "error applying disk config" because no file was opened.
            // `read_to_string` also lands here for a file that is not UTF-8 — see the note above.
            Err(e) => DiskConfig {
                path: Some(path.to_path_buf()),
                assignments: Vec::new(),
                problems: vec![format!(
                    "error applying disk config: error opening explicitly configured {TS_DEBUG_ENV_FILE} {}: {e}",
                    path.display()
                )],
            },
        };
    }
    let mut problems = Vec::new();
    for name in files {
        let path = Path::new(name);
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let mut config = scan_file(path, &contents);
                // Anything that went wrong with an earlier entry is still worth saying.
                problems.append(&mut config.problems);
                config.problems = problems;
                return config;
            }
            // The normal case on almost every host: no file, nothing to apply, no complaint.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            // Go collects these and carries on to the next candidate.
            Err(e) => problems.push(format!(
                "error applying disk config: {}: {e}",
                path.display()
            )),
        }
    }
    DiskConfig {
        path: None,
        assignments: Vec::new(),
        problems,
    }
}

/// What [`apply_disk_config`] did, for the startup log lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
    /// The file the assignments came from, if one was read.
    pub path: Option<PathBuf>,
    /// The variable names that were set, in file order — names only: a value may be a secret.
    pub keys: Vec<String>,
    /// Operator-facing text for everything the file asked for that did **not** apply, ready to log
    /// one line each. Empty is the normal case.
    ///
    /// These are carried rather than printed because [`apply_disk_config`] runs before the logger
    /// exists, and they are not fatal: Go stashes the same text in `applyDiskConfigErr` and prints
    /// it from `run` — `log.Printf("Error reading environment config: %v", err)` — with the daemon
    /// already on its way up. When this fork grows a health tracker, this is what it reads.
    pub problems: Vec<String>,
}

/// Go `envknob.ApplyDiskConfig`: find the env file, apply it to **our own** environment, and report
/// what was applied and what was not.
///
/// A file that is absent, or a platform that has none, is the empty [`Applied`] and not a problem.
/// Nothing here is fatal — see the module docs on why a typo in an optional file must not be the
/// reason a node does not come back up.
///
/// # Safety / ordering
///
/// This mutates the process environment, so it must run **before any other thread exists** —
/// `tailnetd` calls it from a synchronous `main`, before the tokio runtime is built. Calling it from
/// a running daemon would race every `std::env::var` in the process.
pub fn apply_disk_config() -> Applied {
    let explicit = explicit_env_file(std::env::var_os(TS_DEBUG_ENV_FILE));
    let config = load_disk_config(
        explicit.as_deref(),
        platform_env_files(std::env::consts::OS),
    );
    let keys = config.assignments.iter().map(|a| a.key.clone()).collect();
    for Assignment { key, value } in config.assignments {
        // SAFETY: called from `main` before the tokio runtime (and so any other thread) exists,
        // which is the documented contract above. `key` is non-empty, contains no `=` (the line
        // was cut at the first one) and neither half contains a NUL — `parse_key_value_env` drops
        // all three, which are exactly `set_var`'s panic conditions.
        unsafe { std::env::set_var(&key, os_value(value)) };
    }
    Applied {
        path: config.path,
        keys,
        problems: config.problems,
    }
}

/// [`TS_DEBUG_ENV_FILE`]'s value as a path, or `None` when it is unset **or empty** — Go tests
/// `os.Getenv(…) != ""`, so exporting it empty is the same as not exporting it, which is how a unit
/// file or a wrapper script turns the override back off.
fn explicit_env_file(value: Option<OsString>) -> Option<PathBuf> {
    let name = value?;
    if name.is_empty() {
        return None;
    }
    Some(PathBuf::from(name))
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

    /// What a clean file asks for: a scan that neither stopped nor dropped a line.
    fn applied(contents: &str) -> Vec<Assignment> {
        let parsed = parse_key_value_env(contents);
        assert_eq!(parsed.refusal, None, "unexpected refusal in {contents:?}");
        assert!(
            parsed.skipped.is_empty(),
            "unexpected skipped line in {contents:?}: {:?}",
            parsed.skipped
        );
        parsed.assignments
    }

    /// A scratch path of our own. Keyed by pid and thread so parallel tests cannot collide.
    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tailnetd-envknob-{tag}-{}-{:?}.txt",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    /// Write `contents` to a scratch file and hand back its path.
    fn temp_file(tag: &str, contents: &str) -> PathBuf {
        let path = temp_path(tag);
        std::fs::write(&path, contents).expect("write scratch env file");
        path
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
    fn the_override_variable_keeps_gos_spelling() {
        // An operator reaching for this is following `tailscaled` documentation or muscle memory. A
        // variable renamed after this daemon would be one that silently does nothing.
        assert_eq!(TS_DEBUG_ENV_FILE, "TS_DEBUG_ENV_FILE");
    }

    #[test]
    fn parses_plain_lines_and_skips_blanks_and_comments() {
        // Go's applyKeyValueEnv: trim, skip blank and `#` lines, cut at the first `=`, trim both
        // halves.
        let got = applied(
            "\n  \n# a comment\n   # indented comment\nTS_DISABLE_SSH_SERVER=1\n  TS_DISABLE_PORTMAPPER = true  \n",
        );
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
        assert_eq!(
            applied("TS_DEBUG=a=b=c\n"),
            assigns(&[("TS_DEBUG", b"a=b=c")])
        );
    }

    #[test]
    fn skips_lines_without_an_equals_and_lines_with_an_empty_key() {
        // Go `strings.Cut` reports no separator → skip; an empty key names no variable → skip. Both
        // are silent in Go, and neither stops the scan.
        let got = applied("not an assignment\n=value\n   =value\nTS_OK=1\n");
        assert_eq!(got, assigns(&[("TS_OK", b"1")]));
    }

    #[test]
    fn keeps_an_empty_value() {
        // `KEY=` sets the variable to the empty string; it is not the same as leaving it unset, and
        // Go does not skip it.
        assert_eq!(applied("TS_DEBUG=\n"), assigns(&[("TS_DEBUG", b"")]));
    }

    #[test]
    fn unquotes_a_double_quoted_value() {
        // A quoted value is how an operator keeps leading/trailing spaces and `#` through the trim.
        let got = applied("TS_DEBUG=\"  spaced # value  \"\n");
        assert_eq!(got, assigns(&[("TS_DEBUG", b"  spaced # value  ")]));
    }

    #[test]
    fn unquote_handles_gos_escape_set() {
        let got = applied(
            "A=\"tab\\there\"\nB=\"q\\\"uote\"\nC=\"back\\\\slash\"\nD=\"\\x41\\101\"\nE=\"\\u00e9\"\nF=\"\\U0001F600\"\n",
        );
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
        assert_eq!(
            applied("TS_DEBUG=\"\\xff\"\n"),
            assigns(&[("TS_DEBUG", &[0xff])])
        );
    }

    #[test]
    fn an_unquoted_value_is_taken_verbatim() {
        // Only a value that STARTS with a quote is unquoted; a bare backslash in an unquoted value is
        // a backslash, not a broken escape (a Windows-style path must not be refused).
        let got = applied("TS_DEBUG=C:\\not\\an\\escape\n");
        assert_eq!(got, assigns(&[("TS_DEBUG", b"C:\\not\\an\\escape")]));
    }

    #[test]
    fn a_refused_line_stops_the_scan_and_keeps_the_lines_above_it() {
        // Go Setenvs as it scans and RETURNS at the bad line: line 1 is already in the environment
        // when the error surfaces, and line 4 is never reached. Keeping the prefix is what makes a
        // non-fatal parse error safe — an operator's `TS_DISABLE_SSH_SERVER=1` must not quietly stop
        // applying because of a typo further down the same file.
        let parsed =
            parse_key_value_env("TS_DISABLE_SSH_SERVER=1\n\nTS_DEBUG=\"unterminated\nTS_BELOW=1\n");
        assert_eq!(
            parsed.assignments,
            assigns(&[("TS_DISABLE_SSH_SERVER", b"1")])
        );
        let refusal = parsed.refusal.expect("the bad line is a refusal");
        assert_eq!(refusal.kind, ParseErrorKind::InvalidValue);
        assert_eq!(refusal.line_number, 3);
        assert_eq!(refusal.line, "TS_DEBUG=\"unterminated");
        assert_eq!(
            refusal.to_string(),
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
            let refusal = parse_key_value_env(bad)
                .refusal
                .unwrap_or_else(|| panic!("expected {bad:?} to be refused"));
            assert_eq!(
                refusal.kind,
                ParseErrorKind::InvalidValue,
                "{bad:?} must be refused as an invalid value"
            );
            assert_eq!(refusal.line, bad);
        }
    }

    #[test]
    fn a_nul_byte_skips_its_own_line_and_lets_the_scan_continue() {
        // Go hands the NUL to os.Setenv, which returns EINVAL, which envknob.Setenv throws away: the
        // line does not apply and the file keeps going. Rust's set_var would panic on it instead, so
        // the line is dropped here — same end state, and the scan is not stopped by it.
        let parsed = parse_key_value_env("TS_BAD=\"a\\x00b\"\nTS_GOOD=2\n");
        assert_eq!(parsed.assignments, assigns(&[("TS_GOOD", b"2")]));
        assert_eq!(parsed.refusal, None);
        assert_eq!(parsed.skipped.len(), 1);
        assert_eq!(parsed.skipped[0].kind, ParseErrorKind::NulByte);
        assert_eq!(parsed.skipped[0].line_number, 1);
    }

    #[test]
    fn no_env_file_anywhere_is_not_a_problem() {
        // Linux: the platform list is empty by design, and an operator who configured nothing has
        // nothing to be told about. Same for a platform file that is simply not there.
        assert_eq!(
            load_disk_config(None, platform_env_files("linux")),
            DiskConfig::default()
        );
        let missing = temp_path("absent");
        let _ = std::fs::remove_file(&missing);
        assert_eq!(
            load_disk_config(None, &[missing.to_str().expect("utf-8 temp path")]),
            DiskConfig::default()
        );
    }

    #[test]
    fn a_missing_platform_file_falls_through_to_the_next_one() {
        // Go skips an `os.IsNotExist` candidate and tries the next, and stops at the first file that
        // opens.
        let missing = temp_path("fallthrough-absent");
        let _ = std::fs::remove_file(&missing);
        let present = temp_file("fallthrough-present", "# knobs\nTS_DISABLE_SSH_SERVER=1\n");

        let got = load_disk_config(
            None,
            &[
                missing.to_str().expect("utf-8 temp path"),
                present.to_str().expect("utf-8 temp path"),
            ],
        );
        let _ = std::fs::remove_file(&present);

        assert_eq!(got.path.as_deref(), Some(present.as_path()));
        assert_eq!(got.assignments, assigns(&[("TS_DISABLE_SSH_SERVER", b"1")]));
        assert!(got.problems.is_empty(), "{:?}", got.problems);
    }

    #[test]
    fn a_files_problems_name_the_file_the_line_and_what_was_lost() {
        // Go wraps the scan's error as `error parsing %s: %w`; the file name is half of what makes
        // the message actionable and the line number is the other half. Both halves are reported
        // WITHOUT losing what did apply — the daemon is starting either way, so the operator needs
        // to know exactly which part of their file is not in effect.
        let path = temp_file(
            "problems",
            "TS_GOOD=1\nTS_NUL=\"a\\x00b\"\nTS_DEBUG=\"unterminated\nTS_BELOW=1\n",
        );
        let got = load_disk_config(None, &[path.to_str().expect("utf-8 temp path")]);
        let _ = std::fs::remove_file(&path);

        assert_eq!(got.assignments, assigns(&[("TS_GOOD", b"1")]));
        assert_eq!(got.problems.len(), 2, "{:?}", got.problems);
        let prefix = format!("error parsing {}: ", path.display());
        assert!(
            got.problems[0].starts_with(&prefix)
                && got.problems[0].contains("line 2: invalid NUL byte")
                && got.problems[0].contains("the rest of the file applied"),
            "the skipped line must name the file, the line and its consequence: {}",
            got.problems[0]
        );
        assert!(
            got.problems[1].starts_with(&prefix)
                && got.problems[1].contains("line 3: invalid value in line")
                && got.problems[1].contains("every line below it was not applied"),
            "the refusal must name the file, the line and its consequence: {}",
            got.problems[1]
        );
    }

    #[test]
    fn an_explicit_env_file_is_read_ahead_of_the_platform_list() {
        // Go reads TS_DEBUG_ENV_FILE FIRST and returns straight after it. It is also the only way to
        // point a Linux daemon at an env file at all, since the platform list is empty there.
        let platform = temp_file("explicit-platform", "TS_FROM_PLATFORM=1\n");
        let explicit = temp_file("explicit-override", "TS_FROM_OVERRIDE=1\n");

        let got = load_disk_config(
            Some(&explicit),
            &[platform.to_str().expect("utf-8 temp path")],
        );
        let linux = load_disk_config(Some(&explicit), platform_env_files("linux"));
        let _ = std::fs::remove_file(&platform);
        let _ = std::fs::remove_file(&explicit);

        assert_eq!(got.path.as_deref(), Some(explicit.as_path()));
        assert_eq!(got.assignments, assigns(&[("TS_FROM_OVERRIDE", b"1")]));
        assert!(got.problems.is_empty(), "{:?}", got.problems);
        assert_eq!(linux.assignments, assigns(&[("TS_FROM_OVERRIDE", b"1")]));
    }

    #[test]
    fn an_explicit_env_file_that_cannot_be_opened_is_a_problem_and_not_a_fall_through() {
        // Go: `error opening explicitly configured TS_DEBUG_ENV_FILE: %w`, returned immediately — a
        // file an operator NAMED is not a candidate that may quietly be absent, and the platform
        // list is not consulted behind it.
        let platform = temp_file("explicit-missing-platform", "TS_FROM_PLATFORM=1\n");
        let missing = temp_path("explicit-missing");
        let _ = std::fs::remove_file(&missing);

        let got = load_disk_config(
            Some(&missing),
            &[platform.to_str().expect("utf-8 temp path")],
        );
        let _ = std::fs::remove_file(&platform);

        assert!(got.assignments.is_empty(), "{:?}", got.assignments);
        assert_eq!(got.path.as_deref(), Some(missing.as_path()));
        assert_eq!(got.problems.len(), 1, "{:?}", got.problems);
        assert!(
            got.problems[0].contains("error opening explicitly configured TS_DEBUG_ENV_FILE")
                && got.problems[0].contains(&missing.display().to_string()),
            "the problem must name the variable and the file: {}",
            got.problems[0]
        );
    }

    #[test]
    fn an_empty_override_variable_is_no_override() {
        // Go tests `os.Getenv("TS_DEBUG_ENV_FILE") != ""`, so exporting it empty is the same as not
        // exporting it — which is how a unit file or a wrapper script turns it back off.
        assert_eq!(explicit_env_file(None), None);
        assert_eq!(explicit_env_file(Some(OsString::from(""))), None);
        assert_eq!(
            explicit_env_file(Some(OsString::from("/etc/tailnetd/other.txt"))),
            Some(PathBuf::from("/etc/tailnetd/other.txt"))
        );
    }
}
