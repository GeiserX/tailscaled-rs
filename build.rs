//! Build script: embed a build stamp (git commit + rustc version) so `tailnetd --version` can print
//! a Go-`tailscaled`-style multi-line version block (Go prints `tailscale commit: <sha>` +
//! `go version: ...`). Pure `std` + the `git`/`rustc` already on the build host — NO build
//! dependency. When git or rustc is unavailable (e.g. building from a release tarball with no
//! `.git`), each value falls back to `"unknown"` so the `env!(...)` lookups in `main.rs` still
//! resolve at compile time and the build never breaks.
//!
//! It also stamps the facts `tnet debug build-info` reports (the analogue of Go's
//! `tailscale debug go-buildinfo`, which dumps `runtime/debug.BuildInfo`): the target triple and
//! cargo profile cargo hands every build script, plus the **resolved engine version + git rev** read
//! out of the committed `Cargo.lock`. The engine pin is the single fact an operator most needs when
//! triaging a datapath bug, and a stripped release binary otherwise carries no trace of it. Same
//! discipline as above: every value degrades to `"unknown"` rather than failing the build.

use std::process::Command;

fn main() {
    println!("cargo:rustc-env=TAILNETD_GIT_COMMIT={}", git_commit());
    println!("cargo:rustc-env=TAILNETD_RUSTC_VERSION={}", rustc_version());

    // `TARGET` / `PROFILE` are set by cargo for every build script, so these two never need a
    // fallback of their own — but keep the same shape as the rest in case a future non-cargo caller
    // drops them.
    println!(
        "cargo:rustc-env=TAILNETD_BUILD_TARGET={}",
        env_or_unknown("TARGET")
    );
    println!(
        "cargo:rustc-env=TAILNETD_BUILD_PROFILE={}",
        env_or_unknown("PROFILE")
    );
    let (engine_version, engine_rev) = engine_stamp();
    println!("cargo:rustc-env=TAILNETD_ENGINE_VERSION={engine_version}");
    println!("cargo:rustc-env=TAILNETD_ENGINE_REV={engine_rev}");

    // Re-run when HEAD or the index moves so the commit stamp stays fresh, without reverting to
    // cargo's default "rerun if any package file changed" (which over-rebuilds). Only emit paths
    // that exist — a `rerun-if-changed` on a missing path makes cargo treat it as always-changed.
    println!("cargo:rerun-if-changed=build.rs");
    for p in [".git/HEAD", ".git/index", "Cargo.lock"] {
        if std::path::Path::new(p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }
}

/// A cargo-provided build-script env var, or `unknown` when absent/empty.
fn env_or_unknown(name: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The crate name of the engine facade in `Cargo.lock` (the package name, not the `tailscale` lib
/// name we import it as — see the dependency comment in `Cargo.toml`).
const ENGINE_PACKAGE: &str = "geiserx_tailscale";

/// The engine's resolved `(version, git rev)` as recorded in the committed `Cargo.lock`, so the
/// binary can report the exact engine it was built against. Reads the lockfile rather than
/// `Cargo.toml` because the lockfile is what cargo actually resolved (and it carries the version
/// alongside the rev). Either half falls back to `"unknown"` — a missing/renamed/registry-sourced
/// entry must degrade the report, never break the build.
fn engine_stamp() -> (String, String) {
    let Ok(lock) = std::fs::read_to_string("Cargo.lock") else {
        return ("unknown".to_string(), "unknown".to_string());
    };
    // `[[package]]` stanzas are blank-line separated; find the one naming the engine facade.
    for stanza in lock.split("\n\n") {
        if !stanza
            .lines()
            .any(|l| l.trim() == format!("name = \"{ENGINE_PACKAGE}\""))
        {
            continue;
        }
        let version = toml_string(stanza, "version").unwrap_or_else(|| "unknown".to_string());
        // `source = "git+<url>?rev=<sha>#<sha>"` — the fragment after `#` is the resolved commit.
        // A non-git source (a registry dependency, once the pin moves there) simply has no rev.
        let rev = toml_string(stanza, "source")
            .and_then(|s| s.rsplit_once('#').map(|(_, sha)| sha.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        return (version, rev);
    }
    ("unknown".to_string(), "unknown".to_string())
}

/// Pull `key = "value"` out of one `Cargo.lock` stanza. The lockfile is cargo-generated with a fixed
/// layout (one `key = "value"` per line, no multi-line strings on these keys), so a line scan is
/// enough — no TOML parser, keeping the build-dependency-free promise above.
fn toml_string(stanza: &str, key: &str) -> Option<String> {
    stanza
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix(&format!("{key} = \"")))
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_string)
}

/// Short git commit SHA, suffixed `-dirty` when the working tree has uncommitted changes; `unknown`
/// if git is absent or this is not a checkout.
fn git_commit() -> String {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=9", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // `--untracked-files=no`: "dirty" should mean uncommitted changes to *tracked* sources, not the
    // mere presence of an untracked scratch file (which would spuriously stamp `-dirty` on an
    // otherwise-clean build of the committed tree).
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    match sha {
        Some(s) if dirty => format!("{s}-dirty"),
        Some(s) => s,
        None => "unknown".to_string(),
    }
}

/// The `rustc --version` string (the faithful analogue of Go's `go version:` line); `unknown` if it
/// cannot be queried.
fn rustc_version() -> String {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}
