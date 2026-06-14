//! Build script: embed a build stamp (git commit + rustc version) so `tailnetd --version` can print
//! a Go-`tailscaled`-style multi-line version block (Go prints `tailscale commit: <sha>` +
//! `go version: ...`). Pure `std` + the `git`/`rustc` already on the build host — NO build
//! dependency. When git or rustc is unavailable (e.g. building from a release tarball with no
//! `.git`), each value falls back to `"unknown"` so the `env!(...)` lookups in `main.rs` still
//! resolve at compile time and the build never breaks.

use std::process::Command;

fn main() {
    println!("cargo:rustc-env=TAILNETD_GIT_COMMIT={}", git_commit());
    println!("cargo:rustc-env=TAILNETD_RUSTC_VERSION={}", rustc_version());

    // Re-run when HEAD or the index moves so the commit stamp stays fresh, without reverting to
    // cargo's default "rerun if any package file changed" (which over-rebuilds). Only emit paths
    // that exist — a `rerun-if-changed` on a missing path makes cargo treat it as always-changed.
    println!("cargo:rerun-if-changed=build.rs");
    for p in [".git/HEAD", ".git/index"] {
        if std::path::Path::new(p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }
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
