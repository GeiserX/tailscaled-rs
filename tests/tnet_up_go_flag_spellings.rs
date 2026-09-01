//! `tnet up` must take Go's own `up` flag spellings, so a ported command line runs.
//!
//! Go's `tailscale up` spells four things differently from this fork, or not at all: `--auth-key`
//! (its canonical name for `--authkey`/`--authkey-file`, including the `file:<path>` value form),
//! `--login-server` (its name for `--control-url`), `--host-routes` (a `notFalseVar` this fork
//! deliberately does not implement) and `--nickname` (which Go does NOT register on `up` either —
//! profile naming lives on `set`). Until `#313` all four exited 2 at argument parsing, so a command
//! line copied out of Go's docs died before it reached the daemon.
//!
//! This file was born as a guard on the backlog entry that asked for that fix, cross-checking the
//! entry's prose against the CLI. The entry is gone — the work merged — but the CLI half of the
//! guard is the part worth keeping, so what remains is a regression test on `tnet up` itself: every
//! Go spelling must get past the parser, the two that are pure renames must stay *aliases* rather
//! than becoming second flags, and `--nickname` must still be answered by name.
//!
//! The fork's flag surface is read by running the built `tnet` binary and parsing `--help` — clap's
//! own parser, not a second copy of the flag list — the way `tests/homebrew_formula.rs` checks the
//! Homebrew formula against the tree it packages.

use std::process::Command;
use std::process::Output;

/// Go's `up` spellings a ported command line carries.
const GO_UP_SPELLINGS: [&str; 4] = [
    "--auth-key",
    "--login-server",
    "--nickname",
    "--host-routes",
];

fn tnet(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tnet"))
        .args(args)
        .output()
        .expect("the `tnet` binary built for this test should run")
}

/// The long flags `tnet <subcommand>` accepts, read off its own `--help`. This is the fork's flag
/// surface as clap reports it, so a flag renamed in `src/bin/tnet.rs` moves this set with it.
fn accepted_flags(subcommand: &str) -> Vec<String> {
    let mut flags: Vec<String> = help_text(subcommand)
        .lines()
        .filter_map(declared_flag)
        .collect();
    flags.sort();
    flags.dedup();
    flags
}

/// `tnet <subcommand> --help`, as clap renders it.
fn help_text(subcommand: &str) -> String {
    let out = tnet(&[subcommand, "--help"]);
    assert!(
        out.status.success(),
        "`tnet {subcommand} --help` should exit 0, got {:?}",
        out.status
    );
    String::from_utf8(out.stdout).expect("clap help should be UTF-8")
}

/// The long flag a clap help line *declares*, if any: the option column is `    --authkey <KEY>`
/// or `-v, --verbose`. Only the declaration counts — a flag merely mentioned in a neighbouring
/// flag's help prose (`set --help` talks about `--list`, which lives on `switch`) is not a flag
/// this subcommand accepts, and reading one as such would let a wrong claim pass.
fn declared_flag(line: &str) -> Option<String> {
    let mut token = line.trim_start();
    if let Some(rest) = token.strip_prefix('-')
        && let Some(rest) = rest.strip_prefix(|c: char| c.is_ascii_alphabetic())
        && let Some(rest) = rest.strip_prefix(", ")
    {
        token = rest;
    }
    let name: String = token
        .strip_prefix("--")?
        .chars()
        .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
        .collect();
    (!name.is_empty()).then(|| format!("--{name}"))
}

#[test]
fn tnet_up_takes_each_go_up_flag_spelling() {
    // The defect this guards against returning: a command line copied from Go dying at argument
    // parsing. Every one of Go's four spellings must get past clap. Each is given the argument
    // shape Go gives it — `--host-routes` is Go's `notFalseVar`, a bool flag that never consumes
    // the next argument.
    for flag in GO_UP_SPELLINGS {
        let argv: Vec<&str> = if flag == "--host-routes" {
            vec!["up", flag]
        } else {
            vec!["up", flag, "placeholder"]
        };
        let out = tnet(&argv);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_ne!(
            out.status.code(),
            Some(2),
            "`tnet up {flag}` should not exit 2 at argument parsing; got: {stderr}"
        );
        assert!(
            !stderr.contains("unexpected argument"),
            "`tnet up {flag}` should not hit clap's \"unexpected argument\"; got: {stderr}"
        );
    }
}

#[test]
fn host_routes_carries_gos_only_true_is_allowed_refusal() {
    // Go's `--host-routes` is a `notFalseVar`: `--host-routes`/`--host-routes=true` is accepted and
    // does nothing, `--host-routes=false` is a usage error. Porting the flag without its refusal
    // would silently accept an operator's explicit "no".
    let out = tnet(&["up", "--host-routes=false"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "`tnet up --host-routes=false` should fail the way Go's notFalseVar does"
    );
    assert!(
        stderr.contains("only 'true' is allowed"),
        "`tnet up --host-routes=false` should carry Go's \"unsupported value; only 'true' is \
         allowed\" refusal; got: {stderr}"
    );
}

#[test]
fn nickname_is_distinguished_from_the_flags_that_are_only_renames() {
    // `--auth-key` and `--login-server` were aliases waiting to be written: `up` already carried the
    // behaviour under another name, and they are now clap aliases of it. `--nickname` was never that
    // — `up` has no profile-naming flag, in this fork OR in Go, only `set` does (and Go's `login`) —
    // so it is answered by name instead, pointing at where the behaviour lives.
    let up_flags = accepted_flags("up");

    assert!(
        up_flags.contains(&"--authkey".to_owned())
            && up_flags.contains(&"--authkey-file".to_owned())
            && up_flags.contains(&"--control-url".to_owned()),
        "`tnet up` should still carry the flags `--auth-key`/`--login-server` alias onto"
    );
    // An alias is one flag under two names, so it stays off the option column and is listed on its
    // target's line — which is exactly what makes it a rename rather than a second flag.
    let up_help = help_text("up");
    for (canonical, alias) in [
        ("--authkey", "--auth-key"),
        ("--control-url", "--login-server"),
    ] {
        assert!(
            !up_flags.contains(&alias.to_owned()),
            "`{alias}` should be an alias of `{canonical}`, not a flag of its own"
        );
        assert!(
            up_help.contains(&format!("[alias: {alias}]")),
            "`tnet up --help` should show `{alias}` as an alias of `{canonical}`"
        );
    }
    assert!(
        !up_flags.contains(&"--nickname".to_owned()),
        "`up --nickname` is answered by name, not offered as a flag: Go does not register it on \
         `up` either"
    );
    let refusal = tnet(&["up", "--nickname", "work-laptop"]);
    let refusal = String::from_utf8_lossy(&refusal.stderr).into_owned();
    assert!(
        refusal.contains("tnet set --nickname"),
        "`tnet up --nickname` should name where profile naming lives; got: {refusal}"
    );
    assert!(
        accepted_flags("set").contains(&"--nickname".to_owned()),
        "`tnet set --nickname` is where this fork's profile naming lives"
    );
}
