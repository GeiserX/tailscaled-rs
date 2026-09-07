//! `tnet up` and `tnet login` must take Go's own flag spellings, so a ported command line runs.
//!
//! `newUpFlagSet` (`cmd/tailscale/cli/up.go`) registers three flags on `up` that this fork spells
//! differently, or not at all: `--auth-key` (Go's canonical name for `--authkey`/`--authkey-file`,
//! including the `file:<path>` value form), `--login-server` (its name for `--control-url`) and
//! `--host-routes` (a `notFalseVar` this fork deliberately does not implement). Until `#313` all
//! three exited 2 at argument parsing, so a command line copied out of Go's docs died before it
//! reached the daemon.
//!
//! `--nickname` is NOT one of them, and this file is careful to say so. `newUpFlagSet` builds one
//! flag set for both `up` and `login` and registers `--nickname` inside `if cmd == "login"`, so
//! `tailscale up --nickname` is a usage error upstream too — profile naming lives on `login` and on
//! `set`. It is exercised on `up` here only because operators reach for it there anyway, and the
//! fork answers it by name instead of leaving them clap's "unexpected argument".
//!
//! One flag set means one flag surface to guard: because `newUpFlagSet` is shared, whatever `up`
//! owes Go's spellings, `login` owes too — `--auth-key` and `--host-routes` from the unconditional
//! part, `--nickname` from the `if cmd == "login"` part. So the `up` tests below have `login`
//! counterparts, and the counterparts are the point: giving one command the flags and not the other
//! is the divergence that hides behind a green `up` test.
//!
//! This file was born as a guard on the backlog entry that asked for the `up` work, cross-checking
//! the entry's prose against the CLI. The entry is gone — the work merged — but the CLI half of the
//! guard is the part worth keeping, so what remains is a regression test on `tnet up` itself: every
//! Go `up` spelling must get past the parser, the two that are pure renames must stay *aliases*
//! rather than becoming second flags, and `--nickname` must still be refused by name rather than
//! quietly acquiring `up` behaviour Go has no counterpart for.
//!
//! The fork's flag surface is read by running the built `tnet` binary and parsing `--help` — clap's
//! own parser, not a second copy of the flag list — the way `tests/homebrew_formula.rs` checks the
//! Homebrew formula against the tree it packages.

use std::process::Command;
use std::process::Output;

/// The flags Go's `newUpFlagSet` registers on `up` unconditionally, in the spellings a ported
/// command line carries: `--auth-key` (up.go:102), `--login-server` (up.go:108) and the hidden
/// `notFalseVar` `--host-routes` (up.go:111).
const GO_UP_FLAGS: [&str; 3] = ["--auth-key", "--login-server", "--host-routes"];

/// The flag `newUpFlagSet` registers only under `if cmd == "login"`, so it is on Go's `login` and
/// `set` but never on Go's `up`. Kept apart from [`GO_UP_FLAGS`] on purpose: calling it an `up`
/// spelling is the mistake that sends an implementer off to build `up --nickname`.
const GO_LOGIN_ONLY_FLAG: &str = "--nickname";

/// The flags Go's shared flag set gives `login`: the two registered unconditionally that this fork
/// spelled differently or not at all, plus the one registered only under `if cmd == "login"`.
/// `--login-server` is absent because `tnet login` already carried it under Go's own name.
const GO_LOGIN_FLAGS: [&str; 3] = ["--auth-key", "--host-routes", GO_LOGIN_ONLY_FLAG];

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
    // parsing. Every flag Go registers on `up` must get past clap. Each is given the argument
    // shape Go gives it — `--host-routes` is Go's `notFalseVar`, a bool flag that never consumes
    // the next argument.
    for flag in GO_UP_FLAGS {
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
    // behaviour under another name, and they are now clap aliases of it. `--nickname` was never
    // that. `up` has no profile-naming flag, in this fork OR in Go: `newUpFlagSet` registers it
    // inside `if cmd == "login"`, so only Go's `login` and `set` have one. It is therefore answered
    // by name — a refusal that points at where the behaviour does live.
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
        !up_flags.contains(&GO_LOGIN_ONLY_FLAG.to_owned()),
        "`up --nickname` is answered by name, not offered as a flag: Go does not register it on \
         `up` either"
    );

    let out = tnet(&["up", GO_LOGIN_ONLY_FLAG, "work-laptop"]);
    let refusal = String::from_utf8_lossy(&out.stderr).into_owned();
    // Refused, but on this fork's terms rather than clap's: the operator gets told where profile
    // naming lives, not "unexpected argument". The status check states the intent — `up` must never
    // grow a working `--nickname`, since Go's has none to match — though with no daemon reachable
    // here it is the message assertions below that actually discriminate: drop the refusal and the
    // command fails on the socket instead, with none of this text.
    assert!(
        !out.status.success(),
        "`tnet up --nickname` must fail: accepting it would give `up` behaviour upstream's `up` \
         does not have; got: {refusal}"
    );
    assert_ne!(
        out.status.code(),
        Some(2),
        "`tnet up --nickname` should be refused by name, not by clap; got: {refusal}"
    );
    assert!(
        !refusal.contains("unexpected argument"),
        "`tnet up --nickname` should be refused by name, not by clap; got: {refusal}"
    );
    assert!(
        refusal.contains("tnet set --nickname"),
        "`tnet up --nickname` should name where profile naming lives; got: {refusal}"
    );
    // The refusal also has to state the upstream half, because getting *that* wrong is what sends
    // an implementer off to add `up --nickname` for parity it would not be buying. Go's `up` has no
    // such flag, and the message must not leave the operator believing otherwise.
    assert!(
        refusal.contains("not a `tailscale up` flag"),
        "the refusal should say Go's `up` has no `--nickname` either, not just that this fork's \
         does not; got: {refusal}"
    );
    assert!(
        refusal.contains("only when the command is `login`"),
        "the refusal should say where `newUpFlagSet` does register `--nickname`; got: {refusal}"
    );

    assert!(
        accepted_flags("set").contains(&GO_LOGIN_ONLY_FLAG.to_owned()),
        "`tnet set --nickname` is where this fork's profile naming lives"
    );
}

#[test]
fn tnet_login_takes_each_flag_gos_shared_flag_set_gives_it() {
    // The same defect as `tnet_up_takes_each_go_up_flag_spelling`, one command over: `login` reads
    // its flags off `newUpFlagSet` too, so `tailscale login --auth-key=…`, `--host-routes` and
    // `--nickname` all parse upstream and must parse here rather than exiting 2.
    for flag in GO_LOGIN_FLAGS {
        let argv: Vec<&str> = if flag == "--host-routes" {
            vec!["login", flag]
        } else {
            vec!["login", flag, "placeholder"]
        };
        let out = tnet(&argv);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_ne!(
            out.status.code(),
            Some(2),
            "`tnet login {flag}` should not exit 2 at argument parsing; got: {stderr}"
        );
        assert!(
            !stderr.contains("unexpected argument"),
            "`tnet login {flag}` should not hit clap's \"unexpected argument\"; got: {stderr}"
        );
    }
}

#[test]
fn login_host_routes_carries_the_same_refusal_up_does() {
    // `notFalseVar` is registered once, for both commands, so the refusal belongs to both. Porting
    // the flag onto `login` without it would accept an operator's explicit "no" and ignore it.
    let out = tnet(&["login", "--host-routes=false"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "`tnet login --host-routes=false` should fail the way Go's notFalseVar does"
    );
    assert!(
        stderr.contains("only 'true' is allowed"),
        "`tnet login --host-routes=false` should carry Go's \"unsupported value; only 'true' is \
         allowed\" refusal; got: {stderr}"
    );
}

#[test]
fn nickname_is_a_login_flag_here_because_it_is_one_upstream() {
    // The other half of `nickname_is_distinguished_from_the_flags_that_are_only_renames`: `up` has
    // no profile-naming flag, and the reason is that `newUpFlagSet` gives it to `login`. So `login`
    // has to actually offer it — a refusal on `up` that points at a command which does not take the
    // flag either would just move the dead end.
    let login_flags = accepted_flags("login");
    assert!(
        login_flags.contains(&GO_LOGIN_ONLY_FLAG.to_owned()),
        "`tnet login --nickname` is where Go registers profile naming for a login"
    );
    assert!(
        !accepted_flags("up").contains(&GO_LOGIN_ONLY_FLAG.to_owned()),
        "`up` must still not offer it: Go's `up` does not either"
    );

    // Go's canonical key spelling is an alias on `login` for the same reason it is one on `up`: one
    // flag, two names, not a second flag with its own value.
    assert!(
        !login_flags.contains(&"--auth-key".to_owned()),
        "`--auth-key` should be an alias of `--authkey`, not a flag of its own"
    );
    assert!(
        help_text("login").contains("[alias: --auth-key]"),
        "`tnet login --help` should show `--auth-key` as an alias of `--authkey`"
    );

    // And the `up` refusal now names a command that exists, which is what makes it a signpost
    // rather than a dead end.
    let refusal = String::from_utf8_lossy(&tnet(&["up", GO_LOGIN_ONLY_FLAG, "work-laptop"]).stderr)
        .into_owned();
    assert!(
        refusal.contains("tnet login --nickname"),
        "`up --nickname` should point at the login that takes it; got: {refusal}"
    );
}
