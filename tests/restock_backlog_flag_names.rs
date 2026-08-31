//! `docs/restock-beads.json` must spell this fork's own flags the way `tnet` actually spells them.
//!
//! That file is a backlog handed to whoever picks the work up: each entry states what upstream Go
//! does, what this fork does instead, and therefore what has to be decided. The "what this fork
//! does instead" half is a copy of facts owned by `src/bin/tnet.rs`, and a wrong copy is worse than
//! no copy — an entry that credits `tnet up` with a flag it rejects gives contradictory acceptance
//! criteria, so the implementer cannot tell an *alias for an existing flag* (rename work) from
//! *behaviour this fork does not have yet* (new work). The `up` flag entry got exactly that wrong:
//! it listed Go's `--auth-key`, `--login-server` and `--nickname` as "the flag this fork already
//! has", one sentence after correctly saying `tnet up` has none of them.
//!
//! So the two halves are checked against each other here, the way `tests/homebrew_formula.rs`
//! checks the Homebrew formula against the tree it packages: the backlog text with
//! [`include_str!`], and the fork's real flag surface by running the built `tnet` binary — clap's
//! own parser, not a second copy of the flag list.
//!
//! That `up` entry has since been WORKED: all four Go spellings now reach `tnet up` — two as
//! aliases, one as an accepted no-op, `--nickname` as a refusal that names `tnet set --nickname` —
//! so the half of it that said they die at argument parsing is history, not a claim about the CLI
//! as it stands. The
//! checks below moved with the code — each Go spelling must now get PAST the parser, and
//! `--nickname` must be answered by name — which is what keeps this file a guard on `tnet up`
//! instead of a guard on a sentence nobody will read again.

use std::process::Command;
use std::process::Output;

const BACKLOG: &str = include_str!("../docs/restock-beads.json");

/// The backlog entry under test. Named rather than indexed so reordering the file is not a
/// silent pass on a different entry.
const ENTRY_TITLE: &str = "tnet up rejects four Go up flags a ported command line still carries";

/// Go's spellings, which the entry's whole point is that `tnet up` does *not* accept.
const GO_UP_SPELLINGS: [&str; 4] = [
    "--auth-key",
    "--login-server",
    "--nickname",
    "--host-routes",
];

/// The `description` of [`ENTRY_TITLE`], with JSON escapes resolved.
fn entry_description() -> String {
    let beads = serde_json::from_str::<serde_json::Value>(BACKLOG)
        .expect("docs/restock-beads.json should be valid JSON");
    let beads = beads["beads"]
        .as_array()
        .expect("docs/restock-beads.json should have a `beads` array");
    beads
        .iter()
        .find(|b| b["title"].as_str() == Some(ENTRY_TITLE))
        .unwrap_or_else(|| panic!("docs/restock-beads.json should still carry `{ENTRY_TITLE}`"))
        ["description"]
        .as_str()
        .expect("the entry should have a string `description`")
        .to_owned()
}

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
/// this subcommand accepts, and reading one as such would let a wrong backlog claim pass.
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

/// Every `(…)` in `text`, innermost content only (the entry nests none).
fn parentheticals(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('(') {
        let after = &rest[open + 1..];
        match after.find(')') {
            Some(close) => {
                found.push(&after[..close]);
                rest = &after[close + 1..];
            }
            None => break,
        }
    }
    found
}

/// The flags named by a parenthetical that is *nothing but* a list of flags, e.g.
/// ``(`--authkey`, `--authkey-file`, `--control-url`)``. In this entry such a list is only ever
/// used to say "these are the spellings this fork already has on `up`", so every member has to be
/// a real `tnet up` flag. A parenthetical carrying any prose (`(set --nickname, which since #294
/// renames …)`) is making some other claim and is not read as one of these lists.
fn flag_only_list(parenthetical: &str) -> Option<Vec<String>> {
    let mut flags = Vec::new();
    for token in parenthetical
        .split([' ', ',', '/'])
        .map(|t| t.trim().trim_matches('`'))
        .filter(|t| !t.is_empty())
    {
        if !token.starts_with("--") {
            return None;
        }
        flags.push(token.to_owned());
    }
    (!flags.is_empty()).then_some(flags)
}

#[test]
fn the_entry_still_describes_the_four_go_up_spellings() {
    // Guard for the tests below: they are only meaningful while this entry is still about these
    // four flags. If it is rewritten to cover something else, fail here rather than passing
    // vacuously.
    let description = entry_description();
    for flag in GO_UP_SPELLINGS {
        assert!(
            description.contains(flag),
            "`{ENTRY_TITLE}` should still name `{flag}`"
        );
    }
}

#[test]
fn every_flag_the_entry_credits_to_this_fork_is_one_tnet_up_accepts() {
    // The bug this catches: listing Go's spellings as flags the fork already has. The implementer
    // then reads "make `--auth-key` an alias of `--auth-key`" and has no criterion to build to.
    let description = entry_description();
    let up_flags = accepted_flags("up");
    let mut checked = 0;
    for parenthetical in parentheticals(&description) {
        let Some(flags) = flag_only_list(parenthetical) else {
            continue;
        };
        for flag in flags {
            assert!(
                up_flags.contains(&flag),
                "`{ENTRY_TITLE}` lists `{flag}` as a spelling this fork already has, but `tnet up` \
                 does not accept it. Name the flag `tnet up` really carries, or move the claim out \
                 of a bare flag list if it is about a different subcommand."
            );
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "`{ENTRY_TITLE}` should still name what this fork spells instead of Go's flags, as a \
         parenthesised flag list — otherwise this check passes on nothing"
    );
}

#[test]
fn tnet_up_takes_each_go_spelling_the_entry_names() {
    // The entry's premise WAS that a command line copied from Go dies at argument parsing. That is
    // the defect it asked to have fixed, so the check is inverted rather than deleted: every one of
    // Go's four spellings must now get past clap. Each is given the argument shape Go gives it —
    // `--host-routes` is Go's `notFalseVar`, a bool flag that never consumes the next argument.
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
            "`tnet up {flag}` should no longer exit 2 at argument parsing; got: {stderr}"
        );
        assert!(
            !stderr.contains("unexpected argument"),
            "`tnet up {flag}` should no longer hit clap's \"unexpected argument\"; got: {stderr}"
        );
    }
}

#[test]
fn nickname_is_distinguished_from_the_flags_that_are_only_renames() {
    // `--auth-key` and `--login-server` were aliases waiting to be written: `up` already carried the
    // behaviour under another name, and they are now clap aliases of it. `--nickname` was never that
    // — `up` has no profile-naming flag, in this fork OR in Go, only `set` does (and Go's `login`) —
    // so it is answered by name instead, pointing at where the behaviour lives.
    let description = entry_description();
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
    assert!(
        description.contains("`set --nickname`"),
        "`{ENTRY_TITLE}` should point at `set --nickname` as where this fork's profile naming \
         lives, so `up --nickname` is scoped as new behaviour rather than a rename"
    );
    assert!(
        description.contains("`tnet login` already accepts"),
        "`{ENTRY_TITLE}` should record that `--login-server` is a name `tnet login` already \
         accepts — that is what makes it a rename on `up` and not new behaviour"
    );
}
