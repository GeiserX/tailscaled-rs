//! The README's "parsed but not modelled" `set` paragraph must split permanence the way
//! `docs/ENGINE_ASKS.md` §34 does.
//!
//! §34 is where this fork records what it wants FROM the engine and what it will never build. It
//! covers the same four Go `set` flags the README paragraph covers, and it does not treat them
//! alike: three of them (`--relay-server-port`, `--relay-server-static-endpoints`, `--sync`) are an
//! open **Ask** — a relay listener, a `Hostinfo.PeerRelay` advertisement, a way to stop the map
//! poll — so the states this build enforces for them are what it does *today*. The fourth,
//! `--remote-config`, is filed under **NOT asked for**: it is declined by design, because it would
//! add a control-plane write path into prefs and the LocalAPI that THREAT_MODEL §4.1 does not
//! grant. That one really is permanent.
//!
//! Calling all four "permanent" in the README quietly promotes an engine gap to a product
//! decision: a reader deciding whether to file the work, or whether to wait for it, gets the
//! opposite answer from the two files. So the coupling is checked here rather than left to
//! whoever next edits one of them — both documents with [`include_str!`], the same trick
//! `tests/engine_doc_publish_verdicts.rs` uses to keep `docs/ENGINE.md` honest against the script
//! it describes. Which flags are asked-for and which are declined is PARSED out of §34, not
//! hard-coded, so landing the engine support (or declining another flag) moves this test with it.

const README: &str = include_str!("../README.md");
const ENGINE_ASKS: &str = include_str!("../docs/ENGINE_ASKS.md");

/// The §34 heading, matched by its number and lead so a retitle that keeps the section intact
/// still resolves.
const ASK_HEADING_PREFIX: &str = "## 34. ";

/// The marker §34 puts on the flag it refuses to file as an ask.
const NOT_ASKED_FOR: &str = "**NOT asked for:";

/// The first words of the README paragraph under test.
const PARAGRAPH_LEAD: &str = "Four of Go's `set` flags are";

/// Body of `docs/ENGINE_ASKS.md` §34, heading excluded, up to the next top-level section.
fn ask_34() -> &'static str {
    let start = ENGINE_ASKS.find(ASK_HEADING_PREFIX).unwrap_or_else(|| {
        panic!("docs/ENGINE_ASKS.md should still contain `{ASK_HEADING_PREFIX}`")
    });
    let body = &ENGINE_ASKS[start + ASK_HEADING_PREFIX.len()..];
    match body.find("\n## ") {
        Some(end) => &body[..end],
        None => body,
    }
}

/// Every `--flag` §34 names, in backticks, normalised to its bare long name: `` `--sync=false` ``
/// and `` `--relay-server-port <PORT>` `` both collapse to the flag itself, and Go's `--no-` /
/// `--sync=false` negations collapse onto the positive spelling they negate. Deduplicated, in
/// order of first mention.
fn flags_named_in(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for chunk in text.split('`').skip(1).step_by(2) {
        let Some(rest) = chunk.strip_prefix("--") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        let name = name.trim_end_matches('-');
        let name = name.strip_prefix("no-").unwrap_or(name);
        if name.is_empty() {
            continue;
        }
        let flag = format!("--{name}");
        if !found.contains(&flag) {
            found.push(flag);
        }
    }
    found
}

/// The flag §34 explicitly declines — the `--remote-config` of the "NOT asked for" paragraph.
fn declined_flag() -> String {
    let section = ask_34();
    let start = section
        .find(NOT_ASKED_FOR)
        .unwrap_or_else(|| panic!("§34 should still mark one flag `{NOT_ASKED_FOR}`"));
    let line_end = section[start..]
        .find('\n')
        .map_or(section.len(), |i| start + i);
    let mut named = flags_named_in(&section[start..line_end]);
    assert_eq!(
        named.len(),
        1,
        "§34's `{NOT_ASKED_FOR}` line should name exactly one flag, found {named:?}"
    );
    named.remove(0)
}

/// The flags §34 asks the engine for: everything it names except the declined one.
fn asked_for_flags() -> Vec<String> {
    let declined = declined_flag();
    let asked: Vec<String> = flags_named_in(ask_34())
        .into_iter()
        .filter(|f| *f != declined)
        .collect();
    assert!(
        !asked.is_empty(),
        "§34 should still ask for at least one flag's engine support"
    );
    asked
}

/// The README paragraph about the four unmodelled `set` flags, split at the sentence that turns to
/// the declined flag: `.0` covers the engine-gated ones, `.1` covers the declined one.
fn readme_halves() -> (&'static str, &'static str) {
    let start = README.find(PARAGRAPH_LEAD).unwrap_or_else(|| {
        panic!("README.md should still contain a paragraph opening `{PARAGRAPH_LEAD}`")
    });
    let body = &README[start..];
    let paragraph = match body.find("\n\n") {
        Some(end) => &body[..end],
        None => body,
    };
    let declined = declined_flag();
    let mention = paragraph.find(&declined).unwrap_or_else(|| {
        panic!("the README paragraph should still name the declined flag `{declined}`")
    });
    // Back up to the start of the sentence that introduces it.
    let split = paragraph[..mention].rfind(". ").map_or(0, |i| i + 2);
    assert!(
        split > 0,
        "the README paragraph should cover the engine-gated flags BEFORE turning to `{declined}`"
    );
    (&paragraph[..split], &paragraph[split..])
}

#[test]
fn the_readme_calls_the_engine_gated_set_flags_current_not_permanent() {
    let (gated, _) = readme_halves();
    let lowered = gated.to_lowercase();
    assert!(
        !lowered.contains("permanent"),
        "the README describes the states behind {:?} as permanent, but §34 asks the engine to \
         change them — say `currently` there and reserve `permanently` for the flag §34 declines. \
         Offending half:\n{gated}",
        asked_for_flags()
    );
    assert!(
        lowered.contains("currently"),
        "the README should say the engine-gated states are the ones this daemon is CURRENTLY in, \
         so a reader can tell an open engine ask from a product decision. Offending half:\n{gated}"
    );
}

#[test]
fn the_readme_still_calls_the_declined_set_flag_permanent() {
    let (_, declined_half) = readme_halves();
    assert!(
        declined_half.to_lowercase().contains("permanent"),
        "§34 declines `{}` by design rather than deferring it, so the README must keep saying its \
         refusal is permanent — otherwise a reader files an engine ask this fork has already \
         refused. Offending half:\n{declined_half}",
        declined_flag()
    );
}

#[test]
fn the_readme_sorts_each_of_section_34s_flags_into_the_right_half() {
    let (gated, declined_half) = readme_halves();
    let declined = declined_flag();
    for flag in asked_for_flags() {
        assert!(
            gated.contains(&flag),
            "§34 asks the engine for `{flag}`, so the README's engine-gated half should name it. \
             Offending half:\n{gated}"
        );
    }
    assert!(
        !gated.contains(&declined),
        "`{declined}` is declined by design, not engine-gated, so it must not sit in the half the \
         README credits to `docs/ENGINE_ASKS.md` §34. Offending half:\n{gated}"
    );
    assert!(
        declined_half.contains(&declined),
        "the README's second half should be the one that explains `{declined}`. Offending \
         half:\n{declined_half}"
    );
}

#[test]
fn the_readmes_engine_gated_half_still_points_at_the_ask_that_backs_it() {
    let (gated, _) = readme_halves();
    assert!(
        gated.contains("ENGINE_ASKS.md") && gated.contains("§34"),
        "the engine-gated half should cite `docs/ENGINE_ASKS.md` §34 — that citation is what lets \
         a reader check `currently` against the open ask. Offending half:\n{gated}"
    );
}
