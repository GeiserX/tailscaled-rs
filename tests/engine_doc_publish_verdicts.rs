//! `docs/ENGINE.md` §3 and `scripts/check-engine-rev-released.sh` must agree on when the pin may
//! be traded for a `version`.
//!
//! Publishing this crate hinges on one judgement call, documented in §3's "Trading the `rev` for a
//! version": adding `version = "…"` beside the engine's `git` + `rev` pin is only honest if the
//! named crates.io release really was cut from the pinned tree. The script is the oracle for that,
//! and it has THREE verdicts, not two — a release can record the pinned commit and still not carry
//! the pinned contents, because `cargo publish` will happily package a modified working tree and
//! stamp `"dirty": true` next to the sha1. That case is `INCONCLUSIVE`, and it blocks the shortcut
//! exactly as `MISMATCH` does.
//!
//! Prose drifts away from a script silently, and this particular drift ends with someone reading
//! "the sha1 matches" as permission to publish an engine tree the gate never ran against. So the
//! two are embedded here with [`include_str!`] (the same trick `src/ipn/install.rs` uses to keep
//! the packaging units honest) and checked against each other: every verdict the script can print
//! must be accounted for in the section that tells a reader how to act on it, the section must say
//! that `MATCH` requires `dirty` to be false rather than a bare sha1 match, and the script must
//! keep `MATCH` as its only success.

const DOC: &str = include_str!("../docs/ENGINE.md");
const SCRIPT: &str = include_str!("../scripts/check-engine-rev-released.sh");

const SECTION_HEADING: &str = "### Trading the `rev` for a version";

/// The part of `docs/ENGINE.md` that tells a reader when the shortcut is available. Scoped to that
/// subsection on purpose: a verdict named anywhere else in the file (or in a neighbouring section
/// about a different script) is no help to someone acting on this decision.
fn shortcut_section() -> &'static str {
    let start = DOC
        .find(SECTION_HEADING)
        .unwrap_or_else(|| panic!("docs/ENGINE.md should still contain `{SECTION_HEADING}`"));
    let body = &DOC[start + SECTION_HEADING.len()..];
    match body.find("\n### ") {
        Some(end) => &body[..end],
        None => body,
    }
}

/// Every verdict word the script can print, in the form a reader sees it: the uppercase token that
/// opens the line, e.g. `MATCH` from `echo "MATCH: …"`. Parsed rather than hard-coded so that a
/// fourth verdict added to the script fails this test instead of quietly bypassing the docs.
fn script_verdicts() -> Vec<&'static str> {
    let mut found: Vec<&str> = Vec::new();
    for line in SCRIPT.lines() {
        let Some(rest) = line.trim_start().strip_prefix("echo \"") else {
            continue;
        };
        let Some(word) = rest.split(':').next() else {
            continue;
        };
        let is_verdict = word.len() >= 2 && word.chars().all(|c| c.is_ascii_uppercase());
        if is_verdict && !found.contains(&word) {
            found.push(word);
        }
    }
    found
}

#[test]
fn the_script_still_reports_the_three_verdicts_this_doc_describes() {
    // Guard for the two tests below: they are only meaningful while the script is the three-way
    // oracle the docs describe. If a verdict is renamed or dropped, fail here — with the list —
    // rather than letting the doc checks pass vacuously.
    let verdicts = script_verdicts();
    assert_eq!(
        verdicts,
        vec!["MISMATCH", "INCONCLUSIVE", "MATCH"],
        "scripts/check-engine-rev-released.sh changed its verdicts; docs/ENGINE.md §3 needs the \
         same edit"
    );
}

#[test]
fn the_doc_accounts_for_every_verdict_the_script_can_report() {
    // The failure this catches: naming only `MATCH` and `MISMATCH`, which reads as "a matching
    // sha1 is the whole test" and leaves the `INCONCLUSIVE` case — pinned commit, modified tree —
    // looking like it clears the shortcut.
    let section = shortcut_section();
    for verdict in script_verdicts() {
        assert!(
            section.contains(verdict),
            "`{SECTION_HEADING}` never mentions the `{verdict}` verdict, so a reader hitting it \
             has no instruction for what it means for publishing"
        );
    }
}

#[test]
fn the_doc_requires_a_clean_tree_and_not_just_a_matching_sha1() {
    // `MATCH` is sha1-equality AND `dirty` = false; the script exits non-zero on the second half
    // alone. The section has to carry both halves, or it licenses publishing against a tree that
    // was never the pinned tree.
    let section = shortcut_section();
    assert!(
        section.contains("dirty"),
        "`{SECTION_HEADING}` must state that `MATCH` also requires `dirty` to be false — without \
         it, the section reduces the verdict to a sha1 comparison the script does not accept on \
         its own"
    );
}

#[test]
fn match_is_the_scripts_only_success() {
    // The doc now says every outcome other than `MATCH` blocks the shortcut. That is a claim about
    // the script's exit status, so pin it: `INCONCLUSIVE` must exit non-zero, and the single
    // `exit 0` must be the one the `MATCH` branch reaches.
    let inconclusive = SCRIPT
        .find("INCONCLUSIVE")
        .expect("the script should still have an INCONCLUSIVE branch");
    let matched = SCRIPT
        .find("echo \"MATCH:")
        .expect("the script should still have a MATCH branch");
    assert!(
        SCRIPT[inconclusive..matched].contains("exit 1"),
        "the INCONCLUSIVE branch must exit non-zero; docs/ENGINE.md §3 tells readers it blocks the \
         shortcut"
    );
    assert_eq!(
        SCRIPT.matches("exit 0").count(),
        1,
        "MATCH should be the script's only success path"
    );
    assert!(
        SCRIPT[matched..].contains("exit 0"),
        "the single `exit 0` should be the one MATCH reaches"
    );
}
