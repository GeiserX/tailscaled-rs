//! `docs/ENGINE.md` must describe every verdict `check-engine-rev-released.sh` can reach.
//!
//! §3 of `docs/ENGINE.md` ("Trading the `rev` for a version") is where the decision to add a
//! crates.io `version` alongside the `git` + `rev` pin is made, and it delegates that decision to
//! `scripts/check-engine-rev-released.sh`. The script has three verdicts, not two: a matching
//! `sha1` still yields `INCONCLUSIVE` when the release was packaged from a dirty tree, because the
//! stamp then names the commit the work started from rather than the contents that shipped. A
//! section that names only `MATCH` and `MISMATCH` reads as though a matching sha1 were sufficient,
//! which would hand consumers of the published daemon an engine tree our gate never ran against —
//! exactly the failure the script exists to prevent.
//!
//! So these tests pin doc and script together: every verdict the script prints has to be accounted
//! for in that section, and the section has to state the `dirty` half of a clean `MATCH`. Adding a
//! fourth verdict to the script without documenting it fails here.

/// The committed script, embedded so the test reads the same file CI runs.
const SCRIPT: &str = include_str!("../scripts/check-engine-rev-released.sh");

/// The committed doc, embedded for the same reason.
const DOC: &str = include_str!("../docs/ENGINE.md");

/// Heading of the section that makes the trade-the-pin decision.
const SECTION_HEADING: &str = "### Trading the `rev` for a version";

/// Every verdict the script can print: the all-caps label opening an `echo "LABEL: …"` line.
///
/// Scanning the script rather than hard-coding the list is the point — a verdict added there is a
/// verdict this test starts demanding documentation for.
fn script_verdicts() -> Vec<String> {
    let mut verdicts: Vec<String> = Vec::new();
    for line in SCRIPT.lines() {
        let Some(rest) = line.trim_start().strip_prefix("echo \"") else {
            continue;
        };
        let Some((label, _)) = rest.split_once(':') else {
            continue;
        };
        // Verdict labels are shouted; every other echo in the script is prose or a field name.
        if !label.is_empty()
            && label.chars().all(|c| c.is_ascii_uppercase())
            && !verdicts.iter().any(|v| v == label)
        {
            verdicts.push(label.to_string());
        }
    }
    verdicts
}

/// The body of the trade-the-pin section, up to the next heading.
fn trading_section() -> &'static str {
    let start = DOC
        .find(SECTION_HEADING)
        .unwrap_or_else(|| panic!("docs/ENGINE.md should still contain `{SECTION_HEADING}`"));
    let body = &DOC[start + SECTION_HEADING.len()..];
    match body
        .find("\n### ")
        .into_iter()
        .chain(body.find("\n## "))
        .min()
    {
        Some(end) => &body[..end],
        None => body,
    }
}

/// `needle` appears in `haystack` as a whole word, so `MATCH` is not found inside `MISMATCH`.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    haystack.match_indices(needle).any(|(i, _)| {
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let after = i + needle.len();
        let after_ok = after == bytes.len() || !bytes[after].is_ascii_alphanumeric();
        before_ok && after_ok
    })
}

#[test]
fn script_still_has_the_three_known_verdicts() {
    // Guards the extraction itself: if the echo shape changes, the coverage test below would pass
    // vacuously instead of failing loudly.
    let verdicts = script_verdicts();
    for expected in ["MATCH", "MISMATCH", "INCONCLUSIVE"] {
        assert!(
            verdicts.iter().any(|v| v == expected),
            "check-engine-rev-released.sh should still print a `{expected}:` verdict; found {verdicts:?}"
        );
    }
}

#[test]
fn trading_section_documents_every_script_verdict() {
    // The decision section must account for all three outcomes — naming only MATCH and MISMATCH
    // leaves the dirty-tree case looking like a pass.
    let section = trading_section();
    for verdict in script_verdicts() {
        assert!(
            contains_word(section, &verdict),
            "`{SECTION_HEADING}` in docs/ENGINE.md does not mention the `{verdict}` verdict that \
             scripts/check-engine-rev-released.sh can print"
        );
    }
}

#[test]
fn trading_section_requires_a_non_dirty_release() {
    // A clean MATCH is sha1-equal AND dirty=false; the section has to say the second half, since
    // that is the whole difference between MATCH and INCONCLUSIVE.
    let section = trading_section();
    assert!(
        contains_word(section, "dirty"),
        "`{SECTION_HEADING}` in docs/ENGINE.md must state that a release packaged from a dirty \
         tree is not a MATCH"
    );
}
