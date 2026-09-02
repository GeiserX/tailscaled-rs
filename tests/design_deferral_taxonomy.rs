//! Every entry in `docs/DESIGN.md`'s "Remaining Go surface to match" list must carry one of the
//! two statuses that section defines for itself.
//!
//! That section is where a parity pass records why a Go feature is still unmatched, and its
//! preamble is unusually strict about the vocabulary: nothing Go does is "out of scope by choice",
//! every entry is either *not-yet-built* (file a bead and ship it) or *blocked* on a substrate the
//! fork lacks, and a blocked entry is "a **deferral with a named unblock**, never a decision to
//! skip it". The words are the whole point of the list — someone deciding whether to start the
//! work, or to wait for it, reads the status tag and stops there.
//!
//! So an entry labelled "out of scope" costs the list its meaning: it is the one phrase the
//! preamble spends a sentence disowning, and it tells that reader the opposite of what the same
//! entry's own reason says three lines later. This test keeps the two halves of the section
//! honest against each other — the preamble is checked for the taxonomy it promises, and every
//! bullet under it for a status drawn from that taxonomy — with [`include_str!`], the same trick
//! `tests/engine_doc_publish_verdicts.rs` and `tests/readme_set_flag_permanence.rs` use to hold a
//! document to something other than the next editor's memory.

const DESIGN: &str = include_str!("../docs/DESIGN.md");

/// The section heading, matched by its lead so a retitle that keeps the list intact still resolves.
const SECTION_HEADING_PREFIX: &str = "## Remaining Go surface to match";

/// The phrase the preamble disowns, and therefore the one no entry may wear as its status.
const DISOWNED: &str = "out of scope";

/// The statuses the section allows an entry to carry, lowercased for matching. The first two are
/// the taxonomy the preamble names; `shipped`/`done` cover an entry that closed since it was
/// listed and is kept for the record (`configure kubeconfig` is one today).
const STATUSES: &[&str] = &["not-yet-built", "blocked", "deferred", "shipped", "done"];

/// Body of the section, heading excluded, up to the next top-level heading.
fn section() -> &'static str {
    let start = DESIGN.find(SECTION_HEADING_PREFIX).unwrap_or_else(|| {
        panic!("docs/DESIGN.md should still contain a `{SECTION_HEADING_PREFIX}` section")
    });
    let body = &DESIGN[start + SECTION_HEADING_PREFIX.len()..];
    match body.find("\n## ") {
        Some(end) => &body[..end],
        None => body,
    }
}

/// The prose between the heading and the first entry — where the taxonomy is defined.
fn preamble() -> &'static str {
    let body = section();
    match body.find("\n- ") {
        Some(end) => &body[..end],
        None => panic!("the section should still list entries as `- ` bullets"),
    }
}

/// The entries themselves: each top-level `- ` bullet together with its indented continuation
/// paragraphs, so a status (or a disowned phrase) written in an entry's second paragraph is read
/// as part of that entry. Stops at the first unindented line that is not a bullet, which is where
/// the trailing blockquote about the release gate begins.
fn entries() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    for line in section().lines() {
        if line.starts_with("- ") {
            if let Some(entry) = current.take() {
                out.push(entry);
            }
            current = Some(line.to_string());
        } else if line.trim().is_empty() || line.starts_with("  ") {
            if let Some(entry) = current.as_mut() {
                entry.push('\n');
                entry.push_str(line);
            }
        } else if let Some(entry) = current.take() {
            out.push(entry);
        }
    }
    out.extend(current);
    out
}

/// The first line of an entry, for a failure message that points at the right bullet.
fn lead(entry: &str) -> &str {
    entry.lines().next().unwrap_or(entry)
}

#[test]
fn the_preamble_still_defines_the_taxonomy_the_entries_are_checked_against() {
    let preamble = preamble();
    for promised in [
        "*not-yet-built*",
        "*blocked*",
        "deferral with a named unblock",
    ] {
        assert!(
            preamble.contains(promised),
            "the section's preamble should still promise `{promised}`; got:\n{preamble}"
        );
    }
    // The disowning sentence is what makes "out of scope" a defect below rather than a synonym.
    assert!(
        preamble.contains("\"out of scope by choice.\""),
        "the preamble should still disown `out of scope by choice`; got:\n{preamble}"
    );
}

#[test]
fn every_entry_carries_a_status_from_that_taxonomy() {
    for entry in entries() {
        let lowered = entry.to_lowercase();
        assert!(
            STATUSES.iter().any(|status| lowered.contains(status)),
            "`{}` should carry one of {STATUSES:?}; got:\n{entry}",
            lead(&entry)
        );
    }
}

#[test]
fn no_entry_is_filed_under_the_phrase_the_preamble_disowns() {
    for entry in entries() {
        assert!(
            !entry.to_lowercase().contains(DISOWNED),
            "`{}` reads as a decision to skip the feature, which this section says never happens \
             — describe it as deferred, or blocked on its named unblock; got:\n{entry}",
            lead(&entry)
        );
    }
}

#[test]
fn the_tpm_entry_is_deferred_on_the_two_layers_it_actually_waits_for() {
    let matches: Vec<String> = entries()
        .into_iter()
        .filter(|entry| {
            entry.contains("--encrypt-state") && entry.contains("--hardware-attestation")
        })
        .collect();
    let [entry] = matches.as_slice() else {
        panic!(
            "expected exactly one entry covering both TPM flags, found {}",
            matches.len()
        );
    };
    let lowered = entry.to_lowercase();
    assert!(
        lowered.contains("blocked") || lowered.contains("deferred"),
        "the TPM entry should be blocked/deferred, not skipped; got:\n{entry}"
    );
    // A deferral is only a deferral if it names what would end it. Both layers, both spellings.
    assert!(
        lowered.contains("keystore") || lowered.contains("key store"),
        "the TPM entry should name the platform keystore it waits on; got:\n{entry}"
    );
    assert!(
        lowered.contains("state-store") || lowered.contains("state store"),
        "the TPM entry should name the pluggable state-store layer it waits on; got:\n{entry}"
    );
}
