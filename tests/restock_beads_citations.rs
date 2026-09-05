//! `docs/restock-beads.json` is the hand-off from a parity sweep to the tracker: each entry names a
//! gap and cites the upstream file it was verified against. The citation is the whole value of the
//! file. An entry whose `upstream` says "the CLI" or points at a commit nobody swept is worse than
//! no entry at all — it files a bead a reader cannot check, and the next sweep re-finds the same
//! gap because it cannot tell what the last one already looked at.
//!
//! So the rule is mechanical and this test enforces it mechanically: every entry cites exactly one
//! upstream path, at the same commit the file pins in its header, written `<path> @ <commit>`. A
//! path that starts with a slash, carries a space, or names no file is not a citation; a commit
//! that disagrees with `pin` means the entry and the sweep are describing two different trees.
//!
//! The other half of the contract is one gap per entry, and the two fields that carry the gap are
//! the two this file holds unique: no two entries may file the same `title`, and no two may file
//! the same `description`. Both comparisons normalise first ([`normalized`]) — trimmed, internal
//! whitespace squeezed, case folded — because a re-file that survives review is far likelier to
//! differ by a stray double space or a capital letter than by a word. The description is in there
//! because it is the field that cannot be legitimately shared: two entries may reasonably arrive at
//! similar titles, but a repeated paragraph is a copied entry somebody edited the title of and
//! nothing else.
//!
//! The citation *path* is deliberately NOT unique, and
//! [`two_entries_may_cite_the_same_upstream_file`] pins that down so it is not quietly tightened
//! later. One upstream file holds many independent gaps — `cmd/tailscale/cli/up.go` alone carries
//! every `up` flag, `warnOnAdvertiseRoutes` and `runUp`'s refusals — and a sweep that finds two of
//! them has two beads to file, not one. Forbidding the repeat would leave a sweeper two ways out
//! and both are worse than the duplicate: fold two unrelated gaps into one undifferentiated bead,
//! or cite the second to some other file to get past the check — a citation to a file nobody read,
//! which is the exact rot the paragraph above calls worse than no entry at all.
//!
//! It deliberately does NOT check that the paths exist upstream — that needs the network, and CI
//! has none. What it can hold is the shape, and the shape is what silently rots: the first entry
//! written by hand rather than generated is the one that says `ping.go` instead of
//! `cmd/tailscale/cli/ping.go @ <commit>`.
//!
//! An empty `beads` array is legitimate — a sweep that found nothing new says so — so the tests
//! below are all per-entry, and none of them requires there to be an entry.
//!
//! The rules live in [`citation_defect`] and [`first_collision`] so the tests over the real file
//! and the tests over synthetic entries run the same code, the way `tests/markdown_table_cells.rs`
//! splits `table_defects` from the documents it scans. Read with [`include_str!`], as
//! `tests/parity_audit_ledger.rs` reads `PARITY_AUDIT.json`.

use serde_json::Value;

const RESTOCK: &str = include_str!("../docs/restock-beads.json");

/// The schema tag the factory dispatches on. A file that renames it is a different format.
const SCHEMA: &str = "restock-beads/v1";

fn restock() -> Value {
    serde_json::from_str(RESTOCK).expect("docs/restock-beads.json should be valid JSON")
}

fn pin(doc: &Value) -> String {
    doc["pin"]
        .as_str()
        .expect("`pin` should be a string")
        .to_string()
}

fn beads(doc: &Value) -> Vec<Value> {
    doc["beads"]
        .as_array()
        .expect("`beads` should be an array")
        .clone()
}

/// Why one `upstream` string is not a citation, or `None` when it is one.
///
/// Splitting on the whole ` @ ` separator (not on '@') keeps an email-shaped path from being read
/// as a citation: exactly one separator, so exactly one path and one commit.
fn citation_defect(upstream: &str, pin: &str) -> Option<String> {
    let parts: Vec<&str> = upstream.split(" @ ").collect();
    if parts.len() != 2 {
        return Some(format!(
            "`upstream` should be `<path> @ <commit>`, got {upstream:?}"
        ));
    }
    let (path, commit) = (parts[0], parts[1]);
    if commit != pin {
        return Some(format!(
            "citation commit should be the pinned commit {pin:?}, got {commit:?}"
        ));
    }
    if path.is_empty() || path.starts_with('/') || path.contains(' ') {
        return Some(format!(
            "citation path should be a repo-relative upstream path, got {path:?}"
        ));
    }
    // A gap is verified in a file, not in a package. `cmd/tailscale/cli` names a directory a
    // reader still has to search; `cmd/tailscale/cli/ping.go` is the thing that was read.
    if !path.ends_with(".go") {
        return Some(format!(
            "citation should name a Go source file, got {path:?}"
        ));
    }
    None
}

/// The form two entries are compared in: trimmed, every run of whitespace squeezed to one space,
/// case folded. Two entries that differ only in typography are one entry filed twice.
fn normalized(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// The first pair of entries whose `field` is the same string once [`normalized`], as
/// `(earlier index, later index, the later entry's text)`.
fn first_collision(beads: &[Value], field: &str) -> Option<(usize, usize, String)> {
    let mut seen: Vec<(String, usize)> = Vec::new();
    for (i, bead) in beads.iter().enumerate() {
        let raw = bead[field]
            .as_str()
            .unwrap_or_else(|| panic!("bead {i}: `{field}` should be a string"));
        let key = normalized(raw);
        if let Some((_, earlier)) = seen.iter().find(|(seen_key, _)| *seen_key == key) {
            return Some((*earlier, i, raw.to_string()));
        }
        seen.push((key, i));
    }
    None
}

#[test]
fn header_names_the_schema_and_a_full_commit_sha() {
    let doc = restock();
    assert_eq!(
        doc["schema"].as_str(),
        Some(SCHEMA),
        "`schema` should be {SCHEMA}"
    );
    let pin = pin(&doc);
    // A tag name would be ambiguous — tags move, and the citations below have to name the exact
    // tree the sweep read. Require the resolved 40-hex commit.
    assert_eq!(
        pin.len(),
        40,
        "`pin` should be a full 40-hex commit: {pin:?}"
    );
    assert!(
        pin.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "`pin` should be lowercase hex: {pin:?}"
    );
}

#[test]
fn every_entry_carries_the_four_required_fields() {
    for (i, bead) in beads(&restock()).into_iter().enumerate() {
        for field in ["title", "description", "upstream"] {
            let v = bead[field]
                .as_str()
                .unwrap_or_else(|| panic!("bead {i}: `{field}` should be a non-empty string"));
            assert!(
                !v.trim().is_empty(),
                "bead {i}: `{field}` should not be blank"
            );
        }
        let priority = bead["priority"]
            .as_u64()
            .unwrap_or_else(|| panic!("bead {i}: `priority` should be an integer"));
        assert!(
            (1..=4).contains(&priority),
            "bead {i}: `priority` should be 1-4, got {priority}"
        );
    }
}

#[test]
fn every_citation_is_one_path_at_the_pinned_commit() {
    let doc = restock();
    let pin = pin(&doc);
    for (i, bead) in beads(&doc).into_iter().enumerate() {
        let upstream = bead["upstream"]
            .as_str()
            .expect("`upstream` should be a string");
        if let Some(defect) = citation_defect(upstream, &pin) {
            panic!("bead {i}: {defect}");
        }
    }
}

#[test]
fn no_two_entries_file_the_same_title() {
    if let Some((earlier, later, title)) = first_collision(&beads(&restock()), "title") {
        panic!("beads {earlier} and {later} file the same title {title:?} — two beads for one gap");
    }
}

#[test]
fn no_two_entries_file_the_same_description() {
    if let Some((earlier, later, _)) = first_collision(&beads(&restock()), "description") {
        panic!(
            "beads {earlier} and {later} file the same description — one entry copied and retitled"
        );
    }
}

/// A synthetic entry, for the tests that exercise the rules on input the real file must never hold.
fn entry(title: &str, description: &str) -> Value {
    serde_json::json!({ "title": title, "description": description })
}

const PIN: &str = "53a0d659afa51835dd7a9283873cca44261454f8";

#[test]
fn a_title_that_differs_only_in_spacing_is_a_duplicate() {
    let entries = [
        entry("ping --timeout takes milliseconds", "one"),
        entry("Ping  --timeout\ttakes milliseconds ", "two"),
    ];
    let (earlier, later, _) =
        first_collision(&entries, "title").expect("a retyped title is still the same title");
    assert_eq!((earlier, later), (0, 1));
}

#[test]
fn a_description_repeated_under_a_new_title_is_a_duplicate() {
    let entries = [
        entry("no health tracker", "StatusReport.health holds one entry."),
        entry("Health is a stub", "StatusReport.health holds one entry."),
    ];
    let (earlier, later, _) = first_collision(&entries, "description")
        .expect("a copied entry with a fresh title is still a copied entry");
    assert_eq!((earlier, later), (0, 1));
}

#[test]
fn entries_that_differ_in_both_fields_do_not_collide() {
    let entries = [
        entry(
            "no completion subcommand",
            "ffcomplete.Inject has no counterpart.",
        ),
        entry("no health tracker", "StatusReport.health holds one entry."),
    ];
    assert_eq!(first_collision(&entries, "title"), None);
    assert_eq!(first_collision(&entries, "description"), None);
}

/// Two gaps found in one upstream file are two beads, and both cite the file they were read in.
///
/// This is the rule the module doc argues for, kept executable so a later pass does not tighten it
/// into path-uniqueness by accident. `up.go` holds `warnOnAdvertiseRoutes` and `--timeout`'s
/// grammar and they are unrelated gaps; a check that rejected the second citation would only push
/// the sweeper into naming a file nobody read.
#[test]
fn two_entries_may_cite_the_same_upstream_file() {
    let shared = format!("cmd/tailscale/cli/up.go @ {PIN}");
    assert_eq!(citation_defect(&shared, PIN), None);
    assert_eq!(citation_defect(&shared, PIN), None);
}

#[test]
fn a_citation_that_names_a_directory_is_a_defect() {
    let defect = citation_defect(&format!("cmd/tailscale/cli @ {PIN}"), PIN)
        .expect("a package is not a file");
    assert!(defect.contains("Go source file"), "{defect}");
}

#[test]
fn a_citation_at_another_commit_is_a_defect() {
    let stale = "cmd/tailscale/cli/up.go @ ac33a4cc1a33c6eb9f48eae0c2eca08e0c5b56c5";
    let defect =
        citation_defect(stale, PIN).expect("a citation off the pin describes another tree");
    assert!(defect.contains("pinned commit"), "{defect}");
}

#[test]
fn a_citation_with_no_separator_is_a_defect() {
    let defect = citation_defect("cmd/tailscale/cli/up.go", PIN).expect("a path is not a citation");
    assert!(defect.contains("<path> @ <commit>"), "{defect}");
}
