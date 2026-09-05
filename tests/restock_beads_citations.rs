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
//! It deliberately does NOT check that the paths exist upstream — that needs the network, and CI
//! has none. What it can hold is the shape, and the shape is what silently rots: the first entry
//! written by hand rather than generated is the one that says `ping.go` instead of
//! `cmd/tailscale/cli/ping.go @ <commit>`.
//!
//! An empty `beads` array is legitimate — a sweep that found nothing new says so — so the tests
//! below are all per-entry, and none of them requires there to be an entry.
//!
//! Read with [`include_str!`], as `tests/parity_audit_ledger.rs` reads `PARITY_AUDIT.json`.

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
        // Exactly one ` @ ` separator: "<path> @ <commit>". Splitting on the whole separator (not
        // on '@') keeps an email-shaped path from being read as a citation.
        let parts: Vec<&str> = upstream.split(" @ ").collect();
        assert_eq!(
            parts.len(),
            2,
            "bead {i}: `upstream` should be `<path> @ <commit>`, got {upstream:?}"
        );
        let (path, commit) = (parts[0], parts[1]);
        assert_eq!(
            commit, pin,
            "bead {i}: citation commit should be the pinned commit, got {commit:?}"
        );
        assert!(
            !path.is_empty() && !path.starts_with('/') && !path.contains(' '),
            "bead {i}: citation path should be a repo-relative upstream path, got {path:?}"
        );
        // A gap is verified in a file, not in a package. `cmd/tailscale/cli` names a directory a
        // reader still has to search; `cmd/tailscale/cli/ping.go` is the thing that was read.
        assert!(
            path.ends_with(".go"),
            "bead {i}: citation should name a Go source file, got {path:?}"
        );
    }
}

#[test]
fn no_two_entries_file_the_same_title() {
    let mut seen: Vec<String> = Vec::new();
    for (i, bead) in beads(&restock()).into_iter().enumerate() {
        let title = bead["title"]
            .as_str()
            .expect("`title` should be a string")
            .to_string();
        assert!(
            !seen.contains(&title),
            "bead {i}: duplicate title {title:?} — two beads for one gap"
        );
        seen.push(title);
    }
}
