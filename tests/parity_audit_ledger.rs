//! `PARITY_AUDIT.json` must agree with itself: the counts it states, the verdicts it records, and
//! the divergences it lists are three views of one audit, and a reader trusts them because they
//! match.
//!
//! They did not. The file went in with five `gaps` rows and five `faithful` ones while the prose
//! that shipped it announced "six faithful; four gaps" — a reader had to recount ten rows by hand
//! to find out which half was wrong. A ledger nobody can trust without redoing its arithmetic is
//! no cheaper to consult than re-reading the ten merged diffs it exists to summarise.
//!
//! So the totals now live in the file, next to the rows they count, and this test recomputes them
//! from those rows. It also checks the structural claim the totals rest on — a `gaps` row is a row
//! with at least one entry in `findings`, and a `faithful` row is one with none — because that is
//! what makes a verdict a fact about the data rather than an assertion beside it.
//!
//! The last test is narrower: it holds the `#296` row's two named divergences to having a finding
//! each. That row's notes named both the narrowed parent-directory creation and the missing
//! `checkKubeconfigWritable` precheck, but only the first was written up, and a divergence named
//! in a summary and absent from the list is exactly the kind of gap this file is meant to close.
//!
//! The last two tests are about evidence rather than arithmetic. The rows cite upstream by line
//! number - `up.go:305-307`, `(line 222)` - and a line number is only checkable next to the
//! revision it counts in. The file carried that revision in prose only ("against upstream
//! v1.102.3"), and a reader who resolved a bare `up.go:305` against `main` instead landed on
//! unrelated code and concluded the citations had gone stale. They had not. So the pin now has a
//! field of its own, every citation is anchored to it, and the anchors all have to name the same
//! commit - a row re-cut against a later release would otherwise read like all the others while
//! pointing at different code.
//!
//! Read with [`include_str!`], the trick `tests/engine_doc_publish_verdicts.rs` and
//! `tests/design_deferral_taxonomy.rs` use to hold a document to something firmer than the next
//! editor's memory.

use serde_json::Value;

const AUDIT: &str = include_str!("../PARITY_AUDIT.json");

/// The two verdicts the audit assigns. Anything else is a typo that would silently fall out of
/// both totals, so it is rejected rather than counted.
const VERDICTS: &[&str] = &["faithful", "gaps"];

fn audit() -> Value {
    serde_json::from_str(AUDIT).expect("PARITY_AUDIT.json should be valid JSON")
}

/// The `auditedPrs` rows, as `(pull request url, verdict)`.
fn rows(audit: &Value) -> Vec<(String, String)> {
    audit["auditedPrs"]
        .as_array()
        .expect("`auditedPrs` should be an array")
        .iter()
        .map(|row| {
            let url = row["url"].as_str().expect("a row should carry a `url`");
            let verdict = row["verdict"]
                .as_str()
                .expect("a row should carry a `verdict`");
            (url.to_string(), verdict.to_string())
        })
        .collect()
}

/// The `findings` entries, as `(pull request url, title + detail)` — the two prose fields joined,
/// because which of them names a symbol is an editorial choice and not one worth testing.
fn findings(audit: &Value) -> Vec<(String, String)> {
    audit["findings"]
        .as_array()
        .expect("`findings` should be an array")
        .iter()
        .map(|f| {
            let url = f["prUrl"]
                .as_str()
                .expect("a finding should carry a `prUrl`");
            let title = f["title"].as_str().unwrap_or_default();
            let detail = f["detail"].as_str().unwrap_or_default();
            (url.to_string(), format!("{title}\n{detail}"))
        })
        .collect()
}

#[test]
fn the_stated_totals_match_the_rows_they_count() {
    let audit = audit();
    let summary = &audit["summary"];
    assert!(
        summary.is_object(),
        "PARITY_AUDIT.json should carry a `summary` block stating the totals, so a reader does not \
         have to recount the rows to check a claim made about them"
    );

    let rows = rows(&audit);
    let faithful = rows.iter().filter(|(_, v)| v == "faithful").count();
    let gaps = rows.iter().filter(|(_, v)| v == "gaps").count();
    let findings = findings(&audit).len();

    for (key, computed) in [
        ("auditedPrs", rows.len()),
        ("faithful", faithful),
        ("gaps", gaps),
        ("findings", findings),
    ] {
        let stated = summary[key].as_u64().unwrap_or_else(|| {
            panic!("`summary.{key}` should be a number; the rows below say {computed}")
        });
        assert_eq!(
            stated as usize, computed,
            "`summary.{key}` says {stated}, the rows say {computed}"
        );
    }

    // Belt and braces: the two verdict totals have to exhaust the rows, or a third verdict word
    // has crept in and both totals are quietly under-reporting.
    assert_eq!(
        faithful + gaps,
        rows.len(),
        "every audited pull request should be counted by exactly one verdict total"
    );
}

#[test]
fn every_verdict_is_one_the_audit_defines() {
    for (url, verdict) in rows(&audit()) {
        assert!(
            VERDICTS.contains(&verdict.as_str()),
            "{url} carries verdict {verdict:?}, which is neither {VERDICTS:?}"
        );
    }
}

#[test]
fn a_gaps_verdict_is_backed_by_a_finding_and_a_faithful_one_by_none() {
    let audit = audit();
    let findings = findings(&audit);
    let rows = rows(&audit);

    for (url, verdict) in &rows {
        let count = findings.iter().filter(|(pr, _)| pr == url).count();
        match verdict.as_str() {
            "gaps" => assert!(
                count > 0,
                "{url} is recorded as `gaps` but no entry in `findings` says what the gap is"
            ),
            "faithful" => assert_eq!(
                count, 0,
                "{url} is recorded as `faithful` but `findings` lists {count} divergence(s) \
                 against it"
            ),
            other => unreachable!("unknown verdict {other:?} on {url}"),
        }
    }

    // A finding against a pull request the audit never read is a dangling row: nothing states what
    // was checked, so nothing supports the verdict it implies.
    for (pr, _) in &findings {
        assert!(
            rows.iter().any(|(url, _)| url == pr),
            "`findings` names {pr}, which is not one of the audited pull requests"
        );
    }
}

#[test]
fn the_kubeconfig_row_writes_up_both_divergences_its_notes_name() {
    const PR: &str = "https://github.com/GeiserX/tailscaled-rs/pull/296";
    // Both are Go symbols from `cmd/tailscale/cli/configure-kube.go`: the call the port narrowed,
    // and the precheck it left out.
    const NAMED: &[&str] = &["MkdirAll", "checkKubeconfigWritable"];

    let audit = audit();
    let notes = audit["auditedPrs"]
        .as_array()
        .expect("`auditedPrs` should be an array")
        .iter()
        .find(|row| row["url"].as_str() == Some(PR))
        .map(|row| row["notes"].as_str().unwrap_or_default().to_string())
        .unwrap_or_else(|| panic!("{PR} should still be one of the audited pull requests"));

    let written_up = findings(&audit)
        .into_iter()
        .filter(|(pr, _)| pr == PR)
        .map(|(_, prose)| prose)
        .collect::<Vec<_>>()
        .join("\n");

    for symbol in NAMED {
        assert!(
            notes.contains(symbol),
            "the {PR} row's notes no longer mention {symbol}; if the divergence went away, drop it \
             from this test too"
        );
        assert!(
            written_up.contains(symbol),
            "the {PR} row's notes name a {symbol} divergence that no entry in `findings` writes \
             up, so the summary claims a gap the list does not carry"
        );
    }
}

/// The pinned upstream revision, read from the file so the test states no line number of its own.
fn pinned(audit: &Value) -> (String, String) {
    let upstream = &audit["summary"]["upstream"];
    assert!(
        upstream.is_object(),
        "`summary.upstream` should name the revision the citations below are line numbers in; \
         without it a bare `up.go:305` is only reproducible by guessing which revision it meant"
    );
    let git_ref = upstream["ref"]
        .as_str()
        .expect("`summary.upstream.ref` should name the upstream release, e.g. `v1.102.3`");
    let commit = upstream["commit"].as_str().expect(
        "`summary.upstream.commit` should carry the full commit the release tag resolves to",
    );
    (git_ref.to_string(), commit.to_string())
}

/// Every `upstream` field in the file, as `(what it belongs to, its value)`.
fn upstream_fields(audit: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for row in audit["auditedPrs"].as_array().unwrap_or(&Vec::new()) {
        if let Some(u) = row["upstream"].as_str() {
            let url = row["url"].as_str().unwrap_or("an audited row");
            out.push((format!("the {url} row"), u.to_string()));
        }
    }
    for f in audit["findings"].as_array().unwrap_or(&Vec::new()) {
        if let Some(u) = f["upstream"].as_str() {
            let title = f["title"].as_str().unwrap_or("an untitled finding");
            out.push((format!("the finding {title:?}"), u.to_string()));
        }
    }
    out
}

/// Does this prose hang a line number off an upstream Go file? Two spellings are in use — the
/// `serve_v2.go:1407` form and the `(line 222)` form the `#302` row writes out — and both leave a
/// reader needing to know which revision to count lines in. Fork-side citations (`…rs:12428`) are
/// not upstream and are anchored by the repository's own history instead.
fn cites_an_upstream_line(text: &str) -> bool {
    let digit_follows = |sep: &str| {
        text.split(sep)
            .skip(1)
            .any(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
    };
    digit_follows(".go:") || digit_follows("line ") || digit_follows("lines ")
}

#[test]
fn the_audit_states_the_revision_its_line_numbers_belong_to() {
    let audit = audit();
    let (git_ref, commit) = pinned(&audit);

    assert!(
        commit.len() == 40
            && commit
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "`summary.upstream.commit` is {commit:?}; it should be a full 40-character commit hash, \
         because a tag can be moved and an abbreviation can become ambiguous"
    );
    assert!(
        audit["summary"]["note"]
            .as_str()
            .unwrap_or_default()
            .contains(&git_ref),
        "`summary.note` describes the audit without naming {git_ref}, the release \
         `summary.upstream.ref` pins it to; the prose and the field should agree on one revision"
    );
}

#[test]
fn every_upstream_citation_is_anchored_to_the_pinned_revision() {
    let audit = audit();
    let (_, commit) = pinned(&audit);

    // A row or a finding that counts lines in an upstream file has to say which file, at which
    // revision. This is the whole difference between evidence and an assertion: `up.go:305-307` is
    // checkable in one command against a stated commit and unfalsifiable without one.
    let mut cited: Vec<(String, String)> = Vec::new();
    for row in audit["auditedPrs"].as_array().expect("`auditedPrs`") {
        let url = row["url"].as_str().unwrap_or_default().to_string();
        cited.push((
            format!("the {url} row"),
            row["notes"].as_str().unwrap_or_default().to_string(),
        ));
    }
    for f in audit["findings"].as_array().expect("`findings`") {
        let title = f["title"].as_str().unwrap_or_default();
        cited.push((
            format!("the finding {title:?}"),
            format!("{}\n{}", title, f["detail"].as_str().unwrap_or_default()),
        ));
    }

    for (what, prose) in &cited {
        if !cites_an_upstream_line(prose) {
            continue;
        }
        let anchored = upstream_fields(&audit)
            .iter()
            .any(|(owner, _)| owner == what);
        assert!(
            anchored,
            "{what} counts lines in an upstream Go file but carries no `upstream` field saying \
             which file, at which revision, those lines are in"
        );
    }

    // And every anchor points at the one pinned revision. A citation quietly re-cut against a
    // later release reads exactly like the rest of the file while resolving to other code.
    let fields = upstream_fields(&audit);
    assert!(
        !fields.is_empty(),
        "no `upstream` field anywhere in the audit; nothing here is reproducible"
    );
    for (what, value) in fields {
        assert!(
            value.contains(&format!("@ {commit}")),
            "{what} cites {value:?}, which is not the pinned revision {commit}"
        );
        assert!(
            value.contains(".go"),
            "{what} cites {value:?}, which names no upstream Go file"
        );
    }
}
