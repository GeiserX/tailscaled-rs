//! The audit-log ask in `docs/ENGINE_ASKS.md` must not offer a shape that silently leaves one of
//! the two commands it promises behind.
//!
//! Ask #41 exists so that `tnet logout --reason` and `tnet down --reason` stop being local-only,
//! and it hands the engine two API shapes to choose between. Only one of them can carry both:
//! `logout` is a control-plane call the engine already makes, so a reason argument on it reaches
//! control, but `down` never calls the engine at all (`Backend::down` in `src/ipn/mod.rs` tears the
//! datapath down and persists `want_running = false`, and that is the whole operation). A
//! logout-only shape therefore satisfies the ask's own "Daemon impact once landed" promise for
//! exactly half the commands it names — and an engine implementer who picks it because the ask read
//! as interchangeable would leave `down --reason` local-only with nothing left to file.
//!
//! So the asymmetry has to be written down where the choice is made. This test holds the section to
//! it with [`include_str!`], the same trick `tests/engine_doc_publish_verdicts.rs` and
//! `tests/design_deferral_taxonomy.rs` use to keep a document honest against something other than
//! the next editor's memory.

const ASKS: &str = include_str!("../docs/ENGINE_ASKS.md");

/// The ask, matched by its number so a retitle that keeps the ask intact still resolves.
const SECTION_HEADING_PREFIX: &str = "## 41.";

/// The logout-only API the first option offers.
const LOGOUT_ONLY_API: &str = "logout_with_reason";

/// The general audit submission — the only offered shape a `down` can travel on.
const GENERAL_API: &str = "send_audit_log";

/// Body of ask #41, heading excluded, up to the next top-level heading.
fn section() -> &'static str {
    let start = ASKS.find(SECTION_HEADING_PREFIX).unwrap_or_else(|| {
        panic!("docs/ENGINE_ASKS.md should still contain a `{SECTION_HEADING_PREFIX}` section")
    });
    let body = &ASKS[start + SECTION_HEADING_PREFIX.len()..];
    match body.find("\n## ") {
        Some(end) => &body[..end],
        None => body,
    }
}

/// The numbered options under `**Ask`, each as the text from its own `N. ` line up to the next
/// one (or to the end of the ask) — so prose written under an option, after its code fence, is
/// read as part of that option and not of its neighbour.
fn ask_options() -> Vec<String> {
    let body = section();
    let ask = body
        .find("**Ask")
        .map(|start| &body[start..])
        .expect("the ask should still introduce its API shapes with a `**Ask` line");
    // A line that opens an option looks like `1. …`: everything before the first `. ` is digits.
    let starts_option = |line: &str| {
        line.split_once(". ")
            .is_some_and(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
    };
    let mut out: Vec<String> = Vec::new();
    for line in ask.lines() {
        if starts_option(line) {
            out.push(String::new());
        }
        if let Some(current) = out.last_mut() {
            current.push_str(line);
            current.push('\n');
        }
    }
    assert!(
        out.len() >= 2,
        "the ask should still offer more than one API shape: {ask}"
    );
    out
}

/// The paragraph that promises what lands once the engine ships this.
fn daemon_impact() -> &'static str {
    let body = section();
    let start = body
        .find("**Daemon impact once landed:**")
        .expect("ask #41 should still carry a `**Daemon impact once landed:**` paragraph");
    &body[start..]
}

#[test]
fn the_logout_only_shape_says_it_does_not_carry_down() {
    let logout_only: Vec<String> = ask_options()
        .into_iter()
        .filter(|o| o.contains(LOGOUT_ONLY_API) && !o.contains(GENERAL_API))
        .collect();
    for option in &logout_only {
        assert!(
            option.contains("down"),
            "an option that offers only `{LOGOUT_ONLY_API}` must say what it does to \
             `down --reason`, or an implementer reads it as covering both: {option}"
        );
        assert!(
            option.contains(GENERAL_API) || option.contains("option 2"),
            "an option that offers only `{LOGOUT_ONLY_API}` must point at the shape that does \
             carry `down`'s reason: {option}"
        );
    }
}

#[test]
fn the_landing_promise_names_the_shape_that_carries_downs_reason() {
    let impact = daemon_impact();
    assert!(
        impact.contains("down --reason"),
        "the promise should still name `down --reason`: {impact}"
    );
    assert!(
        impact.contains(GENERAL_API) || impact.contains("option 2"),
        "the promise that `down --reason` stops being local-only must name the shape that gets it \
         there, so half an implementation is not read as all of it: {impact}"
    );
}
