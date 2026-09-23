//! The c2n ask in `docs/ENGINE_ASKS.md` must not quietly promise to answer the control plane's
//! debug reads.
//!
//! Ask #43 asks the engine for one primitive — a way to register a control-to-node handler — and
//! then does something the other asks do not have to: it says which of upstream's ~20 c2n handlers
//! this fork would answer with it, and which it would not. That second list is the security
//! judgement. Upstream's `/debug/*` family is a remote read of daemon internals *by the control
//! plane*, and `docs/THREAT_MODEL.md` names a compromised control plane as adversary (d) and
//! records it as unmitigated — so those paths are a decision of their own, taken after the hook
//! lands, not a rider on it.
//!
//! The failure this guards against is a quiet one. An editor extending the "would answer first"
//! list — `/debug/health` looks harmless next to `/posture/identity`, and `/debug/prefs` reads like
//! the prefs readback the fork already has over LocalAPI — moves a path across that line without
//! touching the paragraph that explains why the line is there, and the ask then reads as
//! pre-approval for something nobody approved. Whoever implements it downstream is reading the
//! list, not the paragraph.
//!
//! So the two lists are checked against each other, and against the two pref doc comments that
//! point at this ask for their missing behaviour. The paths are parsed out of the document rather
//! than written down here: a path this file never heard of is still held to the rule.
//!
//! Held with [`include_str!`], the same trick `tests/engine_ask_reason_covers_down.rs` and
//! `tests/engine_doc_publish_verdicts.rs` use to keep a document honest against something firmer
//! than the next editor's memory.

const ASKS: &str = include_str!("../docs/ENGINE_ASKS.md");
const PREFS: &str = include_str!("../src/prefs.rs");
const THREAT_MODEL: &str = include_str!("../docs/THREAT_MODEL.md");
const SYSPOLICY: &str = include_str!("../src/ipn/syspolicy.rs");

/// Every c2n handler upstream registers at `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8` (v1.102.4),
/// method prefix dropped, each with the Go file that registers it. A census that misses one scopes
/// the hook against a table that is not upstream's.
const GO_C2N_HANDLERS: &[(&str, &str)] = &[
    ("/echo", "ipn/ipnlocal/c2n.go"),
    ("/logtail/flush", "ipn/ipnlocal/c2n.go"),
    ("/sockstats", "ipn/ipnlocal/c2n.go"),
    ("/debug/pprof/heap", "ipn/ipnlocal/c2n.go"),
    ("/debug/pprof/allocs", "ipn/ipnlocal/c2n.go"),
    ("/debug/goroutines", "ipn/ipnlocal/c2n.go"),
    ("/debug/prefs", "ipn/ipnlocal/c2n.go"),
    ("/debug/metrics", "ipn/ipnlocal/c2n.go"),
    ("/debug/component-logging", "ipn/ipnlocal/c2n.go"),
    ("/debug/logheap", "ipn/ipnlocal/c2n.go"),
    ("/debug/netmap", "ipn/ipnlocal/c2n.go"),
    ("/debug/health", "ipn/ipnlocal/c2n.go"),
    ("/netfilter-kind", "ipn/ipnlocal/c2n.go"),
    ("/update", "feature/clientupdate/clientupdate.go"),
    ("/posture/identity", "feature/posture/posture.go"),
    (
        "/appconnector/routes",
        "feature/appconnectors/appconnectors.go",
    ),
    ("/wol", "feature/wakeonlan/wakeonlan.go"),
    ("/vip-services", "ipn/ipnlocal/serve.go"),
    ("/tls-cert-status", "ipn/ipnlocal/cert.go"),
    ("/ssh/usernames", "ssh/tailssh/tailssh.go"),
    ("/debug/tka/log", "feature/tailnetlock/tailnetlock.go"),
    ("/conn25/state", "feature/conn25/conn25.go"),
];

/// The two paths the engine already answers itself, which the ask keeps engine-side rather than
/// listing as answered or declined.
const ENGINE_ANSWERED: &[&str] = &["/echo", "/vip-services"];

/// The ask, matched by its number so a retitle that keeps the ask intact still resolves.
const ASK_HEADING_PREFIX: &str = "## 43.";

/// The subsection naming what this fork would answer once the hook exists.
const ANSWERED_HEADING: &str = "### The handlers this fork would answer first";

/// The subsection naming what it would not, and why not yet.
const DECLINED_HEADING: &str =
    "### The handlers it declines until they have their own security answer";

/// The pref doc comments that record a reduction this ask is the mechanism behind, each paired with
/// the field's declaration as it is written in `src/prefs.rs`.
const REDUCED_PREFS: &[&str] = &["posture_checking", "auto_update_apply"];

/// Body of ask #43, heading excluded, up to the next top-level heading.
fn ask_section() -> &'static str {
    let start = ASKS.find(ASK_HEADING_PREFIX).unwrap_or_else(|| {
        panic!("docs/ENGINE_ASKS.md should still contain a `{ASK_HEADING_PREFIX}` section")
    });
    let body = &ASKS[start + ASK_HEADING_PREFIX.len()..];
    match body.find("\n## ") {
        Some(end) => &body[..end],
        None => body,
    }
}

/// Body of one `###` subsection of ask #43, heading excluded, up to the next `###`.
fn subsection(heading: &'static str) -> &'static str {
    let section = ask_section();
    let start = section
        .find(heading)
        .unwrap_or_else(|| panic!("ask #43 should still contain a `{heading}` subsection"));
    let body = &section[start + heading.len()..];
    match body.find("\n### ") {
        Some(end) => &body[..end],
        None => body,
    }
}

/// Every single-backtick code span in `text`, in order, contents only.
fn code_spans(text: &str) -> Vec<&str> {
    let mut spans = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else { break };
        spans.push(&after[..close]);
        rest = &after[close + 1..];
    }
    spans
}

/// The c2n request paths named in `text`, method prefix dropped and deduplicated.
///
/// A c2n path is written in this document the way control sends it: a code span that is either the
/// path itself (`` `/echo` ``) or an HTTP method and the path (`` `POST /update` ``). Everything
/// else in a code span — Go identifiers, Go source paths like `feature/posture/posture.go`, pref
/// names — is not a request path and is skipped, because only a leading `/` (after an optional
/// method) marks one.
fn c2n_paths(text: &str) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    for span in code_spans(text) {
        let candidate = match span.split_once(' ') {
            Some((method, rest)) if method.chars().all(|c| c.is_ascii_uppercase()) => rest,
            _ => span,
        };
        if !candidate.starts_with('/') {
            continue;
        }
        let path = candidate.trim().to_string();
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

/// The section number a markdown heading opens with, if it opens with one: `"## 3. Adversaries"`
/// and `"### 5.4 Tailnet Lock is INERT"` are `3` and `5.4`. The trailing period is optional in
/// `docs/THREAT_MODEL.md` — `§3` writes one and `§5.4` does not — so it is not part of the number.
fn heading_number(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('#')?.trim_start_matches('#').trim_start();
    let token = rest.split_whitespace().next()?.trim_end_matches('.');
    token
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.')
        .then_some(token)
        .filter(|t| !t.is_empty())
}

/// The doc comment above a `Prefs` field, joined into one line.
fn pref_doc(field: &str) -> String {
    let decl = format!("    pub {field}: ");
    let idx = PREFS
        .find(&decl)
        .unwrap_or_else(|| panic!("src/prefs.rs should still declare `{field}`"));
    let mut lines: Vec<&str> = PREFS[..idx]
        .lines()
        .rev()
        .map_while(|line| line.trim_start().strip_prefix("///"))
        .map(str::trim)
        .collect();
    lines.reverse();
    assert!(
        !lines.is_empty(),
        "`{field}` should still carry the doc comment that records what it cannot do"
    );
    lines.join(" ")
}

/// The `/debug/*` family is a remote read of daemon internals, so it belongs on the declined side
/// of the ask — named there, not merely absent from the other list.
#[test]
fn the_debug_family_is_declined_and_never_promised() {
    let answered = c2n_paths(subsection(ANSWERED_HEADING));
    let declined = c2n_paths(subsection(DECLINED_HEADING));

    let promised_debug: Vec<&String> = answered
        .iter()
        .filter(|p| p.starts_with("/debug"))
        .collect();
    assert!(
        promised_debug.is_empty(),
        "ask #43 lists {promised_debug:?} among the handlers this fork would answer first, but the \
         `/debug/*` family is a control-plane read of daemon internals: it needs the security \
         judgement in `{DECLINED_HEADING}`, and THREAT_MODEL §5.4 (a compromised control plane is \
         not mitigated) before anything answers it"
    );

    assert!(
        declined.iter().any(|p| p.starts_with("/debug")),
        "ask #43 should still name the `/debug/*` paths it declines; a family gestured at but not \
         enumerated is not a decision an implementer can act on. Declined paths found: {declined:?}"
    );
}

/// No path may be on both lists: "we would answer this first" and "we decline this" cannot both be
/// true of the same handler, and a reader acting on either statement gets the opposite behaviour.
#[test]
fn no_handler_is_both_promised_and_declined() {
    let answered = c2n_paths(subsection(ANSWERED_HEADING));
    let declined = c2n_paths(subsection(DECLINED_HEADING));

    let both: Vec<&String> = answered.iter().filter(|p| declined.contains(p)).collect();
    assert!(
        both.is_empty(),
        "ask #43 both promises and declines {both:?}"
    );
}

/// Every threat-model section the declined list leans on has to exist, because the whole weight of
/// declining rests on that citation being real and findable.
#[test]
fn the_declined_lists_threat_model_citations_resolve() {
    let declined = subsection(DECLINED_HEADING);

    let mut cited = Vec::new();
    let mut rest = declined;
    while let Some(at) = rest.find('§') {
        let after = &rest[at + '§'.len_utf8()..];
        let number: String = after
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let number = number.trim_end_matches('.').to_string();
        if !number.is_empty() && !cited.contains(&number) {
            cited.push(number);
        }
        rest = after;
    }

    assert!(
        !cited.is_empty(),
        "the declined list should cite the threat model that justifies declining, not just assert it"
    );
    for number in &cited {
        assert!(
            THREAT_MODEL
                .lines()
                .any(|line| heading_number(line) == Some(number.as_str())),
            "ask #43 cites THREAT_MODEL §{number}, which docs/THREAT_MODEL.md has no heading for"
        );
    }
}

/// The prefs that document a reduction because of the missing c2n channel must point at this ask,
/// and the handler each of them names must be one the ask actually commits to answering first —
/// otherwise the pointer leads to a document that would not fix the pref.
#[test]
fn the_reduced_prefs_point_at_an_ask_that_covers_them() {
    let answered = c2n_paths(subsection(ANSWERED_HEADING));

    for field in REDUCED_PREFS {
        let doc = pref_doc(field);
        assert!(
            doc.contains("ask #43"),
            "`Prefs::{field}` documents behaviour the missing c2n channel costs it, so it should \
             name the ask that would restore it (`ask #43`)"
        );

        let needed = c2n_paths(&doc);
        assert!(
            !needed.is_empty(),
            "`Prefs::{field}` should name the c2n path that would answer for it, so a reader can \
             find the handler rather than the subsystem"
        );
        for path in &needed {
            assert!(
                answered.contains(path),
                "`Prefs::{field}` points at ask #43 for `{path}`, but that path is not among the \
                 handlers the ask would answer first ({answered:?}) — the pref's pointer leads \
                 nowhere"
            );
        }
    }
}

/// The bullet of the answered subsection whose bold lead names `path`, up to the next bullet.
fn answered_bullet(path: &str) -> &'static str {
    subsection(ANSWERED_HEADING)
        .split("\n- ")
        .skip(1)
        .find(|bullet| {
            bullet
                .lines()
                .next()
                .is_some_and(|lead| lead.starts_with("**") && lead.contains(path))
        })
        .unwrap_or_else(|| panic!("ask #43 should still answer `{path}` in its own bullet"))
}

/// Every upstream c2n handler is accounted for: named in the ask, and — unless the engine already
/// answers it — placed on one side of the answered/declined line.
#[test]
fn the_census_names_every_handler_go_registers() {
    let named = c2n_paths(ask_section());
    let answered = c2n_paths(subsection(ANSWERED_HEADING));
    let declined = c2n_paths(subsection(DECLINED_HEADING));

    for (path, go_file) in GO_C2N_HANDLERS {
        assert!(
            named.iter().any(|p| p == path),
            "Go registers c2n `{path}` in `{go_file}`, but ask #43 never names it, so its census \
             of upstream's handlers is incomplete"
        );
        if ENGINE_ANSWERED.contains(path) {
            continue;
        }
        assert!(
            answered.iter().any(|p| p == path) || declined.iter().any(|p| p == path),
            "Go registers c2n `{path}` in `{go_file}`, but ask #43 neither answers nor declines it"
        );
    }
}

/// Go's `handleC2NUpdatePost` checks `Enabled` before `Supported`, so a node with the pref unset or
/// `false` answers `not enabled`; `not supported` is only the answer once the pref is `true`.
#[test]
fn post_update_refuses_not_enabled_before_not_supported() {
    let bullet = answered_bullet("/update");
    let not_enabled = bullet.find("\"not enabled\"").unwrap_or_else(|| {
        panic!(
            "ask #43's `/update` handler omits Go's `\"not enabled\"` refusal, which is what \
             `POST /update` answers while `Prefs::auto_update_apply` is unset or false"
        )
    });
    let not_supported = bullet
        .find("\"not supported\"")
        .expect("ask #43's `/update` handler should still carry Go's `\"not supported\"` refusal");
    assert!(
        not_enabled < not_supported,
        "ask #43 should give `\"not enabled\"` before `\"not supported\"`, in \
         `handleC2NUpdatePost`'s order"
    );
}

/// Go decides `PostureDisabled` from the `PostureChecking` policy's `ShouldEnable` over the pref,
/// not from the pref alone, and the daemon's syspolicy must carry that key for the handler to read.
#[test]
fn posture_disabled_honours_the_posture_checking_policy() {
    let bullet = answered_bullet("/posture/identity");
    assert!(
        bullet.contains("`PostureChecking` policy") && bullet.contains("should_enable"),
        "ask #43's `/posture/identity` handler must let the `PostureChecking` policy override \
         `Prefs::posture_checking` through `PreferenceOption::should_enable`, as Go's \
         `choice.ShouldEnable(prefs.PostureChecking())` does"
    );
    assert!(
        bullet.contains("failed policy read"),
        "ask #43's `/posture/identity` handler must say a failed `PostureChecking` read leaves the \
         pref to decide, as Go's handler logs the error and falls through to `ShouldEnable`"
    );
    assert!(
        SYSPOLICY.contains("def(\"PostureChecking\", ValueType::PreferenceOption)"),
        "src/ipn/syspolicy.rs should still register `PostureChecking` as a PreferenceOption, the \
         policy ask #43's posture handler reads"
    );
}
