//! Drift tripwire for how the docs describe the Go `up`/`set` pref flags (ENGINE_ASKS §21).
//!
//! Eight of those flags shipped once the engine grew a `Config` field for each; only the four Linux
//! subnet-router knobs are still engine-gated. Two docs describe that remaining work — `docs/
//! ENGINE_ASKS.md` §21 (the ask itself) and `docs/PARITY_GAP_ANALYSIS.md` (the orienting map) — and
//! a stale sentence in either one reads as "the daemon still can't do this", which is exactly the
//! kind of claim this repo refuses to leave lying around (the honest-omission rule cuts both ways:
//! don't ship an inert flag, and don't keep calling a shipped flag missing).
//!
//! These tests assert the *shape* of those claims, not their prose: the section marks each shipped
//! flag shipped, keeps its superseded rationale explicitly labelled as the as-filed record so a
//! reader can't mistake its present tense for the current pin, and names only the four residual
//! knobs as open. They fail if a flag ships (or regresses) without the docs moving with it.

/// The eight flags that shipped: the engine carries a `Config` field for each and `tnet` wires it.
const SHIPPED_FLAGS: [&str; 8] = [
    "--operator",
    "--exit-node-allow-lan-access",
    "--nickname",
    "--report-posture",
    "--auto-update",
    "--update-check",
    "--advertise-connector",
    "--webclient",
];

/// The residue of ask §21: the Linux subnet-router knobs, which need the engine's router/netfilter
/// layer and ride the Linux OS-router work.
const STILL_GATED_FLAGS: [&str; 4] = [
    "--snat-subnet-routes",
    "--stateful-filtering",
    "--netfilter-mode",
    "--unattended",
];

const ENGINE_ASKS: &str = include_str!("../docs/ENGINE_ASKS.md");
const PARITY: &str = include_str!("../docs/PARITY_GAP_ANALYSIS.md");

/// The body of ENGINE_ASKS §21, from its heading to the next top-level ask heading.
fn ask_21() -> &'static str {
    let start = ENGINE_ASKS
        .find("\n## 21.")
        .expect("ENGINE_ASKS.md has no §21 heading");
    let rest = &ENGINE_ASKS[start + 1..];
    let end = rest[1..]
        .find("\n## ")
        .map_or(rest.len(), |offset| offset + 1);
    &rest[..end]
}

/// The banner is everything above the as-filed rationale: what is true at the current pin.
fn ask_21_banner_and_record() -> (&'static str, &'static str) {
    let section = ask_21();
    let split = section
        .find("**Why")
        .expect("ENGINE_ASKS §21 has no `**Why` rationale");
    (&section[..split], &section[split..])
}

#[test]
fn engine_ask_21_marks_every_shipped_pref_flag_as_shipped() {
    let (banner, _) = ask_21_banner_and_record();
    assert!(
        banner.contains("SHIPPED"),
        "ENGINE_ASKS §21 no longer opens with a shipped banner"
    );
    for flag in SHIPPED_FLAGS {
        assert!(
            banner.contains(flag),
            "ENGINE_ASKS §21's shipped banner does not mention `{flag}`, which the daemon wires \
             today — a reader of the ask below would think it is still engine-gated"
        );
    }
}

#[test]
fn engine_ask_21_labels_its_superseded_rationale_as_the_as_filed_record() {
    let (_, record) = ask_21_banner_and_record();
    assert!(
        record.contains("AS FILED"),
        "ENGINE_ASKS §21's rationale is not labelled as the as-filed record, so its account of \
         what the engine `Config` lacks reads as a claim about the current pin"
    );
    for stale in [
        "are **not daemon-fixable today**",
        "has **no field** to carry them",
    ] {
        assert!(
            !record.contains(stale),
            "ENGINE_ASKS §21 still asserts, in the present tense, that the shipped flags cannot be \
             wired: {stale:?}"
        );
    }
}

#[test]
fn engine_ask_21_names_only_the_four_linux_router_knobs_as_open() {
    let (banner, _) = ask_21_banner_and_record();
    let still_open = banner
        .split("**Still open:**")
        .nth(1)
        .expect("ENGINE_ASKS §21's banner has no `**Still open:**` clause");
    // Just that paragraph: the follow-ups below it legitimately name shipped prefs.
    let still_open = still_open.split("\n>\n").next().unwrap_or(still_open);
    for flag in STILL_GATED_FLAGS {
        assert!(
            still_open.contains(flag),
            "ENGINE_ASKS §21 no longer lists `{flag}` as still engine-gated"
        );
    }
    for flag in SHIPPED_FLAGS {
        assert!(
            !still_open.contains(flag),
            "ENGINE_ASKS §21 lists the shipped flag `{flag}` as still open"
        );
    }
}

#[test]
fn parity_map_no_longer_counts_the_shipped_pref_flags_as_missing() {
    for (index, line) in PARITY.lines().enumerate() {
        let lowered = line.to_ascii_lowercase();
        if !lowered.contains("pref flag") && !lowered.contains("pref-flag") {
            continue;
        }
        for stale in ["~12", "12 missing", "twelve"] {
            assert!(
                !lowered.contains(stale),
                "docs/PARITY_GAP_ANALYSIS.md:{} still counts the pre-#269 dozen missing pref \
                 flags; eight shipped, four remain: {line}",
                index + 1
            );
        }
    }
}

#[test]
fn parity_engine_gated_row_for_ask_21_lists_only_the_still_gated_flags() {
    let row = PARITY
        .lines()
        .find(|line| line.starts_with('|') && line.contains("**#21**"))
        .expect("docs/PARITY_GAP_ANALYSIS.md §4.1 has no row for engine ask #21");
    // `| Gap | Bead | Engine ask | Note |` — the leading `|` makes the gap the second field.
    let gap = row.split('|').nth(1).expect("malformed table row");
    for flag in STILL_GATED_FLAGS {
        assert!(
            gap.contains(flag),
            "the #21 row's gap cell no longer names `{flag}`: {gap}"
        );
    }
    for flag in SHIPPED_FLAGS {
        assert!(
            !gap.contains(flag),
            "the #21 row still lists the shipped flag `{flag}` as an engine-gated gap: {gap}"
        );
    }
}
