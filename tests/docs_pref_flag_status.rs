//! Doc/code lockstep for the Go `up`/`set` pref flags of engine ask #21.
//!
//! Eight of the twelve pref flags ask #21 requested are now wired: the engine grew the `Config`
//! field, the daemon carries the pref, and `tnet up`/`set` accept the flag. Documentation that
//! still describes them as unavailable is not a cosmetic wart — `docs/ENGINE_ASKS.md` is the
//! engine's work queue and `docs/PARITY_GAP_ANALYSIS.md` is the "what is left" map, so a stale
//! entry there asks the engine lane to build a field it already shipped and tells a reader a
//! feature is missing while `tnet --help` offers it.
//!
//! Prose drifts silently, so this pins it to the code. Each shipped flag's [`Prefs`] field is
//! *named* below, which makes the field's existence a compile-time fact; the assertions then
//! require the ask entry for that flag to be marked shipped. Delete the field and this stops
//! compiling; delete the flag's wiring without touching the doc and the pair goes out of step
//! here rather than in a reader's head. The four Linux subnet-router knobs have no `Prefs` field
//! and must still read as open — the residue ask #21 genuinely wants.
//!
//! The docs are pulled in with [`include_str!`], so the assertions run against the committed
//! files with no I/O and no path assumptions.

use tailscaled_rs::prefs::Prefs;

const ENGINE_ASKS: &str = include_str!("../docs/ENGINE_ASKS.md");
const PARITY_GAP: &str = include_str!("../docs/PARITY_GAP_ANALYSIS.md");

/// The bullet list of ask #21 — the entries between the "**Ask —" lead-in and the
/// workload-identity paragraph that closes the ask. Each entry is one requested `Config` field.
fn ask_21_entries() -> Vec<String> {
    let start = ENGINE_ASKS
        .find("**Ask — add the engine `Config` fields")
        .expect("ENGINE_ASKS.md must still carry the ask-#21 field list");
    let rest = &ENGINE_ASKS[start..];
    let end = rest
        .find("**Workload-identity flags**")
        .expect("the workload-identity paragraph must still close ask #21");
    // Split on the bullet marker at column 0; continuation lines are indented, so each chunk is
    // one whole entry.
    rest[..end]
        .split("\n- ")
        .skip(1)
        .map(|e| e.trim_end().to_string())
        .collect()
}

/// The single ask-#21 entry that mentions `flag`, or a panic naming the flag that lost its entry.
fn entry_for(flag: &str) -> String {
    let entries = ask_21_entries();
    let mut hits = entries.into_iter().filter(|e| e.contains(flag));
    let hit = hits
        .next()
        .unwrap_or_else(|| panic!("ask #21 has no entry mentioning `{flag}`"));
    assert!(
        hits.next().is_none(),
        "`{flag}` appears in more than one ask-#21 entry; the status markers become ambiguous"
    );
    hit
}

/// Every flag the daemon actually wired must read as SHIPPED in ask #21, and must name the engine
/// `Config` field it landed as — so the engine lane is never asked to build it twice.
#[test]
fn ask_21_marks_every_wired_pref_flag_shipped() {
    let p = Prefs::default();

    // (Go flag, the `Prefs` field carrying it, the engine `Config` field it maps to). Naming the
    // field makes its existence a COMPILE-TIME requirement of this test: if a pref is ever
    // removed, this file fails to build long before the doc assertion below could go stale.
    let wired: Vec<(&str, &str)> = vec![
        ("--operator", {
            let _: &Option<String> = &p.operator_user;
            "operator_user"
        }),
        ("--exit-node-allow-lan-access", {
            let _: &bool = &p.exit_node_allow_lan_access;
            "exit_node_allow_lan_access"
        }),
        ("--nickname", {
            let _: &Option<String> = &p.node_nickname;
            "node_nickname"
        }),
        ("--report-posture", {
            let _: &bool = &p.posture_checking;
            "posture_checking"
        }),
        ("--auto-update", {
            let _: &Option<bool> = &p.auto_update_apply;
            "auto_update_apply"
        }),
        ("--update-check", {
            let _: &bool = &p.auto_update_check;
            "auto_update_check"
        }),
        ("--advertise-connector", {
            let _: &bool = &p.advertise_app_connector;
            "advertise_app_connector"
        }),
        ("--webclient", {
            let _: &bool = &p.run_web_client;
            "run_web_client"
        }),
    ];

    for (flag, config_field) in wired {
        let entry = entry_for(flag);
        assert!(
            entry.starts_with("✅ SHIPPED"),
            "`{flag}` is wired (Prefs carries it) but ask #21 still lists it as an open request:\n{entry}"
        );
        assert!(
            entry.contains(config_field),
            "the ask-#21 entry for `{flag}` must name the engine field it shipped as \
             (`{config_field}`), so the mapping survives the next reader:\n{entry}"
        );
    }
}

/// The four Linux subnet-router knobs are the whole of what ask #21 still wants: no engine field,
/// no pref, no flag. They must not be swept up in the "shipped" relabelling.
#[test]
fn ask_21_still_asks_for_the_linux_router_knobs() {
    for flag in [
        "--snat-subnet-routes",
        "--stateful-filtering",
        "--netfilter-mode",
        "--unattended",
    ] {
        let entry = entry_for(flag);
        assert!(
            entry.starts_with("⬜ STILL OPEN"),
            "`{flag}` has no engine field and no pref, so ask #21 must still list it as open:\n{entry}"
        );
    }
}

/// The rationale paragraph explains why the flags were refused. It was written against engine rev
/// `6035651`, where the fields genuinely did not exist; at the current pin they do. It may stay as
/// the record of what was asked, but it must not read as a statement about today.
#[test]
fn ask_21_rationale_is_labelled_as_the_original_filing() {
    let start = ENGINE_ASKS
        .find("## 21.")
        .expect("ask #21 must still exist in ENGINE_ASKS.md");
    let section = &ENGINE_ASKS[start..];
    let section = &section[..section.find("\n## ").unwrap_or(section.len())];

    assert!(
        !section.contains("not daemon-fixable today"),
        "ask #21's rationale still claims the flags are unfixable TODAY, which the shipped eight \
         contradict; it must be scoped to the rev it was filed against"
    );
    assert!(
        section.contains("as filed, at engine rev `6035651`"),
        "ask #21's rationale must say which rev it describes, or a reader takes it for current"
    );
}

/// The parity map's one-paragraph summary is what a reader skims; it must not still promise ~12
/// missing pref flags when four remain.
#[test]
fn parity_gap_summary_counts_only_the_residual_pref_flags() {
    for stale in ["~12 missing `up`/`set` pref flags", "#21 ~12 pref-flag"] {
        assert!(
            !PARITY_GAP.contains(stale),
            "PARITY_GAP_ANALYSIS.md still advertises \"{stale}\"; eight of those twelve shipped"
        );
    }
    assert!(
        PARITY_GAP.contains("four residual Linux subnet-router `up`/`set` pref flags"),
        "the executive summary must name the four pref flags that actually remain"
    );
}

/// The §1 pie chart buckets **open beads**, not flags — which is why shipping eight flags does not
/// move it: `tsd-1m9` stays open for the residual four. Pinning "the slices sum to the open-bead
/// total" keeps that reading honest, and stops the chart being "corrected" into a flag count.
#[test]
fn parity_gap_pie_slices_sum_to_the_open_bead_count() {
    let pie_start = PARITY_GAP
        .find("pie showData")
        .expect("the §1 gating-factor pie must still exist");
    let pie = &PARITY_GAP[pie_start..];
    let pie = &pie[..pie.find("```").expect("the pie block must be fenced")];
    assert!(
        pie.contains("(open beads)"),
        "the pie title must keep saying it counts open beads, not flags"
    );

    let sum: u32 = pie
        .lines()
        .filter_map(|l| l.rsplit_once("\" : "))
        .map(|(_, n)| {
            n.trim()
                .parse::<u32>()
                .expect("a pie slice must be a count")
        })
        .sum();

    let open_beads: u32 = PARITY_GAP
        .lines()
        .find(|l| l.contains(" open beads (`bd list --status open`)"))
        .expect("§7 must still state the open-bead total")
        .split_whitespace()
        .next()
        .expect("the open-bead total leads its line")
        .parse()
        .expect("the open-bead total must be a number");

    assert_eq!(
        sum, open_beads,
        "the gating-factor pie must account for every open bead: {sum} charted vs {open_beads} open"
    );
}
