//! The accidental-setting-revert guard — the Rust analogue of Go's
//! `checkForAccidentalSettingReverts` (`cmd/tailscale/cli/up.go`).
//!
//! ## Why this exists (the `up` vs `set` parity story)
//!
//! Go's `tailscale up` has REPLACE semantics: a fresh `up` builds a full `Prefs` from the command
//! line, defaulting *every* flag not passed — so any non-default setting you forget to re-mention
//! would silently revert. To stop that footgun, Go runs `checkForAccidentalSettingReverts` first: if
//! the command would revert a non-default pref it didn't mention, it is **rejected** (not silently
//! applied) with a message telling the operator to either re-mention the setting or pass `--reset`.
//! `tailscale set`, by contrast, is a pure PATCH and has no such guard.
//!
//! This daemon's `begin_up` merge is itself a PATCH (it only overwrites prefs the request named), so
//! it would never *actually* revert an unmentioned pref. But the **goal is parity with Go's `up`
//! contract**: a user who runs `tnet up --ssh` on a node that already advertises routes should get
//! Go's behavior — "mention your routes too, or pass --reset" — not a silent `set`-like patch. This
//! guard supplies exactly that contract. When it passes (every non-default pref was mentioned), the
//! PATCH merge and a true REPLACE produce an identical end state, so layering the guard over the safe
//! PATCH merge is observably equivalent to Go's REPLACE — without the data-loss risk a true wholesale
//! replace would carry if the guard ever had a hole. `up --reset` is the one path that performs the
//! genuine wholesale replace (see [`crate::prefs::Prefs::reset_up_managed_to_default`]); it bypasses
//! this guard by construction (the caller skips it when `reset` is set).
//!
//! The guard is a **pure, read-only** function over `(prefs, opts, ever_configured)` so it is
//! unit-testable without a live `Backend` or engine, and it never mutates state — a tripped guard is
//! a pre-flight rejection that leaves the node exactly as it was.

use crate::localapi::RevertedPref;
use crate::prefs::Prefs;

use super::UpOptions;

/// Check whether an `up` described by `opts`, applied to the current `prefs`, would silently revert
/// any non-default pref the command did not mention — returning the list of such reverts (empty =
/// the `up` is safe to proceed). The Rust analogue of Go's `checkForAccidentalSettingReverts`.
///
/// `has_logged_in` is the node's "has actually registered / reached Running before" signal (the
/// daemon's `Prefs::has_logged_in`, the analogue of Go's `Persist.UserProfile.LoginName != ""`). It is
/// deliberately NOT the daemon's `ever_configured` (prefs-file existence): Go's check is
/// `curPrefs.ControlURL == ""` (never logged in), and Go's `set` never writes ControlURL, so a
/// `set`-then-`up` on a fresh node stays unguarded there — keying on prefs-file existence (which a
/// bare `set` creates) would wrongly arm the guard on that sequence. See bead tsd-i7c.
///
/// ## Two exemptions (both mirror Go)
///
/// 1. **Fresh node** (`!has_logged_in`): a node that has never logged in has no settings worth
///    guarding, so the first real `up` is never guarded (Go's `curPrefs.ControlURL == ""`
///    early-return). A `tnet set` before that first `up` does NOT arm the guard (it does not log the
///    node in), matching Go's `set`-never-writes-ControlURL behavior.
/// 2. **Bare `up`** (`!opts.mentions_any_pref()`): an `up` that names no prefs is "just connect,
///    change nothing" (Go's `simpleUp`). Our PATCH merge changes nothing in that case, so there is
///    nothing to revert — guarding it would wrongly flag *every* non-default pref. Skip it.
///
/// Otherwise: for each up-managed pref, if the command did **not** mention it AND its current value
/// differs from the default, it is an accidental revert. The set of prefs checked here is exactly the
/// set [`Prefs::reset_up_managed_to_default`] resets — they must stay in lockstep.
///
/// `caller` note: when `opts.reset` is set the caller must NOT call this (a `--reset` up explicitly
/// opts into reverting unmentioned prefs to default); this function does not re-check `reset`.
pub(super) fn check_accidental_reverts(
    prefs: &Prefs,
    opts: &UpOptions,
    has_logged_in: bool,
) -> Vec<RevertedPref> {
    // Exemption 1: never-logged-in node — no settings worth guarding (Go's ControlURL=="" early-return).
    if !has_logged_in {
        return Vec::new();
    }
    // Exemption 2: bare `up` (Go's simpleUp) — names no prefs, so changes nothing.
    if !opts.mentions_any_pref() {
        return Vec::new();
    }

    let d = Prefs::default();
    let mut reverts = Vec::new();

    // Each arm: "the command did NOT mention this pref (the override is the unchanged sentinel) AND
    // the current value is non-default" → the operator would lose it. The rendered `value` is the
    // current value as the string they must re-supply to keep it. Field order here is the
    // deterministic order the CLI receives (it sorts for display).
    if opts.hostname.is_none()
        && prefs.hostname != d.hostname
        && let Some(v) = &prefs.hostname
    {
        reverts.push(RevertedPref {
            key: "hostname".into(),
            value: v.clone(),
        });
    }
    if opts.control_url.is_none()
        && prefs.control_url != d.control_url
        && let Some(v) = &prefs.control_url
    {
        reverts.push(RevertedPref {
            key: "control_url".into(),
            value: v.clone(),
        });
    }
    if opts.tun.is_none() && prefs.tun_enabled != d.tun_enabled {
        reverts.push(RevertedPref {
            key: "tun".into(),
            value: prefs.tun_enabled.to_string(),
        });
    }
    if opts.tun_name.is_none()
        && prefs.tun_name != d.tun_name
        && let Some(v) = &prefs.tun_name
    {
        reverts.push(RevertedPref {
            key: "tun_name".into(),
            value: v.clone(),
        });
    }
    if opts.tun_mtu.is_none()
        && prefs.tun_mtu != d.tun_mtu
        && let Some(v) = prefs.tun_mtu
    {
        reverts.push(RevertedPref {
            key: "tun_mtu".into(),
            value: v.to_string(),
        });
    }
    if opts.exit_node.is_none()
        && prefs.exit_node != d.exit_node
        && let Some(v) = &prefs.exit_node
    {
        reverts.push(RevertedPref {
            key: "exit_node".into(),
            value: v.clone(),
        });
    }
    if opts.advertise_exit_node.is_none() && prefs.advertise_exit_node != d.advertise_exit_node {
        reverts.push(RevertedPref {
            key: "advertise_exit_node".into(),
            value: prefs.advertise_exit_node.to_string(),
        });
    }
    if opts.advertise_routes.is_none() && prefs.advertise_routes != d.advertise_routes {
        reverts.push(RevertedPref {
            key: "advertise_routes".into(),
            value: prefs.advertise_routes.join(","),
        });
    }
    if opts.advertise_tags.is_none() && prefs.advertise_tags != d.advertise_tags {
        reverts.push(RevertedPref {
            key: "advertise_tags".into(),
            value: prefs.advertise_tags.join(","),
        });
    }
    if opts.accept_routes.is_none() && prefs.accept_routes != d.accept_routes {
        reverts.push(RevertedPref {
            key: "accept_routes".into(),
            value: prefs.accept_routes.to_string(),
        });
    }
    if opts.accept_dns.is_none() && prefs.accept_dns != d.accept_dns {
        reverts.push(RevertedPref {
            key: "accept_dns".into(),
            value: prefs.accept_dns.to_string(),
        });
    }
    if opts.shields_up.is_none() && prefs.shields_up != d.shields_up {
        reverts.push(RevertedPref {
            key: "shields_up".into(),
            value: prefs.shields_up.to_string(),
        });
    }
    if opts.ssh.is_none() && prefs.ssh_enabled != d.ssh_enabled {
        reverts.push(RevertedPref {
            key: "ssh".into(),
            value: prefs.ssh_enabled.to_string(),
        });
    }

    reverts
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Drift tripwire (the H1 safeguard).** The accidental-revert guard, the `--reset` helper
    /// ([`Prefs::reset_up_managed_to_default`]), and the [`Prefs`] struct itself must stay in
    /// lockstep: every up-managed pref MUST be both reset by `--reset` and checked by the guard, or a
    /// future `up` silently reverts it (the exact footgun the guard exists to prevent) and `--reset`
    /// leaves it set. That lockstep was comment-only; this test makes a drift a COMPILE error.
    ///
    /// It exhaustively destructures `Prefs` with **no `..`**, so adding or removing any field stops
    /// compilation here and forces the author to classify the new field below: either UP-MANAGED
    /// (then it must be added to BOTH `reset_up_managed_to_default` AND `check_accidental_reverts`,
    /// and to the runtime assertion in this test), or EXEMPT (lifecycle/registration — listed with a
    /// reason). The runtime half then proves the guard actually fires on every field classified
    /// up-managed, so you cannot satisfy the compiler by classifying a field up-managed and forgetting
    /// the guard arm.
    #[test]
    fn prefs_guard_reset_lockstep_no_silent_drift() {
        // Exhaustive destructure — NO `..`. Adding/removing a Prefs field breaks this and forces a
        // conscious classification (see the doc above).
        let Prefs {
            // --- EXEMPT (not up-managed; never guarded, never reset by --reset) ---
            want_running: _, // lifecycle — `up`/`down` own it directly, not a revertable setting.
            logged_out: _,   // lifecycle — `up`/`logout` own it directly.
            // EXEMPT despite being `up`-settable (`up --ephemeral`): it is a REGISTRATION-TIME
            // intent the engine only honors on a fresh register (a no-op on an already-registered
            // node), and our `up` is a PATCH merge (an unmentioned `ephemeral` is left untouched, never
            // defaulted) — so it can never be silently reverted, and a guard arm would only emit a
            // SPURIOUS "about to revert ephemeral" warning. Mentioning `--ephemeral` still makes `up`
            // non-bare (see `UpOptions::mentions_any_pref`), so the guard correctly checks the OTHER
            // prefs — exactly as Go's REPLACE-semantics `up` would. Not in `--reset` either (resetting
            // a registration-time property on a live node is meaningless).
            ephemeral: _,
            taildrop_dir: _, // configured out-of-band (engine Config), not an `up` flag.
            has_logged_in: _, // registration signal — the guard's own fresh-node INPUT, never a guarded setting (tsd-i7c).
            // --- UP-MANAGED (MUST be in reset + guard; asserted at runtime below) ---
            control_url: _,
            hostname: _,
            accept_routes: _,
            accept_dns: _,
            shields_up: _,
            exit_node: _,
            advertise_exit_node: _,
            advertise_routes: _,
            advertise_tags: _,
            ssh_enabled: _,
            tun_enabled: _,
            tun_name: _,
            tun_mtu: _,
        } = Prefs::default();

        // Runtime half: for EACH field classified up-managed above, build a node where ONLY that
        // field is non-default and assert the guard reports it as a revert when an UNRELATED pref is
        // mentioned (so the bare-up exemption doesn't apply). If a field is classified up-managed but
        // its guard arm is missing, this fails. The "unrelated mention" is `want_running`-only via a
        // sentinel `UpOptions` that mentions a *different* up-managed pref than the one under test.
        //
        // We drive each via a tiny table of (set-non-default closure, expected revert key). Each
        // closure mutates exactly one up-managed field away from its default. (Aliased to dodge
        // clippy::type_complexity on the `Vec<(&str, fn(&mut Prefs))>` literal.)
        type Case = (&'static str, fn(&mut Prefs));
        let cases: Vec<Case> = vec![
            ("control_url", |p| {
                p.control_url = Some("https://hs.example".into())
            }),
            ("hostname", |p| p.hostname = Some("h".into())),
            ("accept_routes", |p| p.accept_routes = true),
            // accept_dns DEFAULTS to true, so its non-default value is false.
            ("accept_dns", |p| p.accept_dns = false),
            ("shields_up", |p| p.shields_up = true),
            ("exit_node", |p| p.exit_node = Some("100.64.0.9".into())),
            ("advertise_exit_node", |p| p.advertise_exit_node = true),
            ("advertise_routes", |p| {
                p.advertise_routes = vec!["10.0.0.0/8".into()]
            }),
            ("advertise_tags", |p| {
                p.advertise_tags = vec!["tag:server".into()]
            }),
            ("ssh", |p| p.ssh_enabled = true),
            ("tun", |p| p.tun_enabled = true),
            ("tun_name", |p| p.tun_name = Some("tailscale0".into())),
            ("tun_mtu", |p| p.tun_mtu = Some(1280)),
        ];

        for (expected_key, set_non_default) in &cases {
            let mut prefs = Prefs {
                want_running: true,
                ..Prefs::default()
            };
            set_non_default(&mut prefs);

            // (a) The guard must report this field as a revert when an UNRELATED pref is mentioned.
            // Mention `hostname` to defeat the bare-up exemption — unless the field under test IS
            // hostname, in which case mention `ssh` instead (any other up-managed pref works).
            let opts = if *expected_key == "hostname" {
                UpOptions {
                    ssh: Some(true),
                    ..UpOptions::default()
                }
            } else {
                UpOptions {
                    hostname: Some("other".into()),
                    ..UpOptions::default()
                }
            };
            let reverts = check_accidental_reverts(&prefs, &opts, true);
            assert!(
                reverts.iter().any(|r| r.key == *expected_key),
                "guard did not report up-managed pref '{expected_key}' as a revert — its arm is \
                 missing from check_accidental_reverts (lockstep drift)"
            );

            // (b) `--reset` must restore this field to its default (proves reset covers it too).
            let mut reset_prefs = prefs.clone();
            reset_prefs.reset_up_managed_to_default();
            let d = Prefs::default();
            match *expected_key {
                "control_url" => assert_eq!(reset_prefs.control_url, d.control_url),
                "hostname" => assert_eq!(reset_prefs.hostname, d.hostname),
                "accept_routes" => assert_eq!(reset_prefs.accept_routes, d.accept_routes),
                "accept_dns" => assert_eq!(reset_prefs.accept_dns, d.accept_dns),
                "shields_up" => assert_eq!(reset_prefs.shields_up, d.shields_up),
                "exit_node" => assert_eq!(reset_prefs.exit_node, d.exit_node),
                "advertise_exit_node" => {
                    assert_eq!(reset_prefs.advertise_exit_node, d.advertise_exit_node)
                }
                "advertise_routes" => {
                    assert_eq!(reset_prefs.advertise_routes, d.advertise_routes)
                }
                "advertise_tags" => {
                    assert_eq!(reset_prefs.advertise_tags, d.advertise_tags)
                }
                "ssh" => assert_eq!(reset_prefs.ssh_enabled, d.ssh_enabled),
                "tun" => assert_eq!(reset_prefs.tun_enabled, d.tun_enabled),
                "tun_name" => assert_eq!(reset_prefs.tun_name, d.tun_name),
                "tun_mtu" => assert_eq!(reset_prefs.tun_mtu, d.tun_mtu),
                other => panic!("unclassified up-managed key in test table: {other}"),
            }
        }
    }

    #[test]
    fn up_options_fields_classified_against_guard_no_silent_drift() {
        // The Prefs-side lockstep above closes the "new persisted field skips the guard" hole. This
        // closes the OTHER direction the `ephemeral` case slipped through: a new `UpOptions` flag must
        // also force a conscious guard decision. Exhaustively destructure `UpOptions` — NO `..` — so
        // adding a flag breaks this test until it is classified GUARD-RELEVANT (must be both a
        // `check_accidental_reverts` arm AND in `mentions_any_pref`) or DIRECTIVE/REGISTRATION (a
        // bare-up-preserving action that is neither). The classification is documented per-field; the
        // assertions below verify the two non-obvious cases (`ephemeral`, `force_reauth`) actually
        // behave as classified, so the comment can't drift from reality.
        let crate::ipn::UpOptions {
            // --- GUARD-RELEVANT: a pref flag → has a guard arm AND is in mentions_any_pref ---
            hostname: _,
            control_url: _,
            tun: _,
            tun_name: _,
            tun_mtu: _,
            exit_node: _,
            advertise_exit_node: _,
            advertise_routes: _,
            advertise_tags: _,
            accept_routes: _,
            accept_dns: _,
            shields_up: _,
            ssh: _,
            // --- DIRECTIVE: not a pref; bypasses or is exempt from the guard, NOT in mentions_any_pref ---
            reset: _,        // its own guard-BYPASS path (caller skips the guard when set).
            force_reauth: _, // re-key lifecycle action; excluded from mentions_any_pref + the guard.
            // --- REGISTRATION-TIME: up-settable but never reverts (PATCH merge + honored only on a
            //     fresh register), so it IS in mentions_any_pref (mentioning it makes up non-bare, Go-
            //     faithfully checking the OTHER prefs) but is NOT a guard arm and NOT in --reset. ---
            ephemeral: _,
        } = crate::ipn::UpOptions::default();

        // Verify the two non-obvious classifications actually hold (so the table can't lie):
        // `force_reauth` is a directive → must NOT make a bare up look non-bare.
        assert!(
            !crate::ipn::UpOptions {
                force_reauth: true,
                ..Default::default()
            }
            .mentions_any_pref(),
            "force_reauth must be excluded from mentions_any_pref (it's a directive, not a pref)"
        );
        // `reset` likewise.
        assert!(
            !crate::ipn::UpOptions {
                reset: true,
                ..Default::default()
            }
            .mentions_any_pref(),
            "reset must be excluded from mentions_any_pref"
        );
        // `ephemeral` IS in mentions_any_pref (mentioning it makes up non-bare → guard checks others),
        // but it is NOT a guard arm: setting only `ephemeral` non-default reports NO revert for it.
        assert!(
            crate::ipn::UpOptions {
                ephemeral: Some(true),
                ..Default::default()
            }
            .mentions_any_pref(),
            "ephemeral must be in mentions_any_pref (Go checks the other prefs when it is named)"
        );
        let mut eph_prefs = Prefs {
            want_running: true,
            ephemeral: true, // the only non-default pref
            ..Prefs::default()
        };
        // Mention an unrelated pref (hostname) to defeat the bare-up exemption; ephemeral must NOT
        // appear as a revert (it has no guard arm by design — it never reverts under PATCH merge).
        let reverts = check_accidental_reverts(
            &eph_prefs,
            &crate::ipn::UpOptions {
                hostname: Some("h".into()),
                ..Default::default()
            },
            true,
        );
        assert!(
            !reverts.iter().any(|r| r.key == "ephemeral"),
            "ephemeral must never be reported as a revert (registration-time, PATCH-merge-safe)"
        );
        // And --reset must leave ephemeral untouched (not in the reset set).
        eph_prefs.reset_up_managed_to_default();
        assert!(
            eph_prefs.ephemeral,
            "--reset must NOT clear ephemeral (it's not an up-managed policy pref)"
        );
    }

    #[test]
    fn advertise_tags_validation() {
        use super::super::validate_advertise_tags;
        // Valid: tag:<name> — letter-led, [A-Za-z0-9-] only.
        assert!(validate_advertise_tags(&["tag:server".into(), "tag:ci".into()]).is_ok());
        assert!(validate_advertise_tags(&["tag:web-1".into()]).is_ok());
        assert!(validate_advertise_tags(&[]).is_ok());
        // Invalid: bare name, empty tag name, wrong prefix.
        assert!(validate_advertise_tags(&["server".into()]).is_err());
        assert!(validate_advertise_tags(&["tag:".into()]).is_err());
        assert!(validate_advertise_tags(&["notatag:x".into()]).is_err());
        // Invalid per Go CheckTag: leading digit, underscore, space, punctuation.
        assert!(validate_advertise_tags(&["tag:9server".into()]).is_err());
        assert!(validate_advertise_tags(&["tag:my_tag".into()]).is_err());
        assert!(validate_advertise_tags(&["tag:has space".into()]).is_err());
        assert!(validate_advertise_tags(&["tag:exit!".into()]).is_err());
    }

    /// A node that already advertises routes; the canonical "non-default prefs present" fixture.
    fn configured_prefs() -> Prefs {
        Prefs {
            want_running: true,
            advertise_routes: vec!["10.0.0.0/8".into()],
            accept_routes: true,
            hostname: Some("node-a".into()),
            ..Prefs::default()
        }
    }

    #[test]
    fn fresh_node_is_never_guarded() {
        // has_logged_in = false → the first real `up` is exempt even with mentioned flags +
        // non-default prefs (Go's `curPrefs.ControlURL == ""` early-return). This is the key tsd-i7c
        // case: a node that has a prefs.json (e.g. from a prior `tnet set`) but has NEVER logged in is
        // still treated as fresh, so a `set`-then-`up` sequence is not spuriously rejected.
        let prefs = configured_prefs();
        let opts = UpOptions {
            ssh: Some(true),
            ..UpOptions::default()
        };
        assert!(check_accidental_reverts(&prefs, &opts, false).is_empty());
    }

    #[test]
    fn bare_up_is_exempt_even_with_nondefault_prefs() {
        // No pref mentioned (Go's simpleUp) → never trips, even though routes/accept/hostname are set.
        let prefs = configured_prefs();
        let opts = UpOptions::default();
        assert!(check_accidental_reverts(&prefs, &opts, true).is_empty());
    }

    #[test]
    fn mentioning_only_ssh_trips_on_unmentioned_nondefaults() {
        // `up --ssh` on a configured node with routes+accept+hostname set → all three are reverts.
        let prefs = configured_prefs();
        let opts = UpOptions {
            ssh: Some(true),
            ..UpOptions::default()
        };
        let reverts = check_accidental_reverts(&prefs, &opts, true);
        let keys: Vec<&str> = reverts.iter().map(|r| r.key.as_str()).collect();
        assert!(keys.contains(&"advertise_routes"), "{keys:?}");
        assert!(keys.contains(&"accept_routes"), "{keys:?}");
        assert!(keys.contains(&"hostname"), "{keys:?}");
        // ssh itself was mentioned → not a revert.
        assert!(!keys.contains(&"ssh"), "{keys:?}");
        // The advertise_routes value is rendered as the comma-joined current set.
        let ar = reverts
            .iter()
            .find(|r| r.key == "advertise_routes")
            .unwrap();
        assert_eq!(ar.value, "10.0.0.0/8");
    }

    #[test]
    fn re_mentioning_every_nondefault_passes() {
        // `up --ssh --advertise-routes=10/8 --accept-routes --hostname=node-a` → nothing unmentioned
        // is non-default → guard passes (the PATCH merge then == a true replace).
        let prefs = configured_prefs();
        let opts = UpOptions {
            ssh: Some(true),
            advertise_routes: Some(vec!["10.0.0.0/8".into()]),
            accept_routes: Some(true),
            hostname: Some("node-a".into()),
            ..UpOptions::default()
        };
        assert!(check_accidental_reverts(&prefs, &opts, true).is_empty());
    }

    #[test]
    fn no_trip_when_only_nondefault_is_the_mentioned_one() {
        // ssh is the ONLY non-default pref; `up --ssh` mentions it → nothing else to revert → passes.
        let prefs = Prefs {
            want_running: true,
            ssh_enabled: true,
            ..Prefs::default()
        };
        let opts = UpOptions {
            ssh: Some(true),
            ..UpOptions::default()
        };
        assert!(check_accidental_reverts(&prefs, &opts, true).is_empty());
    }

    #[test]
    fn clearing_a_pref_counts_as_mentioning_it() {
        // `up --clear-exit-node` (exit_node = Some(None)) on a node with an exit node set + routes:
        // exit_node is mentioned (so not a revert), but advertise_routes is still an accidental revert.
        let prefs = Prefs {
            want_running: true,
            exit_node: Some("100.64.0.9".into()),
            advertise_routes: vec!["10.0.0.0/8".into()],
            ..Prefs::default()
        };
        let opts = UpOptions {
            exit_node: Some(None),
            ..UpOptions::default()
        };
        let reverts = check_accidental_reverts(&prefs, &opts, true);
        let keys: Vec<&str> = reverts.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, vec!["advertise_routes"], "{keys:?}");
    }
}
