//! The exit-node edit gate — the refusal an administrator's `ExitNodeIP` policy is owed, and the
//! bounded exemption `ExitNode.AllowOverride` buys.
//!
//! This is the exit-node half of Go's `checkEditPrefsAccessLocked` (`ipn/ipnlocal/local.go`), which
//! runs before a prefs edit is applied: when the edit touches the exit node and the policy manages
//! it, the edit is rejected with `exit node cannot be changed: managed by policy`
//! (`fmt.Errorf("exit node cannot be changed: %w", errManagedByPolicy)`). It is the same shape as
//! the always-on disconnect gate next door ([`alwayson`](super::alwayson)), for the same reason: a
//! policy that only *re-applies* the administrator's value silently overwrites whatever the operator
//! typed, so the command reports success and does the opposite of what it says.
//!
//! Four answers, in this order:
//!
//! 1. the edit does not name an exit node → [`ExitNodeEdit::Untouched`]. Go masks on
//!    `mp.ExitNodeIDSet || mp.ExitNodeIPSet || mp.AutoExitNodeSet`, so a `set --hostname` under an
//!    exit-node policy is not an exit-node edit and is not gated.
//! 2. the policy pins nothing this build applies → [`ExitNodeEdit::NoOverride`]: an ordinary edit on
//!    an unmanaged node, which is the overwhelmingly common case (no policy file at all).
//! 3. pinned, and `ExitNode.AllowOverride` unset or false → **refused**
//!    ([`ExitNodeEditRefused::ManagedByPolicy`]).
//! 4. pinned, override allowed → the edit is accepted **unless it would leave the node with no exit
//!    node**, which Go refuses with the same message (its `changeDisablesExitNodeLocked` guard): the
//!    administrator allowed the user to move the egress, not to turn it off. An accepted edit that
//!    names a *different* node is an [`ExitNodeEdit::Override`], the exemption the backend then
//!    remembers; one that names the pinned node itself is [`ExitNodeEdit::NoOverride`], because
//!    there is nothing to exempt — Go clears the flag "when the user switches back to the state
//!    required by policy".
//!
//! ## What counts as "managed"
//!
//! Go asks `b.polc.HasAnyOf(pkey.ExitNodeID, pkey.ExitNodeIP)`, so upstream a file naming only
//! `ExitNodeID` locks the pref. This build **refuses** `ExitNodeID` rather than applying it (it
//! selects an exit node by tailnet IP or MagicDNS name, and storing a stable node id would match no
//! peer and egress directly — see [`syspolicy`](super::syspolicy)'s module docs), so locking on it
//! would refuse the operator's exit node on the strength of a key that pins nothing: the node would
//! end up with no exit node and no permitted way to choose one. The gate therefore locks on what is
//! actually applied — [`syspolicy::ExitNodePolicy::pinned`](super::syspolicy::ExitNodePolicy) — and
//! the `ExitNodeID` refusal says so where it is documented.
//!
//! ## The window an override buys
//!
//! An accepted override would be undone at the very next reconcile point, because
//! [`syspolicy::apply_to_prefs`](super::syspolicy::apply_to_prefs) re-applies the pinned value after
//! every prefs write. Go's answer is `b.overrideExitNodePolicy`, and it is ported whole:
//! [`Backend::override_exit_node_policy`](super::Backend::override_exit_node_policy) suppresses that
//! re-apply while the override stands, and is cleared on exactly the events Go clears it on — the
//! node connecting or disconnecting, a profile switch, and the administrator changing `ExitNodeID`,
//! `ExitNodeIP` or `ExitNode.AllowOverride`. An exemption that is never cleared would be worse than
//! one that never existed: the administrator's pin would survive in the policy file and nowhere else.
//!
//! Upstream: `ipn/ipnlocal/local.go` (`checkEditPrefsAccessLocked`, `changeDisablesExitNodeLocked`,
//! `onEditPrefsLocked`, `sysPolicyChanged`) @ `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8`.

use super::syspolicy::ExitNodePolicy;

/// An exit-node edit the policy refused, and the message Go prints for it.
///
/// One variant because Go has one error site: both the "no override allowed" case and the "override
/// allowed but this edit turns the exit node off" case produce `exit node cannot be changed: managed
/// by policy`. Splitting them here would invent a distinction an operator comparing `tnet` against
/// `tailscale` would not see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitNodeEditRefused {
    /// The effective policy pins the exit node and this edit is not one it permits.
    ManagedByPolicy,
}

impl ExitNodeEditRefused {
    /// Go's message for this refusal, verbatim.
    pub const fn message(self) -> &'static str {
        // `fmt.Errorf("exit node cannot be changed: %w", errManagedByPolicy)`, where
        // `errManagedByPolicy = errors.New("managed by policy")`.
        match self {
            Self::ManagedByPolicy => "exit node cannot be changed: managed by policy",
        }
    }
}

impl std::fmt::Display for ExitNodeEditRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ExitNodeEditRefused {}

/// What a permitted edit means for the standing exit-node exemption — the bookkeeping half of Go's
/// `onEditPrefsLocked`, decided by the same function that decided whether to allow the edit at all
/// so the two can never disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExitNodeEdit {
    /// The edit does not name an exit node, so it says nothing about the exemption: whatever stood
    /// before still stands. Go's mask guard.
    Untouched,
    /// The edit names an exit node and leaves nothing to exempt — either no policy pins one, or the
    /// operator picked the pinned node itself. Any standing exemption ends.
    NoOverride,
    /// The operator picked a different node than the policy's, as `ExitNode.AllowOverride` permits.
    /// The exemption is granted: the re-apply must leave this choice alone until something clears
    /// it.
    Override,
}

/// Decide whether this edit may change the exit node, and what it means for the exemption — Go's
/// `checkEditPrefsAccessLocked` exit-node arm together with the `onEditPrefsLocked` assignment that
/// follows it.
///
/// `named` is the edit as `up`/`set` carry it: the outer `Option` is the "unchanged unless named"
/// sentinel (`None` = this command did not mention `--exit-node`) and the inner one is the value,
/// where `None` is `--exit-node=` — the clear. `policy` is
/// [`syspolicy::exit_node_policy`](super::syspolicy::exit_node_policy)'s answer, passed in rather
/// than read here so the decision is testable without the process-global policy registry — the same
/// split the policy module uses throughout.
///
/// Pure, so it runs before a single pref is mutated or persisted: a refused edit leaves the node
/// exactly as it was, which is the whole point of a gate that sits in front of the write.
pub(super) fn check_exit_node_edit(
    named: Option<Option<&str>>,
    policy: &ExitNodePolicy,
) -> Result<ExitNodeEdit, ExitNodeEditRefused> {
    // (1) Go's mask: an edit that does not touch the exit node is not an exit-node edit.
    let Some(wanted) = named else {
        return Ok(ExitNodeEdit::Untouched);
    };
    // (2) Nothing applied, nothing to manage.
    let Some(pinned) = policy.pinned.as_deref() else {
        return Ok(ExitNodeEdit::NoOverride);
    };
    // (3) The default: the administrator pinned a node and did not invite anyone to move it.
    if !policy.allow_override {
        return Err(ExitNodeEditRefused::ManagedByPolicy);
    }
    // (4) Go's `changeDisablesExitNodeLocked`: an override may move the egress, never turn it off.
    // A cleared selector is the only way an edit can leave the node with no exit node — this fork's
    // `up`/`set` write the named value straight into the pref — so it is the only case to refuse.
    let Some(wanted) = wanted else {
        return Err(ExitNodeEditRefused::ManagedByPolicy);
    };
    // The operator picking the policy's own node needs no exemption, and ends any that stood.
    if wanted == pinned {
        return Ok(ExitNodeEdit::NoOverride);
    }
    Ok(ExitNodeEdit::Override)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned-and-locked policy: an administrator who set `ExitNodeIP` and nothing else.
    fn pinned() -> ExitNodePolicy {
        ExitNodePolicy {
            pinned: Some("100.64.0.9".to_string()),
            allow_override: false,
        }
    }

    /// The same pin, with the administrator's opt-in to user overrides.
    fn pinned_with_override() -> ExitNodePolicy {
        ExitNodePolicy {
            allow_override: true,
            ..pinned()
        }
    }

    /// A node no administrator has managed: the gate is invisible, whatever the edit says.
    #[test]
    fn an_unmanaged_node_may_change_its_exit_node_freely() {
        let unmanaged = ExitNodePolicy::default();
        for named in [None, Some(None), Some(Some("100.64.0.3")), Some(Some(""))] {
            let expected = match named {
                None => ExitNodeEdit::Untouched,
                Some(_) => ExitNodeEdit::NoOverride,
            };
            assert_eq!(
                check_exit_node_edit(named, &unmanaged),
                Ok(expected),
                "with no policy pinning an exit node nothing may be refused ({named:?})"
            );
        }
        // `ExitNode.AllowOverride` on its own means nothing: Go reads it only after the policy has
        // already said the exit node is managed.
        let allowed_but_unpinned = ExitNodePolicy {
            pinned: None,
            allow_override: true,
        };
        assert_eq!(
            check_exit_node_edit(Some(Some("100.64.0.3")), &allowed_but_unpinned),
            Ok(ExitNodeEdit::NoOverride)
        );
    }

    /// The bead's case: the policy pins a node, the operator names another, and the answer is a
    /// visible error rather than a success that stores the administrator's value.
    #[test]
    fn a_pinned_exit_node_refuses_every_edit_that_names_one() {
        for named in [Some(None), Some(Some("100.64.0.3")), Some(Some("peer-a"))] {
            assert_eq!(
                check_exit_node_edit(named, &pinned()),
                Err(ExitNodeEditRefused::ManagedByPolicy),
                "a pinned exit node is not the operator's to move ({named:?})"
            );
        }
        assert_eq!(
            ExitNodeEditRefused::ManagedByPolicy.to_string(),
            "exit node cannot be changed: managed by policy",
            "Go's message, verbatim"
        );
        // Even re-typing the policy's own value is refused without the override key: Go gates on the
        // mask, not on whether the edit would change anything.
        assert_eq!(
            check_exit_node_edit(Some(Some("100.64.0.9")), &pinned()),
            Err(ExitNodeEditRefused::ManagedByPolicy)
        );
    }

    /// A policy that pins an exit node still leaves every other pref alone — the mask guard. Without
    /// it, `tnet set --hostname kiosk-3` on a managed node would be refused for naming no exit node
    /// at all.
    #[test]
    fn an_edit_that_names_no_exit_node_is_never_gated() {
        for policy in [ExitNodePolicy::default(), pinned(), pinned_with_override()] {
            assert_eq!(
                check_exit_node_edit(None, &policy),
                Ok(ExitNodeEdit::Untouched),
                "{policy:?}"
            );
        }
    }

    /// The administrator's opt-in: the egress may move, and the move is remembered.
    #[test]
    fn an_allowed_override_may_move_the_egress() {
        assert_eq!(
            check_exit_node_edit(Some(Some("100.64.0.3")), &pinned_with_override()),
            Ok(ExitNodeEdit::Override),
            "ExitNode.AllowOverride exists precisely so a user may pick a different node"
        );
        // Picking the policy's own node is not an override, so it ends any that stood — Go clears
        // the flag when the user switches back to the state the policy requires.
        assert_eq!(
            check_exit_node_edit(Some(Some("100.64.0.9")), &pinned_with_override()),
            Ok(ExitNodeEdit::NoOverride)
        );
    }

    /// The bound on the opt-in: an override can move the egress but never turn it off.
    #[test]
    fn an_allowed_override_may_not_disable_the_exit_node() {
        assert_eq!(
            check_exit_node_edit(Some(None), &pinned_with_override()),
            Err(ExitNodeEditRefused::ManagedByPolicy),
            "`--exit-node=` under a pinning policy is a disconnect from the administrator's egress, \
             which is what Go's changeDisablesExitNodeLocked refuses"
        );
    }
}
