//! Always-on mode — the disconnect refusals an MDM policy can impose, and the audit record a
//! permitted disconnect leaves behind.
//!
//! This is the Rust analogue of Go's `ipnauth.CheckDisconnectPolicy` (`ipn/ipnauth/policy.go`), the
//! rule that `--reason` exists to satisfy. It is three refusals in one decision, in this order:
//!
//! 1. `AlwaysOn.Enabled` unset (or false) → **anyone may disconnect**. This is the common case: a
//!    node with no policy file behaves exactly as it did before this module existed.
//! 2. `AlwaysOn.Enabled` set, `AlwaysOn.OverrideWithReason` unset → the disconnect is refused
//!    outright: *disconnect not allowed: always-on mode is enabled*.
//! 3. Both set → an **empty** reason is refused (*disconnect not allowed: reason required*) and a
//!    non-empty one is accepted **and** recorded as a `DISCONNECT_NODE` audit record.
//!
//! ## Where the audit record goes, and what is deliberately missing
//!
//! Go hands the record to an audit logger that ships it to the control plane. This daemon has no
//! such transport (the engine exposes none — that is engine ask #41 in `docs/ENGINE_ASKS.md`), so
//! the record is written to the **daemon's own log** by [`Backend::down`]/[`Backend::logout`], in
//! Go's `details` wording, with Go's action name beside it. The refusals themselves need nothing
//! from the engine and are what actually stops the disconnect; only the *delivery* of the record to
//! control is deferred.
//!
//! The *re-connect* half of always-on mode is the other side of this gate, and it is split the way
//! Go splits it: `applySysPolicyLocked` forcing `WantRunning` back to true lives in
//! [`syspolicy::apply_to_prefs`](super::syspolicy::apply_to_prefs), which runs at every reconcile
//! point (daemon start, `up`, `set`, `--config` reload). So a node this gate refuses to disconnect
//! also comes back up if something else stopped it.
//!
//! Still deferred, deliberately: Go's `ReconnectAfter` timer and the `overrideAlwaysOn` flag that
//! goes with it (`onEditPrefsLocked` arms the timer after a permitted disconnect, and the re-assert
//! is suppressed while the override stands). That pair is a background task with its own lifecycle,
//! and without it the window a permitted disconnect buys is "until the next reconcile point" rather
//! than the duration an administrator configured — see
//! [`syspolicy`](super::syspolicy)'s module docs.
//!
//! [`Backend::down`]: super::Backend::down
//! [`Backend::logout`]: super::Backend::logout
//!
//! Upstream: `ipn/ipnauth/policy.go` (and the `checkEditPrefsAccessLocked` caller in
//! `ipn/ipnlocal/local.go`) @ `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8`.

use super::syspolicy;
use super::syspolicy::{PKEY_ALWAYS_ON, PKEY_ALWAYS_ON_OVERRIDE_WITH_REASON};

/// Go `tailcfg.AuditNodeDisconnect`, the `ClientAuditAction` a permitted disconnect is logged
/// under: `AuditNodeDisconnect = ClientAuditAction("DISCONNECT_NODE")` (`tailcfg/tailcfg.go`).
/// Carried verbatim so a log this daemon writes and one Go ships to control name the same action.
pub const AUDIT_NODE_DISCONNECT: &str = "DISCONNECT_NODE";

/// Who asked for the disconnect — the stand-in for Go's `ipnauth.Actor`, which is what decides
/// whether the policy is consulted at all.
///
/// Go wraps a client's actor in `ipnauth.WithPolicyChecks`, which returns the actor unwrapped for
/// the `unrestricted` case (the daemon acting on its own behalf) and wrapped — i.e. policy-checked —
/// for everyone else. This enum is that fork in the road, made explicit at the call site so a new
/// caller of [`Backend::down`](super::Backend::down) has to say which one it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor<'a> {
    /// A LocalAPI caller: `tnet down` / `tnet logout`, carrying the operator's `--reason` (Go
    /// attaches it to the prefs edit as `apitype.RequestReasonKey` and reads it back out of the
    /// request context). `None` is a `--reason`-less invocation, which Go sees as the empty string.
    /// **Policy-checked.**
    Operator {
        /// The operator's justification, verbatim as it arrived over the LocalAPI.
        reason: Option<&'a str>,
    },
    /// The daemon reconciling intent it has **already persisted** on its own initiative — today only
    /// a `--config` reload that set `Enabled:false`, where `reload_config` has written
    /// `want_running=false` before the engine teardown is even scheduled. Go's `unrestricted` actor,
    /// which `WithPolicyChecks` hands back unwrapped. **Not policy-checked**: there is no operator to
    /// supply a reason, and refusing here would abort a reload halfway, leaving the persisted prefs
    /// disagreeing with the live engine. Go reaches the same end state by a different road — its
    /// `applySysPolicyLocked` simply forces `WantRunning` back to true after the reload — and this
    /// daemon now takes that road too: `apply_config` reconciles policy after merging the config, so
    /// under `AlwaysOn.Enabled` a reloaded `Enabled:false` never reaches this actor at all (the
    /// reconcile puts `want_running` back up and the reload becomes a rebuild). The unrestricted
    /// actor stays because that is what the road is *for*: the case with no always-on policy, where
    /// the reload really does stop the node and there is no operator to ask for a reason.
    Daemon,
}

/// A disconnect the policy refused, and the message Go prints for it.
///
/// Two variants because Go has two `errors.New` sites, with two different remedies: the first is
/// "you cannot", the second is "you must say why". Collapsing them into one string would lose the
/// only actionable difference between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectRefused {
    /// `AlwaysOn.Enabled` is set and `AlwaysOn.OverrideWithReason` is not — no reason can help.
    AlwaysOn,
    /// Both keys are set, but the disconnect carried no reason (or an empty one).
    ReasonRequired,
}

impl DisconnectRefused {
    /// Go's message for this refusal, verbatim — an operator comparing `tnet` against `tailscale`
    /// reads the same sentence.
    pub const fn message(self) -> &'static str {
        match self {
            // `errors.New("disconnect not allowed: always-on mode is enabled")`
            Self::AlwaysOn => "disconnect not allowed: always-on mode is enabled",
            // `errors.New("disconnect not allowed: reason required")`
            Self::ReasonRequired => "disconnect not allowed: reason required",
        }
    }
}

impl std::fmt::Display for DisconnectRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for DisconnectRefused {}

/// Decide whether `actor` may disconnect this node — Go `ipnauth.CheckDisconnectPolicy`.
///
/// `profile` is the current profile's display name (Go's `profile.Name()`) and `username` the
/// actor's OS username, both of which appear only in the audit record. On success the return is the
/// audit record's `details` text when the policy **required** one (Go calls `auditFn` only on the
/// both-keys-set path), or `None` when the policy had nothing to say — so a node with no policy
/// file writes no audit record, exactly as in Go.
///
/// Errors are the refusals; they are returned before anything is torn down, so a refused disconnect
/// leaves the node exactly as it was.
pub fn check_disconnect_policy(
    actor: Actor<'_>,
    profile: &str,
    username: Option<&str>,
) -> Result<Option<String>, DisconnectRefused> {
    // Go's `WithPolicyChecks` returns an `unrestricted` actor unwrapped, so the policy is never
    // consulted for it. Same here, and for the same reason (see `Actor::Daemon`).
    let Actor::Operator { reason } = actor else {
        return Ok(None);
    };
    decide(
        syspolicy::get_boolean(PKEY_ALWAYS_ON, false),
        syspolicy::get_boolean(PKEY_ALWAYS_ON_OVERRIDE_WITH_REASON, false),
        reason,
        profile,
        username,
    )
}

/// The decision behind [`check_disconnect_policy`], over the two already-resolved policy booleans so
/// it is testable without the process-global policy registry (the same split
/// [`syspolicy::get_boolean`] uses).
fn decide(
    always_on: bool,
    override_with_reason: bool,
    reason: Option<&str>,
    profile: &str,
    username: Option<&str>,
) -> Result<Option<String>, DisconnectRefused> {
    if !always_on {
        return Ok(None);
    }
    if !override_with_reason {
        return Err(DisconnectRefused::AlwaysOn);
    }
    // Go reads the reason out of the request context, where an absent header and an empty one are
    // both the empty string — so a missing `--reason` and `--reason ""` are one case, not two.
    let reason = reason.unwrap_or_default();
    if reason.is_empty() {
        return Err(DisconnectRefused::ReasonRequired);
    }
    Ok(Some(audit_details(profile, username, reason)))
}

/// Go's two `details` renderings for a `DISCONNECT_NODE` audit record, chosen by whether the actor
/// has a username (`%q is being disconnected by %q: %v` / `%q is being disconnected: %v`).
///
/// The reason is [sanitized](sanitize_request_reason) on the way in. Go's record is a JSON field
/// shipped to control; this fork's lands in a line-oriented daemon log, where a raw newline in
/// operator-typed free text would forge a second record.
fn audit_details(profile: &str, username: Option<&str>, reason: &str) -> String {
    let reason = sanitize_request_reason(reason);
    let profile = syspolicy::quoted(profile);
    // Go's `if username, _ := actor.Username(); username != ""` — the empty string takes the short
    // form, so an empty `Some("")` must not render as `by ""`.
    match username.filter(|u| !u.is_empty()) {
        Some(username) => format!(
            "{profile} is being disconnected by {}: {reason}",
            syspolicy::quoted(username)
        ),
        None => format!("{profile} is being disconnected: {reason}"),
    }
}

/// Harden an operator-supplied `--reason` text (Go's LocalAPI `RequestReason`, carried by both
/// `logout` and `down`) for the daemon log. The reason is free text typed by whoever ran the
/// command, and it lands in a log a human (or a log shipper) reads later,
/// so it is untrusted for formatting: every control character — newline, CR, tab, ANSI escape —
/// becomes `_` so one reason can never forge a second log line or steer a terminal, and the value is
/// capped at [`MAX_LOGGED_REASON`] characters so a megabyte of "justification" cannot flood the log.
/// Truncation is marked with a trailing `…` so a reader can tell the record is not the whole text.
/// Same treatment (and same rationale) as the `bugreport` note's `sanitize_marker_note`.
///
/// It lives beside the policy that gives the reason its meaning because both the daemon's own
/// "disconnect requested" log line ([`crate::server`]) and the audit record built here need exactly
/// one definition of what a loggable reason is.
pub(crate) fn sanitize_request_reason(reason: &str) -> String {
    let mut out: String = reason
        .chars()
        .take(MAX_LOGGED_REASON)
        .map(|c| if c.is_control() { '_' } else { c })
        .collect();
    if reason.chars().nth(MAX_LOGGED_REASON).is_some() {
        out.push('…');
    }
    out
}

/// Character cap applied to a logged `--reason` (see [`sanitize_request_reason`]). Generous
/// for a real justification, far below anything that would bloat the daemon log.
pub(crate) const MAX_LOGGED_REASON: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    /// The node an admin has not managed: the gate is invisible, with or without a reason.
    #[test]
    fn an_unmanaged_node_may_always_disconnect_and_writes_no_audit_record() {
        for reason in [None, Some(""), Some("scheduled maintenance")] {
            assert_eq!(
                decide(false, false, reason, "tagged-devices", None),
                Ok(None),
                "AlwaysOn.Enabled unset must let a disconnect through untouched ({reason:?})"
            );
            // `AlwaysOn.OverrideWithReason` on its own means nothing: Go reads it only after
            // `AlwaysOn` has already said the node is managed.
            assert_eq!(
                decide(false, true, reason, "tagged-devices", None),
                Ok(None),
                "OverrideWithReason without AlwaysOn must not gate anything ({reason:?})"
            );
        }
    }

    /// Always-on with no override: the refusal is outright, and a reason does not buy past it.
    #[test]
    fn always_on_without_an_override_refuses_even_a_reasoned_disconnect() {
        for reason in [None, Some(""), Some("scheduled maintenance")] {
            assert_eq!(
                decide(true, false, reason, "example.com", None),
                Err(DisconnectRefused::AlwaysOn),
                "a reason must not open a door the policy never opened ({reason:?})"
            );
        }
        assert_eq!(
            DisconnectRefused::AlwaysOn.to_string(),
            "disconnect not allowed: always-on mode is enabled",
            "Go's message, verbatim"
        );
    }

    /// Both keys set: an absent reason and an empty one are the same refusal, which is Go's — it
    /// tests the context value for `== \"\"`, and a missing header reads back as empty.
    #[test]
    fn an_override_policy_still_refuses_a_reasonless_disconnect() {
        for reason in [None, Some("")] {
            assert_eq!(
                decide(true, true, reason, "example.com", None),
                Err(DisconnectRefused::ReasonRequired),
                "an empty justification is no justification ({reason:?})"
            );
        }
        assert_eq!(
            DisconnectRefused::ReasonRequired.to_string(),
            "disconnect not allowed: reason required",
            "Go's message, verbatim"
        );
    }

    /// The permitted path: the disconnect goes ahead AND leaves Go's audit record behind.
    #[test]
    fn a_reasoned_disconnect_is_permitted_and_audited_in_gos_wording() {
        // No username (every platform but Windows, in Go): the short form.
        assert_eq!(
            decide(
                true,
                true,
                Some("laptop returned to IT"),
                "example.com",
                None
            ),
            Ok(Some(
                r#""example.com" is being disconnected: laptop returned to IT"#.to_string()
            ))
        );
        // With one: Go's `%q`-quoted `by` form.
        assert_eq!(
            decide(
                true,
                true,
                Some("laptop returned to IT"),
                "example.com",
                Some("alice")
            ),
            Ok(Some(
                r#""example.com" is being disconnected by "alice": laptop returned to IT"#
                    .to_string()
            ))
        );
        // Go takes the short form for an empty username (`username != ""`), not `by ""`.
        assert_eq!(
            decide(true, true, Some("x"), "example.com", Some("")),
            decide(true, true, Some("x"), "example.com", None),
            "an empty username must render as if there were none"
        );
    }

    /// The audit record is a log line built out of operator free text, so the text cannot be allowed
    /// to end the line and start a new one.
    #[test]
    fn an_audited_reason_cannot_forge_a_second_record() {
        let Ok(Some(details)) = decide(
            true,
            true,
            Some("returned to IT\nINFO forged: node re-registered"),
            "example.com",
            None,
        ) else {
            panic!("a reasoned disconnect under an override policy must be permitted");
        };
        assert!(
            !details.contains('\n'),
            "a newline must not survive into the audit record: {details:?}"
        );
        assert_eq!(
            details,
            r#""example.com" is being disconnected: returned to IT_INFO forged: node re-registered"#
        );
    }

    /// The daemon acting on its own already-persisted intent is Go's `unrestricted` actor: the
    /// policy is not consulted for it, even when always-on would refuse an operator outright.
    #[test]
    fn the_daemons_own_reconcile_is_not_policy_checked() {
        // `check_disconnect_policy` is the function with the actor fork in it, so it is the one
        // called here; with no policy source registered in this test process both booleans resolve
        // false anyway, which is why the assertion that carries the weight is the `decide` pair
        // above — this pins that `Actor::Daemon` never reaches them.
        assert_eq!(
            check_disconnect_policy(Actor::Daemon, "example.com", None),
            Ok(None)
        );
    }

    #[test]
    fn request_reason_is_sanitized_before_it_reaches_the_log() {
        // The reason (`logout --reason`, `down --reason`) is operator free text that ends up in the
        // daemon log, so a newline must not be able to forge a second log record and an escape must
        // not be able to steer a terminal that later renders the log.
        let forged = "returned to IT\nINFO forged: node re-registered";
        let clean = sanitize_request_reason(forged);
        assert!(
            !clean.contains('\n'),
            "a newline must not survive into the log line: {clean:?}"
        );
        assert_eq!(clean, "returned to IT_INFO forged: node re-registered");
        assert_eq!(
            sanitize_request_reason("laptop returned to IT"),
            "laptop returned to IT",
            "ordinary text must pass through untouched"
        );
        assert!(
            !sanitize_request_reason("\u{1b}[2Jwiped").contains('\u{1b}'),
            "ANSI escapes must be neutralized"
        );

        // Over-long input is capped and marked as truncated.
        let long = "j".repeat(MAX_LOGGED_REASON + 50);
        let capped = sanitize_request_reason(&long);
        assert_eq!(capped.chars().count(), MAX_LOGGED_REASON + 1);
        assert!(
            capped.ends_with('…'),
            "truncation must be visible: {capped:?}"
        );
        // Exactly at the cap: no truncation marker.
        let exact = sanitize_request_reason(&"j".repeat(MAX_LOGGED_REASON));
        assert_eq!(exact.chars().count(), MAX_LOGGED_REASON);
        assert!(!exact.ends_with('…'));
    }
}
