//! The control-URL change guard — the Rust analogue of Go `tailscale up`'s
//! `can't change --login-server without --force-reauth` check (`cmd/tailscale/cli/up.go`).
//!
//! ## Why this exists
//!
//! Changing which control server a node talks to is a re-registration, not an in-place tweak: the
//! node must authenticate afresh against the new server. Go's `up` therefore **refuses** to change
//! the control URL on a node that is already Running unless the operator also passes `--force-reauth`
//! (which performs exactly that fresh registration). Without the guard, `up --control-url <other>`
//! would silently re-point a live node's control plane while keeping its old node key — a confusing,
//! half-migrated state.
//!
//! This fork treated `control_url` as an ordinary `up` pref override (gated only by the generic
//! accidental-revert guard), so it lacked this protection. [`change_blocked`] supplies it. The
//! `--force-reauth` escape hatch already exists (it discards the node key so the rebuilt engine
//! registers fresh — see [`crate::ipn::Backend::begin_up`]).
//!
//! ## Faithful synonym handling
//!
//! Go does not trip the guard when the URL only changes between *synonyms* of the default control
//! server (`ipn.IsLoginServerSynonym`: `https://login.tailscale.com` and
//! `https://controlplane.tailscale.com` are the same service). In this daemon the default is also
//! expressed as `control_url = None` (no override → the engine's built-in default). So
//! [`normalize`] collapses `None` **and** both default URLs to a single sentinel: switching between
//! any of them is not a real change and never trips the guard. Only a move to a genuinely different
//! server is a change.
//!
//! The decision is a **pure, read-only** function so it is unit-testable without a live `Backend` or
//! engine — a tripped guard is a pre-flight rejection that mutates nothing.

/// The two default Tailscale control-server URLs Go treats as interchangeable
/// (`ipn.IsLoginServerSynonym`). Switching between these — or between either and the daemon's
/// "no override" default (`None`) — is not a control-server change.
const LOGIN_SERVER_SYNONYMS: [&str; 2] = [
    "https://login.tailscale.com",
    "https://controlplane.tailscale.com",
];

/// Normalize a control-URL pref to a comparison key: `None` (use the engine default) and any of the
/// [`LOGIN_SERVER_SYNONYMS`] all collapse to `None` (= "the default control server"); any other URL
/// maps to itself. Two prefs denote the same control server iff their normalized forms are equal.
fn normalize(url: Option<&str>) -> Option<&str> {
    match url {
        None => None,
        Some(u) if LOGIN_SERVER_SYNONYMS.contains(&u) => None,
        Some(u) => Some(u),
    }
}

/// Whether an `up` must be **refused** for changing the control URL on a Running node without
/// `--force-reauth` — the Rust analogue of Go's `controlURLChanged && backendState==Running &&
/// !forceReauth` check.
///
/// Returns `true` (block) only when **all** hold:
/// - `proposed` actually changes the control server vs `current` (after [`normalize`] — a synonym
///   swap or "default→default" is not a change). A `proposed` of `None` means the `up` did not
///   mention `--control-url`, so it changes nothing and never blocks (a bare `up` is unaffected).
/// - `running` — the node is actually **Running** (Go's `backendState == ipn.Running`). The caller
///   passes the node's real reported state, NOT mere device-presence (a device can be installed
///   while `Starting`/`NeedsLogin`, where Go would not guard). A non-Running node re-registers on its
///   next `up` anyway, so a server change is harmless there.
/// - `!force_reauth` — the operator did not opt into the fresh registration that legitimizes the
///   change.
pub fn change_blocked(
    current: Option<&str>,
    proposed: Option<&str>,
    running: bool,
    force_reauth: bool,
) -> bool {
    // A `proposed` of `None` = "--control-url not mentioned" = no change requested. (This is distinct
    // from `Some("https://login.tailscale.com")`, an explicit set to the default, which `normalize`
    // still treats as the default — also not a change vs a `None`/default current.)
    let Some(_) = proposed else {
        return false;
    };
    let changed = normalize(current) != normalize(proposed);
    changed && running && !force_reauth
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_A: &str = "https://login.tailscale.com";
    const DEFAULT_B: &str = "https://controlplane.tailscale.com";
    const CUSTOM: &str = "https://hs.example.com";
    const OTHER: &str = "https://other.example.com";

    #[test]
    fn bare_up_never_blocks() {
        // proposed = None (the up didn't pass --control-url) → never a change, regardless of state.
        assert!(!change_blocked(None, None, true, false));
        assert!(!change_blocked(Some(CUSTOM), None, true, false));
        assert!(!change_blocked(Some(DEFAULT_A), None, true, false));
    }

    #[test]
    fn same_url_is_not_a_change() {
        assert!(!change_blocked(Some(CUSTOM), Some(CUSTOM), true, false));
    }

    #[test]
    fn default_synonyms_are_not_a_change() {
        // login.tailscale.com ↔ controlplane.tailscale.com, and None ↔ either default, are synonyms.
        assert!(!change_blocked(
            Some(DEFAULT_A),
            Some(DEFAULT_B),
            true,
            false
        ));
        assert!(!change_blocked(
            Some(DEFAULT_B),
            Some(DEFAULT_A),
            true,
            false
        ));
        assert!(!change_blocked(None, Some(DEFAULT_A), true, false));
        assert!(!change_blocked(Some(DEFAULT_B), None, true, false)); // (proposed None anyway)
        // A real custom server → a default is a genuine change (handled by the change cases below),
        // but default → default in either direction must never trip.
    }

    #[test]
    fn real_change_on_running_node_without_force_reauth_blocks() {
        // The canonical case Go guards: a genuinely different server, node up, no --force-reauth.
        assert!(change_blocked(None, Some(CUSTOM), true, false));
        assert!(change_blocked(Some(DEFAULT_A), Some(CUSTOM), true, false));
        assert!(change_blocked(Some(CUSTOM), Some(OTHER), true, false));
    }

    #[test]
    fn real_change_on_non_running_node_does_not_block() {
        // Only Running nodes are guarded (Go's backendState==Running). `running == false` covers a
        // down node AND a device-present-but-not-yet-Running node (Starting/NeedsLogin/Expired) — the
        // caller passes the node's REAL state, not device-presence, so the guard never over-fires in
        // those states (the fidelity point: a device can be installed mid-interactive-login). Such a
        // node re-registers on its next up anyway, so changing the server is fine.
        assert!(!change_blocked(None, Some(CUSTOM), false, false));
        assert!(!change_blocked(Some(CUSTOM), Some(OTHER), false, false));
    }

    #[test]
    fn force_reauth_is_the_escape_hatch() {
        // The same real change, but --force-reauth opts into the fresh registration → allowed.
        assert!(!change_blocked(None, Some(CUSTOM), true, true));
        assert!(!change_blocked(Some(CUSTOM), Some(OTHER), true, true));
    }
}
