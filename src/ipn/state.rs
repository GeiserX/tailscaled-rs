//! Pure state derivation + TUN-name selection for the IPN backend.
//!
//! These are the standalone, `self`-free pieces of the state machine, split out of [`super`] so
//! they can be unit-tested without a live `Backend`/engine. The [`State`] enum is re-exported from
//! [`crate::ipn`] (so `crate::ipn::State` still resolves for callers like `localapi`); the
//! derivation fns ([`derive_state_from`], [`state_from_device`]) and the macOS TUN-name helpers
//! ([`default_tun_name`], [`lowest_free_utun`]) are crate-internal helpers used by `super`.

/// The IPN lifecycle state, mirroring `ipn.State` (subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Process started, nothing configured yet.
    NoState,
    /// No valid login / not authenticated to control.
    ///
    /// Transient nuance from the concurrent bring-up split: between
    /// [`begin_up`](super::Backend::begin_up) (which sets `want_running = true` but installs no device yet)
    /// and [`finish_up`](super::Backend::finish_up), a concurrent `status` observes `(device = None,
    /// want_running = true)` and reports `NeedsLogin` for the duration of the handshake — i.e. a
    /// `status` polled *during* an `up` may briefly read `NeedsLogin` before `Running`. This is the
    /// deliberate latency-vs-staleness tradeoff of not holding the lock across `Device::new` (a
    /// poller is no longer *blocked* for the handshake; it sees this transient state instead). A
    /// future refinement could surface a dedicated "bringing up" signal as `Starting`.
    NeedsLogin,
    /// Registered to control, but the machine is not yet authorized by a tailnet admin (Go's
    /// `ipn.NeedsMachineAuth`). See the `// LIMITATION:` note on [`Backend::derive_state`](super::Backend):
    /// the engine does not surface this from a status snapshot, and no current code path produces it; it
    /// would require [`Backend::up`](super::Backend::up) to branch on a typed registration error. Kept for `ipn.State`
    /// parity.
    NeedsMachineAuth,
    /// The node key is already in use by a different user/profile (Go's `ipn.InUseOtherUser`).
    /// Unreachable in this single-user, auth-key-only daemon; kept only for `ipn.State` parity.
    InUseOtherUser,
    /// `WantRunning = true`; engine is up, awaiting the first netmap.
    Starting,
    /// Fully up: netmap received, addresses assigned.
    Running,
    /// Configured + authed, but `WantRunning = false` (explicitly down).
    Stopped,
}

impl State {
    /// The stable string name (matches Tailscale's `ipn.State.String()` values).
    pub fn as_str(self) -> &'static str {
        match self {
            State::NoState => "NoState",
            State::NeedsLogin => "NeedsLogin",
            State::NeedsMachineAuth => "NeedsMachineAuth",
            State::InUseOtherUser => "InUseOtherUser",
            State::Starting => "Starting",
            State::Running => "Running",
            State::Stopped => "Stopped",
        }
    }
}

/// The default TUN interface name to request when the operator gave none, by platform.
///
/// `None` means "let the engine choose its default" (`tailscale0` on Linux, which the kernel
/// accepts). macOS is special: the engine coerces a `None` name to `tailscale0`, which the kernel
/// rejects (utun interfaces *must* be named `utun*`), and `tun-rs` also rejects a *bare* `"utun"`
/// (it parses the trailing digits as the unit, and `""` fails: "cannot parse integer from empty
/// string"). The only value that works through the engine on macOS is an explicit, currently-free
/// `utunN`. So on macOS we scan existing interfaces and return the lowest free index. Linux/BSD
/// return `None` (the engine's `tailscale0` default stands).
///
/// (The real fix is a platform-aware default in the engine — see `docs/ENGINE_ASKS.md` #5 — at
/// which point this becomes a redundant no-op. Until then it keeps macOS TUN working.)
///
/// Note the inherent, bounded TOCTOU: another process could claim the chosen `utunN` between this
/// scan and the engine's device create. That is fine — device creation fails closed (no silent
/// downgrade), so the operator simply retries and the next scan picks a different free index.
#[cfg(feature = "tun")]
pub(super) fn default_tun_name() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        Some(lowest_free_utun())
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The lowest `utunN` name not currently present on the host (macOS). Enumerates interfaces via
/// `if-addrs`; if enumeration fails, falls back to `utun0` (the kernel will still reject it if taken,
/// which fails closed and prompts a retry — never a silent wrong-interface).
#[cfg(all(feature = "tun", target_os = "macos"))]
pub(super) fn lowest_free_utun() -> String {
    use std::collections::BTreeSet;
    let used: BTreeSet<u32> = if_addrs::get_if_addrs()
        .map(|ifaces| {
            ifaces
                .into_iter()
                .filter_map(|i| {
                    i.name
                        .strip_prefix("utun")
                        .and_then(|n| n.parse::<u32>().ok())
                })
                .collect()
        })
        .unwrap_or_default();
    let n = (0..)
        .find(|n| !used.contains(n))
        .expect("a free utun index exists");
    format!("utun{n}")
}

/// Pure state-derivation decision, extracted from [`Backend::derive_state`](super::Backend) so it is
/// unit-testable without a live `Backend` or engine.
///
/// Inputs are the observable facts the reported [`State`] is a function of:
/// - `has_device`: an engine [`tailscale::Device`] is currently constructed (the node is "up").
/// - `have_self_node`: the engine has received a netmap and assigned this node its addresses.
/// - `want_running` / `logged_out`: the persisted [`Prefs`](crate::prefs::Prefs) intent.
/// - `has_node_key`: a usable node key is persisted on disk — the analogue of Go's
///   `hasNodeKeyLocked()`, which is exactly what Go's `nextStateLocked` gates `Stopped` on
///   (`ipn/ipnlocal/local.go`: `!wantRunning && !loggedOut && hasNodeKey → Stopped`, else the
///   no-netmap path → `NoState`). A node configured by `set` but never brought up (so no key was
///   ever minted) reports `NoState`, matching Go — NOT `Stopped`. `up` persists the key before it
///   can be brought `down`, and `down` keeps it, so the common up→down→restart path still reports
///   `Stopped`; only `logout`/force-reauth wipe it (and `logged_out` is checked first).
///
/// See the `// LIMITATION:` note on [`Backend::derive_state`](super::Backend) for why
/// [`State::NeedsMachineAuth`] and [`State::InUseOtherUser`] are never produced here.
pub(super) fn derive_state_from(
    has_device: bool,
    have_self_node: bool,
    want_running: bool,
    logged_out: bool,
    has_node_key: bool,
) -> State {
    match has_device {
        true if have_self_node => State::Running,
        true => State::Starting,
        false if logged_out => State::NeedsLogin,
        false if want_running => State::NeedsLogin, // wants up but no engine → needs (re)auth
        // Go gates `Stopped` on a persisted node key (`hasNodeKeyLocked`); a configured-but-never-
        // registered node (e.g. `set` then never `up`) has no key → `NoState`, like Go.
        false if has_node_key => State::Stopped,
        false => State::NoState,
    }
}

/// Map the engine's authoritative [`tailscale::DeviceState`] to the daemon's reported [`State`]
/// plus two optional, mutually-exclusive detail strings: the interactive-login auth URL and the
/// terminal-failure reason. Pure, so the mapping is unit-testable without a live engine.
///
/// Returns `(State, auth_url, error)`:
/// - **`State`** — the lifecycle state surfaced on the wire (`StatusReport.state`). There are only
///   ever the seven `ipn.State` names (pinned by [`state_as_str_is_stable`](tests)); we deliberately
///   do **not** mint an eighth variant for a terminal failure. Go surfaces that case the same way:
///   the state stays `NeedsLogin`, and a separate `ipnstate.Status.ErrMessage` field carries the
///   reason. The `error` return below is that field's analogue.
/// - **`auth_url`** (2nd) — `Some(url)` **only** for `NeedsLogin(url)`: an interactive-login flow is
///   pending and the operator must authorize the node at that URL. Always `None` otherwise.
/// - **`error`** (3rd) — `Some(reason)` **only** for `Failed(e)`: registration hard-failed and the
///   engine will not retry. It carries [`tailscale::RegistrationError`]'s `Display` string so a
///   caller can report *why* (and, via [`RegistrationError::is_permanent`](tailscale::RegistrationError::is_permanent),
///   that it is terminal). Always `None` otherwise.
///
/// This is the source of truth when a device exists: the engine knows about interactive-login,
/// key-expiry, and hard registration failure — distinctions netmap-presence alone cannot make.
/// - `Connecting` → `Starting` (registering; the netmap stream is not yet live), no url, no error.
/// - `Running` → `Running`, no url, no error. The engine publishes `Running` only once "registered
///   and the netmap stream is live" (per its `DeviceState` doc), so it already implies the node is
///   up — we do not second-guess it with a separate self-node check.
/// - `NeedsLogin(url)` → [`State::NeedsLogin`] **carrying the auth URL** — an `up` without a usable
///   auth key needs a human to authorize the node at that URL (the interactive-login flow).
/// - `Expired` → [`State::NeedsLogin`] with **no url and no error**: an expired node key is a
///   re-auth *prompt*, not a hard failure (the operator simply re-runs `tnet up`); the engine
///   carries no URL here, and we deliberately do not populate `error` so an expiry never looks like
///   a terminal registration failure.
/// - `Failed(e)` splits on [`RegistrationError::is_permanent`](tailscale::RegistrationError::is_permanent),
///   because the engine reuses this one variant for two very different cases:
///   - **permanent** (`AuthRejected` / `KeyExpired`) → [`State::NeedsLogin`] with **no url** but
///     **`error = Some(e.to_string())`**: a failure the engine will NOT retry. The state stays
///     `NeedsLogin` (no eighth `ipn.State`; see above), but `error` carries the reason so the
///     daemon/CLI can distinguish "interactive login pending" (`auth_url` set, transient) from
///     "registration hard-failed" (`error` set, terminal). The absent `auth_url` is intentional: a
///     hard failure must NOT masquerade as an interactive-login prompt.
///   - **transient** (`NetworkUnreachable` / `Timeout`) → [`State::Starting`] with **no url and no
///     error**: the engine keeps retrying (it publishes `Failed(NetworkUnreachable)` precisely when
///     "a retry may succeed"), so this is neither terminal nor a login problem. Reporting it via
///     `error` would tell the operator to rotate a key that is actually fine — the exact misleading
///     guidance this mapping exists to avoid — so a transient failure looks like ongoing
///     convergence, and the next poll reflects the retry's outcome.
pub(super) fn state_from_device(
    ds: tailscale::DeviceState,
) -> (State, Option<String>, Option<String>) {
    use tailscale::DeviceState;
    match ds {
        DeviceState::Running => (State::Running, None, None),
        DeviceState::Connecting => (State::Starting, None, None),
        DeviceState::NeedsLogin(url) => (State::NeedsLogin, Some(url.to_string()), None),
        // Key expiry is a re-auth prompt, not a hard failure: NeedsLogin with no url and no error
        // (an expiry must not be reported as a terminal registration failure).
        DeviceState::Expired => (State::NeedsLogin, None, None),
        // A `Failed` outcome splits on permanence — the engine reuses this one variant for BOTH a
        // terminal failure AND a transient one (it publishes `Failed(NetworkUnreachable)` when the
        // control session can't connect, with the explicit intent that "a retry / fresh Device::new
        // may succeed" — see ts_runtime control_runner). Treating every `Failed` as terminal would
        // tell the operator "permanent failure, use a fresh key" on a mere network blip — exactly
        // the misleading guidance this whole change exists to remove. So we gate on
        // `RegistrationError::is_permanent()` (true only for `AuthRejected` / `KeyExpired`):
        DeviceState::Failed(e) if e.is_permanent() => {
            // PERMANENT (bad/expired/unknown key): the engine will NOT retry. Keep the state mapped
            // to NeedsLogin (no eighth ipn.State — Go surfaces this via a separate ErrMessage
            // field), but carry the reason in `error` so the daemon/CLI can tell a hard failure
            // (error set, no auth_url) apart from interactive login (auth_url set, no error). No
            // auth_url: a hard failure is not an interactive-login prompt.
            (State::NeedsLogin, None, Some(e.to_string()))
        }
        // TRANSIENT (`NetworkUnreachable` / `Timeout`): the engine keeps retrying, so this is NOT
        // terminal and NOT a login problem — surface it as `Starting` (still converging), with no
        // `error` (so the CLI never tells the operator to rotate a key that is actually fine) and no
        // auth_url. The next poll reflects the retry's outcome (Running, or a permanent Failed).
        DeviceState::Failed(_) => (State::Starting, None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `derive_state_from` is the whole state machine's decision in one pure function; exercise the
    // full input matrix here so the reported `ipn.State` can never silently drift. (The two
    // parity-only variants — `NeedsMachineAuth` / `InUseOtherUser` — are intentionally not produced
    // by this function; see the `// LIMITATION:` note on `Backend::derive_state`.)

    #[test]
    fn no_device_not_configured_is_no_state() {
        // Fresh process, never brought up, no intent → NoState.
        assert_eq!(
            derive_state_from(false, false, false, false, false),
            State::NoState
        );
    }

    #[test]
    fn no_device_want_running_but_logged_out_is_needs_login() {
        // Logged out always wins (suppresses auto-start); the node needs a (re)login.
        assert_eq!(
            derive_state_from(false, false, true, true, true),
            State::NeedsLogin
        );
        // …and even with want_running false, an explicit logout still reads as NeedsLogin.
        assert_eq!(
            derive_state_from(false, false, false, true, true),
            State::NeedsLogin
        );
    }

    #[test]
    fn no_device_want_running_is_needs_login() {
        // Wants to be up but the engine isn't constructed → needs (re)auth to bring it up.
        assert_eq!(
            derive_state_from(false, false, true, false, true),
            State::NeedsLogin
        );
    }

    #[test]
    fn device_present_no_self_node_is_starting() {
        // Engine is up but no netmap yet → Starting. (This is also where a machine awaiting admin
        // approval honestly lands; see the LIMITATION note.) The prefs are irrelevant once a device
        // exists, so assert both intents collapse to Starting.
        assert_eq!(
            derive_state_from(true, false, true, false, true),
            State::Starting
        );
        assert_eq!(
            derive_state_from(true, false, false, false, false),
            State::Starting
        );
    }

    #[test]
    fn device_present_with_self_node_is_running() {
        // Engine up + netmap received → Running, regardless of the persisted intent.
        assert_eq!(
            derive_state_from(true, true, true, false, true),
            State::Running
        );
        assert_eq!(
            derive_state_from(true, true, false, true, true),
            State::Running
        );
    }

    #[test]
    fn down_with_persisted_key_is_stopped() {
        // No device, not logged out, not wanting to run, but a node key IS on disk → explicitly
        // Stopped (a previously-registered node, intentionally down) — distinct from NoState. This is
        // the up→down→restart path: `up` minted+persisted the key, `down` kept it.
        assert_eq!(
            derive_state_from(false, false, false, false, true),
            State::Stopped
        );
    }

    #[test]
    fn has_node_key_is_the_only_no_state_vs_stopped_discriminator() {
        // With identical (no-device, not-logged-out, not-want-running) inputs, `has_node_key` is the
        // sole bit that flips NoState ↔ Stopped — Go's `hasNodeKeyLocked()` gate. A node configured
        // by `set` but never `up` (no key minted) is NoState (matching Go), not Stopped. Pin both.
        assert_eq!(
            derive_state_from(false, false, false, false, false),
            State::NoState
        );
        assert_eq!(
            derive_state_from(false, false, false, false, true),
            State::Stopped
        );
    }

    #[test]
    fn state_as_str_is_stable() {
        // The state string is a wire contract (LocalAPI StatusReport.state); pin every name.
        assert_eq!(State::NoState.as_str(), "NoState");
        assert_eq!(State::NeedsLogin.as_str(), "NeedsLogin");
        assert_eq!(State::NeedsMachineAuth.as_str(), "NeedsMachineAuth");
        assert_eq!(State::InUseOtherUser.as_str(), "InUseOtherUser");
        assert_eq!(State::Starting.as_str(), "Starting");
        assert_eq!(State::Running.as_str(), "Running");
        assert_eq!(State::Stopped.as_str(), "Stopped");
    }

    // macOS picks an explicit free `utunN` (the engine default `tailscale0` is rejected, and a bare
    // `utun` fails tun-rs's unit parse). The utun-picker is macOS-only behavior, so this test —
    // which exercises it — is `target_os = "macos"`-gated. (`if_addrs` itself is now a general unix
    // dep, used here on macOS for the utun scan and on all unix for the link-change monitor.)
    #[cfg(all(feature = "tun", target_os = "macos"))]
    #[test]
    fn default_tun_name_is_free_utun_on_macos() {
        let name = default_tun_name().expect("macOS must pick a concrete utun name");
        let n = name
            .strip_prefix("utun")
            .and_then(|s| s.parse::<u32>().ok())
            .expect("name must be utun<N> with a numeric unit");
        // The chosen index must be free: not a utun currently on the host.
        let used: std::collections::BTreeSet<u32> = if_addrs::get_if_addrs()
            .map(|ifs| {
                ifs.into_iter()
                    .filter_map(|i| {
                        i.name
                            .strip_prefix("utun")
                            .and_then(|s| s.parse::<u32>().ok())
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert!(!used.contains(&n), "chosen utun{n} must be free");
    }

    // On non-macOS the daemon defers to the engine's default name (None).
    #[cfg(all(feature = "tun", not(target_os = "macos")))]
    #[test]
    fn default_tun_name_is_none_off_macos() {
        assert_eq!(default_tun_name(), None);
    }

    // `state_from_device` maps the engine's authoritative `DeviceState` → `(State, auth_url, error)`.
    // It is the source of truth when a device exists, so the interactive-login URL surfacing, the
    // expiry→NeedsLogin collapse, and the terminal-failure→`error` surfacing must not drift. The
    // `auth_url` and `error` outputs are mutually exclusive (interactive-login vs. hard failure) and
    // every non-NeedsLogin(url)/non-Failed state carries neither. Pure, so testable without a live
    // engine.

    #[test]
    fn device_running_is_running_no_url() {
        // The engine publishes `Running` only once "registered and the netmap stream is live", so it
        // maps straight to `Running` (no separate self-node check). A healthy state carries neither
        // an auth URL nor a failure reason.
        let (st, url, err) = state_from_device(tailscale::DeviceState::Running);
        assert_eq!(st, State::Running);
        assert!(url.is_none());
        assert!(err.is_none(), "Running is not a failure → no error reason");
    }

    #[test]
    fn device_connecting_is_starting() {
        // Registering, netmap stream not yet live → still converging. Neither an auth URL nor a
        // failure reason while merely converging.
        let (st, url, err) = state_from_device(tailscale::DeviceState::Connecting);
        assert_eq!(st, State::Starting);
        assert!(url.is_none());
        assert!(
            err.is_none(),
            "Connecting is not a failure → no error reason"
        );
    }

    #[test]
    fn device_needs_login_carries_auth_url() {
        // The headline of interactive login: NeedsLogin(url) → State::NeedsLogin + the URL surfaced
        // verbatim so the CLI can print a clickable login link. Interactive login is NOT a hard
        // failure, so the `error` field stays empty (auth_url and error are mutually exclusive).
        let url: url::Url = "https://login.example.com/a/abc123".parse().unwrap();
        let (st, out, err) = state_from_device(tailscale::DeviceState::NeedsLogin(url.clone()));
        assert_eq!(st, State::NeedsLogin);
        assert_eq!(out.as_deref(), Some(url.as_str()));
        assert!(
            err.is_none(),
            "interactive login carries an auth_url, not an error reason"
        );
    }

    #[test]
    fn device_expired_is_needs_login_no_url() {
        // Key expiry needs re-auth but the engine carries no URL here → NeedsLogin, no URL. An
        // expiry is a re-auth *prompt*, not a terminal failure, so `error` is also empty (it must
        // NOT be reported like a hard registration failure).
        let (st, url, err) = state_from_device(tailscale::DeviceState::Expired);
        assert_eq!(st, State::NeedsLogin);
        assert!(url.is_none());
        assert!(
            err.is_none(),
            "key expiry is a re-auth prompt, not a terminal failure → no error reason"
        );
    }

    #[test]
    fn device_failed_carries_error_reason() {
        // A terminal registration failure (bad/unknown auth key) the engine will NOT retry. The
        // state still collapses to `NeedsLogin` (no eighth `ipn.State`; see `state_from_device`'s
        // doc), but the failure must surface through the `error` field — and crucially NOT through
        // `auth_url`, so a hard failure can never be mistaken for an interactive-login prompt.
        let (st, url, err) = state_from_device(tailscale::DeviceState::Failed(
            tailscale::RegistrationError::AuthRejected("bad auth key".into()),
        ));
        assert_eq!(st, State::NeedsLogin, "a hard failure maps to NeedsLogin");
        assert!(
            url.is_none(),
            "a hard failure has NO login URL — it must not look like interactive login"
        );
        let reason = err.expect("a terminal failure must carry its reason in `error`");
        // `RegistrationError::AuthRejected`'s Display is
        // "authentication rejected by control: {0}", so it contains the inner reason verbatim.
        assert!(
            reason.contains("bad auth key"),
            "the error must carry the rejection reason, got {reason:?}"
        );
    }

    #[test]
    fn device_failed_key_expired_carries_error() {
        // The other terminal `RegistrationError` variant: an *expired* node key that surfaces as a
        // hard `Failed` (distinct from the transient `DeviceState::Expired` re-auth prompt above).
        // It likewise stays `NeedsLogin` with no auth_url, but populates `error` with the variant's
        // Display string ("node key expired; re-authentication required").
        let (st, url, err) = state_from_device(tailscale::DeviceState::Failed(
            tailscale::RegistrationError::KeyExpired,
        ));
        assert_eq!(st, State::NeedsLogin);
        assert!(
            url.is_none(),
            "a hard failure carries no interactive-login URL"
        );
        let reason = err.expect("a terminal failure must carry its reason in `error`");
        assert!(
            reason.contains("expired"),
            "the error must describe the key-expiry failure, got {reason:?}"
        );
    }

    #[test]
    fn failed_splits_on_permanence_permanent_carries_error_transient_is_starting() {
        // The core of the review fix: `Failed(e)` is NOT uniformly terminal. The engine reuses the
        // variant for both a permanent failure (the user must re-pair) AND a transient one it keeps
        // retrying (`Failed(NetworkUnreachable)` on a control-session connect blip). The daemon must
        // split on `RegistrationError::is_permanent()` so a network hiccup never tells the operator
        // their key is bad. This test drives BOTH classes and is also the transposition guard for the
        // two same-typed `Option<String>` outputs (auth_url ⊕ error are mutually exclusive).
        let url: url::Url = "https://login.example.com/a/xyz".parse().unwrap();
        let cases = [
            tailscale::RegistrationError::AuthRejected("bad key".into()),
            tailscale::RegistrationError::KeyExpired,
            tailscale::RegistrationError::NeedsLogin(url),
            tailscale::RegistrationError::NetworkUnreachable,
            tailscale::RegistrationError::Timeout,
        ];
        for re in cases {
            let permanent = re.is_permanent();
            let expected_reason = re.to_string();
            let (st, auth_url, error) =
                state_from_device(tailscale::DeviceState::Failed(re.clone()));

            // NEVER populate auth_url for a Failed of any flavor — a hard failure (or a retrying
            // one) must not masquerade as an interactive-login prompt. This is the transposition
            // guard: a swap of the auth_url/error fields would trip here.
            assert!(
                auth_url.is_none(),
                "a Failed variant must NEVER populate auth_url; variant {re:?}"
            );

            if permanent {
                // AuthRejected / KeyExpired: terminal → NeedsLogin + the reason in `error`.
                assert_eq!(
                    st,
                    State::NeedsLogin,
                    "a permanent Failed maps to NeedsLogin; variant {re:?}"
                );
                assert_eq!(
                    error.as_deref(),
                    Some(expected_reason.as_str()),
                    "a permanent Failed must carry its Display reason verbatim in `error`; variant {re:?}"
                );
            } else {
                // NetworkUnreachable / Timeout / the NeedsLogin-URL form: the engine keeps retrying,
                // so this is ongoing convergence, NOT a terminal error. Surface `Starting` with no
                // error — so the CLI never tells the operator to rotate a key that is actually fine.
                assert_eq!(
                    st,
                    State::Starting,
                    "a transient/retrying Failed maps to Starting (still converging); variant {re:?}"
                );
                assert!(
                    error.is_none(),
                    "a transient Failed must NOT populate `error` (no misleading permanent-failure \
                     guidance); variant {re:?}"
                );
            }
        }
    }
}
