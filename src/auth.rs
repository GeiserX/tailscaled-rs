//! LocalAPI peer authorization (the `ipnauth` analogue).
//!
//! The control socket is a Unix domain socket. We authorize each connection by the **peer
//! process credentials** (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`getpeereid` on macOS — both
//! surfaced by `tokio::net::UnixStream::peer_cred()`), mirroring Tailscale's model:
//!
//! - **Anyone who can reach the socket may read** (`status`) — read commands are not gated.
//! - **Only root (uid 0) or the same user that owns the daemon may write** (`up` / `down`, which
//!   mutate node lifecycle and prefs).
//!
//! Note that "anyone may read" is bounded in practice by the `0700` state directory the socket
//! lives in (see [`crate::ensure_state_dir_secure`] and the socket-dir hardening in
//! [`crate::server`]): a different user typically cannot even traverse to the socket. The uid gate
//! here is the second layer — it is what still denies *writes* if the socket is ever reachable.
//!
//! This is deliberately the MVP policy. The richer Tailscale "operator user" GID matrix is a later
//! phase; the seam for it is [`AuthPolicy`] (constructed once at startup, threaded into the server)
//! plus the peer's `gid` — see the note on [`AuthPolicy::for_peer`]. Growing to an operator tier
//! means extending [`AuthPolicy`] and adding an `Access` variant, not rewriting the call sites.

/// What a caller is allowed to do over the LocalAPI, decided from its peer credentials.
///
/// Two-variant rather than a `{read, write}` struct because read is currently unconditional — the
/// distinction that matters is only "may this caller mutate?". A future operator tier adds a
/// variant here (e.g. `Operator`) rather than a third bool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// May issue read-only commands (`status`) but not mutate.
    ReadOnly,
    /// Fully authorized: may issue lifecycle/prefs mutations (`up`, `down`) as well as reads.
    ReadWrite,
}

impl Access {
    /// Whether this access level may issue mutating commands.
    pub(crate) fn can_write(self) -> bool {
        matches!(self, Access::ReadWrite)
    }
}

/// The authorization policy, constructed **once** at daemon startup and threaded into the server.
///
/// Today it holds only the daemon's effective uid (the "owner" a peer is compared against). This
/// is the deliberate extension seam: the Phase-2 operator-GID matrix adds fields here (an operator
/// gid, an allowlist, …) and a richer [`Access`] variant, without changing the per-connection call
/// sites in [`crate::server`].
#[derive(Debug, Clone, Copy)]
pub struct AuthPolicy {
    /// The daemon's effective uid — the "owner" that, alongside root, is granted write.
    owner_euid: u32,
}

impl AuthPolicy {
    /// Build the policy from the current process. Call once at startup, not per connection.
    ///
    /// Uses the daemon's **effective** uid. This is correct for the "same user that owns the
    /// daemon" policy as long as the daemon is not run setuid (euid == ruid); a setuid deployment
    /// would make "owner" the setuid target rather than the launching user — revisit `peer_cred`'s
    /// ruid then.
    pub fn from_current_process() -> Self {
        Self {
            owner_euid: current_euid(),
        }
    }

    /// Construct a policy with an explicit owner uid. Test-only today (the unit tests below drive
    /// the uid-policy decision without a real process); `#[cfg(test)]`-gated so it is not dead code
    /// in the production build. A future config-driven construction would lift the gate.
    #[cfg(test)]
    pub(crate) fn with_owner_euid(owner_euid: u32) -> Self {
        Self { owner_euid }
    }

    /// Decide a peer's [`Access`] from its uid under this policy.
    ///
    /// Policy: root (uid 0) or the owner uid → `ReadWrite`; everyone else → `ReadOnly`. Pure, so it
    /// is unit-testable without a socket.
    pub(crate) fn access_for_uid(&self, peer_uid: u32) -> Access {
        if peer_uid == 0 || peer_uid == self.owner_euid {
            Access::ReadWrite
        } else {
            Access::ReadOnly
        }
    }

    /// Resolve the [`Access`] for a connected LocalAPI peer, plus its uid for logging.
    ///
    /// Reads the peer's uid via `stream.peer_cred()` **once** and applies [`Self::access_for_uid`].
    /// Returns `(access, Some(uid))` so the caller can log the exact uid that drove the decision
    /// (no second `peer_cred()` syscall, and the log can never disagree with the authorization). If
    /// the credential lookup fails, we fail **closed** (`ReadOnly`, `None` uid) — an unidentifiable
    /// caller must never get write.
    ///
    /// The peer's `gid` (`cred.gid()`) is intentionally not consulted yet; it is the input the
    /// future operator-GID tier will add here.
    pub fn for_peer(&self, stream: &tokio::net::UnixStream) -> (Access, Option<u32>) {
        match stream.peer_cred() {
            Ok(cred) => {
                let uid = cred.uid();
                (self.access_for_uid(uid), Some(uid))
            }
            Err(e) => {
                tracing::warn!(error = %e, "auth: peer_cred lookup failed; defaulting to read-only");
                (Access::ReadOnly, None)
            }
        }
    }
}

/// The effective uid of the current process (the daemon's owner), used for the same-user check.
///
/// Private — the rest of the daemon goes through [`AuthPolicy`] and never calls libc directly, so
/// the single `unsafe` site lives here.
fn current_euid() -> u32 {
    // SAFETY: geteuid() always succeeds, takes no arguments, and has no preconditions.
    unsafe { libc::geteuid() }
}

/// Whether a given LocalAPI command requires write permission.
///
/// Centralized so the server has one authority on which verbs mutate. Read commands
/// (`status`/`watch`, plus the read-only diagnostics `ip`/`whois`/`ping`) return false;
/// lifecycle/prefs commands (`up`, `set`, `down`) return true. The match is exhaustive over
/// [`crate::localapi::Request`], so a new command forces an explicit authorization decision at
/// compile time.
pub(crate) fn requires_write(request: &crate::localapi::Request) -> bool {
    use crate::localapi::Request;
    match request {
        // Reads: never gated. `ip`/`whois`/`ping` are diagnostics that mutate no state, so they are
        // classified exactly like `status`/`watch` (ping sends overlay traffic but changes nothing).
        // `FileList` only enumerates the receive directory — a read, like `status`.
        Request::Status
        | Request::Watch
        | Request::Ip
        | Request::Whois { .. }
        | Request::Ping { .. }
        | Request::Version
        | Request::GetPrefs
        | Request::ProfileList
        | Request::LockStatus
        | Request::DnsStatus
        | Request::DnsQuery { .. }
        | Request::Netcheck
        // `syspolicy list`/`reload` (Go `tailscale syspolicy`) only read the effective MDM/system
        // policy. Go gates BOTH on `PermitRead` — its LocalAPI `policy/` handler checks only
        // `PermitRead`, even for the POST/reload, because "reload" re-reads the external policy
        // sources and mutates NO node state. So both are reads, like `status`/`dns status`.
        | Request::SyspolicyList
        | Request::SyspolicyReload
        | Request::BugReport { .. }
        | Request::GetServeConfig
        | Request::FileList
        // `file cp --targets` only enumerates peers we could send to — a read, like `status`/`list`.
        | Request::FileTargets => false,
        // Writes: lifecycle/prefs mutations plus the Taildrop transfers. `FileCp` initiates a send
        // and `FileGet` consumes/deletes an inbound file, so both mutate and gate like `up`/`down`.
        Request::Up { .. }
        | Request::Set { .. }
        | Request::Down
        | Request::Logout
        | Request::SwitchProfile { .. }
        | Request::DeleteProfile { .. }
        | Request::Nc { .. }
        | Request::SetServeConfig { .. }
        | Request::FileCp { .. }
        | Request::FileGet { .. }
        // `file get <dir>` drains the inbox: writes files as the daemon's uid AND deletes the
        // received files from the receive store — a write, gated like `up`/`down`/`file get`.
        | Request::FileGetDir { .. }
        // `IdToken` MINTS a bearer credential: control signs an OIDC JWT whose subject is this node's
        // identity, which a relying party (e.g. cloud workload-identity federation) accepts as proof
        // this machine is who it claims. That is materially more sensitive than a status read — Go's
        // LocalAPI gates `serveIDToken` on `PermitWrite` (not `PermitRead`, unlike `whois`), so a
        // local user who is not root / not the daemon's uid must not be able to mint a node credential.
        | Request::IdToken { .. }
        // `Metrics` scrapes this node's Prometheus counters, which can carry sensitive operational
        // data. Go gates `serveMetrics` on `PermitWrite` — explicitly "out of paranoia that the
        // metrics might contain something sensitive" — NOT `PermitRead`, so a socket-reachable local
        // user who is not root / not the daemon's uid must not be able to scrape them.
        | Request::Metrics
        // `DebugCapture` installs a dataplane capture hook and writes a pcap as the daemon's uid —
        // it taps all plaintext traffic, so it gates like `up`/`down`, never a read.
        | Request::DebugCapture { .. }
        // `Cert` provisions a TLS cert and returns its PRIVATE KEY — a sensitive credential, and an
        // ACME control round-trip (not a passive read). Go gates `serveCert` on write; a
        // socket-reachable non-owner must not be able to mint a cert/key. Gates like `up`/`IdToken`.
        | Request::Cert { .. }
        // `LockSign`/`LockDisable` MUTATE tailnet-wide trust (co-sign a node into the lock / turn the
        // lock off for the whole tailnet). Go gates the NetworkLock mutation LocalAPI on write; these
        // are among the most sensitive writes there are, so a socket-reachable non-owner must never
        // reach them. Gate like `up`/`down`.
        | Request::LockInit { .. }
        | Request::LockSign { .. }
        | Request::LockDisable { .. } => true,
    }
}

/// Returned by [`authorize`] when a request is refused: the caller lacked the required access.
///
/// A distinct (zero-field) type rather than `()` so the `Result` error carries meaning and so the
/// signature reads as a real authorization verdict (and satisfies `clippy::result_unit_err`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied;

/// Authorize a request under a caller's [`Access`]: `Ok(())` if permitted, `Err(Denied)` otherwise.
///
/// Pure and side-effect-free so the security-critical deny decision is directly unit-testable
/// without a socket or a second uid. The server maps `Err(Denied)` to a `permission denied`
/// [`crate::localapi::Response::Error`].
pub fn authorize(request: &crate::localapi::Request, access: Access) -> Result<(), Denied> {
    if requires_write(request) && !access.can_write() {
        Err(Denied)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::localapi::Request;

    fn up() -> Request {
        Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            accept_routes: None,
            accept_dns: None,
            shields_up: None,
            ssh: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
        }
    }

    fn set() -> Request {
        Request::Set {
            hostname: None,
            accept_routes: None,
            accept_dns: None,
            shields_up: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            ssh: None,
        }
    }

    fn file_cp() -> Request {
        Request::FileCp {
            path: "/tmp/send.bin".into(),
            peer: "100.64.0.2".into(),
            name: None,
        }
    }

    fn file_get() -> Request {
        Request::FileGet {
            name: "inbound.bin".into(),
            dest: "/tmp/inbound.bin".into(),
            delete_after: true,
        }
    }

    #[test]
    fn root_gets_write() {
        let p = AuthPolicy::with_owner_euid(1000);
        assert_eq!(p.access_for_uid(0), Access::ReadWrite);
    }

    #[test]
    fn owner_uid_gets_write() {
        let p = AuthPolicy::with_owner_euid(1000);
        assert_eq!(p.access_for_uid(1000), Access::ReadWrite);
    }

    #[test]
    fn other_uid_is_read_only() {
        let p = AuthPolicy::with_owner_euid(1000);
        assert_eq!(p.access_for_uid(1001), Access::ReadOnly);
        assert!(!p.access_for_uid(1001).can_write());
    }

    #[test]
    fn requires_write_classifies_commands() {
        assert!(!requires_write(&Request::Status));
        assert!(requires_write(&Request::Down));
        assert!(
            requires_write(&Request::Logout),
            "logout deregisters + wipes the key — a write, gated like down"
        );
        assert!(requires_write(&up()));
        assert!(requires_write(&set()));
        assert!(
            requires_write(&Request::DebugCapture {
                path: "/tmp/x.pcap".into(),
                seconds: Some(5)
            }),
            "debug capture installs a dataplane tap + writes a file — a write"
        );
        assert!(
            requires_write(&Request::IdToken {
                audience: "https://example.com".into()
            }),
            "id-token mints a node-identity bearer credential — a write (Go gates it PermitWrite, \
             unlike the PermitRead whois), so a non-root/non-owner local user can't mint one"
        );
        assert!(
            requires_write(&Request::Metrics),
            "metrics may expose sensitive operational data — a write (Go gates serveMetrics on \
             PermitWrite 'out of paranoia', not PermitRead), so a non-root/non-owner can't scrape it"
        );
        assert!(!requires_write(&Request::GetServeConfig));
        assert!(
            !requires_write(&Request::DnsStatus),
            "dns status only reads the control-pushed MagicDNS config — a read, gated like status"
        );
        assert!(
            !requires_write(&Request::Netcheck),
            "netcheck only reads the net-report (DERP-region latency) — a read, gated like status"
        );
    }

    #[test]
    fn taildrop_transfers_require_write() {
        // `file cp` initiates a send and `file get` consumes/deletes an inbound file — both mutate,
        // so they classify as writes like `up`/`down`. `file get` with no args (`FileList`) only
        // enumerates the receive dir, so it stays a read like `status`.
        assert!(requires_write(&file_cp()));
        assert!(requires_write(&file_get()));
        assert!(!requires_write(&Request::FileList));
        // `file cp --targets` only enumerates eligible peers — a read, like `list`/`status`.
        assert!(!requires_write(&Request::FileTargets));
        assert_eq!(authorize(&Request::FileTargets, Access::ReadOnly), Ok(()));
    }

    #[test]
    fn read_only_diagnostics_do_not_require_write() {
        // `ip`/`whois`/`ping`/`version` mutate no state — they must classify as reads, like
        // `status`/`watch`.
        assert!(
            !requires_write(&Request::Watch),
            "watch only streams status snapshots — a read, gated exactly like status"
        );
        assert!(!requires_write(&Request::Ip));
        assert!(!requires_write(&Request::Whois {
            ip: "100.64.0.1".into()
        }));
        assert!(!requires_write(&Request::Ping {
            ip: "100.64.0.1".into(),
            timeout_ms: None,
        }));
        assert!(
            !requires_write(&Request::Version),
            "version only reports a constant — a read, gated like status"
        );
        assert!(
            !requires_write(&Request::GetPrefs),
            "get only reads the persisted prefs — a read, gated like status"
        );
        assert!(
            !requires_write(&Request::ProfileList),
            "switch --list only reads the profile set — a read"
        );
        assert!(
            !requires_write(&Request::LockStatus),
            "lock status only reads TKA status — a read"
        );
        assert!(
            !requires_write(&Request::BugReport { note: None }),
            "bugreport only reads daemon state into a marker — a read"
        );
        assert!(
            !requires_write(&Request::GetServeConfig),
            "serve status only reads the serve config — a read"
        );
        assert!(
            requires_write(&Request::SetServeConfig {
                config: Default::default()
            }),
            "setting the serve config persists state + re-arms listeners — a write"
        );
        assert!(
            requires_write(&Request::SwitchProfile {
                target: "work".into()
            }),
            "switching profiles changes lifecycle + persisted state — a write"
        );
        assert!(
            requires_write(&Request::DeleteProfile {
                target: "work".into()
            }),
            "removing a profile deletes persisted state — a write"
        );
        assert!(
            requires_write(&Request::Nc {
                host: "peer".into(),
                port: 22
            }),
            "nc opens an outbound connection — a write, gated like up/down"
        );
    }

    #[test]
    fn read_only_caller_may_run_diagnostics() {
        assert_eq!(authorize(&Request::Ip, Access::ReadOnly), Ok(()));
        assert_eq!(
            authorize(
                &Request::Whois {
                    ip: "100.64.0.1".into()
                },
                Access::ReadOnly
            ),
            Ok(())
        );
        assert_eq!(
            authorize(
                &Request::Ping {
                    ip: "100.64.0.1".into(),
                    timeout_ms: Some(5000),
                },
                Access::ReadOnly
            ),
            Ok(())
        );
    }

    // The security-critical deny path, tested directly (no socket, no second uid needed). These
    // tests fail if the gate is deleted or inverted — closing the mutation-survives gap the review
    // flagged.
    #[test]
    fn read_only_caller_is_denied_writes() {
        assert_eq!(authorize(&Request::Down, Access::ReadOnly), Err(Denied));
        assert_eq!(authorize(&up(), Access::ReadOnly), Err(Denied));
        assert_eq!(authorize(&set(), Access::ReadOnly), Err(Denied));
        // Taildrop transfers are writes: a read-only caller must be denied both.
        assert_eq!(authorize(&file_cp(), Access::ReadOnly), Err(Denied));
        assert_eq!(authorize(&file_get(), Access::ReadOnly), Err(Denied));
    }

    #[test]
    fn read_only_caller_may_still_read() {
        assert_eq!(authorize(&Request::Status, Access::ReadOnly), Ok(()));
        // Listing waiting Taildrop files is a read — allowed without write.
        assert_eq!(authorize(&Request::FileList, Access::ReadOnly), Ok(()));
    }

    #[test]
    fn read_write_caller_may_do_everything() {
        assert_eq!(authorize(&Request::Status, Access::ReadWrite), Ok(()));
        assert_eq!(authorize(&Request::Down, Access::ReadWrite), Ok(()));
        assert_eq!(authorize(&up(), Access::ReadWrite), Ok(()));
        assert_eq!(authorize(&set(), Access::ReadWrite), Ok(()));
        assert_eq!(authorize(&file_cp(), Access::ReadWrite), Ok(()));
        assert_eq!(authorize(&Request::FileList, Access::ReadWrite), Ok(()));
        assert_eq!(authorize(&file_get(), Access::ReadWrite), Ok(()));
    }
}
