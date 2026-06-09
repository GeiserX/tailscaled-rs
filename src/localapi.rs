//! LocalAPI wire types — the request/response DTOs spoken over the control socket.
//!
//! These are this crate's *own* serde types, deliberately decoupled from the engine's internal
//! types so the IPC surface is stable independent of engine churn. The transport today is
//! newline-delimited JSON over a Unix domain socket (see [`crate::server`]). Peer-credential
//! authorization is implemented (`SO_PEERCRED`, see [`crate::auth`]), matching Tailscale's
//! `LocalAPI` policy: reads are allowed for anyone, writes only for root or the same UID as the
//! daemon.

use serde::{Deserialize, Serialize};

/// A command sent by the CLI to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Report current state and netmap.
    Status,
    /// Stream status: the daemon replies with an initial [`StatusReport`] line and then one more
    /// every time the connection state transitions, until the client disconnects. This is a
    /// long-lived connection (the analogue of `tailscale status --watch`), not a one-shot. Read-only
    /// — gated identically to [`Status`](Request::Status).
    Watch,
    /// Bring the node up (`WantRunning = true`), optionally (re)setting login/config fields.
    Up {
        /// Pre-auth key for non-interactive registration.
        authkey: Option<String>,
        /// Override the control server URL.
        control_url: Option<String>,
        /// Override the requested hostname.
        hostname: Option<String>,
        /// Use a real kernel TUN interface (`TransportMode::Tun`) instead of the userspace netstack.
        /// `None` leaves the persisted pref unchanged; `Some(true/false)` sets it. Requires a daemon
        /// built with the `tun` feature + root; the daemon fails loudly otherwise. `#[serde(default)]`
        /// keeps the wire backward-compatible with clients that omit it.
        #[serde(default)]
        tun: Option<bool>,
        /// Desired TUN interface name (only meaningful with `tun: Some(true)`).
        #[serde(default)]
        tun_name: Option<String>,
        /// TUN interface MTU (only meaningful with `tun: Some(true)`).
        #[serde(default)]
        tun_mtu: Option<u16>,
    },
    /// Bring the node down (`WantRunning = false`) without logging out.
    Down,
}

/// The daemon's reply to a [`Request`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    /// A status snapshot.
    Status(StatusReport),
    /// A command succeeded.
    Ok {
        /// Human-readable detail.
        message: String,
    },
    /// A command failed.
    Error {
        /// Human-readable detail.
        message: String,
    },
}

/// A snapshot of daemon + netmap state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    /// The IPN state name. One of the seven [`crate::ipn::State`] variants (the authoritative
    /// list is [`crate::ipn::State::as_str`]): `NoState`, `NeedsLogin`, `NeedsMachineAuth`,
    /// `InUseOtherUser`, `Starting`, `Running`, `Stopped`. (`NeedsMachineAuth`/`InUseOtherUser`
    /// exist for Go-`ipn.State` parity and are not currently reachable; see `ipn::State`.)
    pub state: String,
    /// The persisted `WantRunning` intent.
    pub want_running: bool,
    /// This node's tailnet IPv4, once a netmap has been received.
    pub self_ipv4: Option<String>,
    /// This node's display name, once known.
    pub self_name: Option<String>,
    /// The interactive-login authorization URL, set only when `state == "NeedsLogin"` because the
    /// engine reported `DeviceState::NeedsLogin(url)` — i.e. an `up` with no usable auth key needs a
    /// human to authorize the node in a browser. `None` in every other state. The CLI prints this so
    /// `tnet up` (no `--authkey`) yields a clickable login link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    /// A terminal registration-failure reason, set only when the engine reported
    /// `DeviceState::Failed(RegistrationError)` — a **permanent** failure (e.g. a bad/expired/unknown
    /// auth key) that the engine will *not* retry. `None` in every other state.
    ///
    /// This is the Rust analogue of Go's `ipnstate.Status.ErrMessage`: rather than fabricate an
    /// eighth `ipn.State`, terminal failure is carried as a separate field so the reported `state`
    /// stays one of the seven canonical `ipn.State` names. It is deliberately distinct from
    /// [`auth_url`](StatusReport::auth_url): an `auth_url` means interactive login is *pending and
    /// will succeed once the user authorizes* (transient), whereas `error` means registration
    /// *hard-failed and re-running with the same key will loop forever* (terminal — the operator must
    /// re-authenticate). The CLI prints this and, on an interactive `up`, bails early instead of
    /// dwelling the full auth-URL poll window implying that login will help.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Known peers in the netmap.
    pub peers: Vec<PeerReport>,
}

/// A single peer entry in a [`StatusReport`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReport {
    /// Display name (FQDN if known, else bare hostname).
    pub name: String,
    /// Tailnet IPv4 address.
    pub ipv4: String,
    /// Whether the peer advertises a default route (is an exit-node candidate).
    pub is_exit_node: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // The CLI and daemon are separate processes that agree only on this JSON wire format, so the
    // tagged representations are a contract: assert the exact `cmd`/`kind` discriminants.

    #[test]
    fn request_status_wire_format() {
        let json = serde_json::to_string(&Request::Status).unwrap();
        assert_eq!(json, r#"{"cmd":"status"}"#);
    }

    #[test]
    fn request_up_round_trips_with_fields() {
        let req = Request::Up {
            authkey: Some("tskey-auth-xxx".to_string()),
            control_url: None,
            hostname: Some("node-a".to_string()),
            tun: Some(true),
            tun_name: Some("tailscale0".to_string()),
            tun_mtu: Some(1280),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&json).unwrap();
        match back {
            Request::Up {
                authkey,
                hostname,
                control_url,
                tun,
                tun_name,
                tun_mtu,
            } => {
                assert_eq!(authkey.as_deref(), Some("tskey-auth-xxx"));
                assert_eq!(hostname.as_deref(), Some("node-a"));
                assert!(control_url.is_none());
                assert_eq!(tun, Some(true));
                assert_eq!(tun_name.as_deref(), Some("tailscale0"));
                assert_eq!(tun_mtu, Some(1280));
            }
            other => panic!("expected Up, got {other:?}"),
        }
    }

    #[test]
    fn request_down_wire_format() {
        assert_eq!(
            serde_json::to_string(&Request::Down).unwrap(),
            r#"{"cmd":"down"}"#
        );
    }

    #[test]
    fn request_watch_wire_format() {
        // `watch` is the streaming-status command; assert its discriminant so daemon + CLI agree.
        assert_eq!(
            serde_json::to_string(&Request::Watch).unwrap(),
            r#"{"cmd":"watch"}"#
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"watch"}"#).unwrap(),
            Request::Watch
        ));
    }

    #[test]
    fn response_error_is_tagged() {
        let resp = Response::Error {
            message: "boom".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"kind":"error","message":"boom"}"#);
    }

    #[test]
    fn status_report_round_trips() {
        let report = Response::Status(StatusReport {
            state: "Running".to_string(),
            want_running: true,
            self_ipv4: Some("100.70.22.12".to_string()),
            self_name: Some("node-a".to_string()),
            auth_url: None,
            error: None,
            peers: vec![PeerReport {
                name: "peer-b".to_string(),
                ipv4: "100.64.0.2".to_string(),
                is_exit_node: true,
            }],
        });
        let json = serde_json::to_string(&report).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        match back {
            Response::Status(s) => {
                assert_eq!(s.state, "Running");
                assert_eq!(s.peers.len(), 1);
                assert!(s.peers[0].is_exit_node);
                assert!(s.auth_url.is_none());
            }
            other => panic!("expected Status, got {other:?}"),
        }
        // `auth_url` is `skip_serializing_if = None`, so a no-login status carries no `auth_url` key.
        assert!(
            !json.contains("auth_url"),
            "auth_url must be omitted when None"
        );
        // `error` is likewise `skip_serializing_if = None`: a non-failing status carries no `error` key.
        assert!(
            !json.contains("\"error\""),
            "error must be omitted when None"
        );
    }

    #[test]
    fn status_report_auth_url_round_trips() {
        // Interactive login: when the daemon surfaces a NeedsLogin auth URL it must serialize and
        // survive the round-trip so the CLI can print it.
        let report = StatusReport {
            state: "NeedsLogin".to_string(),
            want_running: true,
            self_ipv4: None,
            self_name: None,
            auth_url: Some("https://login.example.com/a/abc123".to_string()),
            error: None,
            peers: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("auth_url"));
        // Interactive login is transient, not a terminal failure: the URL is present, `error` absent.
        assert!(
            !json.contains("\"error\""),
            "error must be absent when only auth_url is set"
        );
        let back: StatusReport = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.auth_url.as_deref(),
            Some("https://login.example.com/a/abc123")
        );
        assert_eq!(back.state, "NeedsLogin");
        assert!(back.error.is_none());
    }

    #[test]
    fn status_report_error_round_trips() {
        // Terminal failure: a bad/expired/unknown auth key makes the engine report
        // `DeviceState::Failed`, which surfaces as `state == "NeedsLogin"` with a populated `error`
        // and no `auth_url`. The reason string must serialize and survive the round-trip so the CLI
        // can print it and bail instead of dwelling the auth-URL poll window.
        let report = StatusReport {
            state: "NeedsLogin".to_string(),
            want_running: true,
            self_ipv4: None,
            self_name: None,
            auth_url: None,
            error: Some("authentication rejected by control: invalid key".to_string()),
            peers: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"error\""));
        assert!(json.contains("authentication rejected by control: invalid key"));
        let back: StatusReport = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.error.as_deref(),
            Some("authentication rejected by control: invalid key")
        );
        assert_eq!(back.state, "NeedsLogin");
        assert!(back.auth_url.is_none());
    }

    #[test]
    fn status_report_error_omitted_when_none() {
        // `error` is `skip_serializing_if = None`: a status that is not a terminal failure must not
        // carry an `error` key on the wire.
        let report = StatusReport {
            state: "Running".to_string(),
            want_running: true,
            self_ipv4: Some("100.70.22.12".to_string()),
            self_name: Some("node-a".to_string()),
            auth_url: None,
            error: None,
            peers: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("\"error\""),
            "error must be omitted when None"
        );
    }

    #[test]
    fn status_report_error_and_auth_url_are_independent() {
        // The wire format keeps the transient (interactive login pending) and terminal (registration
        // hard-failed) cases distinct: each report carries exactly one of the two fields, never both.

        // Interactive login pending: `auth_url` present, `error` absent.
        let pending = StatusReport {
            state: "NeedsLogin".to_string(),
            want_running: true,
            self_ipv4: None,
            self_name: None,
            auth_url: Some("https://login.example.com/a/abc123".to_string()),
            error: None,
            peers: vec![],
        };
        let pending_json = serde_json::to_string(&pending).unwrap();
        assert!(pending_json.contains("auth_url"));
        assert!(!pending_json.contains("\"error\""));
        let pending_back: StatusReport = serde_json::from_str(&pending_json).unwrap();
        assert_eq!(
            pending_back.auth_url.as_deref(),
            Some("https://login.example.com/a/abc123")
        );
        assert!(pending_back.error.is_none());

        // Terminal failure: `error` present, `auth_url` absent.
        let failed = StatusReport {
            state: "NeedsLogin".to_string(),
            want_running: true,
            self_ipv4: None,
            self_name: None,
            auth_url: None,
            error: Some("authentication rejected by control: invalid key".to_string()),
            peers: vec![],
        };
        let failed_json = serde_json::to_string(&failed).unwrap();
        assert!(failed_json.contains("\"error\""));
        assert!(!failed_json.contains("auth_url"));
        let failed_back: StatusReport = serde_json::from_str(&failed_json).unwrap();
        assert_eq!(
            failed_back.error.as_deref(),
            Some("authentication rejected by control: invalid key")
        );
        assert!(failed_back.auth_url.is_none());
    }

    #[test]
    fn request_up_all_none_round_trips() {
        // The CLI sends `up` with every override absent (use the daemon's persisted prefs /
        // engine defaults). The all-`None` shape must survive the JSON wire intact.
        let req = Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&json).unwrap();
        match back {
            Request::Up {
                authkey,
                control_url,
                hostname,
                tun,
                tun_name,
                tun_mtu,
            } => {
                assert!(authkey.is_none());
                assert!(control_url.is_none());
                assert!(hostname.is_none());
                assert!(tun.is_none());
                assert!(tun_name.is_none());
                assert!(tun_mtu.is_none());
            }
            other => panic!("expected Up, got {other:?}"),
        }
    }

    #[test]
    fn secret_string_debug_is_redacted() {
        // Auth keys flow through the daemon as `secrecy::SecretString` precisely so they never
        // land in a `Debug` rendering or log line. Pin that redaction property here.
        // NB: the sentinel deliberately avoids a real provider prefix (e.g. `tskey-auth-`) so
        // secret scanners don't flag this redaction test as a leaked credential (it isn't one).
        let sentinel = "SENSITIVE-VALUE-SHOULD-NOT-APPEAR";
        let s = secrecy::SecretString::from(sentinel.to_string());
        assert!(!format!("{s:?}").contains(sentinel));
    }
}
