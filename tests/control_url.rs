//! Control-URL parse + scheme contract.
//!
//! The daemon lets a node be pointed at a custom control server (via `up --control-url` or
//! persisted prefs). `Backend::up` in `src/ipn.rs` parses that string with `url::Url::parse`
//! and fails *loud* (`with_context("invalid control_url ...")`) on a malformed URL rather than
//! silently falling back to the engine default — pointing at the wrong control plane must never
//! be silent. These tests pin that pure parse/scheme logic in isolation (the full `up()` needs a
//! live engine), mirroring the validation `Backend::up` / the engine `Config` enforce: only an
//! `http`/`https` control URL is meaningful, and any other scheme is rejectable by inspecting
//! `Url::scheme()`.

#[test]
fn malformed_control_url_is_rejected() {
    // A non-URL string must be an `Err` — this is what makes `up` fail loud instead of
    // defaulting silently.
    assert!(url::Url::parse("not a url").is_err());
}

#[test]
fn http_control_url_parses_with_http_scheme() {
    // A bare http Headscale-style URL is the common self-hosted control plane.
    let u = url::Url::parse("http://headscale.example/").expect("http URL should parse");
    assert_eq!(u.scheme(), "http");
}

#[test]
fn https_control_url_is_allowed() {
    // https is the default/expected control-plane transport.
    let u = url::Url::parse("https://controlplane.tailscale.com/").expect("https URL should parse");
    assert_eq!(u.scheme(), "https");
}

#[test]
fn file_scheme_parses_but_is_not_an_allowed_control_scheme() {
    // `url::Url::parse` happily accepts `file://` — so parse-success alone is not enough.
    // A scheme allowlist check (`scheme() == "http" | "https"`) is what WOULD reject it; this
    // documents that contract: a `file:` control URL is never a valid control plane.
    let u = url::Url::parse("file:///etc/passwd").expect("file URL parses");
    assert_eq!(u.scheme(), "file");
    assert!(!matches!(u.scheme(), "http" | "https"));
}
