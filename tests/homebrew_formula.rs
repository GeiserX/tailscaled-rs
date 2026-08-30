//! The Homebrew formula in `packaging/homebrew/` must keep describing the thing this tree builds.
//!
//! A formula is a copy of facts that live elsewhere — the binaries the crate installs, the cargo
//! features a distributed build has to carry, the engine opt-in the daemon refuses to start without,
//! the licence. Nothing in a `brew install` re-derives any of them: the formula is executed on a
//! stranger's machine, long after the commit that invalidated it, and the failure it produces there
//! is a build error or (worse) a daemon that silently can't do half of what it advertises. So each of
//! those facts is checked here against the file that owns it, with [`include_str!`] — the same trick
//! `src/ipn/install.rs` uses to keep the packaging units honest, and
//! `tests/engine_doc_publish_verdicts.rs` uses to keep a doc and its script in step.
//!
//! One asymmetry is deliberate. A formula pins its source tarball by SHA-256, and that digest cannot
//! exist before the tag does, so the formula here necessarily LAGS `Cargo.toml` between a release
//! being cut and `scripts/homebrew-formula.sh` being run against it. The lag is allowed; the reverse
//! — a formula claiming a version this tree has not released — is not.

const FORMULA: &str = include_str!("../packaging/homebrew/tailscaled-rs.rb");
const CARGO_TOML: &str = include_str!("../Cargo.toml");
const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const TAILNETD_MAIN: &str = include_str!("../src/bin/tailnetd.rs");
const REFRESH_SCRIPT: &str = include_str!("../scripts/homebrew-formula.sh");

/// The value of a `key = "value"` line in `Cargo.toml`'s `[package]` block (the first block in the
/// file), e.g. `version` or `license`.
fn cargo_package_field(key: &str) -> String {
    let prefix = format!("{key} = \"");
    CARGO_TOML
        .lines()
        .find_map(|l| l.strip_prefix(&prefix)?.strip_suffix('"'))
        .unwrap_or_else(|| panic!("Cargo.toml should still have a `{key} = \"…\"` line"))
        .to_string()
}

/// Every binary the crate installs, from its `[[bin]] name = "…"` entries. `cargo install` (what the
/// formula runs) installs all of them, so all of them land on a `brew install` user's PATH.
fn cargo_bin_names() -> Vec<String> {
    let mut names = Vec::new();
    let mut in_bin = false;
    for line in CARGO_TOML.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_bin = trimmed == "[[bin]]";
            continue;
        }
        if in_bin
            && let Some(name) = trimmed
                .strip_prefix("name = \"")
                .and_then(|r| r.strip_suffix('"'))
        {
            names.push(name.to_string());
        }
    }
    assert!(
        !names.is_empty(),
        "Cargo.toml should still declare [[bin]] targets"
    );
    names
}

/// A `major.minor.patch` triple, for comparing the formula's tag against the crate's version.
fn semver(s: &str) -> (u64, u64, u64) {
    let s = s.strip_prefix('v').unwrap_or(s);
    let mut it = s.split('.');
    let mut next = || {
        it.next()
            .unwrap_or_else(|| panic!("{s} is not a major.minor.patch version"))
            .parse::<u64>()
            .unwrap_or_else(|e| panic!("{s} is not a major.minor.patch version: {e}"))
    };
    (next(), next(), next())
}

/// The one `url "…"` line the formula builds from — the source tarball for a released tag, and the
/// line `scripts/homebrew-formula.sh` rewrites.
fn formula_source_url() -> &'static str {
    let mut urls = FORMULA.lines().filter_map(|l| {
        l.trim()
            .strip_prefix("url \"")
            .and_then(|r| r.split('"').next())
    });
    let url = urls
        .next()
        .expect("the formula should carry a source `url \"…\"`");
    assert_eq!(
        urls.next(),
        None,
        "exactly one `url` line, or the refresh script rewrites the wrong one"
    );
    url
}

/// The value of a bare `word "…"` stanza in the formula (`sha256`, `license`, `homepage`, …).
fn formula_stanza(name: &str) -> &'static str {
    let prefix = format!("{name} \"");
    FORMULA
        .lines()
        .find_map(|l| l.trim().strip_prefix(&prefix)?.split('"').next())
        .unwrap_or_else(|| panic!("the formula should carry a `{name} \"…\"` stanza"))
}

/// The comma-separated cargo feature list following a `--features` argument, wherever it appears —
/// in the formula's `cargo install` line or in the release workflow's `cross build` line. Returned
/// sorted so two lists can be compared as sets.
fn features_after_flag(haystack: &str) -> Vec<String> {
    let after = haystack
        .split("--features")
        .nth(1)
        .expect("expected a `--features` argument");
    // The formula quotes its arguments (`"--features", "tun,ssh,acme"`), the workflow does not
    // (`--features tun,ssh,acme`); take the first token of feature-name characters either way.
    let list: String = after
        .chars()
        .skip_while(|c| !c.is_ascii_alphanumeric())
        .take_while(|c| c.is_ascii_alphanumeric() || *c == ',' || *c == '-' || *c == '_')
        .collect();
    let mut feats: Vec<String> = list.split(',').map(|f| f.to_string()).collect();
    feats.sort();
    feats
}

/// A `const NAME: &str = "value";` line in `src/bin/tailnetd.rs` — the daemon's own copy of the
/// engine opt-in the formula has to reproduce.
fn tailnetd_const(name: &str) -> &'static str {
    let prefix = format!("const {name}: &str = \"");
    TAILNETD_MAIN
        .lines()
        .find_map(|l| l.strip_prefix(&prefix)?.split('"').next())
        .unwrap_or_else(|| panic!("src/bin/tailnetd.rs should still define `{name}`"))
}

#[test]
fn formula_builds_a_released_tag_of_this_repository() {
    let url = formula_source_url();
    let repo = cargo_package_field("repository");
    assert!(
        url.starts_with(&format!("{repo}/archive/refs/tags/v")) && url.ends_with(".tar.gz"),
        "the formula must build a source tag of {repo}, got {url}"
    );
    assert_eq!(
        formula_stanza("homepage"),
        repo,
        "homepage must be this repository"
    );

    // The tag it pins, versus the version this tree is at. The formula may lag (its SHA-256 only
    // exists once the tag is published — run `scripts/homebrew-formula.sh --write` after a release);
    // it may never lead, which would be a formula pointing at a tarball nobody can download.
    let tag = url
        .rsplit('/')
        .next()
        .and_then(|f| f.strip_suffix(".tar.gz"))
        .expect("the source url should end in `<tag>.tar.gz`");
    let crate_version = cargo_package_field("version");
    assert!(
        semver(tag) <= semver(&crate_version),
        "the formula claims {tag}, which this tree ({crate_version}) has not released — a \
         `brew install` would 404 on the source tarball"
    );

    // The digest is a real SHA-256 of that tarball's bytes, not a placeholder.
    let sha = formula_stanza("sha256");
    assert!(
        sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
        "sha256 must be a 64-char hex digest, got {sha:?}"
    );
}

#[test]
fn formula_installs_and_exercises_every_binary_the_crate_builds() {
    // `cargo install` puts every [[bin]] on the user's PATH, so a binary that stops existing (or a
    // new one) has to be reflected in what the formula's `test do` block proves works.
    let test_block = FORMULA
        .split_once("test do")
        .expect("the formula should have a `test do` block")
        .1;
    for bin in cargo_bin_names() {
        assert!(
            test_block.contains(&format!("bin}}/{bin}")),
            "the formula's test block must exercise the `{bin}` binary this crate installs"
        );
    }
}

#[test]
fn formula_ships_the_same_features_the_release_binaries_do() {
    // A distributed build that quietly drops `acme` (or `tun`, or `ssh`) is not a lean build: it is
    // one where `tnet cert`, `serve --https`/`funnel`, TUN mode or the SSH server fail closed for a
    // reason the operator never chose. Whatever the release workflow ships, the formula ships.
    let install_line = FORMULA
        .lines()
        .find(|l| l.contains("cargo") && l.contains("install"))
        .expect("the formula should install with `cargo install`");
    let workflow_line = RELEASE_WORKFLOW
        .lines()
        .find(|l| l.contains("cross build"))
        .expect("the release workflow should still build with `cross build`");
    assert_eq!(
        features_after_flag(install_line),
        features_after_flag(workflow_line),
        "the formula's cargo features must match the released binaries'"
    );
}

#[test]
fn formula_sets_the_exact_engine_opt_in_the_daemon_demands() {
    // The daemon refuses to start unless this variable holds this value — a typo here is a service
    // that never comes up, discovered only on the user's machine.
    let var = tailnetd_const("EXPERIMENT_VAR");
    let value = tailnetd_const("REQUIRED_EXPERIMENT_VALUE");
    let assignment = format!("{var}: \"{value}\"");
    assert!(
        FORMULA.contains(&assignment),
        "the formula's service block must set `{assignment}` so `brew services` can start the daemon"
    );
    assert!(
        FORMULA.contains(&format!("ENV[\"{var}\"] = \"{value}\"")),
        "the formula must set {var} for the build too, as the release workflow does"
    );
    // And the caveats have to tell someone running it by hand the same thing.
    assert!(
        FORMULA.contains(&format!("{var}={value}")),
        "the caveats must show the `{var}={value}` a foreground run needs"
    );
}

#[test]
fn formula_licence_matches_the_crate() {
    assert_eq!(formula_stanza("license"), cargo_package_field("license"));
}

#[test]
fn refresh_script_still_matches_the_lines_it_rewrites() {
    // `scripts/homebrew-formula.sh` keys on two exact line shapes; if the formula is reformatted so
    // they no longer match, the script silently emits an unchanged formula and the next release ships
    // a stale URL with a valid-looking digest for the previous tarball.
    let url_lines = FORMULA
        .lines()
        .filter(|l| l.starts_with("  url \"https://github.com/"))
        .count();
    let sha_lines = FORMULA
        .lines()
        .filter(|l| l.starts_with("  sha256 \""))
        .count();
    assert_eq!(
        url_lines, 1,
        "the script rewrites exactly one `  url \"https://github.com/…` line"
    );
    assert_eq!(
        sha_lines, 1,
        "the script rewrites exactly one `  sha256 \"…` line"
    );
    assert!(
        REFRESH_SCRIPT.contains("packaging/homebrew/tailscaled-rs.rb"),
        "the refresh script must still point at this formula"
    );
}
