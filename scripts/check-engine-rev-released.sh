#!/bin/sh
# Check whether the engine commit this daemon pins was ever cut as a crates.io release.
#
# Why this exists: `cargo publish` refuses a crate with a `git` dependency, and this daemon pins the
# engine by `git` + `rev`. Cargo does accept a `version` ALONGSIDE `git` + `rev` — the git source
# still wins for our builds, while the published manifest carries the registry version — which is
# the one edit that would unblock publishing without changing what this repository builds. But it is
# only honest if the release named by that version was cut from the pinned commit. Otherwise every
# consumer of the published daemon builds against an engine tree we never gated, silently.
#
# `scripts/check-engine-on-crates-io.sh` answers a different question ("is each engine crate in the
# lockfile published at all?"). This one answers "is the pinned TREE what those releases contain?".
#
# Only one version can possibly match, and this script checks exactly it. A release's version number
# is whatever the manifest said at the commit it was cut from, so a release cut from the pinned
# commit necessarily carries the pinned tree's own version — which is the version `Cargo.lock`
# records for the git dependency. If that release was cut from some other commit, no other release
# can match the pin either.
#
# Usage:  scripts/check-engine-rev-released.sh
# Exit:   0 = the pinned rev is published as a release, so the `version` can be added;
#         1 = it is not (or cannot be trusted), so the pin still blocks publishing;
#         2 = the question could not be answered (unparseable manifest, network, missing tools).
#
# Network: downloads one `.crate` tarball from the crates.io static CDN and reads only the
# `.cargo_vcs_info.json` that `cargo publish` stamps into it. Override the host with CRATES_CDN=.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$root/Cargo.toml"
lock="$root/Cargo.lock"
cdn="${CRATES_CDN:-https://static.crates.io}"
crate=geiserx_tailscale

[ -r "$manifest" ] || { echo "not readable: $manifest" >&2; exit 2; }
[ -r "$lock" ] || { echo "not readable: $lock" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 2; }

# The pinned rev, from the engine facade's dependency line in Cargo.toml.
rev=$(sed -n "s/.*package = \"$crate\".*rev = \"\([0-9a-f]*\)\".*/\1/p" "$manifest" | head -n 1)
[ -n "$rev" ] || { echo "no rev pin for $crate found in $manifest" >&2; exit 2; }

# The version that pin resolves to: what the engine's own manifests say at that commit.
version=$(awk -v c="$crate" '
  /^\[\[package\]\]/ { name = ""; version = "" }
  /^name = /         { name = $3;    gsub(/"/, "", name) }
  /^version = /      { version = $3; gsub(/"/, "", version) }
  /^$/               { if (name == c) { print version; found = 1; exit } }
  END                { if (!found && name == c) print version }
' "$lock")
[ -n "$version" ] || { echo "no $crate entry in $lock" >&2; exit 2; }

echo "pinned rev:      $rev"
echo "resolves to:     $crate $version"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

url="$cdn/crates/$crate/$crate-$version.crate"
code=$(curl -sS --max-time 60 -A 'tailscaled-rs engine release check' \
  -o "$tmp/crate.tar.gz" -w '%{http_code}' "$url" 2>/dev/null) || code=""
case "$code" in
  200) ;;
  404)
    echo
    echo "$crate $version is not published. The pin cannot be traded for a version."
    echo "Run scripts/check-engine-on-crates-io.sh for the full publication picture."
    exit 1
    ;;
  *)
    echo "download of $url failed (HTTP '${code:-none}'); not a verdict" >&2
    exit 2
    ;;
esac

# `cargo publish` stamps the commit it packaged into .cargo_vcs_info.json. A release predating that
# stamp has no such file, which is itself an answer: the release cannot be tied back to a commit.
info=$(tar -xzOf "$tmp/crate.tar.gz" "$crate-$version/.cargo_vcs_info.json" 2>/dev/null || true)
if [ -z "$info" ]; then
  echo
  echo "$crate $version carries no .cargo_vcs_info.json, so it cannot be tied to a commit."
  exit 1
fi

sha1=$(printf '%s' "$info" | tr -d ' \n' | sed -n 's/.*"sha1":"\([0-9a-f]*\)".*/\1/p')
dirty=no
printf '%s' "$info" | tr -d ' \n' | grep -q '"dirty":true' && dirty=yes

echo "released from:   ${sha1:-unknown}${sha1:+ (dirty tree: $dirty)}"
echo

if [ "$sha1" != "$rev" ]; then
  echo "MISMATCH: $crate $version was cut from a different commit than the pin."
  echo "Publishing tailscaled-rs would hand consumers that other tree while our own gate ran"
  echo "against the pinned commit. Adding \`version = \"$version\"\` next to the pin is therefore"
  echo "not safe; moving the pin to a released commit is an engine-version change instead"
  echo "(see docs/ENGINE.md §1)."
  exit 1
fi

if [ "$dirty" = yes ]; then
  echo "INCONCLUSIVE: $version records the pinned commit, but was packaged from a modified tree,"
  echo "so the sha1 is a starting point rather than proof the contents match. Diff before relying"
  echo "on it."
  exit 1
fi

echo "MATCH: $crate $version was cut from the pinned commit."
echo "\`version = \"$version\"\` can be added alongside the git pin to unblock \`cargo publish\`."
exit 0
