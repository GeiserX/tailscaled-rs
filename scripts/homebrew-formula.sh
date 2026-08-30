#!/bin/sh
# Point `packaging/homebrew/tailscaled-rs.rb` at a released tag: rewrite its `url` + `sha256` pair
# for the version you name, with the checksum computed from the tarball GitHub actually serves.
#
# Why this exists: a Homebrew formula pins its source by SHA-256, and that digest only exists once
# the tag does — so the formula in this tree necessarily lags the version in `Cargo.toml` until
# someone refreshes it AFTER the release is cut (`tests/homebrew_formula.rs` allows the lag and
# refuses the reverse, a formula claiming a version this tree has not released). A hand-typed digest
# is the one thing in that step nobody can review, so it is computed here instead.
#
# Usage:  scripts/homebrew-formula.sh [--write] [vX.Y.Z]
#         --write    edit the formula in place (default: print the rewritten formula to stdout)
#         vX.Y.Z     the release tag (default: `v` + the version in Cargo.toml)
# Exit:   0 = formula rewritten; 2 = the question could not be answered (no tag published, the
#         download failed, no SHA-256 tool, or the formula no longer has the lines to rewrite).
#
# Network: downloads the GitHub source tarball for the tag — the same URL Homebrew fetches, so the
# digest is of the bytes a `brew install` will verify.
#
# After running it with --write, copy the formula into the tap (see packaging/homebrew/README.md).

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
formula="$root/packaging/homebrew/tailscaled-rs.rb"
write=0

for arg in "$@"; do
    case "$arg" in
        --write) write=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        -*) echo "unknown option: $arg" >&2; exit 2 ;;
        *) tag="$arg" ;;
    esac
done

[ -r "$formula" ] || { echo "not readable: $formula" >&2; exit 2; }

# Default tag: the crate version in Cargo.toml, which release-please keeps equal to the last cut
# release (the `[package]` block is the first one, so the first `version =` line is the crate's).
if [ -z "${tag:-}" ]; then
    version=$(awk -F'"' '/^version = "/ { print $2; exit }' "$root/Cargo.toml")
    [ -n "$version" ] || { echo "no version found in Cargo.toml" >&2; exit 2; }
    tag="v$version"
fi
case "$tag" in
    v[0-9]*) ;;
    *) echo "tag must look like vX.Y.Z, got: $tag" >&2; exit 2 ;;
esac

# Rebuild the source URL from the one the formula already carries, so the script and the formula can
# never disagree about which repository the tap builds from.
url_prefix=$(sed -n 's|^  url "\(https://github\.com/[^"]*/archive/refs/tags/\)v[0-9][^"]*"$|\1|p' "$formula")
[ -n "$url_prefix" ] || { echo "no source url line to rewrite in $formula" >&2; exit 2; }
grep -q '^  sha256 "' "$formula" || { echo "no sha256 line to rewrite in $formula" >&2; exit 2; }
url="${url_prefix}${tag}.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# `--fail` so a 404 (tag not published yet) is an error rather than an HTML page we would happily
# checksum; `--location` because the archive redirects to codeload.
curl --fail --silent --show-error --location --output "$tmp/src.tar.gz" "$url" \
    || { echo "download failed: $url (is $tag published?)" >&2; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then
    sha=$(sha256sum "$tmp/src.tar.gz" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    sha=$(shasum -a 256 "$tmp/src.tar.gz" | awk '{print $1}')
else
    echo "no sha256sum/shasum available to checksum the tarball" >&2
    exit 2
fi
case "$sha" in
    ????????????????????????????????????????????????????????????????) ;;
    *) echo "unexpected SHA-256 output: $sha" >&2; exit 2 ;;
esac

awk -v url="$url" -v sha="$sha" '
    /^  url "https:\/\/github\.com\// { print "  url \"" url "\""; next }
    /^  sha256 "/                     { print "  sha256 \"" sha "\""; next }
    { print }
' "$formula" > "$tmp/formula.rb"

if [ "$write" -eq 1 ]; then
    cat "$tmp/formula.rb" > "$formula"
    echo "$formula now builds $tag (sha256 $sha)" >&2
else
    cat "$tmp/formula.rb"
fi
