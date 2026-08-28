#!/bin/sh
# Report which published `geiserx_tailscale` version — if any — was cut from exactly the engine
# source this daemon pins, so the `git` + `rev` engine deps can be traded for registry `version`
# deps without changing a byte of what the daemon builds.
#
# Why this is not obvious: a published engine crate records the commit it was cut from in
# `.cargo_vcs_info.json`, and the natural move is to compare that sha1 against our `rev`. It never
# matches, and it never can. Engine releases are cut by release-please, which bumps every workspace
# version in a dedicated `chore(main): release X` commit and publishes from *that* commit. The
# daemon pins the tree it built and tested, which is an ANCESTOR of the release commit. So the
# backward comparison answers "no" for every release, forever, and leaves you no way forward.
#
# Go forward from the pin instead: find the first release commit that is a descendant of the pin,
# and check what landed in between. If the answer is "release metadata only", then the version that
# release published IS the pinned source under a different number, and depending on it is a no-op.
#
# Usage:  scripts/engine-release-for-pin.sh [rev]
#         (rev defaults to the `rev = "…"` on the `tailscale` dep in Cargo.toml)
# Env:    ENGINE_REMOTE=  override the engine git remote (default: the dep's `git = "…"` URL)
#         CRATES_INDEX=   override the crates.io sparse index
# Exit:   0 = a published release carries exactly the pinned source
#         1 = answered, and the answer is no (pin not yet released, real source landed in between,
#             or that version is absent/yanked on crates.io)
#         2 = the question could not be answered (bad manifest, network, unknown rev)

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$root/Cargo.toml"
index="${CRATES_INDEX:-https://index.crates.io}"

[ -r "$manifest" ] || { echo "not readable: $manifest" >&2; exit 2; }

# The `tailscale` dep line carries both the remote and the rev. Read them from the manifest rather
# than hardcoding, so this cannot drift away from what Cargo actually resolves.
depline=$(grep -m1 '^tailscale = ' "$manifest" || true)
[ -n "$depline" ] || { echo "no \`tailscale\` dependency in $manifest" >&2; exit 2; }

extract() { printf '%s' "$depline" | sed -n "s/.*$1 = \"\([^\"]*\)\".*/\1/p"; }

pin="${1:-$(extract rev)}"
remote="${ENGINE_REMOTE:-$(extract git)}"
[ -n "$pin" ]    || { echo "no \`rev\` on the \`tailscale\` dep; nothing to resolve" >&2; exit 2; }
[ -n "$remote" ] || { echo "no \`git\` URL on the \`tailscale\` dep" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# Blobless partial clone: we need the full commit graph of `main` to walk descendants, but only the
# handful of blobs the pin→release diff touches. That is ~1 MiB and a couple of seconds, versus a
# full clone of the engine. Blobs are fetched lazily by the diff below.
git init -q --bare "$work/eng"
git -C "$work/eng" remote add origin "$remote"
git -C "$work/eng" fetch -q --filter=blob:none origin '+refs/heads/main:refs/remotes/origin/main' \
  || { echo "could not fetch $remote" >&2; exit 2; }

git -C "$work/eng" cat-file -e "$pin^{commit}" 2>/dev/null \
  || { echo "rev $pin is not a commit in $remote" >&2; exit 2; }

echo "pinned rev      $pin"

if ! git -C "$work/eng" merge-base --is-ancestor "$pin" origin/main; then
  echo "the pinned rev is not an ancestor of the engine's main branch, so no release can contain it."
  exit 1
fi

# release-please names its release commits `chore(main): release <version>`. Other `chore(release):`
# commits touch the release machinery and are NOT releases, so match the subject exactly.
subject=$(git -C "$work/eng" log -1 --format='%s' "$pin")
case $subject in
  "chore(main): release "*) release=$pin ;;
  *)
    # --ancestry-path keeps only commits on a path from the pin, so an unrelated concurrent release
    # on another line of history cannot be mistaken for ours. --reverse makes the first hit the
    # earliest, i.e. the release that first contains the pin.
    release=$(git -C "$work/eng" log --reverse --ancestry-path --format='%H %s' "$pin..origin/main" \
      | grep -m1 -F -e "chore(main): release " | cut -d' ' -f1 || true)
    ;;
esac

if [ -z "${release:-}" ]; then
  echo
  echo "no release commit contains this rev yet — the pinned engine source has not been published."
  echo "Until it is, the \`git\` + \`rev\` deps cannot become registry deps and tailscaled-rs cannot"
  echo "be published (cargo publish rejects a git dependency)."
  exit 1
fi

rel_subject=$(git -C "$work/eng" log -1 --format='%s' "$release")
version=$(printf '%s' "$rel_subject" | sed -n 's/^chore(main): release \([0-9][^ ]*\).*/\1/p')
distance=$(git -C "$work/eng" rev-list --count "$pin..$release")

echo "release commit  $release"
echo "                $rel_subject"
echo "version         ${version:-?}"
echo "distance        $distance commit(s) after the pin"

[ -n "$version" ] || { echo "could not read a version out of the release subject" >&2; exit 2; }

# What landed between the pin and the release. A release-please release commit should touch only
# version metadata; anything else means the published tarball is NOT the source we test.
changed=$(git -C "$work/eng" diff --name-only "$pin" "$release")

# Files the release machinery is allowed to touch, at any depth in the workspace.
extra=$(printf '%s\n' "$changed" | grep -vE '(^|/)(Cargo\.toml|Cargo\.lock|CHANGELOG\.md|\.release-please-manifest\.json)$' || true)

# `Cargo.lock` is deliberately tolerated above, but it is NOT release metadata: between-releases
# commits in the engine sometimes touch nothing else (a dependency bump, a RUSTSEC patch). It is
# tolerated because a *library* dependency's lockfile has no effect on us — Cargo resolves the whole
# graph from `tailscaled-rs`'s own `Cargo.lock`, which pins every transitive crate regardless of
# whether the engine arrives by git or from the registry. Report it anyway, so "no source change"
# is never read as "nothing happened".
lock_touched=$(printf '%s\n' "$changed" | grep -cE '(^|/)Cargo\.lock$' || true)

# Within the manifests, every changed line must be a release-please version bump. The engine tags
# each such line with an `x-release-please-version` marker; the workspace `[package] version` field
# is the one bumped line that carries no marker.
manifest_noise=$(git -C "$work/eng" diff -U0 "$pin" "$release" -- '*Cargo.toml' \
  | grep -E '^[+-]' | grep -vE '^(\+\+\+|---)' \
  | grep -v 'x-release-please-version' \
  | grep -vE '^[+-]version = "[0-9][^"]*"[[:space:]]*$' || true)

if [ -n "$extra" ] || [ -n "$manifest_noise" ]; then
  echo "diff            REAL SOURCE CHANGES between the pin and the release"
  echo
  if [ -n "$extra" ]; then
    echo "files outside the release metadata set:"
    printf '%s\n' "$extra" | sed 's/^/  /'
  fi
  if [ -n "$manifest_noise" ]; then
    echo "manifest changes that are not version bumps:"
    printf '%s\n' "$manifest_noise" | sed 's/^/  /'
  fi
  echo
  echo "geiserx_tailscale $version is therefore NOT the source this daemon builds. Depending on it"
  echo "would be a real engine change: run it through the bump discipline in docs/ENGINE.md §1."
  exit 1
fi

echo "diff            release metadata only (no source change)"
if [ "${lock_touched:-0}" -gt 0 ]; then
  echo "                Cargo.lock also moved; a dependency's lockfile does not affect what"
  echo "                tailscaled-rs resolves, so it does not change the published source."
fi

# Published and unyanked? Sparse-index path layout: `<first-two>/<next-two>/<name>` for names of 4+
# characters, which every `geiserx_*` crate is.
tmp="$work/idx"
code=$(curl -sS --max-time 30 -A 'tailscaled-rs engine release check' \
  -o "$tmp" -w '%{http_code}' "$index/ge/is/geiserx_tailscale" 2>/dev/null) || code=""
case "$code" in
  200) ;;
  *) echo "index request failed (HTTP '${code:-none}'); cannot confirm publication" >&2; exit 2 ;;
esac

line=$(grep -F "\"vers\":\"$version\"" "$tmp" || true)
if [ -z "$line" ]; then
  echo "crates.io       geiserx_tailscale $version is NOT published"
  exit 1
elif printf '%s' "$line" | grep -q '"yanked":true'; then
  echo "crates.io       geiserx_tailscale $version is YANKED"
  exit 1
fi
echo "crates.io       geiserx_tailscale $version published, not yanked"

echo
echo "geiserx_tailscale $version carries exactly the source at this rev."
if [ "$distance" -eq 0 ]; then
  echo "The pin is that release commit, so the pinned manifests self-report $version: a"
  echo "\`version = \"$version\"\` requirement resolves against this pin as-is, and the engine deps in"
  echo "Cargo.toml can become registry deps. See docs/ENGINE.md §3."
else
  echo "The pin is $distance commit(s) BEFORE that release, so its manifests still self-report the"
  echo "PREVIOUS version. Cargo rejects \`version = \"$version\"\` next to this \`rev\` for that reason"
  echo "(\"candidate versions found which didn't match\"). Moving the pin onto"
  echo "$release — a source-identical change — makes the two agree."
  echo "See docs/ENGINE.md §3."
fi
