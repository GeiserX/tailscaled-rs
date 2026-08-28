#!/bin/sh
# Check that every engine crate this daemon links is published on crates.io at the exact version
# `Cargo.lock` resolves.
#
# Why this exists: `cargo publish` refuses a crate that has a `git` dependency, so `tailscaled-rs`
# can only be published once the whole engine (`tailscale-rs`, published under the `geiserx_*`
# namespace) is on crates.io. That is an upstream property that changes underneath us — every
# engine bump re-opens the question for whatever versions the new pin resolves to. This script
# answers it from the lockfile, so the answer is never a stale claim in a doc.
#
# It reads `Cargo.lock` (not `Cargo.toml`), so it covers the full resolved graph: the transitive
# engine crates and the ones only an optional feature (`tun`, `ssh`, `acme`, …) pulls in.
#
# Usage:  scripts/check-engine-on-crates-io.sh [path/to/Cargo.lock]
# Exit:   0 = every engine crate is published and unyanked; 1 = at least one is not;
#         2 = the question could not be answered (bad lockfile, index unreachable).
#
# Network: reads the crates.io sparse index (https://index.crates.io), the interface built for
# automation. Override with CRATES_INDEX= to point at a mirror.

set -eu

lock="${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/Cargo.lock}"
index="${CRATES_INDEX:-https://index.crates.io}"

[ -r "$lock" ] || { echo "not readable: $lock" >&2; exit 2; }

# Every engine crate is named `geiserx_*` (the facade `geiserx_tailscale` plus the `geiserx_ts_*`
# workspace members). Emit "<name> <version>" for each `[[package]]` block matching that prefix.
crates=$(awk '
  /^\[\[package\]\]/ { name = ""; version = "" }
  /^name = /         { name = $3;    gsub(/"/, "", name) }
  /^version = /      { version = $3; gsub(/"/, "", version) }
  /^$/               { if (name ~ /^geiserx_/) print name, version; name = ""; version = "" }
  END                { if (name ~ /^geiserx_/) print name, version }
' "$lock")

[ -n "$crates" ] || { echo "no geiserx_* engine crates found in $lock" >&2; exit 2; }

# crates.io sparse-index path layout: 1-char names live under 1/, 2-char under 2/, 3-char under
# 3/<first>/, and everything longer under <first-two>/<next-two>/.
index_path() {
  n=$1
  case ${#n} in
    1) printf '1/%s' "$n" ;;
    2) printf '2/%s' "$n" ;;
    3) printf '3/%s/%s' "$(printf '%.1s' "$n")" "$n" ;;
    *) printf '%.2s/%s/%s' "$n" "$(printf '%s' "$n" | cut -c3-4)" "$n" ;;
  esac
}

missing=0
checked=0
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT INT TERM

for entry in $(printf '%s\n' "$crates" | tr ' ' '@'); do
  name=${entry%@*}
  version=${entry#*@}
  checked=$((checked + 1))

  # Ask for the status code explicitly rather than leaning on curl's exit code: with HTTP/2 a 404
  # does not reliably surface as curl's "HTTP error" exit, and a timeout must never be mistaken for
  # "unpublished".
  code=$(curl -sS --max-time 30 -A 'tailscaled-rs engine publication check' \
    -o "$tmp" -w '%{http_code}' "$index/$(index_path "$name")" 2>/dev/null) || code=""

  case "$code" in
    200) ;;
    404)
      printf 'MISSING  %-36s %-8s (crate not in the index)\n' "$name" "$version"
      missing=$((missing + 1))
      continue
      ;;
    *)
      echo "index request for $name failed (HTTP '${code:-none}'); not a publication verdict" >&2
      exit 2
      ;;
  esac

  # One JSON object per line, one line per published version.
  line=$(grep -F "\"vers\":\"$version\"" "$tmp" || true)
  if [ -z "$line" ]; then
    printf 'MISSING  %-36s %-8s (version not published)\n' "$name" "$version"
    missing=$((missing + 1))
  elif printf '%s' "$line" | grep -q '"yanked":true'; then
    printf 'YANKED   %-36s %-8s\n' "$name" "$version"
    missing=$((missing + 1))
  else
    printf 'ok       %-36s %-8s\n' "$name" "$version"
  fi
done

echo
if [ "$missing" -eq 0 ]; then
  echo "All $checked engine crates are published on crates.io at the locked version."
  exit 0
fi
echo "$missing of $checked engine crates are not usable from crates.io at the locked version."
echo "Until that is 0, tailscaled-rs cannot be published (cargo publish rejects a git dependency)."
exit 1
