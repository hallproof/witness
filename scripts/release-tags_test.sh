#!/usr/bin/env bash
#
# release-tags_test.sh: test release-tags.sh on a copy of the repo's go.mod
# files, in --dry-run mode, so it never touches git. make test runs it.
#
# It checks the tag list (every nested module but the test-only e2e) and
# that the script refuses a release while any module requires a module of
# this repo at a version other than the tag. Each refusal is checked with jq
# and without it.

set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)

# The copy lives inside the repo, under a dot directory that Go and
# modules.sh both skip, and goes away when the test ends.
tmp=$(mktemp -d "$repo/.release-tags-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
# The copy sits in this repo's work tree. Point git at nothing, so a script
# that ignored --dry-run fails instead of tagging the real repo.
export GIT_DIR="$tmp/no-git"

failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# fresh makes $tmp a copy of the scripts and every go.mod.
fresh() {
  rm -rf "${tmp:?}"/*
  mkdir -p "$tmp/scripts"
  cp "$repo/scripts/modules.sh" "$repo/scripts/release-tags.sh" "$tmp/scripts/"
  cp "$repo/go.mod" "$tmp/go.mod"
  for dir in $("$repo/scripts/modules.sh"); do
    mkdir -p "$tmp/$dir"
    cp "$repo/$dir/go.mod" "$tmp/$dir/go.mod"
  done
}

# release runs the copy's release-tags.sh --dry-run, with jq hidden when
# $1 is "nojq".
release() {
  local how=$1
  shift
  if [ "$how" = nojq ]; then
    RELEASE_TAGS_NO_JQ=1 "$tmp/scripts/release-tags.sh" --dry-run "$@"
  else
    "$tmp/scripts/release-tags.sh" --dry-run "$@"
  fi
}

# The version every module in the repo requires its siblings at today.
current=$(go mod edit -json "$repo/forge/go.mod" |
  awk -F'"' '/"Path": "github.com\/hallproof\/witness",$/ {getline; print $4; exit}')
[ -n "$current" ] || { echo "release-tags_test: can't read forge's witness version" >&2; exit 1; }

for how in jq nojq; do
  # The tag list: the root and every nested module, except e2e.
  fresh
  if ! out=$(release "$how" "$current" 2>&1); then
    fail "$how: dry run of $current refused: $out"
  fi
  printf '%s\n' "$out" | grep -qx "$current" || fail "$how: no root tag $current in: $out"
  for dir in $("$repo/scripts/modules.sh"); do
    if [ "$dir" = e2e ]; then
      printf '%s\n' "$out" | grep -q "^e2e/" && fail "$how: tags the test-only e2e module: $out"
    else
      printf '%s\n' "$out" | grep -qx "$dir/$current" || fail "$how: no tag $dir/$current in: $out"
    fi
  done

  # A tag the modules don't require yet.
  fresh
  if out=$(release "$how" v99.0.0 2>&1); then
    fail "$how: tagged v99.0.0 while the modules require $current"
  fi
  printf '%s\n' "$out" | grep -q "forge/go.mod requires github.com/hallproof/witness at $current" ||
    fail "$how: v99.0.0 refusal doesn't name forge: $out"

  # One module behind.
  fresh
  go mod edit -require "github.com/hallproof/witness@v0.0.1" "$tmp/keysmith/go.mod"
  if out=$(release "$how" "$current" 2>&1); then
    fail "$how: tagged $current while keysmith requires v0.0.1"
  fi
  printf '%s\n' "$out" | grep -q "keysmith/go.mod requires github.com/hallproof/witness at v0.0.1" ||
    fail "$how: keysmith refusal: $out"

  # A sibling at the zero pseudo-version, in a module that isn't tagged.
  fresh
  go mod edit -require "github.com/hallproof/witness/forge@v0.0.0-00010101000000-000000000000" "$tmp/e2e/go.mod"
  if out=$(release "$how" "$current" 2>&1); then
    fail "$how: tagged $current while e2e requires forge at the zero version"
  fi
  printf '%s\n' "$out" | grep -q "e2e/go.mod requires github.com/hallproof/witness/forge at v0.0.0-00010101000000-000000000000" ||
    fail "$how: e2e refusal: $out"
done

if [ "$failures" -ne 0 ]; then
  echo "release-tags_test: $failures failure(s)" >&2
  exit 1
fi
echo "release-tags_test: ok"
