#!/usr/bin/env bash
#
# release-tags.sh: tag the root and every nested module at one version, and
# push the tags together.
#
#   scripts/release-tags.sh vX.Y.Z
#   scripts/release-tags.sh --dry-run vX.Y.Z
#
# The nested modules (witness/forge, witness/chronicle and one adapter per
# library) release with the root, on the same commit. Someone who gets
# keysmith@vX.Y.Z needs keysmith/vX.Y.Z to exist, so a root tag on its own is
# a broken release. This script creates whichever of the tags don't exist yet
# on HEAD, then pushes them all with one atomic push: the remote takes every
# tag or none of them.
#
# e2e is a test-only module. make test, make lint and CI run it like the
# others, but nobody imports it, so it gets no tag.
#
# Before it tags anything, the script checks every module's go.mod: each
# require of a module from this repo (github.com/hallproof/witness or one of
# its nested modules) must name exactly vX.Y.Z. The replace lines keep local
# builds on the working tree, but a consumer's build ignores them and
# resolves the require, so a require at any other version ships a release
# that pulls in the wrong code, or code that was never published. Bump them
# all first, for example:
#
#   go mod edit -require github.com/hallproof/witness@vX.Y.Z forge/go.mod
#
# --dry-run runs that check and prints the tags it would create, one per
# line, without touching git. The check reads `go mod edit -json` with jq
# when jq is installed, and with awk when it isn't (or when
# RELEASE_TAGS_NO_JQ is set).

set -euo pipefail

usage() { echo "usage: release-tags.sh [--dry-run] vX.Y.Z" >&2; exit 2; }

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=1
  shift
fi
[ $# -eq 1 ] || usage
TAG=$1
[[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] ||
  { echo "release-tags: '$TAG' is not a version like v1.2.3" >&2; exit 2; }

# Modules that are tested but never tagged.
TEST_ONLY=" e2e "

cd "$(dirname "$0")/.."
ROOT=$(go mod edit -json go.mod | awk -F'"' '/"Path":/ {print $4; exit}')
[ -n "$ROOT" ] || { echo "release-tags: can't read the root module path" >&2; exit 1; }

# intra prints "path version" for every require in go.mod $1 of a module from
# this repo.
intra() {
  if [ -z "${RELEASE_TAGS_NO_JQ:-}" ] && command -v jq >/dev/null 2>&1; then
    go mod edit -json "$1" | jq -r --arg r "$ROOT" \
      '.Require[]? | select(.Path == $r or (.Path | startswith($r + "/"))) | "\(.Path) \(.Version)"'
  else
    # go mod edit -json prints each require as its own object, Path then
    # Version on the lines after it, inside the "Require" array.
    go mod edit -json "$1" | awk -F'"' -v r="$ROOT" '
      /^\t"Require": \[/ { in_req = 1; next }
      in_req && /^\t\]/ { in_req = 0 }
      in_req && $2 == "Path" { path = $4 }
      in_req && $2 == "Version" && (path == r || index(path, r "/") == 1) { print path, $4 }
    '
  fi
}

modules=$(scripts/modules.sh)
bad=0
for dir in . $modules; do
  while read -r path ver; do
    [ -n "$path" ] || continue
    if [ "$ver" != "$TAG" ]; then
      echo "release-tags: ${dir#./}/go.mod requires $path at $ver, not $TAG" >&2
      bad=1
    fi
  done < <(intra "$dir/go.mod")
done
if [ "$bad" -ne 0 ]; then
  echo "release-tags: refusing to tag $TAG. Require every module from $ROOT at $TAG first." >&2
  exit 1
fi

tags=("$TAG")
for dir in $modules; do
  case "$TEST_ONLY" in
  *" $dir "*) continue ;;
  esac
  tags+=("$dir/$TAG")
done

if [ "$DRY_RUN" -eq 1 ]; then
  printf '%s\n' "${tags[@]}"
  exit 0
fi

head=$(git rev-parse HEAD)
to_push=()
for t in "${tags[@]}"; do
  if git rev-parse -q --verify "refs/tags/$t" >/dev/null; then
    at=$(git rev-parse "refs/tags/$t^{commit}")
    if [ "$at" != "$head" ]; then
      echo "release-tags: $t already points at $at, not HEAD $head" >&2
      exit 1
    fi
  else
    git tag "$t"
  fi
  if git ls-remote --exit-code --tags origin "refs/tags/$t" >/dev/null 2>&1; then
    echo "$t is already on origin"
  else
    to_push+=("refs/tags/$t")
  fi
done

if [ "${#to_push[@]}" -eq 0 ]; then
  echo "release-tags: every tag for $TAG is already on origin"
  exit 0
fi

git push --atomic origin "${to_push[@]}"
echo "release-tags: pushed ${to_push[*]#refs/tags/}"
