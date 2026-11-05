#!/usr/bin/env bash
#
# release-tags.sh: tag the root and every nested module at one version, and
# push the tags together.
#
#   scripts/release-tags.sh vX.Y.Z
#
# The nested modules (witness/forge, witness/chronicle and one adapter per
# library) release with the root, on the same commit. Someone who gets
# keysmith@vX.Y.Z needs keysmith/vX.Y.Z to exist, so a root tag on its own is
# a broken release. This script creates whichever of the tags don't exist yet
# on HEAD, then pushes them all with one atomic push: the remote takes every
# tag or none of them.

set -euo pipefail

[ $# -eq 1 ] || { echo "usage: release-tags.sh vX.Y.Z" >&2; exit 2; }
TAG=$1
[[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] ||
  { echo "release-tags: '$TAG' is not a version like v1.2.3" >&2; exit 2; }

cd "$(dirname "$0")/.."
tags=("$TAG")
for dir in $(scripts/modules.sh); do
  tags+=("$dir/$TAG")
done

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
