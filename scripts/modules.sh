#!/usr/bin/env bash
#
# modules.sh: list the nested modules, one directory per line, sorted.
#
# A nested module is a directory one level down with its own go.mod, such as
# forge or keysmith. The root module isn't listed.

set -euo pipefail
cd "$(dirname "$0")/.."
for gomod in */go.mod; do
  [ -f "$gomod" ] || continue
  dirname "$gomod"
done | sort
