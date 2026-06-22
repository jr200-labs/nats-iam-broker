#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 <label> <file>" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage

label="$1"
file="$2"

[ -f "$file" ] || {
    echo "message text file not found: $file" >&2
    exit 2
}

default_blocked_terms="claude,codex,kilo,composer,grok"
blocked_terms="${BANNED_COMMIT_WORDS:-$default_blocked_terms}"

[ -n "$blocked_terms" ] || exit 0

hits=""
old_ifs="$IFS"
IFS=,
for raw in $blocked_terms; do
    IFS="$old_ifs"
    term="$(printf '%s' "$raw" | xargs)"
    IFS=,
    [ -n "$term" ] || continue
    if grep -iEqw -- "$term" "$file"; then
        if [ -z "$hits" ]; then
            hits="$term"
        else
            hits="$hits, $term"
        fi
    fi
done
IFS="$old_ifs"

if [ -n "$hits" ]; then
    echo "${label} contains blocked attribution term(s): ${hits}" >&2
    exit 1
fi
