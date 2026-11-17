#!/usr/bin/env bash
# Checks that the folder of a release archive holds exactly the files that
# packaging/archive-files.txt lists for it: nothing more (no tests, no server links, no stray
# helper), nothing less, and no subfolders.
#   check-archive.sh <archive> <folder>      e.g.  check-archive.sh linux-x86_64 elf-gate-linux-x86_64
set -euo pipefail
# The same byte order for sort and comm, whatever the locale of the machine.
export LC_ALL=C

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <archive> <folder>" >&2
    exit 2
fi
archive="$1"
folder="$2"
list="$(dirname "${BASH_SOURCE[0]}")/../archive-files.txt"

expected="$(awk -v a="$archive" '$1 !~ /^#/ && $1 == a { print $2 }' "$list" | sort)"
if [ -z "$expected" ]; then
    echo "no files listed for '$archive' in $list" >&2
    exit 1
fi
actual="$(cd "$folder" && find . \( -type f -o -type l \) | sed 's|^\./||' | sort)"
unexpected="$(comm -13 <(printf '%s\n' "$expected") <(printf '%s\n' "$actual"))"
missing="$(comm -23 <(printf '%s\n' "$expected") <(printf '%s\n' "$actual"))"
folders="$(cd "$folder" && find . -mindepth 1 -type d | sed 's|^\./||' | sort)"

status=0
if [ -n "$unexpected" ]; then
    echo "Unexpected files in $folder: $(echo $unexpected)" >&2
    status=1
fi
if [ -n "$missing" ]; then
    echo "Missing files in $folder: $(echo $missing)" >&2
    status=1
fi
if [ -n "$folders" ]; then
    echo "Unexpected folders in $folder: $(echo $folders)" >&2
    status=1
fi
if [ "$status" -eq 0 ]; then
    echo "$folder: exactly the $(printf '%s\n' "$expected" | wc -l | tr -d ' ') listed files"
fi
exit "$status"
