#!/bin/bash
# Usage: run.sh <scenario-name>   (see scenarios/)
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
export ROOT=${ROOT:-$(cd "$HERE/../../.." && pwd)}
export XR=${XR:-$ROOT/bin/xray}
export WORK=${WORK:-$(mktemp -d /tmp/elf-gate-lab.XXXXXX)}
SCEN="$HERE/scenarios/$1.sh"
[ -f "$SCEN" ] || { echo "no such scenario: $1"; ls "$HERE/scenarios" | sed 's/\.sh$//'; exit 1; }
[ -x "$XR" ] || { echo "xray not found at $XR (set XR=...)"; exit 1; }
mkdir -p "$WORK"
python3 "$HERE/gen_configs.py" "$WORK" "$XR"
echo "work dir: $WORK"
exec timeout "${TIMEOUT:-150}" unshare -Urnmpf --mount-proc bash "$HERE/inner.sh" "$SCEN"
