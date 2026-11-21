#!/usr/bin/env bash
# PreCompact: snapshot the resume card so the next context window starts from disk, not from a summary.
R="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$R" || exit 0
E="$(python3 -c 'import sys; sys.path.insert(0,"scripts"); import sanelib as L; e=L.current(required=False); print(e.dir if e else "")' 2>/dev/null)"
[ -z "$E" ] && exit 0
{ echo "# state snapshot $(date -u +%Y-%m-%dT%H:%M:%SZ)"; python3 scripts/sane status; echo; echo "## next"; python3 scripts/sane next -n 8; echo; echo "## open hypotheses"; python3 scripts/sane hyp list; } > "$E/state-snapshot.md" 2>&1
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) compaction" >> "$E/logs/compactions.log"
exit 0
