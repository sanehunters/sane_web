#!/usr/bin/env bash
# SessionStart: the resume card. Also re-printed after a compaction so the state survives it.
R="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$R" || exit 0
echo "=== sane_web — web bug bounty framework ==="
echo "Read CLAUDE.md, then START.md. The state below is on disk; trust it over memory."
echo
python3 scripts/sane status 2>&1 | head -40
echo
python3 scripts/sane doctor --brief 2>&1 | head -3
E="$(python3 -c 'import sys; sys.path.insert(0,"scripts"); import sanelib as L; e=L.current(required=False); print(e.dir if e else "")' 2>/dev/null)"
if [ -n "$E" ]; then
  [ -f "$E/state-snapshot.md" ] && { echo; echo "--- snapshot written before the last compaction ---"; tail -25 "$E/state-snapshot.md"; }
  # make $E, $RATE, $OOB, HDR, $A, $B available to every later shell command when the harness supports it
  if [ -n "$CLAUDE_ENV_FILE" ] && [ -f "$E/env.sh" ]; then echo "source \"$E/env.sh\"" >> "$CLAUDE_ENV_FILE"; fi
  echo
  echo "Shell commands that touch the target start with:  source \"$E/env.sh\""
fi
echo "Rules that never bend: in scope only · programme rate and headers · minimal proof, no damage · never fabricate · a primitive is not a finding."
exit 0
