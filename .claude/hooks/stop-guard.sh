#!/usr/bin/env bash
# Stop: refuse once to end the turn while a candidate is unverified, an item is running past its timebox,
# or a ready finding has not been shown to the operator. The second attempt passes (stop_hook_active).
R="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
IN="$(cat)"
echo "$IN" | grep -q '"stop_hook_active"[[:space:]]*:[[:space:]]*true' && exit 0
cd "$R" || exit 0
B="$(python3 scripts/sane status --brief 2>/dev/null)"
[ -z "$B" ] && exit 0
MSG=""
echo "$B" | grep -q "OVERDUE" && MSG="$MSG\n- An item is past its timebox: call it off (scripts/sane mark ... parked|negative|candidate --note ...) or say why it deserves more time."
echo "$B" | grep -Eq "cand [1-9]" && MSG="$MSG\n- A candidate is unverified: run playbook PB-09 (/verify) or mark why it cannot be verified now."
E="$(python3 -c 'import sys; sys.path.insert(0,"scripts"); import sanelib as L; e=L.current(required=False); print(e.dir if e else "")' 2>/dev/null)"
if [ -n "$E" ] && [ -d "$E/.git" ] && [ -n "$(git -C "$E" status --porcelain 2>/dev/null | head -1)" ]; then
  git -C "$E" add -A >/dev/null 2>&1 && git -C "$E" commit -q -m "checkpoint $(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null 2>&1
fi
if [ -n "$MSG" ]; then
  printf "Before stopping:%b\nState: %s\n" "$MSG" "$B" >&2
  exit 2
fi
exit 0
