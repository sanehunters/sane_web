#!/usr/bin/env bash
# UserPromptSubmit: one line of phase, next playbook, coverage and overdue timeboxes on every turn.
R="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$R" && python3 scripts/sane status --brief 2>/dev/null | head -2
exit 0
