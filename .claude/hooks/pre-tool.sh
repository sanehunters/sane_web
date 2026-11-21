#!/usr/bin/env bash
# PreToolUse (Bash, WebFetch): scope, rate, forbidden-mode and required-header guard. Exit 2 blocks.
exec python3 "${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}/scripts/scope_guard.py"
