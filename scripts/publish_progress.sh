#!/usr/bin/env bash
# Keep GitHub in step with a build in progress, so that nothing exists only on this machine.
#
#   GH_TOKEN=... scripts/publish_progress.sh                 one round, now
#   GH_TOKEN=... scripts/publish_progress.sh --loop 300      a round every 300 seconds until scripts/.publish.stop exists
#   JOURNALS="/path/a/journal.jsonl /path/b/journal.jsonl"   workflow journals to fold into the build log (optional)
#
# Each round:
#   1. folds workflow results into checklist/_buildlog.jsonl and checklist/_reviewed.txt
#   2. commits to main every chapter that changed and lints clean, plus the index, the build log and any other
#      tracked change, and pushes
#   3. pushes a snapshot of the whole working tree, drafts that do not lint yet included, to the branch `wip`
#      (main is never left with a chapter that fails the linter; `wip` always has everything)
#   4. updates the chapter issues and the build tracker
set -u
R="$(cd "$(dirname "$0")/.." && pwd)"; cd "$R" || exit 1
[ -n "${GH_TOKEN:-}" ] || { echo "set GH_TOKEN"; exit 1; }
AUTH=$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 -w0)
push() { git -c http.extraheader="Authorization: Basic $AUTH" push -q "$@" 2>&1 | tail -1; }

round() {
  # shellcheck disable=SC2086
  [ -n "${JOURNALS:-}" ] && python3 scripts/build_log.py $JOURNALS >/dev/null 2>&1
  python3 scripts/chapter_index.py >/dev/null 2>&1
  # chapters: only those that lint
  good=""; drafts=""
  for f in $(git status --porcelain checklist/ | awk '{print $2}' | grep -E '^checklist/[a-z-]+\.md$'); do
    if python3 scripts/lint_checklist.py "$f" >/dev/null 2>&1; then good="$good $f"; else drafts="$drafts $(basename "$f" .md)"; fi
  done
  # shellcheck disable=SC2086
  [ -n "$good" ] && git add $good
  git add checklist/README.md checklist/_reviewed.txt checklist/_buildlog.jsonl 2>/dev/null
  git add -u -- . ':!checklist/*.md' 2>/dev/null          # other tracked files that changed
  git add src scripts docs playbooks templates .claude kb/classes.json 2>/dev/null   # new files outside checklist/
  if ! git diff --cached --quiet; then
    n=$(ls checklist/*.md | grep -vc README); r=$(grep -vc '^#' checklist/_reviewed.txt 2>/dev/null); r=${r:-0}
    git commit -q -m "Progress: $n chapters on disk, $r reviewed$( [ -n "$good" ] && echo "; chapters:$(echo "$good" | sed 's#checklist/##g; s#\.md##g')")

Co-Authored-By: Claude Mythos 5.2 <noreply@anthropic.com>"
    push origin main
    echo "$(date +%H:%M) main <-$( [ -n "$good" ] && echo "$good" || echo " (index, log or tooling)")"
  fi
  # everything, drafts included, to the wip branch
  export GIT_INDEX_FILE="$R/.git/wip-index"
  cp "$R/.git/index" "$GIT_INDEX_FILE" 2>/dev/null
  git add -A >/dev/null 2>&1
  tree=$(git write-tree)
  unset GIT_INDEX_FILE
  if [ "$tree" != "$(git rev-parse -q --verify 'refs/wip-last^{tree}' 2>/dev/null)" ]; then
    c=$(git commit-tree "$tree" -p HEAD -m "wip snapshot $(date -u +%FT%TZ): working tree including drafts${drafts:+ ($drafts )}")
    git update-ref refs/wip-last "$c"
    push -f origin "$c:refs/heads/wip"
    echo "$(date +%H:%M) wip  <- snapshot${drafts:+, drafts:$drafts}"
  fi
  python3 scripts/gh_issues.py chapters 2>&1 | head -1
}

if [ "${1:-}" = "--loop" ]; then
  every="${2:-300}"
  while [ ! -f scripts/.publish.stop ]; do round; sleep "$every"; done
  rm -f scripts/.publish.stop; echo "stopped"
else
  round
fi
