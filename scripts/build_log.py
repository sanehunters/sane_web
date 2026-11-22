#!/usr/bin/env python3
"""Fold the results of chapter-writing workflow runs into the repository, so nothing about the build lives only in
a session directory.

    scripts/build_log.py <journal.jsonl> [<journal.jsonl> ...]

Reads each workflow journal and updates:
  checklist/_buildlog.jsonl   one line per finished writer or reviewer: chapter, stage, item count, lint errors,
                              fact tags it wanted, problems it found and fixed, its notes
  checklist/_reviewed.txt     chapters whose reviewer returned with zero lint errors
Both files are merged, never truncated: results from earlier runs are kept.
"""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "checklist", "_buildlog.jsonl")
REV = os.path.join(ROOT, "checklist", "_reviewed.txt")


def main():
    have = {}
    if os.path.exists(LOG):
        for line in open(LOG, encoding="utf-8"):
            try:
                d = json.loads(line)
                have[(d["chapter"], d["stage"])] = d
            except Exception:
                pass
    reviewed = set()
    if os.path.exists(REV):
        reviewed = {l.strip() for l in open(REV, encoding="utf-8") if l.strip() and not l.startswith("#")}
    for journal in sys.argv[1:]:
        if not os.path.exists(journal):
            continue
        label = {}
        for line in open(journal, encoding="utf-8"):
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("type") == "started" and d.get("label"):
                label[d["agentId"]] = d["label"]
            elif d.get("type") == "result":
                lab = label.get(d.get("agentId"), "")
                res = d.get("result")
                if isinstance(res, str):
                    try:
                        res = json.loads(res)
                    except Exception:
                        res = None
                if ":" not in lab or not isinstance(res, dict):
                    continue
                stage, chapter = lab.split(":", 1)
                rec = {"chapter": chapter, "stage": stage}
                for k in ("items", "lint_errors", "lint_warnings", "missing_tags", "problems_found", "problems_fixed", "top_problems", "notes"):
                    if k in res:
                        rec[k] = res[k]
                have[(chapter, stage)] = rec
                if stage == "review" and res.get("lint_errors") == 0:
                    reviewed.add(chapter)
    with open(LOG, "w", encoding="utf-8") as f:
        for k in sorted(have):
            f.write(json.dumps(have[k], ensure_ascii=False) + "\n")
    with open(REV, "w", encoding="utf-8") as f:
        f.write("# Chapters that have passed the adversarial review. Written by scripts/build_log.py; read by chapter_index.py, chapters_todo.py and gh_issues.py.\n")
        for s in sorted(reviewed):
            f.write(s + "\n")
    print(f"build log: {len(have)} results, {len(reviewed)} chapters reviewed")


if __name__ == "__main__":
    main()
