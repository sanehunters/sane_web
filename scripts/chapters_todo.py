#!/usr/bin/env python3
"""What is left to write and review in the checklist, as args for the `write-chapters` workflow.

    scripts/chapters_todo.py                       a table: every chapter and its state
    scripts/chapters_todo.py --json                the workflow args: chapters to write, chapters to review
    scripts/chapters_todo.py --json --model opus --effort max
                                                   run the writers on a named model and effort (reviewers always
                                                   use --review-model, default opus, at --review-effort, default max)
    scripts/chapters_todo.py --json --only xss,csrf     restrict to some chapters
    scripts/chapters_todo.py --json --rereview          also review chapters already marked reviewed

A chapter is `to write` when its file is missing or does not lint; `to review` when it lints and is not listed in
checklist/_reviewed.txt. Briefs (what each chapter must cover) come from src/chapters.json.
"""
import argparse, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import sanelib as L  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--model")
    ap.add_argument("--effort", default="max")
    ap.add_argument("--review-model", default="opus")
    ap.add_argument("--review-effort", default="max")
    ap.add_argument("--only", default="")
    ap.add_argument("--rereview", action="store_true")
    ap.add_argument("--inline", action="store_true", help="embed each brief in the args instead of letting the writer read src/chapters.json")
    a = ap.parse_args()
    briefs = {b["slug"]: b for b in json.load(open(os.path.join(ROOT, "src", "chapters.json"), encoding="utf-8"))["chapters"]}
    rf = os.path.join(L.CHECKLIST, "_reviewed.txt")
    reviewed = {l.strip() for l in open(rf, encoding="utf-8") if l.strip() and not l.startswith("#")} if os.path.exists(rf) else set()
    only = {s for s in a.only.split(",") if s}
    write, review, rows = [], [], []
    for c in L.classes():
        if not c.get("chapter") or (only and c["slug"] not in only):
            continue
        slug = c["slug"]
        p = os.path.join(L.CHECKLIST, slug + ".md")
        state, items = "missing", 0
        if os.path.exists(p):
            ch = L.parse_chapter(p)
            err, _ = L.lint_chapter(ch)
            items = len(ch["items"])
            state = "draft" if (err or not items) else ("reviewed" if slug in reviewed else "written")
        rows.append((slug, c["prefix"], state, items))
        if state in ("missing", "draft"):
            # compact by default: the writer reads its brief from src/chapters.json; --inline embeds it in the args
            b = dict(briefs.get(slug) or {}) if a.inline else {}
            b.update(slug=slug, prefix=c["prefix"])
            if a.model:
                b["model"], b["effort"] = a.model, a.effort
            write.append(b)
        elif state == "written" or a.rereview:
            review.append({"slug": slug, "prefix": c["prefix"]})
    # most-paid classes first, so that an interrupted run has written what matters most
    stats = json.load(open(os.path.join(L.KB, "data", "stats.json"), encoding="utf-8"))["classes"]
    write.sort(key=lambda b: -stats.get(b["slug"], {}).get("paid", 0))
    review.sort(key=lambda b: -stats.get(b["slug"], {}).get("paid", 0))
    if a.json:
        print(json.dumps({"root": ROOT, "reviewModel": a.review_model, "reviewEffort": a.review_effort, "write": write, "reviewOnly": review}))
        return
    w = max(len(r[0]) for r in rows)
    for slug, pfx, state, items in rows:
        print(f"{slug.ljust(w)}  {pfx}  {state:9} {items or ''}")
    n = len(rows)
    print(f"\n{sum(1 for r in rows if r[2] in ('written', 'reviewed'))}/{n} written, {sum(1 for r in rows if r[2] == 'reviewed')}/{n} reviewed; "
          f"{len(write)} to write, {len(review)} to review")
    if write or review:
        print("continue: pass `scripts/chapters_todo.py --json` as args to the `write-chapters` workflow (the /build-checklist skill does this)")


if __name__ == "__main__":
    main()
