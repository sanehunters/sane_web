#!/usr/bin/env python3
"""Lint checklist chapters against docs/11-item-schema.md. Exit 1 on any error.

  scripts/lint_checklist.py                 every chapter
  scripts/lint_checklist.py checklist/xss.md checklist/csrf.md
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sanelib as L


def main():
    paths = sys.argv[1:]
    if not paths:
        paths = [os.path.join(L.CHECKLIST, f) for f in sorted(os.listdir(L.CHECKLIST))
                 if f.endswith(".md") and not f.startswith(("_", "README"))]
    total_e = total_w = items = 0
    seen = {}
    for p in paths:
        ch = L.parse_chapter(p)
        e, w = L.lint_chapter(ch)
        for it in ch["items"]:
            if it["id"] in seen:
                e.append(f"{it['id']}: duplicate id (also in {seen[it['id']]})")
            seen[it["id"]] = ch["slug"]
        items += len(ch["items"])
        total_e += len(e)
        total_w += len(w)
        flag = "FAIL" if e else "ok"
        print(f"{flag:4} {ch['slug']:16} {len(ch['items']):3} items  {len(e)} errors  {len(w)} warnings")
        for x in e:
            print(f"       error: {x}")
        for x in w:
            print(f"       warn:  {x}")
    print(f"{len(paths)} chapters, {items} items, {total_e} errors, {total_w} warnings")
    sys.exit(1 if total_e else 0)


if __name__ == "__main__":
    main()
