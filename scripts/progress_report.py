#!/usr/bin/env python3
"""Write PROGRESS.md: what is built, what is being written right now, and the state of every chapter.

    scripts/progress_report.py [<workflow journal.jsonl> ...]

With journals (newest last) it also shows which agents are running at this moment and on which model. Called by
scripts/publish_progress.sh every round, so the page on GitHub is never more than a few minutes old.
"""
import json, os, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import sanelib as L  # noqa: E402


def running_now(journal):
    """Labels whose latest attempt has started and not returned, in the newest journal only."""
    if not journal or not os.path.exists(journal):
        return [], None
    latest, done = {}, set()
    for line in open(journal, encoding="utf-8"):
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("type") == "started" and d.get("label"):
            latest[d["label"]] = d["agentId"]
        elif d.get("type") == "result":
            done.add(d.get("agentId"))
    live = [lab for lab, aid in latest.items() if aid not in done]
    # an agent whose transcript has not been touched for 20 minutes is waiting (usage limit) or dead
    tdir = os.path.dirname(journal)
    newest = max((os.path.getmtime(os.path.join(tdir, f)) for f in os.listdir(tdir) if f.endswith(".jsonl")), default=0)
    return live, newest


def main():
    journals = [j for j in sys.argv[1:] if os.path.exists(j)]
    lanes = json.load(open(os.path.join(L.CHECKLIST, "_lanes.json")))
    rf = os.path.join(L.CHECKLIST, "_reviewed.txt")
    reviewed = {l.strip() for l in open(rf, encoding="utf-8") if l.strip() and not l.startswith("#")} if os.path.exists(rf) else set()
    log = {}
    lp = os.path.join(L.CHECKLIST, "_buildlog.jsonl")
    if os.path.exists(lp):
        for line in open(lp, encoding="utf-8"):
            try:
                d = json.loads(line)
                log[(d["chapter"], d["stage"])] = d
            except Exception:
                pass
    live, newest = running_now(journals[-1] if journals else None)
    writing = {l.split(":", 1)[1] for l in live if l.startswith("write:")}
    reviewing = {l.split(":", 1)[1] for l in live if l.startswith("review:")}
    rows, cards = [], 0
    counts = {"reviewed": 0, "written": 0, "draft": 0, "queued": 0}
    for c in L.classes():
        if not c.get("chapter"):
            continue
        slug = c["slug"]
        p = os.path.join(L.CHECKLIST, slug + ".md")
        lane = next((n for n, d in lanes["lanes"].items() if slug in d["chapters"]), "")
        state, items, mtime = "queued", 0, ""
        if os.path.exists(p):
            ch = L.parse_chapter(p)
            err, _ = L.lint_chapter(ch)
            items = len(ch["items"])
            state = "draft" if (err or not items) else ("reviewed" if slug in reviewed else "written")
            mtime = time.strftime("%d %b %H:%M", time.gmtime(os.path.getmtime(p)))
            if state in ("written", "reviewed"):
                cards += items
        counts[state] += 1
        now = "being reviewed" if slug in reviewing else ("being written" if slug in writing else "")
        rv = log.get((slug, "review"))
        note = f"review fixed {rv.get('problems_fixed', 0)} of {rv.get('problems_found', 0)} problems" if rv else ""
        rows.append((lane, c, state, items, now, mtime, note))
    n = len(rows)
    stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    done_w = counts["written"] + counts["reviewed"]
    bar = lambda k: "█" * round(20 * k / n) + "░" * (20 - round(20 * k / n))
    o = ["# Build progress", "",
         f"_Updated {stamp} by `scripts/publish_progress.sh`. Refreshes every few minutes while a build is running._", "",
         "| | | |", "|---|---|---|",
         f"| Chapters written | `{bar(done_w)}` | **{done_w} of {n}** ({cards} test cards) |",
         f"| Chapters reviewed | `{bar(counts['reviewed'])}` | **{counts['reviewed']} of {n}** |",
         f"| Drafts in progress | | {counts['draft']} (on the `wip` branch until they lint) |",
         f"| Not started | | {counts['queued']} |", ""]
    if journals:
        idle = newest and (time.time() - newest) > 1200
        o += ["## Right now", ""]
        if live and not idle:
            o += [f"{len(live)} agent(s) working:", ""] + [f"- `{l}`" for l in sorted(live)]
        elif live and idle:
            o += [f"The build is paused: no agent has written anything for {int((time.time() - newest) / 60)} minutes. This is normally a usage "
                  "limit; the workflow resumes by itself when the limit resets. Waiting agents:", ""] + [f"- `{l}`" for l in sorted(live)]
        else:
            o += ["No agent is running. Either the build has finished or it needs to be relaunched (`/build-checklist`)."]
        o += ["", "Order of work: every chapter is written first (most-paid classes first), then every chapter gets an adversarial review. "
              "\"Reviewed\" therefore stays at zero until the writers are done.", ""]
    o += ["## Chapters", "", "| Chapter | Lane | State | Cards | Now | File last changed (UTC) | Review |", "|---|---|---|---|---|---|---|"]
    order = {"reviewed": 0, "written": 1, "draft": 2, "queued": 3}
    for lane, c, state, items, now, mtime, note in sorted(rows, key=lambda r: (order[r[2]], r[0], r[1]["slug"])):
        name = f"[{c['name']}](checklist/{c['slug']}.md)" if state in ("written", "reviewed") else c["name"]
        o.append(f"| {name} | `{lane}` | {state} | {items or ''} | {now} | {mtime} | {note} |")
    o += ["", "## Everything else", "",
          "The engine, the scope guard and hooks, the playbooks, the skills and agents, the saved workflows, the report library and the "
          "tests are complete; the build tracker issue lists them with links. `scripts/selftest.sh` exercises all of it against a local "
          "stand-in target.", "",
          "States: **queued** not started · **draft** on disk, does not lint yet · **written** lints clean, on `main` · **reviewed** passed the adversarial review."]
    with open(os.path.join(ROOT, "PROGRESS.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(o) + "\n")
    L.write_json(os.path.join(L.CHECKLIST, "_now.json"), {"updated": stamp, "running": sorted(live), "paused": bool(live and newest and (time.time() - newest) > 1200)})
    print(f"PROGRESS.md: {done_w}/{n} written, {counts['reviewed']} reviewed, {len(live)} running")


if __name__ == "__main__":
    main()
