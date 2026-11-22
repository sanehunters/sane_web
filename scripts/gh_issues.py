#!/usr/bin/env python3
"""Mirror the playbooks as GitHub issues, and open run-sheets for engagements.

The files under playbooks/ are the source of truth. This script publishes them where the work is tracked, so a
session (or a person) can read the procedure, its timebox and its call-off rule as an issue, tick steps off, and
discuss amendments.

  scripts/gh_issues.py sync [--repo owner/name]
      one issue per playbook (label `playbook`), created or updated by title, plus a pinned-style index issue
      "Run-sheet: the hunt, step by step" that lists every playbook with its trigger, timebox, call-off and exit.

  scripts/gh_issues.py list [--repo owner/name]
      print the playbook issues with their numbers and links.

  scripts/gh_issues.py chapters [--reviewed slug,slug] [--repo owner/name]
      one issue per checklist chapter (label `chapter`, milestone "Checklist: 36 chapters") listing its test cards,
      and a "Build tracker" issue showing every component and chapter with its state. Chapters named in
      checklist/_reviewed.txt or --reviewed are closed. Safe to run repeatedly.

  scripts/gh_issues.py runsheet <engagement> --repo owner/private-evidence-repo
      open one tracking issue for an engagement: a task list of the phases with their timeboxes, to tick off as
      the hunt proceeds. It contains the programme's name, so it goes ONLY to a private repository you name.
      The script refuses a public repository.

Needs GH_TOKEN (or GITHUB_TOKEN) with `repo` scope. --repo defaults to this checkout's `origin`.
"""
import json, os, re, subprocess, sys, urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PB_DIR = os.path.join(ROOT, "playbooks")
LABELS = {
    "playbook": ("1d76db", "A step-by-step procedure from playbooks/"),
    "run-sheet": ("0e8a16", "Index or per-engagement tracking list"),
    "phase:setup": ("c5def5", "PB-00, PB-01"),
    "phase:surface": ("c5def5", "PB-02 to PB-05"),
    "phase:test": ("c5def5", "PB-06 to PB-08"),
    "phase:prove": ("c5def5", "PB-09 to PB-12"),
    "phase:always": ("fbca04", "PB-13, PB-14: apply in every phase"),
}
PHASE = {0: "phase:setup", 1: "phase:setup", 2: "phase:surface", 3: "phase:surface", 4: "phase:surface", 5: "phase:surface",
         6: "phase:test", 7: "phase:test", 8: "phase:test", 9: "phase:prove", 10: "phase:prove", 11: "phase:prove",
         12: "phase:prove", 13: "phase:always", 14: "phase:always"}


def token():
    t = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not t:
        sys.exit("set GH_TOKEN (a GitHub token with repo scope)")
    return t


def api(method, path, data=None):
    req = urllib.request.Request("https://api.github.com" + path, method=method,
                                 data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Authorization": "token " + token(), "Accept": "application/vnd.github+json",
                                          "User-Agent": "sane-web-issues", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r) if r.status != 204 else None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:300]
        if e.code == 422 and "already_exists" in body:
            return None
        sys.exit(f"GitHub API {method} {path}: HTTP {e.code} {body}")


def default_repo():
    try:
        url = subprocess.run(["git", "-C", ROOT, "remote", "get-url", "origin"], capture_output=True, text=True).stdout.strip()
        m = re.search(r"github\.com[:/]([^/]+/[^/.]+)", url)
        return m.group(1) if m else None
    except Exception:
        return None


def parse_playbook(path):
    text = open(path, encoding="utf-8").read()
    lines = text.split("\n")
    title = lines[0].lstrip("# ").strip()
    m = re.match(r"PB-(\d\d)", title)
    hdr = dict(re.findall(r"(?m)^\|\s*\*\*(.+?)\*\*\s*\|\s*(.*?)\s*\|\s*$", text))

    def section(name):
        s = re.search(rf"(?ms)^## {re.escape(name)}\n(.*?)(?=^## |\Z)", text)
        return s.group(1).strip() if s else ""
    return {"id": f"PB-{m.group(1)}" if m else "", "n": int(m.group(1)) if m else -1, "title": title, "hdr": hdr,
            "body": "\n".join(lines[1:]).strip(), "calloff": section("Call it off when"), "done": section("Done when"),
            "file": os.path.relpath(path, ROOT)}


def playbooks():
    return [parse_playbook(os.path.join(PB_DIR, f)) for f in sorted(os.listdir(PB_DIR)) if re.match(r"PB-\d\d", f)]


def one_line(s, n=160):
    s = re.sub(r"\s+", " ", re.sub(r"(?m)^[-*]\s*", "", s)).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def issue_body(pb):
    h = pb["hdr"]
    top = (f"> **Trigger:** {h.get('Trigger', '—')}\n"
           f"> **Timebox:** {h.get('Timebox', '—')}\n"
           f"> **Call it off when:** {one_line(pb['calloff'], 400) or '—'}\n"
           f"> **Done when:** {one_line(pb['done'], 400) or '—'}\n"
           f"> **Next:** {h.get('Next', '—')}\n")
    foot = (f"\n\n---\nSource of truth: [`{pb['file']}`](../blob/main/{pb['file']}). This issue is regenerated by "
            f"`scripts/gh_issues.py sync`; propose changes in a comment or edit the file. In a session: `scripts/sane playbook {pb['id']}`.")
    return top + "\n" + pb["body"] + foot


def existing(repo, label):
    out, page = {}, 1
    while True:
        batch = api("GET", f"/repos/{repo}/issues?state=all&labels={label}&per_page=100&page={page}")
        for i in batch:
            if "pull_request" not in i:
                out[i["title"]] = i
        if len(batch) < 100:
            return out
        page += 1


def cmd_sync(repo):
    for name, (color, desc) in LABELS.items():
        api("POST", f"/repos/{repo}/labels", {"name": name, "color": color, "description": desc})
    have = existing(repo, "playbook")
    by_id = {t.split(" ")[0]: i for t, i in have.items()}
    numbers = {}
    for pb in playbooks():
        data = {"title": pb["title"], "body": issue_body(pb), "labels": ["playbook", PHASE.get(pb["n"], "phase:always")]}
        cur = by_id.get(pb["id"])
        if cur:
            if cur["title"] != data["title"] or (cur.get("body") or "") != data["body"]:
                api("PATCH", f"/repos/{repo}/issues/{cur['number']}", data)
                print(f"updated #{cur['number']} {pb['title']}")
            else:
                print(f"current #{cur['number']} {pb['title']}")
            numbers[pb["id"]] = cur["number"]
        else:
            new = api("POST", f"/repos/{repo}/issues", data)
            numbers[pb["id"]] = new["number"]
            print(f"created #{new['number']} {pb['title']}")
    rows = ["| Step | Playbook | Trigger | Timebox | Call it off when | Done when |", "|---|---|---|---|---|---|"]
    for pb in playbooks():
        h = pb["hdr"]
        rows.append(f"| {pb['id']} | #{numbers[pb['id']]} | {one_line(h.get('Trigger', ''), 110)} | {one_line(h.get('Timebox', ''), 60)} | "
                    f"{one_line(pb['calloff'], 170) or '—'} | {one_line(pb['done'], 170) or '—'} |")
    body = ("The hunt as a sequence of procedures. Each row links to the issue that holds the full playbook: its steps, decision points, "
            "timebox and the rule for calling it off. `scripts/sane status` in a session names the row that applies now.\n\n"
            + "\n".join(rows) +
            "\n\n### Clocks\n\n| Unit | Clock | When it runs out |\n|---|---|---|\n"
            "| Checklist card, cost low / medium / high | 20 / 45 / 120 minutes | close negative, park, promote to candidate, or one written extension |\n"
            "| Hypothesis | 45 minutes to a decisive experiment | park with what is missing |\n"
            "| Verification | 45 minutes | park with the conditions observed |\n"
            "| Chain attempt | 90 minutes | back to parked, missing link named |\n"
            "| Known CVE, per product | 60 minutes | negative or parked on the CVE card |\n"
            "| Research block, per deployment | 3 hours | change deployment or lens |\n\n"
            "The flow is drawn in [`FLOW.md`](../blob/main/FLOW.md); the division of work across agents is in "
            "[`docs/10-operations.md`](../blob/main/docs/10-operations.md).\n\n---\nRegenerated by `scripts/gh_issues.py sync`.")
    title = "Run-sheet: the hunt, step by step"
    rs = existing(repo, "run-sheet").get(title)
    if rs:
        api("PATCH", f"/repos/{repo}/issues/{rs['number']}", {"body": body})
        print(f"updated #{rs['number']} {title}")
    else:
        new = api("POST", f"/repos/{repo}/issues", {"title": title, "body": body, "labels": ["run-sheet"]})
        print(f"created #{new['number']} {title}")
    print(f"https://github.com/{repo}/issues?q=label%3Aplaybook")


def cmd_list(repo):
    for t, i in sorted(existing(repo, "playbook").items()):
        print(f"#{i['number']:<4} {i['state']:6} {t}  {i['html_url']}")


def cmd_runsheet(repo, name):
    info = api("GET", f"/repos/{repo}")
    if not info.get("private"):
        sys.exit(f"{repo} is public. An engagement run-sheet names a private programme: it goes only to a private repository.")
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import sanelib as L
    if name not in L.list_engagements():
        sys.exit(f"no such engagement: {name}")
    eng = L.Engagement(name)
    m = eng.meta
    lines = [f"Programme: **{m.get('programme')}** {m.get('programme_url', '')}", "",
             f"Authorised: {'yes' if m['authorisation'].get('confirmed') else 'NOT CONFIRMED'} — {m['authorisation'].get('basis', '')}",
             f"Rate: {m.get('rate_limit_rps')}/s · required headers: {', '.join(m.get('required_headers') or []) or 'none'} · "
             f"exclusions: {', '.join(m.get('exclusions') or []) or 'none'}", "",
             "Tick a step when its **Done when** holds. Each step's timebox and call-off rule are in its playbook.", ""]
    for pb in playbooks():
        if pb["n"] >= 13:
            continue
        lines.append(f"- [ ] **{pb['title']}** — timebox {one_line(pb['hdr'].get('Timebox', ''), 60)} — done when: {one_line(pb['done'], 200)}")
    lines += ["", "Always in force: PB-13 (signals: record a fact, re-plan) and PB-14 (incidents: stop, record, tell the operator).",
              "", "### Findings", "", "| Id | Title | Severity | State | HackerOne report |", "|---|---|---|---|---|", "| | | | | |"]
    for name_, (color, desc) in LABELS.items():
        api("POST", f"/repos/{repo}/labels", {"name": name_, "color": color, "description": desc})
    new = api("POST", f"/repos/{repo}/issues", {"title": f"[{eng.name}] run-sheet", "body": "\n".join(lines), "labels": ["run-sheet"]})
    print(f"created {new['html_url']}")


# ---------------------------------------------------------------- build visibility: chapters and the tracker

COMPONENTS = [
    ("Applicability engine and console", ["scripts/sane", "scripts/sanelib.py"], "scope, assets, facts, the planner, lanes, briefs, timeboxes, findings, the report gate"),
    ("Fingerprinter", ["scripts/fingerprint.py"], "about twenty requests per host: tier, technology and versions, auto-facts, clustering"),
    ("CVE lookup", ["scripts/cve.py"], "product version to ranked CVEs: NVD, CISA KEV, EPSS, HexBrain, nuclei templates"),
    ("Scope guard and hooks", ["scripts/scope_guard.py", ".claude/hooks/pre-tool.sh", ".claude/settings.json"], "blocks out-of-scope requests, unthrottled scanners, forbidden modes, missing required headers"),
    ("Fact and lane vocabularies", ["checklist/_facts.json", "checklist/_lanes.json"], "what a card may require; how the hunt is divided"),
    ("Disclosed-report library", ["kb/data/index.jsonl", "kb/reports/README.md", "kb/programs.md"], "15,219 HackerOne reports by class and programme, linked"),
    ("Playbooks PB-00 to PB-14", ["playbooks/README.md", "playbooks/PB-14-incidents.md"], "SOC-style procedures with timeboxes and call-off rules"),
    ("Method and flow", ["CLAUDE.md", "START.md", "FLOW.md"], "standing orders, the method, the diagrams"),
    ("Standards", ["docs/02-reportability.md", "docs/04-evidence-standard.md", "docs/05-reporting-style.md", "docs/06-severity.md", "docs/07-graveyard.md", "docs/10-operations.md", "docs/11-item-schema.md"], "reportability, evidence, reporting style, severity, graveyard, operations, card schema"),
    ("Skills (17) and subagents (9)", [".claude/skills/hunt/SKILL.md", ".claude/agents/class-hunter.md", "scripts/build_claude.py"], "generated from src/ with the playbooks embedded"),
    ("Saved workflows", [".claude/workflows/squad-hunt.js", ".claude/workflows/cve-sweep.js", ".claude/workflows/research-lenses.js", ".claude/workflows/verify-finding.js"], "fan out lanes, CVE sweeps, research lenses; three-lens verification"),
    ("Report template and gate", ["templates/report.md"], "the submission skeleton; `scripts/sane gate` checks readiness"),
    ("Tests", ["scripts/selftest.sh", "scripts/tests/test_scope_guard.py", "scripts/tests/test_workflows.js"], "end-to-end self-test, 54 guard cases, workflow logic under stubs"),
]


def chapter_state():
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import sanelib as L
    lanes = json.load(open(os.path.join(ROOT, "checklist", "_lanes.json")))["lanes"]
    stats = json.load(open(os.path.join(ROOT, "kb", "data", "stats.json")))["classes"]
    out = []
    for c in L.classes():
        if not c.get("chapter"):
            continue
        p = os.path.join(ROOT, "checklist", c["slug"] + ".md")
        lane = next((n for n, d in lanes.items() if c["slug"] in d["chapters"]), "—")
        row = {"slug": c["slug"], "prefix": c["prefix"], "name": c["name"], "lane": lane, "written": False, "items": [], "errors": None,
               "gate": "", "stats": stats.get(c["slug"], {})}
        if os.path.exists(p):
            ch = L.parse_chapter(p)
            err, _ = L.lint_chapter(ch)
            row.update(written=not err and bool(ch["items"]), errors=len(err), gate=ch["meta"].get("Applies when", ""),
                       items=[(it["id"], it["title"], it["meta"].get("Requires", ""), it["cost"]) for it in ch["items"]])
        out.append(row)
    return out


def chapter_issue(row, reviewed):
    st = row["stats"]
    lib = (f"{st.get('reports', 0):,} disclosed reports in the library, {st.get('paid', 0):,} paid, median paid bounty "
           f"${st.get('median_bounty', 0):,.0f}, top ${st.get('max_bounty', 0):,.0f} — [`kb/reports/{row['slug']}.md`](../blob/main/kb/reports/{row['slug']}.md)")
    if row["written"]:
        status = f"**Written** — {len(row['items'])} test cards, lints with 0 errors." + (" **Adversarial review: done.**" if reviewed else " Adversarial review: in the queue.")
    elif row["errors"] is not None:
        status = f"**Being written** — a draft is on disk and does not lint yet ({row['errors']} schema errors); the writer is still on it."
    else:
        status = "**Queued** — a writer agent will take it, then an adversarial reviewer checks technique accuracy, gate precision, safety and prior art."
    b = [f"> {status}", "",
         f"- File: [`checklist/{row['slug']}.md`](../blob/main/checklist/{row['slug']}.md)",
         f"- Lane: `{row['lane']}` (see [`docs/10-operations.md`](../blob/main/docs/10-operations.md))",
         f"- Chapter gate (`Applies when`): `{row['gate'] or 'set when written'}`",
         f"- Prior art: {lib}", ""]
    if row["items"]:
        b += ["### Test cards", "", "Each is one falsifiable claim. The planner queues a card on an asset only when the asset's facts satisfy `Requires`.", "",
              "| Card | Claim | Requires | Cost |", "|---|---|---|---|"]
        for iid, title, req, cost in row["items"]:
            b.append(f"| {iid} | {title} | `{req or '—'}` | {cost} |")
    b += ["", "---", "Regenerated by `scripts/gh_issues.py chapters`. The card schema is [`docs/11-item-schema.md`](../blob/main/docs/11-item-schema.md)."]
    return "\n".join(b)


def milestone(repo, title, desc):
    for m in api("GET", f"/repos/{repo}/milestones?state=all&per_page=100"):
        if m["title"] == title:
            return m["number"]
    return api("POST", f"/repos/{repo}/milestones", {"title": title, "description": desc})["number"]


def cmd_chapters(repo, reviewed_slugs):
    for name, (color, desc) in {"chapter": ("5319e7", "One checklist chapter of test cards"), "build": ("0e8a16", "Build progress of this repository"),
                                "lane:known": ("bfd4f2", ""), "lane:infra": ("bfd4f2", ""), "lane:authz": ("bfd4f2", ""),
                                "lane:logic": ("bfd4f2", ""), "lane:injection": ("bfd4f2", ""), "lane:client": ("bfd4f2", "")}.items():
        api("POST", f"/repos/{repo}/labels", {"name": name, "color": color, "description": desc})
    ms = milestone(repo, "Checklist: 36 chapters", "Every vulnerability class as a chapter of applicability-gated test cards")
    rows = chapter_state()
    have = existing(repo, "chapter")
    by_slug = {}
    for t, i in have.items():
        m = re.search(r"\(`([a-z-]+)`\)\s*$", t)
        if m:
            by_slug[m.group(1)] = i
    numbers, changed = {}, 0
    for row in rows:
        title = f"Chapter {row['prefix']} · {row['name']} (`{row['slug']}`)"
        reviewed = row["slug"] in reviewed_slugs
        data = {"title": title, "body": chapter_issue(row, reviewed), "labels": ["chapter", f"lane:{row['lane']}"], "milestone": ms,
                "state": "closed" if (row["written"] and reviewed) else "open"}
        cur = by_slug.get(row["slug"])
        if cur:
            numbers[row["slug"]] = cur["number"]
            if (cur.get("body") or "") != data["body"] or cur["state"] != data["state"]:
                api("PATCH", f"/repos/{repo}/issues/{cur['number']}", data)
                changed += 1
        else:
            st = data.pop("state")
            new = api("POST", f"/repos/{repo}/issues", data)
            numbers[row["slug"]] = new["number"]
            if st == "closed":
                api("PATCH", f"/repos/{repo}/issues/{new['number']}", {"state": "closed"})
            changed += 1
    # the tracker
    written = [r for r in rows if r["written"]]
    cards = sum(len(r["items"]) for r in written)
    pbs = {t.split(" ")[0]: i["number"] for t, i in existing(repo, "playbook").items()}
    b = ["What exists in this repository and what is still being written. Regenerated automatically; the commit history is the detail.", "",
         "### Components", ""]
    for name, paths, desc in COMPONENTS:
        ok = all(os.path.exists(os.path.join(ROOT, p)) for p in paths)
        b.append(f"- [{'x' if ok else ' '}] **{name}** — {desc} (" + ", ".join(f"[`{p}`](../blob/main/{p})" for p in paths[:3]) + ")")
    b += ["", f"### Checklist chapters: {len(written)} of {len(rows)} written, {cards} test cards", "",
          "| Chapter | Lane | State | Cards | Issue |", "|---|---|---|---|---|"]
    for r in rows:
        state = ("reviewed" if r["slug"] in reviewed_slugs else "written, review queued") if r["written"] else ("draft on disk" if r["errors"] is not None else "queued")
        b.append(f"| {r['prefix']} · {r['name']} | `{r['lane']}` | {state} | {len(r['items']) or ''} | #{numbers[r['slug']]} |")
    if pbs:
        b += ["", "### Playbooks", "", " · ".join(f"{k} #{v}" for k, v in sorted(pbs.items()))]
    b += ["", "---", "Regenerated by `scripts/gh_issues.py chapters`."]
    title = "Build tracker: what exists and what is in progress"
    tr = existing(repo, "build").get(title)
    body = "\n".join(b)
    if tr:
        if (tr.get("body") or "") != body:
            api("PATCH", f"/repos/{repo}/issues/{tr['number']}", {"body": body})
        n = tr["number"]
    else:
        n = api("POST", f"/repos/{repo}/issues", {"title": title, "body": body, "labels": ["build"]})["number"]
    print(f"chapters: {len(written)}/{len(rows)} written, {cards} cards, {len(reviewed_slugs)} reviewed; {changed} issue(s) updated; tracker #{n}")
    print(f"https://github.com/{repo}/issues/{n}   https://github.com/{repo}/milestone/{ms}")


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    repo = None
    if "--repo" in args:
        i = args.index("--repo")
        repo = args[i + 1]
        del args[i:i + 2]
    repo = repo or default_repo() or sys.exit("no --repo given and no GitHub origin found")
    if args[0] == "sync":
        cmd_sync(repo)
    elif args[0] == "list":
        cmd_list(repo)
    elif args[0] == "chapters":
        # scripts/gh_issues.py chapters [--reviewed slug,slug,...]   one issue per chapter, a milestone, and the build tracker
        reviewed = set()
        if "--reviewed" in args:
            reviewed = {s for s in args[args.index("--reviewed") + 1].split(",") if s}
        rf = os.path.join(ROOT, "checklist", "_reviewed.txt")
        if os.path.exists(rf):
            reviewed |= {l.strip() for l in open(rf, encoding="utf-8") if l.strip() and not l.startswith("#")}
        cmd_chapters(repo, reviewed)
    elif args[0] == "runsheet" and len(args) > 1:
        if "--repo" not in sys.argv:
            sys.exit("runsheet needs an explicit --repo owner/private-evidence-repo")
        cmd_runsheet(repo, args[1])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
