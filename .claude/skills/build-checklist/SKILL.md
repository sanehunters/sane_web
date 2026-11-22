---
name: build-checklist
description: Write and review the checklist chapters that are still missing, in draft or unreviewed — the maintenance task that builds or extends the checklist itself, not a hunt. Use when the user says continue writing the checklist, finish the chapters, resume the build, add a chapter, or when scripts/chapters_todo.py shows work left.
---

<!-- GENERATED from src/skills/build-checklist.md by scripts/build_claude.py. Edit that file or the included playbook, then rebuild. -->

# /build-checklist — finish or extend the checklist

This is repository maintenance: it writes test cards. It sends nothing to any target.

`$ARGUMENTS`: empty for everything that is left; chapter slugs to restrict (`/build-checklist xss csrf`); `rereview`
to review chapters again.

## 1. See what is left

```bash
scripts/chapters_todo.py          # every chapter: missing | draft | written | reviewed
```

- `missing` or `draft`: the file does not exist or does not lint. It needs a writer, then a reviewer.
- `written`: lints clean, not yet in `checklist/_reviewed.txt`. It needs a reviewer.
- `reviewed`: done.

If a previous build was interrupted, drafts that never reached `main` are on the `wip` branch. Bring them into the
working tree first so the writers continue them instead of starting over:

```bash
git fetch origin wip && git checkout origin/wip -- checklist/    # then: git reset -q checklist/   (keep them unstaged)
```

## 2. Launch

Running this skill is the user's request for multi-agent orchestration. Build the args and run the saved workflow
`write-chapters` with them (pass the JSON as a value, not a string):

```bash
scripts/chapters_todo.py --json                                   # writers on the session model
scripts/chapters_todo.py --json --model opus --effort max         # writers on a named model and effort
scripts/chapters_todo.py --json --only xss,csrf                   # some chapters only
scripts/chapters_todo.py --json --rereview                        # review everything again
```

Reviewers run on `--review-model` (default `opus`) at `--review-effort` (default `max`).

Each writer reads its brief from `src/chapters.json` (how many cards, what the chapter must cover, gate guidance),
the schema (`docs/11-item-schema.md`), the fact vocabulary (`checklist/_facts.json`), the reference chapter
(`checklist/ssrf.md`) and the class's disclosed reports (`kb/reports/<slug>.md`), writes
`checklist/<slug>.md`, and lints it to zero errors. Each reviewer then attacks the chapter: technique accuracy,
gate precision, safety, proof and false positives, severity, prior-art relevance, coverage, structure; it fixes
what it finds in place. Six agents run at a time, most-paid classes first.

To add a chapter that does not exist yet: add the class to `kb/classes.json` (slug, prefix, `chapter: true`), give
it a lane in `checklist/_lanes.json`, add its brief to `src/chapters.json`, run `scripts/kb_build.py`, then launch.

## 3. Keep GitHub in step while it runs

```bash
GH_TOKEN=... JOURNALS="<transcript dir>/journal.jsonl" scripts/publish_progress.sh --loop 300
```

Every round: workflow results are folded into `checklist/_buildlog.jsonl` and `checklist/_reviewed.txt`; chapters
that lint are committed to `main` and pushed; a snapshot of the whole working tree, drafts included, goes to the
branch `wip`; the chapter issues and the build tracker are updated. Stop it with `touch scripts/.publish.stop`.
The transcript directory is printed when the workflow launches.

## 4. When it returns

1. `scripts/build_log.py <journal>` then read `checklist/_buildlog.jsonl`: every `missing_tags` entry is a writer
   or reviewer saying a card is gated too broadly because the vocabulary lacks a fact. For each one worth having,
   add the fact to `checklist/_facts.json` (kind, group, `needs`, description, cheapest probe), tighten the cards
   that asked for it, and if the fingerprinter can detect it, teach `scripts/fingerprint.py`.
2. `scripts/sane lint` must report zero errors across all chapters.
3. `scripts/selftest.sh` must pass.
4. `scripts/chapter_index.py`, `scripts/build_claude.py`, then commit and push; `scripts/gh_issues.py chapters`
   closes the issues of reviewed chapters.
5. Anything still `missing` or `draft` (an agent died, a limit was hit): run this skill again. It only launches
   what is left.
