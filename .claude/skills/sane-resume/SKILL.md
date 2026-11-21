---
name: sane-resume
description: Resume an engagement in a new session or after context compaction — rebuild working context from disk and continue with the next action. Use when the user says continue, resume, pick up where we left off, or at the start of any session with an active engagement.
---

<!-- GENERATED from src/skills/sane-resume.md by scripts/build_claude.py. Edit that file or the included playbook, then rebuild. -->

# /sane-resume

State is on disk. Rebuild from it; do not rely on what you think happened.

```bash
scripts/sane status                                   # phase and next playbook
E=$(scripts/sane env | sed 's/^source "//; s#/env.sh"$##')
tail -40 "$E/notes.md"                                # the notebook
tail -25 "$E/logs/journal.jsonl"                      # the last actions
[ -f "$E/state-snapshot.md" ] && tail -40 "$E/state-snapshot.md"   # written before the last compaction
scripts/sane finding list; scripts/sane hyp list
scripts/sane next -n 10
```

Then, in order:

1. An item in `doing` → finish it or close it by the timebox rules (`playbooks/README.md`).
2. A `candidate` → `/verify`.
3. A `verified` finding without a ready report → `/report`.
4. Otherwise the playbook `sane status` names.

Re-check the things that go stale between sessions before sending anything: sessions in `accounts/*.headers`
(log in again if expired), the scope (`scripts/sane scope show`; programmes change it), and the authorisation line.
If the programme's scope or policy may have changed, re-run `scripts/sane scope import-h1` and read the diff.

Say in two sentences where things stand and what you are doing next, then do it.
