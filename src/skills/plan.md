---
name: plan
description: Compute and read the applicability matrix — which checklist items apply to which asset, which are n/a and why, what is blocked, what is next. Use after facts change, when the user asks what to test, why something was skipped, or what the coverage is.
---

# /plan — playbook PB-05

| Question | Command |
|---|---|
| What applies where? | `scripts/sane plan` |
| Why was something closed? | `scripts/sane plan --why` (reason and evidence per row) |
| What is still unknown? | `scripts/sane probes` |
| What is blocked on a capability? | `scripts/sane blockers` |
| What should I do now? | `scripts/sane next -n 20` |
| Coverage by chapter | `scripts/sane coverage` |
| One card | `scripts/sane card <ITEM> <asset>` |

The planner is the only thing that decides applicability. If a closure looks wrong, the fact behind it is wrong:
correct it with evidence (`scripts/sane fact set`). If an item's `Requires` looks wrong, note it in `notes.md` as
a checklist defect; do not override by hand.

Report the plan to the user in two or three sentences: how large the unfiltered matrix was, how many tests are
queued, what was closed and on what grounds, and what is blocked.

<!-- include playbooks/PB-05-plan.md -->
