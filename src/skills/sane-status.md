---
name: sane-status
description: Show where the engagement stands — phase, next playbook, scope and asset counts, coverage, items in progress and overdue, candidates, findings, open hypotheses, blockers. Use when the user asks for status, progress, coverage, or what is left.
---

# /sane-status

```bash
scripts/sane status          # phase, next action, counts, anything running past its timebox
scripts/sane coverage        # every chapter by status
scripts/sane blockers        # capabilities whose absence blocks the most value
scripts/sane finding list    # findings and their states
scripts/sane hyp list        # open hypotheses
```

Report to the user in this order, briefly:

1. Phase and the next action (with its playbook).
2. Findings: verified, ready, submitted.
3. Candidates awaiting verification and items past their timebox, if any.
4. Coverage in one sentence: tested, queued, closed by gating.
5. What is blocked on them.

A claim of coverage is the `coverage` table and nothing else. Do not summarise from memory.
