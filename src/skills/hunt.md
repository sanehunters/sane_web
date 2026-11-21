---
name: hunt
description: Run the hunt loop — take the best applicable test card, start its clock, test with a control, record exactly one outcome, repeat. Use when the queue is non-empty and the user says hunt, continue, test, or find bugs.
---

# /hunt — playbook PB-06

`$ARGUMENTS` may name an asset or a class (`/hunt app.example.com`, `/hunt access-control`).

Loop, one card at a time:

1. `scripts/sane next [--asset H] [--class C]`. If candidates are listed first, do `/verify` before anything else.
2. `scripts/sane card <ITEM> <asset>` — read all of it, including "Not a finding when" and the prior art.
3. `scripts/sane start <asset> <ITEM>` — the timebox starts (20 / 45 / 120 minutes by cost).
4. Aim: pick the two or three endpoints from `recon/<host>/map.md` where the claim is most likely true.
5. Test as the card's How says. Every command: `source "$E/env.sh"`, `"${HDR[@]}"`, output saved under
   `$E/evidence/<host>/<ITEM>/`. Always a control request beside the test request.
6. Record one outcome with `scripts/sane mark <asset> <ITEM> <status> --note "..."`:
   `negative` (name the mechanism) · `candidate` (→ `/verify` now) · `parked` (→ `/chain` later) · `dup-risk` · `skipped`.
7. If the card's precondition was false, fix the fact instead of marking: `scripts/sane fact set ...`.

When the clock runs out: close, park, promote, or extend once with a written reason. Never drift.

For several deployments, give each to one `class-hunter` agent. Never two on one deployment.

Stop and switch to PB-14 on rate limiting, blocks, degradation, or any third-party data in a response.

<!-- include playbooks/PB-06-hunt.md -->

<!-- include playbooks/PB-13-signals.md -->
