# PB-06 · Hunt: one card at a time

| | |
|---|---|
| **Trigger** | `scripts/sane next` returns items |
| **Entry state** | Facts settled for the deployment; accounts recorded where the items need them |
| **Runs as** | Main session, or one `class-hunter` agent per deployment |
| **Timebox** | per card: 20 minutes (`low`), 45 (`medium`), 120 (`high`) |
| **Output on disk** | a row in `coverage.csv` for every card opened; raw evidence under `evidence/<host>/<item>/` |
| **Next** | PB-09 when a card yields a candidate; PB-10 when it yields a primitive; otherwise the next card |

The loop is deliberately small. A card is one falsifiable claim about the target. You try to make it true, and
you write down which way it went and why.

## Steps

1. **Take the top card.** `scripts/sane next`, then `scripts/sane card <ITEM> <asset>`.
   The card prints the claim, where to aim, how to test, what counts as proof, the known false positives, and the
   disclosed reports that show the technique paying.
2. **Start the clock.** `scripts/sane start <asset> <ITEM>` creates `evidence/<asset>/<ITEM>/` and stamps the time.
3. **Aim before firing.** From `recon/<host>/map.md` pick the two or three endpoints where this claim is most
   likely true. A card run against the endpoint the developer hardened first teaches nothing. If a prior-art
   report matches the feature in front of you, read it: `scripts/sane kb show <id>`.
4. **Run the test as the card's How says**, adapted to the real endpoint. Every command that touches the target
   starts with `source "$E/env.sh"` and carries `"${HDR[@]}"`. Save raw output, do not retype it:
   `curl -sS "${HDR[@]}" $A ... -D "$E/evidence/$H/<ITEM>/01-resp.headers" -o "$E/evidence/$H/<ITEM>/01-resp.body"`
5. **Compare with a control.** One request that should succeed and one that should fail, alongside the test
   request. Without the control you cannot tell a finding from the application's normal behaviour.
6. **Decide and record.** Exactly one of:

   | Outcome | Command |
   |---|---|
   | The control holds | `scripts/sane mark <asset> <ITEM> negative --note "<the mechanism: which check, where, how observed>"` |
   | A signal that needs proof | `scripts/sane mark <asset> <ITEM> candidate --note "<what was seen; what would prove it>"` → PB-09 now |
   | Real, without standalone impact | `scripts/sane mark <asset> <ITEM> parked --note "<what it would chain with>"` → PB-10 later |
   | Real, but a duplicate is likely | `scripts/sane mark <asset> <ITEM> dup-risk --note "<why: scanner-findable, old, already in hacktivity>"` |
   | Deliberately not run | `scripts/sane mark <asset> <ITEM> skipped --note "<risk or budget reason>"` |

7. **Anything else you noticed** goes in `notes.md` as one line, and into PB-13's table if it is a known signal.
   Then the next card.

## Decision points

- The card's precondition turns out false on this asset (no such feature after all) → do not mark it negative.
  Fix the fact: `scripts/sane fact set <asset> <tag>=0 --ev "..."`. The planner closes this card and its siblings.
- You find the feature the card needs on a different endpoint or host → test there; record the asset where it
  lives.
- A WAF blocks the payload → three attempts at an encoding or context change guided by `find_bypasses` (HexBrain)
  or the chapter's bypass notes, then park with the note "WAF: <vendor>, blocked on <pattern>". Fighting a WAF is
  rarely the best use of the hour.
- The test would change or destroy data, lock an account or message real users → do it only on your own account
  B, or skip with the reason.
- 429s or blocks start → PB-14.
- The same idea would clearly apply to a sibling endpoint → test the sibling inside the same card; note both.

## Call it off when

- The card's timebox expires: close it negative, park it, promote it, or extend once with a written reason
  (`playbooks/README.md`, "Timeboxes and calling it off").
- Three distinct techniques hit the same generic control.
- Continuing would need a volume of requests the programme rate does not allow in the timebox.

## Done when

The card has a hand-written status with a note that a stranger could check, and its evidence is on disk.

## Hand to the operator when

- A card needs something physical or personal: an SMS code, a payment, a second device.
- You believe you have a critical. Verify first (PB-09), then tell them at once; they may want to submit before
  anything else happens.
