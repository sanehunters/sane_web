# PB-05 · Plan: the applicability matrix

| | |
|---|---|
| **Trigger** | Facts were settled or changed; a new asset was fingerprinted; a blocker was lifted |
| **Entry state** | At least one fingerprinted deployment |
| **Runs as** | Main session |
| **Timebox** | 10 minutes |
| **Output on disk** | nothing new: the plan is computed from facts every time. `plan.csv` on request |
| **Next** | PB-06 |

The planner evaluates every checklist item against every asset's facts and gives each pair exactly one status.
You do not choose what applies; you make sure the facts are right and read the result.

## Steps

1. **Run it.** `scripts/sane plan`
   Read the last lines first: how large the unfiltered matrix was, how many tests are queued, how many were closed
   and why.
2. **Audit the closures.** `scripts/sane plan --why | less`
   Every `n/a`, `blocked` and `excluded` row carries its reason and the evidence behind the fact. Scan for
   closures that rest on a weak fact (evidence like "not seen on /"). Fix the fact, not the status.
3. **Lift what can be lifted.** `scripts/sane blockers` lists the capabilities whose absence blocks the most
   value (a second account, an OOB host, a browser). `scripts/sane probes` lists facts still unknown.
4. **Read the queue.** `scripts/sane next -n 20`
   Order is expected value: how often the class is paid and how much, the item's severity range, the asset's
   weight, divided by cost. It is a default, not a law. Move something up when PB-04 gave you a specific reason.
5. **Decide the split.** If more than one deployment has a queue and subagents are available, give each
   deployment to one `class-hunter` and keep verification in the main session. Never two hunters on one
   deployment: they share the rate limit and trip each other's sessions.

## Decision points

- The queue is dominated by one chapter → fine if that is where the application's risk is; otherwise check
  whether a fact is too generous (for example `params=1` opening every injection item on a static-looking host).
- An item you believe applies is `n/a` → read its reason; if the fact is wrong, set it with evidence. If the
  item's `Requires` is wrong, that is a checklist defect: note it in `notes.md` for a schema fix; do not mark by hand.
- Everything is `probe` → PB-04 has not been done for that deployment.
- The queue is empty and nothing is blocked → PB-08.

## Call it off when

- Not applicable: this playbook is ten minutes of reading.

## Done when

You can say in two sentences what will be tested first and why, and what is blocked on what.

## Hand to the operator when

- `sane blockers` shows a capability only they can supply.
