---
name: squad
description: Divide the engagement across agents and run them — plan which deployments and lanes run side by side, launch mappers, lane hunters, CVE specialists or researchers with complete briefs, verify every candidate with three independent lenses, and collect the results. Use when several deployments or lanes have work queued, when the user asks to go faster, fan out, parallelise, use agents, or run the whole hunt.
---

# /squad — divide and run

`$ARGUMENTS`: empty for a hunt wave; `cve` for a known-vulnerability sweep; `research <host>` for the research
lenses; `verify F-NNN` for one finding.

You are the coordinator. You plan, brief, launch, read returns against the disk, and decide. You do not hand off
decisions about scope, about whether something is a finding, or about what the operator is told.

## 1. Preconditions

```bash
scripts/sane status      # authorised, scope present, assets fingerprinted
scripts/sane lanes       # the queue by deployment and lane
scripts/sane blockers    # what a missing account or capability is costing
```

If authorisation or scope is missing, do PB-00 and PB-01 yourself first. Nothing is delegated before they exist:
`scripts/sane brief` refuses to print without an authorisation basis.

## 2. Plan the wave

```bash
scripts/sane squad                      # who runs now, on what, at what rate share; what waits and why
scripts/sane squad --pairs 2            # when two account pairs are recorded: two authenticated lanes at once
scripts/sane squad app.example.com      # restrict to one or more deployments
```

Read the plan. It follows the rules in the operations document included below: unauthenticated lanes (`known`,
`infra`) run beside anything; authenticated lanes run one per account pair per deployment; the programme rate is
divided among the agents on a deployment; a deployment without a map gets a mapper first.

## 3. Launch

Running this skill is the user's request for multi-agent orchestration. Use the Workflow tool with the saved
workflow and pass the JSON as `args` (as a JSON value, not a string):

| Goal | Build the args | Workflow `name` |
|---|---|---|
| A hunt wave | `scripts/sane squad --json` | `squad-hunt` |
| Known-vulnerability sweep | `scripts/sane squad --mode cve --json` | `cve-sweep` |
| Novel-bug research on one deployment | `scripts/sane squad --mode research <host> --json` | `research-lenses` |
| Verify one finding | `scripts/sane squad --mode verify --finding F-NNN --json` | `verify-finding` |

If the Workflow tool is not available, do the same with the Agent tool: one call per row of the plan, all in a
single message so they run together, each with the output of
`scripts/sane brief <agent> <host> [--lane L] [--lens X] [--finding F-NNN] --share <agents on that deployment>` as
its prompt and the agent type named in the plan.

Add to a brief, below what the tool printed, anything you know that is not on disk yet. Never add your
expectation of the result.

## 4. While it runs

Keep working: read the maps as they land, register a second account pair, read the programme's best-paid
write-ups (`/prior-art`), start a report for anything already verified. Do not test the deployments your agents
are on: you would share their sessions and their rate.

## 5. When it returns

Check every return against the disk before acting on it (the table in the operations document, section 6).

- **Survivors** (two of three lenses hold, triager not refuted):
  ```bash
  scripts/sane finding new --title "<working title>" --asset <host> --item <ITEM>
  # write findings/F-NNN/claim.md from the candidate, and verify.json from the verdicts
  scripts/sane finding set F-NNN state=verified reproductions=<n>
  scripts/sane mark <host> <ITEM> finding --finding F-NNN --note "<one line>"
  ```
  Then `/chain` if the triager said `weak`, otherwise `/report`. Tell the operator at once about anything high or
  critical.
- **Killed candidates:** `scripts/sane mark <host> <ITEM> negative|parked --note "<the lens's reason>"`.
- **Agents that did not finish:** their cards are still `todo` or `doing`; close overdue `doing` rows by the
  timebox rules and re-run the lane.
- **New facts and maps:** `scripts/sane plan`, then `scripts/sane squad` again. The next wave is whatever now
  heads the queue, including the lanes that were waiting.

Repeat until `scripts/sane lanes` shows the queues drained, then `/squad research <richest host>`.

## 6. Report to the user

After each wave, in a few lines: what ran on what, how many cards were closed and how, which candidates survived
verification and which were killed and why, what is blocked on them, and what the next wave is.

<!-- include docs/10-operations.md -->
