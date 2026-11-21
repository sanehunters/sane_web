# Playbooks

A playbook is a procedure for one situation: what triggers it, what to do in order, where to branch, when to stop,
what it must leave on disk and which playbook comes next. They are written the way a SOC writes runbooks, because
the problem is the same: an operator arriving cold must be able to act correctly without rediscovering the method.

`scripts/sane status` always names the playbook that applies now. `scripts/sane playbook PB-NN` prints one.
Each playbook is mirrored as a GitHub issue in this repository (label `playbook`), so the procedure can be read,
discussed and amended where the work is tracked; `scripts/gh_issues.py sync` regenerates the issues from these
files. The files are the source of truth.

## The set

| Id | Playbook | Trigger | Timebox | Next |
|---|---|---|---|---|
| [PB-00](PB-00-engage.md) | Engage: authorisation and policy | a new programme | 20 min | PB-01 |
| [PB-01](PB-01-scope.md) | Scope: import and lock | authorisation recorded | 15 min | PB-02 |
| [PB-02](PB-02-recon.md) | Recon: find the assets | scope locked | 60 min, then background | PB-03 |
| [PB-03](PB-03-fingerprint.md) | Fingerprint, tier and cluster | assets without a fingerprint | 30 min | PB-04, PB-07 |
| [PB-04](PB-04-map.md) | Map the application and settle the facts | items waiting on unknown facts | 90 min per deployment | PB-05 |
| [PB-05](PB-05-plan.md) | Plan: the applicability matrix | facts settled or changed | 10 min | PB-06 |
| [PB-06](PB-06-hunt.md) | Hunt: one card at a time | a non-empty queue | per card: 20 / 45 / 120 min | PB-09, PB-10 |
| [PB-07](PB-07-cve.md) | CVE: version to verified exploit | a product with a version | 60 min per product | PB-09 |
| [PB-08](PB-08-research.md) | Research: hunting for novel bugs | queue empty, or a rich target | 3 h blocks | PB-09 |
| [PB-09](PB-09-verify.md) | Verify a candidate | any `candidate` | 45 min | PB-10, PB-11 |
| [PB-10](PB-10-chain.md) | Chain and escalate impact | a verified primitive or a parked item | 90 min | PB-11 |
| [PB-11](PB-11-report.md) | Report: write, gate, hand over | a verified finding | 60 min | PB-12 |
| [PB-12](PB-12-after-submission.md) | After submission: triage, retest, lessons | a submitted report changes state | 30 min per event | PB-06 |
| [PB-13](PB-13-signals.md) | Signals: when you see X, do Y | any observation during any phase | — | varies |
| [PB-14](PB-14-incidents.md) | Incidents: blocked, banned, broke something, saw data you should not | any of those | immediate | varies |

[`FLOW.md`](../FLOW.md) draws how they connect.

## Format

Every playbook has the same parts, in this order.

| Part | Contains |
|---|---|
| **Header table** | Trigger · Entry state · Runs as (main session or which agent) · Timebox · Output on disk · Next |
| **Steps** | numbered; each is one action with its command, what to expect and what to record |
| **Decision points** | `if <observation> → <playbook or step>`; the branches are part of the procedure, not an afterthought |
| **Call it off when** | the stop rules: time, request budget, signals that the path is dead or unsafe |
| **Done when** | the exit criteria, checkable on disk |
| **Hand to the operator when** | the things only a human can supply or decide |

## Timeboxes and calling it off

A hunter's scarcest resource is attention, and the commonest way to waste it is to keep pushing on an idea because
of the time already spent. Every unit of work here has a clock.

| Unit | Clock | Where it is tracked |
|---|---|---|
| Checklist item, cost `low` | 20 minutes | `scripts/sane start` stamps it; `sane status` and the prompt hook flag it OVERDUE |
| Checklist item, cost `medium` | 45 minutes | same |
| Checklist item, cost `high` | 120 minutes | same |
| Hypothesis (PB-08) | 45 minutes to a decisive experiment | `sane hyp` ledger |
| Playbook | the Timebox in its header | the session |

When a clock runs out there are exactly four moves, and continuing silently is not one of them:

1. **Close it negative**, with the mechanism that stopped you: `sane mark <asset> <item> negative --note "..."`.
2. **Park it**, when the primitive is real and the impact is missing: `... parked --note "would chain with ..."`.
3. **Promote it** to `candidate` and go to PB-09, when there is a signal worth verifying.
4. **Extend once**, by one more timebox, after writing in `notes.md` the specific observation that justifies it
   and the experiment that will settle it. A second extension needs the operator.

Signs a path is dead and should be called off before the clock: three different techniques produced the same
generic error; the control is implemented in a framework default rather than in application code; the behaviour is
documented as intended; the only remaining idea requires an assumption you cannot test in scope.

## Session timeline for a fresh programme

A realistic first day. Adjust to the size of the scope; keep the proportions.

| Clock | Phase | Playbook | Leaves on disk |
|---|---|---|---|
| 0:00–0:20 | Authorisation, policy read, rules recorded | PB-00 | `engagement.json` rules, `policy.md` |
| 0:20–0:35 | Scope imported, checked against the policy text | PB-01 | `scope.json` |
| 0:35–1:30 | Passive recon; ports on IP assets | PB-02 | `assets.json`, `recon/` |
| 1:30–2:00 | Fingerprint everything; tiers and clusters | PB-03 | `facts/`, `recon/<host>/tech.json` |
| 2:00–2:30 | CVE pass on every product with a version (cheap, sometimes a quick win) | PB-07 | `recon/<host>/cves.json` |
| 2:30–4:00 | Accounts, authenticated walk of the top deployment, facts settled | PB-04 | `facts/`, `recon/<host>/map.md` |
| 4:00–4:10 | Plan | PB-05 | the queue |
| 4:10–end | Hunt in card order; verify candidates as they appear; report what survives | PB-06, PB-09, PB-10, PB-11 | `coverage.csv`, `findings/` |
| when the queue thins | Research on the richest deployment | PB-08 | `hypotheses.jsonl` |

Recon keeps running in the background after 1:30; new assets re-enter at PB-03.
