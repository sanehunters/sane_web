# START — the method

Read this once per session. It explains how the pieces fit, so that the playbooks and cards make sense when you
meet them one at a time.

## 1. What this is for

The operator holds invitations to HackerOne programmes. Each has a scope: domains, wildcards, IP ranges. The job
is to find vulnerabilities in those assets that the programme will accept and pay for, prove them without harm,
and write them up so well that triage is quick. Everything in this repository serves one of four needs:

| Need | Served by |
|---|---|
| Stay inside the rules | the scope file, the guard hook, PB-00, PB-01, PB-14 |
| Spend effort where a bug is likely | fingerprinting, facts, the planner, the report library's priors |
| Find the bug | the checklist cards, the CVE flow, the research lenses |
| Get it accepted | three-lens verification, chaining, the reporting standard, the gate |

## 2. The idea that matters most: facts gate tests

A checklist that is run top to bottom on every asset wastes most of its effort: GraphQL tests on a static site,
upload tests where nothing uploads, SAML tests on an app with no SSO. It also buries the few tests that matter
under hundreds that do not. This repository does not work that way.

- Every asset has a **facts** record: what kind of thing it is, what it runs, which features it has. A fact is
  `yes`, `no` or unknown, and carries the evidence it rests on. The vocabulary is `checklist/_facts.json`.
- Every checklist item declares a **`Requires`** expression over those facts, and every chapter an
  **`Applies when`** gate.
- The **planner** (`scripts/sane plan`) evaluates each item against each asset and gives the pair one status:

  | Status | Meaning | What you do |
  |---|---|---|
  | `todo` | the facts say this test applies here | it is in the queue (`sane next`) |
  | `probe` | a fact it depends on is unknown | settle the fact once (`sane probes`); many items resolve together |
  | `n/a` | a fact rules it out | nothing; the reason and evidence are recorded |
  | `blocked` | it needs a capability you lack (second account, callback host, browser) | supply it or leave it (`sane blockers`) |
  | `excluded` | the programme does not accept this class | nothing |

- Hosts that serve the same application are **clustered**; deployment-level items run once per cluster.

So the work is not "run the tests". It is "establish the facts, then run what they justify". When you think the
planner is wrong, the fact is wrong: fix it with evidence. You never mark an item not-applicable by hand.

## 3. The state machine

`scripts/sane status` computes the phase from disk and names the next playbook. The phases:

| Phase | You have | Playbook | You leave with |
|---|---|---|---|
| P0 Engage | a programme name | PB-00 | authorisation, rules, exclusions recorded |
| P1 Scope | the policy | PB-01 | `scope.json` matching the policy |
| P2 Recon | a scope | PB-02 | in-scope assets |
| P3 Fingerprint | assets | PB-03 | tiers, clusters, technology, auto-facts |
| — CVE pass | products with versions | PB-07 | verified known-vulnerability candidates, or the reasons there are none |
| P4 Map | app and API deployments | PB-04 | accounts, the feature map, facts settled |
| P5 Hunt | a queue | PB-05, PB-06 | every queued card closed with a reason |
| P6 Research | a mapped application and a thin queue | PB-08 | hypotheses tested, novel candidates |
| P7 Verify | a candidate | PB-09 | a verified finding or a closed card |
| — Chain | a primitive or weak finding | PB-10 | a demonstrated higher impact, or a parked note |
| P8 Report | a verified finding | PB-11 | a gated report handed to the operator |
| — After | a submitted report | PB-12 | replies, retests, lessons |

Two playbooks run across all phases: PB-13 routes any observation to where it belongs; PB-14 handles incidents.
Verification pre-empts hunting: an unverified candidate is handled before the next card.

## 4. A session, start to finish

```text
scripts/sane status                       # where am I; which playbook
scripts/sane playbook PB-NN               # read the procedure
... do it ...
scripts/sane next                         # the best cards now
scripts/sane card XSS-004 app.example.com # one card: claim, where, how, proof, false positives, prior art
scripts/sane start app.example.com XSS-004
source "$E/env.sh"; curl -sS "${HDR[@]}" $A ...        # the test, evidence saved under $E/evidence/
scripts/sane mark app.example.com XSS-004 negative --note "output is HTML-encoded by the template engine in all three contexts tested"
```

Resuming: the SessionStart hook prints the status. Read `engagements/<name>/notes.md` and the last lines of
`logs/journal.jsonl`, then `scripts/sane next`.

## 5. How a hunter thinks

The cards hold techniques. These habits decide whether the techniques find anything.

- **Depth beats breadth.** One application understood well yields more than fifty skimmed. Spend the PB-04 hour.
- **Follow the money and the identity.** Bugs that pay sit where value moves (payments, credits, plans) and where
  identity is decided (login, reset, invitations, tenants, roles).
- **Authorisation is the richest seam.** About one disclosed report in ten is an access-control bug, and they are
  found with two accounts and patience, not tools. If you have accounts A and B, the access-control chapter is
  rarely the wrong place to be.
- **New and neglected code is weaker.** The feature released last month and the API version nobody maintains.
- **Read before you send.** The JavaScript bundle is the specification the developers did not mean to publish.
- **Always run a control.** A result means nothing without the request that shows normal behaviour beside it.
- **Ask what the developer assumed.** Then look for where that assumption is not enforced (PB-08).
- **Know the graveyard.** `docs/07-graveyard.md` lists what gets closed as informative. Do not spend an hour
  proving something no programme pays for.
- **Impact is demonstrated, not argued.** If the report needs the word "could", the proof is not finished.
- **Stop when the clock says so.** Park it, write why, move on. You can come back with a better idea.

## 6. What is reportable

All four must hold. `docs/02-reportability.md` expands each.

1. **In scope**, on an asset the programme lists, in a class it does not exclude.
2. **Real**: reproduced from clean state at least twice, with a control, and it survived the guard lens.
3. **Impactful**: a security consequence for the programme or its users that the proof shows. A missing header,
   a version banner or a theoretical weakness is not one.
4. **Yours to report**: not a known duplicate, found within the rules, proven without harm.

## 7. Models, effort and delegation

Any of Claude Opus 5.5, Opus 5 or Mythos 5.2 runs this. Verification lenses and research benefit from higher
effort; recon and fingerprinting do not need it. Use subagents for work that is independent and whose output is a
conclusion: recon in the background, one mapper or hunter per deployment, the three verification lenses. Keep
verification decisions, chaining and the final read of a report in the main session. One agent per deployment at
a time.

## 8. Where things are written down

| What | Where |
|---|---|
| Rules of this engagement | `engagement.json`, `policy.md` |
| What may be touched | `scope.json` |
| What exists | `assets.json`, `recon/` |
| What is true of each asset, and why | `facts/<host>.json` |
| What each application does | `recon/<host>/map.md`, `recon/<host>/requests/` |
| What was tested and how it went | `coverage.csv`, `evidence/` |
| Ideas | `hypotheses.jsonl`, `notes.md` |
| What was found | `findings/F-NNN/` |
| What happened | `logs/journal.jsonl`, `logs/audit.jsonl`, `logs/incidents.md` |

The engagement folder is its own git repository and is never pushed to this one. If the operator supplies a
private remote for evidence, push there.
