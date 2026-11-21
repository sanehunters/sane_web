# engagements/

One folder per programme, created by `scripts/sane new <name>`. Everything here is private programme data and
evidence. It is ignored by this repository's `.gitignore` and must never be committed to it. Each engagement
folder is its own git repository so the work has history; push it only to a private remote you control.

```text
engagements/
  .active                      name of the active engagement (or set $SANE_ENGAGEMENT)
  <name>/
    engagement.json            authorisation, rate, required headers, exclusions, accounts, capabilities, blockers
    policy.md                  the programme's policy text as fetched or pasted
    scope.json                 in / out / other, from HackerOne plus your manual rules
    allow-infra.txt            optional: extra hosts that are your infrastructure or reference material, not targets
    env.sh                     source this at the start of every shell command that touches the target
    accounts/                  session headers per test account (A.headers, B.headers, ADM.headers). Never committed
    assets.json                every host seen, its scope verdict, fingerprint, technology, cluster
    facts/<host>.json          what is true of each asset, with the evidence and who set it
    recon/<host>/              tech.json, cves.json, js/, map.md, requests/, invariants.md, urls-history.txt
    coverage.csv               one row per asset x card that a hunter touched: status, note, evidence, clocks
    hypotheses.jsonl           the research ledger
    evidence/<host>/<ITEM>/    raw captures made while running a card
    findings/F-NNN/            finding.json, claim.md, verify.json, dupcheck.md, chain.md, report.md, cleanup.md, evidence/, poc/
    notes.md                   the hunter's notebook
    logs/journal.jsonl         what the console did
    logs/audit.jsonl           every network command the scope guard saw, and its decision
    logs/incidents.md          anything that went wrong, and what was done about it
    state-snapshot.md          written before each context compaction
```

To keep engagements outside the checkout, set `SANE_ENGAGEMENT_ROOT=/some/path`.

To give an engagement a private remote:

```bash
git -C engagements/<name> remote add origin git@github.com:<you>/<private-evidence-repo>.git
git -C engagements/<name> push -u origin main
```
