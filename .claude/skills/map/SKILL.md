---
name: map
description: Map one application — create test accounts, walk every feature authenticated, mine the JavaScript, write the feature inventory and trust model, and settle the applicability facts. Use when sane probes lists unknown facts, before hunting on any app or API deployment.
---

# /map — playbook PB-04

`$ARGUMENTS` is the host (the deployment representative). Procedure: `scripts/sane playbook PB-04`.

1. `scripts/sane probes <host>` — the unknown facts, ranked by what they unlock.
2. Accounts A and B (different tenants), plus a low-privilege member where roles exist, per the programme's
   account rules. Headers into `accounts/*.headers`; then
   `scripts/sane fact set @eng account=1 two-accounts=1 priv-accounts=1 --ev "..."`.
3. Walk every feature once with request logging on. One line per feature in `recon/<host>/map.md`; one saved
   request per feature in `recon/<host>/requests/`.
4. Mine `recon/<host>/js/` for routes, parameters, roles and flags the UI never showed.
5. Settle every fact from step 1 with evidence: `scripts/sane fact set <host> tag=1|0 ... --ev "..."`.
   Zero only when you looked where it would be.
6. Ask the library about the richest features: HexBrain `plan_tests`, or `scripts/sane kb search <words>`.
7. Write the five-line trust model at the top of `map.md`.

Delegate to `surface-mapper` when several deployments need mapping; one agent per deployment.

While mapping, do not chase oddities: one line in `notes.md`, route it with PB-13, keep walking.
