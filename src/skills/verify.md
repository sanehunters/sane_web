---
name: verify
description: Verify a candidate vulnerability through three independent lenses — reproduce from clean state, find the guard that explains it away, and read it as the programme's triager — before it may be called a finding. Use whenever an item is marked candidate, a hypothesis is confirmed, a CVE check hits, or the user says they think they found something.
---

# /verify — playbook PB-09

`$ARGUMENTS` is a finding id (`F-003`) or `<asset> <ITEM>`. Procedure: `scripts/sane playbook PB-09`.

1. Open the finding if needed: `scripts/sane finding new --title "..." --asset <host> --item <ITEM>`. Raw captures
   go in `findings/F-NNN/evidence/`.
2. Write `findings/F-NNN/claim.md`: one sentence (attacker's starting position, action, result) and the steps as
   you believe them. This file and the evidence folder are all the verifiers get. None of your reasoning.
3. Launch the three lenses in parallel, each as its own agent with only `claim.md` and the evidence:
   - `verify-reproduce`: twice from clean state, then from the weakest attacker position that still works.
   - `verify-guard`: assume the application is correct; test every innocent explanation.
   - `verify-triager`: scope, exclusions, intended behaviour, realistic CVSS, duplicate search → `dupcheck.md`.
4. Write their verdicts to `findings/F-NNN/verify.json` (`holds` | `weak` | `refuted`, each with a note).
5. Decide:
   - at least two `holds` and the triager not `refuted` →
     `scripts/sane finding set F-NNN state=verified reproductions=<n>` and
     `scripts/sane mark <asset> <ITEM> finding --finding F-NNN --note "..."`
   - triager `weak` → `/chain` before reporting
   - otherwise → re-mark the item `negative` or `parked` with the reason the lens found. Delete nothing.

A verifier that was told what to conclude will conclude it. Give them the claim, not the excitement.

If a subagent cannot be used, play each lens yourself in a separate pass, writing the verdict before starting the
next, and say in `verify.json` that the lenses were not independent.

<!-- include playbooks/PB-09-verify.md -->
