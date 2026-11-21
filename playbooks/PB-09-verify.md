# PB-09 · Verify a candidate

| | |
|---|---|
| **Trigger** | Any item marked `candidate`, any confirmed hypothesis, any verified CVE check |
| **Entry state** | A signal with raw evidence on disk |
| **Runs as** | Three independent agents (`verify-reproduce`, `verify-guard`, `verify-triager`), or the main session playing each lens in turn |
| **Timebox** | 45 minutes |
| **Output on disk** | `findings/F-NNN/verify.json` with three verdicts; `finding.json` state `verified` or the item re-marked |
| **Next** | PB-10 if the impact can grow; PB-11 if it stands; back to PB-06 if it falls |

Most candidates are wrong. The author of a finding is the person least able to see why. Verification is three
attempts to kill it, made by readers who did not find it. It survives if at least two lenses hold and the triager
lens does not refute it.

## Steps

1. **Open the finding.** `scripts/sane finding new --title "<working title>" --asset <host> --item <ITEM>` if it
   does not exist. Put the raw requests and responses in `findings/F-NNN/evidence/`.
2. **Write the claim in one sentence** at the top of `findings/F-NNN/claim.md`: attacker's starting position,
   action, result. "A logged-in user of organisation A can download any invoice PDF of organisation B by
   requesting /api/v2/invoices/{id}/pdf with B's invoice id." Add the exact reproduction steps as you believe
   them. The verifiers get this file and the evidence folder, and nothing of your reasoning.
3. **Lens 1 — reproduce** (`verify-reproduce`). From a clean state: new session tokens, a fresh pair of test
   objects, no cached cookies. Follow `claim.md` literally. Then reproduce again from the weakest attacker
   position that still works (unauthenticated instead of authenticated, viewer instead of member, cross-tenant
   instead of same-tenant). Record each run: `scripts/sane finding set F-NNN reproductions=<n>`.
   Verdict `holds` only if it reproduced twice from clean state.
4. **Lens 2 — find the guard** (`verify-guard`). Assume the application is correct and explain the observation
   without a vulnerability. Check, each with a request:
   - Is victim B's object actually private? (Is it public by design, shared with A, or in the same tenant?)
   - Is the data really B's, or A's own data returned under B's id, or a default/placeholder?
   - Is it cached: does the result change when B changes the object?
   - Does it need a precondition A arranged (A was once a member, A holds an old link)?
   - Is there a second check later that stops the real impact (a signed URL that 403s, a job that never runs)?
   - Is the "victim" a test artefact (same browser, shared cookie jar, the same account twice)?
   Verdict `holds` only if every alternative explanation was tested and excluded.
5. **Lens 3 — read it as the programme's triager** (`verify-triager`). With the policy open:
   - Is the asset in scope, and is this class excluded? (`scripts/sane scope check`, `engagement.json` exclusions)
   - Would they call it intended behaviour? Is it documented?
   - What is the realistic severity on what is proven, with the CVSS vector written out?
   - Has this exact bug been reported here before? Search the programme's disclosed reports
     (`scripts/sane kb program`, HexBrain `search_reports` with the programme and endpoint) and write
     `findings/F-NNN/dupcheck.md` with what was searched and found.
   - Does it need unlikely user interaction, a privileged attacker, or physical or network position?
   Verdict `holds`, `weak` (valid, likely low or informative) or `refuted`.
6. **Record the verdicts** in `findings/F-NNN/verify.json`:
   ```json
   {"lenses": {
     "reproduce": {"verdict": "holds", "note": "2/2 from clean sessions; also works as a Viewer"},
     "guard":     {"verdict": "holds", "note": "object is private (B's list shows no share); data changes when B edits it; no later check"},
     "triager":   {"verdict": "holds", "note": "in scope *.example.com; class not excluded; no matching disclosed report; CVSS 6.5"}}}
   ```
7. **Decide.**
   - Two or three `holds`, triager not `refuted` → `scripts/sane finding set F-NNN state=verified`, and
     `scripts/sane mark <asset> <ITEM> finding --finding F-NNN --note "<one line>"`.
   - Triager `weak` → PB-10 before reporting: the fact is real and the impact is not yet enough.
   - Otherwise → re-mark the item `negative` or `parked` with the reason the lens found. Delete nothing.

## Decision points

- It reproduces only sometimes → it is a race or a cache: characterise the rate over twenty attempts and say so;
  a 1-in-20 race is still a finding when the impact is high.
- It reproduces only in your browser → a client-side artefact; re-test with `curl` and clean cookies.
- The guard lens finds the object was shared with A → not a finding; fix the test data and re-run the card once.
- The triager lens finds a disclosed duplicate → `dup-risk`; report only if yours is demonstrably a different root
  cause or a bypass of the fix, and say that in the first line.

## Call it off when

- It cannot be reproduced from clean state twice in 45 minutes. Park it with the conditions observed.

## Done when

`verify.json` has three verdicts with notes, `dupcheck.md` exists, and the item's status reflects the decision.

## Hand to the operator when

- The finding is verified and critical or high: tell them now, before polishing anything.
- Verification would need a real user's data or account. It never does; ask them how to construct the test instead.
