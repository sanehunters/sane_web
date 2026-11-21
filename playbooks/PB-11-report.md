# PB-11 · Report: write, gate, hand over

| | |
|---|---|
| **Trigger** | A finding in state `verified` |
| **Entry state** | `findings/F-NNN/` has `claim.md`, `verify.json`, `dupcheck.md` and raw evidence |
| **Runs as** | `report-writer` agent, reviewed in the main session |
| **Timebox** | 60 minutes |
| **Output on disk** | `findings/F-NNN/report.md`, `poc/`, numbered evidence, `cleanup.md`; `finding.json` state `ready` |
| **Next** | The operator submits. Then PB-12 |

The report is the product. A triager spends two to five minutes on first read and decides most of the outcome in
that time. The reports that get paid quickly read as if written by someone who respects that: one clear claim,
steps that work on the first try, proof that cannot be argued with, and impact stated without inflation.
`docs/05-reporting-style.md` has the full style; this is the procedure.

## Steps

1. **Rebuild the proof from clean state while writing the steps.** Do not write steps from memory. Perform each
   one again with fresh sessions and write down exactly what you did as you do it. This is the third
   reproduction and it catches the step you forgot you did.
2. **Make the proof of concept a single artefact** in `findings/F-NNN/poc/`:
   - server-side bugs: one `curl` command or a short script with the two sessions as variables;
   - client-side bugs: one HTML file the triager can open, or one URL;
   - chains: one script that runs the links in order and prints the end state.
   It must work for someone who has only the report, two accounts and the file.
3. **Capture the evidence.** Raw request and response pairs as text (headers included, secrets redacted to the
   first and last four characters). Screenshots for anything visual, taken with the scriptable browser, showing
   the URL bar and both accounts' identities. For multi-step or timing bugs, a short screen recording. Name them
   in order: `01-victim-creates-invoice.png`, `02-attacker-request.txt`, `03-attacker-receives-pdf.png`.
4. **Write `report.md` from the template** (`templates/report.md`, already in the finding folder):
   - **Title:** `[bug class] in [exact place] allows [attacker] to [impact]`. No severity words, no exclamation.
   - **Summary:** three to five sentences; attacker's starting position and what the victim must do, stated exactly.
   - **Steps to Reproduce:** numbered, one action each, the literal request for each, the two test accounts named.
   - **Proof of Concept:** the artefact from step 2 and the list of attachments.
   - **Impact:** who is affected, what the attacker gains, at what scale, as demonstrated. What you deliberately
     did not do.
   - **Remediation:** the check to add and where, in a sentence or two.
   - **Severity:** a CVSS vector that matches the proof (docs/06). Under-claiming slightly earns trust;
     over-claiming earns a downgrade and a slower triage next time.
5. **Write `cleanup.md`:** every object the testing created (accounts, files, records, callbacks, DNS names) and
   whether it was removed. Remove what you can now.
6. **Gate it.** `scripts/sane gate F-NNN`
   Every line must pass: scope, exclusions, sections, numbered steps, a raw request in a code block, a CVSS
   vector, two reproductions, three verification lenses, the duplicate check, no unredacted secret, no
   speculative impact wording. Fix and re-run until it says READY.
7. **Read it once as the triager.** Cold, top to bottom, following your own steps. Cut every sentence that does
   not help them reproduce or assess. Then hand it to the operator with: the title, the severity and vector, the
   asset and scope line, and the path to the folder.

## Decision points

- The steps do not reproduce while you write them → back to PB-09; do not paper over it.
- The impact paragraph needs "could" or "might" to sound serious → the proof is short of the claim. Either prove
  more (PB-10) or claim less.
- Several instances of the same root cause → one report listing all instances, unless the policy says to file
  separately; never split one fix into several reports to multiply bounties.
- The finding touches data you should not have seen (real users' PII appeared in a response) → PB-14 first; the
  report says what category of data was exposed and that you stopped, with the data itself redacted.

## Call it off when

- Not applicable. A verified finding is always written up, even when it will be held for a chain.

## Done when

`scripts/sane gate F-NNN` prints READY and the operator has the hand-over line.

## Hand to the operator when

- Always: submission is theirs. This framework does not submit to HackerOne. They choose the asset, weakness and
  severity fields in the form, paste the report, attach the files, and answer the programme.
