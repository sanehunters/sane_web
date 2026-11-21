---
name: report
description: Write a HackerOne report for a verified finding in the voice of an experienced manual bug bounty hunter — exact title, tight summary, numbered reproduction steps with raw requests, a single working proof of concept, demonstrated impact, an honest CVSS vector — then pass the readiness gate. Use when a finding is verified or the user asks to write up, draft, or prepare a report or PoC.
---

# /report — playbook PB-11

`$ARGUMENTS` is the finding id. Procedure: `scripts/sane playbook PB-11`. Style: `docs/05-reporting-style.md`
(read it before writing; it has a complete example). Evidence: `docs/04-evidence-standard.md`. Rating:
`docs/06-severity.md`.

1. **Rebuild the proof from clean state while writing the steps.** Fresh sessions, fresh test objects. Write each
   step as you perform it. Never from memory.
2. **One proof-of-concept artefact** in `findings/F-NNN/poc/`: a `curl` command or short script for server-side
   bugs, one HTML file or URL for client-side bugs, one script for a chain. It must work for someone holding only
   the report, two accounts and the file.
3. **Evidence**, numbered in the order the report cites it: raw request and response text with secrets cut to the
   first and last four characters; screenshots from the scriptable browser with the URL and the account visible.
4. **Write `report.md`** from the template already in the folder:
   - Title: `[bug class] in [exact place] allows [attacker] to [impact]`
   - Summary: three to five sentences; the attacker's starting position and what the victim must do, exactly
   - Steps to Reproduce: numbered, one action each, the literal request, both test accounts named, ends on the observation
   - Proof of Concept · Impact (as demonstrated, with what you deliberately did not do) · Remediation (one or two sentences)
   - Severity: the CVSS vector the proof supports
5. **`cleanup.md`**: everything the testing created and whether it was removed.
6. **Gate:** `scripts/sane gate F-NNN` until it prints READY.
7. **Read it cold as the triager.** Cut every sentence that does not help them reproduce or assess.
8. **Hand over** to the operator: title, severity and vector, asset and scope line, folder path. They submit.

Voice: first person, plain verbs, concrete nouns, no adjectives doing the work of evidence, no "could
potentially", no vulnerability definitions, no bullet lists of everything an attacker "may" do. 250 to 600 words
plus requests for a single bug.

For a known CVE: name the CVE in the title, cite the advisory, show the version evidence and the advisory's
request with the target's response; never attach a weaponised exploit.

Delegate the draft to `report-writer`; the final read and the gate stay in the main session.

<!-- include playbooks/PB-11-report.md -->

<!-- include docs/05-reporting-style.md -->

<!-- include docs/06-severity.md -->
