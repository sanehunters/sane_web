---
name: research
description: Hunt for novel, application-specific vulnerabilities by modelling the application's invariants and testing hypotheses through twelve research lenses. Use when the card queue is empty or thin, when the target is a rich application, or when the user asks for novel bugs, zero-days, logic flaws, or something scanners and checklists would not find.
---

# /research — playbook PB-08

`$ARGUMENTS` is the deployment. Requires PB-04 done: `recon/<host>/map.md` with the feature table and trust model.
Procedure: `scripts/sane playbook PB-08`.

1. **Invariants.** Write fifteen to thirty rules the application must hold ("a viewer cannot cause any write",
   "a total equals the sum of its lines at server prices") into `recon/<host>/invariants.md`.
2. **Lenses.** Take them one at a time against the feature table: `second-path`, `state-machine`,
   `identity-binding`, `trust-boundary`, `parser-differential`, `time-and-concurrency`, `derived-data`,
   `forgotten-surface`, `variant`, `integration`, `client-trust`, `source`.
3. **Ledger.** Each plausible break:
   `scripts/sane hyp add --asset <host> --lens <lens> --text "<claim>" --why "<observation>" --test "<cheapest experiment>"`
4. **Variants from the library.** `scripts/sane kb program "<name>"`, read the best-paid write-ups in full
   (`scripts/sane kb show <id>`), and ask where the same root cause reappears. HexBrain `find_bypasses` with
   `protection: fix` shows how fixes were bypassed elsewhere.
5. **Read the code you have.** Bundles and source maps in `recon/<host>/js/`; open-source components at the
   version in use (the `source-code-review` skill applies).
6. **Test in rank order** (impact × plausibility ÷ cost), each with a control, 45 minutes to a decisive
   experiment.
7. **Close every hypothesis:** `scripts/sane hyp close H-NNN --result confirmed|refuted|parked --note "..."`.
   Confirmed → `scripts/sane finding new ...` → `/verify`.
8. A confirmed pattern that would apply elsewhere becomes a proposed checklist card in `notes.md`.

Give independent lenses to `researcher` agents (one lens, one deployment each); keep ranking and testing decisions
in the main session. Stop generating at thirty open hypotheses and test.
