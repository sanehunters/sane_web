---
name: chain
description: Escalate impact by chaining primitives — turn a parked primitive or a weak finding into a demonstrated higher-impact result without doing harm. Use when the triager lens says weak, when parked items accumulate, or when the user asks to increase severity, chain bugs, or escalate.
---

# /chain — playbook PB-10

Procedure: `scripts/sane playbook PB-10` (it holds the table of "you have X, you are missing Y, look for Z").

1. List the primitives as capabilities, not bug names:
   `grep -E ',(parked|finding),' "$E/coverage.csv"` plus the open findings.
2. For each, name what it is missing for impact and look for exactly that (the PB-10 table; the `Chains` section
   of the primitive's chapter; `docs/07-graveyard.md`'s right-hand column).
3. Check the library: `scripts/sane kb search <class a> <class b>`, HexBrain `search_reports`.
4. Build the chain end to end on your own accounts. Write `findings/F-NNN/chain.md`: every link with its request,
   response and resulting state. The last state is the impact you will claim.
5. Re-rate on the end state (`docs/06-severity.md`), then `/verify` the chain as a whole.

Hard edges:

- The next link needs another user's real account or data → rebuild with your second account, or describe the
  step without doing it.
- The escalation would use credentials found in the target → one identity call at most; report what the
  credential is, not what it opens.
- If the standalone finding is already medium or higher and the chain is speculative, report now and add the
  escalation as a follow-up. Sitting on a valid bug invites a duplicate.

Ninety minutes without a working second link: back to `parked`, with the missing link named precisely.

<!-- include playbooks/PB-10-chain.md -->
