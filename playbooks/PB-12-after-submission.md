# PB-12 · After submission: triage replies, retests, lessons

| | |
|---|---|
| **Trigger** | A submitted report changes state: a triager asks something, it is triaged, closed, paid, or a retest is requested |
| **Entry state** | `finding.json` has the HackerOne report id (`scripts/sane finding set F-NNN h1_id=<id> state=submitted`) |
| **Runs as** | Main session with the operator |
| **Timebox** | 30 minutes per event |
| **Output on disk** | `findings/F-NNN/thread.md` (the exchange, summarised); `finding.json` state; lessons in `notes.md` |
| **Next** | PB-06 |

## Steps by event

### "Needs more info"

1. Read the question twice. Answer exactly what was asked, first, in one or two sentences.
2. Reproduce again from clean state before replying; the target may have changed.
3. Reply with the missing piece only: the exact request, a clearer screenshot, the account ids. No restating of
   the report, no argument about severity in the same message.
4. If it no longer reproduces, say so plainly and say when it last did, with the evidence timestamps.

### Severity lowered or disputed

1. Re-read your own impact section against the programme's severity guidance. Are they right?
2. If you can demonstrate more, do PB-10 and add a comment with the new proof. A demonstration moves a rating;
   an argument rarely does.
3. If you cannot, accept it in one polite sentence. Reputation with a programme's team is worth more than one
   rating.

### Closed as duplicate

1. Ask, once and politely, for the original report's id or date if it was not given.
2. Record in `notes.md`: the class, the endpoint and how long the original had been open. If duplicates of this
   kind recur on this programme, raise its `dup-risk` threshold: prefer deeper, application-specific findings
   (PB-08) over what scanners and the top cards find first.

### Closed as informative or not applicable

1. Find the reason in their words and map it to one of: out of scope, excluded class, intended behaviour, no
   security impact, cannot reproduce.
2. Record it in `notes.md` and, where it generalises, tighten the method: add the exclusion tag to the
   engagement, or note the "Not a finding when" line that the card was missing.
3. Do not resubmit the same finding reworded. If you have new impact, comment on the closed report.

### Triaged or resolved, retest requested

1. Run the original proof of concept unchanged. Record the result.
2. Then test the fix, not just the payload: the sibling endpoint, another encoding, another verb, the same bug
   one object type over (CVE-015 and PB-08's `variant` lens). A bypass is a new report that references the old
   one in its first line.
3. Reply with what you ran and what happened.

### Paid

1. Record the amount and severity in `finding.json`. Thank them in one line.
2. Write the lesson: what made this one land (the feature, the lens, the card). Search for the same pattern on
   the programme's other deployments while the idea is fresh.

## Decision points

- The programme asks you to stop testing something → stop at once, record it as a rule in `engagement.json`
  `policy_notes[]`, and add an `out` scope rule if it names an asset.
- The fix is live and your test objects still exist → clean them up and say so.
- A mediation request seems warranted → that is the operator's call, and rarely worth it.

## Done when

The thread has a reply or a recorded decision, `finding.json` reflects the state, and any lesson is written down
where the next session will read it.

## Hand to the operator when

- Always: every message to the programme is sent by them.
