# PB-00 · Engage: authorisation and policy

| | |
|---|---|
| **Trigger** | The operator names a programme to hunt on |
| **Entry state** | No engagement, or `sane status` says "authorised NOT CONFIRMED" |
| **Runs as** | Main session, with the operator present |
| **Timebox** | 20 minutes |
| **Output on disk** | `engagements/<name>/engagement.json` with authorisation, rules, exclusions; `policy.md` |
| **Next** | PB-01 |

Nothing is sent to any target in this playbook. Its job is to make every later decision checkable against a
written rule.

## Steps

1. **Create the engagement.**
   `scripts/sane new <name> --handle <hackerone handle>`
   Expect: the folder path and "active engagement".
2. **Record the authorisation.** Ask the operator, once: which HackerOne account was invited to or enrolled in
   this programme, and is it theirs. Then:
   `scripts/sane set authorised=yes basis="private programme invitation accepted by <h1 user> on <date>" h1_username=<h1 user>`
   Without a basis the scope guard refuses every request to an in-scope host.
3. **Get the policy text.** With API credentials (`H1_USERNAME`, `H1_TOKEN`): `scripts/sane scope import-h1`
   writes `policy.md` and the structured scope. Without them: ask the operator to paste the policy page and the
   scope table into `engagements/<name>/policy.md`.
4. **Read the whole policy** and extract, in this order. Quote the sentence for each in `notes.md`.
   - Required request headers or User-Agent (`X-HackerOne-Research: <user>`, `X-Bug-Bounty: ...`):
     `scripts/sane set required_headers+='X-HackerOne-Research: <user>'`
   - Rate limit. If none is stated, keep the default of 5 requests per second:
     `scripts/sane set rate_limit_rps=<n>`
   - Account rules: which e-mail to register with (often `<user>@wearehackerone.com` aliases), whether to
     create your own tenant, any test credentials offered.
   - Excluded bug classes. Map each to a tag from `scripts/sane fact list`'s exclusion vocabulary
     (`checklist/_facts.json` → `exclusions`): `scripts/sane set exclusions+=clickjacking exclusions+=rate-limit ...`
   - Programme permissions that are facts: takeover claims, availability testing, brute force.
     `scripts/sane fact set @eng takeover-ok=1 dos-ok=0 bruteforce-ok=0 --ev "<policy sentences>"`
   - Anything unusual: testing windows, forbidden assets inside a wildcard, data-handling rules, a required
     report format, whether chained reports are paid per link or per chain.
5. **Read what the programme has already paid for.** `scripts/sane kb program "<programme name>"`, and with the
   HexBrain connector `get_program_history`. Note in `notes.md` the classes they pay and what they closed as
   informative. This is the single best predictor of what is worth your time here.
6. **Capabilities.** `scripts/sane doctor`. Record what exists:
   `scripts/sane fact set @eng oob=1 browser=1 --ev "interactsh-client installed; playwright chromium present"`.
   Set the callback host if there is one: `scripts/sane set oob_host=<host>`.

## Decision points

- The policy forbids automated scanning → set `exclusions+=automated`, and in PB-06 every card is run by hand with
  `curl`; no nuclei, ffuf or sqlmap on this engagement.
- The programme is a VDP (no bounties) → say so to the operator before spending time; continue only if they want it.
- The policy text and the structured scope disagree → the stricter reading wins; record the conflict in `notes.md`
  and raise it in PB-01.
- The operator cannot say which account is enrolled → stop. Do not proceed on an assumption.

## Call it off when

- There is no written basis for authorisation.
- The programme is paused or not accepting submissions (`submission_state` in `engagement.json`).

## Done when

`scripts/sane status` shows "authorised yes", a rate, the required headers (or "none" confirmed from the policy),
and the exclusions list reflects the policy.

## Hand to the operator when

- API credentials, the policy text, or the enrolled username are missing.
- The policy requires a registration step only a human can do (KYC, NDA, VPN profile, an allow-listed IP).
