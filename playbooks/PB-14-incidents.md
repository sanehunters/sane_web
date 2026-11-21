# PB-14 · Incidents: blocked, banned, broke something, saw data you should not

| | |
|---|---|
| **Trigger** | Any of the situations below |
| **Entry state** | Testing is in progress |
| **Runs as** | Main session |
| **Timebox** | Immediate. Stop first, then follow the row |
| **Output on disk** | `logs/incidents.md`: time, what happened, what was sent, what was done about it |
| **Next** | As the row says; often a pause and a message to the operator |

Things go wrong on live targets. What separates a professional from a liability is what happens in the next five
minutes. The rule for all of these: **stop the activity, write down exactly what happened, tell the operator.**
`logs/audit.jsonl` has every network command the guard saw; use it to reconstruct the timeline.

## Rate limited (429, slow responses, temporary blocks)

1. Stop all requests to the host for ten minutes.
2. Halve `rate_limit_rps` (`scripts/sane set rate_limit_rps=<n>`). The guard enforces the new ceiling.
3. Resume with the manual cards; leave fuzzing and content discovery for last.
4. If it recurs at the lower rate, the limit is per-account or per-endpoint: note which, and work elsewhere.

## Blocked or banned (WAF block page on everything, connection resets, account suspended)

1. Stop. Do not rotate IPs, switch VPNs or register replacement accounts to get around it: evading a block can
   itself breach the programme's terms.
2. Record the last twenty requests from `logs/audit.jsonl` in `logs/incidents.md`.
3. Tell the operator. Unblocking usually means waiting, or a message to the programme, and both are theirs.
4. Work on another deployment meanwhile.

## The target degraded while you were testing (errors for everyone, timeouts, a visible outage)

1. Stop every request to that target at once, including background jobs (`pkill` the scanners you started).
2. Do not test whether it is "still down" more than once a few minutes later with a single GET.
3. Write the timeline: what ran, at what rate, from when to when.
4. Tell the operator immediately. If your testing may be the cause, the programme should hear it from you first,
   with the timeline. That message is the operator's to send.

## You changed or deleted something that was not yours

1. Stop. Do not try to repair it by guessing.
2. Record exactly what request did it and what the state was before, as far as you know.
3. Tell the operator; the programme needs to know which object, when, and how to restore it.
4. Afterwards, find out why the test was not confined to your own accounts and write that into `notes.md`.

## You saw real third-party data (customer PII, credentials, internal documents, payment data)

1. Stop at the first record. Do not page, enumerate, download or search.
2. Do not copy the data into evidence. Keep the request and a response with the values redacted to their shape
   (`j***@e******.com`, `4111 **** **** 1111`), enough to show the category.
3. If raw data was already saved to disk, delete those files and note that you did.
4. This is usually a strong finding. Go to PB-09 with the redacted evidence and state in the report what category
   of data was exposed, that you viewed the minimum needed to confirm it, and that nothing was retained.

## You found working credentials or keys (cloud keys, API tokens, database passwords, admin logins)

1. Do not use them to explore. One read-only identity call is the ceiling (`aws sts get-caller-identity`, the
   provider's "who am I"), and only where the policy does not forbid validating secrets.
2. Redact in all notes and evidence to the first and last four characters.
3. Report quickly (PB-09, PB-11): leaked live credentials are time-sensitive for the programme.

## A request went to something out of scope

1. Stop. Work out how: a redirect followed, a host list that was not filtered, a wrong variable.
2. Record the host, the request and the time in `logs/incidents.md`.
3. Add the host as an `out` rule so the guard blocks it from now on.
4. Tell the operator. A single stray GET is usually a non-event; they decide whether it needs mentioning to
   anyone. Then fix the cause (the list, the script) before resuming.

## A subdomain takeover claim is live

1. The claim must hold only an inert proof file at an unguessable path. Nothing at the root, no cookie capture,
   no redirects, no JavaScript.
2. Screenshot and save `dig` output immediately, then report (PB-11) the same hour.
3. Release or hand over the resource as the policy says, as soon as the programme confirms; record when.

## Something looks already compromised (a web shell, someone else's backdoor, data for sale)

1. Do not interact with it beyond the request that revealed it.
2. Capture that request and response.
3. Tell the operator at once. The programme will want to know urgently, through its security contact; this may
   not be a normal bounty submission.

## You are unsure whether an action is allowed

1. Do not do it.
2. Find the sentence in the policy. If there is none, ask the operator, who can ask the programme.
3. Record the answer in `engagement.json` `policy_notes[]` so the question is settled for later sessions.

## Done when

`logs/incidents.md` has the entry, the cause is fixed or the activity is paused, and the operator knows.
