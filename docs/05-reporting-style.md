# 05 — Reporting style

A report is read by a triager who has a queue, has never seen your testing, and will reproduce your steps
literally. The reports that are triaged in an hour and paid without argument share a voice: a working hunter
explaining to a colleague what they found, plainly, with the evidence in the order the reader needs it. This file
describes that voice. `templates/report.md` is its skeleton and `scripts/sane gate` checks its mechanics.

## 1. What a triager does with your report

1. Reads the title and decides which queue and how urgent.
2. Reads the summary and decides whether it is plausible and in scope.
3. Follows the steps with their own two accounts. If a step fails or is ambiguous, they ask ("needs more info")
   and you lose days, or they close it.
4. Reads the impact and sets a severity.
5. Forwards it to an engineer, who reads the remediation line and the raw request.

Write for those five moments. Anything that serves none of them is cut.

## 2. Voice

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

## 3. Title

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

## 4. Summary

Three to five sentences, answering in order:

1. What is the feature? (one clause, for a reader who does not use the product)
2. What is wrong? (the missing or broken check, as precisely as you know it)
3. Who can exploit it, from what starting position, and what must the victim do?
4. What do they get?

> Organisations can download invoices as PDF. The JSON endpoint `/api/v2/invoices/{id}` verifies that the invoice
> belongs to the caller's organisation, but the PDF endpoint `/api/v2/invoices/{id}/pdf` does not. Any logged-in
> user can download any organisation's invoice by changing the numeric id. Invoice ids are sequential. The PDF
> contains the customer's legal name, billing address, VAT number and line items.

## 5. Steps to reproduce

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

## 6. Proof of concept

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

## 7. Impact

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

## 8. Remediation

One or two sentences, the check and the place. You are not designing their system; you are pointing at the line.

> Apply the same organisation check the JSON endpoint uses before rendering the PDF.

## 9. What never goes in

- Scanner output pasted as the finding. A tool can point; the report shows the manual proof.
- A list of "other things I noticed" that are not findings. One report, one root cause.
- Other users' real data, unredacted secrets, or full dumps of anything.
- Demands, deadlines, bounty expectations, comparisons with other programmes.
- Claims you cannot reproduce on request.
- AI boilerplate: generic vulnerability definitions, "In today's digital landscape", bulleted lists of everything
  an attacker "may" do, OWASP paragraphs. A triager stops reading at the first one.

## 10. A complete example

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
