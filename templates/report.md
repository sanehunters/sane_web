<!--
{{ID}} · {{ASSET}}
Fill every <<...>> and delete these comments before `scripts/sane gate {{ID}}`.
Style rules are in docs/05-reporting-style.md. The short form: write it the way you would explain it to a tired
engineer who has ten more reports to read. First person, past tense for what you did, present tense for what the
application does. No headings beyond the ones below. No adjectives doing the work evidence should do.
-->

# <<Weakness>> in <<feature / endpoint>> allows <<who>> to <<what, concretely>>

<!-- Title formula: [bug class] in [exact place] allows [attacker precondition] to [impact].
     Good: "IDOR in /api/v2/invoices/{id}/pdf lets any logged-in user download other organisations' invoices"
     Bad:  "Critical IDOR vulnerability found!!" -->

**Asset:** `{{ASSET}}` (<<scope line this falls under>>)
**Weakness:** <<HackerOne weakness name>> (CWE-<<n>>)
**Severity:** <<Critical | High | Medium | Low>> — `<<CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N>>` (<<score>>)

## Summary

<<Three to five sentences. What the feature is, what check is missing or wrong, and what I could do because of it.
State the attacker's starting position exactly: unauthenticated, any registered user, a member of the same
organisation with the Viewer role. State what the victim has to do, if anything.>>

## Steps to Reproduce

<!-- Numbered, each step one action, each with the exact request or click. A triager with two fresh accounts and
     no knowledge of the app must reach the same result. Name the accounts: attacker A, victim B. -->

Test accounts used (both mine):

- Attacker A: `<<a email / user id / org id>>`
- Victim B: `<<b email / user id / org id>>`

1. As victim B, <<create the object / note the identifier>>. The object's id is `<<id>>`.
2. As attacker A, log in and capture any authenticated request to obtain A's session.
3. Send the following request with A's session:

```http
<<METHOD>> <</path?query>> HTTP/2
Host: {{ASSET}}
Cookie: <<session=A's session, redacted to first/last 4 characters>>
Content-Type: application/json

<<body>>
```

4. The server responds with B's data:

```http
HTTP/2 200 OK
Content-Type: application/json

<<the part of the response that proves it, B's values visible, anything sensitive redacted>>
```

5. <<For a state change: log in as B and show the change. For XSS: open the URL as B and observe the alert / the callback.>>

## Proof of Concept

<!-- One command or one file that reproduces the result end to end. Attach the script from poc/ and paste the
     short form here. Screenshots or a screen recording go in as attachments, named in order: 01-..., 02-... -->

```bash
<<curl command or script invocation that reproduces the finding with the two test accounts>>
```

Attachments: `<<01-request-as-A.png>>`, `<<02-B-data-in-response.png>>`, `<<poc.py>>`

## Impact

<<Who is affected, what the attacker gains, and at what scale, stated as what the proof shows. Tie it to the
business: other customers' invoices with names, addresses and amounts; takeover of any account with one click;
read access to the internal metadata service and the instance role's credentials. If the identifiers are
sequential or enumerable, say so and say that I did not enumerate beyond my own two accounts. If I stopped
before a further step on purpose, say what I did not do.>>

## Remediation

<<One or two sentences an engineer can act on: the check to add and where. "Verify that the invoice's
organisation_id equals the session's organisation before rendering the PDF; the JSON endpoint
/api/v2/invoices/{id} already does this.">>

## Supporting Material / References

- <<CWE or OWASP reference, one line>>
- <<a similar disclosed report, if it helps the triager place the bug: https://hackerone.com/reports/NNNN>>

<!-- Before sending, the operator checks: scope line, programme exclusions, duplicates in hacktivity, that every
     secret is redacted, and that the test objects created are listed for clean-up. -->
