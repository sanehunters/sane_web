---
name: hunt
description: Run the hunt loop — take the best applicable test card, start its clock, test with a control, record exactly one outcome, repeat. Use when the queue is non-empty and the user says hunt, continue, test, or find bugs.
---

<!-- GENERATED from src/skills/hunt.md by scripts/build_claude.py. Edit that file or the included playbook, then rebuild. -->

# /hunt — playbook PB-06

`$ARGUMENTS` may name an asset or a class (`/hunt app.example.com`, `/hunt access-control`).

Loop, one card at a time:

1. `scripts/sane next [--asset H] [--class C]`. If candidates are listed first, do `/verify` before anything else.
2. `scripts/sane card <ITEM> <asset>` — read all of it, including "Not a finding when" and the prior art.
3. `scripts/sane start <asset> <ITEM>` — the timebox starts (20 / 45 / 120 minutes by cost).
4. Aim: pick the two or three endpoints from `recon/<host>/map.md` where the claim is most likely true.
5. Test as the card's How says. Every command: `source "$E/env.sh"`, `"${HDR[@]}"`, output saved under
   `$E/evidence/<host>/<ITEM>/`. Always a control request beside the test request.
6. Record one outcome with `scripts/sane mark <asset> <ITEM> <status> --note "..."`:
   `negative` (name the mechanism) · `candidate` (→ `/verify` now) · `parked` (→ `/chain` later) · `dup-risk` · `skipped`.
7. If the card's precondition was false, fix the fact instead of marking: `scripts/sane fact set ...`.

When the clock runs out: close, park, promote, or extend once with a written reason. Never drift.

For several deployments, give each to one `class-hunter` agent. Never two on one deployment.

Stop and switch to PB-14 on rate limiting, blocks, degradation, or any third-party data in a response.


---

## Reference: PB-06 · Hunt: one card at a time

_Included from `playbooks/PB-06-hunt.md`. That file is the source of truth._

| | |
|---|---|
| **Trigger** | `scripts/sane next` returns items |
| **Entry state** | Facts settled for the deployment; accounts recorded where the items need them |
| **Runs as** | Main session, or one `class-hunter` agent per deployment |
| **Timebox** | per card: 20 minutes (`low`), 45 (`medium`), 120 (`high`) |
| **Output on disk** | a row in `coverage.csv` for every card opened; raw evidence under `evidence/<host>/<item>/` |
| **Next** | PB-09 when a card yields a candidate; PB-10 when it yields a primitive; otherwise the next card |

The loop is deliberately small. A card is one falsifiable claim about the target. You try to make it true, and
you write down which way it went and why.

### Steps

1. **Take the top card.** `scripts/sane next`, then `scripts/sane card <ITEM> <asset>`.
   The card prints the claim, where to aim, how to test, what counts as proof, the known false positives, and the
   disclosed reports that show the technique paying.
2. **Start the clock.** `scripts/sane start <asset> <ITEM>` creates `evidence/<asset>/<ITEM>/` and stamps the time.
3. **Aim before firing.** From `recon/<host>/map.md` pick the two or three endpoints where this claim is most
   likely true. A card run against the endpoint the developer hardened first teaches nothing. If a prior-art
   report matches the feature in front of you, read it: `scripts/sane kb show <id>`.
4. **Run the test as the card's How says**, adapted to the real endpoint. Every command that touches the target
   starts with `source "$E/env.sh"` and carries `"${HDR[@]}"`. Save raw output, do not retype it:
   `curl -sS "${HDR[@]}" $A ... -D "$E/evidence/$H/<ITEM>/01-resp.headers" -o "$E/evidence/$H/<ITEM>/01-resp.body"`
5. **Compare with a control.** One request that should succeed and one that should fail, alongside the test
   request. Without the control you cannot tell a finding from the application's normal behaviour.
6. **Decide and record.** Exactly one of:

   | Outcome | Command |
   |---|---|
   | The control holds | `scripts/sane mark <asset> <ITEM> negative --note "<the mechanism: which check, where, how observed>"` |
   | A signal that needs proof | `scripts/sane mark <asset> <ITEM> candidate --note "<what was seen; what would prove it>"` → PB-09 now |
   | Real, without standalone impact | `scripts/sane mark <asset> <ITEM> parked --note "<what it would chain with>"` → PB-10 later |
   | Real, but a duplicate is likely | `scripts/sane mark <asset> <ITEM> dup-risk --note "<why: scanner-findable, old, already in hacktivity>"` |
   | Deliberately not run | `scripts/sane mark <asset> <ITEM> skipped --note "<risk or budget reason>"` |

7. **Anything else you noticed** goes in `notes.md` as one line, and into PB-13's table if it is a known signal.
   Then the next card.

### Decision points

- The card's precondition turns out false on this asset (no such feature after all) → do not mark it negative.
  Fix the fact: `scripts/sane fact set <asset> <tag>=0 --ev "..."`. The planner closes this card and its siblings.
- You find the feature the card needs on a different endpoint or host → test there; record the asset where it
  lives.
- A WAF blocks the payload → three attempts at an encoding or context change guided by `find_bypasses` (HexBrain)
  or the chapter's bypass notes, then park with the note "WAF: <vendor>, blocked on <pattern>". Fighting a WAF is
  rarely the best use of the hour.
- The test would change or destroy data, lock an account or message real users → do it only on your own account
  B, or skip with the reason.
- 429s or blocks start → PB-14.
- The same idea would clearly apply to a sibling endpoint → test the sibling inside the same card; note both.

### Call it off when

- The card's timebox expires: close it negative, park it, promote it, or extend once with a written reason
  (`playbooks/README.md`, "Timeboxes and calling it off").
- Three distinct techniques hit the same generic control.
- Continuing would need a volume of requests the programme rate does not allow in the timebox.

### Done when

The card has a hand-written status with a note that a stranger could check, and its evidence is on disk.

### Hand to the operator when

- A card needs something physical or personal: an SMS code, a payment, a second device.
- You believe you have a critical. Verify first (PB-09), then tell them at once; they may want to submit before
  anything else happens.

---

## Reference: PB-13 · Signals: when you see X, do Y

_Included from `playbooks/PB-13-signals.md`. That file is the source of truth._

| | |
|---|---|
| **Trigger** | Any observation, in any phase, that matches a row below |
| **Entry state** | — |
| **Runs as** | Whoever saw it |
| **Timebox** | Two minutes to record and route; the follow-up has its own clock |
| **Output on disk** | A fact set with evidence, or a line in `notes.md`, or a hypothesis |
| **Next** | The chapter or playbook the row names |

This is the routing table: an alert comes in, you look up what it means and where it goes. The first action is
almost always to record a fact, because a recorded fact re-plans every card that depends on it. Do not test on the
spot unless the row says so; finish what you were doing and let the queue bring it back with the right priority.

### Signals from responses and headers

| You see | It means | Record | Then |
|---|---|---|---|
| A product name with a version anywhere (header, footer, `/version`, error page, bundle banner) | a CVE lookup is possible | add to `recon/<host>/tech.json`; `known-product=1` | PB-07 now; it is cheap |
| `Age`, `X-Cache`, `CF-Cache-Status`, `X-Varnish` | a shared cache stores responses | `cache=1` | `checklist/cache.md` |
| `Access-Control-Allow-Origin` echoing your Origin, or `null` | CORS policy is dynamic | `cors-headers=1` | `checklist/cors.md` |
| `Via`, two different `Server` values across error types, a CDN error page for some paths and an app error for others | front end and back end disagree about something | `reverse-proxy=1` | `checklist/smuggling.md`, traversal items on path normalisation |
| A JWT (`eyJ...`) in a cookie, header or URL | signed-token logic | `jwt=1`; decode the header and payload into `notes.md` | `checklist/jwt.md` |
| `rO0AB`, `__VIEWSTATE`, `O:8:"`, base64 that decodes to a class name | serialized objects cross the boundary | `serialized=1` | `checklist/deser.md` |
| A stack trace or framework error page | technology and often paths, versions, query fragments | the tech fact; the trace into `evidence/` | CVE-001; the matching injection chapter if the error followed your input |
| A different error for a single quote, a backslash or `{{7*7}}` than for plain text | input reaches an interpreter | one line in `notes.md` with the request | `sqli`, `ssti`, `rce` chapter by error type |
| `Location:` built from a parameter | a redirect you may control | `redirect-param=1` | `checklist/redirect.md`; keep as a chain link for OAuth and SSRF |
| Your Host or `X-Forwarded-Host` value in a response body, link or `Location` | the app builds URLs from request headers | note the endpoint | `checklist/host-header.md`, `checklist/cache.md` |
| A 403 on a path that clearly exists | access control at the edge, maybe only there | note the path | BAC bypass items (path normalisation, method, headers) |
| A 401/403 from the API where the UI never called it | a hidden or privileged endpoint | add to `map.md` as `hidden` | `access-control` chapter as a low role |
| Response carries more fields than the UI shows (`isAdmin`, `role`, `internalNote`, other users' e-mails) | excessive data exposure; also names for mass assignment | save the response | `checklist/api.md` |
| `Set-Cookie` without `HttpOnly` on the session, or a token in `localStorage` | XSS becomes account takeover | note it | raises the ceiling of every XSS item |
| A 500 on unexpected types (array for string, negative number, very long value) | unvalidated input path | `notes.md` with the request | PB-08 hypothesis, lens `parser-differential` or `client-trust` |
| Response time jumps for certain inputs | a blind channel, or a heavy query | note the timing pair | blind injection items; do not turn it into load |
| An S3, GCS or Azure Blob URL | cloud storage in use | `cloud-storage=1`; the bucket name | `checklist/cloud.md` |
| A CNAME to a third-party service, or an "unclaimed" page | possible takeover | `cname-3p=1`, `dangling=1` | `checklist/takeover.md`; check `takeover-ok` in the policy first |

### Signals from features

| You see | It means | Record | Then |
|---|---|---|---|
| Any field that takes a URL (webhook, import, avatar by link, "fetch from") | the server makes requests for you | `url-fetch=1` | `checklist/ssrf.md` |
| "Download as PDF", invoices, reports, e-mail previews built from your input | server-side rendering | `render=1` | SSR-007, `checklist/ssti.md`, XSS in the renderer |
| File upload of any kind | storage, serving and often processing | `upload=1`; if the stored file differs from what you sent, `file-processing=1` | `checklist/upload.md`, XXE and SSRF file-format items |
| Numeric or guessable ids in requests | objects addressed directly | `object-ids=1` | `checklist/access-control.md` with accounts A and B |
| Organisations, teams, workspaces | tenant isolation to break | `multi-tenant=1` | cross-tenant items first: they pay the most |
| Roles and permissions UI | vertical access control | `roles=1` | BFLA items with the low role |
| Invitations, share links, magic links | tokens that grant access | `invite=1` | token scope, reuse and leakage items in BAC and AUT |
| Password reset, e-mail change, 2FA setup | account-takeover surface | `password-reset=1`, `mfa=1` | `checklist/authn.md`, HHI-001 |
| "Sign in with ..." or an SSO option | OAuth or SAML glue | `oauth-login=1` / `saml=1` | `checklist/oauth.md` |
| Coupons, credits, plans, checkout, refunds, limits | money and counters | `payments=1`, `limited-action=1` | `checklist/logic.md`, `checklist/race.md` |
| A rich-text or Markdown editor; anywhere your text is shown to others | stored content | `user-content=1`, `rich-text=1` | stored XSS items; try the e-mail and PDF renderings of the same field |
| Templates with `{{placeholders}}` you can edit | server-side evaluation of your template | `template-input=1` | `checklist/ssti.md` |
| An XML body, SOAP, SAML, or an import of SVG/DOCX/XLSX/RSS | an XML parser on your input | `xml-input=1` | `checklist/xxe.md` |
| A chat assistant or "AI" feature | an LLM reading content, maybe with tools | `ai-feature=1` | `checklist/llm.md` |
| A GraphQL endpoint | a second API with its own authorisation | `graphql=1`, the path | `checklist/graphql.md`; compare with REST (lens `second-path`) |
| `new WebSocket(` or a 101 response | a channel that often skips the HTTP middleware | `websocket=1` | `checklist/websocket.md` |
| `postMessage` listeners in the bundle | cross-window trust | `postmessage=1` | `checklist/client-side.md` |
| Swagger, OpenAPI, Postman collection | the full endpoint list | `api-docs=1`; save the file | API items: sweep every operation unauthenticated and as the low role |
| `/v1/` next to `/v2/`, or `/internal/`, `/beta/`, `/mobile/` | parallel implementations | note both | lens `second-path`: replay every v2 authorisation test against v1 |
| A staging, dev or UAT twin of production | weaker controls, sometimes shared data or sessions | the asset, if in scope | replay the top findings and auth flows there |

### Signals from your own results

| You see | It means | Then |
|---|---|---|
| One real IDOR | the authorisation pattern is per-endpoint, not central | sweep every sibling endpoint and verb for the same pattern before reporting; report the set |
| One reflected parameter unescaped | the output encoding is not framework-wide | check the other parameters on the same template and the stored variants |
| A fix that blocks your exact payload | a block-list | the bypass is a new finding: `find_bypasses`, encodings, alternate verbs |
| Three cards in a row closed for the same framework-level control | this application is solid at that layer | stop spending cards there; go where the code is hand-written (PB-08) |
| Everything on a host returns the same page | you are looking at a default vhost or a WAF | `default-page=1`; virtual-host and path discovery items |
| A sudden run of 429 or 403 | you were rate limited or blocked | PB-14 |
| Real personal data of a third party in a response | you have found something and must stop looking at it | PB-14, then PB-09 |

### Done when

The fact is recorded with its evidence, or the note or hypothesis is written, and you are back on what you were
doing.