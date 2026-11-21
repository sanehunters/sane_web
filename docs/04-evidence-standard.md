# 04 — Evidence and proof-of-concept standard

Evidence is what lets someone else believe you. It is collected while testing, not reconstructed afterwards.

## 1. Rules

1. **Raw, not retyped.** Save what the tool produced. `curl -sS -D headers.txt -o body.bin`, `--trace-ascii`,
   browser HAR export, terminal output through `tee`. A request written from memory is not evidence.
2. **A control beside every test.** The request that should work and does; the one that should fail and does; the
   test request. Three files, named so the relationship is obvious.
3. **Timestamps and identity.** Each capture shows when it was taken and as whom. `date -u` in the log; account
   label in the file name.
4. **Your own victims.** Victim B is your account. A third party's data never enters an evidence folder; if it
   appears in a response, redact to shape and follow PB-14.
5. **Redact secrets at capture.** Session cookies, tokens and keys are cut to the first and last four characters
   in anything that will be attached. Keep the unredacted originals only in `accounts/`, which is never committed.
6. **Never fabricate or tidy.** No edited screenshots, no merged responses, no "representative" output. If a
   capture is ugly, take it again.
7. **Reproducible from the folder alone.** Someone with the finding folder and two accounts can repeat everything.

## 2. Layout

```text
engagements/<name>/
  evidence/<host>/<ITEM>/            raw captures made while running a card
    01-control-own-object.txt
    02-control-denied.txt
    03-test-request.txt
  findings/F-NNN/
    finding.json                     state, asset, item, severity, reproductions, h1_id
    claim.md                         one sentence + the steps as believed (input to PB-09)
    verify.json                      the three lens verdicts
    dupcheck.md                      what was searched for duplicates and what was found
    chain.md                         for chains: each link and its evidence
    report.md                        the submission
    cleanup.md                       objects created during testing and whether they were removed
    evidence/                        numbered, in the order the report refers to them
      01-victim-creates-invoice.png
      02-attacker-request.txt
      03-attacker-response.txt
    poc/                             the artefact that reproduces it
      poc.sh | poc.py | poc.html
```

## 3. Capturing

```bash
source "$E/env.sh"; D="$E/evidence/$H/BAC-003"; mkdir -p "$D"
# request and response in one file, headers included, with a timestamp
{ date -u +"# %Y-%m-%dT%H:%M:%SZ as A"; curl -sS -i "${HDR[@]}" $A "$T/api/v2/invoices/48213/pdf" -o - | head -c 4000; } > "$D/03-test-request.txt"
# full trace when the exact bytes matter (smuggling, CRLF, encodings)
curl -sS --trace-ascii "$D/trace.txt" "${HDR[@]}" --path-as-is "$T/static/..%2f..%2fetc/hostname" -o /dev/null
```

Screenshots come from the scriptable browser (Playwright or the Chrome DevTools MCP): full page, URL bar or the
URL printed into the image, the account's identity visible. One screenshot per claim.

## 4. Proof by impact type

| Claim | Minimum proof | Stop before |
|---|---|---|
| Read another user's data | B's object in A's response, and B's own view of the same object | a second victim; enumeration |
| Change another user's data | the request as A, then B's view showing the change | anything B cannot undo |
| Account takeover | login as B after the attack, on your B | any real account |
| XSS | `alert(document.domain)` or a callback carrying `document.domain`, in the victim role's session | reading real users' sessions |
| SSRF | internal content or the oracle table; for metadata, the role name or identity document | using credentials |
| RCE | output of `id`/`hostname`, or a DNS callback with the hostname | a shell, file writes, lateral movement |
| SQL injection | DBMS version, current user; a boolean pair for blind | table contents |
| File read | `/etc/hostname`; first line of `/etc/passwd` | secrets, source beyond one innocuous file |
| File upload → execution | a file that prints a fixed marker, then deleted | a web shell |
| Auth bypass | one protected page or API response | browsing further |
| Payment or logic | the order or entitlement in your account, at the wrong price or state | cashing out; repeat use |
| Race condition | the over-limit state in your account, and the success rate over N runs | draining anything |
| Takeover of a subdomain | an inert file at an unguessable path, `dig` output | content at the root, cookie capture |
| Leaked credential | one identity call | any other call |
| Known CVE | the advisory's distinguishing request and response on the target | the destructive part of any public exploit |

## 5. Clean-up

List in `cleanup.md` every account, object, file, webhook, callback and DNS record the testing created. Remove
what you can as soon as the evidence is captured; say in the report what remains and how to recognise it (a
naming convention like `h1-<username>-test` on everything you create makes this easy).
