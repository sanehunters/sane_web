# 07 — The graveyard

What gets closed as informative, not applicable or duplicate, on almost every programme. Knowing this list saves
more hours than any technique. Each chapter has its own graveyard section; this is the cross-class core. The
bracketed tag is the exclusion tag from `checklist/_facts.json` that closes the matching items when the policy
names it.

An entry here is not "never report". It is "never report alone". Several are useful chain links (PB-10).

## Almost never accepted standalone

| Observation | Why it is closed | Becomes a finding when |
|---|---|---|
| Missing security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy [`missing-headers`] | best practice, no exploit shown | never by itself; it only removes a mitigation from another finding |
| Cookie without `Secure`/`HttpOnly`/`SameSite` [`missing-headers`] | same | you have XSS and the session cookie is readable: mention it there |
| Clickjacking on pages with no sensitive one-click action [`clickjacking`] | no impact | a state-changing action completes in one or two clicks inside the frame, with a PoC page |
| Self-XSS [`self-xss`] | the victim attacks themselves | a login CSRF, a CSRF on the storing field or a cache makes it fire for someone else |
| Logout CSRF, login CSRF [`csrf-low`] | no meaningful impact | login CSRF plus a stored self-XSS, or plus a feature that binds the victim's data to your account |
| Open redirect [`open-redirect`] | phishing aid only | it leaks an OAuth code or token, bypasses an SSRF allow-list, or accepts `javascript:` |
| Missing rate limit [`rate-limit`] | policy-level, noisy to prove | it defeats a 4–6 digit code within the allowed volume, with the arithmetic shown |
| User, e-mail or username enumeration [`user-enum`] | accepted risk for most products | it exposes private membership (who is a customer of a sensitive service) or feeds a demonstrated attack |
| Version, banner or stack-trace disclosure [`version-disclosure`] | information only | the version has a CVE you verified (PB-07); the trace contains a secret |
| Internal IP addresses or host names in responses | information only | they are the missing piece of an SSRF |
| TLS configuration, weak ciphers, certificate details [`ssl-tls`] | scanner output | essentially never |
| SPF, DKIM, DMARC records [`spf-dmarc`] | scanner output | a few programmes accept spoofing of the main domain with a delivered-to-inbox proof; most do not |
| Content spoofing, text injection [`content-spoofing`] | no code execution, no origin compromise | HTML injection that survives into e-mails sent by the company to other users |
| Reverse tabnabbing [`tabnabbing`] | browsers mitigate it by default now | essentially never |
| CSV / formula injection [`csv-injection`] | the spreadsheet application's problem | essentially never |
| Host header reflected with no consumer [`host-header`] | no impact | reset-link poisoning or cache poisoning (HHI, CCH) |
| CORS `*` without credentials, or reflection on public data [`cors`] | nothing private is readable | credentialed reflection on an endpoint returning secrets, with a PoC page |
| Outdated JavaScript library | no exploit path in this app | you exploit it in this app |
| Known CVE by version number only [`known-cve`] | back-ports, virtual patches | the advisory's check verifies and you prove minimal impact |
| `autocomplete` on password fields, password policy, "no account lockout" | best practice | never |
| Session not invalidated on logout or password change [`session-expiry`] | many programmes exclude it | a few accept it for password change; check the policy |
| Public keys by design: Google Maps browser key, Firebase web config, Stripe publishable key, Sentry DSN, Algolia search key | designed to be public | the key has write or admin rights it should not, shown with a harmless call |
| EXIF data in uploaded images | privacy nicety | the product is one where location is sensitive and other users can fetch the original |
| Denial of service of any kind [`dos`] | out of bounds to test | the policy invites it, or one small request takes the service down and you show it in a way that does not |
| Anything needing a man-in-the-middle, physical access, a rooted device or malware on the victim [`mitm`, `physical`] | outside the threat model | never on web programmes |
| Social engineering of staff or users [`social-engineering`] | forbidden | never |
| Bugs in third-party SaaS the company merely uses [`third-party`] | not theirs to fix | it is their misconfiguration of that service |
| Credentials from breach dumps [`leaked-credentials`] | not a vulnerability in the target | never; do not try them |
| "Prompt injection" that only changes the model's tone or reveals a generic system prompt [`prompt-injection`] | no security boundary crossed | the model acts with privileges or data the user does not have |
| Scanner output without a manual proof [`automated`] | noise | you verify and prove it by hand |

## Duplicates before you start

On a programme that has been public for more than a few weeks, assume someone has already reported everything a
default scan finds: exposed `.git`, `.env`, default credentials on obvious panels, the reflected XSS on the search
box, the open redirect on `?next=`, the takeover on the abandoned CNAME. Check them quickly, because sometimes
they are still there, but do not build the day around them. What is rarely duplicated: authorisation bugs that
need two accounts and an understanding of the product; logic bugs in the money path; chains; anything behind a
feature that takes effort to set up; findings on assets that needed real recon to discover; bypasses of previous
fixes.

## How to use this file

- Before spending a timebox on a card, check whether its outcome would land here. If so, run the quick check,
  record the primitive as `parked`, and move on.
- When PB-09's triager lens says `weak`, find the row here and read its right-hand column: that is the PB-10
  assignment.
- When a report is closed as informative, add the lesson to the chapter's graveyard so the next session inherits it.
