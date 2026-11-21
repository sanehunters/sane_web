# 06 — Severity

HackerOne programmes rate with CVSS (3.1 on most, 4.0 on some) or with their own table; the policy says which
(PB-00). Rate on what the proof shows. A triager who sees an honest vector trusts the rest of the report.

## 1. CVSS 3.1, the parts that get argued about

`CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_`

| Metric | Choose | Common mistake |
|---|---|---|
| **AV** | `N` for anything over the internet | — |
| **AC** | `L` unless success depends on something outside your control: winning a race with low odds, guessing an unguessable value, a specific configuration, a man-in-the-middle position | marking `L` for a race you win one time in fifty |
| **PR** | `N` unauthenticated; `L` any self-registered account or low role; `H` an admin-level account | `N` for a bug that needs a login because "anyone can sign up". Free sign-up is still `L` |
| **UI** | `R` if a victim must do anything: click, open, visit | `N` for reflected XSS or CSRF |
| **S** | `C` when the impact lands in a different security authority than the vulnerable component: XSS (browser context), SSRF reaching other systems, sandbox escapes. Otherwise `U` | `C` for everything serious |
| **C / I / A** | `H` total loss for the affected scope (any user's data, arbitrary write); `L` limited or non-sensitive; `N` none shown | `H/H/H` for an IDOR that reads one field |

## 2. Typical vectors, as a sanity check

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

## 3. How programmes move the number

- **Asset tier.** Many programmes cap severity per asset (`max_severity` in the imported scope). A critical on a
  marketing site is paid as the cap says.
- **Data sensitivity.** The same IDOR is medium on display names and high on documents or payment data.
- **Scale.** "Any user" beats "users who shared a link with me". Enumerable ids matter; say whether they are.
- **Privileges required.** A bug needing a paid plan or an invited role is rated below the same bug from a free
  account.
- **Mitigations in place.** HttpOnly cookies, CSP, short-lived tokens lower XSS impact unless you show a way
  around them.
- **Chains.** Rated on the end state; some programmes pay per link.

## 4. Writing the rating

Give the vector and the score, then one sentence for any metric a reader might dispute:

> Medium — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5). `PR:L` because a free account is enough;
> `C:H` because full invoices of any tenant are readable. The programme's own table lists cross-tenant data
> exposure as High; I have left the field at the CVSS result.

When in doubt between two levels, claim the lower and let the evidence argue. Never rate on what the class can do
in theory.

## 5. CVSS 4.0

Where the programme uses it: `AT` (attack requirements) takes over part of what `AC:H` meant; `UI` splits into
`P` (passive: just visiting) and `A` (active: a deliberate action); impact is split into the vulnerable system
(`VC/VI/VA`) and subsequent systems (`SC/SI/SA`), which replaces Scope. XSS is typically
`VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` with `UI:A` for reflected and `UI:P` for stored. `scripts/sane gate` accepts
either version's vector.
