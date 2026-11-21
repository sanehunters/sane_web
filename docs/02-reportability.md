# 02 — What is reportable

A behaviour is reportable when four things hold together. `scripts/sane gate` checks the mechanical parts; the
judgement is here.

## 1. In scope

- The asset matches an `in` rule and no `out` rule (`scripts/sane scope check`). The finding lives where the
  vulnerable code runs, not where you started: an SSRF on an in-scope app that reaches a third party is in scope;
  a bug on the third party's own service is not.
- The class is not excluded by the policy. An excluded class is reportable only as a link in a chain whose end
  impact is not excluded and is demonstrated.
- The method was allowed: the rate, the tools, the accounts, the data touched.
- Third-party components hosted by the programme (their Jira, their WordPress) are in scope when the host is;
  bugs in the vendor's SaaS (their Zendesk tenant, their Okta) usually are not, unless it is the organisation's
  misconfiguration.

## 2. Real

- Reproduced at least twice from clean state: new sessions, fresh test objects.
- With a control: the same request that should succeed does, and the one that should fail does.
- The guard lens (PB-09) failed to explain it away: the object was private, the data was the victim's, nothing was
  cached, no precondition was arranged, no later check stops it.
- It still reproduces on the day of the report.

## 3. Impactful

There is a consequence for the organisation or its users that a reasonable security team would act on, and the
proof shows it.

| Has impact | Does not, by itself |
|---|---|
| Reading or changing another user's or tenant's data | Reading your own data by another route |
| Acting as another user; taking over an account | Logging yourself out; changing your own settings via CSRF |
| Executing script in another user's session on the target origin | Script that runs only in your own session (self-XSS) |
| Reading files, running commands, reaching internal services from the server | An error message, a version banner, an internal IP |
| Getting paid features, money or credit you are not entitled to | Client-side only bypass that the server rejects |
| A secret that grants access to something | A key designed to be public (Maps browser key, Stripe publishable key, Firebase web config) |
| A working known-CVE exploit on their host | An old version number |

"Best practice" gaps are not impact: missing headers, weak TLS settings, cookie flags, password policy, lack of
rate limiting without a demonstrated consequence, SPF/DMARC. `docs/07-graveyard.md` is the long list.

## 4. Yours to report

- Not a duplicate you can detect: search the programme's disclosed reports and hacktivity before writing
  (`dupcheck.md`). You cannot see undisclosed duplicates; speed and depth are the only defences.
- Found by you, within the rules, without harm. A finding obtained by breaking a rule is not improved by being
  true.
- Reported once: one root cause, one report, all instances listed.

## Borderline calls

| Situation | Call |
|---|---|
| Needs the victim to click a link | Reportable; state it (`UI:R`). Check the policy for "user interaction" exclusions. |
| Needs the attacker to be a member of the same organisation | Reportable when the role is not supposed to have that power; say which role. |
| Needs an admin attacker | Usually not, unless it crosses tenants or reaches the server. |
| Works only on an outdated browser | Usually not. |
| Open redirect, alone | Low or excluded; hold it as a chain link. |
| Rate-limit absence on login | Excluded on most programmes; reportable when it defeats a short OTP or a reset code and you show the arithmetic within the allowed volume. |
| Subdomain takeover you could claim | Reportable where `takeover-ok`; claim with an inert proof file only. |
| Leaked credentials in a public repository | Reportable when live and the organisation's; validate with one identity call if the policy allows. |
| Known CVE, version matches, check fails | Not reportable. |
| Known CVE, check verifies, exploit proven minimal | Reportable; check the patch-window rule. |
| A bug you can describe but not trigger | Not yet. Park it. |
