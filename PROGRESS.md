# Build progress

_Updated 2026-11-22 12:51 UTC by `scripts/publish_progress.sh`. Refreshes every few minutes while a build is running._

| | | |
|---|---|---|
| Chapters written | `████████████░░░░░░░░` | **22 of 36** (295 test cards) |
| Chapters reviewed | `░░░░░░░░░░░░░░░░░░░░` | **0 of 36** |
| Drafts in progress | | 0 (on the `wip` branch until they lint) |
| Not started | | 14 |

## Right now

6 agent(s) working:

- `write:cache`
- `write:clickjacking`
- `write:network`
- `write:oauth`
- `write:race`
- `write:upload`

Order of work: every chapter is written first (most-paid classes first), then every chapter gets an adversarial review. "Reviewed" therefore stays at zero until the writers are done.

## Chapters

| Chapter | Lane | State | Cards | Now | File last changed (UTC) | Review |
|---|---|---|---|---|---|---|
| [Broken access control: IDOR, BOLA, BFLA, privilege escalation](checklist/access-control.md) | `authz` | written | 18 |  | 21 Nov 17:34 |  |
| [API flaws: mass assignment, excessive data exposure, versioning](checklist/api.md) | `authz` | written | 15 |  | 22 Nov 02:51 |  |
| [Authentication, sessions, password reset & 2FA](checklist/authn.md) | `authz` | written | 18 |  | 21 Nov 17:34 |  |
| [GraphQL](checklist/graphql.md) | `authz` | written | 13 |  | 21 Nov 12:53 |  |
| [JWT & signed-token flaws](checklist/jwt.md) | `authz` | written | 11 |  | 21 Nov 12:53 |  |
| [OAuth, OIDC, SAML & SSO](checklist/oauth.md) | `authz` | written | 15 | being written | 22 Nov 12:50 |  |
| [Cross-site request forgery](checklist/csrf.md) | `client` | written | 12 |  | 22 Nov 08:08 |  |
| [Open redirect](checklist/redirect.md) | `client` | written | 10 |  | 22 Nov 08:01 |  |
| [Cross-site scripting](checklist/xss.md) | `client` | written | 18 |  | 21 Nov 17:32 |  |
| [Cloud, storage buckets & CI/CD exposure](checklist/cloud.md) | `infra` | written | 14 |  | 22 Nov 08:10 |  |
| [Information disclosure, secrets & exposed files](checklist/disclosure.md) | `infra` | written | 17 |  | 22 Nov 07:12 |  |
| [Network services on IP & CIDR assets](checklist/network.md) | `infra` | written | 12 | being written | 22 Nov 12:50 |  |
| [Subdomain takeover & dangling DNS](checklist/takeover.md) | `infra` | written | 10 |  | 22 Nov 08:03 |  |
| [CRLF & header injection](checklist/crlf.md) | `injection` | written | 8 |  | 22 Nov 12:30 |  |
| [Insecure deserialization](checklist/deser.md) | `injection` | written | 11 |  | 21 Nov 12:53 |  |
| [Command & code injection (RCE)](checklist/rce.md) | `injection` | written | 14 |  | 22 Nov 07:59 |  |
| [SQL injection](checklist/sqli.md) | `injection` | written | 14 |  | 22 Nov 02:51 |  |
| [Server-side request forgery](checklist/ssrf.md) | `injection` | written | 10 |  | 21 Nov 12:22 |  |
| [Path traversal, LFI & RFI](checklist/traversal.md) | `injection` | written | 13 |  | 22 Nov 07:55 |  |
| [XML external entities & XML injection](checklist/xxe.md) | `injection` | written | 10 |  | 21 Nov 12:53 |  |
| [Known CVEs, default installs & technology-specific bugs](checklist/cve.md) | `known` | written | 17 |  | 22 Nov 02:54 |  |
| [Business logic, payments & abuse of functionality](checklist/logic.md) | `logic` | written | 15 |  | 22 Nov 07:12 |  |
| WebSocket | `authz` | queued |  |  |  |  |
| Clickjacking & UI redressing | `client` | queued |  | being written |  |  |
| Client-side: postMessage, DOM, CSP, JS supply chain | `client` | queued |  |  |  |  |
| CORS misconfiguration | `client` | queued |  |  |  |  |
| Prototype pollution | `client` | queued |  |  |  |  |
| Web cache poisoning & cache deception | `infra` | queued |  | being written |  |  |
| Host header attacks | `infra` | queued |  |  |  |  |
| Recon & hidden surface (method chapter) | `infra` | queued |  |  |  |  |
| HTTP request smuggling & desync | `infra` | queued |  |  |  |  |
| LLM & AI features | `injection` | queued |  |  |  |  |
| NoSQL, LDAP & other query injection | `injection` | queued |  |  |  |  |
| Server-side template injection | `injection` | queued |  |  |  |  |
| File upload | `injection` | queued |  | being written |  |  |
| Race conditions | `logic` | queued |  | being written |  |  |

## Everything else

The engine, the scope guard and hooks, the playbooks, the skills and agents, the saved workflows, the report library and the tests are complete; the build tracker issue lists them with links. `scripts/selftest.sh` exercises all of it against a local stand-in target.

States: **queued** not started · **draft** on disk, does not lint yet · **written** lints clean, on `main` · **reviewed** passed the adversarial review.
