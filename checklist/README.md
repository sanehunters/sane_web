# Checklist

36 chapters, one per vulnerability class. 20 are written (268 test cards); the rest are in the writing queue.
A card is one falsifiable claim about a target. It declares the facts it `Requires`, and the planner
(`scripts/sane plan`) queues it on an asset only when that asset's recorded facts satisfy them.

| File | What it is |
|---|---|
| [`_facts.json`](_facts.json) | the fact vocabulary: every tag a chapter or card may require, how the fingerprinter or a hunter settles it |
| [`_lanes.json`](_lanes.json) | how chapters group into lanes that different agents can run side by side |
| [`../docs/11-item-schema.md`](../docs/11-item-schema.md) | the chapter and card schema; `scripts/sane lint` enforces it |
| [`../kb/reports/`](../kb/reports/README.md) | the disclosed reports each chapter is built from |

States: **queued** (not written yet) · **draft** (on disk, does not lint yet) · **written** (lints clean) · **reviewed** (passed the adversarial review).

## Lane `known` — Known vulnerabilities

Pin the exact version, look up what is known, verify with the advisory's own request, prove minimally. Fast, and occasionally the best finding of the engagement.

Sessions: none. Agent: `cve-exploiter`.

| Chapter | Prefix | State | Cards | Applies when | In the report library |
|---|---|---|---|---|---|
| [Known CVEs, default installs & technology-specific bugs](cve.md) | `CVE` | written | 17 | `http, known-product\|cms\|wordpress\|spring\|java\|php\|dotnet\|node\|python\|ruby` | [240 reports, 64 paid, median $1,000](../kb/reports/cve.md) |

## Lane `infra` — Infrastructure and exposure

What is exposed that should not be, and how do the layers in front of the application disagree with it? Mostly unauthenticated. Recon items here produce new surface for every other lane.

Sessions: none, or account A read-only for a few items. Agent: `class-hunter`.

| Chapter | Prefix | State | Cards | Applies when | In the report library |
|---|---|---|---|---|---|
| [Subdomain takeover & dangling DNS](takeover.md) | `STO` | written | 10 | `cname-3p\|dangling\|cloud-storage\|http` | [178 reports, 27 paid, median $300](../kb/reports/takeover.md) |
| HTTP request smuggling & desync | `SMG` | queued |  | `—` | [78 reports, 27 paid, median $1,800](../kb/reports/smuggling.md) |
| Web cache poisoning & cache deception | `CCH` | queued |  | `—` | [48 reports, 11 paid, median $550](../kb/reports/cache.md) |
| Host header attacks | `HHI` | queued |  | `—` | [11 reports, 2 paid, median $175](../kb/reports/host-header.md) |
| [Cloud, storage buckets & CI/CD exposure](cloud.md) | `CLD` | written | 14 | `http\|ip\|cloud-storage` | [139 reports, 34 paid, median $750](../kb/reports/cloud.md) |
| [Information disclosure, secrets & exposed files](disclosure.md) | `INF` | written | 17 | `http` | [1,780 reports, 351 paid, median $500](../kb/reports/disclosure.md) |
| Network services on IP & CIDR assets | `NET` | queued |  | `—` | [116 reports, 16 paid, median $425](../kb/reports/network.md) |
| Recon & hidden surface (method chapter) | `RCN` | queued |  | `—` | [0 reports, 0 paid, median $0](../kb/reports/recon.md) |

## Lane `authz` — Identity and authorisation

Who is allowed to do what to which object, and where is that decided? Replay every request as the wrong user, the wrong tenant, the wrong role, and through every alternative route. The highest-yield lane on any application with accounts.

Sessions: A and B in different tenants; a low-privilege member and an admin in A's tenant. Agent: `class-hunter`.

| Chapter | Prefix | State | Cards | Applies when | In the report library |
|---|---|---|---|---|---|
| [OAuth, OIDC, SAML & SSO](oauth.md) | `OAU` | draft | 3 | `http, app\|api, oauth-login\|oauth-provider\|saml` | [87 reports, 18 paid, median $1,000](../kb/reports/oauth.md) |
| [JWT & signed-token flaws](jwt.md) | `JWT` | written | 11 | `http, jwt` | [13 reports, 6 paid, median $1,800](../kb/reports/jwt.md) |
| [GraphQL](graphql.md) | `GQL` | written | 13 | `graphql` | [57 reports, 19 paid, median $2,500](../kb/reports/graphql.md) |
| WebSocket | `WSS` | queued |  | `—` | [17 reports, 3 paid, median $800](../kb/reports/websocket.md) |
| [Broken access control: IDOR, BOLA, BFLA, privilege escalation](access-control.md) | `BAC` | written | 18 | `http, app\|api` | [1,459 reports, 374 paid, median $500](../kb/reports/access-control.md) |
| [Authentication, sessions, password reset & 2FA](authn.md) | `AUT` | written | 18 | `http, app\|api, login` | [1,339 reports, 218 paid, median $500](../kb/reports/authn.md) |
| [API flaws: mass assignment, excessive data exposure, versioning](api.md) | `API` | written | 15 | `http, api` | [71 reports, 16 paid, median $550](../kb/reports/api.md) |

## Lane `injection` — Server-side input handling

Which input reaches an interpreter, a parser, a file system or an outbound request, and can I see or infer the result? Probe by behaviour with a control; tools only once a behaviour is established.

Sessions: A. Agent: `class-hunter`.

| Chapter | Prefix | State | Cards | Applies when | In the report library |
|---|---|---|---|---|---|
| LLM & AI features | `LLM` | queued |  | `—` | [15 reports, 0 paid, median $0](../kb/reports/llm.md) |
| [Server-side request forgery](ssrf.md) | `SSR` | written | 10 | `http, app\|api` | [365 reports, 112 paid, median $714](../kb/reports/ssrf.md) |
| [XML external entities & XML injection](xxe.md) | `XXE` | written | 10 | `http, app\|api` | [59 reports, 10 paid, median $1,250](../kb/reports/xxe.md) |
| Server-side template injection | `TPL` | queued |  | `—` | [21 reports, 6 paid, median $2,300](../kb/reports/ssti.md) |
| [Insecure deserialization](deser.md) | `DSR` | written | 11 | `http, app\|api` | [101 reports, 29 paid, median $1,000](../kb/reports/deser.md) |
| [SQL injection](sqli.md) | `SQL` | written | 14 | `http, app\|api, params` | [338 reports, 85 paid, median $1,350](../kb/reports/sqli.md) |
| NoSQL, LDAP & other query injection | `NSQ` | queued |  | `—` | [16 reports, 4 paid, median $2,750](../kb/reports/nosqli.md) |
| [Command & code injection (RCE)](rce.md) | `RCE` | written | 14 | `http, app\|api` | [606 reports, 111 paid, median $1,500](../kb/reports/rce.md) |
| [Path traversal, LFI & RFI](traversal.md) | `LFI` | written | 13 | `http, app\|api` | [356 reports, 64 paid, median $1,000](../kb/reports/traversal.md) |
| File upload | `UPL` | queued |  | `—` | [43 reports, 10 paid, median $500](../kb/reports/upload.md) |
| [CRLF & header injection](crlf.md) | `CRL` | written | 8 | `http` | [148 reports, 24 paid, median $450](../kb/reports/crlf.md) |

## Lane `client` — Client-side and cross-origin

What runs in the victim's browser on the target's origin, and what will the target accept from another origin? Every proof ends in the victim's session, shown in the browser.

Sessions: A as attacker, B as victim in the scriptable browser. Agent: `class-hunter`.

| Chapter | Prefix | State | Cards | Applies when | In the report library |
|---|---|---|---|---|---|
| [Cross-site scripting](xss.md) | `XSS` | written | 18 | `http, app` | [2,640 reports, 569 paid, median $500](../kb/reports/xss.md) |
| [Cross-site request forgery](csrf.md) | `CSR` | written | 12 | `http, app\|api, cookie-auth, state-change` | [556 reports, 99 paid, median $300](../kb/reports/csrf.md) |
| CORS misconfiguration | `COR` | queued |  | `—` | [61 reports, 5 paid, median $500](../kb/reports/cors.md) |
| [Open redirect](redirect.md) | `RDR` | written | 10 | `http` | [362 reports, 70 paid, median $300](../kb/reports/redirect.md) |
| Prototype pollution | `PPL` | queued |  | `—` | [53 reports, 0 paid, median $0](../kb/reports/proto-pollution.md) |
| Clickjacking & UI redressing | `UIR` | queued |  | `—` | [170 reports, 11 paid, median $500](../kb/reports/clickjacking.md) |
| Client-side: postMessage, DOM, CSP, JS supply chain | `CSD` | queued |  | `—` | [16 reports, 2 paid, median $1,000](../kb/reports/client-side.md) |

## Lane `logic` — Business logic and concurrency

What does the business assume happens once, in order, at the server's price? Break the order, the count and the arithmetic. Needs understanding more than tooling.

Sessions: A, and B where a second party is involved. Agent: `class-hunter`.

| Chapter | Prefix | State | Cards | Applies when | In the report library |
|---|---|---|---|---|---|
| Race conditions | `RAC` | queued |  | `—` | [89 reports, 17 paid, median $500](../kb/reports/race.md) |
| [Business logic, payments & abuse of functionality](logic.md) | `BIZ` | written | 15 | `http, app\|api` | [456 reports, 83 paid, median $500](../kb/reports/logic.md) |

Generated by `scripts/chapter_index.py`. Do not edit by hand.
