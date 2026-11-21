# PB-10 · Chain and escalate impact

| | |
|---|---|
| **Trigger** | A verified finding whose impact could be greater; a `weak` triager verdict; any `parked` primitive |
| **Entry state** | At least one real, reproducible behaviour that falls short of the impact a programme pays for |
| **Runs as** | Main session |
| **Timebox** | 90 minutes per chain attempt |
| **Output on disk** | `findings/F-NNN/chain.md`: the links, each with its own evidence; an updated severity |
| **Next** | PB-09 for the chain as a whole, then PB-11 |

Programmes pay for impact. The same root cause is a $150 report or a $5,000 report depending on what the proof
shows at the end of it. This playbook is the work between those two numbers, and it has a hard edge: you raise
impact by demonstrating more, never by doing harm.

## Steps

1. **List the primitives.** `grep -E ',(parked|finding),' "$E/coverage.csv"` and the open findings. Write each as
   a capability, not a bug name: "I can make the server send a GET to any URL and see the status code", "I can
   set any user's display name to arbitrary HTML that is rendered escaped in the app and unescaped in e-mails",
   "I can redirect a logged-in user from the target's domain to any URL".
2. **For each primitive ask what it is missing** and look for exactly that:

   | You have | Missing for impact | Look for |
   |---|---|---|
   | Open redirect | a secret that travels with the redirect | OAuth `redirect_uri` allow-listing by prefix (OAU), SSRF allow-lists (SSR-004), `javascript:` scheme (XSS) |
   | Self-XSS | a way to make it fire in the victim's session | login CSRF, CSRF on the field that stores it, a cache that stores your response (CCH) |
   | Reflected or stored XSS | the consequence | session or API-token theft when cookies are not HttpOnly, forced e-mail change, admin action via XHR |
   | CSRF on a minor action | a sensitive action or account binding | e-mail change, OAuth account linking, API-key creation |
   | CORS reflection | a credentialed endpoint returning secrets | token, API-key or PII endpoints with cookie auth |
   | Blind SSRF | a readable response or a state change | redirects, internal services with GET side effects (stop at proof), cloud metadata |
   | IDOR read of low-value data | higher-value objects or a write | the same pattern on exports, attachments, tokens, invitations; the write verb on the same route |
   | Information disclosure (ids, e-mails, internal hosts) | a use for it | IDOR that needed unguessable ids; password reset that needed an e-mail; SSRF that needed a host name |
   | Subdomain takeover | what trusts that subdomain | cookies scoped to the parent domain, CORS allow-lists, CSP `script-src`, OAuth redirect allow-lists |
   | Host header control | a consumer of the header | password-reset links (HHI), cache keys (CCH) |
   | CRLF injection | a header that matters | `Set-Cookie` for session fixation, response splitting into XSS |
   | File upload of arbitrary type | execution or rendering | same-origin serving (stored XSS), a path you control (traversal), a processor (RCE via converters) |
   | Path traversal read | a secret that opens a door | source code for further bugs; never use live credentials found this way |
   | Low-privilege account takeover vector | reach to a privileged user | the same vector against an admin of your own tenant |

3. **Check the library for the chain.** HexBrain `search_reports` with both class names; offline
   `scripts/sane kb search <a> <b>`. A chain that has paid before is easier to explain and to rate.
4. **Build the chain on your own accounts**, end to end, as a single reproducible sequence. Write
   `findings/F-NNN/chain.md`: each link, its request and response, and the state after it. The final state must
   be the impact you will claim.
5. **Re-rate.** Score the chain on its end state (docs/06). Note which links are separately reportable: some
   programmes pay per link, most pay the chain once. Follow the policy from PB-00.
6. **Know when the single bug is enough.** If the standalone finding is already medium or higher and the chain is
   speculative, report it now and continue chaining afterwards; a follow-up comment with a demonstrated escalation
   is welcome on most programmes. Sitting on a valid bug risks a duplicate.

## Decision points

- The next link needs another user's real account or data → stop. Rebuild the scenario with your own second
  account, or describe the step and what it would give without doing it.
- The escalation would use credentials found in the target (cloud keys, tokens, database passwords) → one
  read-only identity call at most (`aws sts get-caller-identity`), and only where the policy does not forbid it.
  Report what the credential is, not what it opens.
- The chain depends on an excluded class as one link → acceptable when the end impact stands by itself; say so
  in the report's first paragraph.
- Two primitives on different programmes → never chained.

## Call it off when

- Ninety minutes without a working second link.
- The only escalations left are harmful or out of scope.

## Done when

`chain.md` reproduces end to end from clean state, or the primitive is back in `parked` with the missing link
named precisely.

## Hand to the operator when

- You can describe a critical impact that is one harmful step away. They decide, with the programme if needed,
  whether that step may be taken; the default is that it is described, not performed.
