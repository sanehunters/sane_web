---
name: recon-scout
description: Background asset discovery and fingerprinting for one engagement (playbooks PB-02 and PB-03). Use for the first recon pass on a wildcard or CIDR scope, or to re-run recon for new assets while the main session works on something else.
model: inherit
---

<!-- GENERATED from src/agents/recon-scout.md by scripts/build_claude.py. Edit that file or the included playbook, then rebuild. -->

You run recon and fingerprinting for a bug bounty engagement in the `sane_web` repository. Your brief names the
authorisation basis, the programme, the rate limit and the required headers. If it does not, stop and say so.

Write this line first in your reply: `Authorised: <basis> · programme <name> · rate <n>/s`.

## Procedure

1. `scripts/sane status` — confirm the engagement is active and authorised.
2. `scripts/sane recon` — passive subdomain sources for every in-scope wildcard. Names are scope-checked before
   they are stored. Nothing out of scope is resolved, probed or fetched.
3. CIDR scope: `scripts/sane sweep`, then `scripts/sane ports <ip>` for each alive in-scope address.
4. `scripts/sane fp --all` — fingerprint, tier, cluster.
5. For hosts tiered `app` or `api`, collect historical URLs from third-party archives into
   `$E/recon/<host>/urls-history.txt` (`gau` or `waybackurls` when installed; these do not touch the target).
6. `scripts/sane asset list`.

Follow the decision points and call-off rules in `playbooks/PB-02-recon.md` and `playbooks/PB-03-fingerprint.md`.

## Limits

- You discover and fingerprint. You do not test for vulnerabilities, run content discovery, or log in.
- Every command that touches a target starts with `source "$E/env.sh"`.
- A name that is not in scope is recorded in `recon/seen-not-in-scope.txt` by the tool and left alone.
- If requests start failing with 429 or blocks, stop and report it (playbook PB-14).
- Never commit or push.

## Return

A table of deployments (representative host, tier, title, technology with versions, number of aliases), the hosts
with `cname-3p` or `dangling` set, the products with versions that deserve a CVE pass, anything that looked odd,
and what you did not finish.


---

## Reference: PB-02 · Recon: find the assets

_Included from `playbooks/PB-02-recon.md`. That file is the source of truth._

| | |
|---|---|
| **Trigger** | Scope locked; wildcards or ranges in it |
| **Entry state** | `scope.json` has `in` rules; `assets.json` holds only seeds |
| **Runs as** | `recon-scout` agent in the background, or the main session |
| **Timebox** | 60 minutes for the first pass; later passes run in the background |
| **Output on disk** | `assets.json`; `recon/seen-not-in-scope.txt`; `recon/<host>/` per asset |
| **Next** | PB-03 |

Recon here has one purpose: put testable assets in front of the fingerprinter. It is not a collection hobby.
Everyone runs the same subdomain tools on a public wildcard; the edge is in what you do with the list, which is
PB-03 and PB-04.

### Steps

1. **Passive subdomains for every in-scope wildcard.** `scripts/sane recon`
   Sources: certificate transparency (crt.sh), `subfinder` when installed, HexBrain's `get_attack_surface` when
   the key is set. Every name is scope-checked before it is stored; names that are not in scope go to
   `recon/seen-not-in-scope.txt` and are never touched.
2. **Your own lists.** Anything else you gather (other tools, a wordlist run) goes through the same gate:
   `scripts/sane recon --file hosts.txt`.
3. **Ranges.** For CIDR scope: `scripts/sane sweep` (host discovery at the programme rate), then
   `scripts/sane ports <ip>` per alive address. For named hosts that matter, `scripts/sane ports <host>` finds
   web services on other ports.
4. **Historical URLs for hosts that look alive** (after PB-03 has tiered them, for `app` and `api` tiers only):
   ```bash
   source "$E/env.sh"; H=<host>; mkdir -p "$E/recon/$H"
   gau --subs=false "$H" 2>/dev/null | sort -u > "$E/recon/$H/urls-history.txt"   # or waybackurls
   ```
   These are third-party archives, not requests to the target.
5. **Record what stands out** in `notes.md`: names that reveal function (`admin`, `staging`, `internal`, `vpn`,
   `jenkins`, `api-v1`), naming patterns that predict siblings, hosts on unusual providers.

### Decision points

- A name resolves to a CNAME on a third-party service → the fingerprinter sets `cname-3p`; the takeover chapter
  picks it up in PB-05. Nothing to do here.
- Hundreds of names → do not fingerprint by hand-picked favourites. PB-03 tiers all of them cheaply and the
  planner collapses duplicates.
- A name outside the scope looks like the same organisation → it stays out. Note it for the operator; do not
  resolve, probe or fetch it.
- Active brute-force enumeration (permutations, DNS brute force) → only when the wildcard is in scope and the
  passive pass was thin; throttle the resolver and scope-filter the output.

### Call it off when

- The first pass has run all three sources. Further enumeration has steeply diminishing returns compared with
  mapping the applications you already have.
- Sixty minutes have passed. Move on; run the rest in the background.

### Done when

`scripts/sane asset list` shows the in-scope assets, and every in-scope wildcard has been enumerated at least once
(`logs/journal.jsonl` has a `recon` entry naming the root).

### Hand to the operator when

- The programme offers a host list or VPN access to those who ask.
- A paid data source (SecurityTrails, Shodan, Censys) would help and you need a key.

---

## Reference: PB-03 · Fingerprint, tier and cluster

_Included from `playbooks/PB-03-fingerprint.md`. That file is the source of truth._

| | |
|---|---|
| **Trigger** | In-scope assets without a fingerprint |
| **Entry state** | `assets.json` has hosts with no `fp` |
| **Runs as** | Main session (`scripts/sane fp --all` is one command) |
| **Timebox** | 30 minutes for up to a few hundred hosts |
| **Output on disk** | `facts/<host>.json`, `recon/<host>/tech.json`, `recon/<host>/js/`, tiers and clusters in `assets.json` |
| **Next** | PB-07 for any product with a version; PB-04 for `app` and `api` tiers |

This is where "run every test on every asset" stops. About twenty requests per host decide what kind of thing it
is, what it runs, and which other hosts are the same deployment.

### Steps

1. **Fingerprint.** `scripts/sane fp --all`
   Per host it prints the tier, the facts it could establish, and the products with versions. The budget is fixed
   and small: `/`, a random path, `robots.txt`, OIDC discovery, six GraphQL paths, eight API-documentation paths,
   `/wp-login.php`, one CORS probe, one reflection marker, one WAF canary, and up to ten script bundles.
2. **Read the tiers.** `scripts/sane asset list`

   | Tier | Meaning | What the planner does with it |
   |---|---|---|
   | `dead` | no DNS answer or no HTTP answer | only DNS-level items (takeover) and, for IPs, the network chapter |
   | `redirect` | every path redirects to another host | clustered with the destination when that is an asset |
   | `default` | default page, bare 403/404, parked | content discovery and virtual-host items only |
   | `static` | no cookies, forms, SPA shell or API | disclosure, takeover, cache, client-side source review |
   | `app` | dynamic application | everything its facts allow |
   | `api` | JSON at the root, no UI | API, access-control, injection chapters as facts allow |

3. **Read the clusters.** Hosts with the same response structure, title and status are one deployment; the
   `same as` column names the representative. Deployment-level items run once, on the representative.
   If two hosts were merged that you know are different applications (a shared login page in front of different
   back ends), split them: set a distinguishing fact on one (`scripts/sane fact set <host> ...`) and note it; the
   planner evaluates `host`-unit items on each anyway.
4. **Correct what the fingerprinter got wrong.** It only sees the unauthenticated front door. A host tiered
   `static` that you know has a login behind a JavaScript router is an `app`:
   `scripts/sane fact set <host> app=1 static=0 login=1 --ev "SPA router renders /login; XHR to /api/session"`.
5. **Versions.** For every row with a product and no version, spend two minutes finding it (CVE-001 in
   `checklist/cve.md` lists where versions leak) and write it into `recon/<host>/tech.json`.

### Decision points

- Any product with a version → run PB-07 for it now. It is cheap, and a known critical on an edge appliance is
  the fastest valid report there is.
- `dangling` or `cname-3p` is true on a host → the takeover items will be at the top of the queue; they are quick.
- A host answers only with a WAF challenge → note it; PB-04 uses the browser for that deployment.
- Nothing but `default` and `dead` tiers → the interesting surface is behind virtual hosts, other ports or paths:
  the recon chapter's items (RCN) will be queued for those hosts; consider PB-08 early.

### Call it off when

- A host times out twice. It is tiered `dead`; recon will resurface it if it comes back.

### Done when

`scripts/sane status` shows every in-scope asset fingerprinted, and you have read the tier of each deployment
representative.

### Hand to the operator when

- The target blocks your IP during fingerprinting (PB-14).