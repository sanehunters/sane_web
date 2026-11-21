# PB-03 · Fingerprint, tier and cluster

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

## Steps

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

## Decision points

- Any product with a version → run PB-07 for it now. It is cheap, and a known critical on an edge appliance is
  the fastest valid report there is.
- `dangling` or `cname-3p` is true on a host → the takeover items will be at the top of the queue; they are quick.
- A host answers only with a WAF challenge → note it; PB-04 uses the browser for that deployment.
- Nothing but `default` and `dead` tiers → the interesting surface is behind virtual hosts, other ports or paths:
  the recon chapter's items (RCN) will be queued for those hosts; consider PB-08 early.

## Call it off when

- A host times out twice. It is tiered `dead`; recon will resurface it if it comes back.

## Done when

`scripts/sane status` shows every in-scope asset fingerprinted, and you have read the tier of each deployment
representative.

## Hand to the operator when

- The target blocks your IP during fingerprinting (PB-14).
