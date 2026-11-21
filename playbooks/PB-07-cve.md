# PB-07 · CVE: from version to verified exploit

| | |
|---|---|
| **Trigger** | The fingerprint names a product, framework, CMS, plugin or appliance, ideally with a version |
| **Entry state** | `recon/<host>/tech.json` has at least one entry |
| **Runs as** | `cve-exploiter` agent per product, or the main session |
| **Timebox** | 60 minutes per product: 10 to pin the version, 10 to look up and rank, 40 to verify and prove the best two |
| **Output on disk** | `recon/<host>/cves.json`; `evidence/<host>/CVE-<id>/`; a `candidate` on the matching CVE chapter item |
| **Next** | PB-09 for anything that verified |

Known vulnerabilities on in-scope assets are valid findings when you prove them. A version number is not proof.
Programmes close "outdated software" reports as informative every day; they pay for the request that shows the
vulnerable behaviour on their host. This playbook is the path from the first to the second.

## Steps

1. **Pin the version.** The fingerprinter reads headers, generator tags and titles. Do better where it failed
   (item CVE-001 lists the places): `/version`, `/api/health`, `/status`, login-page build strings, static file
   hashes compared with release tags, `readme.txt` / `CHANGELOG` of plugins, favicon hash, error pages, the
   `X-*-Version` family. Record each in `recon/<host>/tech.json`:
   `[{"name":"grafana","version":"9.1.0","source":"/api/health"}]`
   Record the evidence too: `scripts/sane fact set <host> known-product=1 --ev "Grafana 9.1.0 from /api/health"`.
2. **Look up and rank.** `scripts/sane cve <host>` (or `--tech "grafana 9.1.0"`).
   Sources: NVD by CPE, CISA KEV, EPSS, HexBrain's CVE checks, local nuclei templates. The rank favours:
   exploited in the wild, reachable without authentication, high EPSS, a public check or exploit, high impact.
3. **Filter by the programme.** Read the policy's patch-window rule (many exclude CVEs published in the last 30
   or 90 days, some all N-days without a working exploit): if it applies, the `known-cve` exclusion closes those.
   Drop CVEs that need a configuration the target visibly does not have.
4. **Read the advisory, not the headline.** `scripts/sane cve --id CVE-YYYY-NNNN`
   You need three things: the affected version range (does it include back-ports?), the precondition (module
   enabled, feature on, authentication), and the request that distinguishes vulnerable from patched.
5. **Verify with the advisory's own check.** In order of preference:
   - the detection request from the advisory, a vendor note or the nuclei template's `http:` block, sent by hand
     with `curl` so you see the whole response;
   - nuclei restricted to the matched ids, at the programme rate (the command is printed by `sane cve`):
     `nuclei -u "$T" -id cve-2021-41773,cve-2021-42013 -rl "$RATE" $HDRF`
   Never the whole template set. Save the request and response under `evidence/<host>/CVE-<id>/`.
6. **Exploit to the minimal proof, and stop.** A detection hit is a candidate. To be paid it must show impact on
   this host, and the proof must be harmless:

   | Impact type | Proof that is enough | Never |
   |---|---|---|
   | File read / traversal | `/etc/hostname`, or the first line of `/etc/passwd` | application secrets, user data, private keys |
   | Remote code execution | output of `id` or `hostname`, or a DNS callback carrying the hostname | a shell, a download, a write to disk, persistence |
   | Authentication bypass | the title or one field of a page that requires login, on your own tenant where one exists | browsing other users' data, changing settings |
   | SQL injection | DBMS version and current database user | dumping tables |
   | SSRF | the cloud instance identity document, or an internal service banner | using credentials |
   | Deserialization | a DNS callback from a no-side-effect gadget | any command with effects |
   | XSS | `alert(document.domain)` in your own browser session | touching another user |

   Use a public exploit only after reading every line of it: many are destructive, noisy or backdoored. Prefer to
   re-implement the one request that matters with `curl`.
7. **Record.** `scripts/sane mark <host> <CVE chapter item> candidate --note "CVE-YYYY-NNNN verified: <the observable>"`
   and go to PB-09. The report (PB-11) names the CVE in the title, cites the advisory, shows the version evidence
   and the exploit request and response, and says what an attacker could do next without having done it.
8. **Variants.** If the target is patched, spend ten minutes on what the patch may have missed: the sibling
   endpoint, another encoding of the same payload, the same bug in a plugin that copied the code (item CVE-015).
   A bypass of a fix is a new finding and is rated on its own.

## Decision points

- No version can be found → look up by product name only, take the three highest-ranked unauthenticated CVEs with
  a harmless detection request, and test those. A product without a version is still a product.
- The version is in range but the check says not vulnerable → back-ported fix or virtual patching. Mark the CVE
  item `negative` with that mechanism. Do not report.
- The check says vulnerable but exploitation fails → WAF or a missing precondition. Three attempts, then `parked`
  with the detection evidence; a detection-only report is usually informative.
- The product is an edge or VPN appliance (Citrix, Fortinet, Ivanti, F5, PAN-OS, Exchange) with a KEV-listed CVE
  → this is the highest-value outcome of the playbook; verify with extra care, prove minimally, tell the operator
  immediately.
- The host looks like a honeypot (every probe "succeeds", versions are inconsistent, the IP is not the
  organisation's) → stop and check ownership (PB-01).
- A library CVE on the client side (old jQuery, Bootstrap, Angular) → not a finding without a working exploit in
  this application. Close it unless you can build one.

## Call it off when

- Sixty minutes on one product without a verified check.
- The only remaining path is an exploit whose proof cannot be made harmless.
- The policy excludes the CVE by age, or excludes known CVEs altogether.

## Done when

Every product in `tech.json` has either a verified candidate, or a `negative`/`parked` note on the relevant CVE
item naming the CVEs tried and why they did not apply.

## Hand to the operator when

- A verified critical on internet-facing infrastructure: they will want to submit within the hour.
- The proof would require anything in the "Never" column.
