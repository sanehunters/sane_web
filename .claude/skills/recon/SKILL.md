---
name: recon
description: Discover and fingerprint in-scope assets — passive subdomain enumeration, CIDR sweeps, port scans, then tiering, technology detection and clustering. Use after the scope is locked, when new assets appear, or when the user asks for recon, subdomains, or a fingerprint.
---

# /recon — playbooks PB-02 and PB-03

1. `scripts/sane recon` — passive sources for every in-scope wildcard; every name is scope-checked before it is
   stored. Extra lists: `scripts/sane recon --file hosts.txt`.
2. CIDR scope: `scripts/sane sweep`, then `scripts/sane ports <ip>` for each alive address.
3. `scripts/sane fp --all` — about twenty requests per host: tier, facts, product versions, clusters.
4. `scripts/sane asset list` — read tiers and clusters; correct what the unauthenticated view got wrong with
   `scripts/sane fact set <host> ... --ev "..."`.
5. Any product with a version → `/cve-hunt` now.

Read `scripts/sane playbook PB-02` and `PB-03` for decision points and call-off rules. For large scopes, delegate
to the `recon-scout` agent in the background and continue with PB-04 on what is already fingerprinted.

Recon produces assets and facts, not findings. Stop enumerating after the first pass and go and understand an
application.
