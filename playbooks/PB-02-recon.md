# PB-02 · Recon: find the assets

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

## Steps

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

## Decision points

- A name resolves to a CNAME on a third-party service → the fingerprinter sets `cname-3p`; the takeover chapter
  picks it up in PB-05. Nothing to do here.
- Hundreds of names → do not fingerprint by hand-picked favourites. PB-03 tiers all of them cheaply and the
  planner collapses duplicates.
- A name outside the scope looks like the same organisation → it stays out. Note it for the operator; do not
  resolve, probe or fetch it.
- Active brute-force enumeration (permutations, DNS brute force) → only when the wildcard is in scope and the
  passive pass was thin; throttle the resolver and scope-filter the output.

## Call it off when

- The first pass has run all three sources. Further enumeration has steeply diminishing returns compared with
  mapping the applications you already have.
- Sixty minutes have passed. Move on; run the rest in the background.

## Done when

`scripts/sane asset list` shows the in-scope assets, and every in-scope wildcard has been enumerated at least once
(`logs/journal.jsonl` has a `recon` entry naming the root).

## Hand to the operator when

- The programme offers a host list or VPN access to those who ask.
- A paid data source (SecurityTrails, Shodan, Censys) would help and you need a key.
