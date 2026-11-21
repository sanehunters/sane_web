---
name: map
description: Map one application — create test accounts, walk every feature authenticated, mine the JavaScript, write the feature inventory and trust model, and settle the applicability facts. Use when sane probes lists unknown facts, before hunting on any app or API deployment.
---

<!-- GENERATED from src/skills/map.md by scripts/build_claude.py. Edit that file or the included playbook, then rebuild. -->

# /map — playbook PB-04

`$ARGUMENTS` is the host (the deployment representative). Procedure: `scripts/sane playbook PB-04`.

1. `scripts/sane probes <host>` — the unknown facts, ranked by what they unlock.
2. Accounts A and B (different tenants), plus a low-privilege member where roles exist, per the programme's
   account rules. Headers into `accounts/*.headers`; then
   `scripts/sane fact set @eng account=1 two-accounts=1 priv-accounts=1 --ev "..."`.
3. Walk every feature once with request logging on. One line per feature in `recon/<host>/map.md`; one saved
   request per feature in `recon/<host>/requests/`.
4. Mine `recon/<host>/js/` for routes, parameters, roles and flags the UI never showed.
5. Settle every fact from step 1 with evidence: `scripts/sane fact set <host> tag=1|0 ... --ev "..."`.
   Zero only when you looked where it would be.
6. Ask the library about the richest features: HexBrain `plan_tests`, or `scripts/sane kb search <words>`.
7. Write the five-line trust model at the top of `map.md`.

Delegate to `surface-mapper` when several deployments need mapping; one agent per deployment.

While mapping, do not chase oddities: one line in `notes.md`, route it with PB-13, keep walking.


---

## Reference: PB-04 · Map the application and settle the facts

_Included from `playbooks/PB-04-map.md`. That file is the source of truth._

| | |
|---|---|
| **Trigger** | `scripts/sane probes` lists unknown facts for an `app` or `api` deployment |
| **Entry state** | The deployment is fingerprinted; most feature facts are `?` |
| **Runs as** | `surface-mapper` agent per deployment, or the main session |
| **Timebox** | 90 minutes per deployment; 30 for a small one |
| **Output on disk** | `recon/<host>/map.md` (the feature inventory), `recon/<host>/requests/` (one saved request per feature), facts set with evidence, accounts in `accounts/` |
| **Next** | PB-05 |

This is the hour that separates a hunter from a scanner. You use the product as its users do, with accounts, and
write down what it does. Every later test is aimed with what you learn here. The facts you record decide which
cards the planner opens.

### Steps

1. **See what is unknown and what it is worth.** `scripts/sane probes <host>`
   The list is ordered by the value of the tests each fact unlocks. One walk of the application settles most of it.
2. **Accounts.** Follow the programme's account rules from PB-00. Register attacker **A** and victim **B** with
   different e-mail aliases, in different organisations or tenants where the product has them. Where roles
   exist, add a low-privilege member to A's tenant (**ADM** is A's admin; the member is the low role). Save each
   session's request headers, one per line, in `accounts/A.headers`, `accounts/B.headers`, `accounts/ADM.headers`
   and describe the accounts in `engagement.json` `accounts[]` (label, role, tenant, user id; never passwords).
   `scripts/sane fact set @eng account=1 two-accounts=1 priv-accounts=1 --ev "A and B registered in separate orgs; member M in A's org"`
3. **Walk every feature, authenticated, with the request log on.** Use the scriptable browser with network
   capture, or a logging proxy (`mitmdump -w`), so every request is saved. Click everything once: settings,
   profile, team and roles, billing, integrations and webhooks, import and export, file upload, search, sharing
   and invitations, notifications, API keys, the help widget, account deletion (read, do not confirm).
   For each feature write one line in `recon/<host>/map.md`:
   `feature | endpoint and method | parameters and identifiers | who may use it | state it changes | odd behaviour`
   and save one representative request to `recon/<host>/requests/<feature>.http`.
4. **Mine the client.** The bundles saved by the fingerprinter hold routes the UI never showed you:
   ```bash
   grep -rhoE '["'"'"'`]/(api|v[0-9]+|graphql|internal|admin)[A-Za-z0-9_./{}:-]*' "$E/recon/$H/js/" | sort -u > "$E/recon/$H/routes-from-js.txt"
   grep -rhoE '(isAdmin|role|permission|feature[A-Z_a-z]*|flag[A-Z_a-z]*|internal|debug|beta)[A-Za-z_]*' "$E/recon/$H/js/" | sort | uniq -c | sort -rn | head -50
   ```
   Add routes that exist but have no UI to the map, marked `hidden`.
5. **Settle the facts.** For each row of `sane probes`, record what you saw:
   ```bash
   scripts/sane fact set "$H" signup=1 password-reset=1 mfa=1 cookie-auth=1 roles=1 multi-tenant=1 object-ids=1 \
     invite=1 api-keys=1 state-change=1 --ev "walked authenticated $(date -u +%F): see recon/$H/map.md"
   scripts/sane fact set "$H" upload=1 file-processing=1 --ev "avatar upload is resized server-side (stored bytes differ)"
   scripts/sane fact set "$H" url-fetch=0 render=0 template-input=0 xml-input=0 saml=0 payments=0 ai-feature=0 \
     --ev "no URL-valued parameter, no PDF/export, no template editor, no XML endpoint in the request log; no billing; no assistant"
   ```
   A fact is set to `0` only on evidence: you looked where it would be and it was not there. "Did not see it" after
   a partial walk stays `?`.
6. **Ask the library what this feature set has paid for.** With the HexBrain connector, `plan_tests` for the two
   or three richest features ("export report to PDF", "webhook URL setting", "team invitations"); offline,
   `scripts/sane kb search <feature words>`. Note anything specific in `notes.md`.
7. **Write the trust model** at the top of `map.md` in five lines: the actors (anonymous, user, member, admin,
   other tenant, staff), the objects they own, the identifiers that name those objects, where authorisation is
   decided (gateway, per endpoint, per field), and the one or two places it looks improvised. PB-08 starts here.

### Decision points

- Sign-up is closed and the programme gives no credentials → `account=0`; record the blocker
  (`engagement.json` `blockers[]`) and continue with the unauthenticated surface. Tell the operator: a second
  account roughly doubles what can be tested.
- A feature is behind a paid plan → note it as a blocker; many programmes will grant an upgrade on request.
- The app is a known product (GitLab, Jira, a CMS) → the feature set is public knowledge; shorten the walk and go
  to PB-07 and to the product's own history in the library.
- You notice something odd while mapping (a 500, an id that changes type, a response with too many fields) →
  one line in `notes.md` and keep walking. Chasing it now costs you the map. PB-13 says where each signal leads.

### Call it off when

- The request log has stopped showing new endpoints for fifteen minutes.
- Ninety minutes have passed. Record the unvisited areas in `map.md` and move on; you can return.

### Done when

`scripts/sane probes <host>` shows no asset fact worth more than a few points, `map.md` has the feature table and
the five-line trust model, and the accounts are recorded.

### Hand to the operator when

- Registration needs a phone number, a payment card, a corporate e-mail domain or a CAPTCHA you cannot pass.
- A second or privileged account is needed and only they can obtain it.