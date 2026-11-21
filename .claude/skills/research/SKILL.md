---
name: research
description: Hunt for novel, application-specific vulnerabilities by modelling the application's invariants and testing hypotheses through twelve research lenses. Use when the card queue is empty or thin, when the target is a rich application, or when the user asks for novel bugs, zero-days, logic flaws, or something scanners and checklists would not find.
---

<!-- GENERATED from src/skills/research.md by scripts/build_claude.py. Edit that file or the included playbook, then rebuild. -->

# /research — playbook PB-08

`$ARGUMENTS` is the deployment. Requires PB-04 done: `recon/<host>/map.md` with the feature table and trust model.
Procedure: `scripts/sane playbook PB-08`.

1. **Invariants.** Write fifteen to thirty rules the application must hold ("a viewer cannot cause any write",
   "a total equals the sum of its lines at server prices") into `recon/<host>/invariants.md`.
2. **Lenses.** Take them one at a time against the feature table: `second-path`, `state-machine`,
   `identity-binding`, `trust-boundary`, `parser-differential`, `time-and-concurrency`, `derived-data`,
   `forgotten-surface`, `variant`, `integration`, `client-trust`, `source`.
3. **Ledger.** Each plausible break:
   `scripts/sane hyp add --asset <host> --lens <lens> --text "<claim>" --why "<observation>" --test "<cheapest experiment>"`
4. **Variants from the library.** `scripts/sane kb program "<name>"`, read the best-paid write-ups in full
   (`scripts/sane kb show <id>`), and ask where the same root cause reappears. HexBrain `find_bypasses` with
   `protection: fix` shows how fixes were bypassed elsewhere.
5. **Read the code you have.** Bundles and source maps in `recon/<host>/js/`; open-source components at the
   version in use (the `source-code-review` skill applies).
6. **Test in rank order** (impact × plausibility ÷ cost), each with a control, 45 minutes to a decisive
   experiment.
7. **Close every hypothesis:** `scripts/sane hyp close H-NNN --result confirmed|refuted|parked --note "..."`.
   Confirmed → `scripts/sane finding new ...` → `/verify`.
8. A confirmed pattern that would apply elsewhere becomes a proposed checklist card in `notes.md`.

Give independent lenses to `researcher` agents (one lens, one deployment each); keep ranking and testing decisions
in the main session. Stop generating at thirty open hypotheses and test.


---

## Reference: PB-08 · Research: hunting for novel bugs

_Included from `playbooks/PB-08-research.md`. That file is the source of truth._

| | |
|---|---|
| **Trigger** | The card queue is empty or thin; or a deployment is rich enough that cards alone under-use it |
| **Entry state** | PB-04 is complete for the deployment: `map.md` has the feature table and the trust model |
| **Runs as** | Main session; `researcher` agents for independent lenses |
| **Timebox** | Blocks of three hours per deployment. Each hypothesis: 45 minutes to a decisive experiment |
| **Output on disk** | `hypotheses.jsonl` (every idea, including the dead ones); new facts; candidates |
| **Next** | PB-09 for a confirmed hypothesis; PB-06 when a hypothesis reveals new surface |

The checklist finds the bugs that have names. The bugs that pay best on mature programmes are the ones specific
to this application: an assumption its developers made that no checklist knows about. You find them by building a
model of how the application believes it works and then looking for where that belief is not enforced.

Cards ask "is this known mistake present?". Research asks "what does this system assume, and who checks it?".

### Steps

1. **State the invariants.** From the trust model in `map.md`, write the rules the application must hold for its
   business to work. Aim for fifteen to thirty. Examples of the form:
   - "A user reads only objects of an organisation they belong to."
   - "An invoice total equals the sum of its line items at the prices the server holds."
   - "An e-mail address belongs to at most one account, and only after its owner clicked a link."
   - "A download link works only for the person it was issued to, and only until it expires."
   - "A viewer cannot cause any write."
   - "Step 3 of checkout cannot happen without step 2."
2. **Turn each invariant into hypotheses with a lens.** Take the lenses below one at a time against the feature
   table. Each plausible break is one line in the ledger:
   `scripts/sane hyp add --asset <host> --lens <lens> --text "<the invariant that might be false, stated as a claim>" --why "<the observation that makes it plausible>" --test "<the cheapest experiment that would settle it>"`

   | Lens | The question it asks | Where it tends to pay |
   |---|---|---|
   | `second-path` | The same object or action is reachable by another route. Is the check on every route? | REST vs GraphQL, v1 vs v2, web vs mobile API, export, search, websocket, bulk endpoint, admin vs user UI |
   | `state-machine` | What if steps arrive out of order, twice, or after the object changed state? | checkout, sign-up and verification, approval flows, subscription changes, deleted or suspended objects |
   | `identity-binding` | Which identifier says who I am or whose object this is, and can I supply it? | e-mail in the body vs the session, org id in a header, user id in a JWT claim, "on behalf of" parameters |
   | `trust-boundary` | Where does data cross from one tenant, role or system to another, and who sanitises it? | shared links, invitations, imports, webhooks, support tooling, e-mail templates, analytics exports |
   | `parser-differential` | Two components read the same bytes. Do they agree? | proxy vs app on paths and headers, JSON duplicate keys, Unicode case-folding of e-mails, content-type sniffing |
   | `time-and-concurrency` | What is checked now and used later, or assumed to happen once? | redemptions, balance moves, token invalidation, role removal while a session lives |
   | `derived-data` | A value the server computes from my input and then trusts. | prices, permissions cached in tokens, file names turned into paths, counters, signatures over partial data |
   | `forgotten-surface` | What was built, left running and stopped being maintained? | old API versions, staging hosts, debug routes in the bundle, feature flags, endpoints with no UI |
   | `variant` | A bug paid once here or on a similar product. Is its sibling still alive? | the programme's own disclosed reports; the same framework's past bugs; the fix's neighbouring code |
   | `integration` | A third-party piece is glued on. Does the glue validate? | SSO, payment callbacks, storage pre-signed URLs, e-mail providers, chat widgets, AI assistants with tools |
   | `client-trust` | What does the server believe because the client said so? | hidden fields, prices and roles in requests, client-side feature gating, mass-assignable fields |
   | `source` | The code is partly available. What does it say? | JavaScript bundles and source maps, open-source components, public repositories of the organisation |

3. **Use the library for variants.** For this programme: `scripts/sane kb program "<name>"`, then read the two or
   three best-paid write-ups in full (`scripts/sane kb show <id>`). For each, ask where the same root cause would
   reappear after the fix. For the product type, HexBrain `get_testing_playbook` and `find_bypasses` with
   `protection: fix` show how fixes have been bypassed elsewhere.
4. **Read the code you have.** The bundles in `recon/<host>/js/` are the client half of every invariant. Pretty-
   print them, follow the authenticated API client, list every endpoint and every parameter the UI never sends,
   and read the permission checks the front end performs (each one is a check the back end might have skipped).
   If source maps are published, reconstruct the sources. If a component is open source, clone the version in use
   and audit the handlers behind the endpoints you mapped (the `source-code-review` skill applies).
5. **Rank the ledger and run it.** `scripts/sane hyp list`. Order by impact if true, times how plausible the
   `--why` is, over the cost of the `--test`. Run the cheapest decisive experiment for the top one. Always with a
   control request beside it.
6. **Close every hypothesis.** `scripts/sane hyp close H-NNN --result confirmed|refuted|parked --note "<the experiment and what it showed>"`
   A refuted hypothesis with a good note is an asset: it stops the next session repeating it. A confirmed one
   becomes a candidate: `scripts/sane finding new --title "..." --asset <host>` and PB-09.
7. **Feed the method back.** If the confirmed bug is a pattern that would apply to other targets, write it up as
   a proposed checklist item (title, `Requires`, how, proof) in `notes.md` under "new card". Novel findings are
   how the checklist grows.

### Decision points

- An experiment gives an unexpected result that is neither confirmation nor refutation → that is a new
  observation: write a new hypothesis for it; do not stretch the old one.
- The hypothesis needs a capability you lack (third account, paid plan, another role) → `parked`, with the
  blocker recorded.
- The idea only works with victim interaction → still valid; state the interaction exactly and check the policy's
  stance on it.
- You are generating hypotheses faster than you test them → stop generating at thirty and test.
- Nothing plausible after two full lenses → change deployment; return with fresh eyes or new accounts.

### Call it off when

- A hypothesis has had its 45 minutes without a decisive experiment: close it `parked` with what is missing.
- Three hours on one deployment without a confirmed hypothesis or a new piece of surface: switch deployment or
  lens. Sunk time is not a reason to continue.
- An experiment would need to break something to be decisive.

### Done when

Every hypothesis in the ledger is closed or explicitly open with a next experiment, and each confirmed one has a
finding folder.

### Hand to the operator when

- A hypothesis is high-impact and blocked only by something they can obtain.
- A confirmed novel bug affects a third-party product used by the target: disclosure may involve the vendor as
  well as the programme, and that decision is theirs.