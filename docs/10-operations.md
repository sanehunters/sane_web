# 10 — Operations: how the work is divided

One session cannot hold a whole programme in its head, and should not try. This file says how an engagement is
cut into pieces that separate agents can do well, what each piece is given and must hand back, and which pieces
never leave the coordinator. The aim is simple: more of the surface understood, more applicable tests actually
run, every candidate checked by someone who did not find it.

## 1. The units of work

| Unit | Is | Sized so that | Owner |
|---|---|---|---|
| Engagement | one programme | — | the coordinator (main session) |
| Deployment | one application, however many host names serve it | one agent can hold its map in context | one mapper, then one or more lane hunters |
| Lane | a set of chapters that share accounts, tools and a way of thinking | an agent stays in one mode of thought | one hunter per deployment and lane |
| Card | one falsifiable claim | it fits a timebox of 20, 45 or 120 minutes | the hunter |
| Product | one identified piece of software on one host | 60 minutes | one CVE specialist |
| Lens | one way of looking for a broken invariant | an agent applies it to every feature | one researcher |
| Hypothesis | one suspected broken invariant | 45 minutes to a decisive experiment | the researcher, then the coordinator |
| Finding | one root cause | three people can each try to kill it | three verifiers, then the report writer |

Work is divided along these lines and no others. Two agents on the same deployment and lane duplicate each other;
one agent across several deployments skims all of them.

## 2. Roles

| Role | Agent | Does | Never does |
|---|---|---|---|
| Coordinator | the main session | PB-00, PB-01, PB-05; writes briefs; reads returns; decides what is verified, chained, reported; talks to the operator | hand off a decision about scope, about whether something is a finding, or about what the operator is told |
| Scout | `recon-scout` | PB-02, PB-03 in the background | test for vulnerabilities |
| Mapper | `surface-mapper` | PB-04 on one deployment | attack |
| Hunter | `class-hunter` | PB-06 on one deployment, one lane | verify its own candidate; write reports |
| CVE specialist | `cve-exploiter` | PB-07 on one product | go beyond the minimal proof |
| Researcher | `researcher` | PB-08, one lens on one deployment | call a confirmed hypothesis a finding |
| Verifiers | `verify-reproduce`, `verify-guard`, `verify-triager` | PB-09, one lens each | see each other's work or the hunter's reasoning |
| Writer | `report-writer` | PB-11 draft | submit |

## 3. Lanes

`checklist/_lanes.json` is the definition; `scripts/sane lanes` shows the queue by lane.

| Lane | Chapters | Sessions it uses | Way of thinking |
|---|---|---|---|
| `known` | cve | none | pin the version, verify the advisory's check, prove minimally |
| `infra` | takeover, disclosure, cache, smuggling, host-header, cloud, network, recon | none, or A read-only | what is exposed; where the layers in front disagree with the application |
| `authz` | access-control, authn, oauth, jwt, api, graphql, websocket | A and B in different tenants; a low role and an admin in A's tenant | who may do what to which object, and where that is decided |
| `injection` | sqli, nosqli, ssti, rce, traversal, xxe, deser, ssrf, upload, crlf, llm | A | which input reaches an interpreter, parser, file system or outbound request |
| `client` | xss, csrf, cors, redirect, clickjacking, client-side, proto-pollution | A as attacker, B as victim in the browser | what runs in the victim's browser on the target's origin |
| `logic` | logic, race | A, sometimes B | what the business assumes happens once, in order, at the server's price |

### Running lanes side by side on one deployment

1. `known` and `infra` need no shared session. They run beside anything, including the mapper.
2. The four authenticated lanes change the state of the accounts they use: one logs out, one changes the e-mail,
   one spends the coupon. Two of them on the same accounts corrupt each other's tests and produce false results
   in both directions. So: **one authenticated lane per account pair at a time.** With a single pair A/B they run
   one after another in the order `authz`, `injection`, `client`, `logic`. With two pairs, two run at once.
   Registering a second and third pair (A2/B2, A3/B3) during PB-04 is the cheapest way to multiply throughput.
3. The programme rate is a ceiling for everything sent to one deployment. With K agents on it, each gets rate/K.
   `scripts/sane brief ... --share K` writes that share into the brief.
4. Across different deployments everything runs in parallel, within the programme rate if the programme states
   it per organisation rather than per host (PB-00 records which).

`scripts/sane squad` computes all of this: who runs now, on what, at what rate share, and what waits for what.

## 4. Waves

A fresh programme, divided. Each wave is one fan-out; the coordinator reads the returns before the next.

| Wave | Runs | In parallel | Coordinator does meanwhile | Ends when |
|---|---|---|---|---|
| 0 Set-up | PB-00, PB-01 | — | everything; nothing is delegated before authorisation and scope exist | `sane status` shows authorised and a scope |
| 1 Surface | `recon-scout` | one agent | reads the programme's paid history (`sane kb program`), prepares accounts | every asset is fingerprinted and tiered |
| 2 First contact | `cve-sweep` workflow; `infra` lane per deployment; `surface-mapper` on the two to four richest deployments | all of these at once | registers account pairs; reads the first maps | maps exist; `known` and `infra` queues are drained |
| 3 Depth | `squad-hunt` workflow: authenticated lanes, one per account pair per deployment | deployments in parallel; lanes per the rules above | verifies candidates as they arrive (the workflow runs the three lenses); chains; starts reports | lane queues are drained |
| 4 Research | `research-lenses` workflow on the richest deployment | twelve lenses | tests the top-ranked hypotheses itself | the ledger is closed |
| 5 Ship | `report-writer` per verified finding | one per finding | final read, the gate, hand-over to the operator | the operator has every READY report |
| ∞ Upkeep | `recon-scout` again; PB-12 as reports change state | — | re-plans when facts change | the engagement ends |

Waves 2 to 4 repeat as recon finds new assets and as verified findings suggest where else to look. A report is
written and handed over as soon as its finding is verified; nothing waits for the end of a wave.

## 5. Delegating: the brief

An agent knows only what its brief says. A thin brief gets generic work. `scripts/sane brief <agent> <asset> ...`
writes a complete one from the engagement's state; use it for every delegation, and add your own notes below it.

| Section of the brief | Why it must be there |
|---|---|
| Authorisation | the basis, the HackerOne user, the programme. No basis recorded, no brief is printed |
| Asset | the one host the agent may touch, its tier, aliases it must not test separately, technology, established facts |
| Rules | its rate share, the required headers, how to load the environment, exclusions, policy notes, the stop conditions |
| Accounts | which exist, their roles and tenants, where the session headers are and whether they are present |
| Task | what to do, in the agent's own procedure, and the playbook to read |
| Queue / facts / product / lens / finding | the specific work: the cards in order with timeboxes, or the facts to settle, or the product, the lens, the finding |
| Material | paths to the map, saved requests, bundles, technology file, notebook |
| Return | exactly what to hand back |

What to add by hand: anything you learned that is not on disk yet (a hunch about a feature, an account quirk, a
thing the last agent tripped on).

Never put in a brief: your conclusion about what the agent will find. A verifier told that the bug is real
confirms it. Give the claim, not the confidence.

## 6. Reading what comes back

An agent's return is a report of what it believes it did. Check it against the disk before acting on it.

| Agent says | Check |
|---|---|
| "ran N cards" | `scripts/sane coverage`; the rows exist with notes; negatives name a mechanism, not "not vulnerable" |
| "set these facts" | `scripts/sane fact show <host>`; the evidence is an observation, not an assumption |
| "candidate found" | the request and response are in `evidence/`; replay the request once yourself before spending three verifiers on it |
| "verdict: holds" | the note says what was run; captures exist under the lens's folder |
| "map written" | `map.md` has the feature table and the five-line trust model; `requests/` has files |
| "nothing found" | how many cards, which closed how; a lane closed in ten minutes was not hunted |

A return that cannot be checked is treated as not done. Re-run the lane with the gap named in the brief.

## 7. Saved workflows

Each takes as `args` the JSON printed by the matching `scripts/sane squad` command, so the briefs are always built
from current state. They run in the background; the coordinator keeps working.

| Workflow | Args from | Does | Returns |
|---|---|---|---|
| `squad-hunt` | `scripts/sane squad --json` | mappers and lane hunters side by side; three lenses on every candidate | per lane: cards run, candidate, verdicts, survives |
| `cve-sweep` | `scripts/sane squad --mode cve --json` | one CVE specialist per deployment with products; three lenses on every hit | per deployment: products, CVEs and status, verified candidates |
| `research-lenses` | `scripts/sane squad --mode research <host> --json` | one researcher per lens; then merge and rank the ledger | ranked hypotheses, confirmed ids, gaps |
| `verify-finding` | `scripts/sane squad --mode verify --finding F-NNN --json` | the three lenses on one finding | verdicts and the `verify.json` to write |

The `/squad` skill chooses and runs the right one. Without workflows, do the same thing with the Agent tool: one
call per row of `scripts/sane squad`, all in one message so they run together, each given `scripts/sane brief`'s
output.

## 8. What actually produces findings

The division exists to protect these, in this order of return on effort.

1. **Accounts.** Two accounts in different tenants turn the access-control chapter from blocked to open; a second
   pair doubles how fast the authenticated lanes run. `scripts/sane blockers` shows what a missing account costs.
2. **The map.** A hunter with `map.md` aims cards at the endpoints where they are likely true. A hunter without
   it fires at the front page. Spend the mapper's ninety minutes on every deployment worth hunting.
3. **The authz lane first.** Access control, authentication and API authorisation together are the largest group
   of paid reports in the library and need no tooling, only two sessions and care.
4. **The quick wins early, in parallel.** `known` and `infra` cost little, need nothing, and occasionally return
   the best finding of the engagement. They also show whether the programme's obvious surface is already picked
   clean, which tells you how deep to go.
5. **Verification that is fast and independent.** Every hour between a signal and a verified finding is an hour
   in which someone else can report it. The three lenses run in parallel, at once, on every candidate.
6. **Research on the richest deployment.** When the cards thin out, twelve lenses over a well-mapped application
   find what no checklist lists. This is where findings on mature programmes come from.
7. **Reports that need no second message.** A report triaged on first read is paid weeks sooner and earns the
   reporter faster triage next time.
8. **Coming back.** New assets, new features and new fixes are new surface. `recon-scout` on a schedule and
   PB-12's retest step find bugs that did not exist last month.

## 9. Models, effort and cost

- The coordinator and the verification lenses benefit most from the strongest model and high effort: a wrong
  call there costs a finding or sends a false one.
- Mapping, hunting and research need a capable model; recon and fingerprinting are mostly tool runs.
- Agents inherit the session model. Change one only when you are sure a cheaper tier fits its job.
- A wave of ten agents spends usage quickly. Start with the deployments and lanes `scripts/sane squad` ranks
  first; a wave that finishes is worth more than a larger one cut off halfway. Every agent writes its results to
  disk as it goes, so a cut-off wave loses time, not work.
