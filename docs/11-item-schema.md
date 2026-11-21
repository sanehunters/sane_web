# 11 — The chapter and item schema

The chapters under `checklist/` are the single source of truth for what gets tested. `scripts/sane lint` parses
them with the same code the planner uses, so a chapter that lints is a chapter the planner can gate. Write for a
model that will read one card, on one asset, with no other context.

## 1. Why the schema is strict

The planner decides, for every asset × item pair, whether the item is worth a single request. It can only do that
if each item states in machine-readable form what must be true of the asset. An item without a `Requires` row is
run on everything, which is the failure this repository exists to prevent.

## 2. Chapter shape

```markdown
# <PREFIX> · <Class name>

> Two or three sentences: what the bug is in this class and what it is worth, honestly.

| | |
|---|---|
| **Class** | `<slug from kb/classes.json>` |
| **Applies when** | <fact expression: the gate for the whole chapter> |
| **Pays** | <one line from kb/reports/<slug>.md: report count, median paid bounty, what the top reports had in common> |
| **Weaknesses** | <HackerOne weakness names to file under> · <CWE ids> |

## Why it pays
## The crux question
## Applicability probe
## Triage order
## Items
## Graveyard
## Chains
## Sources
```

- **Applicability probe** names the two to five observations that settle the chapter gate for one asset, the
  `sane fact set` line to record each outcome, and the note to write when the chapter does not apply.
- **Triage order** lists item ids in the order a hunter would try them on a fresh asset: cheapest signal first,
  highest ceiling next.
- **Graveyard** lists what this class produces that programmes close as informative, N/A or duplicate, and why.
  Each line names the exclusion tag from `checklist/_facts.json` when one exists.
- **Chains** names what a primitive from this chapter combines with, by item id.

## 3. Item shape

```markdown
### <PREFIX>-NNN · <the test as a claim about the target, not a topic>

| | |
|---|---|
| **Severity** | <standalone level>; <chained level and with what> |
| **Requires** | <fact expression> |
| **Excluded by** | <exclusion tags, comma-separated, or —> |
| **Unit** | deployment \| host \| programme |
| **Cost** | low \| medium \| high |
| **Weakness** | <HackerOne weakness name> · CWE-<n> |
| **Prior art** | #<report id>, #<report id> |

- **Where:** <which features, endpoints or parameters to aim at, and how to find them on this asset>
- **Test:** <what to check, mechanism first, in one or two sentences>
- **How:** <the exact requests or commands, copy-pasteable; placeholders from §6>
- **Proof:** <the observable that makes this reportable: bytes returned, a state change seen from the victim account, a callback>
- **Not a finding when:** <the result that looks like a hit and is not, and the mechanism that explains it>
- **Escalate:** <what to try next once the primitive holds; chain partners by item id>
```

Required: all seven metadata rows and all six body fields. Ids are `PREFIX-NNN`, numbered `001…` contiguously
within the chapter, never reused. The heading separator is `·`.

### Severity

`critical | high | medium | low | none`, written as `<Level> standalone; <Level> with <partner>` when the chained
level differs. `none` standalone means the item is a primitive: it is recorded and parked, and reported only as
part of a chain. Rate on what the **Proof** shows, not on what the class can reach in theory.

### Requires — the applicability expression

Tags come from `checklist/_facts.json` and nowhere else. Grammar:

| Form | Meaning |
|---|---|
| `a, b` | a AND b |
| `a\|b` | a OR b (binds tighter than the comma: `a, b\|c` is a AND (b OR c)) |
| `!a` | NOT a |
| `—` or empty | always applicable (rare; justify it in **Where**) |

The chapter's **Applies when** is ANDed with each item's **Requires**. Do not repeat the chapter gate in the item.
Evaluation is three-valued: a fact is true, false or unknown.

| Result | Planner status | What happens |
|---|---|---|
| true | `todo` | the item enters the queue for that asset |
| false, on an asset or programme fact | `n/a` | closed with a generated reason naming the fact and its evidence |
| false, on a capability fact only | `blocked` | closed until the operator supplies the capability; listed in `sane blockers` |
| unknown | `probe` | the unknown facts are queued as probes; one probe usually settles many items |

Choose tags so that a false fact really does rule the item out. `Requires: upload` on a stored-XSS-via-SVG item
is right. `Requires: php` on a generic LFI item is wrong: use it only when the technique is PHP-specific
(wrappers, `phar://`). Prefer a narrow item with a precise gate to a broad item with a loose one. When a technique
only matters behind a capability (`two-accounts`, `oob`, `browser`), name the capability: the planner reports it
as a blocker instead of pretending the item was tested.

### Excluded by

Exclusion tags from the `exclusions` map in `checklist/_facts.json`. When the programme's policy lists the tag
(`engagement.json` `exclusions[]`), the item is closed as `excluded`. Use `—` when no common exclusion applies.

### Unit — how often the item runs

| Unit | Runs | Use for |
|---|---|---|
| `deployment` | once per cluster of hosts that serve the same application | almost everything: an IDOR on `app.` is the same IDOR on its alias |
| `host` | on every host name | DNS and routing facts: takeover, virtual-host routing, per-host cache keys, TLS SNI tricks |
| `programme` | once per engagement | organisation-wide work: code-host secret search, bucket naming, dependency confusion |

### Cost

`low` = under about 20 requests, no account needed beyond what `Requires` names. `medium` = up to a few hundred
requests or a multi-step flow. `high` = fuzzing, thousands of requests, long waits, or heavy manual analysis. The
planner divides expected value by cost.

### Prior art

Report ids in the form `#123456`, taken only from `kb/reports/<class>.md` or `kb/data/index.jsonl`. The linter
rejects an id that is not in the index. Pick the two to four reports that best show the technique paying; prefer
ones with a bounty. Never cite an id, bounty or programme from memory.

## 4. Writing rules

1. **One mechanism per item.** "Test for XSS" is a chapter. "A file name is rendered unescaped in the attachment
   list" is an item.
2. **The title is a claim that can be false.** It should read as the first line of a report if the test succeeds.
3. **How is executable.** Real requests with headers and bodies, real tool invocations with flags, the rate-limit
   flag included. No "use Burp to…": there is no Burp here, there is `curl`, a scriptable browser and CLI tools.
4. **Proof is what a triager needs to see.** A reflected string is not proof of XSS; script running in the
   target's origin is. A 200 is not proof of IDOR; victim B's data in attacker A's response is.
5. **Not a finding when** carries the hunter's scar tissue: the false positives and the "works as designed"
   answers. This field saves more time than any other.
6. **Stay inside the rules.** No payload that damages data, no test that needs another user's real account, no
   volume that amounts to denial of service. Destructive verbs (`DELETE`, password change, e-mail change) are
   proven on our own second account.
7. **Plain, exact English.** No filler, no sales language. Write what to send and what to look for.

## 5. Statuses a hunter writes

`sane mark <asset> <item> <status> --note "<mechanism>" [--ev <path>]`

| Status | Meaning | Note must contain |
|---|---|---|
| `negative` | tested; the control holds | the mechanism that stops it (which check, where, observed how) |
| `candidate` | a signal that needs verification | what was observed and what would prove it |
| `finding` | verified, reproducible, in scope, with impact | the finding id `F-NNN` |
| `parked` | a real primitive without standalone impact | what it would chain with |
| `dup-risk` | real, but prior art or scanners make a duplicate likely | the reason |
| `skipped` | deliberately not run | why (budget, risk, operator decision) |

`n/a`, `blocked`, `excluded` and `probe` are written by the planner, not by hand. To overrule the planner, change
the fact (`sane fact set`), not the status.

## 6. Placeholders in **How**

| Placeholder | Meaning |
|---|---|
| `$T` | the asset's base URL, for example `https://app.example.com` |
| `$H` | the host name |
| `$E` | the engagement folder |
| `"${HDR[@]}"` | the programme's required headers and User-Agent as curl arguments (from `$E/env.sh`) |
| `$A`, `$B` | curl arguments carrying attacker A's and victim B's session (from `$E/env.sh`) |
| `$OOB` | the out-of-band callback host |
| `$RATE` | the engagement's requests-per-second ceiling |

Evidence goes under `$E/findings/` or `$E/evidence/<asset>/<item>/`; raw requests and responses are saved with
`curl -sS -D- -o` or `--trace-ascii`, never retyped.
