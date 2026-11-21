# PB-01 · Scope: import and lock

| | |
|---|---|
| **Trigger** | Authorisation recorded, scope empty or changed |
| **Entry state** | `engagement.json` has a basis; `scope.json` has no `in` rules, or the programme updated its scope |
| **Runs as** | Main session |
| **Timebox** | 15 minutes |
| **Output on disk** | `scope.json` with `in`, `out` and `other`; seeded exact hosts in `assets.json` |
| **Next** | PB-02 |

You are not paid for anything outside the scope, and testing outside it can end the operator's access to the
platform. The scope file is what the guard hook enforces, so its errors become your errors.

## Steps

1. **Import.** `scripts/sane scope import-h1` (structured scope from the HackerOne API), or by hand from the
   policy's table:
   `scripts/sane scope add in '*.example.com'` · `scripts/sane scope add in api.example.com` ·
   `scripts/sane scope add in 203.0.113.0/24` · `scripts/sane scope add out blog.example.com --note "third-party hosted"`
2. **Read it back against the policy text.** `scripts/sane scope show`. Check each of these and fix by hand:
   - Out-of-scope lines written in prose in the policy ("anything under `*.corp.example.com`", "our Zendesk",
     "acquisitions") that the structured scope does not carry. Add them as `out` rules.
   - Whether a wildcard includes the apex. `*.example.com` does **not** match `example.com` here. Add the apex
     only if the policy lists it or says so.
   - Assets marked not eligible for bounty: still in scope for submission, but lower priority (`--no-bounty`).
   - Per-asset instructions (the `note` column): path restrictions, "only the /api/ path", environment caveats.
   - Assets of types this framework does not test (mobile apps, source code, hardware) are listed under `other`.
     Tell the operator they exist; `sane_android` covers Android apps.
3. **Prove the lock.** Pick three hosts you know should be in, out and unrelated:
   `scripts/sane scope check app.example.com blog.example.com example.org`
   Expect `in`, `out`, `unknown`.
4. **Seed exact hosts.** `scripts/sane asset seed`.

## Decision points

- The scope is only exact URLs → skip the subdomain part of PB-02; go to PB-03 after seeding.
- The scope contains CIDR ranges → PB-02 includes a sweep and port scan at the programme rate.
- A wildcard is very broad (`*.example.*`, "all assets owned by Example Inc") → ownership must be shown per asset
  before testing: WHOIS, certificate organisation, or a link from an asset that is unambiguously theirs. Record
  the evidence when adding the asset.

## Call it off when

- The scope cannot be established from a written source.

## Done when

`scripts/sane scope show` matches the policy line for line, including the prose exclusions, and step 3 gives the
expected three verdicts.

## Hand to the operator when

- The policy is ambiguous about an asset you would otherwise test. Ask before, not after. The programme's own
  answer (a comment from their team) is the only thing that widens a scope.
