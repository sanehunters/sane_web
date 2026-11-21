---
name: engage
description: Start a new bug bounty engagement — record authorisation, read the programme policy, set rate limit, required headers and exclusions. Use when the user names a HackerOne programme or handle to begin hunting on, or when sane status says authorisation is not confirmed.
---

# /engage — playbook PB-00

Run `scripts/sane playbook PB-00` and follow it exactly. In short:

1. `scripts/sane new <name> --handle <h1 handle>`
2. Ask the operator once for the enrolled HackerOne username, then
   `scripts/sane set authorised=yes basis="<how they are enrolled>" h1_username=<user>`
3. `scripts/sane scope import-h1` (needs `H1_USERNAME` and `H1_TOKEN`), or have the operator paste the policy and
   scope into `engagements/<name>/policy.md`.
4. Read the whole policy. Record required headers, rate limit, exclusions and programme facts with
   `scripts/sane set ...` and `scripts/sane fact set @eng ... --ev "<the policy sentence>"`.
5. `scripts/sane kb program "<programme name>"` to see what they have paid for.
6. `scripts/sane doctor`; record `oob` and `browser` capabilities.

Arguments: `$ARGUMENTS` is the programme name or handle.

Nothing is sent to any target in this skill. Finish by running `scripts/sane status` and continuing with the
playbook it names (PB-01).

<!-- include playbooks/PB-00-engage.md -->
