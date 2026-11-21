---
name: scope
description: Import, edit, show or check the engagement scope. Use when the user gives domains, wildcards, CIDRs or out-of-scope lists, asks whether a host is in scope, or the programme's scope changed.
---

# /scope — playbook PB-01

`scripts/sane playbook PB-01` is the procedure.

| Need | Command |
|---|---|
| Import from HackerOne | `scripts/sane scope import-h1 [handle]` |
| Add a rule | `scripts/sane scope add in '*.example.com'` · `scripts/sane scope add out blog.example.com --note "..."` |
| Read it back | `scripts/sane scope show` |
| Decide one host | `scripts/sane scope check <host> [<host> ...]` |
| Filter a list | `scripts/sane scope filter < hosts.txt > hosts.inscope.txt` |

Rules:

- Out-of-scope rules always win over in-scope rules.
- `*.example.com` does not include `example.com`. Add the apex only when the policy lists it.
- Prose exclusions in the policy text become `out` rules by hand.
- A rule is added only with a source: the structured scope or a sentence of the policy. A host the user would
  like to test is not a source.
- After any change: prove it with three checks (one in, one out, one unrelated), then `scripts/sane asset seed`.
