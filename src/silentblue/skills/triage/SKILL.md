---
name: triage
description: Record an owner decision beside a case id, outside the repository. Use only when the operator asks to assign, accept, or confirm a case. Do not use to delete a finding.
allowed-tools: triage
---

1. Show recorded decisions with `triage`. An empty list means none have been recorded. A scan does not create one.
2. Assign an owner, accept a risk with a reason and an expiry date, or confirm a test secret. The session waits for yes.
3. Stop when the decision is stored under the state directory.

Confirm is only for a `hardcoded-secret` on a test path. The report asks for it by saying `Confirm the value cannot authenticate` on that row. The record stores a hash of the line. A changed line opens the row again. Accept and assign are optional. The finding stays in the report. An accepted row returns to open on its expiry date. `remediate` skips an accepted row until that date. The model cannot set a disposition.

See `references/record.md`.
