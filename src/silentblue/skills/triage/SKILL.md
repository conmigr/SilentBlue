---
name: triage
description: Record an open, assigned, or accepted disposition beside a case id, outside the repository. Use only when the operator asks to assign or accept a case. Do not use to delete a finding.
allowed-tools: triage
---

1. Show the dispositions with `triage`.
2. Assign an owner, or accept a risk with a reason and an expiry date. The session waits for yes.
3. Stop when the decision is stored under the state directory.

The finding stays in the report. An accepted row returns to open on its expiry date. `remediate` skips an accepted row until that date. The model cannot set a disposition.

See `references/record.md`.
