---
name: threat-model
description: Draft a threat model and record acceptance outside the repository. Use when the operator asks to draft or accept the threat model. Do not use to drop a finding.
allowed-tools: scan
---

1. Show the current model. Draft from findings when the operator asks. Draft assess only after yes.
2. Add an assumption only after yes.
3. Accept only after the operator confirms. The hash is stored outside the repository.
4. Stop when acceptance is recorded, or when the operator leaves the draft unaccepted.

Acceptance reorders findings and adds an asset line. It does not drop a finding. A later `scan` uses that acceptance.
