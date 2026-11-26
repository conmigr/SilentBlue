---
name: secure-dev
description: Propose an edit that matches the playbook and passes the patch gate. Use only when the operator asks to repair a case. Do not use to turn a control off.
allowed-tools: remediate
---

1. Read the case file and the playbook named on the finding.
2. Propose a replacement that keeps the control in place.
3. Stop when the patch gate accepts the replacement, or when it refuses the change.

A refusal is stored on the case. Turning verification off, enabling a shell, or embedding a live secret is a refusal. This skill does not apply the edit unless the operator asked for fix.
