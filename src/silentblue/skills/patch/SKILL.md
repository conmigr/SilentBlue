---
name: patch
description: Write a case file for each eligible gap and record a validate vote. Use only when the operator asks to remediate or validate. Do not use to edit source unless the operator passes fix.
allowed-tools: remediate validate
---

1. Run `remediate`. It writes a case for each finding whose verdict is `detector` or `confirmed`, and skips an accepted risk that is still in force.
2. Run `validate` when the operator asks for the vote. Source stays unchanged.
3. Stop when the case files and the vote are recorded.

Unsettled rows are not cases. `--fix` is a separate operator request.
