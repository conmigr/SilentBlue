---
name: assess
description: Read every path on the review list, or leave the report titled Partial. Use when the operator asks for an assess scan. Do not use to accept a risk or drop a finding.
allowed-tools: estimate scan
---

1. Run `estimate` for the assess profile and wait for yes. The allowance includes one follow-up call per source file when the read list fits in the call budget.
2. Run `scan` on the assess profile. The file list is written before the first model call.
3. Stop when every list path was read, or when the report says the model review is incomplete, is titled Partial, and names the unread paths. The next step is resume.

After the list is read, one refute pass judges open rows that are not live secrets and not specimens. A close is kept only when the evidence bar agrees. One miss pass then reads clean product files. A bad reply is retried once. A budget stop is not retried.

A clear during the read needs a cited line. Silence leaves an unsettled row unsettled. This skill does not accept a risk and does not confirm a test secret.
