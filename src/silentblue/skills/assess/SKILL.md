---
name: assess
description: Read every path on the review list, or leave the report saying the review is incomplete. Use when the operator asks for an assess scan. Do not use to accept a risk or drop a finding.
allowed-tools: estimate scan
---

1. Run `estimate` for the assess profile and wait for yes.
2. Run `scan` on the assess profile. The file list is written before the first model call.
3. Stop when every list path was read, or when the report says the model review is incomplete and names the unread paths.

A clear or a confirm needs a cited line. Silence leaves an unsettled row unsettled. This skill does not accept a risk.
