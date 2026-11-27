---
name: report
description: Show findings, counts, exclusions, coverage, and dispositions from the current report. Use when the operator asks to see the report. Do not use to start a scan.
allowed-tools: scan
---

1. Show findings, or the count by control category, or one category. The product-gap count is the release gate. The remediation is the repair to apply. It is not a proof of concept.
2. Read Other open rows when the report has them. `Confirm the value cannot authenticate` means the operator can run `triage` confirm. The scan does not do that itself.
3. Show exclusions when the operator asks what the walk left out.
4. Read both coverage ledgers. Detector saturation and model saturation are separate. A Partial title means resume, not triage.
5. Stop when that view is on screen.

The JSON field names stay the record. This skill does not start a scan.
