---
name: supply
description: Query OSV after the operator confirms, and keep the advisory rows in the report. Use when the operator asks for dependency advisories. Do not use to patch a lockfile.
allowed-tools: scan
---

1. Run `scan` with the OSV query. The session prints the URL, the package count, and the CA result, then waits for yes.
2. Read the advisory rows with the findings command for OSV. Each row names the lockfile, the fixed version when the advisory has a newer one, and the command that refreshes that lockfile.
3. Stop when those rows are in the report, or when the operator answers no.

The query is one batch request. A version range with no lockfile is not sent. This skill does not edit a manifest.
