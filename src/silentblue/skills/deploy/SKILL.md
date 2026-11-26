---
name: deploy
description: Observe one confirmed URL and the deployment files. Use only when the operator asks to review the edge. Do not use to send a payload or contact another host.
allowed-tools: deploy
---

1. Run `deploy` after a report exists. The session prints the files, the URL, and the account, then waits for yes.
2. Send one GET only when the host matches the confirmation and the window is still open.
3. Stop when the observed rows are in the report, or when the report says the edge was not observed.

The response is checked for HSTS, the content-type and frame headers, and cookie flags. A missing header is a finding. A header that is present is a passed check. This does not prove the control stops an attack.

See `references/authorization.md`.
