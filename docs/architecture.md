# Architecture

Silent Blue 0.9.1 turns a source repository into a control-gap report. The detect profile is deterministic. The assess profile adds a model review of a file list written before the first model call. Markdown, SARIF 2.1.0, HTML, PDF, and `findings.json` are rendered from one typed `FinalReport`. YAML is the same object and is written only when requested. `remediate` and `validate` run after that report.

## Stages

```text
D0 scope → D1 context → D2 control model → D3 units → D4 assessment
        → D5 bind → D6 review → D7 dedup → D8 prioritize → D9 report
remediate (D10) → validate (D11)
deploy, after a source report exists
```

D0 walks the repository once. D1 summarizes that inventory. On the assess profile, D2 writes the model file list and loads model findings from the last report. It does not call the model. The list is, in order: files named by the accepted threat model, source files changed since `security-scan/threat-model.json` was committed, untracked source files, then in-repo imports of those files, one step only. A name that resolves outside the repository, including the standard library and third-party packages, stays off the list. OSV already covers declared dependencies. If that threat-model file has no commit, or git cannot be read, the list is the in-scope source tree and the report says which. `.claude`, `.cursor`, `.agents`, and any `backups` directory are left out of the scan. On assess, files that still hold an unsettled detector finding are added to the list. D3 cuts that list into units. D4 reads each unit once. A reply that names a file and a line in the excerpt becomes a finding on that call. Category is the model's word. A playbook is attached when the word matches one, and the finding keeps the model's impact and recommendation. D5 keeps a model finding whose line is still in the file and adds deterministic detector rows. D6 does not call the model and does not delete a finding. A later review clears a carried case id only when the reply cites a line that is still in a file it was shown. D7 merges nearby detector hits of the same rule and leaves model findings intact. D8 orders the gaps and keeps a model case id that was already minted. D9 writes the artifacts.

The detect profile skips D2, D3, D4, and D6. Those stages show `skipped`. It makes no model calls.

D4 uses a fixed worker pool, four by default and never more than 32. Workers return observations. One writer merges them into the same `findings.json`. The model review is complete only when every path on the list was read. `max_calls` and an optional dollar ceiling can stop new units before that. The report then says `Model review incomplete` and names how many list paths were read. A call that fails, or a reply that is not a JSON object, leaves those paths unread and does not delete a carried finding. A JSON object with no observations means those paths were read. Each reply is saved, redacted, under the state directory in `reviews/`, outside the repository. Resume continues the same saved list. The summary states the detector count, the OSV count, and how many list paths were read. The pre-scan estimate assumes the source tree and one call per unit, then stops at `max_calls`. `SILENTBLUE_WORKERS`, `SILENTBLUE_MAX_CALLS`, and `SILENTBLUE_MAX_COST_USD` raise those ceilings. While an assess scan is running, `/status` prints the stage, units finished, and model calls. `/quit` stops after the units already started.

`--stop-after` selects the last analysis stage. D9 still runs when the scope is non-empty, which is why a scope-only run can write an empty report. Stages after the stop point are `not_run`. D9 is `completed` when the files are written. `scan` stops at D9 and leaves source unchanged.

D10 and D11 are the `remediate` and `validate` commands. `deploy` reviews the running edge after a report exists. They are not scan stages, so `--stop-after` and `--resume` do not include them.

## Contracts

Stage handoffs and checkpoints use pydantic models. A checkpoint that fails validation, or whose repository path or tool version does not match the current run, is discarded and the stage runs again. `--resume` reuses a valid checkpoint and skips that stage. A rerun of an earlier stage reruns the stages after it. Resume does not hash file contents, so a resume after edits can reuse a stale inventory. Start a fresh scan when the tree has changed.

Case ids are `sb1_` plus the first 32 hexadecimal characters of a SHA-256 over the repo-relative path, a 10-line bucket, and the rule id. Two gaps that land in the same bucket receive a second id salted with the exact line. A third collision stops the scan before any artifact is written. A model finding keeps the case id it was given. The next assess scan carries that id until a reply cites the line that shows the control in place.

## Scope

The target is untrusted input.

- The walk does not follow directory links. On Windows that includes junctions, which are not reported as symlinks by the operating system.
- A link whose target resolves outside the repository is recorded as a symlink escape and is never opened.
- With `follow_symlinks: false` (the default), file links are excluded even when the target is inside.
- Output path `security-scan` must be absent, or a real directory inside the repository. A symlink is refused before the walk.
- The state directory must resolve outside the repository. The scan refuses to create it inside the target.
- An explicit config file, and `config.local.yaml`, must also live outside the repository.
- An empty inventory exits 2 and does not create a report.

Excluded directory names include `.git`, virtual environments, `node_modules`, build outputs, `security-scan`, `security-remediation`, `.claude`, `.cursor`, `.agents`, and `backups`. The report names `.claude`, `.cursor`, `.agents`, and `backups` when they were present, because they are copies of the tree or agent instructions rather than the tree under review. Two in-scope files with the same bytes are scanned once. The finding keeps the shortest path and lists the others. Files over `scope.max_file_kb` (512 by default) are skipped.

## Detectors

D5 reports control gaps. The repair text describes the control to put in place.

| Rule | Family | What it records |
| --- | --- | --- |
| `hardcoded-secret` | secrets | A credential a real service would accept. Live key shapes stay, including in tests. Fixture values such as `changeme` and `smoke-test` are closed. |
| `sql-unparameterized` | injection | A database execute or query builds the statement from caller-controlled text. A bound parameter, a fixed clause, a non-database `query`, and a repeated clause are one closed row or one finding. When the line does not show the source of the value, the verdict is `inconclusive`. |
| `shell-command` | injection | A shell is given an assembled command, or `os.system` is called with one. |
| `shell-enabled` | injection | A process call sets `shell=True` on a command that is not assembled on that line. |
| `dynamic-eval` | injection | `eval` or `exec` appears on a line that also references external input. |
| `tls-verify-disabled` | transport | Certificate verification is turned off. |
| `debug-enabled` | configuration | Debug mode is enabled in a configuration filename. |
| `cors-wildcard` | access-control | A cross-origin setting allows every origin. |
| `token-in-web-storage` | access-control | A session token is written to `localStorage` or `sessionStorage`. |
| `credential-logged` | secrets | A log call receives a credential value. A message that only mentions the word is skipped. |
| `html-parsed-from-string` | injection | `innerHTML`, `document.write`, `insertAdjacentHTML`, `dangerouslySetInnerHTML`, `v-html`, or a trust-bypass call parses markup. A fixed string literal is skipped for the first three. |
| `nosql-unparameterized` | injection | `$where` is assembled or taken from the request. |
| `ldap-filter-assembled` | injection | A directory filter is assembled. |
| `template-from-string` | injection | A template is compiled from a string that is not a fixed literal. |
| `header-from-request` | injection | A response header is assigned from request data. |
| `path-from-request` | request-routing | A file path is joined or sent from request data. |
| `request-url-from-input` | request-routing | An HTTP client receives a URL from request data. |
| `redirect-from-request` | request-routing | A redirect target comes from request data. |
| `weak-password-hash` | cryptography | A password or secret is passed to MD5 or SHA-1. |
| `weak-token-random` | cryptography | A token or session value uses a non-cryptographic generator. |
| `weak-cipher` | cryptography | A call selects ECB, DES, RC4, or Blowfish. |
| `unsafe-deserialization` | deserialization | A loader can construct objects from a stream. `yaml.safe_load` and `SafeLoader` are skipped. |
| `jwt-verify-disabled` | authentication | Verification is disabled, or the `none` algorithm is allowed. |
| `cookie-flag-disabled` | authentication | A cookie call sets HttpOnly or Secure to false. |
| `csrf-disabled` | access-control | CSRF protection is turned off. |
| `request-body-expanded` | access-control | A create or update takes the request body. |
| `rate-limit-disabled` | resource-limits | A limiter is exempted or its maximum is zero. |
| `default-credential` | secrets | A password is a well-known default. |
| `security-header-disabled` | configuration | A host allow-list is `*`, or a security header or secure-cookie flag is turned off. |
| `logging-disabled` | logging | A call disables the logger. |
| `dependency-unpinned` | supply-chain | A PyPI or npm declaration is not an exact version. `package.json` and `composer.json` lines that say `*` or `latest` stay in the same rule. A lockfile in the same directory that names the package suppresses the finding. |
| `dependency-cleartext` | supply-chain | A requirements line uses cleartext HTTP or `--trusted-host`. |
| `dependency-vulnerable` | supply-chain | OSV names a resolved version from a lockfile, or an exact manifest pin when that directory has no lockfile. The finding carries the CVSS score, vector, component, and whether the package is direct or transitive. |
| `install-verification-disabled` | supply-chain | An install file turns certificate verification off. |
| `ca-bundle-missing` | supply-chain | An install config sets a relative CA bundle path, and that file is not in the repository. |
| `piped-download` | supply-chain | A download is piped into a shell. |
| `workflow-permissions-wide` | supply-chain | A workflow under `.github/workflows` uses `pull_request_target` or `write-all`. |

A full-line comment is not scanned. Lines longer than 4000 characters are checked for secret-shaped tokens only.

Assess uses the same families. On a source excerpt it may also record a login, signup, password, or upload handler with no limiter in the shown lines, an object id from the request with no owner comparison, a password login with no expiry and no second factor in the shown lines, and an authentication failure discarded by an empty handler. Those gaps stay candidates. Detect and assess do not prove that a deployed limit holds, and they do not review process evidence. They send no traffic unless the scan sets `--osv`, `advisories: osv`, or the session command `/scan osv`. That query is one HTTPS POST to `SILENTBLUE_OSV_URL`, or to `https://api.osv.dev/v1/querybatch` when the variable is unset, for resolved versions in `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `go.mod` (confirmed by `go.sum` when it is present), `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `gradle.lockfile`, `packages.lock.json`, and `conan.lock`. An exact pin in `package.json`, `requirements.txt`, `pyproject.toml`, `Pipfile`, or `pom.xml` is sent only when that directory has no lockfile for the ecosystem. A version range with no lockfile is not sent. Certificate verification stays on, with no redirect to another host. A set larger than 1000 is split into further requests to the same host. Each ecosystem, name, and version is sent once. If the CA bundle cannot be loaded, or OSV cannot be reached, `advisories` is `degraded` and the process exits 1. Deploy sends one request to a URL the operator names.

Language packs add the same families for JavaScript, TypeScript, Ruby, C, C++, Rust, Go, Java, PHP, C#, and shell. A pack runs only on files the inventory labeled with that language. The assess walk reads those languages, including Rust and C.

## Report

`findings.json` is `schema_version` `1.1`. A `1.0` file still loads. The report carries the summary, stage outcomes, metrics, findings, and dropped candidates. Markdown, SARIF, HTML, and PDF are projections of that object. HTML is self-contained. PDF is a text rendering of the Markdown and uses no native library. `--format` selects any of `json`, `md`, `sarif`, `html`, `pdf`, and `yaml`. The default writes the first five. `yaml` writes one document whose field names match `findings.json`. Every finding carries `number`, `cvss_score`, `cvss_vector`, and `cvss_version`. The number is the report order, starting at 1. A source finding takes the CVSS v3.1 vector named for its rule, and the score stays in the same band as the severity. An OSV finding keeps the advisory score and vector, and adds `advisory_id` plus the package `component`. A source finding's component is the file. SARIF copies the score, vector, advisory id, and component into result properties. Severity names stay the control-gap ranks used for order.

A Markdown finding is a `## Finding <number>:` block. The identity line is severity, rule, `file:line`, and case id. CVSS version, score, and vector share the next line. Verdict, playbook, category, advisory, package, and fixed version share one line when they have a value. Every finding, including a model finding, uses `Description`, `Evidence`, and `Remediation`. Evidence is a fenced block named with the file. The report opens with a severity table, a control-category table, and an index. Dropped rows are grouped by reason. Stages are named in an appendix. The JSON summary is repeated under Record. HTML uses the same sections, with a left rule for severity, and prints without loading a network asset. PDF is that Markdown with a running header of the repository name and the page number. `/finding` prints the same block.

Metrics include `estimated_cost_usd` and `actual_cost_usd`. The estimate prices the call and excerpt budgets at the short-context list rate dated in `price_date`. The actual cost multiplies token counts from the provider response by that rate. A missing usage field or an unlisted model leaves the actual cost unknown. `SILENTBLUE_PRICE_INPUT_PER_MILLION` and `SILENTBLUE_PRICE_OUTPUT_PER_MILLION` replace the table when both are set. Detect stays at zero.

`run` opens a session after a detect scan. The comprehensive order is `/scan osv`, `/model draft assess`, `/model accept`, then `/scan assess osv`. An accepted model can stay in place and go straight to `/scan assess osv`. The command order for one repository, several repositories, and deploy is in the README How to run section. Slash commands list findings, list only the OSV rows with `/findings osv`, count gaps by control category with `/findings counts`, list one category with `/findings category <name>`, list directories left out of the scan with `/exclusions`, draft a threat model, and accept it. A sentence maps to one of those commands. Small typos map with the same catalog, and two close commands produce `ask` instead of a guess. A request to change the mission, drop a finding, or scan another repository produces `refuse` and no tool call. A sentence that matches nothing may go to one router completion when `SILENTBLUE_API_KEY` is set. That completion sees the sentence and a session card, not the repository. It may name one existing command, and a gated command still waits for an exact `yes`. The model file in `security-scan` is always a draft. Acceptance is a hash under the state directory, outside the repository. An accepted model reorders findings and adds a threat-model line. It does not drop a finding or decide that a control holds. A hash mismatch or a missing cited file marks the model stale and restores severity order. Assess builds its file list before the first model call: accepted threat-model files, files changed since that model was committed, untracked source, then one-step in-repo imports. `/scan assess` asks before spending a model call. One-shot `scan` never prompts. `/status` prints the next legal step from the threat-model state, then the configured provider, model, and endpoint. `what model am I using?` prints that route and does not call the model. `/cost` totals model calls made since this session started. An unlisted model with token counts leaves USD unknown and names the two price variables. A reply with no reasoning count leaves thinking unknown. An assess finish line says how many calls returned tokens, how many failed, how many assessment gaps were added, and whether the model review is complete. An empty observations array is a read path, not a dropped issue. A reply that is not JSON leaves that unit unread. Rows are scan, assess, threat-model, and NLP. Each row names the model, the call count, input tokens, output tokens, thinking tokens, and USD at the list rate. Thinking tokens come from the provider usage object and are not priced a second time. The detect scan that opens `run` keeps `dependency-vulnerable` rows when the previous report stored the resolved-package fingerprint and that fingerprint still matches. The scan message says those rows were kept. A package change leaves them out. `/scan` without `osv` still replaces the report.

SARIF uses `tool.driver.name` `Silent Blue`. Each result's `partialFingerprints["sbFindingId/v1"]` is the case id. Levels are `error` for critical and high, `warning` for medium, and `note` for low and info. Severity names are control-gap ranks. Each finding also stores a CVSS v3.1 vector. A source vector is named for the rule. An advisory vector is the one OSV returned.

The run manifest records the exit code, stage outcomes, finding count, and the model call count. Secret-shaped text in the message and argument list is redacted. Report snippets and descriptions go through the same redaction before they are written.

## State

```text
$SILENTBLUE_STATE_DIR/runs/<run_id>/checkpoints/d0.json
```

The run id is derived from the resolved repository path, the profile, the model provider, the model name, and the scope configuration. `silentblue gc` deletes run directories older than `--max-age-days` (default 5) or outside the newest `--keep-runs` (default 100). It leaves `security-scan` reports and `security-remediation` cases in place.

## Profiles

`profiles/detect.yaml` selects the detect profile. `profiles/assess.yaml` selects the assess profile. `advisories` is `off` or `osv`. The default is `off`. A one-shot `scan` follows the config. The session follows `/scan osv` and `/scan assess osv` instead, so opening a prompt does not send the query. `SILENTBLUE_OSV_URL`, when set, must be an https URL. `SILENTBLUE_CA_BUNDLE`, when set, must be a file outside the repository. A missing bundle is reported with the setting that fixes it. Verification cannot be turned off. `SILENTBLUE_PROVIDER` chooses `openai`, `anthropic`, `grok`, or `gemini`. GPT, Grok, and Gemini receive a chat-completions request with `response_format` set to a JSON object. Gemini uses the OpenAI-compatible endpoint, including Flash selected with `SILENTBLUE_MODEL`. Anthropic receives a messages request. An empty base URL or model name uses that provider's default. `SILENTBLUE_BASE_URL` and `SILENTBLUE_MODEL` override the default. `--profile` overrides the file. Knobs that a file omits come from the built-in defaults. Unknown keys are rejected.

`.env.example` lists those variables. The harness reads `~/.silentblue/.env` and then `./.env`, and only fills keys that are still empty. `~/.silentblue` is the home directory on Windows, macOS, and Linux. A file inside the repository being scanned is ignored. Process environment values win over the file.

The assess route is one HTTPS POST per call. GPT, Grok, and Gemini use `{base_url}/chat/completions` with a bearer token. Anthropic uses `{base_url}/messages` with the `x-api-key` header. The credential is not written to the report or the manifest. Each stage may retry a reply that is not valid JSON once. `model.max_calls` (40 by default) stops further calls. `budgets.max_units` (20) caps how many source groups are read. A rejected gap is dropped. A confirmed or inconclusive gap stays, with its playbook id and verdict.

If the assess profile builds no source units and the detectors also report nothing, the report sets `hollow` and says the empty result is untrusted. An empty objective list does not skip the source walk. A transport failure or an unusable reply marks that stage `degraded` and the process exits 1 after the report is written. An authentication failure exits 2 and writes no report.

## Symbol graph

For an assess scan, Python files are parsed with the standard library into an in-memory map of definitions and direct calls. D4 and D6 receive a short slice for the files in the unit. The graph is not written to the repository and is discarded when the process exits. Files that fail to parse are omitted.

## Remediation

A finding's remediation names the file and line and the control to write there. It does not include a proof of concept. A dependency advisory names the lockfile, whether the package is direct or transitive, the fixed version when one compares as newer than the installed version, and the command for that lockfile. The resolved version after the refresh has to be that fixed version. Certificate verification stays on.

`remediate` reads `security-scan/findings.json` and keeps findings whose verdict is `detector` or `confirmed`. Each one becomes `security-remediation/<case_id>.json`. The case carries the playbook, the current lines, the proposed replacement, and a status of `proposed`, `refused`, or `applied`. The replacement is the repaired source. It is not a proof of concept.

The policy gate refuses a patch that names a different file, leaves the repository, deletes a test, or turns a control off. Turning a control off includes disabling certificate checks, enabling a shell, enabling debug mode, allowing every origin, calling `eval` or `exec`, or inserting a secret-shaped literal. The refusal reason is stored on the case. The default mode is report-only, so the repository source stays as it was. `--mode fix` and `--fix` write a patch only after the gate accepts it. Overlapping ranges in one file keep the earlier range and refuse the later one.

`validate` copies the patched file to a temporary directory outside the repository. Three reviewers read that copy: the security architect, the control owner, and the regression reviewer. Each returns one vote: `fixed`, `partial`, `not_fixed`, or `inconclusive`. The host picks the majority. A tie breaks toward `not_fixed`, then `inconclusive`, then `partial`, then `fixed`. When the original detector still matches the patched copy, a `fixed` verdict is recorded as `partial`. The temporary copy is deleted. The command writes the verdict onto the case file and leaves repository source unchanged. A refused case is recorded as `skipped` and makes no model call.

## How to run

The README How to run section is the operator sequence. This section is the same order with the contract beside it. The command line exits after one command. The session is `run`, and it is the prompt an operator or an agent types at. A sentence maps to one slash command. Draft and accept exist only in that prompt. `silentblue.sdk` repeats the command-line order for a caller.

One repository, command line: `estimate`, `scan`, `scan --osv`, `scan --profile assess`, `deploy`, `remediate`, `validate`. One repository, session: `run --repo`, the threat-model branch, `/scan osv`, `/scan assess`, `/deploy`, `/quit`, then `remediate` and `validate` from the command line. `/scan assess osv` is the assess scan that also queries OSV. `/scan resume` does not.

Several repositories stay several reports. The order is frontend, backend, then components. Repeat the one-repository command line, or open a new `run --repo`, for each path. `batch` is detect-only and is not this review. Deploy runs once, on the repository that holds the edge, after the other reports exist. The session that deploys is the last `run --repo`. Set `SILENTBLUE_DEPLOY_URL` before that prompt. The edge threat model is the one that names the public listener, the origin, and the data store.

A workspace file outside those trees is the later shape of one prompt. This version does not read it.

```json
{
  "name": "product",
  "repos": [
    {"role": "frontend", "path": "C:/src/web"},
    {"role": "backend", "path": "C:/src/api"},
    {"role": "components", "path": "C:/src/ui"}
  ]
}
```

## Deployment

`deploy` runs after `security-scan/findings.json` exists. It reads Terraform, compose files, nginx config, and ingress or gateway YAML under `deploy`, `infra`, `k8s`, `kubernetes`, `helm`, `nginx`, `proxy`, or `gateway`. `--deploy-dir` adds one real directory. The session does not take that flag. Links that leave the root are not opened.

A declared gap is a candidate in the same `findings.json`, with control family `deployment` and verdict `declared`. The review records an origin with no proxy or load balancer, a public listener that stays on clear text, a public listener with no WAF attached, an admin or data port published to the whole internet, and a proxy that copies a client-supplied forwarded header. A WAF being attached is not evidence that it stops an attack. `remediate` does not turn these rows into source patches. A second deploy replaces deployment rows and leaves source rows in place.

The live side is two optional inputs. On the command line they are `--url` and `--snapshot`. In the session they are `SILENTBLUE_DEPLOY_URL` and `SILENTBLUE_DEPLOY_SNAPSHOT`, read when `/deploy` is confirmed. The URL is requested once, over HTTP or HTTPS, with certificate verification left on. A redirect to another host is recorded and not followed. The review keeps the certificate name and expiry, a missing redirect to HTTPS, and `Set-Cookie` flags. The snapshot is JSON outside the repository: `listeners`, `rules`, `waf_attached`, and `public_origin`. Those rows use verdict `observed`. When the URL or the snapshot is absent, the report says that side was not observed and still writes the declared review. The command makes no model calls and sends no payload.

`/deploy` prints `deployment files`, `url`, and `account`, then waits for yes or no. A draft after `deploy` adds a Public edge asset for those rule ids. Accept that draft again so the edge is part of the accepted model.

## Operate

`ingest` reads a SARIF 2.1.0 file and writes the same three report artifacts. Each result needs a rule id, a relative path, and a start line. A `file:` URI is kept only when it resolves inside the repository. Paths that leave the repository, and directory links, are recorded as dropped and are not opened. A result that already carries `partialFingerprints["sbFindingId/v1"]` keeps that case id. Imported rows use origin `imported` and verdict `imported`, so `remediate` does not treat them as confirmed gaps. The command makes no model calls. At most 200 results are imported from a file of at most 2 MB.

`batch` reads a text list of repository paths, skipping blank lines and lines that start with `#`. It runs the detect profile on each repository and continues after a failure. It does not query OSV. The list is a real file of at most 100 paths. The summary manifest records each exit code and a model call count of zero.

`silentblue.sdk` is the supported import surface for `scan`, `estimate`, `ingest`, `batch`, `remediate`, `validate`, and `deploy`. The commands to run from a checkout are in the README. `examples/sample` is the small repository those commands use.

The CI workflow checks out the tree, installs the package, runs `python -m pytest`, and runs a detect scan on Ubuntu, Windows, and macOS. That scan does not pass `--osv`. A completed report exits 0. Findings stay in the report for a person to review. The operator command is `python -m silentblue` on Windows, macOS, and Linux. Imported SARIF rows leave the CVSS and component fields empty.
