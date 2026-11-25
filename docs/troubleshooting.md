# Troubleshooting

Use this page when a command prints a line you did not expect. The run book stays in the [README](../README.md).

Start with the checks that send no network traffic. The command is the same in PowerShell, Terminal, and a Linux shell:

```text
python -m silentblue doctor
```

`doctor` prints the Python version, whether an env file loaded, the assess key state, `ca bundle:`, and `osv url:`. Inside `run`, ask `why is the CA bundle missing?` or `why did OSV fail?`. The answer uses the Python that is running the session.

`python` and `python3` can be different programs. Certificates, `certifi`, and `SILENTBLUE_API_KEY` apply only to the program that printed the path. Quit the session after you change `.env` or install certificates, then start it again. A value already set in the terminal is kept. A `.env` inside the repository being scanned is ignored. Put the file in the Silent Blue directory, or in `~/.silentblue/.env`. That path is the home directory on Windows, macOS, and Linux. On Windows it is the user profile, and Python accepts the `~` spelling.

## CA bundle missing

`CA bundle: missing` means this Python cannot verify HTTPS. The OSV request is not sent. Detect findings are still written, and `Advisories` stays `degraded` if a scan continued.

On a Mac, open Applications, open the Python folder for the same Python the session printed, and double-click `Install Certificates.command`. On Windows, install Python from python.org and install the Windows root certificate updates. On Linux, install the operating system's CA certificates for that Python. Quit Silent Blue and start it again with that same command.

If `certifi` is installed for that Python and its file sits outside the repository, Silent Blue uses that file.

`SILENTBLUE_CA_BUNDLE` replaces the system store. Leave it unset when `ca bundle: ok`. Set it only when the system store still fails, and point it at a CA file outside the repository. A missing file, a file that will not load, or a file inside the repository is reported as missing even when the system store is fine.

## OSV could not be reached

The scan message says the advisory check did not complete. `/status` shows `advisories  degraded`, and the process exits 1. The note names the URL.

The query is one HTTPS POST to `SILENTBLUE_OSV_URL`. When that variable is unset, the URL is `https://api.osv.dev/v1/querybatch`. The request waits 20 seconds. Certificate verification stays on. A redirect to another host is refused. An `http` URL is refused. Confirm that this machine can open the printed URL.

## OSV finished with no advisory rows

`Advisories: queried` and `No OSV findings` means the query finished. None of the versions that were sent had an advisory.

A version range is sent only when a lockfile resolves it. `node_modules` is not walked. An exact pin is sent only when that directory has no lockfile. `Packages: 0` on the preview means nothing was declared in a form OSV can query. The check can still complete.

## OSV rows are gone

`show osv findings` reads the latest `findings.json`. Restarting `run` keeps the advisory rows when the resolved packages still match the last query. The scan message says they were kept.

`/scan` or `/scan assess` without `osv` replaces that file and drops the rows. `/scan resume` does not query OSV and does not keep the rows. The timestamped Markdown, HTML, SARIF, and PDF from the earlier scan remain in `security-scan`.

Type `/scan osv` and then `yes` to query again. A report written before the package fingerprint was stored says the package set was not recorded. One `/scan osv` after that records it.

## Which model is configured

Inside `run`, ask `what model am I using?`. `/status` and `python -m silentblue doctor` print the same route. None of these call the model.

`Provider` and `Model` are the values the next assess call will send. An unset `SILENTBLUE_MODEL` shows that provider's default. `Endpoint` is the full URL. For Gemini that URL ends in `/openai/chat/completions`. Flash uses the same URL. Set `SILENTBLUE_MODEL` to the Flash id and leave `SILENTBLUE_BASE_URL` unset. The Google SDK root is a different request, and this client does not send it.

`Assess key: absent` means the call cannot start. `Price: unknown` means the model is not in the price table. Set both `SILENTBLUE_PRICE_INPUT_PER_MILLION` and `SILENTBLUE_PRICE_OUTPUT_PER_MILLION`, then quit and start the session again. `This session has not called the model` means the route is only configured. A later assess finish line is what says the call ran.

## Assess did not run

`python -m silentblue setup` prints `assess key: absent` until `SILENTBLUE_API_KEY` is set in an env file outside the repository. `SILENTBLUE_PROVIDER` is `openai`, `anthropic`, `grok`, or `gemini`.

Exit 2 means the run was refused before a report. Exit 1 with `assessment degraded` means the report was written and a model call failed. The finish line names the failure: `credential`, `unreachable`, `endpoint error`, or `empty reply`. `model endpoint rejected the credential` is the key. `model endpoint was unreachable` is the network or `SILENTBLUE_BASE_URL`.

`The model was not called` means this scan made no request. `The model ran and returned no token counts` means the replies arrived without usage. `N calls returned tokens` means the model answered. `assessment gaps added: 0` with `Model review complete` means the model read the list and named no new gap. `model review incomplete` means at least one list path was not read. A failed call or a reply that is not a JSON object leaves that unit unread and does not remove a finding already on the report. An empty observations array means those files were read. A cited file and line is kept on the first reply. It stays open until a later reply cites a line that is still in the file. Replies are saved, redacted, under the state directory in `reviews/`, outside the repository. A fenced JSON object, a string line number, `path` in place of `file`, and the older `gaps` shape are accepted. The summary states detector count, OSV count, and list paths read.

`/model draft` makes no model call. `/model draft assess` and `/scan assess` ask for `yes` before they spend.

## Cost is unknown

`actual_cost_usd: unknown` means the provider did not return token counts, or the model is not in the price table. `/cost` names the model when the tokens arrived and the price is missing, and it names both `SILENTBLUE_PRICE_INPUT_PER_MILLION` and `SILENTBLUE_PRICE_OUTPUT_PER_MILLION`.

`/cost` totals the model spend since this session started. It splits scan, assess, threat-model, and NLP. A detect scan stays at zero. Thinking tokens are shown separately and are not priced again. `Thinking is unknown` means that reply sent no reasoning count. Spend from a scan before this session is not included.

## The threat model did not change the report

A draft stays in the repository and does not reorder findings. `/model accept` records the hash outside the repository. `/status` then shows `threat model  accepted`.

`stale` means the draft changed, or a cited file is no longer in scope. Severity order returns. Draft again, then accept again. Accepting the old draft keeps that draft and leaves new advisory rows uncited.

## Directories were left out

`show exclusions` lists every directory name the scan leaves out, then the ones that exist in this repository. `.claude`, `.cursor`, `.agents`, and `backups` are on that list, along with `.git`, `node_modules`, virtualenv directories, and the report directory. A file inside one of those directories is not a finding and is not sent to the model. `/exclusions` is the same command.

`/skills` lists the procedures shipped with the harness. `/skill detect` prints one procedure. The session does not run the steps by itself. `/triage accept` stores an accepted risk outside the repository until the date you give. The finding stays in the report. On that date it is open again. `remediate` skips it until then.

A detect report includes a coverage ledger. Saturated means every in-scope file was checked or has a skip reason. An assess review that stops early lists the unread paths and the ledger is unsaturated. A confirmed deploy checks HSTS, the content-type and frame headers, and cookie flags on the one response. A header that is present is a passed check. A missing header is a finding. That check does not prove the control stops an attack.

## The report was refused or empty

An empty scope exits 2 and writes no report. `hollow` means no source was sent for review. A linked `security-scan` directory exits 2 and is not followed. The state directory, `SILENTBLUE_STATE_DIR` or `~/.silentblue/state`, must sit outside the repository. `~/.silentblue` is the home directory on Windows, macOS, and Linux.

## Deploy made no request

`url  not set` means no request was made. Set `SILENTBLUE_DEPLOY_URL` before `/deploy`, then type `yes`. The URL is `http` or `https`, with a host and no password. Certificate checks stay on. A redirect to another host is recorded and not followed. `SILENTBLUE_DEPLOY_SNAPSHOT` must sit outside the repository. `account  not observed` means the snapshot was not set. The declared review is still written.
