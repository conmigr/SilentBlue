"""Interactive session. Slash commands run the scan and the threat model."""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from silentblue import __version__
from silentblue.config import load_config
from silentblue.dialogue import ROUTER_SYSTEM, Decision, interpret, parse_router_reply
from silentblue.deploy import deploy_preview, run_deploy
from silentblue.errors import SilentBlueError
from silentblue.ledger import SessionLedger
from silentblue.model import ModelReply, configured_model, failure_label, route_status
from silentblue.models import FinalReport, Finding
from silentblue.report import finding_fields, finding_sections
from silentblue.runner import (
    _model_client,
    _prepare_model,
    estimate_repo,
    resolve_state_dir,
    run_scan,
)
from silentblue.style import paint
from silentblue.threat import (
    accept_model,
    draft_from_findings,
    html_path,
    load_model,
    render_text,
    save_model,
    threat_status,
)

Reader = Callable[[], str]
Writer = Callable[[str], None]

_HELP = """\
/help                 Show this list
/status               Repo, threat-model state, and the last scan. Also works while a scan is running
/cost                 Cost since this session started, by scan, assess, threat model, and NLP
/findings             Gaps from the latest report
show findings         Same as /findings
/findings counts      Count of gaps by control category and severity
/findings categories  Gaps grouped by control category
/findings osv         Only the OSV rows from the latest report
show osv findings     Same as /findings osv
show supply chain findings
                      Only that control category. The same form works for the others
/finding <number>     One gap, with the same labels as the report. A case id also works
/report               Paths of the written reports
show report           Same as /report
/model                Show the threat model
show model            Same as /model
/model draft          Draft a threat model from the current findings
/model draft assess   Draft after reading source. Prints the estimate and waits
/model assume <text>  Add an assumption outside the repository
/model accept         Record acceptance of the current draft outside the repository
/scan                 Run a detect scan
/scan assess          Run an assess scan. Prints the estimate and waits
/scan osv             Run a detect scan, then query OSV. Prints the package count and waits
/scan assess osv      Run an assess scan, then query OSV. Prints the estimate and waits
/scan resume          Continue an assess scan from the last finished unit
/deploy               Review deployment files. Set SILENTBLUE_DEPLOY_URL first for the live request
/quit                 Leave the session. A running scan stops after units already started

A sentence works in place of a command. Small typos still map to the same tool.
Ask what model am I using, why the CA bundle is missing, or why OSV did not run.
The model question names the provider, model, and endpoint. It does not call the model.
A request to drop a finding or change the mission is refused.
"""


class Session:
    """One open prompt for a repository."""

    def __init__(
        self,
        repo: Path,
        *,
        state_dir: Path | None = None,
        manifest_dir: Path | None = None,
        reader: Reader | None = None,
        writer: Writer | None = None,
        client=None,
        router: bool = False,
    ) -> None:
        self.repo = repo
        self.state_dir = state_dir
        self.manifest_dir = manifest_dir
        self._echo_prompt = reader is not None or writer is not None
        self.reader = reader or (_read_prompt if writer is None else input)
        self.writer = writer or _console_writer
        self.client = client
        self.ledger = SessionLedger()
        self.router = router
        self._pending_text = ""
        self._router_tried = False
        self._router_client: object | None = None
        self.pending: str | None = None
        self.report: FinalReport | None = None
        self.findings_path: Path | None = None
        self.resolved_state: Path | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._progress_lock = threading.Lock()
        self._progress = {
            "running": False,
            "profile": "",
            "stage": "",
            "units_done": 0,
            "units_total": 0,
            "source_files": 0,
            "files_queued": 0,
            "model_calls": 0,
        }
        raw = self.writer

        def locked(text: str) -> None:
            with self._write_lock:
                raw(text)

        self._write_lock = threading.Lock()
        self.writer = locked

    def run(self) -> int:
        self.writer(f"silentblue {__version__}")
        self.writer(f"repo  {self.repo}")
        try:
            self.resolved_state = resolve_state_dir(self.state_dir, self.repo.expanduser().resolve())
        except SilentBlueError as exc:
            self.writer(f"error: {exc}")
            return exc.exit_code
        self._scan("detect", retain_advisories=True)
        self.writer("")
        self.writer("Type /help")
        while True:
            if self._echo_prompt:
                self.writer("silentblue>")
            try:
                line = self.reader()
            except (EOFError, StopIteration):
                return 0
            if line is None:
                return 0
            if self.pending:
                self._answer(line.strip().lower())
                continue
            if self._turn(line):
                return self._quit()
        return 0

    def _turn(self, line: str) -> bool:
        decision = interpret(line)
        if decision.action == "none":
            decision = self._route(line)
        if decision.action == "refuse":
            self.writer(f"refuse  {decision.reason}")
            return False
        if decision.action == "ask":
            self.writer(f"ask  {decision.text}")
            return False
        if decision.action == "say":
            self._say(decision.reason)
            return False
        if decision.action != "tool" or not decision.command:
            self.writer("I didn't catch that. Type /help")
            return False
        if decision.command == "/quit":
            return True
        if decision.confirm and decision.command == "/model accept":
            self.pending = "model-accept"
            self.writer("Accept the current threat model? yes/no")
            return False
        if decision.confirm and decision.command.startswith("/model assume "):
            self.pending = "model-assume"
            self._pending_text = decision.command.split(None, 2)[2]
            self.writer("Add that assumption? yes/no")
            return False
        self._dispatch(decision.command)
        return False

    def _route(self, line: str) -> Decision:
        client = self._router()
        if client is None:
            return Decision("none")
        user = f"Operator:\n{line.strip()[:500]}\n\nSession:\n{self._card()}"
        try:
            reply = client.complete(ROUTER_SYSTEM, user)
        except SilentBlueError:
            return Decision("none")
        provider, name = _model_identity(client)
        self.ledger.add("nlp", reply, provider, name)
        text = reply.text if isinstance(reply, ModelReply) else str(reply)
        return parse_router_reply(text)

    def _router(self):
        if not self.router:
            return None
        if self.client is not None:
            return self.client
        if self._router_tried:
            return self._router_client
        self._router_tried = True
        self._router_client = _session_router(self.repo)
        return self._router_client

    def _card(self) -> str:
        _model, status = threat_status(self.repo, self.resolved_state, None)
        advisories = "off" if self.report is None else self.report.advisories
        findings = 0 if self.report is None else len(self.report.findings)
        return (
            f"repo {self.repo.name}; threat model {status}; "
            f"advisories {advisories}; findings {findings}"
        )

    def _dispatch(self, command: str) -> None:
        if command == "/help":
            self.writer(_HELP.rstrip())
            return
        if command == "/status":
            self._status()
            return
        if command == "/cost":
            self._cost()
            return
        if command == "/findings osv":
            self._findings_osv()
            return
        if command == "/findings counts":
            self._findings_counts()
            return
        if command == "/findings categories":
            self._findings_categories()
            return
        if command.startswith("/findings category "):
            self._findings_category(command.split(None, 2)[2])
            return
        if command == "/findings":
            self._findings()
            return
        if command.startswith("/finding "):
            self._finding(command.split(None, 1)[1].strip())
            return
        if command == "/report":
            self._report()
            return
        if command == "/model":
            self._show_model()
            return
        if command == "/model draft":
            self._draft("detect")
            return
        if command == "/model draft assess":
            self._ask_assess_draft()
            return
        if command == "/model accept":
            self._accept()
            return
        if command.startswith("/model assume "):
            self._assume(command.split(None, 2)[2])
            return
        if command in {
            "/scan",
            "/scan assess",
            "/scan osv",
            "/scan assess osv",
            "/scan resume",
            "/model draft assess",
            "/deploy",
        } and self._busy():
            self.writer("A scan is already running. Type /status.")
            return
        if command == "/scan":
            self._begin("detect", osv=False)
            return
        if command == "/scan assess":
            self.pending = "scan-assess"
            self._print_estimate("assess")
            self.writer("Continue? yes/no")
            return
        if command == "/scan osv":
            self._ask_osv("scan-osv", assess=False)
            return
        if command == "/scan assess osv":
            self._ask_osv("scan-assess-osv", assess=True)
            return
        if command == "/scan resume":
            self.pending = "scan-resume"
            self._print_estimate("assess")
            self.writer("Continue? yes/no")
            return
        if command == "/deploy":
            self.pending = "deploy"
            url = os.environ.get("SILENTBLUE_DEPLOY_URL", "").strip()
            snapshot = os.environ.get("SILENTBLUE_DEPLOY_SNAPSHOT", "").strip()
            self.writer(deploy_preview(self.repo, url=url, snapshot=snapshot))
            self.writer("Continue? yes/no")
            return
        self.writer("Type /help")

    def _answer(self, line: str) -> None:
        pending = self.pending
        self.pending = None
        if line not in {"yes", "y"}:
            self.writer("Cancelled.")
            return
        if pending == "scan-assess":
            self._begin("assess", osv=False)
            return
        if pending == "scan-osv":
            self._begin("detect", osv=True)
            return
        if pending == "scan-assess-osv":
            self._begin("assess", osv=True)
            return
        if pending == "scan-resume":
            self._begin("assess", resume=True)
            return
        if pending == "model-assess":
            self._draft("assess")
            return
        if pending == "model-accept":
            self._accept()
            return
        if pending == "model-assume":
            self._assume(self._pending_text)
            return
        if pending == "deploy":
            self._deploy()

    def _busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _begin(self, profile: str, resume: bool = False, osv: bool = False) -> None:
        if self._busy():
            self.writer("A scan is already running. Type /status.")
            return
        if self._echo_prompt:
            self._scan(profile, resume=resume, osv=osv)
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._scan,
            kwargs={"profile": profile, "resume": resume, "osv": osv},
            name="silentblue-scan",
            daemon=True,
        )
        self._thread.start()

    def _quit(self) -> int:
        if self._busy():
            self._stop.set()
            self.writer("Stopping after the units already started.")
            assert self._thread is not None
            self._thread.join()
        return 0

    def _snapshot(self) -> dict:
        with self._progress_lock:
            return dict(self._progress)

    def _scan(self, profile: str, resume: bool = False, osv: bool = False, retain_advisories: bool = False) -> None:
        with self._progress_lock:
            self._progress.update(
                running=True,
                profile=profile,
                stage="",
                units_done=0,
                units_total=0,
                source_files=0,
                files_queued=0,
                model_calls=0,
            )
        self.writer(profile)

        def on_status(message: str) -> None:
            shown = _stage_line(message, profile)
            if shown is not None:
                self.writer(shown)

        def on_progress(update: dict) -> None:
            with self._progress_lock:
                self._progress.update(update)
                self._progress["running"] = True

        try:
            result = run_scan(
                repo=self.repo,
                state_dir=self.resolved_state,
                manifest_dir=self.manifest_dir,
                cwd=Path.cwd(),
                profile=profile,
                resume=resume,
                osv=osv,
                retain_advisories=retain_advisories,
                on_usage=lambda reply, provider, model, failure="": self.ledger.add(
                    "assess" if profile == "assess" else "scan",
                    reply,
                    provider,
                    model,
                    failure,
                ),
                client=self.client if profile == "assess" else None,
                on_status=on_status,
                on_progress=on_progress,
                stop_event=self._stop,
            )
        finally:
            with self._progress_lock:
                self._progress["running"] = False
        self.ledger.note_scan("assess" if profile == "assess" else "scan")
        self.writer(result.message)
        if result.findings_path:
            self.findings_path = Path(result.findings_path)
            self.writer(f"report  {result.findings_path}")
            self._load_report()
        if result.exit_code:
            self.writer(f"exit: {result.exit_code}")

    def _deploy(self) -> None:
        result = run_deploy(
            repo=self.repo,
            manifest_dir=self.manifest_dir,
            cwd=Path.cwd(),
        )
        self.writer(result.message)
        if result.findings_path:
            self.findings_path = Path(result.findings_path)
            self.writer(f"report  {result.findings_path}")
            self._load_report()
        if result.exit_code:
            self.writer(f"exit: {result.exit_code}")

    def _load_report(self) -> None:
        if self.findings_path is None or not self.findings_path.is_file():
            self.report = None
            return
        try:
            self.report = FinalReport.model_validate_json(self.findings_path.read_text(encoding="utf-8"))
        except ValueError:
            self.report = None

    def _findings(self) -> None:
        if self._busy():
            self.writer("A scan is running. Type /status for progress.")
        self._load_report()
        if self.report is None or not self.report.findings:
            self.writer("No findings in the latest report.")
            return
        for index, finding in enumerate(self.report.findings, start=1):
            self.writer(f"{index}  {finding.rule_id}  {finding.file}:{finding.line}")
            if finding.threat_note:
                self.writer(f"   {finding.threat_note}")

    def _findings_osv(self) -> None:
        if self._busy():
            self.writer("A scan is running. Type /status for progress.")
            return
        self._load_report()
        if self.report is None or not self.report.findings:
            self.writer("No findings in the latest report.")
            return
        rows = [
            (index, finding)
            for index, finding in enumerate(self.report.findings, start=1)
            if finding.rule_id == "dependency-vulnerable"
        ]
        if not rows:
            self.writer(
                f"No OSV findings in the latest report. Advisories: {self.report.advisories}."
            )
            return
        self.writer(f"OSV findings: {len(rows)}")
        for index, finding in rows:
            advisory = finding.advisory_id or finding.rule_id
            package = ""
            if finding.component is not None and finding.component.purl.startswith("pkg:"):
                component = finding.component
                package = f"  {component.ecosystem} {component.name} {component.version}".rstrip()
            self.writer(f"{index}  {advisory}{package}  {finding.file}:{finding.line}")

    def _findings_counts(self) -> None:
        rows = self._finding_rows()
        if rows is None:
            return
        buckets: dict[str, dict[str, int]] = {}
        for _index, finding in rows:
            key = _category_key(finding)
            bucket = buckets.setdefault(key, {name: 0 for name in _SEVERITIES})
            if finding.severity in bucket:
                bucket[finding.severity] += 1
        ordered = sorted(buckets, key=lambda key: (-sum(buckets[key].values()), _category_label(key)))
        width = max(len("Control category"), len("Total"), *(len(_category_label(key)) for key in ordered))
        self.writer(_count_line("Control category", {name: name for name in _SEVERITIES}, "Total", width, header=True))
        totals = {name: 0 for name in _SEVERITIES}
        for key in ordered:
            bucket = buckets[key]
            for name in _SEVERITIES:
                totals[name] += bucket[name]
            self.writer(_count_line(_category_label(key), bucket, str(sum(bucket.values())), width))
        self.writer(_count_line("Total", totals, str(sum(totals.values())), width))

    def _findings_categories(self) -> None:
        rows = self._finding_rows()
        if rows is None:
            return
        groups: dict[str, list[tuple[int, Finding]]] = {}
        for index, finding in rows:
            groups.setdefault(_category_key(finding), []).append((index, finding))
        for key in sorted(groups, key=lambda item: (-len(groups[item]), _category_label(item))):
            self.writer(f"{_category_label(key)}  {len(groups[key])}")
            self._write_rows(groups[key])

    def _findings_category(self, name: str) -> None:
        rows = self._finding_rows()
        if rows is None:
            return
        keys = list(dict.fromkeys(_category_key(finding) for _index, finding in rows))
        chosen = _pick_category(keys, name)
        if chosen is None:
            matched = [
                (index, finding)
                for index, finding in rows
                if _norm(finding.category) == _norm(name)
            ]
            if not matched:
                labels = ", ".join(_category_label(key) for key in sorted(keys, key=_category_label))
                self.writer(f"No control category matches {name}. Categories: {labels}.")
                return
            self.writer(f"{name} findings: {len(matched)}")
            self._write_rows(matched)
            return
        matched = [(index, finding) for index, finding in rows if _category_key(finding) == chosen]
        self.writer(f"{_category_label(chosen)} findings: {len(matched)}")
        self._write_rows(matched)

    def _finding_rows(self) -> list[tuple[int, Finding]] | None:
        if self._busy():
            self.writer("A scan is running. Type /status for progress.")
        self._load_report()
        if self.report is None or not self.report.findings:
            self.writer("No findings in the latest report.")
            return None
        return list(enumerate(self.report.findings, start=1))

    def _write_rows(self, rows: list[tuple[int, Finding]]) -> None:
        for index, finding in rows:
            name = finding.advisory_id or finding.rule_id
            package = ""
            if finding.component is not None and finding.component.purl.startswith("pkg:"):
                component = finding.component
                package = f"  {component.ecosystem} {component.name} {component.version}".rstrip()
            self.writer(f"{index}  {name}{package}  {finding.file}:{finding.line}")
            if finding.threat_note:
                self.writer(f"   {finding.threat_note}")

    def _finding(self, token: str) -> None:
        self._load_report()
        match = _match(self.report, token)
        if match is None:
            self.writer("No finding with that number or case id.")
            return
        index, finding = match
        number = finding.number or index
        self.writer(f"Finding {number}: {finding.title}")
        for label, value in finding_fields(finding):
            self.writer(f"{label}: {value}")
        for label, text in finding_sections(finding):
            self.writer(f"{label}:")
            if text:
                self.writer(text)

    def _report(self) -> None:
        if self.findings_path is None:
            self.writer("No report yet.")
            return
        directory = self.findings_path.parent
        self.writer(f"findings  {self.findings_path}")
        labels = (
            ("*_report.md", "markdown"),
            ("*_report.html", "html"),
            ("*_report.pdf", "pdf"),
            ("*_report.sarif", "sarif"),
            ("*_report.yaml", "yaml"),
        )
        for pattern, label in labels:
            matches = sorted(directory.glob(pattern))
            if matches:
                self.writer(f"{label}  {matches[-1]}")
        if html_path(self.repo).is_file():
            self.writer(f"threat model  {html_path(self.repo)}")

    def _status(self) -> None:
        root = self.repo.expanduser().resolve()
        _model, status = threat_status(root, self.resolved_state, None)
        gaps = 0 if self.report is None else len(self.report.findings)
        snap = self._snapshot()
        if snap["running"]:
            self.writer("scan  running")
            self.writer(f"profile  {snap['profile']}")
            if snap["stage"]:
                self.writer(f"stage  {snap['stage']}")
            self.writer(f"units  {snap['units_done']} of {snap['units_total']}")
            self.writer(
                f"source files  {snap['files_queued']} queued of {snap['source_files']}"
            )
            self.writer(f"model calls  {snap['model_calls']}")
        self.writer(f"repo  {root}")
        self.writer(f"findings  {gaps}")
        advisories = "off" if self.report is None else self.report.advisories
        self.writer(f"advisories  {advisories}")
        self.writer(f"threat model  {status}")
        self.writer(f"next  {_next_step(status)}")
        for line in self._route_lines():
            self.writer(line)

    def _route_lines(self) -> list[str]:
        try:
            loaded = load_config(None, Path.cwd(), self.repo.expanduser().resolve())
            model = configured_model(loaded.model)
        except SilentBlueError as exc:
            return [f"error: {exc}"]
        return [*route_status(model), self.ledger.activity()]

    def _say(self, topic: str) -> None:
        if topic == "model":
            for line in self._route_lines():
                self.writer(line)
            return
        import sys

        from silentblue.supply import load_ca, osv_endpoint

        root = self.repo.expanduser().resolve()
        ready, note = load_ca(root)
        self.writer(f"Python: {sys.executable}")
        if ready:
            self.writer(
                "CA bundle: ok. This Python can see the certificate store. "
                "The OSV query can use it. Leave SILENTBLUE_CA_BUNDLE unset."
            )
        else:
            self.writer("CA bundle: missing.")
            self.writer(note)
            self.writer(
                "While it is missing, the OSV request is not sent. "
                "Detect findings are still written, and advisories stay degraded."
            )
            self.writer(
                "In a terminal, python3 -m silentblue doctor prints the same result. "
                "python and python3 matter only when those commands print different paths."
            )
        if topic != "osv":
            return
        url, _host, source, url_note = osv_endpoint()
        if url:
            self.writer(f"OSV URL: {url}")
            self.writer(f"OSV source: {source}")
        else:
            self.writer(f"OSV URL: missing. {url_note}")
        advisories = "off" if self.report is None else self.report.advisories
        self.writer(f"Advisories: {advisories}")
        if self.report is not None and self.report.advisory_note:
            self.writer(self.report.advisory_note)
        if advisories == "off":
            self.writer("This report has not kept an OSV query. Type /scan osv and then yes.")

    def _cost(self) -> None:
        if self._busy():
            self.writer("A scan is running. Totals include calls finished so far.")
        for line in self.ledger.render():
            self.writer(line)

    def _show_model(self) -> None:
        model = load_model(self.repo)
        if model is None:
            self.writer("No threat model has been drafted.")
            return
        _model, status = threat_status(self.repo, self.resolved_state, None)
        self.writer(render_text(model, status))
        self.writer(str(html_path(self.repo)))

    def _draft(self, source: str) -> None:
        self._load_report()
        if self.report is None:
            self.writer("No report yet. Run /scan first.")
            return
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        model = draft_from_findings(self.repo.name, self.report.findings, stamp, source="detect")
        if source == "assess":
            model = self._enrich(model)
        try:
            path = save_model(self.repo, model)
        except SilentBlueError as exc:
            self.writer(f"error: {exc}")
            return
        self.writer(f"Draft written  {path}")
        self.writer(render_text(model, "draft"))

    def _enrich(self, model):
        try:
            root = self.repo.expanduser().resolve()
            config = _prepare_model(load_config(None, Path.cwd(), root, "assess"))
            client = self.client or _model_client(config, None)
        except SilentBlueError as exc:
            self.writer(f"error: {exc}")
            return model
        if client is None:
            self.writer("error: assess profile requires SILENTBLUE_API_KEY")
            return model
        files = sorted({item.file for item in model.entry_points} | {link.file for link in model.links})
        listed = "\n".join(files) or "none"
        gaps = "\n".join(
            f"{finding.case_id} {finding.rule_id} {finding.file}:{finding.line} {finding.title}"
            for finding in (self.report.findings if self.report else [])
        )
        user = (
            "Draft a defensive threat model. Cite only files from the list. "
            "Do not drop a finding and do not say a control holds.\n"
            f"Files:\n{listed}\n\nFindings:\n{gaps}\n\n"
            'Return JSON {"assumptions": ["..."], "assets": [{"name", "files", "expected_control"}]}.'
        )
        provider = config.model.provider
        name = config.model.name
        try:
            reply = client.complete(
                "You map assets and trust boundaries for a defensive review. Return one JSON object.",
                user,
            )
        except SilentBlueError as exc:
            self.ledger.add("threat-model", None, provider, name, failure_label(exc))
            self.writer(f"error: {exc}")
            return model
        text = reply.text if isinstance(reply, ModelReply) else str(reply)
        provider, name = _model_identity(client)
        if provider == "unknown":
            provider, name = config.model.provider, config.model.name
        self.ledger.add("threat-model", reply, provider, name)
        extra = _assumptions_from_reply(text)
        if extra:
            model = model.model_copy(update={"source": "assess", "assumptions": [*model.assumptions, *extra]})
        else:
            model = model.model_copy(update={"source": "assess"})
            self.writer("The assess reply named no assumptions. The finding draft was kept.")
        return model

    def _ask_osv(self, pending: str, assess: bool) -> None:
        from silentblue.supply import preview_advisories

        if assess:
            self._print_estimate("assess")
        try:
            self.writer(preview_advisories(self.repo))
        except SilentBlueError as exc:
            self.writer(f"error: {exc}")
            return
        self.pending = pending
        self.writer("Continue? yes/no")

    def _ask_assess_draft(self) -> None:
        self.pending = "model-assess"
        self._print_estimate("assess")
        self.writer("Continue? yes/no")

    def _print_estimate(self, profile: str) -> None:
        try:
            _code, text = estimate_repo(repo=self.repo, cwd=Path.cwd(), profile=profile)
        except SilentBlueError as exc:
            self.writer(f"error: {exc}")
            return
        self.writer(text)

    def _assume(self, text: str) -> None:
        model = load_model(self.repo)
        if model is None:
            self.writer("No threat model has been drafted.")
            return
        cleaned = " ".join(text.split())
        if not cleaned:
            self.writer("Add the assumption text after /model assume.")
            return
        updated = model.model_copy(update={"assumptions": [*model.assumptions, cleaned[:400]]})
        try:
            save_model(self.repo, updated)
        except SilentBlueError as exc:
            self.writer(f"error: {exc}")
            return
        self.writer("Assumption added. Accept the draft again if it was already accepted.")

    def _accept(self) -> None:
        model = load_model(self.repo)
        if model is None:
            self.writer("No threat model has been drafted.")
            return
        try:
            digest = accept_model(self.repo, self.resolved_state, model)
        except SilentBlueError as exc:
            self.writer(f"error: {exc}")
            return
        self.writer(render_text(model, "accepted"))
        self.writer(f"Accepted hash  {digest}")
        self.writer("Acceptance is stored outside the repository. Findings stay open.")


_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _category_key(finding: Finding) -> str:
    text = (finding.control_family or finding.category or "unspecified").strip()
    return text or "unspecified"


def _category_label(key: str) -> str:
    parts = [part for part in key.replace("_", "-").split("-") if part]
    return " ".join(part.capitalize() for part in parts) or "Unspecified"


def _norm(value: str) -> str:
    return " ".join(value.lower().replace("_", " ").replace("-", " ").split())


def _pick_category(keys: list[str], query: str) -> str | None:
    wanted = _norm(query)
    squashed = wanted.replace(" ", "")
    exact = [
        key
        for key in keys
        if _norm(key) == wanted or _norm(key).replace(" ", "") == squashed
    ]
    if len(exact) == 1:
        return exact[0]
    close = [
        key
        for key in keys
        if _close(_norm(key), wanted) or _close(_norm(key).replace(" ", ""), squashed)
    ]
    if len(close) == 1:
        return close[0]
    return None


def _close(left: str, right: str) -> bool:
    from silentblue.dialogue import _distance

    return bool(left and right) and _distance(left, right) <= 2


def _count_line(
    label: str,
    counts: dict[str, int] | dict[str, str],
    total: str,
    width: int,
    *,
    header: bool = False,
) -> str:
    if header:
        cells = [_SEVERITY_LABELS[name].rjust(10) for name in _SEVERITIES]
        return label.ljust(width) + "".join(cells) + "Total".rjust(10)
    cells = [str(counts[name]).rjust(10) for name in _SEVERITIES]
    return label.ljust(width) + "".join(cells) + total.rjust(10)


_SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def run_session(
    repo: Path,
    *,
    state_dir: Path | None = None,
    manifest_dir: Path | None = None,
    reader: Reader | None = None,
    writer: Writer | None = None,
    client=None,
    router: bool = False,
) -> int:
    """Open a session. The reader and writer default to the terminal."""

    return Session(
        repo,
        state_dir=state_dir,
        manifest_dir=manifest_dir,
        reader=reader,
        writer=writer,
        client=client,
        router=router,
    ).run()


def _console_writer(text: str) -> None:
    print(paint(text), flush=True)


def _read_prompt() -> str:
    return input(paint("silentblue> "))


def _stage_line(message: str, profile: str) -> str | None:
    parts = message.split()
    if len(parts) != 3 or parts[0] != "stage":
        return message
    stage, outcome = parts[1], parts[2]
    if outcome == "started":
        if profile != "assess":
            return None
        outcome = "running"
    return f"  {stage}  {outcome}"


def _model_identity(client: object) -> tuple[str, str]:
    settings = getattr(client, "settings", None)
    provider = str(getattr(settings, "provider", "") or "unknown")
    name = str(getattr(settings, "name", "") or "unknown")
    return provider, name


def _next_step(status: str) -> str:
    if status == "accepted":
        return "/scan assess osv keeps this model. /scan osv starts a new draft."
    return "/scan osv, then /model draft assess, then /model accept"


def _session_router(repo: Path):
    """Build the sentence router only when an assess key is already set."""

    if not os.environ.get("SILENTBLUE_API_KEY", "").strip():
        return None
    try:
        from silentblue.model import HttpModelClient

        root = repo.expanduser().resolve()
        config = _prepare_model(load_config(None, Path.cwd(), root, "assess"))
        if not config.model.api_key.strip():
            return None
        return HttpModelClient(config.model)
    except SilentBlueError:
        return None


def _match(report: FinalReport | None, token: str) -> tuple[int, Finding] | None:
    if report is None:
        return None
    if token.isdigit():
        index = int(token)
        if 1 <= index <= len(report.findings):
            return index, report.findings[index - 1]
        return None
    for index, finding in enumerate(report.findings, start=1):
        if finding.case_id == token:
            return index, finding
    return None


def _assumptions_from_reply(text: str) -> list[str]:
    from silentblue.assess import _parse_json_object

    try:
        data = _parse_json_object(text)
    except (ValueError, json.JSONDecodeError):
        return []
    values = data.get("assumptions")
    if not isinstance(values, list):
        return []
    cleaned = []
    for item in values:
        if isinstance(item, str) and item.strip():
            cleaned.append(item.strip()[:400])
    return cleaned[:8]
