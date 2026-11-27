"""Interactive session. Slash commands run the scan and the threat model."""

from __future__ import annotations

import json
import os
import sys
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from silentblue import __version__
from silentblue.config import load_config
from silentblue.dialogue import ROUTER_SYSTEM, Decision, interpret, parse_router_reply
from silentblue.deploy import deploy_preview, open_authorization, run_deploy
from silentblue.errors import SilentBlueError, UsageError
from silentblue.layout import (
    accent,
    card,
    done,
    finding_view,
    help_text,
    prompt_for,
    severity,
    table,
    waiting,
    working,
)
from silentblue.ledger import SessionLedger
from silentblue.model import ModelReply, configured_model, failure_label, route_status
from silentblue.models import FinalReport, Finding
from silentblue.reading import display_id, display_prefix
from silentblue.report import finding_lines
from silentblue.scope import collect_scope
from silentblue.runner import (
    _model_client,
    _prepare_model,
    estimate_repo,
    resolve_state_dir,
    run_scan,
)
from silentblue.skillload import catalog, get_skill
from silentblue.style import paint
from silentblue.triage import TriageEntry, load_entries, record_entry
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


def _terminal_human() -> bool:
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


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
        human: bool | None = None,
    ) -> None:
        self.human = reader is None and writer is None and _terminal_human() if human is None else human
        self.repo = repo
        self.state_dir = state_dir
        self.manifest_dir = manifest_dir
        self._echo_prompt = reader is not None or writer is not None
        self.reader = reader or (self._input if writer is None else input)
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
        self._live_open = False
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
            self._error(exc)
            return exc.exit_code
        self._scan("detect", retain_advisories=True)
        if not self.human:
            self.writer("")
            self.writer("Type /help")
        while True:
            if self.human:
                self.writer("")
            if self._echo_prompt:
                self.writer(prompt_for(bool(self.pending)).rstrip())
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
            if self.human and self.router:
                self.writer(working("Matching that sentence"))
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
            self._ask("Accept the current threat model? yes/no")
            return False
        if decision.confirm and decision.command.startswith("/triage "):
            self.pending = "triage"
            self._pending_text = decision.command
            self._ask("Record that disposition? yes/no")
            return False
        if decision.confirm and decision.command.startswith("/model assume "):
            self.pending = "model-assume"
            self._pending_text = decision.command.split(None, 2)[2]
            self._ask("Add that assumption? yes/no")
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
        if command == "/help" or command.startswith("/help "):
            topic = "" if command == "/help" else command.split(None, 1)[1]
            self.writer(help_text(topic) or "Type /help")
            return
        if command == "/status":
            self._status()
            return
        if command == "/cost":
            self._cost()
            return
        if command == "/exclusions":
            self._exclusions()
            return
        if command == "/skills":
            self._skills()
            return
        if command.startswith("/skill "):
            self._skill(command.split(None, 1)[1].strip())
            return
        if command == "/triage":
            self._triage_list()
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
            self._ask("Continue? yes/no")
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
            self._ask("Continue? yes/no")
            return
        if command == "/deploy":
            self.pending = "deploy"
            url = os.environ.get("SILENTBLUE_DEPLOY_URL", "").strip()
            snapshot = os.environ.get("SILENTBLUE_DEPLOY_SNAPSHOT", "").strip()
            self.writer(deploy_preview(self.repo, url=url, snapshot=snapshot))
            self._ask("Continue? yes/no")
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
        if pending == "triage":
            self._triage_write(self._pending_text)
            return
        if pending == "deploy":
            self._deploy()

    def _busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _begin(self, profile: str, resume: bool = False, osv: bool = False) -> None:
        if self._busy():
            self.writer("A scan is already running. Type /status.")
            return
        if self._echo_prompt or (self.human and profile != "assess"):
            self._scan(profile, resume=resume, osv=osv)
            return
        if self.human:
            self.writer(working("Model review. Type /status. The prompt is ready."))
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
        if self.human:
            label = "Model review" if profile == "assess" else "Detect scan"
            self._live(working(label))
        else:
            self.writer(profile)

        def on_status(message: str) -> None:
            shown = _stage_line(message, profile)
            if shown is None:
                return
            if self.human:
                detail = shown.strip()
                self._live(working(f"{label}  {detail}"))
                return
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
            self._live_end()
        self.ledger.note_scan("assess" if profile == "assess" else "scan")
        self.writer(result.message)
        if result.findings_path:
            self.findings_path = Path(result.findings_path)
            self.writer(f"report  {result.findings_path}")
            self._load_report()
        if result.exit_code:
            self.writer(f"exit: {result.exit_code}")
        if self.human:
            self._finish(done(self._scan_summary()))

    def _error(self, exc: BaseException) -> None:
        self.writer(f"error: {exc}")
        if self.human:
            self.writer("Next  /status")

    def _live(self, text: str) -> None:
        if self.human and sys.stdout.isatty():
            sys.stdout.write("\r\033[K" + paint(text))
            sys.stdout.flush()
            self._live_open = True
            return
        self.writer(text)

    def _live_end(self) -> None:
        if self._live_open:
            sys.stdout.write("\n")
            sys.stdout.flush()
            self._live_open = False

    def _finish(self, line: str) -> None:
        background = threading.current_thread() is not threading.main_thread()
        if self.human and sys.stdout.isatty() and background:
            sys.stdout.write("\n" + paint(line) + "\n\n" + paint(prompt_for(bool(self.pending))))
            sys.stdout.flush()
            return
        self.writer(line)

    def _scan_summary(self) -> str:
        if self.report is None:
            return "Scan finished"
        count = len(self.report.findings)
        noun = "finding" if count == 1 else "findings"
        buckets: dict[str, int] = {}
        for finding in self.report.findings:
            buckets[finding.severity] = buckets.get(finding.severity, 0) + 1
        bits = [
            f"{name} {buckets[name]}"
            for name in ("critical", "high", "medium", "low", "info")
            if buckets.get(name)
        ]
        tail = "  ".join(bits)
        return f"{count} {noun}" + (f"  {tail}" if tail else "")

    def _deploy(self) -> None:
        from urllib.parse import urlsplit

        url = os.environ.get("SILENTBLUE_DEPLOY_URL", "").strip()
        authorization = None
        if url and self.resolved_state is not None:
            host = urlsplit(url).hostname or ""
            try:
                authorization = open_authorization(self.resolved_state, self.repo, host)
            except SilentBlueError as exc:
                self._error(exc)
                return
        result = run_deploy(
            repo=self.repo,
            manifest_dir=self.manifest_dir,
            cwd=Path.cwd(),
            authorization=authorization,
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
        rows = list(enumerate(self.report.findings, start=1))
        if self.human:
            self._show_table("Findings", rows)
            return
        for index, finding in rows:
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
            bucket = buckets.setdefault(key, {name: 0 for name in (*_SEVERITIES, *_OUTCOMES)})
            if finding.severity in bucket:
                bucket[finding.severity] += 1
            outcome = "unsettled" if finding.verdict == "inconclusive" else "confirmed"
            bucket[outcome] += 1
        ordered = sorted(buckets, key=lambda key: (-sum(buckets[key].values()), _category_label(key)))
        width = max(len("Control category"), len("Total"), *(len(_category_label(key)) for key in ordered))
        self.writer(_count_line("Control category", {name: name for name in _SEVERITIES}, "Total", width, header=True))
        totals = {name: 0 for name in (*_SEVERITIES, *_OUTCOMES)}
        for key in ordered:
            bucket = buckets[key]
            for name in totals:
                totals[name] += bucket[name]
            self.writer(_count_line(_category_label(key), bucket, str(sum(bucket[name] for name in _SEVERITIES)), width))
        self.writer(_count_line("Total", totals, str(sum(totals[name] for name in _SEVERITIES)), width))

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

    def _show_table(self, title: str, rows: list[tuple[int, Finding]]) -> None:
        repo = self.report.repo_name if self.report is not None else ""
        body = []
        for index, finding in rows:
            shown = display_id(repo, finding.number or index)
            body.append([
                accent(shown),
                severity(finding.severity),
                finding.rule_id,
                f"{finding.file}:{finding.line}",
            ])
        self.writer(f"{title}  {len(rows)}")
        self.writer("")
        for line in table(["#", "Severity", "Rule", "Location"], body):
            self.writer(line)
        self.writer("")
        first = display_id(repo, rows[0][1].number or rows[0][0])
        noun = "finding" if len(rows) == 1 else "findings"
        self.writer(f"{len(rows)} {noun}.  /finding {first} opens the first.")

    def _write_rows(self, rows: list[tuple[int, Finding]]) -> None:
        for index, finding in rows:
            name = finding.advisory_id or finding.rule_id
            package = ""
            if finding.component is not None and finding.component.purl.startswith("pkg:"):
                component = finding.component
                package = f"  {component.ecosystem} {component.name} {component.version}".rstrip()
            shown = display_id(self.report.repo_name, finding.number or index) if self.report is not None else str(index)
            self.writer(f"{shown}  {name}{package}  {finding.file}:{finding.line}")
            if finding.threat_note:
                self.writer(f"   {finding.threat_note}")

    def _finding(self, token: str) -> None:
        self._load_report()
        match = _match(self.report, token)
        if match is None:
            self.writer("No finding with that number or case id.")
            return
        index, finding = match
        repo_name = self.report.repo_name if self.report is not None else ""
        if self.human:
            for line in finding_view(repo_name, finding.number or index, finding):
                self.writer(line)
            return
        for line in finding_lines(finding, index, repo_name):
            self.writer(line)

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
        if self.human:
            rows = [
                ("Repo", str(root)),
                ("Findings", str(gaps)),
                ("Advisories", advisories),
                ("Threat model", status),
                ("Next", _next_step(status)),
            ]
            for line in card("Status", rows, self._route_lines()):
                self.writer(line)
            self.writer("")
            self.writer(done(f"threat model  {status}"))
            return
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

    def _skills(self) -> None:
        try:
            skills = catalog()
        except ValueError as exc:
            self._error(exc)
            return
        for skill in skills:
            self.writer(f"{skill.name}  {skill.description}")

    def _skill(self, name: str) -> None:
        skill = get_skill(name)
        if skill is None:
            self.writer(f"No skill named {name}.")
            return
        self.writer(skill.body)

    def _triage_list(self) -> None:
        from silentblue.triage import active_disposition

        if self.resolved_state is None:
            self.writer("No state directory.")
            return
        entries = load_entries(self.resolved_state, self.repo)
        if not entries:
            self.writer("No dispositions recorded.")
            return
        for entry in entries:
            self.writer(
                f"{entry.case_id}  {active_disposition(entry)}  {entry.owner}  {entry.expires}".rstrip()
            )

    def _triage_write(self, command: str) -> None:
        if self.resolved_state is None:
            self.writer("No state directory.")
            return
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            if command.startswith("/triage confirm "):
                self._confirm_secret(command, stamp)
                return
            if command.startswith("/triage accept "):
                _triage, _accept, case_id, day, reason = command.split(None, 4)
                entry = TriageEntry(
                    case_id=case_id,
                    disposition="accepted",
                    reason=reason,
                    expires=day,
                    recorded_at=stamp,
                )
            else:
                _triage, _assign, case_id, owner = command.split(None, 3)
                entry = TriageEntry(
                    case_id=case_id,
                    disposition="assigned",
                    owner=owner,
                    recorded_at=stamp,
                )
            record_entry(self.resolved_state, self.repo, entry)
        except (ValueError, SilentBlueError) as exc:
            self._error(exc)
            return
        self.writer(f"Recorded  {entry.disposition}  {entry.case_id}")

    def _confirm_secret(self, command: str, stamp: str) -> None:
        from silentblue.confirm import ConfirmEntry, line_hash, record_confirm
        from silentblue.roles import path_role

        if self.resolved_state is None:
            self.writer("No state directory.")
            return
        _triage, _confirm, case_id, reason = command.split(None, 3)
        self._load_report()
        finding = None
        if self.report is not None:
            for item in self.report.findings:
                if item.case_id == case_id:
                    finding = item
                    break
        if finding is None:
            raise UsageError("confirm needs a finding from the latest report")
        if path_role(finding.file) != "test" or finding.rule_id != "hardcoded-secret":
            raise UsageError("confirm is for a test secret")
        digest = line_hash(self.repo, finding.file, finding.line)
        if digest is None:
            raise UsageError("confirm needs the current line")
        record_confirm(
            self.resolved_state,
            self.repo,
            ConfirmEntry(
                case_id=case_id,
                path=finding.file,
                rule_id=finding.rule_id,
                line_hash=digest,
                reason=reason.strip(),
                recorded_at=stamp,
            ),
        )
        self.writer(f"Recorded  confirm  {case_id}")

    def _exclusions(self) -> None:
        try:
            root = self.repo.expanduser().resolve()
            config = load_config(None, Path.cwd(), root)
            scope = collect_scope(root, config.scope, extra_exclude_dirs={config.output.dirname})
        except SilentBlueError as exc:
            self._error(exc)
            return
        names: list[str] = []
        for name in [*config.scope.exclude_dirs, config.output.dirname, *sorted(scope.dir_skips)]:
            if name not in names:
                names.append(name)
        self.writer("Directories left out of the scan")
        for name in names:
            self.writer(f"  {name}")
        self.writer("Present in this repository")
        present = [name for name in names if scope.dir_skips.get(name) and scope.dir_skips[name].count]
        if not present:
            self.writer("  none")
        for name in present:
            skip = scope.dir_skips[name]
            if skip.count == 1 and skip.paths:
                self.writer(f"  {skip.paths[0]}")
                continue
            self.writer(f"  {name}  {skip.count}")
            for path in skip.paths:
                self.writer(f"    {path}")
            remaining = skip.count - len(skip.paths)
            if remaining > 0:
                self.writer(f"    {remaining} more")
        labels = (
            ("excluded_ext", "extension"),
            ("excluded_glob", "pattern"),
            ("too_large", "larger than the file limit"),
            ("unreadable", "unreadable"),
            ("outside_root", "outside the repository"),
            ("symlink_escapes", "symlink leaving the repository"),
            ("symlink_dir", "directory symlink"),
        )
        skipped = [
            (label, scope.excluded_counts[key])
            for key, label in labels
            if scope.excluded_counts.get(key, 0)
        ]
        if skipped:
            self.writer("Other files skipped")
            for label, count in skipped:
                self.writer(f"  {label}  {count}")

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
            self._error(exc)
            return
        self.writer(f"Draft written  {path}")
        self.writer(render_text(model, "draft"))

    def _enrich(self, model):
        try:
            root = self.repo.expanduser().resolve()
            config = _prepare_model(load_config(None, Path.cwd(), root, "assess"))
            client = self.client or _model_client(config, None)
        except SilentBlueError as exc:
            self._error(exc)
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
            self._error(exc)
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
            self._error(exc)
            return
        self.pending = pending
        self._ask("Continue? yes/no")

    def _ask_assess_draft(self) -> None:
        self.pending = "model-assess"
        self._print_estimate("assess")
        self._ask("Continue? yes/no")

    def _ask(self, question: str) -> None:
        if self.human:
            self.writer(waiting(question))
        else:
            self.writer(question)

    def _input(self) -> str:
        return input(paint(prompt_for(bool(self.pending))))

    def _print_estimate(self, profile: str) -> None:
        try:
            _code, text = estimate_repo(repo=self.repo, cwd=Path.cwd(), profile=profile)
        except SilentBlueError as exc:
            self._error(exc)
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
            self._error(exc)
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
            self._error(exc)
            return
        self.writer(render_text(model, "accepted"))
        self.writer(f"Accepted hash  {digest}")
        self.writer("Acceptance is stored outside the repository. Findings stay open.")


_SEVERITIES = ("critical", "high", "medium", "low", "info")
_OUTCOMES = ("confirmed", "unsettled")


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
    labels = [_SEVERITY_LABELS[name] for name in _SEVERITIES] + ["Confirmed", "Unsettled"]
    keys = [*_SEVERITIES, *_OUTCOMES]
    if header:
        cells = [name.rjust(10) for name in labels]
        return label.ljust(width) + "".join(cells) + "Total".rjust(10)
    cells = [str(counts.get(name, 0)).rjust(10) for name in keys]
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
    human: bool | None = None,
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
        human=human,
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
    prefix = display_prefix(report.repo_name)
    lowered = token.lower()
    marker = f"{prefix}-"
    if lowered.startswith(marker) and lowered[len(marker) :].isdigit():
        index = int(lowered[len(marker) :])
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
