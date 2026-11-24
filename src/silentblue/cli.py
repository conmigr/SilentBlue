"""Command line for Silent Blue."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import typer

from silentblue import __version__
from silentblue.batch import run_batch
from silentblue.checkpoints import prune_runs
from silentblue.deploy import run_deploy
from silentblue.config import load_config
from silentblue.envfile import load_operator_env
from silentblue.errors import SilentBlueError
from silentblue.ingest import run_ingest
from silentblue.redact import configure_logging, redact
from silentblue.remediate import run_remediate
from silentblue.cost import format_usd
from silentblue.report import parse_formats
from silentblue.model import configured_model, route_status
from silentblue.runner import estimate_repo, resolve_state_dir, run_scan
from silentblue.session import run_session
from silentblue.validate import run_validate

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Silent Blue defensive security harness.",
)


@app.callback()
def _root() -> None:
    """Silent Blue defensive security harness."""


@app.command()
def setup(
    config: Path | None = typer.Option(None, "--config", help="Profile outside the repository."),
    state_dir: Path | None = typer.Option(None, "--state-dir"),
) -> None:
    """Check that the local environment can run a deterministic scan."""

    code, text = _readiness(config, state_dir)
    typer.echo(text)
    if code == 0:
        typer.echo("Next: python -m silentblue estimate --repo examples/sample")
        typer.echo("Then: python -m silentblue scan --repo examples/sample")
        if "assess key: absent" in text:
            typer.echo("For assess, copy .env.example to .env and set SILENTBLUE_API_KEY.")
    raise typer.Exit(code=code)


@app.command()
def doctor(
    config: Path | None = typer.Option(None, "--config"),
    state_dir: Path | None = typer.Option(None, "--state-dir"),
) -> None:
    """Check config and the state directory. This command makes no network calls."""

    code, text = _readiness(config, state_dir)
    typer.echo(text)
    raise typer.Exit(code=code)


@app.command()
def estimate(
    repo: Path = typer.Option(..., "--repo", exists=True, file_okay=False),
    config: Path | None = typer.Option(None, "--config"),
    profile: str | None = typer.Option(None, "--profile"),
) -> None:
    """Preview scope. Estimation makes no model calls."""

    try:
        code, text = estimate_repo(repo=repo, config_path=config, cwd=Path.cwd(), profile=profile)
    except SilentBlueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=exc.exit_code) from exc
    typer.echo(text)
    raise typer.Exit(code=code)


@app.command()
def run(
    repo: Path = typer.Option(..., "--repo", exists=True, file_okay=False),
    state_dir: Path | None = typer.Option(None, "--state-dir"),
    manifest_dir: Path | None = typer.Option(None, "--manifest-dir"),
) -> None:
    """Open a session. Type /help at the prompt."""

    code = run_session(repo, state_dir=state_dir, manifest_dir=manifest_dir, router=True)
    raise typer.Exit(code=code)


@app.command()
def scan(
    repo: Path = typer.Option(..., "--repo", exists=True, file_okay=False),
    stop_after: str = typer.Option("d9", "--stop-after"),
    config: Path | None = typer.Option(None, "--config"),
    state_dir: Path | None = typer.Option(None, "--state-dir"),
    manifest_dir: Path | None = typer.Option(None, "--manifest-dir"),
    profile: str | None = typer.Option(None, "--profile", help="detect or assess."),
    report_format: str = typer.Option(
        "json,md,sarif,html,pdf",
        "--format",
        help="Comma-separated list: json, md, sarif, html, pdf, yaml.",
    ),
    resume: bool = typer.Option(False, "--resume"),
    osv: bool = typer.Option(False, "--osv", help="Query OSV for pinned PyPI and npm packages."),
) -> None:
    """Scan a repository and write the selected report formats."""

    try:
        selected = parse_formats(report_format)
    except SilentBlueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=exc.exit_code) from exc
    result = run_scan(
        repo=repo,
        stop_after=stop_after,
        config_path=config,
        state_dir=state_dir,
        manifest_dir=manifest_dir,
        resume=resume,
        cwd=Path.cwd(),
        argv=[redact(item) for item in sys.argv],
        profile=profile,
        formats=selected,
        osv=True if osv else None,
    )
    stream = sys.stderr if result.exit_code else sys.stdout
    typer.echo(f"silentblue {__version__}", file=stream)
    typer.echo(result.message, file=stream)
    typer.echo(f"findings: {result.finding_count}", file=stream)
    if result.findings_path:
        typer.echo(f"report: {result.findings_path}", file=stream)
    if result.exit_code == 0:
        typer.echo(
            f"estimated_cost_usd: {format_usd(result.estimated_cost_usd, result.rate_known)}",
            file=stream,
        )
        typer.echo(
            f"actual_cost_usd: {format_usd(result.actual_cost_usd, result.usage_known and result.rate_known)}",
            file=stream,
        )
    raise typer.Exit(code=result.exit_code)


@app.command()
def remediate(
    repo: Path = typer.Option(..., "--repo", exists=True, file_okay=False),
    mode: str = typer.Option("report-only", "--mode", help="report-only or fix."),
    fix: bool = typer.Option(False, "--fix", help="Apply patches the policy gate accepted."),
    findings: Path | None = typer.Option(None, "--findings"),
    config: Path | None = typer.Option(None, "--config"),
    manifest_dir: Path | None = typer.Option(None, "--manifest-dir"),
) -> None:
    """Write one remediation case per confirmed gap."""

    result = run_remediate(
        repo=repo,
        mode=mode,
        fix=fix,
        findings=findings,
        config_path=config,
        manifest_dir=manifest_dir,
        cwd=Path.cwd(),
        argv=[redact(item) for item in sys.argv],
    )
    stream = sys.stderr if result.exit_code else sys.stdout
    typer.echo(f"silentblue {__version__}", file=stream)
    typer.echo(result.message, file=stream)
    typer.echo(f"cases: {result.case_count}", file=stream)
    if result.case_dir:
        typer.echo(f"cases directory: {result.case_dir}", file=stream)
    raise typer.Exit(code=result.exit_code)


@app.command()
def validate(
    repo: Path = typer.Option(..., "--repo", exists=True, file_okay=False),
    case: str | None = typer.Option(None, "--case", help="One sb1_ case id."),
    config: Path | None = typer.Option(None, "--config"),
    manifest_dir: Path | None = typer.Option(None, "--manifest-dir"),
) -> None:
    """Record a host verdict for each remediation case."""

    result = run_validate(
        repo=repo,
        case_id=case,
        config_path=config,
        manifest_dir=manifest_dir,
        cwd=Path.cwd(),
        argv=[redact(item) for item in sys.argv],
    )
    stream = sys.stderr if result.exit_code else sys.stdout
    typer.echo(f"silentblue {__version__}", file=stream)
    typer.echo(result.message, file=stream)
    typer.echo(f"cases: {result.case_count}", file=stream)
    for case_id, verdict in result.verdicts.items():
        typer.echo(f"{case_id}: {verdict}", file=stream)
    raise typer.Exit(code=result.exit_code)


@app.command()
def deploy(
    repo: Path = typer.Option(..., "--repo", exists=True, file_okay=False),
    url: str = typer.Option("", "--url", help="One http or https URL. Requested once."),
    snapshot: Path | None = typer.Option(None, "--snapshot", help="Account file outside the repository."),
    deploy_dir: Path | None = typer.Option(None, "--deploy-dir", help="Extra directory of deployment files."),
    findings: Path | None = typer.Option(None, "--findings"),
    manifest_dir: Path | None = typer.Option(None, "--manifest-dir"),
) -> None:
    """Review the declared deployment and one named URL."""

    result = run_deploy(
        repo=repo,
        url=url or None,
        snapshot=snapshot,
        deploy_dir=deploy_dir,
        findings=findings,
        manifest_dir=manifest_dir,
        cwd=Path.cwd(),
        argv=[redact(item) for item in sys.argv],
    )
    stream = sys.stderr if result.exit_code else sys.stdout
    typer.echo(f"silentblue {__version__}", file=stream)
    typer.echo(result.message, file=stream)
    typer.echo(f"declared: {result.declared_count}", file=stream)
    typer.echo(f"observed: {result.observed_count}", file=stream)
    if result.findings_path:
        typer.echo(f"report: {result.findings_path}", file=stream)
    raise typer.Exit(code=result.exit_code)


@app.command()
def ingest(
    repo: Path = typer.Option(..., "--repo", exists=True, file_okay=False),
    sarif: Path = typer.Option(..., "--sarif", exists=True, dir_okay=False),
    manifest_dir: Path | None = typer.Option(None, "--manifest-dir"),
) -> None:
    """Import SARIF 2.1.0 results into a Silent Blue report."""

    result = run_ingest(
        repo=repo,
        sarif=sarif,
        manifest_dir=manifest_dir,
        cwd=Path.cwd(),
        argv=[redact(item) for item in sys.argv],
    )
    stream = sys.stderr if result.exit_code else sys.stdout
    typer.echo(f"silentblue {__version__}", file=stream)
    typer.echo(result.message, file=stream)
    typer.echo(f"findings: {result.finding_count}", file=stream)
    if result.findings_path:
        typer.echo(f"report: {result.findings_path}", file=stream)
    raise typer.Exit(code=result.exit_code)


@app.command("batch")
def batch_scan(
    repo_list: Path = typer.Option(..., "--list", exists=True, dir_okay=False),
    state_dir: Path | None = typer.Option(None, "--state-dir"),
    manifest_dir: Path | None = typer.Option(None, "--manifest-dir"),
) -> None:
    """Scan each repository in a list. The detect profile makes no model calls."""

    result = run_batch(
        repo_list=repo_list,
        state_dir=state_dir,
        manifest_dir=manifest_dir,
        cwd=Path.cwd(),
        argv=[redact(item) for item in sys.argv],
    )
    stream = sys.stderr if result.exit_code else sys.stdout
    typer.echo(f"silentblue {__version__}", file=stream)
    typer.echo(result.message, file=stream)
    typer.echo(f"repos: {len(result.repos)}", file=stream)
    typer.echo(f"model_calls: {result.model_calls}", file=stream)
    raise typer.Exit(code=result.exit_code)


@app.command()
def gc(
    state_dir: Path | None = typer.Option(None, "--state-dir"),
    keep_runs: int = typer.Option(100, "--keep-runs", min=0),
    max_age_days: int = typer.Option(5, "--max-age-days", min=0),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Prune old run checkpoints. Reports on disk are left in place."""

    configure_logging()
    directory = _gc_state_dir(state_dir)
    removed = prune_runs(
        directory,
        keep_runs=keep_runs,
        max_age_days=max_age_days,
        dry_run=dry_run,
    )
    action = "would remove" if dry_run else "removed"
    typer.echo(f"{action}: {len(removed)}")
    for path in removed:
        typer.echo(path.name)


def main() -> None:
    """Console-script entry point."""

    configure_logging()
    app()


def _readiness(
    config: Path | None,
    state_dir: Path | None = None,
) -> tuple[int, str]:
    configure_logging()
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    lines = [f"silentblue {__version__}", f"python: {version}"]
    if sys.version_info < (3, 11):
        lines.append("config: skipped")
        lines.append("state: skipped")
        return 1, "\n".join(lines)
    imaginary = Path.cwd() / "__silentblue_readiness_target__"
    loaded_files = load_operator_env(imaginary, Path.cwd())
    if loaded_files:
        lines.append("env file: " + ", ".join(str(path) for path in loaded_files))
    else:
        lines.append("env file: absent")
    try:
        loaded = load_config(config, Path.cwd(), imaginary)
        lines.append(f"config: ok ({loaded.profile})")
    except SilentBlueError as exc:
        lines.append(f"config: {exc}")
        lines.append("state: skipped")
        return exc.exit_code, "\n".join(lines)
    try:
        resolved = resolve_state_dir(state_dir, imaginary)
        lines.append(f"state: ok ({resolved})")
    except SilentBlueError as exc:
        lines.append(f"state: {exc}")
        return 1, "\n".join(lines)
    lines.append("model_calls: 0")
    key_state = "present" if os.environ.get("SILENTBLUE_API_KEY", "").strip() else "absent"
    lines.append(f"assess key: {key_state}")
    try:
        lines.extend(route_status(configured_model(loaded.model)))
    except SilentBlueError as exc:
        lines.append(f"model: {exc}")
    lines.append("This check does not call the model.")
    from silentblue.supply import ca_bundle_label, load_ca, osv_endpoint

    lines.append(f"ca bundle: {ca_bundle_label(None)}")
    ready, note = load_ca(None)
    if not ready:
        lines.append(note)
    url, _host, source, url_note = osv_endpoint()
    if url:
        lines.append(f"osv url: {url} ({source})")
    else:
        lines.append(f"osv url: missing. {url_note}")
    return 0, "\n".join(lines)


def _gc_state_dir(flag: Path | None) -> Path:
    if flag is not None:
        return flag.expanduser().resolve()
    env = os.environ.get("SILENTBLUE_STATE_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return Path.home() / ".silentblue" / "state"
