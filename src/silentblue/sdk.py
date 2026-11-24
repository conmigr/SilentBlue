"""Supported Python entry points for Silent Blue.

``scan`` defaults to the detect profile and makes no model calls.
``ingest`` and ``batch`` are detect-only as well.
"""

from __future__ import annotations

from pathlib import Path

from silentblue.batch import run_batch
from silentblue.deploy import run_deploy
from silentblue.ingest import run_ingest
from silentblue.models import BatchResult, DeployResult, IngestResult, RemediateResult, ScanResult, ValidateResult
from silentblue.remediate import run_remediate
from silentblue.runner import estimate_repo, run_scan
from silentblue.validate import run_validate


def _path(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    return Path(value)


def scan(
    repo: str | Path,
    *,
    stop_after: str = "d9",
    profile: str | None = None,
    config: str | Path | None = None,
    state_dir: str | Path | None = None,
    manifest_dir: str | Path | None = None,
    resume: bool = False,
    osv: bool | None = None,
) -> ScanResult:
    """Scan one repository and write the report."""

    return run_scan(
        repo=Path(repo),
        stop_after=stop_after,
        config_path=_path(config),
        state_dir=_path(state_dir),
        manifest_dir=_path(manifest_dir),
        resume=resume,
        profile=profile,
        osv=osv,
    )


def estimate(
    repo: str | Path,
    *,
    config: str | Path | None = None,
    profile: str | None = None,
) -> tuple[int, str]:
    """Preview scope. Estimation makes no model calls."""

    return estimate_repo(repo=Path(repo), config_path=_path(config), profile=profile)


def ingest(
    repo: str | Path,
    sarif: str | Path,
    *,
    manifest_dir: str | Path | None = None,
) -> IngestResult:
    """Import a SARIF 2.1.0 file. This call makes no model calls."""

    return run_ingest(repo=Path(repo), sarif=Path(sarif), manifest_dir=_path(manifest_dir))


def batch(
    repo_list: str | Path,
    *,
    state_dir: str | Path | None = None,
    manifest_dir: str | Path | None = None,
) -> BatchResult:
    """Scan each repository in a list with the detect profile."""

    return run_batch(
        repo_list=Path(repo_list),
        state_dir=_path(state_dir),
        manifest_dir=_path(manifest_dir),
    )


def deploy(
    repo: str | Path,
    *,
    url: str = "",
    snapshot: str | Path | None = None,
    deploy_dir: str | Path | None = None,
    findings: str | Path | None = None,
    manifest_dir: str | Path | None = None,
) -> DeployResult:
    """Review deployment files and one named URL. This call makes no model calls."""

    return run_deploy(
        repo=Path(repo),
        url=url,
        snapshot=_path(snapshot),
        deploy_dir=_path(deploy_dir),
        findings=_path(findings),
        manifest_dir=_path(manifest_dir),
    )


def remediate(
    repo: str | Path,
    *,
    mode: str = "report-only",
    fix: bool = False,
    findings: str | Path | None = None,
    config: str | Path | None = None,
    manifest_dir: str | Path | None = None,
) -> RemediateResult:
    """Write one remediation case per confirmed gap."""

    return run_remediate(
        repo=Path(repo),
        mode=mode,
        fix=fix,
        findings=_path(findings),
        config_path=_path(config),
        manifest_dir=_path(manifest_dir),
    )


def validate(
    repo: str | Path,
    *,
    case_id: str | None = None,
    config: str | Path | None = None,
    manifest_dir: str | Path | None = None,
) -> ValidateResult:
    """Record a host verdict for each remediation case."""

    return run_validate(
        repo=Path(repo),
        case_id=case_id,
        config_path=_path(config),
        manifest_dir=_path(manifest_dir),
    )
