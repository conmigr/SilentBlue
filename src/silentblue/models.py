"""Typed scan state and the report contract."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Severity = Literal["critical", "high", "medium", "low", "info"]
StageName = Literal["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9"]
StageOutcome = Literal["completed", "cached", "not_run", "skipped", "degraded"]
ProfileName = Literal["detect", "assess"]
Verdict = Literal[
    "detector",
    "pending",
    "confirmed",
    "rejected",
    "inconclusive",
    "imported",
    "declared",
    "observed",
]

CASE_ID = re.compile(r"sb1_[0-9a-f]{32}")
STAGES: tuple[StageName, ...] = (
    "d0",
    "d1",
    "d2",
    "d3",
    "d4",
    "d5",
    "d6",
    "d7",
    "d8",
    "d9",
)
ANALYSIS_STAGES: tuple[StageName, ...] = (
    "d0",
    "d1",
    "d2",
    "d3",
    "d4",
    "d5",
    "d6",
    "d7",
    "d8",
)
ASSESS_STAGES: frozenset[StageName] = frozenset({"d2", "d3", "d4", "d6"})


class ComponentDetail(BaseModel):
    """The package a dependency advisory names."""

    model_config = ConfigDict(extra="forbid")

    ecosystem: str
    name: str
    version: str
    purl: str
    fixed_version: str = ""
    relationship: Literal["", "direct", "transitive"] = ""


class Finding(BaseModel):
    """One control gap bound to a file and line."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = ""
    number: int = Field(default=0, ge=0)
    rule_id: str
    control_family: str
    severity: Severity
    title: str
    file: str
    line: int = Field(ge=1)
    description: str
    remediation: str
    snippet: str = ""
    confidence: float = Field(ge=0, le=1)
    origin: Literal["detector", "assessment", "imported", "deployment"] = "detector"
    playbook: str = ""
    verdict: Verdict = "detector"
    also_at: list[int] = Field(default_factory=list)
    threat_note: str = ""
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str = ""
    cvss_version: str = ""
    advisory_id: str = ""
    component: ComponentDetail | None = None


class DroppedFinding(BaseModel):
    """A candidate that did not become a reported finding."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    file: str
    line: int = Field(ge=1)
    reason: str


class ScopedFile(BaseModel):
    """One in-scope file."""

    model_config = ConfigDict(extra="forbid")

    path: str
    size: int = Field(ge=0)
    language: str


class ScopeResult(BaseModel):
    """Inventory produced by the scope walk."""

    model_config = ConfigDict(extra="forbid")

    files: list[ScopedFile]
    excluded_counts: dict[str, int] = Field(default_factory=dict)
    symlink_escapes: list[str] = Field(default_factory=list)


class ContextPackage(BaseModel):
    """Deterministic repository context shared by later stages."""

    model_config = ConfigDict(extra="forbid")

    primary_language: str
    languages: dict[str, int]
    manifests: list[str]
    control_hints: list[str]
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)


class ControlObjective(BaseModel):
    """A control the assessment profile will check."""

    model_config = ConfigDict(extra="forbid")

    control_family: str
    title: str
    rationale: str = ""
    paths: list[str] = Field(default_factory=list)


class WorkUnit(BaseModel):
    """One bounded chunk of assessment work."""

    model_config = ConfigDict(extra="forbid")

    unit_id: str
    control_family: str
    title: str
    rationale: str = ""
    paths: list[str] = Field(default_factory=list)


class RunState(BaseModel):
    """Checkpointed state handed from one stage to the next."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    tool_version: str
    run_id: str
    repo: str
    repo_name: str
    started_at: str
    stop_after: StageName
    scope: ScopeResult | None = None
    context: ContextPackage | None = None
    objectives: list[ControlObjective] = Field(default_factory=list)
    units: list[WorkUnit] = Field(default_factory=list)
    reviewed_units: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    dropped: list[DroppedFinding] = Field(default_factory=list)
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    usage_known: bool = True
    estimated_calls: int = 0
    estimated_input_tokens: int = 0
    estimated_output_tokens: int = 0
    estimated_cost_usd: float | None = None
    rate_known: bool = True
    model_provider: str = ""
    model_name: str = ""
    degraded: bool = False
    advisories: Literal["off", "queried", "degraded"] = "off"
    advisory_note: str = ""
    advisory_fingerprint: str = ""


class CheckpointEnvelope(BaseModel):
    """On-disk checkpoint. A validation failure discards the file."""

    model_config = ConfigDict(extra="forbid")

    stage: StageName
    schema_version: Literal["1.0"] = "1.0"
    complete: bool = True
    state: RunState


class Metrics(BaseModel):
    """Counts rendered with the report."""

    model_config = ConfigDict(extra="forbid")

    files: int
    bytes: int
    languages: dict[str, int]
    primary_language: str
    manifests: list[str]
    control_hints: list[str]
    findings: int
    dropped: int
    source_files: int = 0
    files_reviewed: int = 0
    symlink_escapes: int = 0
    model_calls: int = 0
    estimated_calls: int = 0
    estimated_cost_usd: float | None = None
    actual_cost_usd: float | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_input_tokens: int = 0
    estimated_output_tokens: int = 0
    usage_known: bool = True
    rate_known: bool = True
    price_date: str = ""
    model_provider: str = ""
    model_name: str = ""


class FinalReport(BaseModel):
    """The single object Markdown, SARIF, and findings.json render from."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0", "1.1"] = "1.1"
    tool: Literal["silentblue"] = "silentblue"
    version: str
    repo_name: str
    profile: ProfileName = "detect"
    stop_after: StageName
    generated_at: str
    summary: str
    hollow: bool = False
    threat_model: Literal["none", "draft", "accepted", "stale"] = "none"
    advisories: Literal["off", "queried", "degraded"] = "off"
    advisory_note: str = ""
    advisory_fingerprint: str = ""
    stages: dict[str, StageOutcome]
    metrics: Metrics
    findings: list[Finding]
    dropped: list[DroppedFinding]

    @model_validator(mode="after")
    def case_ids_are_assigned(self) -> FinalReport:
        seen: set[str] = set()
        for finding in self.findings:
            if CASE_ID.fullmatch(finding.case_id) is None:
                raise ValueError("finding is missing a case id")
            if finding.case_id in seen:
                raise ValueError("duplicate case id")
            seen.add(finding.case_id)
        return self


class ScopeConfig(BaseModel):
    """Knobs for the file walk."""

    model_config = ConfigDict(extra="forbid")

    max_file_kb: int = Field(default=512, ge=1, le=10240)
    follow_symlinks: bool = False
    exclude_dirs: list[str] = Field(
        default_factory=lambda: [
            ".git",
            ".hg",
            ".svn",
            "node_modules",
            ".venv",
            "venv",
            "__pycache__",
            "dist",
            "build",
            "security-scan",
            "security-remediation",
            ".silentblue",
        ]
    )
    exclude_exts: list[str] = Field(
        default_factory=lambda: [
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".webp",
            ".ico",
            ".pdf",
            ".zip",
            ".gz",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".mp4",
            ".mp3",
            ".exe",
            ".dll",
            ".so",
            ".dylib",
            ".class",
            ".jar",
        ]
    )
    exclude_globs: list[str] = Field(default_factory=list)

    @field_validator("exclude_exts")
    @classmethod
    def normalize_exts(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for item in value:
            ext = item.lower()
            if not ext.startswith("."):
                ext = f".{ext}"
            normalized.append(ext)
        return normalized


class OutputConfig(BaseModel):
    """Where a successful scan writes artifacts. Always inside the repository."""

    model_config = ConfigDict(extra="forbid")

    dirname: str = "security-scan"

    @field_validator("dirname")
    @classmethod
    def single_segment(cls, value: str) -> str:
        if value in {"", ".", ".."} or any(char in value for char in "/\\:"):
            raise ValueError("output dirname must be a single directory name")
        return value


class ModelConfig(BaseModel):
    """One chat provider. Unused by the detect profile.

    An empty ``base_url`` or ``name`` means the provider default.
    """

    model_config = ConfigDict(extra="forbid")

    provider: str = "openai"
    base_url: str = ""
    api_key: str = ""
    name: str = ""
    timeout_s: int = Field(default=60, ge=1, le=300)
    max_calls: int = Field(default=40, ge=1, le=10_000)


class BudgetConfig(BaseModel):
    """Caps for assessment work."""

    model_config = ConfigDict(extra="forbid")

    max_units: int = Field(default=20, ge=1, le=10_000)
    max_files_per_unit: int = Field(default=4, ge=1, le=30)
    max_excerpt_bytes: int = Field(default=8000, ge=200, le=100_000)
    workers: int = Field(default=4, ge=1, le=32)
    max_cost_usd: float | None = Field(default=None, ge=0)


class AppConfig(BaseModel):
    """Layered configuration for a scan."""

    model_config = ConfigDict(extra="forbid")

    profile: ProfileName = "detect"
    advisories: Literal["off", "osv"] = "off"
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)
    budgets: BudgetConfig = Field(default_factory=BudgetConfig)


class ScanResult(BaseModel):
    """Process result returned to the CLI."""

    model_config = ConfigDict(extra="forbid")

    exit_code: int
    message: str
    finding_count: int = 0
    report_dir: str | None = None
    findings_path: str | None = None
    manifest_path: str | None = None
    estimated_cost_usd: float | None = None
    actual_cost_usd: float | None = None
    usage_known: bool = True
    rate_known: bool = True


class PanelVote(BaseModel):
    """One reviewer's vote on a patched copy."""

    model_config = ConfigDict(extra="forbid")

    role: str
    vote: Literal["fixed", "partial", "not_fixed", "inconclusive"]
    reason: str = ""


class ValidationRecord(BaseModel):
    """Host verdict computed from the panel, stored on the case."""

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["fixed", "partial", "not_fixed", "inconclusive", "skipped"]
    votes: list[PanelVote] = Field(default_factory=list)
    detector_cleared: bool | None = None
    reason: str = ""


class RemediationCase(BaseModel):
    """One proposed repair, joined to a finding by case id."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    tool: Literal["silentblue"] = "silentblue"
    case_id: str
    rule_id: str
    control_family: str
    playbook: str = ""
    severity: str
    title: str
    file: str
    line: int = Field(ge=1)
    mode: Literal["report-only", "fix"]
    status: Literal["proposed", "refused", "applied"]
    refusal: str = ""
    summary: str = ""
    start_line: int = 0
    end_line: int = 0
    current: str = ""
    replacement: str = ""
    applied: bool = False
    generated_at: str
    validation: ValidationRecord | None = None

    @field_validator("case_id")
    @classmethod
    def check_case_id(cls, value: str) -> str:
        if CASE_ID.fullmatch(value) is None:
            raise ValueError("case id")
        return value


class RemediateResult(BaseModel):
    """Process result for remediate."""

    model_config = ConfigDict(extra="forbid")

    exit_code: int
    message: str
    case_count: int = 0
    proposed_count: int = 0
    refused_count: int = 0
    applied_count: int = 0
    model_calls: int = 0
    case_dir: str | None = None
    manifest_path: str | None = None


class DeployResult(BaseModel):
    """Process result for a deployment review."""

    model_config = ConfigDict(extra="forbid")

    exit_code: int
    message: str
    finding_count: int = 0
    declared_count: int = 0
    observed_count: int = 0
    findings_path: str | None = None
    manifest_path: str | None = None
    account_observed: bool = False
    url_observed: bool = False


class ValidateResult(BaseModel):
    """Process result for validate."""

    model_config = ConfigDict(extra="forbid")

    exit_code: int
    message: str
    case_count: int = 0
    model_calls: int = 0
    verdicts: dict[str, str] = Field(default_factory=dict)
    manifest_path: str | None = None


class IngestResult(BaseModel):
    """Process result for SARIF ingest."""

    model_config = ConfigDict(extra="forbid")

    exit_code: int
    message: str
    finding_count: int = 0
    dropped_count: int = 0
    findings_path: str | None = None
    manifest_path: str | None = None
    model_calls: int = 0


class BatchRepoResult(BaseModel):
    """One repository inside a batch run."""

    model_config = ConfigDict(extra="forbid")

    repo: str
    exit_code: int
    finding_count: int = 0
    message: str
    model_calls: int = 0


class BatchResult(BaseModel):
    """Process result for a detect-only batch."""

    model_config = ConfigDict(extra="forbid")

    exit_code: int
    message: str
    repos: list[BatchRepoResult] = Field(default_factory=list)
    model_calls: int = 0
    summary_path: str | None = None
