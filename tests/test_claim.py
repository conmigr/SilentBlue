"""Path roles, the two coverage ledgers, the release gate, and an owner confirm."""

from __future__ import annotations

from silentblue.assess import _agrees
from silentblue.runner import run_scan
from silentblue.confirm import ConfirmEntry, confirm_status, line_hash, record_confirm
from silentblue.dialogue import interpret
from silentblue.models import Finding, ScopedFile, ScopeResult
from silentblue.roles import path_role
from silentblue.scanledger import ledger_for


def _finding(path: str, rule: str, line: int = 1) -> Finding:
    return Finding(
        case_id="sb1_" + "ab" * 16,
        rule_id=rule,
        control_family="injection",
        severity="high",
        title="Row",
        file=path,
        line=line,
        description="A cited line.",
        remediation="Change the line.",
        confidence=0.5,
    )


def test_a_specimen_passes_the_gate_and_a_product_gap_does_not(workspace):
    sample = workspace["repo"] / "examples" / "sample"
    sample.mkdir(parents=True)
    (sample / "app.py").write_text('def read(conn, name):\n    conn.execute("SELECT " + name)\n', encoding="utf-8")
    specimen = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )
    assert specimen.exit_code == 0
    assert "release gate:" not in specimen.message

    (workspace["repo"] / "app.py").write_text(
        'def read(conn, name):\n    conn.execute("SELECT " + name)\n',
        encoding="utf-8",
    )
    product = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )
    assert product.exit_code == 1
    assert "release gate:" in product.message
    assert "product gap" in product.message


def test_roles_follow_the_path():
    assert path_role("src/silentblue/assess.py") == "product"
    assert path_role("tests/test_scan.py") == "test"
    assert path_role("examples/sample/app.py") == "specimen"
    assert path_role("docs/guide.md") == "docs"
    assert path_role("requirements.txt") == "product"


def test_detector_coverage_can_be_saturated_while_the_model_list_is_not():
    scope = ScopeResult(files=[ScopedFile(path="app.py", size=8, language="python")])
    ledger = ledger_for(
        scope,
        read=[],
        review_paths=["app.py"],
        stop="budget",
        refute="not_started",
        miss="not_started",
    )
    assert ledger.saturated
    assert ledger.model_saturated is False
    assert ledger.unread == ["app.py"]
    assert ledger.rows[0].model_state == "unread"


def test_a_quoted_mention_closes_and_a_real_call_does_not(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    quoted = _finding("app.py", "tls-verify-disabled")
    (repo / "app.py").write_text('note = "verify=False"\n', encoding="utf-8")
    assert _agrees(repo, quoted, "mentioned", "verify=False")
    (repo / "app.py").write_text("client.get(url, verify=False)\n", encoding="utf-8")
    assert _agrees(repo, quoted, "mentioned", "verify=False") is False


def test_confirm_matches_the_line_and_reopens_when_it_changes(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    (repo / "tests").mkdir()
    (repo / "tests" / "test_app.py").write_text('token = "not-the-secret"\n', encoding="utf-8")
    digest = line_hash(repo, "tests/test_app.py", 1)
    assert digest is not None
    case_id = "sb1_" + "cd" * 16
    record_confirm(
        state,
        repo,
        ConfirmEntry(
            case_id=case_id,
            path="tests/test_app.py",
            rule_id="hardcoded-secret",
            line_hash=digest,
            reason="The value cannot authenticate.",
            recorded_at="2026-11-27T00:00:00Z",
        ),
    )
    assert confirm_status(state, repo, case_id, digest) == "recorded"
    (repo / "tests" / "test_app.py").write_text('token = "changed-value"\n', encoding="utf-8")
    changed = line_hash(repo, "tests/test_app.py", 1)
    assert confirm_status(state, repo, case_id, changed) == "stale"
    decision = interpret(f"/triage confirm {case_id} the value cannot authenticate")
    assert decision.confirm is True
    assert decision.command.startswith(f"/triage confirm {case_id}")
