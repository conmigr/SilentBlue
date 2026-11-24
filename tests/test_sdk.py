"""The public Python entry points."""

from __future__ import annotations

import json
from pathlib import Path

from silentblue.sdk import estimate, scan
from tests.test_remediate import SOURCE


def test_sdk_scan_is_detect_and_makes_no_model_calls(workspace):
    (workspace["repo"] / "app.py").write_text(SOURCE, encoding="utf-8")
    code, text = estimate(workspace["repo"])
    assert code == 0
    assert "model_calls: 0" in text
    result = scan(
        workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )
    assert result.exit_code == 0
    assert result.finding_count == 1
    assert result.findings_path is not None
    report = json.loads(Path(result.findings_path).read_text(encoding="utf-8"))
    assert report["profile"] == "detect"
    assert report["metrics"]["model_calls"] == 0
    assert report["findings"][0]["case_id"].startswith("sb1_")
