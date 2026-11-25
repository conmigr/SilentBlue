"""Harness skills, coverage ledger, and triage dispositions."""

from datetime import date

from silentblue.models import ScopeConfig
from silentblue.scanledger import ledger_for
from silentblue.scope import collect_scope
from silentblue.skillload import TOOLS, catalog, get_skill
from silentblue.triage import TriageEntry, accepted_case_ids, active_disposition, record_entry


def test_skills_match_the_folder_and_name_real_tools():
    skills = catalog()
    names = [skill.name for skill in skills]
    assert names == sorted(names)
    assert "detect" in names
    assert "triage" in names
    for skill in skills:
        assert skill.name == get_skill(skill.name).name
        assert skill.description
        assert set(skill.allowed_tools) <= TOOLS
        assert skill.body


def test_show_a_skill_maps_without_running_it():
    from silentblue.dialogue import interpret

    listed = interpret("show skills")
    one = interpret("show detect skill")
    assert listed.command == "/skills"
    assert one.command == "/skill detect"
    assert interpret("show findings").command == "/findings"


def test_coverage_ledger_checks_a_source_file_and_skips_prose(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("# notes\n", encoding="utf-8")
    (tmp_path / ".agents").mkdir()
    (tmp_path / ".agents" / "SKILL.md").write_text("name: x\n", encoding="utf-8")
    scope = collect_scope(tmp_path, ScopeConfig())
    ledger = ledger_for(scope)
    rows = {row.path: row for row in ledger.rows}
    assert "injection" in rows["app.py"].families
    assert rows["notes.md"].reason == "outside a language pack"
    assert ".agents/SKILL.md" not in rows
    assert ".agents" in scope.mirror_dirs
    assert ledger.saturated


def test_an_accepted_risk_expires_and_blocks_remediate_until_then(tmp_path):
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    case_id = "sb1_" + "ab" * 16
    entry = TriageEntry(
        case_id=case_id,
        disposition="accepted",
        reason="Tracked in the change window.",
        expires="2026-12-01",
        recorded_at="2026-11-25T00:00:00Z",
    )
    record_entry(state, repo, entry)
    assert active_disposition(entry, date(2026, 11, 25)) == "accepted"
    assert active_disposition(entry, date(2026, 12, 1)) == "open"
    assert case_id in accepted_case_ids(state, repo, date(2026, 11, 25))
    assert case_id not in accepted_case_ids(state, repo, date(2026, 12, 1))
