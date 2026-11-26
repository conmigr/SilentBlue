"""Terminal cards stay plain when stdout is not a terminal."""

from silentblue.layout import card, command_text, done, help_text, table, waiting


def test_help_groups_name_the_commands():
    short = help_text("")
    assert "/status" in short
    assert "/findings osv" not in short
    assert "/scan osv" in help_text("scan")
    assert "/exclusions" in help_text("findings")
    assert "/model draft" in help_text("model")
    assert help_text("wipe") == ""


def test_a_table_lines_up_and_a_pipe_keeps_records():
    lines = table(
        ["#", "Severity", "Rule", "Location"],
        [["rep-1", "high", "sql-unparameterized", "app.py:2"]],
    )
    assert lines[0].startswith("  #")
    assert "Severity" in lines[0]
    assert "rep-1" in lines[1]
    assert "app.py:2" in lines[1]
    shown = card("Status", [("Threat model", "accepted")])
    assert shown[0] == "Status"
    assert "Threat model" in shown[2]
    assert "accepted" in shown[2]
    piped = command_text(["silentblue 0.9.1", "findings: 2", "Scan finished."])
    assert "findings: 2" in piped
    assert done("Scan finished.").startswith("done  ")
    assert waiting("Continue? yes/no") == "waiting  Continue? yes/no"
