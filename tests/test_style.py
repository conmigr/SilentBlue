"""The session accent is one blue, and it stays off when color is disabled."""

from silentblue.style import paint


def test_paint_uses_one_blue_for_chrome(monkeypatch):
    monkeypatch.setattr("silentblue.style.color_enabled", lambda: True)
    prompt = paint("silentblue> ")
    finding = paint("1  sql-unparameterized  app.py:2")
    assert prompt.startswith("\033[38;2;79;125;176m")
    assert "silentblue>" in prompt
    assert finding.endswith("sql-unparameterized  app.py:2")
    assert "\033[38;2;79;125;176m1\033[0m" in finding


def test_paint_is_plain_when_color_is_disabled(monkeypatch):
    monkeypatch.setattr("silentblue.style.color_enabled", lambda: False)
    assert paint("silentblue>") == "silentblue>"
    assert paint("1  sql-unparameterized  app.py:2") == "1  sql-unparameterized  app.py:2"
