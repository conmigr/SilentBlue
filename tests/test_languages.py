"""Each language pack reports a gap and stays quiet on a plain file."""

from __future__ import annotations

import pytest

from silentblue.detectors import detect
from silentblue.models import ScopedFile, ScopeResult
from silentblue.scope import EXT_LANG


def _rules(tmp_path, name: str, source: str) -> set[str]:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    language = EXT_LANG[path.suffix.lower()]
    scope = ScopeResult(
        files=[ScopedFile(path=name, size=path.stat().st_size, language=language)]
    )
    findings, _dropped = detect(tmp_path, scope)
    return {finding.rule_id for finding in findings}


@pytest.mark.parametrize(
    ("name", "source", "rule"),
    [
        ("app.js", "const fn = new Function(code);\n", "dynamic-eval"),
        ("app.rb", 'system("ls #{name}")\n', "shell-command"),
        ("app.c", "system(cmd);\n", "shell-enabled"),
        ("app.rs", 'Command::new("sh").arg("-c").arg(cmd);\n', "shell-enabled"),
        ("main.go", 'exec.Command("sh", "-c", cmd)\n', "shell-enabled"),
        ("App.java", 'Runtime.getRuntime().exec(cmd);\n', "shell-enabled"),
        ("app.php", "shell_exec($cmd);\n", "shell-command"),
        ("App.cs", "Process.Start(path);\n", "shell-enabled"),
        ("build.sh", 'eval "$cmd"\n', "dynamic-eval"),
    ],
)
def test_language_gap(tmp_path, name, source, rule):
    assert rule in _rules(tmp_path, name, source)


@pytest.mark.parametrize(
    ("name", "source"),
    [
        ("app.js", "const ready = 1;\n"),
        ("app.rb", 'name = "ada"\n'),
        ("app.c", "int ready = 1;\n"),
        ("app.rs", "fn ready() {}\n"),
        ("main.go", 'fmt.Println("ok")\n'),
        ("App.java", "int ready = 1;\n"),
        ("app.php", "<?php $ready = 1;\n"),
        ("App.cs", "var ready = 1;\n"),
        ("build.sh", "echo ok\n"),
    ],
)
def test_language_plain_file_is_quiet(tmp_path, name, source):
    assert _rules(tmp_path, name, source) == set()
