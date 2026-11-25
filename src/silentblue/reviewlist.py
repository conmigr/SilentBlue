"""The model review's file list. Built before any model call.

Detectors and OSV still walk the whole tree. This list is the only set of
paths the model is asked to read.
"""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

from silentblue.models import ScopeResult
from silentblue.paths import is_reparse_point, is_within
from silentblue.redact import redact
from silentblue.scope import is_source_path
from silentblue.threat import threat_status

_JS_IMPORT = re.compile(
    r"""(?:import|export)\s+(?:[^'"\n]+?\s+from\s+)?['"](\.[^'"]+)['"]|require\(\s*['"](\.[^'"]+)['"]\s*\)"""
)
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue")


def build_review_list(repo: Path, scope: ScopeResult, state_dir: Path) -> tuple[list[str], str]:
    """Return the model paths, in order, and why the list was built that way."""

    root = repo.resolve()
    allowed = {
        item.path.replace("\\", "/")
        for item in scope.files
        if is_source_path(item.path) and not _skipped(item.path)
    }
    model, status = threat_status(root, state_dir, None)
    cited: list[str] = []
    if model is not None and status == "accepted":
        cited = sorted(path for path in model.cited_files() if path in allowed)
    commit, git_ok = _threat_commit(root)
    if git_ok and commit:
        changed = _git_paths(root, "diff", "--name-only", commit)
        untracked = _git_paths(root, "ls-files", "--others", "--exclude-standard")
        note = (
            "Source files changed since the threat model was committed, plus untracked source."
        )
        ordered = [*cited, *_keep(changed, allowed, cited), *_keep(untracked, allowed, [*cited, *changed])]
    else:
        ordered = [*cited]
        for path in sorted(allowed):
            if path not in ordered:
                ordered.append(path)
        if git_ok:
            note = "The threat model file has no commit, so the list is the source tree."
        else:
            note = "Git could not be read, so the list is the source tree."
    imported = _imports(root, ordered, allowed)
    for path in imported:
        if path not in ordered:
            ordered.append(path)
    return ordered, note


def save_review_list(state_dir: Path, repo: Path, run_id: str, paths: list[str], note: str) -> Path:
    """Write the list outside the repository, before a model call."""

    directory = _review_dir(state_dir, repo, run_id)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "paths.txt"
    path.write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8", newline="\n")
    (directory / "note.txt").write_text(note + "\n", encoding="utf-8", newline="\n")
    return path


def save_reply(state_dir: Path, repo: Path, run_id: str, index: int, text: str) -> Path:
    """Keep one redacted reply outside the repository so a bad shape can be reread."""

    directory = _review_dir(state_dir, repo, run_id)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"reply-{index:04d}.txt"
    path.write_text(redact(text), encoding="utf-8", newline="\n")
    return path


def _review_dir(state_dir: Path, repo: Path, run_id: str) -> Path:
    import hashlib

    digest = hashlib.sha256(str(repo.resolve()).encode("utf-8")).hexdigest()[:16]
    return state_dir / "reviews" / digest / run_id


def _skipped(path: str) -> bool:
    portable = path.replace("\\", "/")
    if portable == ".claude/worktrees" or portable.startswith(".claude/worktrees/"):
        return True
    if "/.claude/worktrees/" in f"/{portable}/":
        return True
    return "backups" in portable.split("/")


def _keep(paths: list[str], allowed: set[str], earlier: list[str]) -> list[str]:
    seen = {item.replace("\\", "/") for item in earlier}
    chosen: list[str] = []
    for path in paths:
        portable = path.replace("\\", "/")
        if portable in allowed and portable not in seen and portable not in chosen:
            chosen.append(portable)
    return chosen


def _threat_commit(repo: Path) -> tuple[str, bool]:
    """Return the commit that last recorded the threat model, and whether git ran."""

    text = _git(repo, "log", "-1", "--format=%H", "--", "security-scan/threat-model.json")
    if text is None:
        return "", False
    return text.strip(), True


def _git_paths(repo: Path, *args: str) -> list[str]:
    text = _git(repo, *args)
    if not text:
        return []
    return [line.strip().replace("\\", "/") for line in text.splitlines() if line.strip()]


def _git(repo: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def _imports(repo: Path, paths: list[str], allowed: set[str]) -> list[str]:
    found: list[str] = []
    seen = set(paths)
    for path in paths:
        for imported in _import_paths(repo, path):
            if imported in allowed and imported not in seen and imported not in found:
                found.append(imported)
                seen.add(imported)
    return found


def _import_paths(repo: Path, relative: str) -> list[str]:
    file_path = repo / relative
    if not file_path.is_file() or is_reparse_point(file_path) or not is_within(repo, file_path):
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    suffix = file_path.suffix.lower()
    if suffix == ".py":
        return _python_imports(repo, relative, text)
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue"}:
        return _javascript_imports(repo, relative, text)
    return []


def _python_imports(repo: Path, relative: str, text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    parent = Path(relative).parent
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            level = node.level or 0
            module = node.module or ""
            if level:
                base = parent
                for _ in range(level - 1):
                    base = base.parent
                parts = [part for part in module.split(".") if part]
                found.extend(_python_candidates(repo, base, parts))
                for alias in node.names:
                    if alias.name and alias.name != "*":
                        found.extend(_python_candidates(repo, base, [*parts, alias.name]))
                continue
            if module:
                found.extend(_python_candidates(repo, Path(), module.split(".")))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                found.extend(_python_candidates(repo, Path(), alias.name.split(".")))
    return found


def _python_candidates(repo: Path, base: Path, parts: list[str]) -> list[str]:
    if not parts:
        target = base / "__init__.py"
        return _inside(repo, target)
    dotted = base.joinpath(*parts)
    found = _inside(repo, dotted.with_suffix(".py"))
    found.extend(_inside(repo, dotted / "__init__.py"))
    return found


def _javascript_imports(repo: Path, relative: str, text: str) -> list[str]:
    parent = (repo / relative).parent
    found: list[str] = []
    for match in _JS_IMPORT.finditer(text):
        specifier = match.group(1) or match.group(2) or ""
        if not specifier.startswith("."):
            continue
        target = (parent / specifier).resolve()
        if not is_within(repo, target):
            continue
        if target.suffix:
            found.extend(_inside(repo, target))
            continue
        for suffix in _JS_SUFFIXES:
            found.extend(_inside(repo, target.with_suffix(suffix)))
            found.extend(_inside(repo, target / f"index{suffix}"))
    return found


def _inside(repo: Path, path: Path) -> list[str]:
    try:
        resolved = path.resolve()
    except OSError:
        return []
    if not resolved.is_file() or is_reparse_point(resolved) or not is_within(repo, resolved):
        return []
    relative = resolved.relative_to(repo.resolve()).as_posix()
    if _skipped(relative) or not is_source_path(relative):
        return []
    return [relative]
