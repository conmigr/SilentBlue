"""Deterministic repository inventory."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from silentblue.models import DirSkip, FileSkip, ScopedFile, ScopeConfig, ScopeResult
from silentblue.paths import is_reparse_point, is_within

EXT_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".vue": "vue",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".swift": "swift",
    ".scala": "scala",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".xml": "xml",
    ".html": "html",
    ".css": "css",
    ".sh": "shell",
    ".ps1": "powershell",
    ".tf": "terraform",
    ".sql": "sql",
    ".env": "dotenv",
    ".md": "markdown",
}

_ESCAPE_CAP = 100
_DIR_SKIP_SAMPLE = 8
SOURCE_LANGUAGES = frozenset(
    {
        "python",
        "javascript",
        "typescript",
        "tsx",
        "vue",
        "ruby",
        "c",
        "cpp",
        "rust",
        "go",
        "java",
        "php",
        "csharp",
        "kotlin",
        "swift",
        "scala",
        "shell",
        "powershell",
    }
)


def is_source_path(relative: str) -> bool:
    """True when the assess walk should read this inventory path."""

    suffix = relative.rsplit(".", 1)
    extension = f".{suffix[-1].lower()}" if len(suffix) == 2 else ""
    return EXT_LANG.get(extension, "") in SOURCE_LANGUAGES


def collect_scope(
    repo: Path,
    config: ScopeConfig,
    extra_exclude_dirs: set[str] | None = None,
) -> ScopeResult:
    """Walk ``repo`` and keep files that stay inside it."""

    root = repo.resolve()
    excluded_dirs = set(config.exclude_dirs)
    if extra_exclude_dirs:
        excluded_dirs.update(extra_exclude_dirs)
    excluded_exts = set(config.exclude_exts)
    max_bytes = config.max_file_kb * 1024
    files: list[ScopedFile] = []
    counts: dict[str, int] = {}
    escapes: list[str] = []
    mirrors: list[str] = []
    skip_counts: dict[str, int] = {}
    skip_paths: dict[str, list[str]] = {}
    mirror_names = {".claude", ".cursor", ".agents", "backups"}
    file_skips: list[FileSkip] = []

    def bump(reason: str) -> None:
        counts[reason] = counts.get(reason, 0) + 1

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        if current != root and not is_within(root, current):
            dirnames[:] = []
            filenames[:] = []
            continue
        kept: list[str] = []
        for name in dirnames:
            path = current / name
            if name in excluded_dirs or name in mirror_names:
                relative = _relative(root, path)
                if relative:
                    if name in mirror_names:
                        mirrors.append(relative)
                    skip_counts[name] = skip_counts.get(name, 0) + 1
                    sample = skip_paths.setdefault(name, [])
                    if len(sample) < _DIR_SKIP_SAMPLE:
                        sample.append(relative)
                bump("excluded_dir")
                continue
            if is_reparse_point(path) or not is_within(root, path):
                _record_link(root, path, bump, escapes)
                continue
            kept.append(name)
        dirnames[:] = kept

        for name in filenames:
            path = current / name
            relative = _relative(root, path)
            if relative is None or not is_within(root, path):
                bump("outside_root")
                _remember_escape(root, path, escapes)
                continue
            if is_reparse_point(path):
                if not _allow_file_link(root, path, config.follow_symlinks, bump, escapes):
                    continue
            if path.suffix.lower() in excluded_exts:
                bump("excluded_ext")
                continue
            if _glob_excluded(relative, config.exclude_globs):
                bump("excluded_glob")
                continue
            try:
                size = path.stat().st_size
            except OSError:
                bump("unreadable")
                if relative:
                    file_skips.append(FileSkip(path=relative, reason="unreadable"))
                continue
            if size > max_bytes:
                bump("too_large")
                if relative:
                    file_skips.append(FileSkip(path=relative, reason="too-large"))
                continue
            language = EXT_LANG.get(path.suffix.lower(), "unknown")
            files.append(ScopedFile(path=relative, size=size, language=language))

    files.sort(key=lambda item: item.path)
    return ScopeResult(
        files=files,
        excluded_counts=dict(sorted(counts.items())),
        symlink_escapes=escapes,
        mirror_dirs=mirrors,
        dir_skips={
            name: DirSkip(count=skip_counts[name], paths=sorted(skip_paths.get(name, [])))
            for name in sorted(skip_counts)
        },
        file_skips=sorted(file_skips, key=lambda item: item.path),
    )


def _record_link(
    root: Path,
    path: Path,
    bump,
    escapes: list[str],
) -> None:
    """Directory links are never followed. Escapes are counted either way."""

    if not is_within(root, path):
        bump("symlink_escapes")
        _remember_escape(root, path, escapes)
        return
    bump("symlink_dir")


def _allow_file_link(
    root: Path,
    path: Path,
    follow: bool,
    bump,
    escapes: list[str],
) -> bool:
    if not is_within(root, path):
        bump("symlink_escapes")
        _remember_escape(root, path, escapes)
        return False
    if not follow:
        bump("symlink")
        return False
    return True


def _remember_escape(root: Path, path: Path, escapes: list[str]) -> None:
    if len(escapes) >= _ESCAPE_CAP:
        return
    relative = _relative(root, path, follow=False)
    escapes.append(relative or path.name)


def _relative(root: Path, path: Path, follow: bool = False) -> str | None:
    try:
        target = path.resolve() if follow else path
        return target.relative_to(root).as_posix()
    except (OSError, ValueError):
        return None


def _glob_excluded(relative: str, patterns: list[str]) -> bool:
    name = relative.rsplit("/", 1)[-1]
    return any(
        fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(name, pattern)
        for pattern in patterns
    )
