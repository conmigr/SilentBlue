"""Repository context derived from the scope inventory."""

from __future__ import annotations

from silentblue.models import ContextPackage, ScopeResult

_MANIFESTS = {
    "package.json": "node",
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "pipfile": "python",
    "go.mod": "go",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "cargo.toml": "rust",
    "gemfile": "ruby",
    "composer.json": "php",
    "dockerfile": "container",
}
_HINTS = frozenset(
    {"auth", "login", "middleware", "csrf", "session", "permission", "crypto", "secret", "jwt", "rate", "pickle", "redirect"}
)
_HINT_CAP = 100


def build_context(scope: ScopeResult) -> ContextPackage:
    """Summarize languages, manifests, and control-related paths."""

    languages: dict[str, int] = {}
    manifests: list[str] = []
    hints: list[str] = []
    total = 0
    for item in scope.files:
        total += item.size
        languages[item.language] = languages.get(item.language, 0) + 1
        name = item.path.rsplit("/", 1)[-1].lower()
        if name in _MANIFESTS:
            manifests.append(item.path)
        if len(hints) < _HINT_CAP and _hinted(item.path):
            hints.append(item.path)
    primary = "unknown"
    if languages:
        primary = sorted(languages.items(), key=lambda item: (-item[1], item[0]))[0][0]
    return ContextPackage(
        primary_language=primary,
        languages=dict(sorted(languages.items())),
        manifests=manifests,
        control_hints=hints,
        file_count=len(scope.files),
        total_bytes=total,
    )


def _hinted(path: str) -> bool:
    parts: list[str] = []
    for chunk in path.lower().replace("\\", "/").split("/"):
        parts.extend(piece for piece in chunk.replace(".", " ").replace("_", " ").replace("-", " ").split() if piece)
    return any(part in _HINTS for part in parts)
