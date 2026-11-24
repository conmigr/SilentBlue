"""Layered YAML configuration."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from silentblue.errors import UsageError
from silentblue.models import AppConfig
from silentblue.paths import is_within

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def packaged_profile(name: str = "detect") -> Path:
    """Return an installed profile."""

    path = Path(__file__).resolve().parent / "profiles" / f"{name}.yaml"
    if not path.is_file():
        raise UsageError("unknown profile")
    return path


def load_config(
    explicit: Path | None,
    cwd: Path,
    repo: Path,
    profile: str | None = None,
) -> AppConfig:
    """Load defaults, then a YAML file, then an optional local overlay."""

    if profile is not None and profile not in {"detect", "assess"}:
        raise UsageError("profile must be detect or assess")
    base_path = _select_base(explicit, cwd, repo, profile or "detect")
    merged = _merge_file(AppConfig().model_dump(), base_path, repo)
    expanded = _expand_env(merged)
    try:
        loaded = AppConfig.model_validate(expanded)
    except ValidationError as exc:
        fields = ", ".join(
            ".".join(str(part) for part in error["loc"]) for error in exc.errors()
        )
        raise UsageError(f"invalid config: {fields}") from exc
    if profile is not None:
        return loaded.model_copy(update={"profile": profile})
    return loaded


def _select_base(explicit: Path | None, cwd: Path, repo: Path, profile: str) -> Path:
    if explicit is not None:
        path = explicit.expanduser().resolve()
        if not path.is_file():
            raise UsageError("config file does not exist")
        if is_within(repo, path):
            raise UsageError("config must live outside the repository")
        return path
    candidate = (cwd / "config.yaml").resolve()
    if candidate.is_file():
        if is_within(repo, candidate):
            return packaged_profile(profile)
        return candidate
    return packaged_profile(profile)


def _merge_file(defaults: dict[str, Any], path: Path, repo: Path) -> dict[str, Any]:
    merged = _deep_merge(defaults, _read_yaml(path))
    local = path.parent / "config.local.yaml"
    if local.is_file():
        if is_within(repo, local.resolve()):
            raise UsageError("config.local.yaml must live outside the repository")
        merged = _deep_merge(merged, _read_yaml(local))
    return merged


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"cannot read config: {exc.strerror or 'unreadable'}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise UsageError("config file is not valid YAML") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise UsageError("config file must be a mapping")
    return data


def _deep_merge(base: Any, overlay: Any) -> Any:
    if isinstance(base, dict) and isinstance(overlay, dict):
        merged = dict(base)
        for key, value in overlay.items():
            if key in merged:
                merged[key] = _deep_merge(merged[key], value)
            else:
                merged[key] = value
        return merged
    return overlay


def _expand_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, str):
        return _ENV.sub(_replace_env, value)
    return value


def _replace_env(match: re.Match[str]) -> str:
    name = match.group(1)
    default = match.group(2)
    if name in os.environ:
        return os.environ[name]
    if default is not None:
        return default
    raise UsageError(f"unset config value: {name}")
