"""Load harness skills from the package. The body is read when one skill is selected."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent / "skills"
_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
TOOLS = frozenset({"estimate", "scan", "triage", "deploy", "remediate", "validate"})


@dataclass(frozen=True)
class Skill:
    """One procedure the harness can list or show."""

    name: str
    description: str
    allowed_tools: tuple[str, ...]
    body: str


def catalog() -> list[Skill]:
    """Every skill, name and description first. Bodies are included for a direct show."""

    skills = [_load(path) for path in sorted(_ROOT.glob("*/SKILL.md"))]
    names = [item.name for item in skills]
    if len(names) != len(set(names)):
        raise ValueError("duplicate skill name")
    return skills


def get_skill(name: str) -> Skill | None:
    """Return one skill by its folder name."""

    for skill in catalog():
        if skill.name == name:
            return skill
    return None


def _load(path: Path) -> Skill:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"{path.parent.name} is missing frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError(f"{path.parent.name} frontmatter does not close")
    raw = yaml.safe_load(text[4:end])
    body = text[end + 5 :].strip()
    if not isinstance(raw, dict):
        raise ValueError(f"{path.parent.name} frontmatter is not a map")
    name = str(raw.get("name") or "")
    description = str(raw.get("description") or "").strip()
    allowed = str(raw.get("allowed-tools") or "").split()
    folder = path.parent.name
    if name != folder or _NAME.fullmatch(name) is None or len(name) > 64:
        raise ValueError(f"{folder} name does not match the folder")
    if not description or len(description) > 1024:
        raise ValueError(f"{name} description is missing or too long")
    if not body:
        raise ValueError(f"{name} is missing a body")
    unknown = [tool for tool in allowed if tool not in TOOLS]
    if unknown:
        raise ValueError(f"{name} names an unknown tool")
    return Skill(name=name, description=description, allowed_tools=tuple(allowed), body=body)
