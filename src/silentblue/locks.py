"""Resolved dependency versions from lockfiles. No network.

A lockfile in a directory is the version list for that ecosystem.
Exact manifest pins are used only when that directory has no lockfile.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from silentblue.paths import is_reparse_point, is_within

_LOCK_CAP = 20 * 1024 * 1024
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        "security-scan",
        "security-remediation",
        ".silentblue",
    }
)
_YARN_VERSION = re.compile(r'^\s*version:?\s+"?([^"\s]+)"?\s*$')
_GEM_SPEC = re.compile(r"^    ([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$")
_GO_MODULE = re.compile(r"^(\S+)\s+(v\S+)$")


@dataclass(frozen=True)
class ResolvedPackage:
    """One name and version taken from a lockfile or an explicit manifest."""

    ecosystem: str
    name: str
    version: str
    file: str
    line: int
    text: str
    direct: bool | None


def resolved_packages(repo: Path) -> list[ResolvedPackage]:
    """Read every supported lockfile that stays inside the repository."""

    root = repo.resolve()
    found: list[ResolvedPackage] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        if current != root and (is_reparse_point(current) or not is_within(root, current)):
            dirnames[:] = []
            continue
        dirnames[:] = [
            name
            for name in dirnames
            if name not in _SKIP_DIRS and not is_reparse_point(current / name) and is_within(root, current / name)
        ]
        names = {name.lower(): name for name in filenames}
        for lowered, original in sorted(names.items()):
            path = current / original
            if is_reparse_point(path) or not is_within(root, path):
                continue
            try:
                if path.stat().st_size > _LOCK_CAP:
                    continue
            except OSError:
                continue
            text = _read(path)
            if text is None:
                continue
            relative = path.relative_to(root).as_posix()
            found.extend(_parse(root, relative, lowered, text))
    return found


def _parse(repo: Path, relative: str, name: str, text: str) -> list[ResolvedPackage]:
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return _npm_lock(relative, text)
    if name == "yarn.lock":
        return _yarn_lock(repo, relative, text)
    if name == "pnpm-lock.yaml":
        return _pnpm_lock(relative, text)
    if name == "poetry.lock":
        return _poetry_lock(repo, relative, text)
    if name == "pipfile.lock":
        return _pipfile_lock(repo, relative, text)
    if name == "uv.lock":
        return _uv_lock(relative, text)
    if name == "go.mod":
        return _go_mod(repo, relative, text)
    if name == "cargo.lock":
        return _cargo_lock(relative, text)
    if name == "gemfile.lock":
        return _gem_lock(relative, text)
    if name == "composer.lock":
        return _composer_lock(repo, relative, text)
    if name == "gradle.lockfile":
        return _gradle_lock(repo, relative, text)
    if name == "packages.lock.json":
        return _nuget_lock(relative, text)
    if name == "conan.lock":
        return _conan_lock(relative, text)
    if name == "pom.xml" and not _sibling(repo, relative, "gradle.lockfile"):
        return _pom(relative, text)
    return []


def _npm_lock(relative: str, text: str) -> list[ResolvedPackage]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    packages = data.get("packages")
    if isinstance(packages, dict):
        root = packages.get("") if isinstance(packages.get(""), dict) else {}
        direct = _name_set(root, ("dependencies", "devDependencies", "optionalDependencies"))
        found: list[ResolvedPackage] = []
        for key, value in packages.items():
            if not isinstance(key, str) or not isinstance(value, dict) or value.get("link") is True:
                continue
            if "node_modules/" not in key:
                continue
            version = value.get("version")
            if not isinstance(version, str) or not version:
                continue
            name = key.split("node_modules/")[-1]
            if not name:
                continue
            line_no, line = _line_containing(text, f"node_modules/{name}")
            found.append(_row("npm", name, version, relative, line_no, line, name in direct))
        return found
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        return _npm_tree(relative, text, dependencies, direct=True)
    return []


def _npm_tree(relative: str, text: str, tree: dict, *, direct: bool) -> list[ResolvedPackage]:
    found: list[ResolvedPackage] = []
    for name, value in tree.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            continue
        version = value.get("version")
        if isinstance(version, str) and version and value.get("link") is not True:
            line_no, line = _line_containing(text, f'"{name}"')
            found.append(_row("npm", name, version, relative, line_no, line, direct))
        nested = value.get("dependencies")
        if isinstance(nested, dict):
            found.extend(_npm_tree(relative, text, nested, direct=False))
    return found


def _yarn_lock(repo: Path, relative: str, text: str) -> list[ResolvedPackage]:
    direct = _manifest_names(repo, relative, "package.json", ("dependencies", "devDependencies", "optionalDependencies"))
    found: list[ResolvedPackage] = []
    for block in re.split(r"\n\s*\n", text):
        lines = [line for line in block.splitlines() if line.strip()]
        if len(lines) < 2:
            continue
        version = ""
        for line in lines[1:]:
            match = _YARN_VERSION.match(line)
            if match:
                version = match.group(1)
                break
        if not version:
            continue
        header = lines[0].strip().strip(",").strip('"')
        name = _yarn_name(header)
        if name is None:
            continue
        line_no, line = _line_containing(text, lines[0].strip())
        known = name in direct if direct is not None else None
        found.append(_row("npm", name, version, relative, line_no, line, known))
    return found


def _yarn_name(header: str) -> str | None:
    header = header.split(",")[0].strip().strip('"')
    if "@npm:" in header:
        return header.split("@npm:", 1)[0] or None
    if header.startswith("@"):
        scope, _, rest = header[1:].partition("/")
        if not scope or not rest or "@" not in rest:
            return None
        name, _range = rest.rsplit("@", 1)
        return f"@{scope}/{name}"
    if "@" not in header:
        return None
    name, _range = header.rsplit("@", 1)
    return name or None


def _pnpm_lock(relative: str, text: str) -> list[ResolvedPackage]:
    try:
        import yaml
    except ImportError:
        return []
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict):
        return []
    direct: set[str] = set()
    importers = data.get("importers")
    if isinstance(importers, dict):
        for importer in importers.values():
            if isinstance(importer, dict):
                direct.update(_name_set(importer, ("dependencies", "devDependencies", "optionalDependencies")))
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section)
        if isinstance(block, dict):
            direct.update(name for name in block if isinstance(name, str))
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return []
    found: list[ResolvedPackage] = []
    for key in packages:
        if not isinstance(key, str):
            continue
        parsed = _pnpm_key(key)
        if parsed is None:
            continue
        name, version = parsed
        line_no, line = _line_containing(text, key.split("(")[0])
        known = name in direct if direct else None
        found.append(_row("npm", name, version, relative, line_no, line, known))
    return found


def _pnpm_key(key: str) -> tuple[str, str] | None:
    body = key.strip().lstrip("/").split("(", 1)[0]
    if body.startswith("@"):
        if "@" in body[1:]:
            name, version = body.rsplit("@", 1)
        else:
            parts = body.split("/")
            if len(parts) < 3:
                return None
            name = "/".join(parts[:-1])
            version = parts[-1]
    elif "@" in body:
        name, version = body.rsplit("@", 1)
    else:
        parts = body.split("/")
        if len(parts) < 2:
            return None
        name, version = parts[-2], parts[-1]
    version = version.strip()
    if not name or not version or not version[0].isdigit():
        return None
    return name, version


def _poetry_lock(repo: Path, relative: str, text: str) -> list[ResolvedPackage]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    direct = _pyproject_names(repo, relative)
    return _toml_packages(relative, text, data.get("package"), "PyPI", direct)


def _pipfile_lock(repo: Path, relative: str, text: str) -> list[ResolvedPackage]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    direct = _pipfile_names(repo, relative)
    found: list[ResolvedPackage] = []
    for section in ("default", "develop"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, value in block.items():
            if not isinstance(name, str) or not isinstance(value, dict):
                continue
            raw = value.get("version")
            if not isinstance(raw, str):
                continue
            version = raw[2:] if raw.startswith("==") else raw
            if not version or version.startswith(("*", "<", ">", "~", "^")):
                continue
            line_no, line = _line_containing(text, f'"{name}"')
            known = name.lower() in direct if direct is not None else None
            found.append(_row("PyPI", name, version, relative, line_no, line, known))
    return found


def _uv_lock(relative: str, text: str) -> list[ResolvedPackage]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    packages = data.get("package")
    if not isinstance(packages, list):
        return []
    direct: set[str] = set()
    found: list[ResolvedPackage] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        source = package.get("source") if isinstance(package.get("source"), dict) else {}
        if source.get("virtual") or source.get("editable"):
            direct.update(_dependency_names(package.get("dependencies")))
            continue
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str) or not version:
            continue
        line_no, line = _line_containing(text, f'name = "{name}"')
        found.append(_row("PyPI", name, version, relative, line_no, line, name.lower() in direct))
    return found


def _go_mod(repo: Path, relative: str, text: str) -> list[ResolvedPackage]:
    confirmed = _go_sum(repo, relative)
    found: list[ResolvedPackage] = []
    in_block = False
    for number, raw in enumerate(text.splitlines(), start=1):
        indirect = "// indirect" in raw
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        body = ""
        if line.startswith("require "):
            body = line[len("require ") :].strip()
        elif in_block and line:
            body = line
        match = _GO_MODULE.match(body)
        if match is None:
            continue
        name, version = match.group(1), match.group(2)
        if confirmed is not None and (name, version) not in confirmed:
            continue
        found.append(_row("Go", name, version, relative, number, raw, not indirect))
    return found


def _go_sum(repo: Path, relative: str) -> set[tuple[str, str]] | None:
    text = _sibling(repo, relative, "go.sum")
    if text is None:
        return None
    confirmed: set[tuple[str, str]] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            confirmed.add((parts[0], parts[1].split("/", 1)[0]))
    return confirmed


def _cargo_lock(relative: str, text: str) -> list[ResolvedPackage]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    packages = data.get("package")
    if not isinstance(packages, list):
        return []
    direct: set[str] = set()
    found: list[ResolvedPackage] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        source = package.get("source") if isinstance(package.get("source"), str) else ""
        if "crates.io" not in source:
            for dep in package.get("dependencies") or []:
                if isinstance(dep, str) and dep.split(" ", 1)[0]:
                    direct.add(dep.split(" ", 1)[0])
            continue
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str) or not version:
            continue
        line_no, line = _line_containing(text, f'name = "{name}"')
        found.append(_row("crates.io", name, version, relative, line_no, line, name in direct))
    return found


def _gem_lock(relative: str, text: str) -> list[ResolvedPackage]:
    direct: set[str] = set()
    found: list[ResolvedPackage] = []
    mode = ""
    for number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("DEPENDENCIES"):
            mode = "dependencies"
            continue
        if line.startswith("  specs:"):
            mode = "specs"
            continue
        if mode == "dependencies":
            if line.startswith("  ") and not line.startswith("   "):
                direct.add(line.strip().split(" ", 1)[0])
            elif line and not line.startswith(" "):
                mode = ""
            continue
        if mode == "specs":
            if line and not line.startswith(" "):
                mode = ""
                continue
            match = _GEM_SPEC.match(line)
            if match:
                name, version = match.group(1), match.group(2).split()[-1]
                found.append(_row("RubyGems", name, version, relative, number, line, name in direct))
    for index, package in enumerate(found):
        if package.name in direct and package.direct is not True:
            found[index] = _row(
                package.ecosystem, package.name, package.version, package.file, package.line, package.text, True
            )
    return found


def _composer_lock(repo: Path, relative: str, text: str) -> list[ResolvedPackage]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    direct = _composer_names(repo, relative)
    found: list[ResolvedPackage] = []
    for section in ("packages", "packages-dev"):
        rows = data.get(section)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = row.get("name")
            version = row.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            cleaned = version[1:] if version.startswith("v") and version[1:2].isdigit() else version
            if not cleaned or not cleaned[0].isdigit():
                continue
            line_no, line = _line_containing(text, f'"name": "{name}"')
            known = name in direct if direct is not None else None
            found.append(_row("Packagist", name, cleaned, relative, line_no, line, known))
    return found


def _gradle_lock(repo: Path, relative: str, text: str) -> list[ResolvedPackage]:
    declared = _gradle_declared(repo, relative)
    found: list[ResolvedPackage] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        coordinate, _configs = line.split("=", 1)
        if coordinate.count(":") < 2:
            continue
        name, version = coordinate.rsplit(":", 1)
        if not name or not version or not version[0].isdigit():
            continue
        known = name in declared if declared is not None else None
        found.append(_row("Maven", name, version, relative, number, raw, known))
    return found


def _nuget_lock(relative: str, text: str) -> list[ResolvedPackage]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    dependencies = data.get("dependencies") if isinstance(data, dict) else None
    if not isinstance(dependencies, dict):
        return []
    found: list[ResolvedPackage] = []
    for framework in dependencies.values():
        if not isinstance(framework, dict):
            continue
        for name, value in framework.items():
            if not isinstance(name, str) or not isinstance(value, dict):
                continue
            version = value.get("resolved")
            if not isinstance(version, str) or not version:
                continue
            kind = value.get("type")
            direct = True if kind == "Direct" else False if kind == "Transitive" else None
            line_no, line = _line_containing(text, f'"{name}"')
            found.append(_row("NuGet", name, version, relative, line_no, line, direct))
    return found


def _conan_lock(relative: str, text: str) -> list[ResolvedPackage]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    direct_refs = [item for item in (data.get("requires") or []) if isinstance(item, str)]
    nodes = (data.get("graph_lock") or {}).get("nodes") if isinstance(data.get("graph_lock"), dict) else None
    refs: list[str] = []
    if isinstance(nodes, dict):
        for node in nodes.values():
            if isinstance(node, dict) and isinstance(node.get("ref"), str):
                refs.append(node["ref"])
    refs.extend(direct_refs)
    found: list[ResolvedPackage] = []
    seen: set[tuple[str, str]] = set()
    for ref in refs:
        parsed = _conan_ref(ref)
        if parsed is None or parsed in seen:
            continue
        seen.add(parsed)
        name, version = parsed
        direct = any(item.startswith(f"{name}/{version}") for item in direct_refs)
        line_no, line = _line_containing(text, f"{name}/{version}")
        found.append(_row("ConanCenter", name, version, relative, line_no, line, direct if direct_refs else None))
    return found


def _conan_ref(ref: str) -> tuple[str, str] | None:
    if "/" not in ref or ref.endswith((".py", ".txt")):
        return None
    name, rest = ref.split("/", 1)
    version = rest.split("#", 1)[0].split("%", 1)[0]
    if not name or not version or not version[0].isdigit():
        return None
    return name, version


def _pom(relative: str, text: str) -> list[ResolvedPackage]:
    found: list[ResolvedPackage] = []
    for chunk in text.split("<dependency>")[1:]:
        body = chunk.split("</dependency>", 1)[0]
        group = _xml_tag(body, "groupId")
        artifact = _xml_tag(body, "artifactId")
        version = _xml_tag(body, "version")
        if not group or not artifact or not version:
            continue
        if "${" in version or any(mark in version for mark in "[],"):
            continue
        name = f"{group}:{artifact}"
        line_no, line = _line_containing(text, f"<artifactId>{artifact}</artifactId>")
        found.append(_row("Maven", name, version, relative, line_no, line, True))
    return found


def _toml_packages(
    relative: str,
    text: str,
    packages: object,
    ecosystem: str,
    direct: set[str] | None,
) -> list[ResolvedPackage]:
    if not isinstance(packages, list):
        return []
    found: list[ResolvedPackage] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str) or not version:
            continue
        line_no, line = _line_containing(text, f'name = "{name}"')
        known = name.lower() in direct if direct is not None else None
        found.append(_row(ecosystem, name, version, relative, line_no, line, known))
    return found


def _dependency_names(value: object) -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        names.update(name.lower() for name in value if isinstance(name, str))
    elif isinstance(value, list):
        for dep in value:
            if isinstance(dep, dict) and isinstance(dep.get("name"), str):
                names.add(dep["name"].lower())
            elif isinstance(dep, str):
                names.add(dep.split(" ", 1)[0].lower())
    return names


def _row(
    ecosystem: str,
    name: str,
    version: str,
    file: str,
    line: int,
    text: str,
    direct: bool | None,
) -> ResolvedPackage:
    return ResolvedPackage(ecosystem, name, version, file, max(line, 1), text, direct)


def _name_set(data: dict, sections: tuple[str, ...]) -> set[str]:
    names: set[str] = set()
    for section in sections:
        block = data.get(section)
        if isinstance(block, dict):
            names.update(name for name in block if isinstance(name, str))
    return names


def _manifest_names(repo: Path, relative: str, filename: str, sections: tuple[str, ...]) -> set[str] | None:
    text = _sibling(repo, relative, filename)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return _name_set(data, sections)


def _pyproject_names(repo: Path, relative: str) -> set[str] | None:
    text = _sibling(repo, relative, "pyproject.toml")
    if text is None:
        return None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    names: set[str] = set()
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    for item in project.get("dependencies") or []:
        if isinstance(item, str):
            names.add(item.split("[", 1)[0].split("=", 1)[0].split("<", 1)[0].split(">", 1)[0].strip().lower())
    poetry = ((data.get("tool") or {}).get("poetry") or {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        deps = poetry.get("dependencies")
        if isinstance(deps, dict):
            names.update(name.lower() for name in deps if isinstance(name, str) and name.lower() != "python")
        groups = poetry.get("group")
        if isinstance(groups, dict):
            for group in groups.values():
                if isinstance(group, dict) and isinstance(group.get("dependencies"), dict):
                    names.update(name.lower() for name in group["dependencies"] if isinstance(name, str))
    return names


def _pipfile_names(repo: Path, relative: str) -> set[str] | None:
    text = _sibling(repo, relative, "Pipfile")
    if text is None:
        return None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    names: set[str] = set()
    for section in ("packages", "dev-packages"):
        block = data.get(section)
        if isinstance(block, dict):
            names.update(name.lower() for name in block if isinstance(name, str))
    return names


def _composer_names(repo: Path, relative: str) -> set[str] | None:
    text = _sibling(repo, relative, "composer.json")
    if text is None:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return _name_set(data, ("require", "require-dev"))


def _gradle_declared(repo: Path, relative: str) -> set[str] | None:
    texts = [text for name in ("build.gradle", "build.gradle.kts") if (text := _sibling(repo, relative, name))]
    if not texts:
        return None
    declared: set[str] = set()
    for text in texts:
        for match in re.finditer(r"['\"]([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+)(?::[^'\"]+)?['\"]", text):
            declared.add(match.group(1))
    return declared


def _xml_tag(body: str, tag: str) -> str:
    match = re.search(rf"<{tag}>\s*([^<]+?)\s*</{tag}>", body)
    return match.group(1).strip() if match else ""


def _sibling(repo: Path, relative: str, name: str) -> str | None:
    directory = (repo.resolve() / relative).parent
    path = directory / name
    if not path.is_file() or is_reparse_point(path) or not is_within(repo.resolve(), path):
        return None
    try:
        if path.stat().st_size > _LOCK_CAP:
            return None
    except OSError:
        return None
    return _read(path)


def _line_containing(text: str, needle: str) -> tuple[int, str]:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number, line
    return 1, needle


def _read(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw[:8192]:
        return None
    return raw.decode("utf-8", errors="replace")
