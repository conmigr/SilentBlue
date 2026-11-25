"""Repair text a developer can apply.

The block names the file and the control. It does not include a proof of concept.
Package rows name the lockfile command and the version to confirm.
"""

from __future__ import annotations

import re

APPLY_MARK = "Do not add a proof-of-concept"

_SPLIT = re.compile(r"[.+_-]")


def apply_note(file: str, line: int, remediation: str, *, origin: str) -> str:
    """Prefix a source or deployment repair so the evidence line can be changed."""

    body = remediation.strip()
    if APPLY_MARK in body:
        return body
    if origin == "deployment" or file in {"url", ""}:
        lead = (
            "Apply this on the deployed service. Change the control below. "
            f"{APPLY_MARK}, a payload, or a request that demonstrates the flaw."
        )
    else:
        lead = (
            f"Apply this in {file} at line {line}. "
            "The evidence is the code to change. Write the replacement in that file, in its language, "
            "so the control below holds. Keep tests and leave every other control on. "
            f"{APPLY_MARK}, a payload, or a request that demonstrates the flaw."
        )
    return f"{lead}\n\n{body}" if body else lead


def choose_fixed(installed: str, fixes: list[str]) -> tuple[str, str]:
    """Pick a fixed version that is newer than the installed one.

    The reason is empty when the versions ordered cleanly, ``unordered`` when
    they did not, ``not-newer`` when every named fix is at or below the
    installed version, and ``none`` when the advisory names no fix.
    """

    cleaned: list[str] = []
    for item in fixes:
        text = item.strip()
        if text and text not in cleaned:
            cleaned.append(text)
    if not cleaned:
        return "", "none"
    current = _version_key(installed)
    keys = [_version_key(item) for item in cleaned]
    if current is not None and all(key is not None for key in keys):
        newer = [item for item, key in zip(cleaned, keys, strict=True) if key > current]
        if not newer:
            return "", "not-newer"
        return min(newer, key=_version_key), ""
    for item in cleaned:
        if item != installed:
            return item, "unordered"
    return "", "none"


def upgrade_remediation(
    *,
    ecosystem: str,
    name: str,
    version: str,
    file: str,
    line: int,
    advisory_id: str,
    fixed: str,
    reason: str,
    fixes: list[str],
    direct: bool | None,
) -> str:
    """Safe upgrade steps for one advisory. The command matches the lockfile."""

    lead = (
        f"Apply this upgrade for {ecosystem} {name} {version} named by {advisory_id}. "
        f"The resolved file is {file}:{line}. "
        f"{APPLY_MARK}, a payload, or a request that demonstrates the flaw."
    )
    relation = _relation(name, direct)
    if reason == "not-newer":
        named = ", ".join(fixes)
        return (
            f"{lead}\n\n"
            f"{advisory_id} names these fixed versions for {name}: {named}. "
            f"None of them compares as newer than {version}, so do not pin a lower version as the repair. "
            f"Remove {name} or move to a release {advisory_id} does not list as affected, then refresh {file}. "
            f"{relation} {_SAFETY}"
        )
    if not fixed:
        return (
            f"{lead}\n\n"
            f"{advisory_id} does not name a fixed version for {ecosystem} {name} {version}. "
            f"Do not guess a version. Do not keep {version}. "
            f"Remove {name} or move to a release {advisory_id} does not list as affected, then refresh {file}. "
            f"Confirm the resolved version is outside the affected range. "
            f"{relation} {_SAFETY}"
        )
    caution = ""
    if reason == "unordered":
        caution = (
            f" The version strings could not be ordered against {version}, "
            f"so confirm {fixed} is outside the affected range before shipping."
        )
    command = _refresh(file, ecosystem, name, fixed)
    return (
        f"{lead}\n\n"
        f"Move {ecosystem} {name} from {version} to {fixed}.{caution} "
        f"{relation} {command} "
        f"After the lockfile changes, the resolved version must be {fixed}, not {version}. "
        f"{_SAFETY}"
    )


_SAFETY = (
    "Leave certificate verification on. "
    "Do not use cleartext HTTP, a trusted-host flag, a checksum bypass, or a script piped into a shell."
)


def _relation(name: str, direct: bool | None) -> str:
    if direct is True:
        return f"{name} is a direct dependency."
    if direct is False:
        return (
            f"{name} is transitive. Upgrade the direct dependency that requires it so the lockfile "
            f"resolves the fixed version. If that dependency cannot move yet, add an override in the same tool. "
            f"Do not vendor a second copy of {name}."
        )
    return "The lockfile does not say whether this package is direct."


def _refresh(file: str, ecosystem: str, name: str, fixed: str) -> str:
    base = file.replace("\\", "/").rsplit("/", 1)[-1].lower()
    where = _where(file)
    if base.startswith("requirements") or base == "constraints.txt":
        return (
            f"Set {name}=={fixed} on the evidence line in {file}. "
            f"{where}, run python -m pip install -r {base}. "
            f"Confirm that file pins {fixed}."
        )
    if base == "uv.lock":
        return (
            f"Set the manifest pin for {name} to {fixed}. "
            f"{where}, run uv lock. Do not pass --allow-insecure-host. "
            f"Confirm {file} resolves {name} {fixed}."
        )
    if base == "poetry.lock":
        return (
            f"Set {name} to {fixed} in pyproject.toml. "
            f"{where}, run poetry update {name}. Confirm {file} resolves {fixed}."
        )
    if base == "pipfile.lock":
        return (
            f'Set {name} = "=={fixed}" in the Pipfile. '
            f"{where}, run pipenv lock. Confirm {file} resolves {fixed}."
        )
    if base in {"package-lock.json", "npm-shrinkwrap.json"}:
        return (
            f"{where}, run npm install {name}@{fixed} --save-exact. "
            f"Leave strict-ssl on. Confirm {file} resolves {fixed}."
        )
    if base == "yarn.lock":
        return (
            f"Use the Yarn that wrote {file}: {where}, run yarn up {name}@{fixed}, "
            f"or yarn upgrade {name}@{fixed} --exact on Yarn 1. Confirm {file} resolves {fixed}."
        )
    if base == "pnpm-lock.yaml":
        return (
            f"{where}, run pnpm add {name}@{fixed} --save-exact. Confirm {file} resolves {fixed}."
        )
    if base in {"go.mod", "go.sum"}:
        module = _go_version(fixed)
        return (
            f"{where}, run go get {name}@{module}, then go mod tidy. "
            f"Confirm go.mod lists {module}. Do not add a replace line to an unpinned fork, "
            f"and do not disable the checksum database."
        )
    if base == "cargo.lock":
        return (
            f"{where}, run cargo update -p {name} --precise {fixed}. Confirm {file} resolves {fixed}."
        )
    if base == "gemfile.lock":
        return (
            f"{where}, set the gem to {fixed} and run bundle update {name}. "
            f"Confirm {file} resolves {fixed}."
        )
    if base == "composer.lock":
        return (
            f"{where}, run composer require {name}:{fixed}. Leave secure-http true. "
            f"Confirm {file} resolves {fixed}."
        )
    if base == "pom.xml":
        return (
            f"Set the version of {name} to {fixed} in {file}. "
            f"Do not add a repository that uses cleartext HTTP. Confirm the resolved version is {fixed}."
        )
    if base == "gradle.lockfile":
        return (
            f"Set {name} to {fixed} in the Gradle dependency this lockfile pins, then regenerate {file}. "
            f"Do not add a repository that uses cleartext HTTP. Confirm the locked version is {fixed}."
        )
    if base == "packages.lock.json":
        return (
            f"{where}, run dotnet add package {name} --version {fixed}. Confirm {file} resolves {fixed}."
        )
    if base == "conan.lock":
        return (
            f"Set {name}/{fixed} in the conanfile that {file} locks and regenerate the lock over HTTPS. "
            f"Confirm {file} resolves {fixed}."
        )
    return (
        f"Set {ecosystem} {name} to {fixed} in {file} and refresh that lockfile with its own tool over HTTPS. "
        f"Confirm the resolved version is {fixed}."
    )


def _where(file: str) -> str:
    parent = file.replace("\\", "/")
    if "/" not in parent:
        return "In the repository root"
    return f"In {parent.rsplit('/', 1)[0]}"


def _go_version(fixed: str) -> str:
    text = fixed.strip()
    if text[:1] in {"v", "V"}:
        return text
    if text[:1].isdigit():
        return f"v{text}"
    return text


def _version_key(value: str) -> tuple[int, ...] | None:
    text = value.strip()
    if len(text) > 1 and text[0] in {"v", "V"} and text[1].isdigit():
        text = text[1:]
    parts: list[int] = []
    for piece in _SPLIT.split(text):
        if not piece:
            continue
        if not piece.isdigit():
            return None
        parts.append(int(piece))
    if not parts:
        return None
    return tuple(parts)
