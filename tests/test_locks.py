"""OSV queries use resolved lockfile versions for every supported ecosystem."""

from __future__ import annotations

import json

from silentblue.models import ScopeResult
from silentblue.supply import _advisory_packages


def _packages(repo, files: dict[str, str]) -> list[tuple[str, str, str, str, bool | None]]:
    for name, text in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    rows = _advisory_packages(repo, ScopeResult(files=[]))
    return [(item.ecosystem, item.name, item.version, item.file, item.direct) for item in rows]


def test_npm_lock_replaces_ranges_and_collapses_duplicates(tmp_path):
    package = json.dumps({"dependencies": {"react": "^18.3.1", "left-pad": "1.2.3"}})
    lock = json.dumps(
        {
            "packages": {
                "": {"dependencies": {"react": "^18.3.1"}},
                "node_modules/react": {"version": "18.3.1"},
                "node_modules/nth-check": {"version": "1.0.2"},
                "node_modules/svgo/node_modules/nth-check": {"version": "1.0.2"},
            }
        }
    )
    rows = _packages(
        tmp_path,
        {"package.json": package, "package-lock.json": lock},
    )
    assert ("npm", "react", "18.3.1", "package-lock.json", True) in rows
    assert ("npm", "nth-check", "1.0.2", "package-lock.json", False) in rows
    assert [item for item in rows if item[1] == "nth-check"] == [
        ("npm", "nth-check", "1.0.2", "package-lock.json", False)
    ]
    assert not any(item[1] == "left-pad" for item in rows)


def test_yarn_pnpm_and_python_locks(tmp_path):
    yarn = '"react@npm:^18.3.1":\n  version: 18.3.1\n\nleft-pad@^1.0.0:\n  version "1.3.0"\n'
    package = json.dumps({"dependencies": {"react": "^18.3.1"}})
    rows = _packages(tmp_path / "yarn", {"package.json": package, "yarn.lock": yarn})
    assert ("npm", "react", "18.3.1", "yarn.lock", True) in rows
    assert ("npm", "left-pad", "1.3.0", "yarn.lock", False) in rows

    pnpm = """
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.3.1
        version: 18.3.1
packages:
  react@18.3.1:
    resolution: {integrity: sha}
  nth-check@1.0.2:
    resolution: {integrity: sha}
"""
    rows = _packages(tmp_path / "pnpm", {"pnpm-lock.yaml": pnpm})
    assert ("npm", "react", "18.3.1", "pnpm-lock.yaml", True) in rows
    assert ("npm", "nth-check", "1.0.2", "pnpm-lock.yaml", False) in rows

    poetry = '[[package]]\nname = "requests"\nversion = "2.32.3"\n\n[[package]]\nname = "certifi"\nversion = "2024.8.30"\n'
    project = "[project]\ndependencies = [\"requests>=2\"]\n"
    rows = _packages(tmp_path / "poetry", {"pyproject.toml": project, "poetry.lock": poetry})
    assert ("PyPI", "requests", "2.32.3", "poetry.lock", True) in rows
    assert ("PyPI", "certifi", "2024.8.30", "poetry.lock", False) in rows

    pipfile = json.dumps({"default": {"requests": {"version": "==2.32.3"}, "certifi": {"version": "==2024.8.30"}}})
    declared = "[packages]\nrequests = \">=2\"\n"
    rows = _packages(tmp_path / "pipenv", {"Pipfile": declared, "Pipfile.lock": pipfile})
    assert ("PyPI", "requests", "2.32.3", "Pipfile.lock", True) in rows
    assert ("PyPI", "certifi", "2024.8.30", "Pipfile.lock", False) in rows

    uv = """
[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }

[package.dependencies]
requests = [{ name = "requests" }]

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
"""
    rows = _packages(tmp_path / "uv", {"uv.lock": uv})
    assert ("PyPI", "requests", "2.32.3", "uv.lock", True) in rows
    assert not any(item[1] == "app" for item in rows)


def test_go_rust_ruby_php_java_nuget_and_conan(tmp_path):
    gomod = "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/sys v0.1.0 // indirect\n)\n"
    gosum = "github.com/gin-gonic/gin v1.9.1 h1:abc\ngolang.org/x/sys v0.1.0/go.mod h1:def\n"
    rows = _packages(tmp_path / "go", {"go.mod": gomod, "go.sum": gosum})
    assert ("Go", "github.com/gin-gonic/gin", "v1.9.1", "go.mod", True) in rows
    assert ("Go", "golang.org/x/sys", "v0.1.0", "go.mod", False) in rows

    cargo = """
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["serde_derive"]

[[package]]
name = "serde_derive"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
    rows = _packages(tmp_path / "rust", {"Cargo.lock": cargo})
    assert ("crates.io", "serde", "1.0.210", "Cargo.lock", True) in rows
    assert ("crates.io", "serde_derive", "1.0.210", "Cargo.lock", False) in rows

    gem = """
GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.9)
    rails (7.1.3)
      rack (= 2.2.9)

DEPENDENCIES
  rails
"""
    rows = _packages(tmp_path / "ruby", {"Gemfile.lock": gem})
    assert ("RubyGems", "rails", "7.1.3", "Gemfile.lock", True) in rows
    assert ("RubyGems", "rack", "2.2.9", "Gemfile.lock", False) in rows

    composer = json.dumps(
        {
            "packages": [{"name": "symfony/http-kernel", "version": "v6.4.8"}],
            "packages-dev": [{"name": "phpunit/phpunit", "version": "v10.5.0"}],
        }
    )
    declared = json.dumps({"require": {"symfony/http-kernel": "^6.4"}})
    rows = _packages(tmp_path / "php", {"composer.json": declared, "composer.lock": composer})
    assert ("Packagist", "symfony/http-kernel", "6.4.8", "composer.lock", True) in rows
    assert ("Packagist", "phpunit/phpunit", "10.5.0", "composer.lock", False) in rows

    gradle = "org.apache.commons:commons-lang3:3.12.0=compileClasspath\njunit:junit:4.13.2=testCompileClasspath\n"
    build = "dependencies {\n    implementation 'org.apache.commons:commons-lang3:3.12.0'\n}\n"
    pom = """
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>${text.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>widget</artifactId>
      <version>1.2.3</version>
    </dependency>
  </dependencies>
</project>
"""
    rows = _packages(tmp_path / "gradle", {"build.gradle": build, "gradle.lockfile": gradle, "pom.xml": pom})
    assert ("Maven", "org.apache.commons:commons-lang3", "3.12.0", "gradle.lockfile", True) in rows
    assert ("Maven", "junit:junit", "4.13.2", "gradle.lockfile", False) in rows
    assert not any(item[1] == "com.example:widget" for item in rows)

    rows = _packages(tmp_path / "maven", {"pom.xml": pom})
    assert ("Maven", "com.example:widget", "1.2.3", "pom.xml", True) in rows
    assert not any("commons-text" in item[1] for item in rows)

    nuget = json.dumps(
        {
            "dependencies": {
                "net8.0": {
                    "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"},
                    "System.Text.Json": {"type": "Transitive", "resolved": "8.0.4"},
                }
            }
        }
    )
    rows = _packages(tmp_path / "dotnet", {"packages.lock.json": nuget})
    assert ("NuGet", "Newtonsoft.Json", "13.0.3", "packages.lock.json", True) in rows
    assert ("NuGet", "System.Text.Json", "8.0.4", "packages.lock.json", False) in rows

    conan = json.dumps(
        {
            "requires": ["zlib/1.2.13#rev"],
            "graph_lock": {
                "nodes": {
                    "0": {"ref": "conanfile.py"},
                    "1": {"ref": "zlib/1.2.13#rev"},
                    "2": {"ref": "openssl/3.0.12#rev"},
                }
            },
        }
    )
    rows = _packages(tmp_path / "cpp", {"conan.lock": conan})
    assert ("ConanCenter", "zlib", "1.2.13", "conan.lock", True) in rows
    assert ("ConanCenter", "openssl", "3.0.12", "conan.lock", False) in rows


def test_exact_manifest_pin_remains_when_no_lockfile_exists(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    from silentblue.models import ScopedFile

    scope = ScopeResult(
        files=[ScopedFile(path="requirements.txt", size=20, language="text")]
    )
    rows = _advisory_packages(tmp_path, scope)
    assert [(item.ecosystem, item.name, item.version, item.direct) for item in rows] == [
        ("PyPI", "requests", "2.32.3", True)
    ]
