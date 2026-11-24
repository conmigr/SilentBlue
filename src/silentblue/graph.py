"""In-memory symbol graph for Python files. It is not written to the repository."""

from __future__ import annotations

import ast
from pathlib import Path

from silentblue.models import ScopeResult
from silentblue.paths import is_reparse_point, is_within


class CodeGraph:
    """Definitions and direct calls extracted from Python syntax."""

    def __init__(self) -> None:
        self.files: dict[str, list[str]] = {}
        self.calls: dict[str, set[str]] = {}

    def summary(self, paths: list[str], limit: int = 30) -> str:
        """A short, read-only slice for the files in one work unit."""

        lines: list[str] = []
        for path in paths:
            for name in self.files.get(path, []):
                callees = sorted(self.calls.get(name, ()))
                if callees:
                    shown = ", ".join(callees[:8])
                    lines.append(f"{path}: {name} calls {shown}")
                else:
                    lines.append(f"{path}: {name} defined")
                if len(lines) >= limit:
                    return "\n".join(lines)
        return "\n".join(lines) if lines else "No symbol graph for these files."


def build_graph(repo: Path, scope: ScopeResult) -> CodeGraph:
    """Parse in-scope Python files. Syntax errors leave that file out of the graph."""

    graph = CodeGraph()
    root = repo.resolve()
    for item in scope.files:
        if not item.path.endswith(".py"):
            continue
        path = root / item.path
        if not is_within(root, path) or is_reparse_point(path):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError, ValueError):
            continue
        _Visitor(item.path, graph).visit(tree)
    return graph


class _Visitor(ast.NodeVisitor):
    def __init__(self, relative: str, graph: CodeGraph) -> None:
        self.relative = relative
        self.graph = graph
        self.stack: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._define(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._define(node)

    def _define(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.graph.files.setdefault(self.relative, []).append(node.name)
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if self.stack:
            callee = _callee_name(node.func)
            if callee:
                self.graph.calls.setdefault(self.stack[-1], set()).add(callee)
        self.generic_visit(node)


def _callee_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None
