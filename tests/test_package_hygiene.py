"""AC-13 and FR-4: the package names no host and imports no consumer, and ships its types."""

from __future__ import annotations

import ast
import re
from pathlib import Path

SOURCE = Path(__file__).resolve().parent.parent / "src" / "wolfworks_mcp_auth"
HOSTNAME = re.compile(r"https?://(?!example\.com)[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CONSUMERS = {"server", "cloud", "grepler", "lifelog_mcp", "envvault"}


def _string_literals(path: Path) -> list[str]:
    tree = ast.parse(path.read_text())
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def test_no_hostname_literal_in_package_source():
    offenders = {
        f"{path.name}: {literal}"
        for path in SOURCE.glob("*.py")
        for literal in _string_literals(path)
        if HOSTNAME.search(literal)
    }
    assert not offenders, offenders


def test_package_imports_no_consuming_application():
    imported = set()
    for path in SOURCE.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
    assert not (imported & CONSUMERS), imported & CONSUMERS


def test_package_ships_the_typing_marker():
    # Without it a consumer's type checker treats every annotation here as `Any`.
    assert (SOURCE / "py.typed").is_file()
