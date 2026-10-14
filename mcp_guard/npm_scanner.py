"""Discover and scan MCP servers distributed as npm packages.

MCP servers are commonly published to npm (``@modelcontextprotocol/server-*``,
``@mcp/*``, ``mcp-*``) and ship an ``mcp.json`` (or one of the other known
config names) next to their code. This module finds those manifests under an
installed ``node_modules`` tree and reports the MCP-related dependencies a
root ``package.json`` declares, so a security team can audit the MCP surface a
project pulls in.

Discovery is filesystem-only: nothing here runs ``npm``/``node``, executes a
discovered manifest, or makes a network call (mirroring the supply-chain
verifier's offline posture). A manifest that cannot be parsed is recorded and
skipped, not fatal.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .formatters import to_dict
from .formatters import to_rich as format_result
from .formatters import to_sarif as format_sarif
from .models import ScanResult
from .parser import MCPParser
from .policy import DenyPolicy
from .rules import ALL_RULES, SecurityRule
from .scanner import Scanner

# Names the root package.json lists that are worth surfacing to a reviewer.
_DEPENDENCY_BLOCKS = ("dependencies", "devDependencies", "optionalDependencies")


def _is_mcp_name(package_name: str) -> bool:
    """Whether an npm package name refers to an MCP server/SDK.

    Matches the common publishing conventions: unscoped ``mcp`` / ``mcp-*`` and
    the two scoped families ``@mcp/*`` and ``@modelcontextprotocol/*``. A bare
    scope (``@mcp`` with no sub-part) never matches.
    """
    name = package_name.lower()
    if name.startswith("@"):
        scope, sep, _ = name.partition("/")
        # A bare scope (no sub-part, e.g. "@mcp" on its own) is not a package.
        if not sep:
            return False
        return scope in ("@mcp", "@modelcontextprotocol")
    return name == "mcp" or name.startswith("mcp-")


def find_mcp_dependencies(package_json: Path) -> list[str]:
    """Return MCP-related dependency names declared in a ``package.json``.

    Reads ``dependencies``, ``devDependencies`` and ``optionalDependencies``.
    A missing file, a parse error, or a non-object document yields ``[]`` so a
    scan never aborts on one bad manifest.
    """
    try:
        data: Any = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    manifest = cast("dict[str, Any]", data)

    names: set[str] = set()
    for key in _DEPENDENCY_BLOCKS:
        raw_block = manifest.get(key)
        if not isinstance(raw_block, dict):
            continue
        block = cast("dict[str, Any]", raw_block)
        for raw_name in block:
            name = str(raw_name)
            if _is_mcp_name(name):
                names.add(name)
    return sorted(names)


def _package_of(config_path: Path, base: Path) -> str:
    """Best-effort npm package name that owns a discovered manifest.

    A config directly under ``<base>/node_modules/<pkg>/`` is attributed to
    ``<pkg>``; a scoped package ``node_modules/@scope/name/`` resolves to
    ``@scope/name``. Falls back to ``unknown`` when the manifest sits outside
    any ``node_modules`` segment.
    """
    try:
        rel = config_path.relative_to(base)
    except ValueError:
        return "unknown"
    parts = list(rel.parts)
    for i, part in enumerate(parts):
        if part != "node_modules" or i + 1 >= len(parts):
            continue
        head = parts[i + 1]
        if head.startswith("@"):
            tail = parts[i + 2] if len(parts) > i + 2 else None
            return f"{head}/{tail}" if tail is not None else head
        return head
    return "unknown"


def discover_mcp_configs(node_modules: Path) -> list[Path]:
    """Find MCP manifests under a ``node_modules`` tree.

    Returns every file whose name is in ``MCPParser.CONFIG_FILES``, sorted for
    determinism. A missing ``node_modules`` yields an empty list.
    """
    if not node_modules.is_dir():
        return []
    found = [
        path
        for path in node_modules.rglob("*")
        if path.is_file() and path.name in MCPParser.CONFIG_FILES
    ]
    return sorted(found)


class NPMScanner:
    """Discover and scan MCP servers installed as npm packages.

    Call :meth:`scan` to populate :attr:`dependencies`, :attr:`results` and
    :attr:`skipped`, then render with :meth:`to_rich`, :meth:`to_json` or
    :meth:`to_sarif`.
    """

    def __init__(
        self,
        base: Path,
        rules: list[SecurityRule] | None = None,
        deny_policy: DenyPolicy | None = None,
    ) -> None:
        self.base = base
        self._scanner = Scanner(rules=rules or list(ALL_RULES), deny_policy=deny_policy)
        self.dependencies: list[str] = []
        self.config_files: list[Path] = []
        self.results: list[ScanResult] = []
        self.skipped: list[tuple[Path, str]] = []

    def scan(self) -> NPMScanner:
        """Discover configs and dependencies under ``self.base`` and scan each.

        A manifest that cannot be parsed is recorded in :attr:`skipped` rather
        than aborting the batch. Returns ``self`` for chaining.
        """
        self.dependencies = find_mcp_dependencies(self.base / "package.json")
        self.config_files = discover_mcp_configs(self.base / "node_modules")

        for config_path in self.config_files:
            try:
                manifest = MCPParser.from_json(config_path)
                manifest.metadata["npm_package"] = _package_of(config_path, self.base)
                self.results.append(self._scanner.scan(manifest))
            except (ValueError, OSError) as exc:
                self.skipped.append((config_path, str(exc)))
        return self

    # -- Output helpers -----------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        """Aggregate report as a JSON string (deps + per-package scans + skips)."""
        payload: dict[str, Any] = {
            "npm_dependencies": self.dependencies,
            "scanned": [to_dict(r) for r in self.results],
            "skipped": [{"path": str(p), "error": err} for p, err in self.skipped],
        }
        return json.dumps(payload, indent=indent)

    def to_sarif(self) -> dict[str, Any]:
        """Combine each per-package scan into a multi-run SARIF document.

        An empty scan yields a valid document with no results.
        """
        runs: list[dict[str, Any]] = []
        for result in self.results:
            runs.extend(format_sarif(result)["runs"])
        schema = "https://json.schemastore.org/sarif-2.1.0.json"
        return {"$schema": schema, "version": "2.1.0", "runs": runs}

    def to_rich(self) -> None:
        """Print the report: a dependency table, each scan, then skipped items."""
        console = Console()

        dep_table = Table(title="MCP-related dependencies (package.json)")
        dep_table.add_column("package", style="cyan")
        if self.dependencies:
            for dep in self.dependencies:
                dep_table.add_row(escape(dep))
        else:
            dep_table.add_row("[dim]none declared[/dim]")
        console.print(dep_table)

        if not self.results and not self.skipped:
            console.print("[yellow]No MCP configs found under node_modules.[/yellow]")

        for result in self.results:
            format_result(result)

        if self.skipped:
            console.print("[yellow]Skipped unreadable manifests:[/yellow]")
            for path, error in self.skipped:
                console.print(f"  [yellow]{escape(str(path))}[/yellow]: {escape(error)}")
