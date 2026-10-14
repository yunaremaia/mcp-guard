"""Tests for npm-package MCP discovery (the ``--npm`` flag)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_guard.npm_scanner import (
    NPMScanner,
    _is_mcp_name,
    _package_of,
    discover_mcp_configs,
    find_mcp_dependencies,
)

#: A minimal manifest the parser accepts with one destructive, unauthenticated
#: tool (the repo's canonical CRITICAL case).
CRITICAL_CONFIG = {
    "name": "demo",
    "version": "1.0.0",
    "tools": [
        {
            "name": "delete_all",
            "description": "delete all files",
            "permissions": ["write"],
        }
    ],
}

BENIGN_CONFIG = {
    "name": "reader",
    "version": "0.1.0",
    "tools": [{"name": "read_file", "description": "read a file"}],
}


def _write_package(root: Path, deps: dict[str, str] | None = None) -> None:
    data: dict[str, object] = {"name": "root", "version": "1.0.0"}
    if deps is not None:
        data["dependencies"] = deps
    (root / "package.json").write_text(json.dumps(data), encoding="utf-8")


def _write_config(node_modules: Path, pkg: str, payload: object) -> Path:
    target_dir = node_modules / pkg
    target_dir.mkdir(parents=True, exist_ok=True)
    config_path = target_dir / "mcp.json"
    text = json.dumps(payload) if not isinstance(payload, str) else payload
    config_path.write_text(text, encoding="utf-8")
    return config_path


class TestIsMcpName:
    @pytest.mark.parametrize(
        "name",
        [
            "mcp",
            "mcp-server",
            "MCP",
            "MCP-Tools",
            "@mcp/tools",
            "@modelcontextprotocol/server-filesystem",
            "@MCP/SERVER",
        ],
    )
    def test_mcp_names_match(self, name: str) -> None:
        assert _is_mcp_name(name) is True

    @pytest.mark.parametrize(
        "name",
        [
            "left-pad",
            "react",
            "node-mcp",          # "mcp-" must be a prefix, not a substring
            "@mcp",                # bare scope never matches
            "@modelcontextprotocol",  # bare scope never matches
            "@github/mcp",          # wrong scope
            "@mcpextra/tools",      # prefix of a scope, not the scope itself
        ],
    )
    def test_non_mcp_names_do_not_match(self, name: str) -> None:
        assert _is_mcp_name(name) is False


class TestFindMcpDependencies:
    def test_collects_all_blocks_and_sorts(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"@mcp/tools": "1.0.0"},
                    "devDependencies": {"mcp-server": "2.0.0"},
                    "optionalDependencies": {"@modelcontextprotocol/server-filesystem": "0.1.0"},
                }
            ),
            encoding="utf-8",
        )
        assert find_mcp_dependencies(tmp_path / "package.json") == [
            "@mcp/tools",
            "@modelcontextprotocol/server-filesystem",
            "mcp-server",
        ]

    def test_missing_file_is_empty(self, tmp_path: Path) -> None:
        assert find_mcp_dependencies(tmp_path / "nope.json") == []

    def test_broken_manifest_is_empty(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
        assert find_mcp_dependencies(tmp_path / "package.json") == []

    def test_non_object_manifest_is_empty(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text("[1, 2, 3]", encoding="utf-8")
        assert find_mcp_dependencies(tmp_path / "package.json") == []

    def test_bare_scope_is_not_a_dependency(self, tmp_path: Path) -> None:
        _write_package(
            tmp_path,
            {"@mcp": "1.0.0", "@modelcontextprotocol": "1.0.0"},
        )
        assert find_mcp_dependencies(tmp_path / "package.json") == []

    def test_mixed_dependency_blocks_deduped(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"mcp-server": "1.0.0"},
                    "devDependencies": {"mcp-server": "1.0.0"},
                }
            ),
            encoding="utf-8",
        )
        assert find_mcp_dependencies(tmp_path / "package.json") == ["mcp-server"]

    def test_scoped_dependencies_sorted(self, tmp_path: Path) -> None:
        _write_package(
            tmp_path,
            {
                "zeta": "1.0.0",
                "@mcp/tools": "1.0.0",
                "@mcp/server": "1.0.0",
                "mcp-core": "1.0.0",
                "@modelcontextprotocol/server-filesystem": "1.0.0",
            },
        )
        assert find_mcp_dependencies(tmp_path / "package.json") == [
            "@mcp/server",
            "@mcp/tools",
            "@modelcontextprotocol/server-filesystem",
            "mcp-core",
        ]


class TestDiscoverMcpConfigs:
    def test_finds_known_config_names(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules"
        _write_config(nm, "pkg-a", BENIGN_CONFIG)
        scoped = nm / "@mcp" / "server"
        scoped.mkdir(parents=True)
        (scoped / "mcp.config.json").write_text(json.dumps(BENIGN_CONFIG), encoding="utf-8")
        found = discover_mcp_configs(nm)
        names = [p.name for p in found]
        assert "mcp.json" in names
        assert "mcp.config.json" in names
        assert len(found) == 2

    def test_missing_node_modules_is_empty(self, tmp_path: Path) -> None:
        assert discover_mcp_configs(tmp_path / "node_modules") == []

    def test_ignores_unrelated_files(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "readme.txt").write_text("hi", encoding="utf-8")
        (nm / "server.py").write_text("x", encoding="utf-8")
        assert discover_mcp_configs(nm) == []


class TestNPMScannerScan:
    def _root(self, tmp_path: Path) -> Path:
        _write_package(tmp_path, {"@mcp/tools": "1.0.0"})
        nm = tmp_path / "node_modules"
        _write_config(nm, "@mcp/tools", CRITICAL_CONFIG)
        _write_config(nm, "benign-pkg", BENIGN_CONFIG)
        return tmp_path

    def test_scans_each_config_and_reports_package(self, tmp_path: Path) -> None:
        scanner = NPMScanner(self._root(tmp_path)).scan()
        assert scanner.dependencies == ["@mcp/tools"]
        assert len(scanner.results) == 2
        attributed = {
            r.manifest.metadata.get("npm_package") for r in scanner.results
        }
        assert "@mcp/tools" in attributed
        assert "benign-pkg" in attributed
        assert scanner.skipped == []

    def test_critical_config_produces_critical_risk(self, tmp_path: Path) -> None:
        scanner = NPMScanner(self._root(tmp_path)).scan()
        by_pkg = {r.manifest.metadata.get("npm_package"): r for r in scanner.results}
        assert by_pkg["@mcp/tools"].risk_score.value == "CRITICAL"
        assert by_pkg["benign-pkg"].risk_score.value in ("LOW", "MEDIUM")

    def test_broken_manifest_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        self._root(tmp_path)
        broken = tmp_path / "node_modules" / "broken-pkg" / "mcp.json"
        broken.parent.mkdir(parents=True)
        broken.write_text("{oops", encoding="utf-8")
        scanner = NPMScanner(tmp_path).scan()
        assert any(p.name == "mcp.json" for p, _ in scanner.skipped)
        assert len(scanner.results) == 2  # the two good configs still scanned

    def test_empty_scan_has_no_results(self, tmp_path: Path) -> None:
        _write_package(tmp_path, {"left-pad": "1.0.0"})
        (tmp_path / "node_modules").mkdir()
        scanner = NPMScanner(tmp_path).scan()
        assert scanner.dependencies == []
        assert scanner.results == []
        assert scanner.skipped == []


class TestNPMScannerOutput:
    def test_json_aggregate_shape(self, tmp_path: Path) -> None:
        scanner = NPMScanner(self._make(tmp_path)).scan()
        payload = json.loads(scanner.to_json())
        assert payload["npm_dependencies"] == ["@mcp/tools"]
        assert len(payload["scanned"]) == 2
        assert payload["skipped"] == []

    def test_sarif_multi_run(self, tmp_path: Path) -> None:
        scanner = NPMScanner(self._make(tmp_path)).scan()
        sarif = scanner.to_sarif()
        assert sarif["version"] == "2.1.0"
        # one run per scanned manifest
        assert len(sarif["runs"]) == 2

    def test_sarif_empty_scan_is_valid_document(self, tmp_path: Path) -> None:
        _write_package(tmp_path)
        (tmp_path / "node_modules").mkdir()
        sarif = NPMScanner(tmp_path).scan().to_sarif()
        assert sarif["runs"] == []
        assert sarif["version"] == "2.1.0"

    @staticmethod
    def _make(tmp_path: Path) -> Path:
        _write_package(tmp_path, {"@mcp/tools": "1.0.0"})
        nm = tmp_path / "node_modules"
        _write_config(nm, "@mcp/tools", CRITICAL_CONFIG)
        _write_config(nm, "benign-pkg", BENIGN_CONFIG)
        return tmp_path

    def test_rich_reports_dependencies_results_and_skips(self, tmp_path: Path) -> None:
        """Exercises to_rich's dep table, per-result print, and skip list."""
        base = self._make(tmp_path)
        # A broken config so the "skipped" branch of to_rich is covered too.
        broken = base / "node_modules" / "bad-pkg" / "mcp.json"
        broken.parent.mkdir(parents=True)
        broken.write_text("{nope", encoding="utf-8")
        scanner = NPMScanner(base).scan()
        # to_rich renders to stdout without raising; assert it is callable.
        scanner.to_rich()
        assert scanner.dependencies == ["@mcp/tools"]
        assert len(scanner.results) == 2
        assert any("bad-pkg" in str(p) for p, _ in scanner.skipped)

    def test_rich_empty_scan_notes_no_configs(self, tmp_path: Path) -> None:
        _write_package(tmp_path)
        (tmp_path / "node_modules").mkdir()
        NPMScanner(tmp_path).scan().to_rich()


class TestPackageOf:
    """Best-effort attribution of a manifest to its owning npm package."""

    def test_unscoped_package(self, tmp_path: Path) -> None:
        base = tmp_path
        config = base / "node_modules" / "mytool" / "mcp.json"
        config.parent.mkdir(parents=True)
        assert _package_of(config, base) == "mytool"

    def test_scoped_package(self, tmp_path: Path) -> None:
        base = tmp_path
        config = base / "node_modules" / "@mcp" / "server" / "mcp.json"
        config.parent.mkdir(parents=True)
        assert _package_of(config, base) == "@mcp/server"

    def test_outside_node_modules_is_unknown(self, tmp_path: Path) -> None:
        base = tmp_path
        config = base / "mcp.json"
        assert _package_of(config, base) == "unknown"

    def test_not_relative_to_base_is_unknown(self, tmp_path: Path) -> None:
        # A path that is not under base falls into the ValueError branch.
        config = tmp_path / "elsewhere" / "mcp.json"
        config.parent.mkdir(parents=True)
        assert _package_of(config, tmp_path / "unrelated") == "unknown"
