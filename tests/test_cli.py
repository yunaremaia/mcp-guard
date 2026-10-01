"""Behavioural tests for the MCP Guard CLI entrypoints."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_guard import __version__
from mcp_guard.cli import main


def write_manifest(directory: Path, data: dict) -> Path:
    """Write a manifest as mcp.json inside directory and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    manifest_file = directory / "mcp.json"
    manifest_file.write_text(json.dumps(data), encoding="utf-8")
    return manifest_file


CLEAN_MANIFEST = {
    "name": "clean-server",
    "version": "1.0.0",
    "description": "A perfectly safe server",
    "tools": [{"name": "get_status", "description": "Safe status check"}],
}

RISKY_MANIFEST = {
    "name": "risky-server",
    "version": "2.1.0",
    "description": "A dangerous server",
    "tools": [{"name": "delete_all", "description": "Delete all resources"}],
}


class TestScanErrorHandling:
    """Scan must fail cleanly instead of raising a traceback."""

    def test_scan_directory_without_config_exits_one(self, tmp_path: Path):
        """A directory with no MCP config should exit 1 with a readable message."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        result = CliRunner().invoke(main, ["scan", str(empty_dir)])

        assert result.exit_code == 1
        assert "Error" in result.output
        assert result.exception is None or isinstance(result.exception, SystemExit)

    def test_scan_malformed_json_exits_one(self, tmp_path: Path):
        """Malformed JSON should be reported, not raised (regression test)."""
        bad = tmp_path / "mcp.json"
        bad.write_text("{invalid json}", encoding="utf-8")

        result = CliRunner().invoke(main, ["scan", str(bad)])

        assert result.exit_code == 1
        assert "Error" in result.output
        assert not isinstance(result.exception, ValueError)

    def test_scan_non_object_json_exits_one(self, tmp_path: Path):
        """A JSON array is not a valid manifest and must not crash."""
        bad = tmp_path / "mcp.json"
        bad.write_text("[1, 2, 3]", encoding="utf-8")

        result = CliRunner().invoke(main, ["scan", str(bad)])

        assert result.exit_code == 1
        assert "Error" in result.output

    def test_scan_broken_config_file_exits_one(self, tmp_path: Path):
        """An unparseable --config should exit 1 rather than be ignored."""
        manifest = write_manifest(tmp_path / "srv", CLEAN_MANIFEST)
        config = tmp_path / "broken.yaml"
        config.write_text("deny: [unclosed", encoding="utf-8")

        result = CliRunner().invoke(
            main, ["scan", str(manifest), "--config", str(config)]
        )

        assert result.exit_code == 1
        assert "Error loading config file" in result.output


class TestScanConfigAutoDiscovery:
    """Deny policy auto-discovery from mcp-guard.yaml next to the manifest."""

    def test_autodiscovers_config_in_target_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A mcp-guard.yaml beside the manifest is picked up automatically."""
        target = tmp_path / "srv"
        manifest = write_manifest(target, RISKY_MANIFEST)
        (target / "mcp-guard.yaml").write_text(
            "deny:\n  tools:\n    - \"delete_*\"\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        result = CliRunner().invoke(main, ["scan", str(manifest), "--format", "json"])

        assert result.exit_code == 0
        findings = json.loads(result.output)["findings"]
        assert "DENY002" in [f["rule_id"] for f in findings]

    def test_autodiscovered_yml_extension_is_supported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """The .yml spelling is discovered as well as .yaml."""
        target = tmp_path / "srv"
        manifest = write_manifest(target, RISKY_MANIFEST)
        (target / "mcp-guard.yml").write_text(
            "deny:\n  servers:\n    - \"risky-*\"\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        result = CliRunner().invoke(main, ["scan", str(manifest), "--format", "json"])

        assert result.exit_code == 0
        findings = json.loads(result.output)["findings"]
        assert "DENY001" in [f["rule_id"] for f in findings]

    def test_broken_autodiscovered_config_is_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A malformed auto-discovered config must not break the scan."""
        target = tmp_path / "srv"
        manifest = write_manifest(target, CLEAN_MANIFEST)
        (target / "mcp-guard.yaml").write_text("deny: [unclosed", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        result = CliRunner().invoke(main, ["scan", str(manifest), "--format", "json"])

        assert result.exit_code == 0
        assert json.loads(result.output)["findings"] == []

    def test_explicit_config_overrides_autodiscovery(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """--config takes precedence over a discovered mcp-guard.yaml."""
        target = tmp_path / "srv"
        manifest = write_manifest(target, RISKY_MANIFEST)
        (target / "mcp-guard.yaml").write_text(
            "deny:\n  tools:\n    - \"delete_*\"\n",
            encoding="utf-8",
        )
        explicit = tmp_path / "policy.yaml"
        explicit.write_text(
            "deny:\n  tools:\n    - \"nothing_matches_this\"\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        result = CliRunner().invoke(
            main,
            ["scan", str(manifest), "--config", str(explicit), "--format", "json"],
        )

        assert result.exit_code == 0
        assert "DENY002" not in [f["rule_id"] for f in json.loads(result.output)["findings"]]


class TestScanOutputFormats:
    """Output format handling for scan."""

    def test_default_format_prints_human_readable(self, tmp_path: Path):
        """The default cli format renders a report and emits no JSON."""
        manifest = write_manifest(tmp_path / "srv", CLEAN_MANIFEST)

        result = CliRunner().invoke(main, ["scan", str(manifest)])

        assert result.exit_code == 0
        assert "clean-server" in result.output

    def test_json_format_is_parseable(self, tmp_path: Path):
        """--format json emits a valid JSON document on stdout."""
        manifest = write_manifest(tmp_path / "srv", RISKY_MANIFEST)

        result = CliRunner().invoke(main, ["scan", str(manifest), "-f", "json"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["server"]["name"] == "risky-server"
        assert payload["risk_score"] == "CRITICAL"

    def test_sarif_format_is_valid_sarif(self, tmp_path: Path):
        """--format sarif emits a SARIF 2.1.0 document."""
        manifest = write_manifest(tmp_path / "srv", RISKY_MANIFEST)

        result = CliRunner().invoke(main, ["scan", str(manifest), "-f", "sarif"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["version"] == "2.1.0"
        assert payload["runs"][0]["tool"]["driver"]["name"] == "mcp-guard"
        assert payload["runs"][0]["results"]

    def test_output_file_is_written(self, tmp_path: Path):
        """--output writes the report to disk and reports the path."""
        manifest = write_manifest(tmp_path / "srv", RISKY_MANIFEST)
        out_file = tmp_path / "report.json"

        result = CliRunner().invoke(
            main, ["scan", str(manifest), "-f", "json", "-o", str(out_file)]
        )

        assert result.exit_code == 0
        assert "Output written to" in result.output
        payload = json.loads(out_file.read_text(encoding="utf-8"))
        assert payload["server"]["name"] == "risky-server"

    def test_invalid_format_is_rejected(self, tmp_path: Path):
        """An unknown --format value is rejected by Click."""
        manifest = write_manifest(tmp_path / "srv", CLEAN_MANIFEST)

        result = CliRunner().invoke(main, ["scan", str(manifest), "-f", "xml"])

        assert result.exit_code != 0


class TestScanFailOn:
    """--fail-on severity threshold gating."""

    def test_critical_threshold_triggers_on_critical_finding(self, tmp_path: Path):
        """A critical finding satisfies --fail-on critical."""
        manifest = write_manifest(tmp_path / "srv", RISKY_MANIFEST)

        result = CliRunner().invoke(
            main, ["scan", str(manifest), "--fail-on", "critical"]
        )

        assert result.exit_code == 1

    def test_lower_threshold_triggers_on_critical_finding(self, tmp_path: Path):
        """A critical finding also satisfies every lower threshold."""
        manifest = write_manifest(tmp_path / "srv", RISKY_MANIFEST)

        result = CliRunner().invoke(main, ["scan", str(manifest), "--fail-on", "low"])

        assert result.exit_code == 1

    def test_critical_threshold_passes_on_clean_manifest(self, tmp_path: Path):
        """A clean manifest does not satisfy --fail-on critical."""
        manifest = write_manifest(tmp_path / "srv", CLEAN_MANIFEST)

        result = CliRunner().invoke(
            main, ["scan", str(manifest), "--fail-on", "critical"]
        )

        assert result.exit_code == 0

    def test_high_threshold_ignores_low_only_findings(self, tmp_path: Path):
        """Low-severity findings do not satisfy --fail-on high."""
        manifest = write_manifest(
            tmp_path / "srv",
            {
                "name": "low-server",
                "tools": [{"name": "ping", "description": "hi"}],
            },
        )

        result = CliRunner().invoke(
            main, ["scan", str(manifest), "--fail-on", "high"]
        )

        assert result.exit_code == 0

    def test_no_threshold_always_exits_zero(self, tmp_path: Path):
        """Without --fail-on the scan never changes the exit code."""
        manifest = write_manifest(tmp_path / "srv", RISKY_MANIFEST)

        result = CliRunner().invoke(main, ["scan", str(manifest)])

        assert result.exit_code == 0


class TestInfoCommand:
    """The info subcommand reports manifest metadata without scanning."""

    def test_info_prints_server_metadata(self, tmp_path: Path):
        """info shows name, version, description and capability count."""
        manifest = write_manifest(tmp_path / "srv", CLEAN_MANIFEST)

        result = CliRunner().invoke(main, ["info", str(manifest)])

        assert result.exit_code == 0
        assert "clean-server" in result.output
        assert "1.0.0" in result.output
        assert "A perfectly safe server" in result.output

    def test_info_lists_capabilities_with_types(self, tmp_path: Path):
        """info enumerates each capability and its type."""
        manifest = write_manifest(tmp_path / "srv", CLEAN_MANIFEST)

        result = CliRunner().invoke(main, ["info", str(manifest)])

        assert result.exit_code == 0
        assert "get_status" in result.output
        assert "[tool]" in result.output

    def test_info_renders_auth_and_risk_markers(self, tmp_path: Path):
        """info marks auth state, write and destructive capabilities."""
        manifest = write_manifest(
            tmp_path / "srv",
            {
                "name": "mixed-server",
                "version": "1.2.3",
                "tools": [
                    {
                        "name": "delete_thing",
                        "description": "Delete a thing",
                        "auth": False,
                    },
                    {
                        "name": "create_thing",
                        "description": "Create a thing",
                        "auth": True,
                    },
                    {"name": "list_things", "description": "List all things"},
                ],
            },
        )

        result = CliRunner().invoke(main, ["info", str(manifest)])

        assert result.exit_code == 0
        assert "delete_thing" in result.output
        assert "create_thing" in result.output
        assert "list_things" in result.output

    def test_info_accepts_a_directory(self, tmp_path: Path):
        """info resolves the manifest when given a directory."""
        target = tmp_path / "srv"
        write_manifest(target, CLEAN_MANIFEST)

        result = CliRunner().invoke(main, ["info", str(target)])

        assert result.exit_code == 0
        assert "clean-server" in result.output

    def test_info_missing_config_exits_one(self, tmp_path: Path):
        """info exits 1 when no MCP config can be found."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        result = CliRunner().invoke(main, ["info", str(empty_dir)])

        assert result.exit_code == 1
        assert "Error" in result.output

    def test_info_malformed_json_exits_one(self, tmp_path: Path):
        """info reports malformed JSON rather than raising (regression test)."""
        bad = tmp_path / "mcp.json"
        bad.write_text("{invalid json}", encoding="utf-8")

        result = CliRunner().invoke(main, ["info", str(bad)])

        assert result.exit_code == 1
        assert "Error" in result.output
        assert not isinstance(result.exception, ValueError)


class TestTopLevelGroup:
    """The root group exposes a version and the registered subcommands."""

    def test_version_flag(self):
        """--version reports the package version."""
        result = CliRunner().invoke(main, ["--version"])

        assert result.exit_code == 0
        assert __version__ in result.output

    def test_help_lists_scan_and_info(self):
        """--help advertises both subcommands."""
        result = CliRunner().invoke(main, ["--help"])

        assert result.exit_code == 0
        assert "scan" in result.output
        assert "info" in result.output

    @pytest.mark.parametrize("command", ["scan", "info"])
    def test_missing_path_argument_is_rejected(self, command: str):
        """Both subcommands require a PATH argument."""
        result = CliRunner().invoke(main, [command])

        assert result.exit_code != 0
