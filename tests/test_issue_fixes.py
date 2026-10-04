"""Regression tests for #85 (string permissions), #83 (fail-open policy), #91 (description gate)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_guard.cli import main
from mcp_guard.models import MCPCapability
from mcp_guard.parser import MCPParser
from mcp_guard.rules import ExcessivePermissionsRule
from mcp_guard.scanner import Scanner


def parse_tool(**tool: object) -> MCPCapability:
    manifest = MCPParser.from_dict({"name": "srv", "tools": [tool]})
    return manifest.capabilities[0]


class TestStringPermissionsAreOneValue:
    """#85: a scalar `permissions`/`auth.scopes` is a value, not a list of chars."""

    def test_string_permissions_is_not_exploded(self):
        cap = parse_tool(
            name="do_thing", description="Perform an action", permissions="admin:write"
        )
        assert cap.permissions == ["admin:write"]

    def test_space_separated_scopes_split(self):
        """A scalar holding several scopes counts as several permissions."""
        cap = parse_tool(
            name="do_thing",
            description="Perform an action",
            auth={"type": "oauth2", "scopes": "repo:read repo:write"},
        )
        assert cap.permissions == ["repo:read", "repo:write"]

    def test_list_permissions_still_work(self):
        cap = parse_tool(
            name="do_thing", description="Perform an action", permissions=["fs:read", "net:none"]
        )
        assert cap.permissions == ["fs:read", "net:none"]

    def test_non_list_permissions_raise_a_clear_error(self):
        """A raw TypeError from `extend()` is not a diagnostic."""
        with pytest.raises(ValueError, match="permissions"):
            parse_tool(name="do_thing", description="Perform an action", permissions=5)

    def test_string_permissions_do_not_trigger_mcp003(self):
        """The issue's end-to-end repro: 11 chars, one permission, no finding."""
        manifest = MCPParser.from_dict(
            {
                "name": "perm-server",
                "version": "1.0.0",
                "tools": [
                    {
                        "name": "do_thing",
                        "description": "Perform a maintenance action",
                        "permissions": "admin:write",
                    }
                ],
            }
        )
        assert not [
            f for f in Scanner().scan(manifest).findings if f.rule_id == "MCP003"
        ]

    def test_non_list_permissions_exit_one_in_the_cli(self, tmp_path: Path):
        manifest = tmp_path / "mcp.json"
        manifest.write_text(
            json.dumps(
                {
                    "name": "perm-server",
                    "version": "1.0.0",
                    "tools": [
                        {"name": "do_thing", "description": "Act", "permissions": 5},
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = CliRunner().invoke(main, ["scan", str(manifest)])
        assert result.exit_code == 1
        assert "TypeError" not in result.output


class TestAutoDiscoveredPolicyIsNotSwallowed:
    """#83: a malformed discovered policy is fatal, not silently dropped."""

    @staticmethod
    def _scan(tmp_path: Path, policy: str) -> tuple[int, str]:
        target = tmp_path / "pol"
        target.mkdir(parents=True, exist_ok=True)
        manifest = target / "mcp.json"
        manifest.write_text(
            json.dumps(
                {
                    "name": "evil-server",
                    "version": "9.9.9",
                    "tools": [
                        {
                            "name": "delete_everything",
                            "description": "Delete everything in the account",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (target / "mcp-guard.yaml").write_text(policy, encoding="utf-8")
        result = CliRunner().invoke(main, ["scan", str(target), "--deny", "-f", "json"])
        return result.exit_code, result.output

    def test_malformed_discovered_policy_exits_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.chdir(tmp_path)
        malformed = "deny:\n  servers:\n    - evil-server\n  tools: [\n"
        exit_code, output = self._scan(tmp_path, malformed)
        assert exit_code == 1
        # Rich hard-wraps at the console width, so match on unwrapped output.
        assert "mcp-guard.yaml" in "".join(output.split())

    def test_valid_discovered_policy_still_denies(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """The fix does not turn every discovered file into an error."""
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._scan(tmp_path, "deny:\n  servers:\n    - evil-server\n")
        assert exit_code == 1
        rule_ids = {f["rule_id"] for f in json.loads(output)["findings"]}
        assert "DENY001" in rule_ids


class TestDescriptionReadVerbGate:
    """#91: a read-only description must not flag on a mentioned noun."""

    @pytest.mark.parametrize(
        ("name", "description"),
        [
            ("list_commands", "List the available commands"),
            ("get_command_history", "Return the command history for a session"),
            ("help", "Show available commands and their arguments"),
            ("readme", "Read the documentation for CLI commands"),
        ],
    )
    def test_read_only_descriptions_do_not_flag(self, name: str, description: str):
        cap = parse_tool(name=name, description=description)
        assert cap.is_command_execution is False
        assert cap.is_write is False
        assert cap.is_destructive is False

    def test_read_only_description_does_not_flag_write(self):
        cap = parse_tool(name="get_updates", description="List pending updates")
        assert cap.is_write is False

    def test_read_only_description_does_not_flag_destructive(self):
        cap = parse_tool(name="get_help", description="Show how to delete files")
        assert cap.is_destructive is False

    def test_descriptions_that_act_still_flag(self):
        """The gate only reads the leading verb; the signal is otherwise intact."""
        cap = parse_tool(name="maintain", description="Delete everything in the account")
        assert cap.is_destructive is True

        cap = parse_tool(name="get_user", description="Delete the user permanently")
        assert cap.is_destructive is True

    def test_conjunction_after_a_read_verb_still_flags(self):
        """`Read the file and delete it` is two operations, not one read."""
        cap = parse_tool(name="operate", description="Read the record and delete it")
        assert cap.is_destructive is True

    def test_destructive_names_stay_flagged(self):
        """The gate is on the description, not the name: `delete_files` acts."""
        cap = parse_tool(name="delete_files", description="Show how to delete files")
        assert cap.is_destructive is True

    def test_rules_see_the_ungated_capability(self):
        """End to end: a read-only description leaves no HIGH finding behind."""
        manifest = MCPParser.from_dict(
            {
                "name": "docs-server",
                "tools": [
                    {"name": "help", "description": "Show available commands and their arguments"}
                ],
            }
        )
        result = Scanner().scan(manifest)
        assert not [f for f in result.findings if f.rule_id in {"MCP009", "MCP005", "MCP001"}]

    def test_permission_budget_unchanged_for_real_lists(self):
        """The parser fix must not relax MCP003 for an actually large list."""
        manifest = MCPParser.from_dict(
            {
                "name": "srv",
                "tools": [
                    {
                        "name": "do_thing",
                        "description": "Perform an action",
                        "permissions": [f"perm:{i}" for i in range(6)],
                    }
                ],
            }
        )
        findings = ExcessivePermissionsRule().check(manifest.capabilities[0], manifest)
        assert [f.rule_id for f in findings] == ["MCP003"]
