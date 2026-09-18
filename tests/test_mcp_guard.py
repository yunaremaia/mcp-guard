"""Tests for MCP Guard."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from mcp_guard.models import (
    MCPCapability,
    MCPCapabilityType,
    MCPManifest,
    RiskFinding,
    RiskLevel,
    ScanResult,
)
from mcp_guard.parser import MCPParser
from mcp_guard.rules import (
    ALL_RULES,
    DestructiveWithoutConfirmationRule,
    ExcessivePermissionsRule,
    NoDescriptionRule,
    UnauthenticatedDestructiveRule,
    UnauthenticatedWriteRule,
    WriteWithoutReadRule,
)
from mcp_guard.scanner import Scanner


class TestModels:
    """Test data models."""

    def test_risk_level_enum(self):
        assert RiskLevel.LOW.value == "LOW"
        assert RiskLevel.CRITICAL.value == "CRITICAL"

    def test_capability_creation(self):
        cap = MCPCapability(
            name="test_tool",
            type=MCPCapabilityType.TOOL,
            description="A test tool",
        )
        assert cap.name == "test_tool"
        assert cap.has_auth is False
        assert cap.is_destructive is False

    def test_manifest_creation(self):
        manifest = MCPManifest(
            name="test-server",
            version="1.0.0",
            capabilities=[
                MCPCapability(name="tool1", type=MCPCapabilityType.TOOL),
            ],
        )
        assert manifest.name == "test-server"
        assert len(manifest.capabilities) == 1

    def test_scan_result_summary(self):
        manifest = MCPManifest(
            name="test",
            capabilities=[
                MCPCapability(name="t1", type=MCPCapabilityType.TOOL),
                MCPCapability(name="t2", type=MCPCapabilityType.TOOL),
            ],
        )
        finding = RiskFinding(
            rule_id="MCP001",
            level=RiskLevel.HIGH,
            message="test",
            capability_name="t1",
            capability_type=MCPCapabilityType.TOOL,
            suggestion="fix",
        )
        result = ScanResult(
            manifest=manifest,
            findings=[finding],
        )
        assert result.summary["total_capabilities"] == 2
        assert result.summary["high"] == 1
        assert result.risk_score == RiskLevel.HIGH


class TestParser:
    """Test MCP manifest parser."""

    def test_from_dict_minimal(self):
        data = {
            "name": "test-server",
            "version": "1.0.0",
        }
        manifest = MCPParser.from_dict(data)
        assert manifest.name == "test-server"
        assert manifest.capabilities == []

    def test_from_dict_with_tools(self):
        data = {
            "name": "test",
            "tools": [
                {"name": "create_user", "description": "Create a user"},
            ],
        }
        manifest = MCPParser.from_dict(data)
        assert len(manifest.capabilities) == 1
        assert manifest.capabilities[0].name == "create_user"
        assert manifest.capabilities[0].is_write is True

    def test_from_dict_with_resources(self):
        data = {
            "name": "test",
            "resources": [
                {"name": "user_data", "description": "User data resource"},
            ],
        }
        manifest = MCPParser.from_dict(data)
        assert len(manifest.capabilities) == 1
        assert manifest.capabilities[0].type == MCPCapabilityType.RESOURCE

    def test_from_dict_with_prompts(self):
        data = {
            "name": "test",
            "prompts": [
                {"name": "greeting", "description": "Greeting prompt"},
            ],
        }
        manifest = MCPParser.from_dict(data)
        assert len(manifest.capabilities) == 1
        assert manifest.capabilities[0].type == MCPCapabilityType.PROMPT

    def test_from_json_file(self):
        data = {"name": "test", "tools": [{"name": "t1"}]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            manifest = MCPParser.from_json(f.name)
        assert manifest.name == "test"
        assert len(manifest.capabilities) == 1

    def test_from_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "mcp.json"
            config.write_text(json.dumps({"name": "test", "tools": [{"name": "t1"}]}))
            manifest = MCPParser.from_directory(tmpdir)
        assert manifest.name == "test"

    def test_from_directory_not_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(FileNotFoundError):
                MCPParser.from_directory(tmpdir)


class TestRules:
    """Test security rules."""

    def test_unauthenticated_write(self):
        rule = UnauthenticatedWriteRule()
        cap = MCPCapability(
            name="create_user",
            type=MCPCapabilityType.TOOL,
            is_write=True,
            has_auth=False,
        )
        manifest = MCPManifest(name="test", capabilities=[cap])
        findings = rule.check(cap, manifest)
        assert len(findings) == 1
        assert findings[0].level == RiskLevel.HIGH

    def test_authenticated_write_no_finding(self):
        rule = UnauthenticatedWriteRule()
        cap = MCPCapability(
            name="create_user",
            type=MCPCapabilityType.TOOL,
            is_write=True,
            has_auth=True,
        )
        manifest = MCPManifest(name="test", capabilities=[cap])
        findings = rule.check(cap, manifest)
        assert len(findings) == 0

    def test_unauthenticated_destructive(self):
        rule = UnauthenticatedDestructiveRule()
        cap = MCPCapability(
            name="delete_user",
            type=MCPCapabilityType.TOOL,
            is_destructive=True,
            has_auth=False,
        )
        manifest = MCPManifest(name="test", capabilities=[cap])
        findings = rule.check(cap, manifest)
        assert len(findings) == 1
        assert findings[0].level == RiskLevel.CRITICAL

    def test_excessive_permissions(self):
        rule = ExcessivePermissionsRule()
        cap = MCPCapability(
            name="admin_action",
            type=MCPCapabilityType.TOOL,
            permissions=["read", "write", "delete", "admin", "sudo", "root"],
        )
        manifest = MCPManifest(name="test", capabilities=[cap])
        findings = rule.check(cap, manifest)
        assert len(findings) == 1
        assert findings[0].level == RiskLevel.MEDIUM

    def test_no_description(self):
        rule = NoDescriptionRule()
        cap = MCPCapability(
            name="some_tool",
            type=MCPCapabilityType.TOOL,
            description="",
        )
        manifest = MCPManifest(name="test", capabilities=[cap])
        findings = rule.check(cap, manifest)
        assert len(findings) == 1
        assert findings[0].level == RiskLevel.LOW

    def test_short_description(self):
        rule = NoDescriptionRule()
        cap = MCPCapability(
            name="some_tool",
            type=MCPCapabilityType.TOOL,
            description="Short",
        )
        manifest = MCPManifest(name="test", capabilities=[cap])
        findings = rule.check(cap, manifest)
        assert len(findings) == 1

    def test_write_without_read(self):
        rule = WriteWithoutReadRule()
        cap = MCPCapability(
            name="create_user",
            type=MCPCapabilityType.TOOL,
            is_write=True,
        )
        manifest = MCPManifest(name="test", capabilities=[cap])
        findings = rule.check(cap, manifest)
        assert len(findings) == 1
        assert findings[0].level == RiskLevel.MEDIUM

    def test_write_with_read_no_finding(self):
        rule = WriteWithoutReadRule()
        write_cap = MCPCapability(
            name="create_user",
            type=MCPCapabilityType.TOOL,
            is_write=True,
        )
        read_cap = MCPCapability(
            name="get_user",
            type=MCPCapabilityType.TOOL,
        )
        manifest = MCPManifest(name="test", capabilities=[write_cap, read_cap])
        findings = rule.check(write_cap, manifest)
        assert len(findings) == 0

    def test_write_with_read_multi_underscore_prefix_match(self):
        rule = WriteWithoutReadRule()
        write_cap = MCPCapability(
            name="create_user_profile",
            type=MCPCapabilityType.TOOL,
            is_write=True,
        )
        read_cap = MCPCapability(
            name="get_user_profile_settings",
            type=MCPCapabilityType.TOOL,
        )
        manifest = MCPManifest(name="test", capabilities=[write_cap, read_cap])
        findings = rule.check(write_cap, manifest)
        assert len(findings) == 0

    def test_write_with_read_multi_underscore_exact_match(self):
        rule = WriteWithoutReadRule()
        write_cap = MCPCapability(
            name="create_user_profile",
            type=MCPCapabilityType.TOOL,
            is_write=True,
        )
        read_cap = MCPCapability(
            name="get_user_profile",
            type=MCPCapabilityType.TOOL,
        )
        manifest = MCPManifest(name="test", capabilities=[write_cap, read_cap])
        findings = rule.check(write_cap, manifest)
        assert len(findings) == 0

    def test_write_with_read_multi_underscore_unmatched(self):
        rule = WriteWithoutReadRule()
        write_cap = MCPCapability(
            name="create_user_profile",
            type=MCPCapabilityType.TOOL,
            is_write=True,
        )
        read_cap = MCPCapability(
            name="get_organization",
            type=MCPCapabilityType.TOOL,
        )
        manifest = MCPManifest(name="test", capabilities=[write_cap, read_cap])
        findings = rule.check(write_cap, manifest)
        assert len(findings) == 1

    def test_destructive_without_confirmation(self):
        rule = DestructiveWithoutConfirmationRule()
        cap = MCPCapability(
            name="delete_all",
            type=MCPCapabilityType.TOOL,
            is_destructive=True,
            input_schema={"properties": {"name": {"type": "string"}}},
        )
        manifest = MCPManifest(name="test", capabilities=[cap])
        findings = rule.check(cap, manifest)
        assert len(findings) == 1
        assert findings[0].level == RiskLevel.HIGH

    def test_destructive_with_confirmation(self):
        rule = DestructiveWithoutConfirmationRule()
        cap = MCPCapability(
            name="delete_all",
            type=MCPCapabilityType.TOOL,
            is_destructive=True,
            input_schema={"properties": {"confirm": {"type": "boolean"}}},
        )
        manifest = MCPManifest(name="test", capabilities=[cap])
        findings = rule.check(cap, manifest)
        assert len(findings) == 0


class TestScanner:
    """Test scanner engine."""

    def test_scan_clean_manifest(self):
        manifest = MCPManifest(
            name="clean-server",
            capabilities=[
                MCPCapability(
                    name="get_status",
                    type=MCPCapabilityType.TOOL,
                    description="Get server status",
                ),
            ],
        )
        scanner = Scanner()
        result = scanner.scan(manifest)
        assert result.risk_score == RiskLevel.LOW
        assert len(result.findings) == 0

    def test_scan_risky_manifest(self):
        manifest = MCPManifest(
            name="risky-server",
            capabilities=[
                MCPCapability(
                    name="delete_database",
                    type=MCPCapabilityType.TOOL,
                    description="Delete the entire database",
                    is_destructive=True,
                    is_write=True,
                    has_auth=False,
                ),
            ],
        )
        scanner = Scanner()
        result = scanner.scan(manifest)
        assert result.risk_score == RiskLevel.CRITICAL
        assert len(result.findings) >= 2

    def test_scan_multiple_capabilities(self):
        manifest = MCPManifest(
            name="multi-server",
            capabilities=[
                MCPCapability(
                    name="get_user",
                    type=MCPCapabilityType.TOOL,
                    description="Get user by ID",
                ),
                MCPCapability(
                    name="create_user",
                    type=MCPCapabilityType.TOOL,
                    description="Create a new user",
                    is_write=True,
                    has_auth=True,
                ),
                MCPCapability(
                    name="delete_user",
                    type=MCPCapabilityType.TOOL,
                    description="Delete a user",
                    is_destructive=True,
                    is_write=True,
                    has_auth=True,
                    input_schema={"properties": {"confirm": {"type": "boolean"}}},
                ),
            ],
        )
        scanner = Scanner()
        result = scanner.scan(manifest)
        assert result.summary["total_capabilities"] == 3


class TestFormatters:
    """Test output formatters."""

    def test_to_dict(self):
        manifest = MCPManifest(name="test", capabilities=[])
        result = ScanResult(manifest=manifest, findings=[])
        d = result.summary
        assert d["total_capabilities"] == 0

    def test_to_json_output(self):
        manifest = MCPManifest(name="test", capabilities=[])
        result = ScanResult(manifest=manifest, findings=[])
        from mcp_guard.formatters import to_json
        json_str = to_json(result)
        parsed = json.loads(json_str)
        assert parsed["server"]["name"] == "test"

    def test_to_sarif(self):
        manifest = MCPManifest(
            name="test",
            capabilities=[
                MCPCapability(
                    name="delete_all",
                    type=MCPCapabilityType.TOOL,
                    is_destructive=True,
                    has_auth=False,
                ),
            ],
        )
        scanner = Scanner()
        result = scanner.scan(manifest)
        from mcp_guard.formatters import to_sarif
        sarif = to_sarif(result)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) > 0


class TestEndToEnd:
    """End-to-end tests."""

    def test_full_scan_pipeline(self):
        """Test complete pipeline: dict -> parse -> scan -> format."""
        data = {
            "name": "e2e-test",
            "version": "1.0.0",
            "tools": [
                {
                    "name": "get_item",
                    "description": "Get an item by ID",
                },
                {
                    "name": "create_item",
                    "description": "Create a new item",
                    "inputSchema": {
                        "properties": {
                            "name": {"type": "string"},
                        },
                    },
                },
                {
                    "name": "delete_item",
                    "description": "Delete an item permanently",
                    "inputSchema": {
                        "properties": {
                            "id": {"type": "string"},
                        },
                    },
                },
            ],
        }

        manifest = MCPParser.from_dict(data)
        assert len(manifest.capabilities) == 3

        scanner = Scanner()
        result = scanner.scan(manifest)

        # delete_item should trigger destructive without auth + without confirmation
        destructive_findings = [
            f for f in result.findings if f.capability_name == "delete_item"
        ]
        assert len(destructive_findings) >= 1

        # Verify JSON output works
        from mcp_guard.formatters import to_json
        json_str = to_json(result)
        parsed = json.loads(json_str)
        assert parsed["server"]["name"] == "e2e-test"
