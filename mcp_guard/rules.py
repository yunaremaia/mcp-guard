"""Security rules for MCP server scanning."""

from __future__ import annotations

from .models import (
    MCPCapability,
    MCPCapabilityType,
    MCPManifest,
    RiskFinding,
    RiskLevel,
)


class SecurityRule:
    """Base class for security rules."""

    rule_id: str = "BASE"
    description: str = ""

    def check(
        self,
        capability: MCPCapability,
        manifest: MCPManifest,
    ) -> list[RiskFinding]:
        """Check a capability against this rule."""
        raise NotImplementedError


class UnauthenticatedWriteRule(SecurityRule):
    """Detect write operations without authentication."""

    rule_id = "MCP001"
    description = "Write operation without authentication"

    def check(
        self,
        capability: MCPCapability,
        manifest: MCPManifest,
    ) -> list[RiskFinding]:
        findings = []
        if capability.is_write and not capability.has_auth:
            findings.append(RiskFinding(
                rule_id=self.rule_id,
                level=RiskLevel.HIGH,
                message=f"Capability '{capability.name}' performs write operations without authentication",
                capability_name=capability.name,
                capability_type=capability.type,
                suggestion="Add authentication (OAuth2, API key) to this capability",
            ))
        return findings


class UnauthenticatedDestructiveRule(SecurityRule):
    """Detect destructive operations without authentication."""

    rule_id = "MCP002"
    description = "Destructive operation without authentication"

    def check(
        self,
        capability: MCPCapability,
        manifest: MCPManifest,
    ) -> list[RiskFinding]:
        findings = []
        if capability.is_destructive and not capability.has_auth:
            findings.append(RiskFinding(
                rule_id=self.rule_id,
                level=RiskLevel.CRITICAL,
                message=f"Capability '{capability.name}' performs destructive operations without authentication",
                capability_name=capability.name,
                capability_type=capability.type,
                suggestion="Add authentication and confirmation mechanism for destructive operations",
            ))
        return findings


class ExcessivePermissionsRule(SecurityRule):
    """Detect capabilities with excessive permissions."""

    rule_id = "MCP003"
    description = "Capability with excessive permissions"

    MAX_PERMISSIONS = 5

    def check(
        self,
        capability: MCPCapability,
        manifest: MCPManifest,
    ) -> list[RiskFinding]:
        findings = []
        if len(capability.permissions) > self.MAX_PERMISSIONS:
            findings.append(RiskFinding(
                rule_id=self.rule_id,
                level=RiskLevel.MEDIUM,
                message=(
                    f"Capability '{capability.name}' has {len(capability.permissions)} "
                    f"permissions (max recommended: {self.MAX_PERMISSIONS})"
                ),
                capability_name=capability.name,
                capability_type=capability.type,
                suggestion="Review and reduce permissions to minimum required",
            ))
        return findings


class NoDescriptionRule(SecurityRule):
    """Detect capabilities without description."""

    rule_id = "MCP004"
    description = "Capability without description"

    def check(
        self,
        capability: MCPCapability,
        manifest: MCPManifest,
    ) -> list[RiskFinding]:
        findings = []
        if not capability.description or len(capability.description.strip()) < 10:
            findings.append(RiskFinding(
                rule_id=self.rule_id,
                level=RiskLevel.LOW,
                message=f"Capability '{capability.name}' lacks a meaningful description",
                capability_name=capability.name,
                capability_type=capability.type,
                suggestion="Add a clear description of what this capability does",
            ))
        return findings


class WriteWithoutReadRule(SecurityRule):
    """Detect write capabilities without corresponding read capability."""

    rule_id = "MCP005"
    description = "Write capability without corresponding read"

    def check(
        self,
        capability: MCPCapability,
        manifest: MCPManifest,
    ) -> list[RiskFinding]:
        findings = []
        if not capability.is_write:
            return findings

        # Check if there's a corresponding read capability
        name = capability.name.lower()
        # Common patterns: create_X / get_X, update_X / get_X
        resource_names = set()
        for cap in manifest.capabilities:
            if cap.name.lower().startswith(("get_", "list_", "read_", "fetch_")):
                resource_names.add(cap.name.lower().split("_", 1)[1])

        # Extract resource name from write operation
        for prefix in ["create_", "update_", "delete_", "add_", "set_", "write_"]:
            if name.startswith(prefix):
                resource = name[len(prefix):]
                # Check for exact match or prefix match (e.g. user_profile and user_profile_settings)
                has_read = False
                for read_resource in resource_names:
                    if (
                        read_resource == resource
                        or read_resource.startswith(resource + "_")
                        or resource.startswith(read_resource + "_")
                    ):
                        has_read = True
                        break

                if not has_read:
                    findings.append(RiskFinding(
                        rule_id=self.rule_id,
                        level=RiskLevel.MEDIUM,
                        message=(
                            f"Write capability '{capability.name}' has no corresponding "
                            f"read capability (expected 'get_{resource}' or similar)"
                        ),
                        capability_name=capability.name,
                        capability_type=capability.type,
                        suggestion=f"Add a 'get_{resource}' capability for data visibility",
                    ))
                break

        return findings


class DestructiveWithoutConfirmationRule(SecurityRule):
    """Detect destructive operations without confirmation mechanism."""

    rule_id = "MCP006"
    description = "Destructive operation without confirmation"

    def check(
        self,
        capability: MCPCapability,
        manifest: MCPManifest,
    ) -> list[RiskFinding]:
        findings = []
        if not capability.is_destructive:
            return findings

        # Check if schema has a confirmation field
        schema = capability.input_schema
        properties = schema.get("properties", {})
        has_confirmation = any(
            key in properties
            for key in ["confirm", "confirmation", "force", "dry_run", "dryRun"]
        )

        if not has_confirmation:
            findings.append(RiskFinding(
                rule_id=self.rule_id,
                level=RiskLevel.HIGH,
                message=(
                    f"Destructive capability '{capability.name}' lacks a confirmation "
                    f"mechanism (no 'confirm' or 'dry_run' field)"
                ),
                capability_name=capability.name,
                capability_type=capability.type,
                suggestion="Add a 'confirm' boolean field to prevent accidental execution",
            ))
        return findings


# Registry of all rules
ALL_RULES: list[SecurityRule] = [
    UnauthenticatedWriteRule(),
    UnauthenticatedDestructiveRule(),
    ExcessivePermissionsRule(),
    NoDescriptionRule(),
    WriteWithoutReadRule(),
    DestructiveWithoutConfirmationRule(),
]
