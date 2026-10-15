"""Security rules for MCP server scanning."""

from __future__ import annotations

from collections.abc import Iterable

from .injection import (
    InjectionMatch,
    MetadataField,
    PromptInjectionDetector,
    capability_fields,
    server_fields,
)
from .models import (
    MCPCapability,
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

    def check_server(self, manifest: MCPManifest) -> list[RiskFinding]:
        """Check server-level manifest fields; runs once per scan."""
        return []


class UnauthenticatedWriteRule(SecurityRule):
    """Detect write operations without authentication."""

    rule_id = "MCP001"
    description = "Write operation without authentication"

    def check(
        self,
        capability: MCPCapability,
        manifest: MCPManifest,
    ) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        if capability.is_write and not capability.has_auth:
            findings.append(
                RiskFinding(
                    rule_id=self.rule_id,
                    level=RiskLevel.HIGH,
                    message=(
                        f"Capability '{capability.name}' performs write operations "
                        "without authentication"
                    ),
                    capability_name=capability.name,
                    capability_type=capability.type,
                    suggestion="Add authentication (OAuth2, API key) to this capability",
                )
            )
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
        findings: list[RiskFinding] = []
        if capability.is_destructive and not capability.has_auth:
            findings.append(
                RiskFinding(
                    rule_id=self.rule_id,
                    level=RiskLevel.CRITICAL,
                    message=(
                        f"Capability '{capability.name}' performs destructive operations "
                        "without authentication"
                    ),
                    capability_name=capability.name,
                    capability_type=capability.type,
                    suggestion=(
                        "Add authentication and confirmation mechanism for destructive operations"
                    ),
                )
            )
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
        findings: list[RiskFinding] = []
        if len(capability.permissions) > self.MAX_PERMISSIONS:
            findings.append(
                RiskFinding(
                    rule_id=self.rule_id,
                    level=RiskLevel.MEDIUM,
                    message=(
                        f"Capability '{capability.name}' has {len(capability.permissions)} "
                        f"permissions (max recommended: {self.MAX_PERMISSIONS})"
                    ),
                    capability_name=capability.name,
                    capability_type=capability.type,
                    suggestion="Review and reduce permissions to minimum required",
                )
            )
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
        findings: list[RiskFinding] = []
        if not capability.description or len(capability.description.strip()) < 10:
            findings.append(
                RiskFinding(
                    rule_id=self.rule_id,
                    level=RiskLevel.LOW,
                    message=f"Capability '{capability.name}' lacks a meaningful description",
                    capability_name=capability.name,
                    capability_type=capability.type,
                    suggestion="Add a clear description of what this capability does",
                )
            )
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
        findings: list[RiskFinding] = []
        if not capability.is_write:
            return findings

        # Check if there's a corresponding read capability
        name = capability.name.lower()
        # Common patterns: create_X / get_X, update_X / get_X
        resource_names: set[str] = set()
        for cap in manifest.capabilities:
            if cap.name.lower().startswith(("get_", "list_", "read_", "fetch_")):
                resource_names.add(cap.name.lower().split("_", 1)[1])

        # Extract resource name from write operation
        for prefix in ["create_", "update_", "delete_", "add_", "set_", "write_"]:
            if name.startswith(prefix):
                resource = name[len(prefix) :]
                # Check for exact match or prefix match
                # (e.g. user_profile and user_profile_settings)
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
                    findings.append(
                        RiskFinding(
                            rule_id=self.rule_id,
                            level=RiskLevel.MEDIUM,
                            message=(
                                f"Write capability '{capability.name}' has no corresponding "
                                f"read capability (expected 'get_{resource}' or similar)"
                            ),
                            capability_name=capability.name,
                            capability_type=capability.type,
                            suggestion=f"Add a 'get_{resource}' capability for data visibility",
                        )
                    )
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
        findings: list[RiskFinding] = []
        if not capability.is_destructive:
            return findings

        # Check if schema has a confirmation field
        schema = capability.input_schema
        properties = schema.get("properties", {})
        has_confirmation = any(
            key in properties for key in ["confirm", "confirmation", "force", "dry_run", "dryRun"]
        )

        if not has_confirmation:
            findings.append(
                RiskFinding(
                    rule_id=self.rule_id,
                    level=RiskLevel.HIGH,
                    message=(
                        f"Destructive capability '{capability.name}' lacks a confirmation "
                        f"mechanism (no 'confirm' or 'dry_run' field)"
                    ),
                    capability_name=capability.name,
                    capability_type=capability.type,
                    suggestion="Add a 'confirm' boolean field to prevent accidental execution",
                )
            )
        return findings


class ExplicitlyDisabledAuthRule(SecurityRule):
    """Detect capabilities that explicitly disable authentication."""

    rule_id = "MCP007"
    description = "Explicitly disabled authentication"

    def check(
        self,
        capability: MCPCapability,
        manifest: MCPManifest,
    ) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        if capability.auth_disabled:
            level = (
                RiskLevel.CRITICAL
                if capability.is_destructive
                else (RiskLevel.HIGH if capability.is_write else RiskLevel.MEDIUM)
            )
            findings.append(
                RiskFinding(
                    rule_id=self.rule_id,
                    level=level,
                    message=(f"Capability '{capability.name}' explicitly disables authentication"),
                    capability_name=capability.name,
                    capability_type=capability.type,
                    suggestion=(
                        "Enable authentication or verify that unauthenticated access is intentional"
                    ),
                )
            )
        return findings


class PromptInjectionRule(SecurityRule):
    """Detect prompt injection phrasing in model-visible MCP metadata.

    Checks names, descriptions, parameter names and every key and string value
    of ``inputSchema`` (nested objects, arrays, ``$defs``), plus the server name
    and description. ``strict=True`` adds Little Canary's structural filter.
    """

    rule_id = "MCP008"
    description = "Possible prompt injection in metadata"

    def __init__(self, strict: bool = False) -> None:
        self.detector = PromptInjectionDetector(strict=strict)

    def check(
        self,
        capability: MCPCapability,
        manifest: MCPManifest,
    ) -> list[RiskFinding]:
        return self.check_tool(capability)

    def check_tool(self, capability: MCPCapability) -> list[RiskFinding]:
        """Check one capability's name, description and input schema."""
        return self._findings(capability_fields(capability), capability)

    def check_server(self, manifest: MCPManifest) -> list[RiskFinding]:
        return self._findings(server_fields(manifest), None, manifest.name)

    def check_manifest(self, manifest: MCPManifest) -> list[RiskFinding]:
        """Check server-level fields and every capability of a manifest."""
        findings = self.check_server(manifest)
        for capability in manifest.capabilities:
            findings.extend(self.check_tool(capability))
        return findings

    def _findings(
        self,
        fields: Iterable[MetadataField],
        capability: MCPCapability | None,
        server_name: str = "",
    ) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        for field in fields:
            for match in self.detector.scan_field(field):
                findings.append(self._to_finding(match, capability, server_name))
        return findings

    def _to_finding(
        self,
        match: InjectionMatch,
        capability: MCPCapability | None,
        server_name: str,
    ) -> RiskFinding:
        owner = f"Capability '{capability.name}'" if capability else f"Server '{server_name}'"
        if match.injection_type == "uninspected-metadata":
            message = f"{owner} field {match.location} was not fully scanned ({match.evidence})"
            suggestion = "Review this field manually; it exceeds the injection scan limits"
        else:
            message = (
                f"{owner} field {match.location} contains possible prompt injection "
                f"({match.injection_type}): {match.evidence!r}"
            )
            suggestion = (
                "Remove instructions aimed at the model from metadata, or review the server "
                "before connecting an agent to it"
            )
        return RiskFinding(
            rule_id=self.rule_id,
            level=match.level,
            message=message,
            capability_name=capability.name if capability else server_name,
            capability_type=capability.type if capability else None,
            suggestion=suggestion,
            properties={
                "injection_type": match.injection_type,
                "metadata_field": match.location,
                "detector": match.detector,
                "evidence": match.evidence,
                "quoted": "true" if match.quoted else "false",
            },
        )


class UnauthenticatedCommandExecutionRule(SecurityRule):
    """Detect command execution without authentication (#89).

    Deliberately decoupled from the write/destructive machinery: a shell tool
    neither mutates data nor destroys it, so it must not raise MCP005-style
    "no corresponding read" advice or MCP001 "performs write operations"
    text. The message states what the tool actually does.
    """

    rule_id = "MCP009"
    description = "Command execution without authentication"

    def check(
        self,
        capability: MCPCapability,
        manifest: MCPManifest,
    ) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        if capability.is_command_execution and not capability.has_auth:
            findings.append(
                RiskFinding(
                    rule_id=self.rule_id,
                    level=RiskLevel.HIGH,
                    message=(
                        f"Capability '{capability.name}' executes arbitrary commands "
                        "without authentication"
                    ),
                    capability_name=capability.name,
                    capability_type=capability.type,
                    suggestion=(
                        "Add authentication (OAuth2, API key) and constrain the command "
                        "surface this capability accepts (allowlist, sandboxing)"
                    ),
                )
            )
        return findings


# Registry of all rules
ALL_RULES: list[SecurityRule] = [
    UnauthenticatedWriteRule(),
    UnauthenticatedDestructiveRule(),
    ExcessivePermissionsRule(),
    NoDescriptionRule(),
    WriteWithoutReadRule(),
    DestructiveWithoutConfirmationRule(),
    ExplicitlyDisabledAuthRule(),
    PromptInjectionRule(),
    UnauthenticatedCommandExecutionRule(),
]
