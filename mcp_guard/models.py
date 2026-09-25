"""Data models for MCP Guard."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MCPCapabilityType(str, Enum):
    """Types of MCP capabilities."""

    TOOL = "tool"
    RESOURCE = "resource"
    PROMPT = "prompt"


class MCPCapability(BaseModel):
    """A single MCP capability (tool, resource, or prompt)."""

    name: str
    type: MCPCapabilityType
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    permissions: list[str] = Field(default_factory=list)
    has_auth: bool = False
    auth_disabled: bool = False
    is_destructive: bool = False
    is_write: bool = False

    @property
    def auth_status(self) -> str:
        """Return auth status: 'required', 'disabled', or 'unknown'."""
        if self.has_auth:
            return "required"
        if self.auth_disabled:
            return "disabled"
        return "unknown"


class MCPManifest(BaseModel):
    """Parsed MCP server manifest."""

    name: str
    version: str = "0.0.0"
    description: str = ""
    capabilities: list[MCPCapability] = Field(default_factory=list[MCPCapability])
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskFinding(BaseModel):
    """A single risk finding."""

    rule_id: str
    level: RiskLevel
    message: str
    capability_name: str = ""
    capability_type: MCPCapabilityType | None = None
    suggestion: str = ""


class ScanResult(BaseModel):
    """Complete scan result."""

    manifest: MCPManifest
    findings: list[RiskFinding] = Field(default_factory=list[RiskFinding])
    risk_score: RiskLevel = RiskLevel.LOW
    summary: dict[str, int] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        """Calculate summary after initialization."""
        self.summary = {
            "total_capabilities": len(self.manifest.capabilities),
            "critical": sum(1 for f in self.findings if f.level == RiskLevel.CRITICAL),
            "high": sum(1 for f in self.findings if f.level == RiskLevel.HIGH),
            "medium": sum(1 for f in self.findings if f.level == RiskLevel.MEDIUM),
            "low": sum(1 for f in self.findings if f.level == RiskLevel.LOW),
            "auth_required": sum(1 for c in self.manifest.capabilities if c.has_auth),
            "auth_disabled": sum(1 for c in self.manifest.capabilities if c.auth_disabled),
            "auth_none": sum(
                1 for c in self.manifest.capabilities if not c.has_auth and not c.auth_disabled
            ),
        }
        # Determine overall risk score
        if self.summary["critical"] > 0:
            self.risk_score = RiskLevel.CRITICAL
        elif self.summary["high"] > 0:
            self.risk_score = RiskLevel.HIGH
        elif self.summary["medium"] > 0:
            self.risk_score = RiskLevel.MEDIUM
        else:
            self.risk_score = RiskLevel.LOW
