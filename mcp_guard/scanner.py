"""Scanner engine for MCP Guard."""

from __future__ import annotations

from .models import MCPManifest, RiskFinding, ScanResult
from .policy import DenyPolicy
from .rules import ALL_RULES, SecurityRule


class Scanner:
    """Scan MCP manifests for security risks."""

    def __init__(
        self,
        rules: list[SecurityRule] | None = None,
        deny_policy: DenyPolicy | None = None,
    ) -> None:
        """Initialize scanner with rules and optional deny policy."""
        self.rules = rules or list(ALL_RULES)
        self.deny_policy = deny_policy

    def scan(
        self,
        manifest: MCPManifest,
        deny_policy: DenyPolicy | None = None,
    ) -> ScanResult:
        """Scan an MCP manifest and return findings."""
        all_findings: list[RiskFinding] = []

        for capability in manifest.capabilities:
            for rule in self.rules:
                findings = rule.check(capability, manifest)
                all_findings.extend(findings)

        # Evaluate deny policy after scanning rules
        policy = deny_policy or self.deny_policy
        if policy:
            deny_findings = policy.check_manifest(manifest)
            all_findings.extend(deny_findings)

        return ScanResult(
            manifest=manifest,
            findings=all_findings,
        )

    def add_rule(self, rule: SecurityRule) -> None:
        """Add a custom rule to the scanner."""
        self.rules.append(rule)
