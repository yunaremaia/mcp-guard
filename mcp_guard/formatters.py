"""Output formatters for scan results."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import RiskLevel, ScanResult


def to_dict(result: ScanResult) -> dict[str, Any]:
    """Convert scan result to dictionary."""
    return {
        "server": {
            "name": result.manifest.name,
            "version": result.manifest.version,
            "description": result.manifest.description,
        },
        "risk_score": result.risk_score.value,
        "summary": result.summary,
        "findings": [
            {
                "rule_id": f.rule_id,
                "level": f.level.value,
                "message": f.message,
                "capability": f.capability_name,
                "type": f.capability_type.value if f.capability_type else None,
                "suggestion": f.suggestion,
            }
            for f in result.findings
        ],
    }


def to_json(result: ScanResult, indent: int = 2) -> str:
    """Convert scan result to JSON string."""
    return json.dumps(to_dict(result), indent=indent)


def to_sarif(result: ScanResult) -> dict[str, Any]:
    """Convert scan result to SARIF format for GitHub Code Scanning."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for finding in result.findings:
        # Add rule if not already added
        if finding.rule_id not in [r["id"] for r in rules]:
            rules.append(
                {
                    "id": finding.rule_id,
                    "shortDescription": {"text": finding.message},
                    "defaultConfiguration": {
                        "level": _sarif_level(finding.level),
                    },
                }
            )

        cap = next(
            (c for c in result.manifest.capabilities if c.name == finding.capability_name),
            None,
        )
        auth_status = cap.auth_status if cap else "unknown"

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.level),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"mcp-server/{finding.capability_name}",
                            }
                        }
                    }
                ],
                "properties": {
                    "auth_status": auth_status,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-guard",
                        "informationUri": "https://github.com/yunaremaia/mcp-guard",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _sarif_level(level: RiskLevel) -> str:
    """Convert RiskLevel to SARIF level."""
    mapping = {
        RiskLevel.CRITICAL: "error",
        RiskLevel.HIGH: "error",
        RiskLevel.MEDIUM: "warning",
        RiskLevel.LOW: "note",
    }
    return mapping.get(level, "note")


def _level_color(level: RiskLevel) -> str:
    """Get Rich color for a risk level."""
    mapping = {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "red bold",
    }
    return mapping[level]


def to_rich(result: ScanResult) -> None:
    """Print scan result with Rich formatting."""
    console = Console()

    score_color = _level_color(result.risk_score)

    console.print()
    console.print(
        Panel(
            f"[bold]{result.manifest.name}[/bold] v{result.manifest.version}\n"
            f"{result.manifest.description}",
            title="MCP Server",
            border_style="blue",
        )
    )

    # Risk Score
    console.print(
        Panel(
            f"[{score_color}]Risk Score: {result.risk_score.value}[/{score_color}]",
            border_style=score_color,
        )
    )

    # Summary table
    summary_table = Table(title="Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="white")
    summary_table.add_row("Total Capabilities", str(result.summary["total_capabilities"]))
    summary_table.add_row("Critical", f"[red]{result.summary['critical']}[/red]")
    summary_table.add_row("High", f"[red]{result.summary['high']}[/red]")
    summary_table.add_row("Medium", f"[yellow]{result.summary['medium']}[/yellow]")
    summary_table.add_row("Low", f"[green]{result.summary['low']}[/green]")
    summary_table.add_row(
        "Auth Required", f"[green]{result.summary.get('auth_required', 0)}[/green]"
    )
    if result.summary.get("auth_disabled", 0) > 0:
        summary_table.add_row(
            "Auth Explicitly Disabled", f"[red]{result.summary['auth_disabled']}[/red]"
        )
    summary_table.add_row("No Auth Field", str(result.summary.get("auth_none", 0)))
    console.print(summary_table)

    # Findings
    if result.findings:
        findings_table = Table(title="Findings")
        findings_table.add_column("Rule", style="cyan", width=10)
        findings_table.add_column("Level", width=10)
        findings_table.add_column("Capability", style="white", width=20)
        findings_table.add_column("Message", style="white", width=50)
        findings_table.add_column("Suggestion", style="dim", width=30)

        for finding in result.findings:
            level_color = _level_color(finding.level)

            findings_table.add_row(
                finding.rule_id,
                f"[{level_color}]{finding.level.value}[/{level_color}]",
                finding.capability_name,
                finding.message,
                finding.suggestion,
            )

        console.print(findings_table)
    else:
        console.print("[green]No security findings detected[/green]")

    console.print()
