"""CLI interface for MCP Guard."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from . import __version__
from .formatters import to_json, to_rich, to_sarif
from .injection import InjectionEngineUnavailableError
from .parser import MCPParser
from .policy import DenyPolicy
from .rules import ALL_RULES, PromptInjectionRule, SecurityRule
from .scanner import Scanner
from .supply_chain import SupplyChainResult, SupplyChainStatus, verify_npm_package


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """MCP Guard - Security scanner for MCP servers."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["cli", "json", "sarif"]),
    default="cli",
    help="Output format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Output file (default: stdout)",
)
@click.option(
    "--fail-on",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default=None,
    help="Exit with error if findings at or above this level",
)
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to YAML configuration file with deny rules",
)
@click.option(
    "--deny",
    "deny_flag",
    is_flag=True,
    default=False,
    help="Exit with error if any denied server or tool is found",
)
@click.option(
    "--deny-server",
    "cli_deny_servers",
    multiple=True,
    help="Server pattern to deny (supports wildcards, can be repeated)",
)
@click.option(
    "--deny-tool",
    "cli_deny_tools",
    multiple=True,
    help="Tool pattern to deny (supports wildcards and server/tool scoping, can be repeated)",
)
@click.option(
    "--strict-injection",
    is_flag=True,
    default=False,
    help="Add Little Canary's structural filter to prompt injection checks "
    "(requires the 'canary' extra)",
)
def scan(
    path: str,
    output_format: str,
    output: str | None,
    fail_on: str | None,
    config_path: str | None,
    deny_flag: bool,
    cli_deny_servers: tuple[str, ...],
    cli_deny_tools: tuple[str, ...],
    strict_injection: bool,
) -> None:
    """Scan an MCP server for security risks.

    PATH can be a directory containing mcp.json or the config file itself.
    """
    console = Console()

    try:
        manifest = MCPParser.from_file(path)
    except FileNotFoundError as e:
        console.print(f"[red]Error: {escape(str(e))}[/red]")
        sys.exit(1)
    except ValueError as e:
        # MCPParser wraps JSON decode and read errors in ValueError.
        # Escaped: a validation error quotes the offending input verbatim, so an
        # attacker-controlled manifest can carry Rich markup into the message.
        console.print(f"[red]Error: {escape(str(e))}[/red]")
        sys.exit(1)

    # Resolve deny policy from config file or CLI options
    deny_policy: DenyPolicy | None = None
    if config_path:
        try:
            deny_policy = DenyPolicy.from_yaml(config_path)
        except Exception as e:
            console.print(f"[red]Error loading config file: {escape(str(e))}[/red]")
            sys.exit(1)
    else:
        path_obj = Path(path)
        search_dirs = [path_obj if path_obj.is_dir() else path_obj.parent, Path.cwd()]
        for base_dir in search_dirs:
            for name in ["mcp-guard.yaml", "mcp-guard.yml"]:
                candidate = base_dir / name
                if candidate.is_file():
                    try:
                        deny_policy = DenyPolicy.from_yaml(candidate)
                    except Exception as e:
                        # Found but unreadable: a security control that fails
                        # open is worse than one that fails, so this is fatal
                        # exactly as it already is via --config (#83).
                        console.print(
                            f"[red]Error loading policy file {candidate}: {escape(str(e))}[/red]"
                        )
                        sys.exit(1)
                    break
            if deny_policy:
                break

    if cli_deny_servers or cli_deny_tools:
        if deny_policy is None:
            deny_policy = DenyPolicy()
        deny_policy.servers.extend(cli_deny_servers)
        deny_policy.tools.extend(cli_deny_tools)

    rules: list[SecurityRule] | None = None
    if strict_injection:
        try:
            strict_rule = PromptInjectionRule(strict=True)
        except InjectionEngineUnavailableError as e:
            console.print(f"[red]Error: {escape(str(e))}[/red]")
            sys.exit(1)
        rules = [strict_rule if isinstance(r, PromptInjectionRule) else r for r in ALL_RULES]

    scanner = Scanner(rules=rules, deny_policy=deny_policy)
    result = scanner.scan(manifest)

    # Format output
    if output_format == "json":
        output_str = to_json(result)
    elif output_format == "sarif":
        output_str = json.dumps(to_sarif(result), indent=2)
    else:
        to_rich(result)
        output_str = None

    # Write or print output
    if output_str is not None:
        if output:
            Path(output).write_text(output_str, encoding="utf-8")
            console.print(f"[green]Output written to {escape(output)}[/green]")
        else:
            click.echo(output_str)

    # Check auto-deny flag
    has_denied = any(f.rule_id.startswith("DENY") for f in result.findings)
    if deny_flag and has_denied:
        sys.exit(1)

    # Exit code based on fail-on threshold
    if fail_on:
        levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        threshold = levels[fail_on]
        # An empty scan reads as "below every threshold", including "low":
        # with `default=0` the comparison `0 >= 0` tripped `--fail-on low`
        # even on a zero-findings scan (#82).
        max_level = max(
            (levels.get(f.level.value.lower(), 0) for f in result.findings),
            default=-1,
        )
        if max_level >= threshold:
            sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True))
def info(path: str) -> None:
    """Show MCP server info without scanning."""
    console = Console()

    try:
        manifest = MCPParser.from_file(path)
    except FileNotFoundError as e:
        console.print(f"[red]Error: {escape(str(e))}[/red]")
        sys.exit(1)
    except ValueError as e:
        # Escaped: see scan() above - validation errors quote the input verbatim.
        console.print(f"[red]Error: {escape(str(e))}[/red]")
        sys.exit(1)

    console.print(f"[bold]Server:[/bold] {escape(manifest.name)} v{escape(manifest.version)}")
    console.print(f"[bold]Description:[/bold] {escape(manifest.description)}")
    console.print(f"[bold]Capabilities:[/bold] {len(manifest.capabilities)}")

    for cap in manifest.capabilities:
        if cap.has_auth:
            auth_status = "🔒"
        elif cap.auth_disabled:
            auth_status = "🚫"
        else:
            auth_status = "🔓"
        write_status = "✏️" if cap.is_write else ""
        destructive_status = "💥" if cap.is_destructive else ""
        console.print(
            f"  {auth_status} {escape(f'[{cap.type.value}]')} {escape(cap.name)} "
            f"{write_status} {destructive_status}"
        )
        if cap.description:
            console.print(f"    {escape(cap.description[:80])}")


@main.command()
@click.argument("package_ref")
@click.option(
    "--policy",
    "-p",
    type=click.Choice(["report", "strict"]),
    default="report",
    help="report: informational output (default). strict: exit with an error "
    "when the package is unsigned (supply chain policy)",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["cli", "json"]),
    default="cli",
    help="Output format",
)
def verify(package_ref: str, policy: str, output_format: str) -> None:
    """Verify the npm supply chain of an MCP server package.

    PACKAGE_REF is an npm package reference: name, name@version,
    @scope/name or @scope/name@version. Checks the npm registry for
    sigstore attestations (provenance / SLSA) published with the
    package version, and reports whether it was built with provenance.

    Exit codes: 0 verified signed (or report mode); 1 unsigned under
    --policy strict, package not found, or registry error.
    """
    console = Console()

    try:
        result = verify_npm_package(package_ref)
    except ValueError as e:
        # InvalidPackageRef subclasses ValueError; invalid refs quote the
        # offending input verbatim, hence the escape.
        console.print(f"[red]Error: {escape(str(e))}[/red]")
        sys.exit(1)

    if output_format == "json":
        click.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    else:
        _print_verify_result(console, result)

    if result.status in (SupplyChainStatus.NOT_FOUND, SupplyChainStatus.REGISTRY_ERROR):
        sys.exit(1)
    if policy == "strict" and result.status is SupplyChainStatus.UNSIGNED:
        sys.exit(1)


def _print_verify_result(console: Console, result: SupplyChainResult) -> None:
    """Render a supply chain result with Rich.

    Every registry-controlled string (package name, version, predicate
    types) is escaped before reaching Rich markup.
    """
    style = {
        SupplyChainStatus.SIGNED: "green",
        SupplyChainStatus.UNSIGNED: "yellow",
        SupplyChainStatus.NOT_FOUND: "red",
        SupplyChainStatus.REGISTRY_ERROR: "red",
    }[result.status]

    console.print(f"[bold]Package:[/bold] {escape(result.package)}")
    console.print(f"[bold]Version:[/bold] {escape(result.version)}")
    console.print(f"[bold]Status:[/bold] [{style}]{escape(result.status.value)}[/{style}]")
    if result.status is SupplyChainStatus.SIGNED:
        provenance = "yes" if result.has_provenance else "no"
        console.print(f"[bold]Provenance:[/bold] {provenance}")
        console.print(f"[bold]Attestations:[/bold] {len(result.attestations)}")
        for att in result.attestations:
            kind = " (provenance)" if att.is_provenance else ""
            console.print(f"  - {escape(att.predicate_type)}{kind}")
    if result.message:
        console.print(f"[dim]{escape(result.message)}[/dim]")


if __name__ == "__main__":
    main()
