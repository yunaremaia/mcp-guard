"""CLI interface for MCP Guard."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .formatters import to_json, to_rich, to_sarif
from .parser import MCPParser
from .policy import DenyPolicy
from .scanner import Scanner


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
def scan(
    path: str,
    output_format: str,
    output: str | None,
    fail_on: str | None,
    config_path: str | None,
    deny_flag: bool,
    cli_deny_servers: tuple[str, ...],
    cli_deny_tools: tuple[str, ...],
) -> None:
    """Scan an MCP server for security risks.

    PATH can be a directory containing mcp.json or the config file itself.
    """
    console = Console()

    try:
        manifest = MCPParser.from_file(path)
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except json.JSONDecodeError as e:
        console.print(f"[red]Error: Invalid JSON - {e}[/red]")
        sys.exit(1)

    # Resolve deny policy from config file or CLI options
    deny_policy: DenyPolicy | None = None
    if config_path:
        try:
            deny_policy = DenyPolicy.from_yaml(config_path)
        except Exception as e:
            console.print(f"[red]Error loading config file: {e}[/red]")
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
                        break
                    except Exception:
                        pass
            if deny_policy:
                break

    if cli_deny_servers or cli_deny_tools:
        if deny_policy is None:
            deny_policy = DenyPolicy()
        deny_policy.servers.extend(cli_deny_servers)
        deny_policy.tools.extend(cli_deny_tools)

    scanner = Scanner(deny_policy=deny_policy)
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
            console.print(f"[green]Output written to {output}[/green]")
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
        max_level = max(
            (levels.get(f.level.value.lower(), 0) for f in result.findings),
            default=0,
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
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    console.print(f"[bold]Server:[/bold] {manifest.name} v{manifest.version}")
    console.print(f"[bold]Description:[/bold] {manifest.description}")
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
            f"  {auth_status} [{cap.type.value}] {cap.name} {write_status} {destructive_status}"
        )
        if cap.description:
            console.print(f"    {cap.description[:80]}")


if __name__ == "__main__":
    main()
