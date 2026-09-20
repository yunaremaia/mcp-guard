# MCP Guard

**Security scanner for MCP servers** — audit capabilities, detect risks, generate security reports.

## Why

The MCP ecosystem exploded (67,000+ servers in 18 months), but security hasn't kept up:
- 87% of MCP servers fail high-trust thresholds
- 72% expose sensitive capabilities unnecessarily
- 53% rely on static API keys

**MCP Guard** helps you audit MCP servers before connecting agents to them.

## Install

```bash
pip install mcp-guard
```

## Quick Start

```bash
# Scan an MCP server directory
mcp-guard scan ./my-mcp-server

# Scan a specific config file
mcp-guard scan ./mcp.json

# Output as JSON
mcp-guard scan ./my-mcp-server --format json

# Output as SARIF (for GitHub Code Scanning)
mcp-guard scan ./my-mcp-server --format sarif --output results.sarif

# Fail CI if HIGH or CRITICAL findings
mcp-guard scan ./my-mcp-server --fail-on high

# Enforce security deny rules from a YAML config
mcp-guard scan ./my-mcp-server --config policy.yaml --deny

# Deny specific servers or tools on the fly
mcp-guard scan ./my-mcp-server --deny-server "untrusted-*" --deny

# Show server info without scanning
mcp-guard info ./my-mcp-server
```

## Deny Rules & Policy Enforcement

You can configure deny rules in a YAML file (e.g. `policy.yaml` or default `mcp-guard.yaml`). Deny rules support exact matches, wildcards (`*`), and tool-level scoping:

```yaml
# Security Policy Configuration
deny:
  # Block unverified or untrusted servers
  servers:
    - "malicious-server"
    - "github-*"
  # Block high-risk tools (exact name, wildcard, or scoped to server)
  tools:
    - "github/delete_repo"
    - "filesystem/write"
    - "sys_*"
```

Use the `--deny` flag to fail with exit code 1 whenever any denied server or tool is detected:

```bash
mcp-guard scan ./my-mcp-server --config policy.yaml --deny
```

## What It Detects

| Rule | Level | Description |
|------|-------|-------------|
| MCP001 | HIGH | Write operation without authentication |
| MCP002 | CRITICAL | Destructive operation without authentication |
| MCP003 | MEDIUM | Capability with excessive permissions |
| MCP004 | LOW | Capability without description |
| MCP005 | MEDIUM | Write capability without corresponding read |
| MCP006 | HIGH | Destructive operation without confirmation |
| MCP007 | MEDIUM / HIGH / CRITICAL | Explicitly disabled authentication ('auth': false) |
| DENY001 | CRITICAL | Server matches security policy deny rule |
| DENY002 | CRITICAL | Tool capability matches security policy deny rule |

### Authentication Detection Semantics

`mcp-guard` validates that capability authentication fields contain truthy configuration rather than mere key presence:

- **Auth Required**: Detected when `auth`, `authorization`, or `security` is present with a truthy value (`true`, configuration object/dict, non-empty string, or non-empty list).
- **Auth Explicitly Disabled**: Flagged when `auth` or `authorization` is set to `false` or `"disabled"`. Capabilities explicitly disabling authentication trigger rule `MCP007` and cannot bypass `MCP001` (write) or `MCP002` (destructive) checks.
- **No Auth Field / Falsy**: Falsy values like `null`, `""`, `0`, or `{}` are treated as unauthenticated.
- **SARIF Integration**: SARIF 2.1.0 output records `properties.auth_status` as `"required"`, `"disabled"`, or `"unknown"` for each capability finding.


## Example Output

```
MCP Server
test-server v1.0.0
A test MCP server

Risk Score: CRITICAL

Summary
Total Capabilities    3
Critical              1
High                  1
Medium                0
Low                   0

Findings
Rule      Level       Capability          Message                              Suggestion
MCP002    CRITICAL    delete_database     Destructive operation without auth    Add authentication
MCP001    HIGH        create_user         Write operation without auth         Add authentication
```

## CI Integration

### GitHub Action

```yaml
name: MCP Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install mcp-guard
      - run: mcp-guard scan ./mcp-server --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## License

MIT

## Trust boundary

Treat MCP tool responses as untrusted input until validated by your agent policy.
