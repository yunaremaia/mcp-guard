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

# Show server info without scanning
mcp-guard info ./my-mcp-server
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
