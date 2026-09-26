# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately by opening a GitHub Security Advisory
or emailing yunare@gmail.com. Do not open public issues for security concerns.

## Security Considerations

- mcp-guard scans MCP server configurations — do not scan untrusted servers with sensitive data
- SARIF output may contain server details — handle with care
- Plugin-based architecture: review third-party plugins before enabling
