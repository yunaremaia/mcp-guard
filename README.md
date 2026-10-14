# MCP Guard

**Security scanner for MCP servers** — audit capabilities, detect risks, generate security reports.

![CI](https://github.com/yunaremaia/mcp-guard/actions/workflows/ci.yml/badge.svg) ![Docker](https://github.com/yunaremaia/mcp-guard/actions/workflows/docker.yml/badge.svg) ![License](https://img.shields.io/github/license/yunaremaia/mcp-guard) ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![Release](https://img.shields.io/github/v/release/yunaremaia/mcp-guard)

## Why

The MCP ecosystem exploded (67,000+ servers in 18 months), but security hasn't kept up:
- 87% of MCP servers fail high-trust thresholds
- 72% expose sensitive capabilities unnecessarily
- 53% rely on static API keys

**MCP Guard** helps you audit MCP servers before connecting agents to them.

## Install

`mcp-guard` is not published on PyPI. Install it directly from the repository:

```bash
pip install git+https://github.com/yunaremaia/mcp-guard.git
```

Requires Python 3.10 or newer.

Alternatively, run it without installing via Docker:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/yunaremaia/mcp-guard:latest scan /work/my-mcp-server
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

# Audit every MCP server installed as an npm dependency under node_modules
mcp-guard scan ./my-project --npm --format json

# Enforce security deny rules from a YAML config
mcp-guard scan ./my-mcp-server --config policy.yaml --deny

# Deny specific servers or tools on the fly
mcp-guard scan ./my-mcp-server --deny-server "untrusted-*" --deny

# Add Little Canary's structural filter to prompt injection checks
# (requires: pip install "mcp-guard[canary] @ git+https://github.com/yunaremaia/mcp-guard.git")
mcp-guard scan ./my-mcp-server --strict-injection

# Verify npm supply chain (sigstore attestations / provenance)
mcp-guard verify @modelcontextprotocol/server-memory

# Enforce a strict policy: fail if the package is unsigned (no provenance)
mcp-guard verify @scope/mcp-server@1.2.0 --policy strict --format json

# Show server info without scanning
mcp-guard info ./my-mcp-server
```

## npm package scanning

MCP servers are commonly published to npm (`@modelcontextprotocol/server-*`,
`@mcp/*`, `mcp-*`) and ship an `mcp.json` (or another known config name) next to
their code. Point `scan` at a project root with `--npm` to audit the MCP surface a
project pulls in:

```bash
# Report the MCP-related dependencies in package.json and scan every MCP
# config found under node_modules/ in JSON
mcp-guard scan ./my-project --npm --format json

# Emit a multi-run SARIF document for GitHub Code Scanning
mcp-guard scan ./my-project --npm --format sarif --output results.sarif

# Fail CI if any installed server trips a deny rule
mcp-guard scan ./my-project --npm --deny-server "untrusted-*" --deny
```

With `--npm`, the path is treated as a **project root** rather than a single
manifest:

- MCP-related dependencies are listed from `package.json`
  (`dependencies`, `devDependencies`, `optionalDependencies`).
- Every `mcp.json` / `mcp.config.json` / `.mcp.json` / `server.json` under
  `node_modules/` is scanned; the owning npm package is attributed to each result.
- A manifest that cannot be parsed is **skipped and reported, not fatal**.
- `--deny`, `--fail-on`, `--config` and the JSON / SARIF / CLI output formats all
  apply to the aggregated result set.

Discovery is filesystem-only: it never runs `npm` or `node`, never executes a
discovered manifest, and makes no network call (the same offline posture as the
supply-chain verifier).

## Supported config formats

`mcp-guard scan <file>` (and `MCPParser.from_file`) auto-detects the format from the file extension:

- **`.json`** — standard JSON manifest; the default.
- **`.yaml` / `.yml`** — YAML manifest (parsed with a safe loader, no code execution).
- **`.js`** — a JavaScript object-literal config (`module.exports = { ... }` or `export default { ... }`). The body is read as a JSON-compatible object literal and is **never executed**, so executable JS bodies are not supported. Keys and string values must use double quotes, as in JSON.

Directories (the `scan ./my-mcp-server` form) still look for a known JSON config file such as `mcp.json`; pass a YAML or `.js` file directly to use those formats.

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

## Supply Chain Verification

`mcp-guard verify` checks whether an npm-distributed MCP server was published
with **sigstore attestations** (provenance / SLSA). It queries the npm registry
for the attestations attached to a package version and reports whether the
artifact you are about to run was built with provenance:

```bash
# Unscoped, scoped, pinned or floating version references all work
mcp-guard verify some-mcp-server
mcp-guard verify @scope/some-mcp-server@1.2.0

# Machine-readable output for CI pipelines
mcp-guard verify @scope/some-mcp-server --format json

# Strict policy: exit code 1 when the version is unsigned
mcp-guard verify @scope/some-mcp-server --policy strict
```

Statuses:

| status | meaning |
|---|---|
| `signed` | sigstore attestations found (and whether one is a SLSA provenance statement) |
| `unsigned` | the version exists but no attestations were published with it |
| `not_found` | the package does not exist on the registry |
| `registry_error` | the registry could not be reached or answered unexpectedly |

Exit codes: `0` when verified signed (or in report mode); `1` when the package
is unsigned under `--policy strict`, when it is not found, or on registry
errors — ready to gate CI jobs.

Notes:

- No new runtime dependencies: the verifier uses only the standard library
  (`urllib`), and the network layer is injectable, so the test suite stays
  fully offline.
- Verification currently covers npm packages. PyPI (PEP 740 attestations),
  Docker (cosign / SBOM) and reproducible-build checks are tracked as
  follow-ups in [#74](https://github.com/yunaremaia/mcp-guard/issues/74).

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
| MCP008 | LOW / MEDIUM / HIGH | Possible prompt injection in server or capability metadata |
| MCP009 | HIGH | Command execution without authentication |
| DENY001 | CRITICAL | Server matches security policy deny rule |
| DENY002 | CRITICAL | Tool capability matches security policy deny rule |

### Authentication Detection Semantics

`mcp-guard` validates that capability authentication fields contain truthy configuration rather than mere key presence:

- **Auth Required**: Detected when `auth`, `authorization`, or `security` is present with a truthy value (`true`, configuration object/dict, non-empty string, or non-empty list).
- **Auth Explicitly Disabled**: Flagged when `auth` or `authorization` is set to `false` or `"disabled"`. Capabilities explicitly disabling authentication trigger rule `MCP007` and cannot bypass `MCP001` (write) or `MCP002` (destructive) checks.
- **No Auth Field / Falsy**: Falsy values like `null`, `""`, `0`, or `{}` are treated as unauthenticated.
- **SARIF Integration**: SARIF 2.1.0 output records `properties.auth_status` as `"required"`, `"disabled"`, or `"unknown"` for each capability finding.


### Prompt Injection Detection (MCP008)

MCP clients pass server and tool metadata to the model, so instructions hidden there act like
part of the prompt. `MCP008` checks the server name and description, every capability name and
description, and every key and string value in `inputSchema` (parameter names, descriptions,
titles, `enum`/`default` values, nested objects, array `items`, `anyOf`/`$defs`). `$ref` is not
resolved; local definitions are scanned where they appear.

- **HIGH**: direct injection phrasing, e.g. "ignore previous instructions", "override safety
  checks", "you are now ...", "DAN mode", chat-template tokens such as `<|im_start|>`,
  "do not tell the user".
- **MEDIUM**: suspicious phrasing with legitimate uses, e.g. a bare "jailbreak", `<IMPORTANT>`
  tags, a line starting with `system:`, directions to read files such as `~/.ssh/id_rsa`, and
  invisible Unicode (zero-width, bidi, tag characters). A HIGH pattern inside quotes (for
  example a security tool describing an attack) is reported as MEDIUM with `quoted: "true"`,
  never suppressed.
- **LOW**: a field longer than 65,536 characters or a schema nested deeper than 64 levels;
  the remainder is not scanned.

Text is normalized before matching: invisible characters are removed, Unicode tag characters
are decoded to the ASCII they hide, and full-width lookalikes are folded (NFKC).

`--strict-injection` also runs [Little Canary](https://github.com/hermes-labs-ai/little-canary)'s
`StructuralFilter`. It adds a broader signature set and decodes base64/hex/ROT13 payloads
before re-checking them. It is deterministic pattern matching. It makes no model, API or
network calls and needs the optional `canary` extra. Strict mode finds more and has more false
positives (for example `sudo` or "developer mode" in a shell tool's description).

To keep scan time linear, the filter sees each field in overlapping 2,000-character windows
(200-character overlap). A Little Canary match longer than 200 characters that crosses a window
boundary can be missed. Base64 and hex tokens longer than 200 characters are decoded whole by
mcp-guard instead, and the decoded text is checked by both detectors. A long token nested
inside a decoded token is not decoded again. Cue words that enable ROT13 and reversed-text
decoding ("rot13", "reverse", ...) are passed to every window of the field. ROT13 or reversed
text longer than 200 characters can still be split across windows.

These are pattern matches, not proof of intent, and they do not catch rephrased or novel
injections. On the hand-written benign fixture in `tests/fixtures/benign_tools.json` (121
tools), the default mode flags 5 tools (4.13%, all MEDIUM) and strict mode flags 6 (4.96%).
Those rates describe that fixture only.

In JSON and SARIF output each MCP008 finding has `injection_type` (e.g. `instruction-override`,
`safety-bypass`, `role-hijack`, `jailbreak`, `fake-authority`, `concealment`,
`prompt-extraction`, `exfiltration`, `hidden-characters`, `encoded-payload`),
`metadata_field` (e.g. `inputSchema.properties.path.description`), `detector`
(`mcp-guard` or `little-canary`), `evidence` and `quoted` properties.

### Command Execution Detection (MCP009)

"Runs arbitrary code" is a different trust boundary from "mutates data" (`is_write`) and
"loses data" (`is_destructive`), so command execution gets its own classification: a shell
tool neither writes nor destroys, and MCP001's "performs write operations" text would be
false in its output. `MCP009` fires at HIGH when a capability with no authentication matches
the execution family — `exec`, `execute`, `eval`, `spawn`, `shell`, `bash`, `cmd`, `command`,
`subprocess`, `popen`, `terminal` — as whole identifier segments or inflected description
words, exactly like MCP001/MCP002. Read-verb suppression applies, so `get_exec_summary` and
`get_command_history` stay unflagged, while `get_and_exec` would still match (`and` marks a
second operation). `run` and `evaluate` are deliberately excluded: measured against this
repo's own 121-tool corpus, they add read-shaped false positives (`run_query`,
`evaluate_model`) without catching any execution name the shell/process nouns miss.

Known residuals, accepted on purpose: `execute_workflow` and `execute_sql` flag (executing a
caller-supplied workflow or SQL string is running arbitrary logic), and a description like
"List the available commands" on a neutral name can trip the phrase match — the same
description-phrase artifact MCP001/MCP002 have. The rule is not coupled into MCP005 (a shell
has no meaningful "corresponding read") or MCP006 (a confirmation field does not make an
unauthenticated shell safe; authentication does).

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
      - run: pip install git+https://github.com/yunaremaia/mcp-guard.git
      - run: mcp-guard scan ./mcp-server --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

If this tool is useful to you, a star helps other people find it.

## Related tools

- **[driftcheck](https://github.com/yunaremaia/driftcheck)** — detect version drift between docs and toolchain files
- **[context-bridge](https://github.com/yunaremaia/context-bridge)** — persistent session memory for AI agents
- **[mcp-reconcile](https://github.com/yunaremaia/mcp-reconcile)** — reconcile conflicting MCP server definitions
- **[tool-call-retry](https://github.com/yunaremaia/tool-call-retry)** — retry failed tool calls with backoff

Part of a family of focused, single-purpose developer tools — each one does one thing
and does it well.

## License

MIT

## Sponsoring / Treasury

This project is MIT licensed and free to use. If you want to support its
maintenance, you can sponsor on GitHub or contribute to the development
treasury wallet on Solana:

- GitHub Sponsors: https://github.com/sponsors/yunaremaia
- Solana: [`Eeztv1nCYUt1fwGWpzKC948gaWfjejYCAuLtUMgzDWbW`](https://solana.com/solana-wallet?base=SOL&address=Eeztv1nCYUt1fwGWpzKC948gaWfjejYCAuLtUMgzDWbW)

## Trust boundary

Treat MCP tool responses as untrusted input until validated by your agent policy.
