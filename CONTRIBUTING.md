# Contributing

## Development setup

    python -m venv .venv
    pip install -e ".[dev]"

## Type checking

The package is fully typed and ships a `py.typed` marker (PEP 561).
Both checkers run in strict mode and must report zero errors:

    mypy --strict mcp_guard/
    pyright

Guidelines:

- Annotate all parameters and return types, including `-> None`.
- Annotate empty containers (`items: list[str] = []`).
- Avoid `Any`. When it is unavoidable (e.g. parsed JSON/YAML), keep it
  at the boundary and narrow it with `cast` or explicit annotations.
- Do not add `# type: ignore` without a specific error code and a reason.
- Use `X | None`, not `Optional[X]` (Python 3.10+).

## Before opening a PR

    pytest
    mypy --strict mcp_guard/
    pyright
    ruff check mcp_guard