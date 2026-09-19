"""Tests for MCP Guard parser error handling."""
import json
import pytest
from pathlib import Path

from mcp_guard.parser import MCPParser


def test_parser_handles_empty_file(tmp_path):
    """Parser should raise ValueError for empty files."""
    empty = tmp_path / "empty.json"
    empty.write_text("")

    with pytest.raises(ValueError, match="Invalid JSON"):
        MCPParser.from_file(empty)


def test_parser_handles_malformed_json(tmp_path):
    """Parser should raise ValueError for malformed JSON."""
    bad = tmp_path / "bad.json"
    bad.write_text("{invalid json}")

    with pytest.raises(ValueError, match="Invalid JSON"):
        MCPParser.from_file(bad)


def test_parser_handles_non_object_json(tmp_path):
    """Parser should raise ValueError for non-object JSON."""
    arr = tmp_path / "array.json"
    arr.write_text('[1, 2, 3]')

    with pytest.raises(ValueError, match="Expected JSON object"):
        MCPParser.from_file(arr)


def test_parser_handles_missing_file(tmp_path):
    """Parser should raise ValueError for missing files."""
    missing = tmp_path / "missing.json"

    with pytest.raises(ValueError, match="Cannot read"):
        MCPParser.from_file(missing)


def test_parser_valid_manifest(tmp_path):
    """Parser should correctly parse a valid manifest."""
    manifest = tmp_path / "mcp.json"
    manifest.write_text(json.dumps({
        "name": "test-server",
        "version": "1.0.0",
        "tools": [
            {"name": "get_data", "description": "Get data from API"}
        ]
    }))

    result = MCPParser.from_file(manifest)
    assert result.name == "test-server"
    assert result.version == "1.0.0"
    assert len(result.capabilities) == 1
    assert result.capabilities[0].name == "get_data"
