"""Tests for YAML and JavaScript config support in MCPParser (#52)."""

from pathlib import Path

import pytest

from mcp_guard.parser import MCPParser, _js_object_literal

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# _js_object_literal helper
# ---------------------------------------------------------------------------

def test_js_object_literal_plain():
    assert _js_object_literal('{"a": 1}') == '{"a": 1}'


def test_js_object_literal_module_exports():
    src = 'module.exports = {\n  "a": [1, 2]\n};\n'
    assert _js_object_literal(src) == '{\n  "a": [1, 2]\n}'


def test_js_object_literal_export_default():
    src = 'export default {"a": "with } brace"};'
    # The closing brace inside the string must not terminate the scan.
    assert _js_object_literal(src) == '{"a": "with } brace"}'


def test_js_object_literal_nested():
    src = '{"outer": {"inner": [1, 2]}}'
    assert _js_object_literal(src) == src


def test_js_object_literal_no_object_passthrough():
    # No leading object: return the stripped text so json reports it.
    assert _js_object_literal("[1, 2, 3]") == "[1, 2, 3]"


def test_js_object_literal_escaped_quote():
    # A backslash-escaped quote inside a string does not end the string, and
    # the closing quote is tracked so later braces are handled correctly.
    assert _js_object_literal('{ "a": "x \\" y" }') == '{ "a": "x \\" y" }'


def test_js_object_literal_single_quoted_string():
    # Braces inside a single-quoted string value are ignored.
    assert _js_object_literal("{'k': 'v { nested }'}") == "{'k': 'v { nested }'}"


def test_js_object_literal_unbalanced_braces():
    # An opening brace with no close returns to end-of-text (with the
    # trailing ';' rstripped); json then reports the malformed body, which
    # from_js turns into a clean ValueError.
    assert _js_object_literal('module.exports = {"a": 1;') == '{"a": 1'


# ---------------------------------------------------------------------------
# from_file extension dispatch
# ---------------------------------------------------------------------------

def test_from_file_yaml(tmp_path):
    target = tmp_path / "mcp.config.yaml"
    target.write_text(
        "name: y\nversion: '1.0.0'\n"
        "tools:\n"
        "  - name: get_thing\n"
        "    description: Get a thing\n"
    )
    manifest = MCPParser.from_file(target)
    assert manifest.name == "y"
    assert manifest.capabilities[0].name == "get_thing"
    assert manifest.source_path == str(target)


def test_from_file_yml(tmp_path):
    target = tmp_path / "server.yml"
    target.write_text("name: yml-server\ntools: []\n")
    manifest = MCPParser.from_file(target)
    assert manifest.name == "yml-server"


def test_from_file_js_module(tmp_path):
    target = tmp_path / "mcp.config.js"
    target.write_text('module.exports = {"name": "js-server", "tools": []};')
    manifest = MCPParser.from_file(target)
    assert manifest.name == "js-server"
    assert manifest.source_path == str(target)


def test_from_file_json_still_works(tmp_path):
    target = tmp_path / "mcp.json"
    target.write_text('{"name": "json-server", "tools": []}')
    manifest = MCPParser.from_file(target)
    assert manifest.name == "json-server"


def test_from_file_unsupported_extension(tmp_path):
    target = tmp_path / "mcp.toml"
    target.write_text("name = 'toml'")
    with pytest.raises(ValueError, match="Invalid JSON"):
        # .toml falls through to from_json, so JSON decode fails.
        MCPParser.from_file(target)


# ---------------------------------------------------------------------------
# from_yaml direct
# ---------------------------------------------------------------------------

def test_from_yaml_fixture():
    manifest = MCPParser.from_yaml(FIXTURES / "yaml_sample.yaml")
    assert manifest.name == "yaml-sample"
    assert manifest.version == "2.0.0"
    names = [c.name for c in manifest.capabilities]
    assert "drop_table" in names
    assert "summarize" in names
    destructive = next(c for c in manifest.capabilities if c.name == "drop_table")
    assert destructive.is_destructive is True
    assert manifest.metadata == {"origin": "yaml"}


def test_from_yaml_malformed(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: [unclosed")
    with pytest.raises(ValueError, match="Invalid YAML"):
        MCPParser.from_yaml(bad)


def test_from_yaml_non_object(tmp_path):
    arr = tmp_path / "list.yaml"
    arr.write_text("- a\n- b\n")
    with pytest.raises(ValueError, match="Expected a YAML object"):
        MCPParser.from_yaml(arr)


def test_from_yaml_missing(tmp_path):
    with pytest.raises(ValueError, match="Cannot read"):
        MCPParser.from_yaml(tmp_path / "missing.yaml")


# ---------------------------------------------------------------------------
# from_js direct
# ---------------------------------------------------------------------------

def test_from_js_fixture():
    manifest = MCPParser.from_js(FIXTURES / "js_module.js")
    assert manifest.name == "js-sample"
    assert manifest.version == "1.1.0"
    assert manifest.capabilities[0].name == "lookup_status"
    assert manifest.metadata == {"origin": "js-module"}


def test_from_js_bare_object(tmp_path):
    target = tmp_path / "bare.js"
    target.write_text('export default {"name": "bare", "version": "0.1.0"};')
    manifest = MCPParser.from_js(target)
    assert manifest.name == "bare"
    assert manifest.version == "0.1.0"


def test_from_js_non_object(tmp_path):
    target = tmp_path / "list.js"
    target.write_text("module.exports = [1, 2, 3];")
    with pytest.raises(ValueError, match="Expected a JavaScript object"):
        MCPParser.from_js(target)


def test_from_js_unsupported_executable(tmp_path):
    # A body that requires real JS evaluation must be rejected, not run.
    target = tmp_path / "exec.js"
    target.write_text("module.exports = {name: require('fs').readFileSync('/x')}")
    with pytest.raises(ValueError, match="JSON-compatible object literal"):
        MCPParser.from_js(target)


def test_from_js_unbalanced_rejected(tmp_path):
    target = tmp_path / "unbalanced.js"
    # No closing brace: the object literal is unbalanced, so the helper
    # returns to end-of-text and json.loads rejects it.
    target.write_text('module.exports = {"name": "x"\n')
    with pytest.raises(ValueError, match="JSON-compatible object literal"):
        MCPParser.from_js(target)


def test_from_js_missing(tmp_path):
    with pytest.raises(ValueError, match="Cannot read"):
        MCPParser.from_js(tmp_path / "missing.js")
