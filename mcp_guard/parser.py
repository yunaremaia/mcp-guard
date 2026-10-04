"""Parser for MCP server manifests."""

from __future__ import annotations

import json
import re
from collections.abc import Collection
from functools import cache
from pathlib import Path
from typing import Any, cast

from .models import MCPCapability, MCPCapabilityType, MCPManifest

# Leading verbs that mark a capability as read-only regardless of the rest of
# its identifier: MCP tool names conventionally lead with the operation verb,
# so `get_clear_status` ("get the clear-status") and `search_update_records`
# ("search the update-records") are reads even though `clear`/`update` appear
# as identifier segments (#84).
_READ_VERBS = frozenset(
    {
        "check",
        "describe",
        "fetch",
        "find",
        "get",
        "has",
        "inspect",
        "is",
        "list",
        "lookup",
        "query",
        "read",
        "return",
        "retrieve",
        "search",
        "select",
        "show",
        "view",
    }
)

# camelCase boundary: lower/digit followed by upper (same split the
# prompt-injection module applies to identifiers).
_CAMEL_SPLIT = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_IDENTIFIER_SEPARATORS = re.compile(r"[\s_\-.]+")

# A conjunction between a leading read verb and a write/destructive keyword
# marks a second operation (`get_and_delete_user`, `fetch_or_drop_table`),
# so the read-verb suppression must not apply. `&` appears as its own token
# after separator splitting (`get_&_delete` -> ["get", "&", "delete"]).
_CONJUNCTIONS = frozenset({"and", "or", "then", "&"})

# Verb inflections matched after a description keyword: third person
# ("Deletes all records"), regular past ("cleared the cache") and gerund
# ("posting the result"). E-final verbs form the past with a bare "d"
# ("deleted") which is deliberately NOT matched — the same suffix would
# flag adjectival participles like "the created date" (#84's false
# positive), so only forms unambiguous with the lemma are included.
_DESCRIPTION_SUFFIX = r"(?:e?s|ed|ing)?"


# Command-execution family (#89): names/descriptions indicating the capability
# runs arbitrary code or spawns processes. This is a third trust boundary,
# deliberately separate from the write and destructive lists: `ssh_exec` does
# not "perform write operations", it runs commands. `run` and `evaluate` are
# excluded (too many read-shaped names — `run_query`, `evaluate_model`), while
# the shell/process nouns carry the family: measured against the repo corpus,
# this set reaches 15/15 real execution names for 3 read-shaped false
# positives. Read-verb suppression applies as everywhere else, so
# `get_exec_summary` and `get_command_history` stay unflagged.
_COMMAND_EXECUTION_KEYWORDS = frozenset(
    {
        "exec",
        "execute",
        "eval",
        "spawn",
        "shell",
        "bash",
        "cmd",
        "command",
        "subprocess",
        "popen",
        "terminal",
    }
)


@cache
def _description_pattern(keyword: str) -> re.Pattern[str]:
    """Compile a description-matching pattern for one keyword.

    Covers the inflected forms the bare lemma misses: `deletes` (third
    person), `cleared` (regular past), `posting` (gerund) and the
    e-dropping gerund of verbs ending in `e` (`writing`, `updating`).
    Consonant-vowel-consonant keywords double their final consonant
    (`dropping`, `putting`) and consonant+y keywords conjugate their `y`
    (`modifies`, `modified`). Common-noun collisions are avoided: the
    doubling rule skips `set`, whose gerund (`setting`/`settings`) is the
    noun #84 protects.
    """

    stem = re.escape(keyword)
    alternatives = [f"{stem}{_DESCRIPTION_SUFFIX}"]

    if keyword.endswith("e"):
        # e-dropping gerund: write -> writing, update -> updating
        alternatives.append(f"{re.escape(keyword[:-1])}ing")

    if (
        len(keyword) >= 3
        and keyword[-1] not in "aeiouwxy"
        and keyword[-2] in "aeiou"
        and keyword[-3] not in "aeiou"
        and keyword != "set"
    ):
        # CVC doubling: drop -> dropping/dropped, put -> putting
        alternatives.append(f"{stem}{keyword[-1]}(?:ing|ed)")

    if len(keyword) >= 2 and keyword[-1] == "y" and keyword[-2] not in "aeiou":
        # consonant+y: modify -> modifies/modified
        alternatives.append(f"{re.escape(keyword[:-1])}(?:ies|ied)")

    return re.compile(rf"\b(?:{'|'.join(alternatives)})\b")


def _as_permission_list(value: Any) -> list[str]:
    """Normalize a `permissions`/`auth.scopes` value to a list of strings.

    YAML and JSON both allow a scalar or a list, so a manifest may declare
    `"permissions": "admin:write"` or the space/comma-separated scope form
    `"repo:read repo:write"` (#85). `list.extend()` on a bare string iterates
    it per character, inflating the count `ExcessivePermissionsRule` compares
    against `MAX_PERMISSIONS`, and a non-iterable raised a bare TypeError.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [part for part in re.split(r"[\s,]+", value.strip()) if part]
    if isinstance(value, list | tuple):
        return [str(item) for item in cast("list[Any]", value)]
    raise ValueError(f"Expected a list or string of permissions/scopes, got {type(value).__name__}")


class MCPParser:
    """Parse MCP server configuration files."""

    # Known MCP config file names
    CONFIG_FILES = [
        "mcp.json",
        "mcp.config.json",
        ".mcp.json",
        "server.json",
    ]

    @classmethod
    def from_file(cls, path: str | Path) -> MCPManifest:
        """Parse an MCP manifest from a file path."""
        path = Path(path)
        if path.is_dir():
            return cls.from_directory(path)
        return cls.from_json(path)

    @classmethod
    def from_directory(cls, dir_path: str | Path) -> MCPManifest:
        """Find and parse MCP config in a directory."""
        dir_path = Path(dir_path)
        for config_name in cls.CONFIG_FILES:
            config_path = dir_path / config_name
            if config_path.exists():
                return cls.from_json(config_path)
        raise FileNotFoundError(
            f"No MCP config found in {dir_path}. Expected one of: {', '.join(cls.CONFIG_FILES)}"
        )

    @classmethod
    def from_json(cls, json_path: str | Path) -> MCPManifest:
        """Parse MCP manifest from a JSON file."""
        json_path = Path(json_path)
        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {json_path}: {e}") from e
        except OSError as e:
            raise ValueError(f"Cannot read {json_path}: {e}") from e

        if not isinstance(data, dict):
            raise ValueError(f"Expected JSON object in {json_path}, got {type(data).__name__}")

        return cls.from_dict(cast("dict[str, Any]", data))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MCPManifest:
        """Parse MCP manifest from a dictionary."""
        capabilities: list[MCPCapability] = []

        # Parse tools
        for tool in data.get("tools", []):
            capabilities.append(cls._parse_capability(tool, MCPCapabilityType.TOOL))

        # Parse resources
        for resource in data.get("resources", []):
            capabilities.append(cls._parse_capability(resource, MCPCapabilityType.RESOURCE))

        # Parse prompts
        for prompt in data.get("prompts", []):
            capabilities.append(cls._parse_capability(prompt, MCPCapabilityType.PROMPT))

        return MCPManifest(
            name=data.get("name", "unknown"),
            version=data.get("version", "0.0.0"),
            description=data.get("description", ""),
            capabilities=capabilities,
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def _parse_capability(
        cls,
        data: dict[str, Any],
        cap_type: MCPCapabilityType,
    ) -> MCPCapability:
        """Parse a single capability from raw data."""
        # Detect permissions from input schema
        permissions = cls._extract_permissions(data)

        # Detect if capability requires auth
        has_auth = cls._detect_auth(data)
        auth_disabled = cls._detect_auth_disabled(data)

        # Detect if capability is destructive
        is_destructive = cls._detect_destructive(data)

        # Detect if capability is write-type
        is_write = cls._detect_write(data)

        # Detect if capability runs arbitrary commands (#89)
        is_command_execution = cls._detect_command_execution(data)

        return MCPCapability(
            name=data.get("name", "unnamed"),
            type=cap_type,
            description=data.get("description", ""),
            input_schema=data.get("inputSchema", data.get("input_schema", {})),
            permissions=permissions,
            has_auth=has_auth,
            auth_disabled=auth_disabled,
            is_destructive=is_destructive,
            is_write=is_write,
            is_command_execution=is_command_execution,
        )

    @classmethod
    def _extract_permissions(cls, data: dict[str, Any]) -> list[str]:
        """Extract permissions from capability data."""
        permissions = _as_permission_list(data.get("permissions"))

        # Check for scopes in auth config
        auth: Any = data.get("auth")
        if isinstance(auth, dict):
            auth_block = cast("dict[str, Any]", auth)
            permissions.extend(_as_permission_list(auth_block.get("scopes")))

        return permissions

    @classmethod
    def _detect_auth(cls, data: dict[str, Any]) -> bool:
        """Detect if capability has authentication configured and enabled.

        Returns True only if auth, authorization, or security is present and truthy
        (not False, None, 0, empty string, or empty collection).
        """
        for key in ("auth", "authorization"):
            if key in data:
                val = data[key]
                if val:
                    return True
        # Check for security in OpenAPI-style
        return bool(data.get("security"))

    @classmethod
    def _detect_auth_disabled(cls, data: dict[str, Any]) -> bool:
        """Detect if capability explicitly disables authentication (e.g. 'auth': false)."""
        for key in ("auth", "authorization"):
            if key in data:
                val = data[key]
                if val is False or (
                    isinstance(val, str)
                    and val.strip().lower() in ("false", "disabled", "none", "off")
                ):
                    return True
        return False

    @staticmethod
    def _name_tokens(name: str) -> list[str]:
        """Tokenize an identifier (snake_case, kebab-case, camelCase) into words."""
        spaced = _CAMEL_SPLIT.sub(" ", name)
        return [token for token in _IDENTIFIER_SEPARATORS.split(spaced.lower()) if token]

    @classmethod
    def _keyword_hit(cls, keywords: Collection[str], name: str, desc: str) -> bool:
        """Match a keyword list against an identifier and its description.

        Names are tokenized so a keyword only matches a whole identifier
        segment: `delete_repo` still matches `delete`, but `get_address` no
        longer matches `add` inside "address" (#84). A leading read-only
        verb suppresses name matching while the keyword directly follows
        it (`search_update_records` is a read); a conjunction in between
        marks a second operation, so `get_and_delete_user` still matches.
        The conjunction check runs for every keyword hit, not just the
        first — `get_delete_and_remove_user` keeps matching too.

        Descriptions are matched on word boundaries with verb
        inflections, so `Deletes`, `cleared` and `updating` are caught
        while `created`, `settings` and `input` still do not trip
        `create`, `set` or `put`.
        """
        tokens = cls._name_tokens(name)
        hits = [i for i, token in enumerate(tokens) if token in keywords]
        conjunction_before_hit = any(token in _CONJUNCTIONS for i in hits for token in tokens[1:i])
        name_match = bool(hits) and not (
            tokens and tokens[0] in _READ_VERBS and not conjunction_before_hit
        )
        if name_match:
            return True
        if cls._description_read_gate(keywords, desc):
            return False
        return any(_description_pattern(keyword).search(desc) for keyword in keywords)

    @classmethod
    def _description_read_gate(cls, keywords: Collection[str], desc: str) -> bool:
        """Detect a description that only mentions a keyword as a read-only object.

        The read-verb gate applied to the name alone left the description
        ungated, so a read-only tool was flagged anyway: `get_command_history`
        suppressed the name, then "Return the command history" re-raised it on
        the noun "command" (#91). A description leading with a read verb is
        suppressed unless a conjunction reveals a second operation ("Read the
        record and delete it"), mirroring the name-path rule.
        """
        first_hit = min(
            (
                match.start()
                for keyword in keywords
                if (match := _description_pattern(keyword).search(desc)) is not None
            ),
            default=-1,
        )
        if first_hit < 0:
            return False
        lead = [token for token in _IDENTIFIER_SEPARATORS.split(desc[:first_hit]) if token]
        return bool(lead) and lead[0] in _READ_VERBS and not any(
            token in _CONJUNCTIONS for token in lead[1:]
        )

    @classmethod
    def _detect_destructive(cls, data: dict[str, Any]) -> bool:
        """Detect if capability performs destructive operations."""
        name = data.get("name", "")
        desc = data.get("description", "").lower()

        destructive_keywords = [
            "delete",
            "remove",
            "destroy",
            "drop",
            "purge",
            "erase",
            "clear",
            "truncate",
            "kill",
            "terminate",
        ]

        return cls._keyword_hit(destructive_keywords, name, desc)

    @classmethod
    def _detect_write(cls, data: dict[str, Any]) -> bool:
        """Detect if capability performs write operations."""
        name = data.get("name", "")
        desc = data.get("description", "").lower()

        write_keywords = [
            "create",
            "update",
            "write",
            "post",
            "put",
            "patch",
            "set",
            "add",
            "insert",
            "modify",
            "edit",
            "send",
        ]

        return cls._keyword_hit(write_keywords, name, desc)

    @classmethod
    def _detect_command_execution(cls, data: dict[str, Any]) -> bool:
        """Detect if the capability executes arbitrary commands (#89).

        Reuses ``_keyword_hit`` so whole-segment name matching, read-verb
        suppression and description inflections apply exactly as they do for
        the write and destructive dimensions.
        """
        name = data.get("name", "")
        desc = data.get("description", "").lower()

        return cls._keyword_hit(_COMMAND_EXECUTION_KEYWORDS, name, desc)
