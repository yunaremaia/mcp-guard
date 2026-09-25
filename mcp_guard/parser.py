"""Parser for MCP server manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from .models import MCPCapability, MCPCapabilityType, MCPManifest


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
        )

    @classmethod
    def _extract_permissions(cls, data: dict[str, Any]) -> list[str]:
        """Extract permissions from capability data."""
        permissions: list[str] = []

        # Check for explicit permissions
        if "permissions" in data:
            permissions.extend(data["permissions"])

        # Check for scopes in auth config
        auth: Any = data.get("auth")
        if isinstance(auth, dict):
            auth_block = cast("dict[str, Any]", auth)
            permissions.extend(auth_block.get("scopes", []))

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

    @classmethod
    def _detect_destructive(cls, data: dict[str, Any]) -> bool:
        """Detect if capability performs destructive operations."""
        name = data.get("name", "").lower()
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

        return any(keyword in name or keyword in desc for keyword in destructive_keywords)

    @classmethod
    def _detect_write(cls, data: dict[str, Any]) -> bool:
        """Detect if capability performs write operations."""
        name = data.get("name", "").lower()
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

        return any(keyword in name or keyword in desc for keyword in write_keywords)
