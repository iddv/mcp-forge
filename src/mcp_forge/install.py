"""Register MCP servers in client app configurations."""

import json
import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class Client:
    """An MCP client application and its config file location."""
    name: str
    config_path: Path
    config_key: str = "mcpServers"
    project_level: bool = False


def _get_claude_desktop_config_path() -> Path:
    """Get the Claude Desktop config path for the current platform."""
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif system == "Windows":
        appdata = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        return Path(appdata) / "Claude" / "claude_desktop_config.json"
    else:
        return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


def _get_clients() -> Dict[str, Client]:
    """Build the clients dict. Called lazily to resolve Path.cwd() at call time."""
    cwd = Path.cwd()
    home = Path.home()

    return {
        # Desktop apps
        "claude": Client(
            name="Claude Desktop",
            config_path=_get_claude_desktop_config_path(),
        ),
        # IDEs and editors
        "cursor": Client(
            name="Cursor",
            config_path=home / ".cursor" / "mcp.json",
        ),
        "windsurf": Client(
            name="Windsurf",
            config_path=home / ".codeium" / "windsurf" / "mcp_config.json",
        ),
        "vscode": Client(
            name="VS Code",
            config_path=cwd / ".vscode" / "mcp.json",
            config_key="servers",
            project_level=True,
        ),
        "kiro": Client(
            name="Kiro",
            config_path=cwd / ".kiro" / "settings" / "mcp.json",
            project_level=True,
        ),
        "zed": Client(
            name="Zed",
            config_path=home / ".config" / "zed" / "settings.json",
            config_key="context_servers",
        ),
        "jetbrains": Client(
            name="JetBrains",
            config_path=cwd / ".junie" / "mcp.json",
            project_level=True,
        ),
        # CLI tools
        "claude-code": Client(
            name="Claude Code",
            config_path=cwd / ".mcp.json",
            project_level=True,
        ),
        # Extensions and plugins
        "continue": Client(
            name="Continue",
            config_path=home / ".continue" / "config.json",
        ),
        "cline": Client(
            name="Cline",
            config_path=home / "Documents" / "Cline" / "mcp_settings.json",
        ),
        "roo-code": Client(
            name="Roo Code",
            config_path=home / ".roo-code" / "mcp.json",
        ),
        "amazon-q": Client(
            name="Amazon Q Developer",
            config_path=home / ".aws" / "amazonq" / "mcp.json",
        ),
    }


# Module-level reference for test patching
CLIENTS: Dict[str, Client] = {}


def _in_virtualenv() -> bool:
    """Check if running inside a virtual environment."""
    return hasattr(sys, "real_prefix") or (
        hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
    )


def get_python_command() -> str:
    """Get the Python command to use in client configs.

    Returns the absolute path to the venv Python if in a virtual environment,
    otherwise returns 'python3'.
    """
    if _in_virtualenv():
        return sys.executable
    return "python3"


def get_server_entry(name: str, project_dir: Path) -> dict:
    """Build the MCP server config entry for a project.

    Args:
        name: Server name.
        project_dir: Absolute path to the project directory.

    Returns:
        Dict with 'command' and 'args' keys.
    """
    return {
        "command": get_python_command(),
        "args": [str(project_dir / "server.py")],
    }


def list_clients() -> List[str]:
    """Return sorted list of supported client keys."""
    return sorted(_get_clients().keys())


def detect_clients(specific: Optional[str] = None) -> Dict[str, Client]:
    """Detect which MCP clients are installed.

    Args:
        specific: If provided, only check this client key.

    Returns:
        Dict of client_key -> Client for found clients.
    """
    clients = CLIENTS or _get_clients()

    if specific:
        if specific not in clients:
            return {}
        client = clients[specific]
        if client.project_level:
            return {specific: client}
        if client.config_path.parent.exists():
            return {specific: client}
        return {}

    found = {}
    for key, client in clients.items():
        if client.project_level:
            found[key] = client
        elif client.config_path.parent.exists():
            found[key] = client
    return found


def install_in_client(
    client: Client,
    server_name: str,
    entry: dict,
    force: bool = False,
) -> bool:
    """Install an MCP server entry into a client's config file.

    Args:
        client: The target client.
        server_name: Name for the server entry.
        entry: The server config dict (command + args).
        force: If True, overwrite existing entries.

    Returns:
        True if installed, False if skipped (existing entry, no force).
    """
    config_path = client.config_path
    config_key = client.config_key

    # Read existing config or start fresh
    if config_path.exists():
        existing_text = config_path.read_text()
        config = json.loads(existing_text)

        # Create backup
        backup_path = config_path.with_suffix(config_path.suffix + ".bak")
        backup_path.write_text(existing_text)
    else:
        config = {}

    if config_key not in config:
        config[config_key] = {}

    # Check for existing entry
    if server_name in config[config_key] and not force:
        return False

    config[config_key][server_name] = entry

    # Write config
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2) + "\n")

    return True
