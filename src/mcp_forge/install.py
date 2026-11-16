"""Register MCP servers in client app configurations."""

import json
import os
import platform
import shutil
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
    detect: List[Path] = field(default_factory=list)
    """Paths that show the client is in use. Defaults to the config file's directory."""


class ConfigError(Exception):
    """A client config file that can't be read or updated safely."""


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
            detect=[cwd / ".vscode"],
        ),
        "kiro": Client(
            name="Kiro",
            config_path=cwd / ".kiro" / "settings" / "mcp.json",
            project_level=True,
            detect=[cwd / ".kiro", home / ".kiro"],
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
            detect=[cwd / ".junie"],
        ),
        # CLI tools
        "claude-code": Client(
            name="Claude Code",
            config_path=cwd / ".mcp.json",
            project_level=True,
            detect=[cwd / ".mcp.json", home / ".claude"],
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


def _project_python(project_dir: Path) -> Optional[Path]:
    """The project's own virtualenv Python, if it has one."""
    for candidate in (
        project_dir / ".venv" / "bin" / "python",
        project_dir / ".venv" / "Scripts" / "python.exe",
    ):
        if candidate.exists():
            return candidate
    return None


def get_server_entry(name: str, project_dir: Path) -> dict:
    """Build the MCP server config entry for a project.

    The server needs the project's own dependencies, not mcp-forge's, so the
    entry runs it with ``uv run --directory <project>`` when uv is installed,
    or with the project's ``.venv`` Python. Failing both it falls back to
    ``python3``, which only works if ``mcp`` is installed for that Python.

    Args:
        name: Server name.
        project_dir: Absolute path to the project directory.

    Returns:
        Dict with 'command' and 'args' keys.
    """
    uv = shutil.which("uv")
    if uv:
        return {
            "command": uv,
            "args": ["run", "--directory", str(project_dir), "python", "server.py"],
        }
    venv_python = _project_python(project_dir)
    if venv_python:
        return {"command": str(venv_python), "args": [str(project_dir / "server.py")]}
    return {"command": "python3", "args": [str(project_dir / "server.py")]}


def list_clients() -> List[str]:
    """Return sorted list of supported client keys."""
    return sorted(_get_clients().keys())


def detect_clients(specific: Optional[str] = None) -> Dict[str, Client]:
    """Detect which MCP clients are installed.

    Global clients count as installed when their config directory exists.
    Project-level clients count when the project already has their config
    directory (or, for Claude Code, when ~/.claude exists), so a bare
    ``mcp-forge install`` doesn't create config for editors you don't use.

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
        # A project-level config can always be created on request
        if client.project_level or _in_use(client):
            return {specific: client}
        return {}

    return {key: client for key, client in clients.items() if _in_use(client)}


def _in_use(client: Client) -> bool:
    """Whether the client looks installed or already used for this project."""
    paths = client.detect or [client.config_path.parent]
    return any(path.exists() for path in paths)


def install_in_client(
    client: Client,
    server_name: str,
    entry: dict,
    force: bool = False,
    dry_run: bool = False,
) -> bool:
    """Install an MCP server entry into a client's config file.

    Args:
        client: The target client.
        server_name: Name for the server entry.
        entry: The server config dict (command + args).
        force: If True, overwrite existing entries.
        dry_run: If True, check everything but write nothing.

    Returns:
        True if installed (or would be), False if skipped (existing entry, no force).

    Raises:
        ConfigError: If the existing config isn't plain JSON with the expected
            shape. The file is left untouched.
    """
    config_path = client.config_path
    config_key = client.config_key

    existing_text = None
    if config_path.exists():
        existing_text = config_path.read_text()
        try:
            config = json.loads(existing_text) if existing_text.strip() else {}
        except json.JSONDecodeError as exc:
            raise ConfigError(
                f"{config_path} is not plain JSON (line {exc.lineno}: {exc.msg}). "
                "It may contain comments; add the entry by hand."
            ) from exc
    else:
        config = {}

    if not isinstance(config, dict):
        raise ConfigError(f"{config_path} does not contain a JSON object.")
    servers = config.setdefault(config_key, {})
    if not isinstance(servers, dict):
        raise ConfigError(f'"{config_key}" in {config_path} is not a JSON object.')

    if server_name in servers and not force:
        return False
    if dry_run:
        return True

    servers[server_name] = entry
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if existing_text is not None:
        backup_path = config_path.with_suffix(config_path.suffix + ".bak")
        backup_path.write_text(existing_text)
    config_path.write_text(json.dumps(config, indent=2) + "\n")

    return True
