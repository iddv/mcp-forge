import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_forge.install import (
    Client,
    detect_clients,
    get_server_entry,
    install_in_client,
    get_python_command,
    list_clients,
)


class TestGetPythonCommand:
    def test_returns_python3_outside_venv(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("mcp_forge.install._in_virtualenv", return_value=False):
                assert get_python_command() == "python3"

    def test_returns_absolute_path_in_venv(self):
        with patch("mcp_forge.install._in_virtualenv", return_value=True):
            cmd = get_python_command()
            assert os.path.isabs(cmd)


class TestGetServerEntry:
    def test_basic_entry(self):
        entry = get_server_entry("my-server", Path("/home/user/my-server"))
        assert entry == {
            "command": entry["command"],  # python3 or abs path
            "args": ["/home/user/my-server/server.py"],
        }

    def test_uses_absolute_path(self):
        entry = get_server_entry("my-server", Path("/home/user/my-server"))
        assert os.path.isabs(entry["args"][0])


class TestDetectClients:
    def test_detects_cursor(self, tmp_path):
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        with patch("mcp_forge.install.CLIENTS", {
            "cursor": Client(
                name="Cursor",
                config_path=cursor_dir / "mcp.json",
            ),
        }):
            found = detect_clients()
            assert "cursor" in found

    def test_ignores_missing_clients(self, tmp_path):
        with patch("mcp_forge.install.CLIENTS", {
            "cursor": Client(
                name="Cursor",
                config_path=tmp_path / "nonexistent" / "mcp.json",
            ),
        }):
            found = detect_clients()
            assert "cursor" not in found


class TestInstallInClient:
    def test_creates_new_config(self, tmp_path):
        config_path = tmp_path / "mcp.json"
        client = Client(name="Cursor", config_path=config_path)
        entry = {"command": "python3", "args": ["/path/to/server.py"]}

        result = install_in_client(client, "my-server", entry, force=False)

        assert result is True
        config = json.loads(config_path.read_text())
        assert config["mcpServers"]["my-server"] == entry

    def test_adds_to_existing_config(self, tmp_path):
        config_path = tmp_path / "mcp.json"
        config_path.write_text(json.dumps({
            "mcpServers": {
                "other-server": {"command": "node", "args": ["index.js"]}
            }
        }))
        client = Client(name="Cursor", config_path=config_path)
        entry = {"command": "python3", "args": ["/path/to/server.py"]}

        result = install_in_client(client, "my-server", entry, force=False)

        assert result is True
        config = json.loads(config_path.read_text())
        assert "other-server" in config["mcpServers"]
        assert "my-server" in config["mcpServers"]

    def test_refuses_overwrite_without_force(self, tmp_path):
        config_path = tmp_path / "mcp.json"
        config_path.write_text(json.dumps({
            "mcpServers": {
                "my-server": {"command": "old", "args": []}
            }
        }))
        client = Client(name="Cursor", config_path=config_path)
        entry = {"command": "python3", "args": ["/path/to/server.py"]}

        result = install_in_client(client, "my-server", entry, force=False)

        assert result is False
        config = json.loads(config_path.read_text())
        assert config["mcpServers"]["my-server"]["command"] == "old"

    def test_overwrites_with_force(self, tmp_path):
        config_path = tmp_path / "mcp.json"
        config_path.write_text(json.dumps({
            "mcpServers": {
                "my-server": {"command": "old", "args": []}
            }
        }))
        client = Client(name="Cursor", config_path=config_path)
        entry = {"command": "python3", "args": ["/path/to/server.py"]}

        result = install_in_client(client, "my-server", entry, force=True)

        assert result is True
        config = json.loads(config_path.read_text())
        assert config["mcpServers"]["my-server"]["command"] == "python3"

    def test_creates_backup(self, tmp_path):
        config_path = tmp_path / "mcp.json"
        config_path.write_text('{"mcpServers": {}}')
        client = Client(name="Cursor", config_path=config_path)
        entry = {"command": "python3", "args": ["/path/to/server.py"]}

        install_in_client(client, "my-server", entry, force=False)

        backup = tmp_path / "mcp.json.bak"
        assert backup.exists()
        assert backup.read_text() == '{"mcpServers": {}}'

    def test_creates_parent_dirs(self, tmp_path):
        config_path = tmp_path / "nested" / "dir" / "mcp.json"
        client = Client(name="Cursor", config_path=config_path)
        entry = {"command": "python3", "args": ["/path/to/server.py"]}

        result = install_in_client(client, "my-server", entry, force=False)

        assert result is True
        assert config_path.exists()

    def test_custom_config_key(self, tmp_path):
        config_path = tmp_path / "mcp.json"
        client = Client(name="VS Code", config_path=config_path, config_key="servers")
        entry = {"command": "python3", "args": ["/path/to/server.py"]}

        install_in_client(client, "my-server", entry, force=False)

        config = json.loads(config_path.read_text())
        assert "servers" in config
        assert "my-server" in config["servers"]
        assert "mcpServers" not in config

    def test_custom_config_key_existing(self, tmp_path):
        config_path = tmp_path / "settings.json"
        config_path.write_text(json.dumps({
            "context_servers": {"old": {}},
            "other_setting": True,
        }))
        client = Client(name="Zed", config_path=config_path, config_key="context_servers")
        entry = {"command": "python3", "args": ["/path/to/server.py"]}

        install_in_client(client, "my-server", entry, force=False)

        config = json.loads(config_path.read_text())
        assert "old" in config["context_servers"]
        assert "my-server" in config["context_servers"]
        assert config["other_setting"] is True


class TestDetectProjectLevel:
    def test_project_level_always_detected(self, tmp_path):
        with patch("mcp_forge.install.CLIENTS", {
            "claude-code": Client(
                name="Claude Code",
                config_path=tmp_path / ".mcp.json",
                project_level=True,
            ),
        }):
            found = detect_clients()
            assert "claude-code" in found

    def test_project_level_specific(self, tmp_path):
        with patch("mcp_forge.install.CLIENTS", {
            "vscode": Client(
                name="VS Code",
                config_path=tmp_path / ".vscode" / "mcp.json",
                project_level=True,
            ),
        }):
            found = detect_clients(specific="vscode")
            assert "vscode" in found


class TestListClients:
    def test_returns_all_clients(self):
        clients = list_clients()
        assert len(clients) >= 12
        assert "claude" in clients
        assert "cursor" in clients
        assert "vscode" in clients
        assert "kiro" in clients
        assert "zed" in clients
        assert "jetbrains" in clients
        assert "claude-code" in clients
        assert "continue" in clients
        assert "cline" in clients
        assert "amazon-q" in clients

    def test_returns_sorted(self):
        clients = list_clients()
        assert clients == sorted(clients)
