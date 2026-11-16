import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from typer.testing import CliRunner

from mcp_forge.cli import app
from mcp_forge.install import (
    Client,
    ConfigError,
    detect_clients,
    get_server_entry,
    install_in_client,
    list_clients,
)


class TestGetServerEntry:
    def test_uses_uv_when_available(self, tmp_path):
        with patch("mcp_forge.install.shutil.which", return_value="/usr/bin/uv"):
            entry = get_server_entry("my-server", tmp_path)
        assert entry == {
            "command": "/usr/bin/uv",
            "args": ["run", "--directory", str(tmp_path), "python", "server.py"],
        }

    def test_uses_project_venv_without_uv(self, tmp_path):
        python = tmp_path / ".venv" / "bin" / "python"
        python.parent.mkdir(parents=True)
        python.touch()
        with patch("mcp_forge.install.shutil.which", return_value=None):
            entry = get_server_entry("my-server", tmp_path)
        assert entry == {"command": str(python), "args": [str(tmp_path / "server.py")]}

    def test_never_uses_mcp_forges_own_python(self, tmp_path):
        with patch("mcp_forge.install.shutil.which", return_value=None):
            entry = get_server_entry("my-server", tmp_path)
        assert entry["command"] != sys.executable
        assert entry == {"command": "python3", "args": [str(tmp_path / "server.py")]}


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
    def test_project_level_not_detected_without_marker(self, tmp_path):
        with patch("mcp_forge.install.CLIENTS", {
            "vscode": Client(
                name="VS Code",
                config_path=tmp_path / ".vscode" / "mcp.json",
                project_level=True,
                detect=[tmp_path / ".vscode"],
            ),
        }):
            assert detect_clients() == {}

    def test_project_level_detected_with_marker(self, tmp_path):
        (tmp_path / ".vscode").mkdir()
        with patch("mcp_forge.install.CLIENTS", {
            "vscode": Client(
                name="VS Code",
                config_path=tmp_path / ".vscode" / "mcp.json",
                project_level=True,
                detect=[tmp_path / ".vscode"],
            ),
        }):
            assert "vscode" in detect_clients()

    def test_claude_code_detected_from_home(self, tmp_path):
        (tmp_path / "home" / ".claude").mkdir(parents=True)
        with patch("mcp_forge.install.CLIENTS", {
            "claude-code": Client(
                name="Claude Code",
                config_path=tmp_path / "project" / ".mcp.json",
                project_level=True,
                detect=[tmp_path / "project" / ".mcp.json", tmp_path / "home" / ".claude"],
            ),
        }):
            assert "claude-code" in detect_clients()

    def test_project_level_specific(self, tmp_path):
        with patch("mcp_forge.install.CLIENTS", {
            "vscode": Client(
                name="VS Code",
                config_path=tmp_path / ".vscode" / "mcp.json",
                project_level=True,
                detect=[tmp_path / ".vscode"],
            ),
        }):
            found = detect_clients(specific="vscode")
            assert "vscode" in found


class TestConfigErrors:
    def _client(self, path, key="mcpServers"):
        return Client(name="Test", config_path=path, config_key=key)

    def test_jsonc_raises_and_leaves_file_alone(self, tmp_path):
        config_path = tmp_path / "settings.json"
        original = '{\n  // my settings\n  "theme": "dark"\n}\n'
        config_path.write_text(original)
        with pytest.raises(ConfigError, match="not plain JSON"):
            install_in_client(self._client(config_path), "s", {"command": "x"})
        assert config_path.read_text() == original
        assert not config_path.with_suffix(".json.bak").exists()

    def test_non_object_root(self, tmp_path):
        config_path = tmp_path / "mcp.json"
        config_path.write_text("[]")
        with pytest.raises(ConfigError):
            install_in_client(self._client(config_path), "s", {"command": "x"})

    def test_non_object_servers(self, tmp_path):
        config_path = tmp_path / "mcp.json"
        config_path.write_text('{"mcpServers": []}')
        with pytest.raises(ConfigError):
            install_in_client(self._client(config_path), "s", {"command": "x"})

    def test_empty_file_is_treated_as_empty_config(self, tmp_path):
        config_path = tmp_path / "mcp.json"
        config_path.write_text("")
        assert install_in_client(self._client(config_path), "s", {"command": "x"})
        assert json.loads(config_path.read_text()) == {"mcpServers": {"s": {"command": "x"}}}


class TestDryRun:
    def test_writes_nothing(self, tmp_path):
        config_path = tmp_path / "sub" / "mcp.json"
        client = Client(name="Test", config_path=config_path)
        assert install_in_client(client, "s", {"command": "x"}, dry_run=True)
        assert not config_path.parent.exists()


class TestInstallCommand:
    def _project(self, tmp_path):
        project = tmp_path / "my-server"
        project.mkdir()
        (project / "server.py").write_text("")
        return project

    def test_continues_past_a_broken_config(self, tmp_path, monkeypatch):
        project = self._project(tmp_path)
        monkeypatch.chdir(project)
        broken = tmp_path / "zed" / "settings.json"
        broken.parent.mkdir()
        broken.write_text("{ // comment\n}")
        good = tmp_path / "cursor" / "mcp.json"
        good.parent.mkdir()
        clients = {
            "zed": Client(name="Zed", config_path=broken, config_key="context_servers"),
            "cursor": Client(name="Cursor", config_path=good),
        }
        with patch("mcp_forge.install.CLIENTS", clients):
            result = CliRunner().invoke(app, ["install"])
        assert result.exit_code == 1
        assert "Zed" in result.output and "not plain JSON" in result.output
        assert "my-server" in json.loads(good.read_text())["mcpServers"]

    def test_dry_run_changes_nothing(self, tmp_path, monkeypatch):
        project = self._project(tmp_path)
        monkeypatch.chdir(project)
        config = tmp_path / "cursor" / "mcp.json"
        config.parent.mkdir()
        with patch("mcp_forge.install.CLIENTS", {"cursor": Client(name="Cursor", config_path=config)}):
            result = CliRunner().invoke(app, ["install", "--dry-run"])
        assert result.exit_code == 0, result.output
        assert "Would install" in result.output
        assert not config.exists()


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
