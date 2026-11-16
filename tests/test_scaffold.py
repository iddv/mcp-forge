import os
from pathlib import Path

import pytest

from mcp_forge.scaffold import scaffold_project, validate_name


class TestValidateName:
    def test_valid_name(self):
        assert validate_name("my-server") is True

    def test_valid_name_underscores(self):
        assert validate_name("my_server") is True

    def test_valid_name_alphanumeric(self):
        assert validate_name("server1") is True

    def test_invalid_name_spaces(self):
        assert validate_name("my server") is False

    def test_invalid_name_special_chars(self):
        assert validate_name("my@server") is False

    def test_invalid_name_empty(self):
        assert validate_name("") is False


class TestScaffoldProject:
    def test_creates_directory(self, tmp_path):
        project_dir = tmp_path / "my-server"
        scaffold_project("my-server", str(tmp_path))
        assert project_dir.is_dir()

    def test_creates_server_py(self, tmp_path):
        scaffold_project("my-server", str(tmp_path))
        server_py = tmp_path / "my-server" / "server.py"
        assert server_py.exists()
        content = server_py.read_text()
        assert 'MCPServer("my-server"' in content
        assert "from mcp.server.mcpserver import MCPServer" in content
        assert "def main():" in content

    def test_creates_pyproject_toml(self, tmp_path):
        scaffold_project("my-server", str(tmp_path))
        pyproject = tmp_path / "my-server" / "pyproject.toml"
        assert pyproject.exists()
        content = pyproject.read_text()
        assert 'name = "my-server"' in content
        assert 'mcp[cli]' in content

    def test_creates_test_file(self, tmp_path):
        scaffold_project("my-server", str(tmp_path))
        test_file = tmp_path / "my-server" / "tests" / "test_server.py"
        assert test_file.exists()
        content = test_file.read_text()
        assert "test_hello" in content

    def test_creates_gitignore(self, tmp_path):
        scaffold_project("my-server", str(tmp_path))
        gitignore = tmp_path / "my-server" / ".gitignore"
        assert gitignore.exists()

    def test_creates_env_example(self, tmp_path):
        scaffold_project("my-server", str(tmp_path))
        env = tmp_path / "my-server" / ".env.example"
        assert env.exists()

    def test_creates_readme(self, tmp_path):
        scaffold_project("my-server", str(tmp_path))
        readme = tmp_path / "my-server" / "README.md"
        assert readme.exists()
        content = readme.read_text()
        assert "my-server" in content

    def test_custom_description(self, tmp_path):
        scaffold_project("my-server", str(tmp_path), description="A cool server")
        server_py = tmp_path / "my-server" / "server.py"
        content = server_py.read_text()
        assert "A cool server" in content

    def test_description_with_quotes_and_backslashes(self, tmp_path):
        import ast

        description = 'Says "hi" from C:\\temp'
        project_dir = scaffold_project("my-server", str(tmp_path), description=description)
        ast.parse((project_dir / "server.py").read_text())
        pyproject = (project_dir / "pyproject.toml").read_text()
        try:
            import tomllib
        except ModuleNotFoundError:  # Python 3.10
            assert 'description = "Says \\"hi\\" from C:\\\\temp"' in pyproject
        else:
            assert tomllib.loads(pyproject)["project"]["description"] == description

    def test_refuses_existing_directory(self, tmp_path):
        (tmp_path / "my-server").mkdir()
        with pytest.raises(FileExistsError):
            scaffold_project("my-server", str(tmp_path))

    def test_refuses_invalid_name(self, tmp_path):
        with pytest.raises(ValueError):
            scaffold_project("bad name!", str(tmp_path))


class TestNewCommand:
    def test_unknown_feature_fails_before_creating_anything(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner

        from mcp_forge.cli import app

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["new", "my-server", "--with", "resources,bogus"])
        assert result.exit_code == 1
        assert "bogus" in result.output
        assert not (tmp_path / "my-server").exists()


class TestVersion:
    def test_plugin_manifest_matches_package_version(self):
        import json

        from mcp_forge import __version__

        root = Path(__file__).resolve().parent.parent
        plugin = json.loads((root / ".claude-plugin" / "plugin.json").read_text())
        assert plugin["version"] == __version__
