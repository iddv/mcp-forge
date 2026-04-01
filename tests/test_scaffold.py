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
        assert 'FastMCP("my-server"' in content
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

    def test_refuses_existing_directory(self, tmp_path):
        (tmp_path / "my-server").mkdir()
        with pytest.raises(FileExistsError):
            scaffold_project("my-server", str(tmp_path))

    def test_refuses_invalid_name(self, tmp_path):
        with pytest.raises(ValueError):
            scaffold_project("bad name!", str(tmp_path))
