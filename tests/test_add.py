from pathlib import Path

import pytest

from mcp_forge.add import add_feature, list_features


class TestListFeatures:
    def test_returns_all_features(self):
        features = list_features()
        assert len(features) == 5
        assert set(features.keys()) == {
            "resources",
            "prompts",
            "elicitation",
            "context",
            "auth",
        }

    def test_features_have_descriptions(self):
        for name, feat in list_features().items():
            assert feat.description, f"Feature {name} missing description"

    def test_elicitation_has_pydantic_dep(self):
        features = list_features()
        assert "pydantic>=2.0.0" in features["elicitation"].deps


def _make_project(tmp_path: Path, *, with_main_block: bool = True) -> Path:
    """Helper to create a minimal project directory."""
    project_dir = tmp_path / "my-server"
    project_dir.mkdir()

    server_lines = [
        'from mcp.server.fastmcp import FastMCP\n',
        '\n',
        'mcp = FastMCP("my-server")\n',
        '\n',
        '\n',
        '@mcp.tool()\n',
        'def hello(name: str) -> str:\n',
        '    return f"Hello, {name}!"\n',
        '\n',
        '\n',
    ]
    if with_main_block:
        server_lines += [
            'if __name__ == "__main__":\n',
            '    main()\n',
        ]

    (project_dir / "server.py").write_text("".join(server_lines))
    (project_dir / "pyproject.toml").write_text(
        '[project]\n'
        'name = "my-server"\n'
        'version = "0.1.0"\n'
        'dependencies = [\n'
        '    "mcp[cli]>=1.6.0",\n'
        ']\n'
    )
    return project_dir


class TestAddFeature:
    def test_inserts_snippet_before_main_block(self, tmp_path):
        project_dir = _make_project(tmp_path)
        add_feature("resources", project_dir)
        content = (project_dir / "server.py").read_text()
        # Snippet should appear before the if __name__ block
        assert "@mcp.resource" in content
        main_pos = content.index('if __name__')
        resource_pos = content.index("@mcp.resource")
        assert resource_pos < main_pos

    def test_appends_if_no_main_block(self, tmp_path):
        project_dir = _make_project(tmp_path, with_main_block=False)
        add_feature("resources", project_dir)
        content = (project_dir / "server.py").read_text()
        assert "@mcp.resource" in content

    def test_adds_deps_to_pyproject(self, tmp_path):
        project_dir = _make_project(tmp_path)
        add_feature("elicitation", project_dir)
        content = (project_dir / "pyproject.toml").read_text()
        assert "pydantic>=2.0.0" in content

    def test_skips_existing_deps(self, tmp_path):
        project_dir = _make_project(tmp_path)
        # Add pydantic manually
        pyproject = project_dir / "pyproject.toml"
        pyproject.write_text(
            '[project]\n'
            'name = "my-server"\n'
            'version = "0.1.0"\n'
            'dependencies = [\n'
            '    "mcp[cli]>=1.6.0",\n'
            '    "pydantic>=2.0.0",\n'
            ']\n'
        )
        add_feature("elicitation", project_dir)
        content = pyproject.read_text()
        assert content.count("pydantic") == 1

    def test_raises_for_unknown_feature(self, tmp_path):
        project_dir = _make_project(tmp_path)
        with pytest.raises(ValueError, match="Unknown feature"):
            add_feature("nonexistent", project_dir)

    def test_raises_if_no_server_py(self, tmp_path):
        project_dir = tmp_path / "empty-project"
        project_dir.mkdir()
        (project_dir / "pyproject.toml").write_text(
            '[project]\nname = "empty"\ndependencies = []\n'
        )
        with pytest.raises(FileNotFoundError):
            add_feature("resources", project_dir)

    def test_replaces_name_placeholder(self, tmp_path):
        project_dir = _make_project(tmp_path)
        add_feature("context", project_dir)
        content = (project_dir / "server.py").read_text()
        # Should not contain raw placeholder
        assert "{{name}}" not in content

    def test_add_multiple_features(self, tmp_path):
        project_dir = _make_project(tmp_path)
        add_feature("resources", project_dir)
        add_feature("prompts", project_dir)
        add_feature("context", project_dir)
        content = (project_dir / "server.py").read_text()
        assert "@mcp.resource" in content
        assert "@mcp.prompt" in content
        assert "process_data" in content
        # All should be before if __name__
        main_pos = content.index('if __name__')
        assert content.index("@mcp.resource") < main_pos
        assert content.index("@mcp.prompt") < main_pos
        assert content.index("process_data") < main_pos
