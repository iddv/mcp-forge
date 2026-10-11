from pathlib import Path

import pytest

from mcp_forge.add import FEATURES, add_feature, list_features


class TestListFeatures:
    def test_returns_all_features(self):
        features = list_features()
        assert set(features.keys()) == {
            "resources",
            "resource-templates",
            "prompts",
            "completions",
            "annotations",
            "structured-output",
            "media",
            "context",
            "elicitation",
            "sampling",
            "roots",
            "lifespan",
            "http",
            "auth",
            "apps",
            "skill",
            "plugin",
            "mcpb",
            "registry",
        }

    def test_requires_reference_known_features(self):
        for name, feat in list_features().items():
            for required in feat.requires:
                assert required in FEATURES, f"{name} requires unknown {required}"

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
        'from mcp.server.mcpserver import MCPServer\n',
        '\n',
        'mcp = MCPServer("my-server", instructions="Test server")\n',
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
        '    "mcp[cli]>=2.3,<3",\n'
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
            '    "mcp[cli]>=2.3,<3",\n'
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

    def test_add_is_idempotent(self, tmp_path):
        project_dir = _make_project(tmp_path)
        first = add_feature("prompts", project_dir)
        second = add_feature("prompts", project_dir)
        assert first.added == ["prompts"]
        assert second.added == [] and second.skipped == ["prompts"]
        assert (project_dir / "server.py").read_text().count("@mcp.prompt") == 1

    def test_required_features_are_added(self, tmp_path):
        project_dir = _make_project(tmp_path)
        result = add_feature("auth", project_dir)
        assert result.added == ["http", "auth"]
        assert "mcp-forge:http" in (project_dir / "server.py").read_text()


class TestServerConstructor:
    def test_pre_snippet_goes_before_constructor(self, tmp_path):
        project_dir = _make_project(tmp_path)
        add_feature("lifespan", project_dir)
        content = (project_dir / "server.py").read_text()
        assert content.index("async def app_lifespan") < content.index("mcp = MCPServer(")
        assert content.index("def cache_get") > content.index("mcp = MCPServer(")

    def test_kwargs_added_and_existing_preserved(self, tmp_path):
        project_dir = _make_project(tmp_path)
        add_feature("lifespan", project_dir)
        add_feature("apps", project_dir)
        content = (project_dir / "server.py").read_text()
        assert (
            'mcp = MCPServer(\n'
            '    "my-server",\n'
            '    instructions="Test server",\n'
            '    lifespan=app_lifespan,\n'
            '    extensions=[apps],\n'
            ')\n'
        ) in content

    def test_kwargs_not_duplicated(self, tmp_path):
        project_dir = _make_project(tmp_path)
        server_py = project_dir / "server.py"
        server_py.write_text(server_py.read_text().replace(
            'instructions="Test server")', 'instructions="Test server", lifespan=my_lifespan)'
        ))
        add_feature("lifespan", project_dir)
        content = server_py.read_text()
        assert "lifespan=my_lifespan" in content
        assert "lifespan=app_lifespan" not in content

    def test_generated_server_is_valid_python(self, tmp_path):
        import ast

        project_dir = _make_project(tmp_path)
        for name, feat in FEATURES.items():
            if feat.kind == "protocol":
                add_feature(name, project_dir)
        ast.parse((project_dir / "server.py").read_text())


class TestMain:
    def test_http_replaces_default_main(self, tmp_path):
        from mcp_forge.scaffold import scaffold_project

        project_dir = scaffold_project("my-server", str(tmp_path))
        add_feature("http", project_dir)
        content = (project_dir / "server.py").read_text()
        assert '"--http"' in content
        assert 'transport="streamable-http"' in content
        assert content.count("def main():") == 1

    def test_http_keeps_custom_main(self, tmp_path):
        from mcp_forge.scaffold import scaffold_project

        project_dir = scaffold_project("my-server", str(tmp_path))
        server_py = project_dir / "server.py"
        server_py.write_text(server_py.read_text().replace("    mcp.run()\n", "    mcp.run()  # custom\n"))
        add_feature("http", project_dir)
        content = server_py.read_text()
        assert "# custom" in content
        assert '"--http"' not in content
