import json

from mcp_forge.add import add_feature
from mcp_forge.distribute import read_tools
from mcp_forge.scaffold import scaffold_project


def _project(tmp_path, name="My_Server"):
    return scaffold_project(name, str(tmp_path), description="Does things")


def test_plugin_adds_manifest_marketplace_and_skill(tmp_path):
    project_dir = _project(tmp_path)
    result = add_feature("plugin", project_dir)
    assert result.added == ["skill", "plugin"]

    plugin = json.loads((project_dir / ".claude-plugin" / "plugin.json").read_text())
    assert plugin["name"] == "my-server"  # kebab-case
    server = plugin["mcpServers"]["my-server"]
    assert server["command"] == "uv"
    assert "${CLAUDE_PLUGIN_ROOT}" in server["args"]

    marketplace = json.loads((project_dir / ".claude-plugin" / "marketplace.json").read_text())
    assert marketplace["plugins"][0] == {"name": "my-server", "source": "./", "description": "Does things"}
    assert (project_dir / "skills" / "my-server" / "SKILL.md").exists()


def test_existing_files_are_not_overwritten(tmp_path):
    project_dir = _project(tmp_path)
    skill = project_dir / "skills" / "my-server" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("custom")
    result = add_feature("skill", project_dir)
    assert result.skipped == ["skill"]
    assert skill.read_text() == "custom"


def test_skill_lists_tools(tmp_path):
    project_dir = _project(tmp_path)
    add_feature("annotations", project_dir)
    add_feature("skill", project_dir)
    content = (project_dir / "skills" / "my-server" / "SKILL.md").read_text()
    assert content.startswith("---\nname: my-server\ndescription: ")
    assert "- `hello`: Say hello to someone." in content
    assert "- `read_note`: Read a note by key." in content


def test_read_tools_handles_decorator_kwargs(tmp_path):
    (tmp_path / "server.py").write_text(
        "@mcp.tool\n"
        "def bare():\n"
        '    """Bare decorator."""\n'
        "\n"
        '@apps.tool(resource_uri="ui://x", description="From kwarg", name="renamed")\n'
        "def ui():\n"
        "    pass\n"
        "\n"
        "@mcp.resource('x://y')\n"
        "def not_a_tool():\n"
        "    pass\n"
    )
    tools = read_tools(tmp_path)
    assert [(t.name, t.description) for t in tools] == [("bare", "Bare decorator."), ("renamed", "From kwarg")]


def test_mcpb_manifest(tmp_path):
    project_dir = _project(tmp_path)
    add_feature("mcpb", project_dir)
    manifest = json.loads((project_dir / "manifest.json").read_text())
    assert manifest["manifest_version"] == "0.4"
    assert manifest["server"]["type"] == "uv"
    assert manifest["server"]["entry_point"] == "server.py"
    assert (project_dir / ".mcpbignore").exists()


def test_registry_server_json(tmp_path):
    project_dir = _project(tmp_path)
    add_feature("registry", project_dir)
    server = json.loads((project_dir / "server.json").read_text())
    assert server["name"].endswith("/My_Server")
    assert server["packages"][0]["registryType"] == "pypi"
    readme = (project_dir / "README.md").read_text()
    assert readme.count("<!-- mcp-name: ") == 1
    add_feature("registry", project_dir)
    assert (project_dir / "README.md").read_text().count("<!-- mcp-name: ") == 1
