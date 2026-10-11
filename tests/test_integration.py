"""End-to-end: scaffold a project, add every feature, and exercise it with a real MCP client.

Skipped unless the ``mcp`` SDK (2.x) is installed.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp")
pytest.importorskip("mcp.server.mcpserver", reason="requires mcp>=2")

from mcp import Client  # noqa: E402
from mcp import types  # noqa: E402

from mcp_forge.add import FEATURES, add_feature  # noqa: E402
from mcp_forge.scaffold import scaffold_project  # noqa: E402

PROTOCOL_FEATURES = [name for name, f in FEATURES.items() if f.kind == "protocol"]


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="module")
def project(tmp_path_factory) -> Path:
    project_dir = scaffold_project("forge-test", str(tmp_path_factory.mktemp("proj")))
    for name in FEATURES:
        add_feature(name, project_dir)
    return project_dir


@pytest.fixture(scope="module")
def server(project):
    spec = importlib.util.spec_from_file_location("forge_test_server", project / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.mcp


async def _elicitation_callback(context, params):
    return types.ElicitResult(action="accept", content={"message": "great", "rating": 5})


async def _sampling_callback(context, params):
    return types.CreateMessageResult(
        role="assistant",
        content=types.TextContent(type="text", text="autumn leaves fall"),
        model="test-model",
    )


async def _list_roots_callback(context):
    return types.ListRootsResult(roots=[types.Root(uri="file:///workspace", name="workspace")])


@pytest.fixture(params=["auto", "legacy"], ids=["2026-07-28", "handshake"])
async def client(server, request):
    # "auto" negotiates the stateless 2026-07-28 protocol (Multi Round-Trip Requests);
    # "legacy" forces the initialize handshake with live server-to-client requests.
    async with Client(
        server,
        mode=request.param,
        elicitation_callback=_elicitation_callback,
        sampling_callback=_sampling_callback,
        list_roots_callback=_list_roots_callback,
    ) as client:
        yield client


def _text(result) -> str:
    assert not result.is_error, result
    return result.content[0].text


def test_generated_server_compiles(project):
    subprocess.run([sys.executable, "-m", "py_compile", str(project / "server.py")], check=True)


def test_generated_test_suite_passes(project):
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        cwd=project, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.anyio
async def test_all_tools_listed(client):
    names = {tool.name for tool in (await client.list_tools()).tools}
    assert {
        "hello", "process_data", "collect_feedback", "read_note", "delete_note", "get_weather",
        "write_haiku", "list_workspace_roots", "cache_put", "cache_get", "render_chart",
        "generate_report", "show_dashboard",
    } <= names


@pytest.mark.anyio
async def test_annotations(client):
    tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    assert tools["read_note"].annotations.read_only_hint is True
    assert tools["read_note"].title == "Read note"
    assert tools["delete_note"].annotations.destructive_hint is True


@pytest.mark.anyio
async def test_structured_output(client):
    tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    assert "temperature_c" in tools["get_weather"].output_schema["properties"]
    result = await client.call_tool("get_weather", {"city": "Lisbon"})
    assert result.structured_content["city"] == "Lisbon"


@pytest.mark.anyio
async def test_resources_and_templates(client):
    config = await client.read_resource("config://app")
    assert json.loads(config.contents[0].text)["version"] == "0.1.0"
    templates = (await client.list_resource_templates()).resource_templates
    assert any(t.uri_template == "users://{user_id}/profile" for t in templates)
    profile = await client.read_resource("users://1/profile")
    assert json.loads(profile.contents[0].text)["name"] == "Ada Lovelace"


@pytest.mark.anyio
async def test_prompts_and_completions(client):
    prompt = await client.get_prompt("summarize", {"text": "hello"})
    assert "hello" in prompt.messages[0].content.text
    completion = await client.complete(
        types.PromptReference(type="ref/prompt", name="code_review"),
        argument={"name": "language", "value": "py"},
    )
    assert completion.completion.values == ["python"]


@pytest.mark.anyio
async def test_context_progress(client):
    progress = []

    async def on_progress(value, total, message):
        progress.append(value)

    result = await client.call_tool("process_data", {"items": ["a", "b"]}, progress_callback=on_progress)
    assert "A, B" in _text(result)
    assert progress == [1, 2]


@pytest.mark.anyio
async def test_elicitation(client):
    result = await client.call_tool("collect_feedback", {})
    assert _text(result) == "Thanks! You rated us 5/5: great"


@pytest.mark.anyio
async def test_sampling(client):
    result = await client.call_tool("write_haiku", {"topic": "autumn"})
    assert _text(result) == "autumn leaves fall"


@pytest.mark.anyio
async def test_roots(client):
    result = await client.call_tool("list_workspace_roots", {})
    assert result.structured_content == {"result": ["file:///workspace"]}


@pytest.mark.anyio
async def test_lifespan(client):
    await client.call_tool("cache_put", {"key": "k", "value": "v"})
    assert _text(await client.call_tool("cache_get", {"key": "k"})) == "v"


@pytest.mark.anyio
async def test_media(client):
    image = await client.call_tool("render_chart", {})
    assert image.content[0].type == "image"
    assert image.content[0].mime_type == "image/png"
    report = await client.call_tool("generate_report", {})
    assert report.content[1].type == "resource_link"
    assert str(report.content[1].uri) == "reports://latest"


@pytest.mark.anyio
async def test_apps(client):
    tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    assert tools["show_dashboard"].meta["ui"]["resourceUri"] == "ui://forge-test/dashboard.html"
    html = await client.read_resource("ui://forge-test/dashboard.html")
    assert "<h1>forge-test</h1>" in html.contents[0].text


def test_http_routes(server):
    from starlette.testclient import TestClient

    with TestClient(server.streamable_http_app()) as http:
        assert http.get("/health").json() == {"status": "ok"}
        # auth: unauthenticated MCP requests are rejected and point at the resource metadata
        response = http.post("/mcp", json={})
        assert response.status_code == 401
        assert "resource_metadata" in response.headers["www-authenticate"]


def test_distribution_files(project):
    plugin = json.loads((project / ".claude-plugin" / "plugin.json").read_text())
    assert plugin["name"] == "forge-test"
    assert "${CLAUDE_PLUGIN_ROOT}" in plugin["mcpServers"]["forge-test"]["args"]
    skill = (project / "skills" / "forge-test" / "SKILL.md").read_text()
    assert skill.startswith("---\nname: forge-test\n")
    assert "`get_weather`" in skill
    manifest = json.loads((project / "manifest.json").read_text())
    assert manifest["server"]["type"] == "uv"
    assert {"name": "hello", "description": "Say hello to someone."} in manifest["tools"]
    server_json = json.loads((project / "server.json").read_text())
    assert server_json["packages"][0]["identifier"] == "forge-test"
    assert "<!-- mcp-name: " in (project / "README.md").read_text()
