from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER_PATH = str(Path(__file__).parent.parent / "server.py")


@pytest.fixture
async def client():
    server_params = StdioServerParameters(
        command="python3",
        args=[SERVER_PATH],
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


@pytest.mark.anyio
async def test_hello(client):
    result = await client.call_tool("hello", {"name": "World"})
    assert "Hello, World!" in result.content[0].text


@pytest.mark.anyio
async def test_list_tools(client):
    tools = await client.list_tools()
    tool_names = [t.name for t in tools.tools]
    assert "hello" in tool_names
