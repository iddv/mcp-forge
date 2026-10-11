import pytest
from mcp import Client

from server import mcp


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    # In-process client: no subprocess, speaks the latest protocol revision.
    async with Client(mcp) as client:
        yield client


@pytest.mark.anyio
async def test_hello(client):
    result = await client.call_tool("hello", {"name": "World"})
    assert "Hello, World!" in result.content[0].text


@pytest.mark.anyio
async def test_list_tools(client):
    tools = await client.list_tools()
    tool_names = [t.name for t in tools.tools]
    assert "hello" in tool_names
