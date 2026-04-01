# MCP-Forge v2: MCP Server Scaffolding CLI

## Overview

MCP-Forge is a CLI tool that scaffolds MCP server projects with sane defaults and helps developers run, test, and install them into MCP clients. It replaces the current 15K LOC "dynamic server generator" with a focused ~500 LOC scaffolding tool.

**Philosophy:** FastMCP already makes writing MCP servers easy. MCP-Forge packages the "getting started" experience — the right project structure, the right config, the right dev workflow. Then it gets out of the way.

## Commands

### `mcp-forge new <name>`

Scaffolds a new MCP server project.

```bash
mcp-forge new my-server
cd my-server
```

**Generated project structure:**

```
my-server/
  server.py           # FastMCP server with one example tool
  pyproject.toml       # Package config with fastmcp dependency
  .env.example         # Environment variable template
  README.md            # Quick start instructions
  tests/
    test_server.py     # Basic test using mcp SDK client
  .gitignore           # Python defaults + .env
```

**server.py contents (example):**

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("my-server", description="My MCP server")

@mcp.tool()
def hello(name: str) -> str:
    """Say hello to someone."""
    return f"Hello, {name}!"

if __name__ == "__main__":
    mcp.run()
```

**pyproject.toml contents:**

```toml
[project]
name = "my-server"
version = "0.1.0"
description = "An MCP server"
requires-python = ">=3.10"
dependencies = [
    "mcp[cli]>=1.6.0",
]

[project.scripts]
my-server = "server:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

**test_server.py contents:**

```python
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

@pytest.fixture
async def client():
    server_params = StdioServerParameters(
        command="python",
        args=["server.py"],
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
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--description` / `-d` | Server description | "An MCP server" |
| `--transport` | Transport type: `stdio` or `sse` | `stdio` |

Stdio is the default because it's what most MCP clients expect and requires zero network configuration.

### `mcp-forge dev`

Runs the MCP server in development mode with the MCP Inspector attached.

```bash
cd my-server
mcp-forge dev
```

**What it does:**

1. Starts the MCP server via `python server.py`
2. Launches `npx @modelcontextprotocol/inspector` pointed at the server process
3. Opens the inspector UI URL in the default browser
4. Watches `server.py` for changes and restarts the server (using `watchfiles` or similar)

**Implementation detail:** The inspector already handles stdio transport natively — `npx @modelcontextprotocol/inspector python server.py` does the right thing. So `mcp-forge dev` is essentially a wrapper that:
- Checks that `npx` is available (warn if not, fall back to running server only)
- Passes the right command to the inspector
- Adds file watching for hot-reload (restarts the inspector process on file changes)

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--no-inspector` | Run server only, skip inspector | false |
| `--port` | Inspector UI port | 5173 |
| `--no-open` | Don't auto-open browser | false |

**Prerequisites:** Node.js/npx must be installed for the inspector. If not found, `mcp-forge dev` prints a clear message and falls back to running the server directly with `python server.py`.

### `mcp-forge install`

Registers the current MCP server in one or more MCP client configurations.

```bash
cd my-server
mcp-forge install                  # auto-detect clients, install in all found
mcp-forge install --client claude  # just Claude Desktop
mcp-forge install --client cursor  # just Cursor
```

**Supported clients (v1):**

| Client | Config file location | Format |
|--------|---------------------|--------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%/Claude/claude_desktop_config.json` (Windows), `~/.config/Claude/claude_desktop_config.json` (Linux) | JSON |
| Cursor | `~/.cursor/mcp.json` | JSON |
| Claude Code | `~/.claude.json` or project `.mcp.json` | JSON |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | JSON |

**What it writes:**

For a stdio server in `/home/user/my-server`:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "python",
      "args": ["/home/user/my-server/server.py"]
    }
  }
}
```

**Behavior:**
- Auto-detects which clients are installed by checking if config files/directories exist
- If the server name already exists in the config, prompts to overwrite
- Creates a backup of the config file before modifying it (`.bak`)
- Uses absolute paths so the server works from anywhere
- `--client` flag limits installation to a specific client
- Prints a summary of what was installed where

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--client` / `-c` | Target a specific client | auto-detect all |
| `--name` | Override the server name in config | project directory name |
| `--force` | Overwrite existing entries without prompting | false |
| `--uninstall` | Remove the server from client configs | false |

## Package Structure

```
mcp-forge/
  pyproject.toml
  README.md
  LICENSE
  src/
    mcp_forge/
      __init__.py        # version
      cli.py             # click/typer CLI entry point (~150 lines)
      scaffold.py        # project generation (~100 lines)
      dev.py             # dev server + inspector launcher (~80 lines)
      install.py         # client config management (~150 lines)
      templates/         # embedded template files
        server.py.tpl
        pyproject.toml.tpl
        test_server.py.tpl
        env.example.tpl
        gitignore.tpl
        readme.md.tpl
  tests/
    test_scaffold.py
    test_install.py
    test_dev.py
```

**Estimated total:** ~500 lines of application code.

## Dependencies

```toml
dependencies = [
    "typer>=0.9.0",        # CLI framework
    "rich>=13.0.0",        # Terminal output
    "watchfiles>=0.20.0",  # File watching for dev mode
]
```

Minimal. No FastMCP dependency in the CLI itself — it only appears in the generated project's deps.

## Distribution

- Published to PyPI as `mcp-forge`
- Installable via `pip install mcp-forge` or `pipx install mcp-forge`
- Single entry point: `mcp-forge` command

## What We're Deleting

The entire existing codebase (~15K LOC) is replaced:

- `forge_mcp_server.py` (2,427 LOC) — gone
- `server_manager.py`, `auto_scaler.py`, `process_monitor.py` — gone
- `authentication_system.py`, `protection_mechanisms.py`, `quota_manager.py` — gone
- `alerting_system.py`, `metrics_collector.py`, `status_reporter.py` — gone
- `storage_manager.py`, `config_manager.py`, `runtime_configurator.py` — gone
- `audit_logger.py`, `request_validator.py`, `logging_system.py` — gone
- `client.py`, `meta_mcp_server.py`, `progress_tracker.py` — gone

We keep: the repo, the git history, the README (rewritten), the LICENSE.

## Future Extensions (NOT in v1)

- TypeScript server scaffolding (`mcp-forge new --lang typescript`)
- Additional templates (`mcp-forge new --template api-wrapper`)
- `mcp-forge test` — run the generated tests
- `mcp-forge publish` — package for distribution
- Community template registry

These are documented here for direction but explicitly excluded from the initial build.

## Success Criteria

1. `pip install mcp-forge && mcp-forge new my-server && cd my-server && mcp-forge dev` works end-to-end in under 30 seconds
2. Generated project is a valid, runnable MCP server out of the box
3. Generated tests pass out of the box
4. `mcp-forge install` correctly modifies at least Claude Desktop and Cursor configs
5. The entire CLI is under 600 lines of code
6. Zero configuration required for basic usage
