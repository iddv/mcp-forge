# MCP-Forge v2: MCP Server Scaffolding CLI

## Overview

MCP-Forge is a CLI tool that scaffolds MCP server projects with sane defaults and registers them in MCP client apps. It replaces the current 15K LOC "dynamic server generator" with a focused ~400 LOC scaffolding tool.

**Philosophy:** FastMCP already makes writing MCP servers easy. The `mcp` CLI already handles `dev` (inspector) and `run`. MCP-Forge fills the two gaps: **scaffolding** (no `mcp create` exists) and **multi-client installation** (`mcp install` only targets Claude Desktop).

## Relationship to the `mcp` CLI

The `mcp` package (v1.26.0, via `pip install mcp[cli]`) ships with:

| `mcp` command | What it does |
|---------------|-------------|
| `mcp dev server.py` | Runs server with MCP Inspector |
| `mcp run server.py` | Runs server directly |
| `mcp install server.py` | Registers in Claude Desktop only |

**MCP-Forge does NOT duplicate these.** Instead:
- `mcp-forge new` fills the scaffolding gap — `mcp` has no `create`/`init`/`new` command
- `mcp-forge install` extends `mcp install` to support multiple clients (Cursor, Windsurf, Claude Code, VS Code)
- The generated README tells users to use `mcp dev` for the inspector

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
  pyproject.toml       # Package config with mcp[cli] dependency
  .env.example         # Environment variable template
  README.md            # Quick start instructions (mentions mcp dev)
  tests/
    test_server.py     # Basic test using mcp SDK client
  .gitignore           # Python defaults + .env
```

**server.py contents:**

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("my-server", description="My MCP server")


@mcp.tool()
def hello(name: str) -> str:
    """Say hello to someone."""
    return f"Hello, {name}!"


def main():
    mcp.run()


if __name__ == "__main__":
    main()
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

[project.optional-dependencies]
test = [
    "pytest>=7.0.0",
    "anyio>=4.0.0",
    "pytest-anyio>=0.0.0",
]

[project.scripts]
my-server = "server:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

**test_server.py contents:**

```python
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
```

**Edge cases:**
- If `./my-server/` already exists, refuse with a clear error. No `--force` in v1 — just tell the user to pick a different name or remove the directory.
- Name validation: must be a valid directory name and Python-safe. Allow `[a-zA-Z0-9_-]+`, minimum 1 character. Hyphens in directory names are fine; the `pyproject.toml` uses the name as-is (PEP 625 allows hyphens). The entry point key uses the hyphenated name too.

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--description` / `-d` | Server description | "An MCP server" |

No `--transport` flag in v1. Stdio only — it's what all clients expect. SSE support deferred to future version.

### `mcp-forge install`

Registers the current project's MCP server in one or more client configurations.

```bash
cd my-server
mcp-forge install                  # auto-detect clients, install in all found
mcp-forge install --client claude  # just Claude Desktop
mcp-forge install --client cursor  # just Cursor
```

**Supported clients (v1):**

| Client | Config file location | Format |
|--------|---------------------|--------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `$APPDATA/Claude/claude_desktop_config.json` (Windows), `~/.config/Claude/claude_desktop_config.json` (Linux) | JSON |
| Cursor | `~/.cursor/mcp.json` | JSON |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | JSON |
| Claude Code | project-level `.mcp.json` | JSON |

Note: Windows `%APPDATA%` is resolved via `os.environ.get('APPDATA')` or `Path.home() / 'AppData/Roaming'`, not shell expansion.

**What it writes:**

For a project in `/home/user/my-server`:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "python3",
      "args": ["/home/user/my-server/server.py"]
    }
  }
}
```

The `command` uses `python3` by default. If running inside a virtual environment, it detects this and uses the absolute path to the venv's Python interpreter instead, so the server works regardless of which shell the client spawns.

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

No `--uninstall` in v1. Users can remove entries manually — it's a one-line JSON edit.

## Package Structure

```
mcp-forge/
  pyproject.toml
  README.md
  LICENSE
  src/
    mcp_forge/
      __init__.py        # version
      cli.py             # typer CLI entry point (~100 lines)
      scaffold.py        # project generation (~100 lines)
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
```

**Estimated total:** ~350 lines of application code.

## Dependencies

```toml
dependencies = [
    "typer>=0.16.0",       # CLI framework (matches mcp[cli] typer version)
    "rich>=13.0.0",        # Terminal output (typer dependency anyway)
]
```

No FastMCP dependency in the CLI itself — it only appears in the generated project's deps. No `watchfiles` needed since we dropped the `dev` command.

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
- `mcp-forge dev` — wrapper around `mcp dev` with file watching / hot-reload
- `mcp-forge test` — run the generated tests
- `mcp-forge publish` — package for distribution
- `--transport sse` flag for `new` command
- `--uninstall` flag for `install` command
- Community template registry

These are documented here for direction but explicitly excluded from the initial build.

## Success Criteria

1. `pip install mcp-forge && mcp-forge new my-server && cd my-server && mcp dev server.py` works end-to-end
2. Generated project is a valid, runnable MCP server out of the box
3. Generated tests pass out of the box (`pip install -e ".[test]" && pytest`)
4. `mcp-forge install` correctly modifies at least Claude Desktop and Cursor configs
5. The entire CLI is under 500 lines of code
6. Zero configuration required for basic usage
