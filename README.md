# MCP-Forge

Scaffold, extend, install, and distribute MCP servers in seconds.

Generated servers target the official [`mcp` Python SDK](https://github.com/modelcontextprotocol/python-sdk) 2.x
(`MCPServer`) and the 2026-07-28 protocol revision, and stay compatible with handshake-era clients.

## Install

mcp-forge is not on PyPI. The `mcp-forge` package there is an unrelated project, so install from GitHub:

```bash
uv tool install git+https://github.com/iddv/mcp-forge
```

or

```bash
pipx install git+https://github.com/iddv/mcp-forge
```

## Quick Start

```bash
# Scaffold a new MCP server project
mcp-forge new my-server
cd my-server

# Add features
mcp-forge add resources prompts annotations

# Package as a Claude Code plugin (with an Agent Skill)
mcp-forge add plugin

# Register in your MCP clients
mcp-forge install
```

## Commands

### `mcp-forge new <name>`

Create a new FastMCP server project with working tests, dependencies, and a ready-to-run example tool.

```bash
mcp-forge new my-server
cd my-server

# Install, then run with the MCP Inspector
pip install -e ".[test]"
mcp dev server.py

# Run tests (in-process MCP client, no subprocess)
pytest
```

### `mcp-forge add <feature>`

Add MCP capabilities to an existing project. Pass one or more features. Adding a feature that
is already present does nothing, and features pull in what they depend on (e.g. `auth` adds `http`).

```bash
mcp-forge add resources completions   # Several at once
mcp-forge add auth                    # Also adds http
mcp-forge features                    # List everything available
```

### `mcp-forge install`

Register your server in MCP client applications. Auto-detects installed clients or targets a specific one.

```bash
# Auto-detect and install in all found clients
mcp-forge install

# Target a specific client
mcp-forge install --client claude
mcp-forge install --client cursor
mcp-forge install --client vscode
```

## Supported Clients

| Client | Config Location | Scope |
|---|---|---|
| Claude Desktop | Platform-specific | Global |
| Cursor | `~/.cursor/mcp.json` | Global |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | Global |
| VS Code | `.vscode/mcp.json` | Project |
| Kiro | `.kiro/settings/mcp.json` | Project |
| Zed | `~/.config/zed/settings.json` | Global |
| JetBrains | `.junie/mcp.json` | Project |
| Claude Code | `.mcp.json` | Project |
| Continue | `~/.continue/config.json` | Global |
| Cline | `~/Documents/Cline/mcp_settings.json` | Global |
| Roo Code | `~/.roo-code/mcp.json` | Global |
| Amazon Q | `~/.aws/amazonq/mcp.json` | Global |

## Available Features

### Protocol features

| Feature | What it adds |
|---|---|
| `resources` | `@mcp.resource()` endpoint with title and MIME type |
| `resource-templates` | Parameterised resource URIs (`users://{user_id}/profile`) |
| `prompts` | `@mcp.prompt()` template |
| `completions` | `@mcp.completion()` argument autocompletion for prompts and templates |
| `annotations` | Tool `title` and behaviour hints (`read_only_hint`, `destructive_hint`, ...) |
| `structured-output` | Tool returning a pydantic model, giving `outputSchema` and `structuredContent` |
| `media` | Image content and `ResourceLink` results |
| `errors` | `ToolError` for expected failures that the model sees and can recover from |
| `notifications` | Resource-updated and tools-list-changed notifications, with a tool registered at runtime |
| `context` | Progress reporting and request metadata via `Context` |
| `elicitation` | Ask the user for structured input with `Resolve` + `Elicit` |
| `sampling` | Ask the client's LLM with `Resolve` + `Sample` (deprecated in the 2026-07-28 spec) |
| `roots` | Read the client's workspace roots with `Resolve` + `ListRoots` (deprecated in the 2026-07-28 spec) |
| `lifespan` | Typed startup/shutdown context shared with every request |
| `middleware` | Request middleware (timing/audit logging) wrapping every MCP request |
| `http` | Streamable HTTP transport (`python server.py --http [--stateless]`, address via `MCP_HOST`/`MCP_PORT`), a `/health` route, and a shared `MCP_REQUEST_STATE_KEY` for multi-replica deployments |
| `auth` | OAuth 2.1 resource server: `TokenVerifier` + `AuthSettings` (requires `http`; set `MCP_PUBLIC_URL` behind a proxy) |
| `apps` | MCP Apps extension: an interactive `ui://` HTML view bound to a tool |

Elicitation, sampling and roots use `Resolve` parameters rather than calling `ctx.elicit()` directly.
That way they work on both stateless 2026-07-28 connections (Multi Round-Trip Requests) and older clients.

### Distribution features

| Feature | Generates |
|---|---|
| `skill` | `skills/<name>/SKILL.md`: an Agent Skill describing when and how to use the server's tools |
| `plugin` | `.claude-plugin/plugin.json` (bundles the server via `${CLAUDE_PLUGIN_ROOT}`) and `marketplace.json`; also adds `skill` |
| `mcpb` | `manifest.json` + `.mcpbignore` for an [MCP Bundle](https://github.com/modelcontextprotocol/mcpb) (Claude Desktop one-click install) |
| `docker` | `Dockerfile` + `.dockerignore` serving the server over Streamable HTTP (requires `http`) |
| `registry` | `server.json` for the [MCP Registry](https://registry.modelcontextprotocol.io) and the `mcp-name` README marker |

Add distribution features after your tools: `skill` and `mcpb` record the tools present at generation
time. Existing files are never overwritten. Delete a file and re-run `add` to regenerate it.

Once the project is pushed to GitHub, anyone can install the plugin in Claude Code:

```
/plugin marketplace add <you>/<repo>
/plugin install <name>@<name>
```

## Use mcp-forge from Claude Code

This repo is itself a Claude Code plugin. Its `mcp-forge` skill teaches Claude the workflow, the
feature catalogue, and SDK 2.x patterns:

```
/plugin marketplace add iddv/mcp-forge
/plugin install mcp-forge@mcp-forge
```

Then ask Claude to "build an MCP server that ...", or run `/mcp-forge`.

## Generated Project

```
my-server/
  server.py           # MCPServer with an example tool
  pyproject.toml       # Dependencies and entry point
  tests/
    test_server.py     # Async tests using an in-process Client
  .env.example
  .gitignore
  README.md
```

## Upgrading from mcp-forge 2.x

mcp-forge 3 generates code for `mcp` 2.x. Projects created by mcp-forge 2 import
`mcp.server.fastmcp` and declare `mcp[cli]>=1.6.0`, so a fresh install now resolves `mcp` 2.x and fails
to import. Either pin `mcp[cli]>=1.28,<2` in those projects, or migrate them: `FastMCP` becomes
`MCPServer` from `mcp.server.mcpserver`. See the
[SDK migration guide](https://py.sdk.modelcontextprotocol.io/v2/migration/).

## Development

```bash
git clone https://github.com/iddv/mcp-forge.git
cd mcp-forge
pip install -e ".[test]"
pytest
```

## License

MIT
