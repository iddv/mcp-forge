# MCP-Forge

Scaffold, extend, and install MCP servers in seconds.

## Install

```bash
pip install mcp-forge
```

or

```bash
pipx install mcp-forge
```

## Quick Start

```bash
# Scaffold a new MCP server project
mcp-forge new my-server
cd my-server

# Add features
mcp-forge add resources
mcp-forge add prompts

# Register in your MCP clients
mcp-forge install
```

## Commands

### `mcp-forge new <name>`

Create a new FastMCP server project with working tests, dependencies, and a ready-to-run example tool.

```bash
mcp-forge new my-server
cd my-server

# Run with the MCP Inspector
mcp dev server.py

# Run tests
pip install -e ".[test]"
pytest
```

### `mcp-forge add <feature>`

Add MCP capabilities to an existing project.

```bash
mcp-forge add resources    # Resource endpoints
mcp-forge add prompts      # Prompt templates
mcp-forge add elicitation  # Interactive user input
mcp-forge add context      # Logging and progress reporting
mcp-forge add auth         # OAuth 2.0 configuration
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

| Feature | What it adds |
|---|---|
| `resources` | `@mcp.resource()` example endpoint |
| `prompts` | `@mcp.prompt()` template |
| `elicitation` | Interactive user input with `ctx.elicit()` |
| `context` | Logging and progress reporting via context |
| `auth` | OAuth 2.0 configuration |

## Generated Project

```
my-server/
  server.py           # FastMCP server with an example tool
  pyproject.toml       # Dependencies and entry point
  tests/
    test_server.py     # Async tests
  .env.example
  .gitignore
  README.md
```

## Development

```bash
git clone https://github.com/iddv/mcp-forge.git
cd mcp-forge
pip install -e ".[test]"
pytest
```

## License

MIT
