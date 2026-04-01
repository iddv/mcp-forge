# MCP-Forge

Scaffold MCP server projects with sane defaults.

## Install

```bash
pip install mcp-forge
```

## Usage

### Create a new MCP server

```bash
mcp-forge new my-server
cd my-server
```

This creates a ready-to-run project with:
- `server.py` — FastMCP server with an example tool
- `pyproject.toml` — dependencies and entry point
- `tests/test_server.py` — working async tests
- `.env.example`, `.gitignore`, `README.md`

### Run and test

```bash
# Run with the MCP Inspector
mcp dev server.py

# Run tests
pip install -e ".[test]"
pytest
```

### Install in MCP clients

```bash
# Auto-detect and install in all found clients
mcp-forge install

# Target a specific client
mcp-forge install --client claude
mcp-forge install --client cursor
mcp-forge install --client windsurf
mcp-forge install --client claude-code
```

Supported clients: Claude Desktop, Cursor, Windsurf, Claude Code.
