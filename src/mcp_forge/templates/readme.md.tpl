# {{name}}

{{description}}

## Setup

```bash
pip install -e .
```

## Run

```bash
# Run with MCP Inspector
mcp dev server.py

# Run directly
python server.py
```

## Test

```bash
pip install -e ".[test]"
pytest
```

## Install in MCP clients

```bash
# Requires mcp-forge: pip install mcp-forge
mcp-forge install
```
