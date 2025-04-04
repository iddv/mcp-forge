# MCP-Forge: Dynamic MCP Server Generator and Manager

MCP-Forge is a powerful framework for dynamically generating, managing, and monitoring Model Context Protocol (MCP) servers. Using the official MCP SDK, this tool enables you to create specialized MCP servers on demand through a centralized interface.

## Key Features

- **Dynamic Server Generation**: Create customized MCP servers from templates with specific capabilities
- **Flexible Templating System**: Extend base templates with custom handlers and server options
- **Server Lifecycle Management**: Start, stop, and monitor multiple MCP servers from a single control point
- **Built-in Customizations**: Add authentication, persistence, HTTP requests, database access, and more
- **MCP SDK Integration**: Built on top of the official Model Context Protocol SDK

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/iddv/mcp-forge.git
   cd mcp-forge
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Quick Start

### Start the Forge Server

```bash
python forge_mcp_server.py --port 9000
```

### Create a Server

Use the client to create a new server:

```bash
python client.py call create_server name="my-server" description="My custom MCP server" capabilities=["echo","time","uptime"]
```

### View Available Servers

```bash
python client.py meta
```

### Connect to a Specific Server

```bash
python client.py --port 9001 tools
```

## Customization

MCP-Forge supports extensive customization of generated servers:

### Add Custom Handlers

```bash
python client.py call create_server name="advanced-server" handlers=["file_reader","http_request"]
```

### Configure Server Options

```bash
python client.py call create_server name="storage-server" options={"persistence":"sqlite","auth":"basic"}
```

## Project Structure

```
mcp-forge/
├── forge_mcp_server.py       # Core forge server
├── template_system/          # Template system for generating servers
│   ├── template_manager.py   # Template loading and parsing
│   ├── customization.py      # Customization points
│   ├── handlers/             # Custom handler templates
│   └── templates/            # Server templates
├── client.py                 # Client for interacting with servers
├── servers/                  # Generated server scripts directory
└── progress_tracker.py       # Development progress tracking utility
```

## Development Status

MCP-Forge is in active development. See the `forge_mcp_server_plan.md` file for the current implementation status and roadmap.

## Requirements

- Python 3.7+
- MCP SDK 1.6.0+

## License

MIT 