# MCP-Forge Server API Specification

This document describes the API for interacting with the MCP-Forge server, which is used to create and manage child MCP servers.

## Overview

The MCP-Forge server provides a Model Context Protocol (MCP) interface for creating, managing, and interacting with specialized MCP servers. All communication with the forge server and its child servers happens through the MCP protocol.

## Connection Details

- **Protocol**: MCP over HTTP
- **Default Port**: 9000
- **Connection Method**: Server-Sent Events (SSE) endpoint at `/sse`

## Server Management API

### Creating a Server

**Tool**: `create_server`

**Description**: Creates a new MCP server instance with specified capabilities.

**Parameters**:
- `name` (optional): Name for the server. If not provided, a unique ID will be generated.
  - Must be at least 3 characters long
  - Can only contain alphanumeric characters, hyphens, and underscores
- `description` (optional): Description of the server. Defaults to "MCP Server".
  - Must be at least 5 characters long
- `capabilities` (optional): List of capabilities the server should have. Defaults to `["echo", "time", "uptime"]`.
  - Standard capabilities: `echo`, `time`, `uptime`
  - Custom capabilities can be added but must be known by the template system
- `handlers` (optional): List of additional handlers to add to the server.
  - Available handlers depend on the template system configuration
- `options` (optional): Dictionary of server options.
  - Available options depend on the template system configuration

**Returns**:
```json
{
  "status": "success|warning|error",
  "message": "Message explaining the result",
  "server": {
    "id": "mcp-20250404-abc123",
    "name": "example-server",
    "description": "Example server",
    "port": 9001,
    "status": "running|initialized|stopped|error",
    "uptime": 123.45,
    "capabilities": ["echo", "time", "uptime"],
    "script_path": "/path/to/server/script.py",
    "error": null,
    "restart_count": 0,
    "latest_logs": {
      "stdout": ["Log line 1", "Log line 2"],
      "stderr": []
    }
  }
}
```

### Starting a Server

**Tool**: `start_server`

**Description**: Starts an existing server instance.

**Parameters**:
- `server_id`: ID of the server to start.

**Returns**:
```json
{
  "status": "success|warning|error",
  "message": "Message explaining the result",
  "error": "Error message (if status is error)"
}
```

### Stopping a Server

**Tool**: `stop_server`

**Description**: Stops a running server instance.

**Parameters**:
- `server_id`: ID of the server to stop.

**Returns**:
```json
{
  "status": "success|warning|error",
  "message": "Message explaining the result",
  "error": "Error message (if status is error)"
}
```

### Restarting a Server

**Tool**: `restart_server`

**Description**: Restarts a running server instance or starts it if it's not running.

**Parameters**:
- `server_id`: ID of the server to restart.

**Returns**:
```json
{
  "status": "success|warning|error",
  "message": "Message explaining the result",
  "error": "Error message (if status is error)"
}
```

### Deleting a Server

**Tool**: `delete_server`

**Description**: Deletes a server instance. If the server is running, it will be stopped first.

**Parameters**:
- `server_id`: ID of the server to delete.

**Returns**:
```json
{
  "status": "success|warning|error",
  "message": "Message explaining the result",
  "error": "Error message (if status is error)"
}
```

### Listing Servers

**Tool**: `list_servers`

**Description**: Lists all managed server instances.

**Parameters**:
- `include_details` (optional): Whether to include detailed information. Defaults to `false`.

**Returns**:
```json
{
  "status": "success",
  "count": 2,
  "servers": [
    {
      "id": "mcp-20250404-abc123",
      "name": "example-server-1",
      "description": "Example server 1",
      "status": "running",
      "port": 9001
    },
    {
      "id": "mcp-20250404-def456",
      "name": "example-server-2",
      "description": "Example server 2",
      "status": "stopped",
      "port": 9002
    }
  ]
}
```

### Getting Server Logs

**Tool**: `get_server_logs`

**Description**: Gets logs from a server instance.

**Parameters**:
- `server_id`: ID of the server.
- `log_type` (optional): Type of logs to get. Can be "stdout", "stderr", or "all". Defaults to "all".
- `max_lines` (optional): Maximum number of lines to return. Defaults to 50.

**Returns**:
```json
{
  "status": "success",
  "server_id": "mcp-20250404-abc123",
  "logs": {
    "stdout": ["Log line 1", "Log line 2"],
    "stderr": []
  }
}
```

## Server Resources

### List of Servers

**Resource URI**: `servers://list`

**Description**: Returns a list of all managed servers in JSON format.

**Returns**: JSON array of server information.

### Server Information

**Resource URI**: `servers://{server_id}/info`

**Description**: Returns information about a specific server in JSON format.

**Parameters**:
- `server_id`: ID of the server.

**Returns**: JSON object with server information.

## Client Usage Examples

### Using the Client Library

```python
import asyncio
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

async def main():
    # Connect to MCP-Forge server
    server_url = "http://localhost:9000/sse"
    sse = await sse_client(server_url).__aenter__()
    client = ClientSession(*sse)
    await client.initialize()
    
    # Create a new server
    result = await client.call_tool("create_server", {
        "name": "example-server",
        "description": "Example MCP server",
        "capabilities": ["echo", "time", "uptime"]
    })
    print(f"Created server: {result['server']['id']} on port {result['server']['port']}")
    
    # List all servers
    servers = await client.call_tool("list_servers", {"include_details": True})
    print(f"Found {servers['count']} servers")
    
    # Connect to the new server
    new_port = result['server']['port']
    new_url = f"http://localhost:{new_port}/sse"
    new_sse = await sse_client(new_url).__aenter__()
    new_client = ClientSession(*new_sse)
    await new_client.initialize()
    
    # Call a tool on the new server
    time_result = await new_client.call_tool("time", {})
    print(f"Time from server: {time_result}")

asyncio.run(main())
```

### Using the Command-Line Client

```bash
# Create a new server
python client.py call create_server name="example-server" description="Example MCP server" capabilities=["echo","time","uptime"]

# List all servers
python client.py call list_servers include_details=true

# Connect to a specific server
python client.py --port 9001 call time

# Get logs from a server
python client.py call get_server_logs server_id="mcp-20250404-abc123" log_type="stdout" max_lines=20

# Delete a server
python client.py call delete_server server_id="mcp-20250404-abc123"
``` 