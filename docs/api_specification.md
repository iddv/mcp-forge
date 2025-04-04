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

### Getting Server Process Statistics

**Tool**: `get_server_process_stats`

**Description**: Gets process statistics for a server instance.

**Parameters**:
- `server_id`: ID of the server.

**Returns**:
```json
{
  "status": "success",
  "server_id": "mcp-20250404-abc123",
  "process": {
    "pid": 12345,
    "cpu_percent": 2.5,
    "memory_percent": 1.2,
    "memory_rss": 12345678,
    "uptime": 3600.5,
    "status": "running",
    "threads": 4,
    "io_read_bytes": 12345,
    "io_write_bytes": 67890,
    "connections": 2
  }
}
```

### Getting Server Process History

**Tool**: `get_server_process_history`

**Description**: Gets historical process statistics for a server instance.

**Parameters**:
- `server_id`: ID of the server.
- `metric` (optional): Metric to get history for. Can be "cpu", "memory", "io", or "all". Defaults to "cpu".
- `points` (optional): Number of data points to return. Defaults to 10.

**Returns**:
```json
{
  "status": "success",
  "server_id": "mcp-20250404-abc123",
  "metric": "cpu",
  "history": [
    {"timestamp": 1712188800, "value": 2.5},
    {"timestamp": 1712188860, "value": 2.7},
    {"timestamp": 1712188920, "value": 2.1}
  ]
}
```

### Getting System Statistics

**Tool**: `get_system_stats`

**Description**: Gets system-wide resource statistics.

**Parameters**: None

**Returns**:
```json
{
  "status": "success",
  "system": {
    "cpu_percent": 25.5,
    "memory_percent": 45.2,
    "memory_available": 8589934592,
    "memory_total": 17179869184,
    "disk_percent": 68.7,
    "disk_free": 107374182400,
    "disk_total": 536870912000,
    "network_sent_bytes": 1234567,
    "network_recv_bytes": 7654321,
    "server_count": 5,
    "server_count_active": 3
  }
}
```

### Getting Resource Limits

**Tool**: `get_resource_limits`

**Description**: Gets resource limits for a server instance.

**Parameters**:
- `server_id`: ID of the server.

**Returns**:
```json
{
  "status": "success",
  "server_id": "mcp-20250404-abc123",
  "limits": {
    "cpu_percent": 50.0,
    "memory_percent": 25.0,
    "memory_bytes": 1073741824,
    "io_read_bytes": null,
    "io_write_bytes": null,
    "connections": 10
  }
}
```

### Setting Resource Limits

**Tool**: `set_resource_limit`

**Description**: Sets a resource limit for a server instance.

**Parameters**:
- `server_id`: ID of the server.
- `limit_name`: Name of the limit to set.
- `limit_value`: Value of the limit. Use null to remove the limit.

**Returns**:
```json
{
  "status": "success",
  "server_id": "mcp-20250404-abc123",
  "limit_name": "cpu_percent",
  "limit_value": 50.0,
  "message": "Resource limit updated successfully"
}
```

### Managing Auto-Scaling

**Tool**: `manage_auto_scaling`

**Description**: Manages auto-scaling groups and rules.

**Parameters**:
- `action`: Action to perform. Can be "create_group", "delete_group", "add_server", "remove_server", "add_rule", "remove_rule", "update_group", or "update_rule".
- `group_name`: Name of the auto-scaling group.
- `min_instances` (optional): Minimum number of instances for the group.
- `max_instances` (optional): Maximum number of instances for the group.
- `server_ids` (optional): List of server IDs to add to or remove from the group.
- `rule_name` (optional): Name of the rule to add, remove, or update.
- `metric` (optional): Metric for the rule. Can be "cpu", "memory", or "connections".
- `threshold` (optional): Threshold value for the rule.
- `rule_action` (optional): Action to take when the rule is triggered. Can be "scale_up", "scale_down", or "restart".
- `cooldown` (optional): Cooldown period in seconds.

**Returns**:
```json
{
  "status": "success",
  "message": "Auto-scaling group created/updated successfully",
  "group": {
    "name": "web-servers",
    "min_instances": 1,
    "max_instances": 5,
    "servers": ["mcp-20250404-abc123", "mcp-20250404-def456"],
    "rules": [
      {
        "name": "high-cpu",
        "metric": "cpu",
        "threshold": 80.0,
        "action": "scale_up",
        "cooldown": 300.0
      }
    ]
  }
}
```

### Getting Configuration

**Tool**: `get_config`

**Description**: Gets configuration values from the MCP-Forge server.

**Parameters**:
- `section` (optional): Configuration section to get. If not provided, returns all sections.
- `key` (optional): Configuration key to get. If not provided, returns all keys in the section.

**Returns**:
```json
{
  "status": "success",
  "config": {
    "server": {
      "host": "localhost",
      "port": 9000,
      "log_level": "info"
    },
    "resources": {
      "default_cpu_limit": 50.0,
      "default_memory_limit": 25.0
    }
  }
}
```

### Setting Configuration

**Tool**: `set_config`

**Description**: Sets a configuration value on the MCP-Forge server.

**Parameters**:
- `section`: Configuration section to set.
- `key`: Configuration key to set.
- `value`: Value to set.

**Returns**:
```json
{
  "status": "success",
  "message": "Configuration updated successfully",
  "section": "server",
  "key": "log_level",
  "value": "debug"
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

### Server Process Information

**Resource URI**: `servers://{server_id}/process`

**Description**: Returns process information about a specific server in JSON format.

**Parameters**:
- `server_id`: ID of the server.

**Returns**: JSON object with server process information.

### Server Resources Information

**Resource URI**: `servers://{server_id}/resources`

**Description**: Returns resource limits and usage for a specific server.

**Parameters**:
- `server_id`: ID of the server.

**Returns**: JSON object with resource information.

### System Resource Information

**Resource URI**: `system://stats`

**Description**: Returns system-wide resource statistics.

**Returns**: JSON object with system statistics.

### System Resources Information

**Resource URI**: `system://resources`

**Description**: Returns system-wide resource limits and usage.

**Returns**: JSON object with resource information.

### Auto-Scaling Groups Information

**Resource URI**: `autoscaling://groups`

**Description**: Returns information about all auto-scaling groups.

**Returns**: JSON object with auto-scaling group information.

### Auto-Scaling Group Information

**Resource URI**: `autoscaling://groups/{group_name}`

**Description**: Returns information about a specific auto-scaling group.

**Parameters**:
- `group_name`: Name of the auto-scaling group.

**Returns**: JSON object with auto-scaling group information.

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

#### Basic Operations

```bash
# Connect to the forge server
python client.py meta

# Create a new server
python client.py create name="example-server" description="Example MCP server" capabilities=["echo","time","uptime"]

# List all servers
python client.py list --details

# Start a server
python client.py start mcp-20250404-abc123

# Stop a server
python client.py stop mcp-20250404-abc123

# Restart a server
python client.py restart mcp-20250404-abc123

# Get server info
python client.py info mcp-20250404-abc123

# Get server logs
python client.py logs mcp-20250404-abc123 --type stdout --lines 20

# Get server process stats
python client.py stats mcp-20250404-abc123

# Delete a server
python client.py delete mcp-20250404-abc123
```

#### Advanced Operations

```bash
# Create a server with custom handlers
python client.py create name="advanced-server" handlers=["file_reader","http_request"]

# Create a server with specific options
python client.py create name="storage-server" options={"persistence":"sqlite","auth":"basic"}

# Use auto-scaling
python client.py call manage_auto_scaling action="create_group" group_name="web-servers" min_instances=1 max_instances=5

# Add a server to an auto-scaling group
python client.py call manage_auto_scaling action="add_server" group_name="web-servers" server_ids=["mcp-20250404-abc123"]

# Add a scaling rule
python client.py call manage_auto_scaling action="add_rule" group_name="web-servers" rule_name="high-cpu" metric="cpu" threshold=80.0 rule_action="scale_up" cooldown=300.0

# Set resource limits
python client.py call set_resource_limit server_id="mcp-20250404-abc123" limit_name="cpu_percent" limit_value=50.0

# Get configuration
python client.py call get_config

# Set configuration
python client.py call set_config section="server" key="log_level" value="debug"

# Connect to a specific server and use its tools
python client.py --port 9001 tools
python client.py --port 9001 call time
```

## API Versioning

The MCP-Forge API is versioned to ensure backward compatibility. The current version is 1.0.

- All API endpoints are versioned and will remain stable within a major version
- Breaking changes will result in a new major version
- Additions and non-breaking changes may be added in minor versions
- API version can be checked using the `system://version` resource

## Error Handling

All API calls return a consistent error response format:

```json
{
  "status": "error",
  "error": {
    "code": "error_code",
    "message": "Detailed error message"
  }
}
```

Common error codes:

- `invalid_request`: The request was malformed or missing required parameters
- `not_found`: The requested resource was not found
- `server_error`: An error occurred on the server
- `invalid_id`: The provided server ID is invalid
- `server_not_running`: The server is not running (for operations that require a running server)
- `limit_exceeded`: A resource limit has been exceeded 