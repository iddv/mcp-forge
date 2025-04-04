# MCP-Forge: Dynamic MCP Server Generator and Manager

MCP-Forge is a powerful framework for dynamically generating, managing, and monitoring Model Context Protocol (MCP) servers. Using the official MCP SDK, this tool enables you to create specialized MCP servers on demand through a centralized interface.

## Key Features

- **Dynamic Server Generation**: Create customized MCP servers from templates with specific capabilities
- **Flexible Templating System**: Extend base templates with custom handlers and server options
- **Server Lifecycle Management**: Start, stop, and monitor multiple MCP servers from a single control point
- **Built-in Customizations**: Add authentication, persistence, HTTP requests, database access, and more
- **Advanced Monitoring**: Track server resources, logs, and performance metrics
- **Auto-Scaling**: Automatically scale servers based on demand and resource usage
- **Centralized Logging**: Aggregate logs from all servers with filtering and searching
- **Real-time Status Reporting**: Monitor server health and performance in real-time
- **Alerting System**: Receive notifications for critical issues through various channels
- **Comprehensive API**: Full-featured client API for managing the entire server ecosystem
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
python client.py create name="my-server" description="My custom MCP server" capabilities=["echo","time","uptime"]
```

### List Available Servers

```bash
python client.py list --details
```

### Start/Stop/Restart Servers

```bash
python client.py start <server-id>
python client.py stop <server-id>
python client.py restart <server-id>
```

### Get Server Information

```bash
python client.py info <server-id>
python client.py logs <server-id>
python client.py stats <server-id>
```

### Connect to a Specific Server

```bash
python client.py --port 9001 tools
```

### Delete a Server

```bash
python client.py delete <server-id>
```

## Customization

MCP-Forge supports extensive customization of generated servers:

### Add Custom Handlers

```bash
python client.py create name="advanced-server" handlers=["file_reader","http_request"]
```

### Configure Server Options

```bash
python client.py create name="storage-server" options={"persistence":"sqlite","auth":"basic"}
```

## Advanced Features

### Auto-Scaling

Configure auto-scaling for groups of servers:

```bash
python client.py call manage_auto_scaling action="create_group" group_name="web-servers" min_instances=1 max_instances=5
```

### Resource Limits

Set resource limits for servers:

```bash
python client.py call set_resource_limit server_id="server-id" limit_name="cpu_percent" limit_value=50.0
```

### Configuration Management

Get and set configuration options:

```bash
python client.py call get_config
python client.py call set_config section="server" key="log_level" value="debug"
```

### Centralized Logging

Access and search logs from all servers:

```bash
python client.py call get_logs source="system" log_level="error" limit=50
python client.py call get_logs source="server-id" limit=100
```

### Status Reporting

Get real-time status information for all servers:

```bash
python client.py call get_server_status
python client.py call get_server_status server_id="server-id"
```

### Performance Metrics

Access performance metrics for the system or specific servers:

```bash
python client.py call get_metrics source="system" time_period="hour"
python client.py call get_metrics source="server-id" time_period="day"
```

### Alert Management

Manage and respond to system alerts:

```bash
python client.py call get_alerts active_only=true
python client.py call acknowledge_alert alert_id="alert-id" user="admin"
python client.py call resolve_alert alert_id="alert-id" resolution_message="Fixed the issue"
```

## Project Structure

```
mcp-forge/
├── forge_mcp_server.py       # Core forge server
├── server_manager.py         # Server instance management
├── config_manager.py         # Configuration management
├── auto_scaler.py            # Auto-scaling system
├── resource_monitor.py       # Resource monitoring
├── process_monitor.py        # Process monitoring
├── logging_system.py         # Centralized logging system
├── log_aggregator.py         # Log aggregation service
├── status_reporter.py        # Status reporting system
├── metrics_collector.py      # Performance metrics collection
├── alerting_system.py        # Alerting system for critical issues
├── template_system/          # Template system for generating servers
│   ├── template_manager.py   # Template loading and parsing
│   ├── customization.py      # Customization points
│   ├── handlers/             # Custom handler templates
│   └── templates/            # Server templates
├── client.py                 # Client for interacting with servers
├── servers/                  # Generated server scripts directory
├── logs/                     # Log files directory
│   ├── aggregated/           # Aggregated log files
│   ├── metrics/              # Metrics data files
│   ├── status/               # Status report files
│   └── alerts/               # Alert history and data
├── docs/                     # Documentation directory
│   └── api_specification.md  # API specification
└── progress_tracker.py       # Development progress tracking utility
```

## API Documentation

For complete API documentation, see the `docs/api_specification.md` file, which contains detailed information about:

- All available client commands
- Server management endpoints
- Resource monitoring capabilities
- Configuration options
- Auto-scaling functionality
- Error handling

## Development Status

MCP-Forge is in active development. See the `forge_mcp_server_plan.md` file for the current implementation status and roadmap.

Run `python progress_tracker.py report` to view the current development progress.

## Requirements

- Python 3.7+
- MCP SDK 1.6.0+
- httpx 0.28.0+
- anyio 4.0.0+
- psutil 5.9.0+
- requests 2.31.0+
- python-dateutil 2.8.2+
- aiosmtplib 2.0.1+ (for email notifications)
- prometheus-client 0.17.1+ (optional, for exposing metrics)

## License

MIT 