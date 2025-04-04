# MCP-Forge Configuration System

MCP-Forge uses a flexible configuration system that allows for customization of all aspects of the framework. This document provides details on how to configure the forge server and its generated child servers.

## Configuration Overview

The configuration is stored in a JSON file (`forge_config.json`) and structured into logical sections. Each section contains related settings that control different aspects of the system.

## Configuration Sections

### Server

Basic server configuration settings for the forge server itself.

```json
"server": {
  "host": "localhost",
  "port": 9000,
  "log_level": "INFO",
  "max_servers": 100,
  "auto_start": true
}
```

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| `host` | String | Host address to bind to | `"localhost"` |
| `port` | Integer | Port to listen on (1024-65535) | `9000` |
| `log_level` | String | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | `"INFO"` |
| `max_servers` | Integer | Maximum number of servers that can be created | `100` |
| `auto_start` | Boolean | Whether to automatically start saved servers on startup | `true` |

### Templates

Settings for the template system that generates child servers.

```json
"templates": {
  "default_capabilities": ["echo", "time", "uptime"],
  "allow_custom_capabilities": true,
  "default_handlers": [],
  "custom_templates_dir": "custom_templates"
}
```

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| `default_capabilities` | Array | Default capabilities for new servers | `["echo", "time", "uptime"]` |
| `allow_custom_capabilities` | Boolean | Whether custom capabilities can be specified | `true` |
| `default_handlers` | Array | Default handlers for new servers | `[]` |
| `custom_templates_dir` | String | Directory for user-defined custom templates | `"custom_templates"` |

### Security

Security-related configuration for the forge server.

```json
"security": {
  "enable_authentication": false,
  "authentication_type": "basic",
  "allowed_ip_ranges": ["127.0.0.1/32", "::1/128"],
  "ssl": {
    "enabled": false,
    "cert_file": "certs/server.crt",
    "key_file": "certs/server.key"
  }
}
```

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| `enable_authentication` | Boolean | Whether authentication is enabled | `false` |
| `authentication_type` | String | Type of authentication (none, basic, token, oauth) | `"basic"` |
| `allowed_ip_ranges` | Array | IP ranges allowed to connect to the server | `["127.0.0.1/32", "::1/128"]` |
| `ssl.enabled` | Boolean | Whether SSL/TLS is enabled | `false` |
| `ssl.cert_file` | String | Path to SSL certificate file | `""` |
| `ssl.key_file` | String | Path to SSL key file | `""` |

### Resources

Resource management settings for controlling child server resource usage.

```json
"resources": {
  "memory_limit_mb": 500,
  "cpu_limit_percent": 50,
  "enable_throttling": false,
  "throttling_strategy": "pause",
  "monitor_interval_seconds": 10,
  "alerts": {
    "memory_warning_percent": 80,
    "cpu_warning_percent": 80
  }
}
```

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| `memory_limit_mb` | Number | Global memory limit in MB | `500` |
| `cpu_limit_percent` | Number | Global CPU usage limit in percent (1-100) | `50` |
| `enable_throttling` | Boolean | Whether to throttle resource usage | `false` |
| `throttling_strategy` | String | Strategy to use for throttling (pause, restart, scale_down) | `"pause"` |
| `monitor_interval_seconds` | Number | Interval for resource monitoring in seconds | `10` |
| `alerts.memory_warning_percent` | Number | Memory usage percentage that triggers a warning | `80` |
| `alerts.cpu_warning_percent` | Number | CPU usage percentage that triggers a warning | `80` |

### Persistence

Settings for data persistence and state management.

```json
"persistence": {
  "save_server_state": true,
  "state_file": "forge_server_state.json",
  "backup_count": 3,
  "auto_save_interval_minutes": 10,
  "storage_type": "file",
  "storage_options": {
    "compression": true,
    "encrypt": false
  }
}
```

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| `save_server_state` | Boolean | Whether to save server state | `true` |
| `state_file` | String | File to save server state | `"forge_server_state.json"` |
| `backup_count` | Integer | Number of backup files to keep | `3` |
| `auto_save_interval_minutes` | Number | Interval for auto-saving state in minutes | `10` |
| `storage_type` | String | Type of storage for persistence (file, sqlite, redis) | `"file"` |
| `storage_options` | Object | Additional options for the selected storage type | `{}` |

### Advanced

Advanced configuration options for fine-tuning the system.

```json
"advanced": {
  "debug_mode": false,
  "enable_experimental": false,
  "process_priority": "normal",
  "connection_timeout_seconds": 30,
  "request_timeout_seconds": 60
}
```

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| `debug_mode` | Boolean | Enable debug mode with additional logging | `false` |
| `enable_experimental` | Boolean | Enable experimental features | `false` |
| `process_priority` | String | Process priority for child servers (low, normal, high) | `"normal"` |
| `connection_timeout_seconds` | Number | Timeout for connections in seconds | `30` |
| `request_timeout_seconds` | Number | Timeout for requests in seconds | `60` |

## Using the Configuration API

The configuration system can be accessed programmatically through the `ConfigManager` class. Here are some examples of how to use it:

```python
from config_manager import ConfigManager

# Create a ConfigManager instance
config = ConfigManager()

# Load the configuration
config.load_config()

# Get a configuration value
port = config.get("server", "port")

# Get a nested configuration value using dot notation
ssl_enabled = config.get("security", "ssl.enabled")

# Set a configuration value
config.set("server", "max_servers", 50)

# Set a nested configuration value
config.set("security", "ssl.enabled", True)

# Update an entire section
config.update_section("templates", {
    "default_capabilities": ["echo", "time", "status"],
    "allow_custom_capabilities": False
})

# Validate the configuration
errors = config.validate_config()
if errors:
    for error in errors:
        print(f"Error: {error}")

# Export the configuration to a file
config.export_config("my_config.json")

# Import configuration from a file
config.import_config("my_config.json")
```

## Configuration File Locations

By default, the configuration file is loaded from `forge_config.json` in the current directory. You can specify a different location when creating the ConfigManager:

```python
config = ConfigManager(config_file="/path/to/my_config.json")
```

## Configuration Schema

The configuration format is defined by a JSON Schema file (`forge_config.schema.json`). This schema is used for validation and provides detailed information about each configuration option.

The schema file can be customized to add new configuration options or change validation rules. If the schema file is not found, the configuration system will fall back to basic validation.

## Configuration Backups

The configuration system automatically creates backups of the configuration file when changes are made. Backups are stored in the `config_backups` directory and are named with timestamps.

The number of backup files to keep is controlled by the `persistence.backup_count` setting.

## Command-Line Configuration

Some configuration options can be overridden from the command line when starting the forge server:

```bash
python forge_mcp_server.py --port 8000 --host 0.0.0.0 --log-level DEBUG
```

Command-line options take precedence over configuration file settings. 