# MCP-Forge Runtime Configuration

MCP-Forge includes a powerful runtime configuration system that allows configuration parameters to be modified without requiring a server restart. This document explains how to use runtime configuration in your application.

## Runtime Configurator Overview

The runtime configuration system is managed by the `RuntimeConfigurator` class and provides:

1. Dynamic configuration updates that take effect immediately
2. Observer pattern for notifying components of configuration changes
3. File watching for automatic detection of external configuration changes
4. Configuration validation to prevent invalid changes

## Basic Usage

### Initializing the Runtime Configurator

To use the runtime configuration system, you need to first initialize a `RuntimeConfigurator` instance:

```python
from config_manager import ConfigManager
from runtime_configurator import RuntimeConfigurator

# Create the configuration manager
config_manager = ConfigManager()
config_manager.load_config()

# Create the runtime configurator
runtime_config = RuntimeConfigurator(config_manager)

# Optionally start the file watching thread
runtime_config.start_watching(interval_seconds=10)
```

### Updating Configuration at Runtime

You can update individual configuration values:

```python
# Update a simple configuration value
runtime_config.update_config("server", "port", 9001)

# Update a nested configuration value using dot notation
runtime_config.update_config("security", "ssl.enabled", True)

# Update an entire section at once
runtime_config.update_section("templates", {
    "default_capabilities": ["echo", "time", "status"],
    "allow_custom_capabilities": False
})
```

### Reacting to Configuration Changes

Components can register as observers to be notified when configuration changes:

```python
# Define a callback function
def on_port_change(change_info):
    new_port = change_info["value"]
    print(f"Server port changed to {new_port}, restarting listener...")
    # Do whatever is needed to handle the change

# Register the observer for a specific configuration key
runtime_config.register_observer(on_port_change, "server", "port")

# Register an observer for an entire section
def on_security_change(change_info):
    security_config = change_info["config"]
    print(f"Security configuration changed: {security_config}")
    # Apply new security settings
    
runtime_config.register_observer(on_security_change, "security")

# Register a global observer for any configuration change
def on_any_change(change_info):
    print("Configuration was modified")
    
runtime_config.register_observer(on_any_change)
```

### Unregistering Observers

When a component no longer needs to be notified, it can unregister:

```python
# Unregister a specific observer
runtime_config.unregister_observer(on_port_change, "server", "port")

# Unregister a section observer
runtime_config.unregister_observer(on_security_change, "security")

# Unregister a global observer
runtime_config.unregister_observer(on_any_change)
```

## Advanced Features

### File Watching

The runtime configurator can automatically detect when the configuration file changes on disk:

```python
# Start watching the configuration file
runtime_config.start_watching(interval_seconds=5)

# Later, stop watching
runtime_config.stop_watching()
```

This is useful when:
- Multiple processes share the same configuration
- Administrators manually edit the configuration file
- Configuration management tools update the file

### Retrieving Modifiable Settings

You can get a list of settings that can be modified at runtime:

```python
modifiable_settings = runtime_config.get_modifiable_settings()

# Display modifiable settings to a user
for section, settings in modifiable_settings.items():
    print(f"\n[{section}]")
    for setting in settings:
        print(f"  {setting['key']} = {setting['value']} ({setting['type']})")
        if setting.get('description'):
            print(f"    Description: {setting['description']}")
        if setting.get('constraints'):
            print(f"    Constraints: {setting['constraints']}")
```

### Configuration Import/Export

You can export the current configuration or import from a file:

```python
# Export the current configuration
runtime_config.export_config("config_backup.json")

# Import a new configuration (will notify observers if changes occur)
runtime_config.import_config("new_config.json")
```

### Manual Reload

You can manually trigger a reload of the configuration file:

```python
# Reload the configuration from disk
runtime_config.reload_config()
```

## Integration with Server Components

To make a server component react to configuration changes:

1. Implement an observer callback function
2. Register the callback for specific configuration items
3. Update component behavior when the callback is triggered

Example:

```python
class HTTPServer:
    def __init__(self, runtime_config):
        self.runtime_config = runtime_config
        self.port = runtime_config.config_manager.get("server", "port")
        
        # Register for configuration changes
        runtime_config.register_observer(self.on_port_change, "server", "port")
        runtime_config.register_observer(self.on_ssl_change, "security", "ssl.enabled")
        
    def on_port_change(self, change_info):
        old_port = self.port
        new_port = change_info["value"]
        self.port = new_port
        
        print(f"Port changed from {old_port} to {new_port}, restarting server...")
        self.restart_server()
        
    def on_ssl_change(self, change_info):
        ssl_enabled = change_info["value"]
        print(f"SSL setting changed to {ssl_enabled}, updating server...")
        self.update_ssl_settings()
        
    def cleanup(self):
        # Unregister observers when shutting down
        self.runtime_config.unregister_observer(self.on_port_change, "server", "port")
        self.runtime_config.unregister_observer(self.on_ssl_change, "security", "ssl.enabled")
```

## Best Practices

1. **Validate configuration changes**: Always validate before applying changes
2. **Graceful handling**: Design components to handle configuration changes gracefully
3. **Selective observation**: Only observe the specific settings that affect your component
4. **Clean up observers**: Unregister observers when components are shut down
5. **Transaction support**: When multiple related settings must change together, use section updates
6. **Documentation**: Document which settings can be changed at runtime and which require restart

## Persistent Storage Integration

The runtime configurator can work with the storage manager for additional persistence capabilities:

```python
from storage_manager import StorageManager

# Create storage manager
storage = StorageManager(config_manager)
storage.initialize()

# Create runtime configurator with storage
runtime_config = RuntimeConfigurator(config_manager, storage)

# Now configuration changes are automatically persisted
```

## Configuration Schema

When using a JSON Schema for configuration validation, the runtime configurator can:

1. Provide detailed information about each setting
2. Validate changes against constraints
3. Provide better user interfaces for configuration

The schema information is used automatically when available through the ConfigManager. 