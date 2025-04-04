# MCP-Forge Storage System

MCP-Forge uses a flexible storage system for data persistence that supports multiple backends. This document provides details on how state and configuration are persisted across server restarts.

## Storage Overview

The storage system is managed by the `StorageManager` class and provides:

1. Server state persistence
2. Key-value storage for application data
3. Automatic backups
4. Multiple backend support (file, SQLite, Redis)

## Storage Backends

### File Storage

The default storage backend uses JSON files to store data:

- Server state is stored in `forge_server_state.json`
- Key-value data is stored in `forge_keyvalue_store.json`
- Automatic backups are created in the `state_backups` directory

File storage is simple and doesn't require additional dependencies, but it's less suitable for high-concurrency scenarios.

### SQLite Storage

SQLite storage provides a lightweight database backend:

- Data is stored in a SQLite database file (default: `forge_storage.db`)
- Tables are created automatically for server state and key-value data
- Suitable for moderate concurrency needs

To use SQLite storage, set the storage type in your configuration:

```json
"persistence": {
  "storage_type": "sqlite",
  "storage_options": {
    "db_path": "forge_storage.db"
  }
}
```

### Redis Storage

Redis storage provides a high-performance, in-memory backend with optional persistence:

- Data is stored in a Redis server with configurable connection parameters
- Suitable for high-concurrency and distributed deployments
- Requires the Redis Python package and a Redis server

To use Redis storage, set the storage type in your configuration:

```json
"persistence": {
  "storage_type": "redis",
  "storage_options": {
    "host": "localhost",
    "port": 6379,
    "db": 0,
    "password": null,
    "expiration_days": 30
  }
}
```

## Storage Configuration

Storage behavior is configured through the `persistence` section of the configuration file:

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
| `storage_type` | String | Storage backend type (file, sqlite, redis) | `"file"` |
| `storage_options` | Object | Additional options for the selected storage backend | `{}` |

### File Storage Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `compression` | Boolean | Whether to compress saved state files | `false` |
| `encrypt` | Boolean | Whether to encrypt saved state files (not implemented yet) | `false` |

### SQLite Storage Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `db_path` | String | Path to the SQLite database file | `"forge_storage.db"` |

### Redis Storage Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `host` | String | Redis server host | `"localhost"` |
| `port` | Integer | Redis server port | `6379` |
| `db` | Integer | Redis database to use | `0` |
| `password` | String | Redis server password | `null` |
| `expiration_days` | Integer | Expiration time for keys in days | `null` (no expiration) |

## Using the Storage API

The storage system can be accessed programmatically through the `StorageManager` class. Here are some examples of how to use it:

```python
from config_manager import ConfigManager
from storage_manager import StorageManager

# Create a ConfigManager instance
config = ConfigManager()
config.load_config()

# Create a StorageManager instance with the configuration
storage = StorageManager(config)
storage.initialize()

# Save server state
server_state = {
    "servers": [
        {"id": "server1", "port": 9001, "status": "running"},
        {"id": "server2", "port": 9002, "status": "stopped"}
    ]
}
storage.save_state(server_state)

# Load server state
loaded_state = storage.load_state()
if loaded_state:
    print(f"Loaded {len(loaded_state['servers'])} servers from storage")

# Store a key-value pair
storage.set_value("last_server_id", "server2")

# Retrieve a key-value pair
last_id = storage.get_value("last_server_id")
print(f"Last server ID: {last_id}")

# Clean up
storage.close()
```

## Automatic State Saving

The storage system supports automatic state saving at configurable intervals. To use this feature:

1. Set `auto_save_interval_minutes` in the configuration
2. Periodically call `check_auto_save()` with the current state

```python
# Check if it's time to auto-save
if storage.check_auto_save(current_state):
    print("State was automatically saved")
```

## Backup Management

Backups are managed automatically by the storage system:

1. When saving state to a file, a backup is created first
2. Backups are stored in the `state_backups` directory
3. The number of backups to keep is controlled by the `backup_count` setting
4. Older backups are automatically deleted

## Failover Behavior

If a storage backend fails to initialize or encounters errors:

1. For SQLite: Falls back to file storage if initialization fails
2. For Redis: Falls back to file storage if Redis server is unavailable
3. For all backends: Errors are logged but don't crash the application

## Storage Security

The storage system supports optional security features:

1. File compression (reduces disk usage and obscures content)
2. Encrypted storage (planned for future implementation)

## Recovery Process

If state becomes corrupted, you can restore from a backup:

1. Stop the forge server
2. Navigate to the `state_backups` directory
3. Copy the desired backup file to the main state file location
4. Restart the forge server 