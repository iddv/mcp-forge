#!/usr/bin/env python
"""
Storage Manager for MCP-Forge

This module handles data persistence and storage for the MCP-Forge server framework.
It supports multiple storage backends including file, SQLite, and Redis.
"""

import json
import logging
import os
import shutil
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Tuple, Callable

# Setup logging
logger = logging.getLogger('storage_manager')

class StorageManager:
    """
    Storage manager for MCP-Forge.
    Handles data persistence and storage operations.
    """
    
    # Supported storage types
    STORAGE_TYPES = ["file", "sqlite", "redis"]
    
    def __init__(self, config_manager=None):
        """
        Initialize the storage manager.
        
        Args:
            config_manager: Optional ConfigManager instance to get persistence settings
        """
        self.config_manager = config_manager
        self.storage_type = "file"  # Default storage type
        self.storage_options = {}
        self.state_file = "forge_server_state.json"
        self.backup_count = 3
        self.auto_save_interval = 10  # minutes
        self.save_state = True
        self._conn = None  # For database connections
        self._last_save_time = time.time()
        
        # Load configuration if provided
        if config_manager:
            self._load_config()
    
    def _load_config(self):
        """Load storage configuration from config manager."""
        if not self.config_manager:
            return
            
        persistence_config = self.config_manager.get_persistence_config()
        self.storage_type = persistence_config.get("storage_type", "file")
        self.storage_options = persistence_config.get("storage_options", {})
        self.state_file = persistence_config.get("state_file", "forge_server_state.json")
        self.backup_count = persistence_config.get("backup_count", 3)
        self.auto_save_interval = persistence_config.get("auto_save_interval_minutes", 10)
        self.save_state = persistence_config.get("save_server_state", True)
        
        # Validate storage type
        if self.storage_type not in self.STORAGE_TYPES:
            logger.warning(f"Unsupported storage type: {self.storage_type}, falling back to 'file'")
            self.storage_type = "file"
    
    def initialize(self) -> bool:
        """
        Initialize the storage system.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Initializing storage manager with type: {self.storage_type}")
            
            if self.storage_type == "sqlite":
                return self._initialize_sqlite()
            elif self.storage_type == "redis":
                return self._initialize_redis()
            else:
                # File storage doesn't need initialization
                return True
        except Exception as e:
            logger.error(f"Error initializing storage: {e}")
            return False
    
    def _initialize_sqlite(self) -> bool:
        """
        Initialize SQLite storage.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            db_path = self.storage_options.get("db_path", "forge_storage.db")
            self._conn = sqlite3.connect(db_path)
            
            # Create tables if they don't exist
            cursor = self._conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS key_value_store (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS server_state (
                    id TEXT PRIMARY KEY,
                    state TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            self._conn.commit()
            
            logger.info(f"SQLite storage initialized at {db_path}")
            return True
        except Exception as e:
            logger.error(f"Error initializing SQLite storage: {e}")
            return False
    
    def _initialize_redis(self) -> bool:
        """
        Initialize Redis storage.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if redis is available
            try:
                import redis
            except ImportError:
                logger.error("Redis package not installed, falling back to file storage")
                self.storage_type = "file"
                return True
                
            host = self.storage_options.get("host", "localhost")
            port = self.storage_options.get("port", 6379)
            db = self.storage_options.get("db", 0)
            password = self.storage_options.get("password", None)
            
            self._conn = redis.Redis(
                host=host,
                port=port,
                db=db,
                password=password,
                decode_responses=True
            )
            
            # Test connection
            self._conn.ping()
            
            logger.info(f"Redis storage initialized at {host}:{port}")
            return True
        except Exception as e:
            logger.error(f"Error initializing Redis storage: {e}")
            logger.warning("Falling back to file storage")
            self.storage_type = "file"
            return True
    
    def close(self) -> bool:
        """
        Close the storage connection.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.storage_type == "sqlite" and self._conn:
                self._conn.close()
                self._conn = None
            elif self.storage_type == "redis" and self._conn:
                self._conn = None
                
            logger.info("Storage connection closed")
            return True
        except Exception as e:
            logger.error(f"Error closing storage connection: {e}")
            return False
    
    def save_state(self, state: Dict[str, Any], key: str = "server_state") -> bool:
        """
        Save state to storage.
        
        Args:
            state: State dictionary to save
            key: Key to save the state under (defaults to 'server_state')
            
        Returns:
            True if successful, False otherwise
        """
        if not self.save_state:
            logger.debug("State saving is disabled in configuration")
            return True
            
        try:
            # Record save time
            self._last_save_time = time.time()
            
            if self.storage_type == "file":
                return self._save_to_file(state)
            elif self.storage_type == "sqlite":
                return self._save_to_sqlite(state, key)
            elif self.storage_type == "redis":
                return self._save_to_redis(state, key)
            else:
                logger.error(f"Unsupported storage type: {self.storage_type}")
                return False
        except Exception as e:
            logger.error(f"Error saving state: {e}")
            return False
    
    def _save_to_file(self, state: Dict[str, Any]) -> bool:
        """
        Save state to file.
        
        Args:
            state: State dictionary to save
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create backup of existing file
            if os.path.exists(self.state_file):
                self._backup_state_file()
            
            # Apply compression if configured
            compression = self.storage_options.get("compression", False)
            
            if compression:
                import gzip
                with gzip.open(f"{self.state_file}.gz", 'wt') as f:
                    json.dump(state, f, indent=2)
                logger.info(f"State saved to {self.state_file}.gz (compressed)")
            else:
                # Ensure directory exists
                os.makedirs(os.path.dirname(os.path.abspath(self.state_file)), exist_ok=True)
                
                with open(self.state_file, 'w') as f:
                    json.dump(state, f, indent=2)
                logger.info(f"State saved to {self.state_file}")
                
            return True
        except Exception as e:
            logger.error(f"Error saving state to file: {e}")
            return False
    
    def _backup_state_file(self) -> bool:
        """
        Create a backup of the state file.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.exists(self.state_file):
                return False
                
            backup_dir = os.path.join(os.path.dirname(os.path.abspath(self.state_file)), "state_backups")
            os.makedirs(backup_dir, exist_ok=True)
            
            # Get the timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create the backup file
            state_filename = os.path.basename(self.state_file)
            backup_file = os.path.join(backup_dir, f"{state_filename}_{timestamp}")
            shutil.copy2(self.state_file, backup_file)
            
            # Clean up old backups
            self._cleanup_backups(backup_dir)
            
            logger.info(f"Created state backup at {backup_file}")
            return True
        except Exception as e:
            logger.error(f"Error creating state backup: {e}")
            return False
    
    def _cleanup_backups(self, backup_dir: str) -> None:
        """
        Clean up old backup files, keeping only the N most recent.
        
        Args:
            backup_dir: Directory containing backup files
        """
        try:
            if self.backup_count <= 0:
                return
                
            # Get all backup files for this state file
            state_filename = os.path.basename(self.state_file)
            backup_files = [os.path.join(backup_dir, f) for f in os.listdir(backup_dir) 
                          if f.startswith(state_filename + "_")]
            
            # Sort by modification time (newest first)
            backup_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            
            # Delete oldest files beyond the backup count
            for file in backup_files[self.backup_count:]:
                os.remove(file)
                logger.debug(f"Deleted old backup file: {file}")
        except Exception as e:
            logger.error(f"Error cleaning up backup files: {e}")
    
    def _save_to_sqlite(self, state: Dict[str, Any], key: str) -> bool:
        """
        Save state to SQLite.
        
        Args:
            state: State dictionary to save
            key: Key to save the state under
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self._conn:
                if not self._initialize_sqlite():
                    return False
            
            # Convert state to JSON string
            state_json = json.dumps(state)
            
            # Save to database
            cursor = self._conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO server_state (id, state, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (key, state_json))
            self._conn.commit()
            
            logger.info(f"State saved to SQLite with key: {key}")
            return True
        except Exception as e:
            logger.error(f"Error saving state to SQLite: {e}")
            return False
    
    def _save_to_redis(self, state: Dict[str, Any], key: str) -> bool:
        """
        Save state to Redis.
        
        Args:
            state: State dictionary to save
            key: Key to save the state under
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self._conn:
                if not self._initialize_redis():
                    return False
            
            # Convert state to JSON string
            state_json = json.dumps(state)
            
            # Save to Redis
            self._conn.set(f"forge:state:{key}", state_json)
            self._conn.set(f"forge:state:{key}:updated", datetime.now().isoformat())
            
            # Set expiration if configured
            expiration = self.storage_options.get("expiration_days")
            if expiration:
                expiration_seconds = int(expiration) * 86400  # Convert days to seconds
                self._conn.expire(f"forge:state:{key}", expiration_seconds)
                self._conn.expire(f"forge:state:{key}:updated", expiration_seconds)
            
            logger.info(f"State saved to Redis with key: {key}")
            return True
        except Exception as e:
            logger.error(f"Error saving state to Redis: {e}")
            return False
    
    def load_state(self, key: str = "server_state") -> Optional[Dict[str, Any]]:
        """
        Load state from storage.
        
        Args:
            key: Key to load the state from (defaults to 'server_state')
            
        Returns:
            State dictionary if found, None otherwise
        """
        try:
            if self.storage_type == "file":
                return self._load_from_file()
            elif self.storage_type == "sqlite":
                return self._load_from_sqlite(key)
            elif self.storage_type == "redis":
                return self._load_from_redis(key)
            else:
                logger.error(f"Unsupported storage type: {self.storage_type}")
                return None
        except Exception as e:
            logger.error(f"Error loading state: {e}")
            return None
    
    def _load_from_file(self) -> Optional[Dict[str, Any]]:
        """
        Load state from file.
        
        Returns:
            State dictionary if found, None otherwise
        """
        try:
            # Check for compressed file first
            compression = self.storage_options.get("compression", False)
            
            if compression and os.path.exists(f"{self.state_file}.gz"):
                import gzip
                with gzip.open(f"{self.state_file}.gz", 'rt') as f:
                    state = json.load(f)
                logger.info(f"State loaded from {self.state_file}.gz (compressed)")
                return state
            elif os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                logger.info(f"State loaded from {self.state_file}")
                return state
            else:
                logger.warning(f"State file not found: {self.state_file}")
                return None
        except Exception as e:
            logger.error(f"Error loading state from file: {e}")
            return None
    
    def _load_from_sqlite(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Load state from SQLite.
        
        Args:
            key: Key to load the state from
            
        Returns:
            State dictionary if found, None otherwise
        """
        try:
            if not self._conn:
                if not self._initialize_sqlite():
                    return None
            
            # Load from database
            cursor = self._conn.cursor()
            cursor.execute('''
                SELECT state FROM server_state
                WHERE id = ?
            ''', (key,))
            result = cursor.fetchone()
            
            if result:
                state_json = result[0]
                state = json.loads(state_json)
                logger.info(f"State loaded from SQLite with key: {key}")
                return state
            else:
                logger.warning(f"State not found in SQLite with key: {key}")
                return None
        except Exception as e:
            logger.error(f"Error loading state from SQLite: {e}")
            return None
    
    def _load_from_redis(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Load state from Redis.
        
        Args:
            key: Key to load the state from
            
        Returns:
            State dictionary if found, None otherwise
        """
        try:
            if not self._conn:
                if not self._initialize_redis():
                    return None
            
            # Load from Redis
            state_json = self._conn.get(f"forge:state:{key}")
            
            if state_json:
                state = json.loads(state_json)
                logger.info(f"State loaded from Redis with key: {key}")
                return state
            else:
                logger.warning(f"State not found in Redis with key: {key}")
                return None
        except Exception as e:
            logger.error(f"Error loading state from Redis: {e}")
            return None
    
    def delete_state(self, key: str = "server_state") -> bool:
        """
        Delete state from storage.
        
        Args:
            key: Key to delete the state for (defaults to 'server_state')
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.storage_type == "file":
                return self._delete_from_file()
            elif self.storage_type == "sqlite":
                return self._delete_from_sqlite(key)
            elif self.storage_type == "redis":
                return self._delete_from_redis(key)
            else:
                logger.error(f"Unsupported storage type: {self.storage_type}")
                return False
        except Exception as e:
            logger.error(f"Error deleting state: {e}")
            return False
    
    def _delete_from_file(self) -> bool:
        """
        Delete state file.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Delete compressed file if exists
            if os.path.exists(f"{self.state_file}.gz"):
                os.remove(f"{self.state_file}.gz")
                logger.info(f"Deleted compressed state file: {self.state_file}.gz")
            
            # Delete regular file if exists
            if os.path.exists(self.state_file):
                os.remove(self.state_file)
                logger.info(f"Deleted state file: {self.state_file}")
                
            return True
        except Exception as e:
            logger.error(f"Error deleting state file: {e}")
            return False
    
    def _delete_from_sqlite(self, key: str) -> bool:
        """
        Delete state from SQLite.
        
        Args:
            key: Key to delete the state for
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self._conn:
                if not self._initialize_sqlite():
                    return False
            
            # Delete from database
            cursor = self._conn.cursor()
            cursor.execute('''
                DELETE FROM server_state
                WHERE id = ?
            ''', (key,))
            self._conn.commit()
            
            logger.info(f"Deleted state from SQLite with key: {key}")
            return True
        except Exception as e:
            logger.error(f"Error deleting state from SQLite: {e}")
            return False
    
    def _delete_from_redis(self, key: str) -> bool:
        """
        Delete state from Redis.
        
        Args:
            key: Key to delete the state for
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self._conn:
                if not self._initialize_redis():
                    return False
            
            # Delete from Redis
            self._conn.delete(f"forge:state:{key}")
            self._conn.delete(f"forge:state:{key}:updated")
            
            logger.info(f"Deleted state from Redis with key: {key}")
            return True
        except Exception as e:
            logger.error(f"Error deleting state from Redis: {e}")
            return False
    
    def set_value(self, key: str, value: Any) -> bool:
        """
        Set a value in the key-value store.
        
        Args:
            key: Key to set
            value: Value to set
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert value to JSON string if not a string
            if not isinstance(value, str):
                value = json.dumps(value)
                
            if self.storage_type == "file":
                return self._set_file_value(key, value)
            elif self.storage_type == "sqlite":
                return self._set_sqlite_value(key, value)
            elif self.storage_type == "redis":
                return self._set_redis_value(key, value)
            else:
                logger.error(f"Unsupported storage type: {self.storage_type}")
                return False
        except Exception as e:
            logger.error(f"Error setting value: {e}")
            return False
    
    def _set_file_value(self, key: str, value: str) -> bool:
        """
        Set a value in the file-based key-value store.
        
        Args:
            key: Key to set
            value: Value to set
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Load existing values
            kv_file = "forge_keyvalue_store.json"
            kv_store = {}
            
            if os.path.exists(kv_file):
                with open(kv_file, 'r') as f:
                    kv_store = json.load(f)
            
            # Update value
            kv_store[key] = {
                "value": value,
                "updated_at": datetime.now().isoformat()
            }
            
            # Save back to file
            with open(kv_file, 'w') as f:
                json.dump(kv_store, f, indent=2)
                
            logger.debug(f"Set value for key '{key}' in file store")
            return True
        except Exception as e:
            logger.error(f"Error setting value in file store: {e}")
            return False
    
    def _set_sqlite_value(self, key: str, value: str) -> bool:
        """
        Set a value in the SQLite key-value store.
        
        Args:
            key: Key to set
            value: Value to set
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self._conn:
                if not self._initialize_sqlite():
                    return False
            
            # Save to database
            cursor = self._conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO key_value_store (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (key, value))
            self._conn.commit()
            
            logger.debug(f"Set value for key '{key}' in SQLite store")
            return True
        except Exception as e:
            logger.error(f"Error setting value in SQLite store: {e}")
            return False
    
    def _set_redis_value(self, key: str, value: str) -> bool:
        """
        Set a value in the Redis key-value store.
        
        Args:
            key: Key to set
            value: Value to set
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self._conn:
                if not self._initialize_redis():
                    return False
            
            # Save to Redis
            self._conn.set(f"forge:kv:{key}", value)
            self._conn.set(f"forge:kv:{key}:updated", datetime.now().isoformat())
            
            # Set expiration if configured
            expiration = self.storage_options.get("expiration_days")
            if expiration:
                expiration_seconds = int(expiration) * 86400  # Convert days to seconds
                self._conn.expire(f"forge:kv:{key}", expiration_seconds)
                self._conn.expire(f"forge:kv:{key}:updated", expiration_seconds)
            
            logger.debug(f"Set value for key '{key}' in Redis store")
            return True
        except Exception as e:
            logger.error(f"Error setting value in Redis store: {e}")
            return False
    
    def get_value(self, key: str, default: Any = None) -> Any:
        """
        Get a value from the key-value store.
        
        Args:
            key: Key to get
            default: Default value if key not found
            
        Returns:
            Value if found, default otherwise
        """
        try:
            if self.storage_type == "file":
                return self._get_file_value(key, default)
            elif self.storage_type == "sqlite":
                return self._get_sqlite_value(key, default)
            elif self.storage_type == "redis":
                return self._get_redis_value(key, default)
            else:
                logger.error(f"Unsupported storage type: {self.storage_type}")
                return default
        except Exception as e:
            logger.error(f"Error getting value: {e}")
            return default
    
    def _get_file_value(self, key: str, default: Any) -> Any:
        """
        Get a value from the file-based key-value store.
        
        Args:
            key: Key to get
            default: Default value if key not found
            
        Returns:
            Value if found, default otherwise
        """
        try:
            kv_file = "forge_keyvalue_store.json"
            
            if not os.path.exists(kv_file):
                return default
            
            with open(kv_file, 'r') as f:
                kv_store = json.load(f)
            
            if key in kv_store:
                value = kv_store[key]["value"]
                
                # Try to parse JSON
                try:
                    return json.loads(value)
                except:
                    return value
            else:
                return default
        except Exception as e:
            logger.error(f"Error getting value from file store: {e}")
            return default
    
    def _get_sqlite_value(self, key: str, default: Any) -> Any:
        """
        Get a value from the SQLite key-value store.
        
        Args:
            key: Key to get
            default: Default value if key not found
            
        Returns:
            Value if found, default otherwise
        """
        try:
            if not self._conn:
                if not self._initialize_sqlite():
                    return default
            
            # Get from database
            cursor = self._conn.cursor()
            cursor.execute('''
                SELECT value FROM key_value_store
                WHERE key = ?
            ''', (key,))
            result = cursor.fetchone()
            
            if result:
                value = result[0]
                
                # Try to parse JSON
                try:
                    return json.loads(value)
                except:
                    return value
            else:
                return default
        except Exception as e:
            logger.error(f"Error getting value from SQLite store: {e}")
            return default
    
    def _get_redis_value(self, key: str, default: Any) -> Any:
        """
        Get a value from the Redis key-value store.
        
        Args:
            key: Key to get
            default: Default value if key not found
            
        Returns:
            Value if found, default otherwise
        """
        try:
            if not self._conn:
                if not self._initialize_redis():
                    return default
            
            # Get from Redis
            value = self._conn.get(f"forge:kv:{key}")
            
            if value:
                # Try to parse JSON
                try:
                    return json.loads(value)
                except:
                    return value
            else:
                return default
        except Exception as e:
            logger.error(f"Error getting value from Redis store: {e}")
            return default
    
    def check_auto_save(self, state: Dict[str, Any]) -> bool:
        """
        Check if it's time to auto-save the state and save if needed.
        
        Args:
            state: State dictionary to save
            
        Returns:
            True if saved, False otherwise
        """
        if not self.save_state:
            return False
            
        # Check if it's time to auto-save
        current_time = time.time()
        elapsed_minutes = (current_time - self._last_save_time) / 60
        
        if elapsed_minutes >= self.auto_save_interval:
            logger.debug(f"Auto-saving state after {elapsed_minutes:.1f} minutes")
            return self.save_state(state)
            
        return False 