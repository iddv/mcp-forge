#!/usr/bin/env python
"""
Configuration Manager for MCP-Forge

This module handles configuration loading, validation, and persistence
for the MCP-Forge server framework.
"""

import json
import logging
import os
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Tuple
import time
from datetime import datetime

# Setup logging
logger = logging.getLogger('config_manager')

class ConfigManager:
    """
    Configuration manager for MCP-Forge.
    Handles configuration loading, validation, and persistence.
    """
    
    # Add debounce control to prevent excessive backups
    _last_backup_time = 0
    _backup_min_interval = 60  # Minimum seconds between backups
    _backup_in_progress = False
    
    # Default configuration values
    DEFAULT_CONFIG = {
        "server": {
            "host": "localhost",
            "port": 9000,
            "log_level": "INFO",
            "max_servers": 100,
            "auto_start": True
        },
        "templates": {
            "default_capabilities": ["echo", "time", "uptime"],
            "allow_custom_capabilities": True,
            "default_handlers": [],
            "custom_templates_dir": "custom_templates"
        },
        "security": {
            "enable_authentication": False,
            "authentication_type": "basic",
            "allowed_ip_ranges": ["127.0.0.1/32", "::1/128"],
            "ssl": {
                "enabled": False,
                "cert_file": "",
                "key_file": ""
            }
        },
        "resources": {
            "memory_limit_mb": 500,
            "cpu_limit_percent": 50,
            "enable_throttling": False,
            "throttling_strategy": "pause",
            "monitor_interval_seconds": 10,
            "alerts": {
                "memory_warning_percent": 80,
                "cpu_warning_percent": 80
            }
        },
        "persistence": {
            "save_server_state": True,
            "state_file": "forge_server_state.json",
            "backup_count": 3,
            "auto_save_interval_minutes": 10,
            "storage_type": "file",
            "storage_options": {}
        },
        "advanced": {
            "debug_mode": False,
            "enable_experimental": False,
            "process_priority": "normal",
            "connection_timeout_seconds": 30,
            "request_timeout_seconds": 60
        }
    }
    
    def __init__(self, config_file: str = "forge_config.json", schema_file: str = "forge_config.schema.json", backup_dir: str = "config_backups"):
        """
        Initialize the configuration manager.
        
        Args:
            config_file: Path to the configuration file
            schema_file: Path to the JSON schema file
            backup_dir: Directory for configuration backups
        """
        self.config_file = config_file
        self.schema_file = schema_file
        self.backup_dir = backup_dir
        self.config = deepcopy(self.DEFAULT_CONFIG)
        self.schema = None
        self.config_loaded = False
        
        # Create backup directory if it doesn't exist
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        # Try to load schema file
        self._load_schema()
        
        # Load or create configuration
        if os.path.exists(config_file):
            self.load_config()
        else:
            self._create_default_config()
        
    def _load_schema(self):
        """Load JSON schema for configuration validation."""
        if os.path.exists(self.schema_file):
            try:
                with open(self.schema_file, 'r') as f:
                    self.schema = json.load(f)
                logger.info(f"Schema loaded from {self.schema_file}")
            except Exception as e:
                logger.error(f"Error loading schema: {e}")
                self.schema = None
        else:
            logger.warning(f"Schema file not found: {self.schema_file}")
            self.schema = None
    
    def _create_default_config(self):
        """Create a default configuration."""
        self.config = deepcopy(self.DEFAULT_CONFIG)
        self.save_config()
        logger.info(f"Created default configuration at {self.config_file}")
    
    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file.
        
        Returns:
            Loaded configuration dictionary
        """
        try:
            # Ensure schema is loaded
            if self.schema is None:
                self._load_schema()
                
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                
                # Make a backup of the existing config before merging
                self._create_backup()
                
                # Merge loaded config with defaults (to ensure all keys exist)
                self._merge_configs(self.config, loaded_config)
                logger.info(f"Configuration loaded from {self.config_file}")
            else:
                # Create default config file
                self.save_config()
                logger.info(f"Created default configuration at {self.config_file}")
            
            # Validate the config
            errors = self.validate_config()
            if errors:
                logger.warning(f"Configuration validation found {len(errors)} issues:")
                for error in errors:
                    logger.warning(f"  - {error}")
                
            self.config_loaded = True
            return self.config
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            logger.info("Using default configuration")
            return self.config
    
    def _create_backup(self) -> bool:
        """
        Create a backup of the current configuration.
        
        Returns:
            Boolean indicating success.
        """
        # Skip backup if we're already creating one (prevent recursion)
        if ConfigManager._backup_in_progress:
            return True
            
        # Debounce: prevent excessive backups
        current_time = time.time()
        if current_time - ConfigManager._last_backup_time < ConfigManager._backup_min_interval:
            logger.debug("Skipping backup due to debounce interval")
            return True
        
        # Only backup if the file exists
        if not os.path.exists(self.config_file):
            return False
            
        try:
            ConfigManager._backup_in_progress = True
            
            # Generate backup filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(
                self.backup_dir, 
                f"{os.path.basename(self.config_file).split('.')[0]}_{timestamp}.json"
            )
            
            # Copy the file
            with open(self.config_file, 'r') as source:
                config_data = source.read()
                
            with open(backup_file, 'w') as target:
                target.write(config_data)
                
            logger.info(f"Created configuration backup at {backup_file}")
            ConfigManager._last_backup_time = current_time
            return True
        except Exception as e:
            logger.error(f"Error creating configuration backup: {e}")
            return False
        finally:
            ConfigManager._backup_in_progress = False
    
    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            section: Configuration section
            key: Key within the section (if None, returns the entire section)
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default
        """
        if not self.config_loaded:
            self.load_config()
            
        if section not in self.config:
            return default
            
        if key is None:
            return self.config[section]
        
        # Handle nested keys with dot notation
        if '.' in key:
            keys = key.split('.')
            value = self.config[section]
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            return value
            
        return self.config[section].get(key, default)
    
    def set(self, section: str, key: str, value: Any) -> bool:
        """
        Set a configuration value.
        
        Args:
            section: Configuration section
            key: Key within the section (can use dot notation for nested values)
            value: Value to set
            
        Returns:
            True if successful, False otherwise
        """
        if not self.config_loaded:
            self.load_config()
            
        if section not in self.config:
            self.config[section] = {}
        
        # Handle nested keys with dot notation
        if '.' in key:
            keys = key.split('.')
            target = self.config[section]
            for k in keys[:-1]:
                if k not in target:
                    target[k] = {}
                target = target[k]
            target[keys[-1]] = value
        else:
            self.config[section][key] = value
            
        # Validate the change
        error = self._validate_single_value(section, key, value)
        if error:
            logger.warning(f"Configuration setting has validation issue: {error}")
            
        return self.save_config()
    
    def update_section(self, section: str, values: Dict[str, Any]) -> bool:
        """
        Update an entire configuration section.
        
        Args:
            section: Configuration section
            values: Dictionary of values to set
            
        Returns:
            True if successful, False otherwise
        """
        if not self.config_loaded:
            self.load_config()
            
        if section not in self.config:
            self.config[section] = {}
            
        # Recursively update the section
        self._merge_configs(self.config[section], values)
        
        return self.save_config()
    
    def validate_config(self) -> List[str]:
        """
        Validate the current configuration.
        
        Returns:
            List of validation errors (empty if valid)
        """
        if not self.config_loaded:
            self.load_config()
            
        errors = []
        
        # Use JSON Schema validation if available
        if self.schema:
            errors.extend(self._validate_against_schema())
            if errors:
                return errors
                
        # Perform additional validation checks
                
        # Validate server section
        server = self.config.get("server", {})
        if not isinstance(server.get("port"), int) or not (1024 <= server.get("port") <= 65535):
            errors.append("server.port must be an integer between 1024 and 65535")
            
        if not isinstance(server.get("max_servers"), int) or server.get("max_servers") <= 0:
            errors.append("server.max_servers must be a positive integer")
            
        # Validate templates section
        templates = self.config.get("templates", {})
        if not isinstance(templates.get("default_capabilities"), list):
            errors.append("templates.default_capabilities must be a list")
            
        if not isinstance(templates.get("allow_custom_capabilities"), bool):
            errors.append("templates.allow_custom_capabilities must be a boolean")
            
        # Validate resources section
        resources = self.config.get("resources", {})
        if not isinstance(resources.get("memory_limit_mb"), (int, float)) or resources.get("memory_limit_mb") <= 0:
            errors.append("resources.memory_limit_mb must be a positive number")
            
        if not isinstance(resources.get("cpu_limit_percent"), (int, float)) or not (0 < resources.get("cpu_limit_percent") <= 100):
            errors.append("resources.cpu_limit_percent must be a number between 0 and 100")
            
        # Validate SSL configuration
        security = self.config.get("security", {})
        ssl_config = security.get("ssl", {})
        if ssl_config.get("enabled", False):
            cert_file = ssl_config.get("cert_file", "")
            key_file = ssl_config.get("key_file", "")
            if not cert_file or not os.path.exists(cert_file):
                errors.append(f"security.ssl.cert_file '{cert_file}' not found")
            if not key_file or not os.path.exists(key_file):
                errors.append(f"security.ssl.key_file '{key_file}' not found")
        
        return errors
    
    def _validate_against_schema(self) -> List[str]:
        """
        Validate the configuration against the JSON schema.
        
        Returns:
            List of validation errors (empty if valid)
        """
        if not self.schema:
            return []
            
        try:
            # Use jsonschema library if available
            try:
                import jsonschema
                jsonschema.validate(instance=self.config, schema=self.schema)
                return []
            except ImportError:
                logger.warning("jsonschema library not found, using basic validation")
                return self._basic_schema_validation()
            except jsonschema.exceptions.ValidationError as e:
                return [str(e)]
        except Exception as e:
            logger.error(f"Error during schema validation: {e}")
            return [f"Schema validation error: {str(e)}"]
    
    def _basic_schema_validation(self) -> List[str]:
        """
        Perform basic schema validation without using jsonschema.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Check required sections
        required_sections = self.schema.get("required", [])
        for section in required_sections:
            if section not in self.config:
                errors.append(f"Missing required section: {section}")
        
        # Validate each section
        for section, section_schema in self.schema.get("properties", {}).items():
            if section not in self.config:
                continue
                
            # Check required properties
            required_props = section_schema.get("required", [])
            for prop in required_props:
                if prop not in self.config[section]:
                    errors.append(f"Missing required property: {section}.{prop}")
            
            # Validate property types and values
            for prop, prop_schema in section_schema.get("properties", {}).items():
                if prop not in self.config[section]:
                    continue
                    
                value = self.config[section][prop]
                prop_type = prop_schema.get("type")
                
                # Check type
                if prop_type == "string" and not isinstance(value, str):
                    errors.append(f"{section}.{prop} must be a string")
                elif prop_type == "integer" and not isinstance(value, int):
                    errors.append(f"{section}.{prop} must be an integer")
                elif prop_type == "number" and not isinstance(value, (int, float)):
                    errors.append(f"{section}.{prop} must be a number")
                elif prop_type == "boolean" and not isinstance(value, bool):
                    errors.append(f"{section}.{prop} must be a boolean")
                elif prop_type == "array" and not isinstance(value, list):
                    errors.append(f"{section}.{prop} must be an array")
                elif prop_type == "object" and not isinstance(value, dict):
                    errors.append(f"{section}.{prop} must be an object")
                
                # Check enum
                if "enum" in prop_schema and value not in prop_schema["enum"]:
                    enum_values = ", ".join([str(v) for v in prop_schema["enum"]])
                    errors.append(f"{section}.{prop} must be one of: {enum_values}")
                
                # Check minimum/maximum
                if isinstance(value, (int, float)):
                    if "minimum" in prop_schema and value < prop_schema["minimum"]:
                        errors.append(f"{section}.{prop} must be at least {prop_schema['minimum']}")
                    if "maximum" in prop_schema and value > prop_schema["maximum"]:
                        errors.append(f"{section}.{prop} must be at most {prop_schema['maximum']}")
        
        return errors
    
    def _validate_single_value(self, section: str, key: str, value: Any) -> Optional[str]:
        """
        Validate a single configuration value.
        
        Args:
            section: Configuration section
            key: Key within the section
            value: Value to validate
            
        Returns:
            Error message if invalid, None if valid
        """
        if not self.schema:
            return None
            
        # Parse nested keys
        keys = key.split('.') if '.' in key else [key]
        
        try:
            # Find the schema for this property
            section_schema = self.schema.get("properties", {}).get(section, {})
            if not section_schema:
                return None
                
            prop_schema = section_schema.get("properties", {})
            for k in keys:
                if k not in prop_schema:
                    return None
                if "properties" in prop_schema[k]:
                    prop_schema = prop_schema[k].get("properties", {})
                else:
                    prop_schema = prop_schema[k]
            
            # Validate type
            prop_type = prop_schema.get("type")
            if prop_type == "string" and not isinstance(value, str):
                return f"{section}.{key} must be a string"
            elif prop_type == "integer" and not isinstance(value, int):
                return f"{section}.{key} must be an integer"
            elif prop_type == "number" and not isinstance(value, (int, float)):
                return f"{section}.{key} must be a number"
            elif prop_type == "boolean" and not isinstance(value, bool):
                return f"{section}.{key} must be a boolean"
            elif prop_type == "array" and not isinstance(value, list):
                return f"{section}.{key} must be an array"
            elif prop_type == "object" and not isinstance(value, dict):
                return f"{section}.{key} must be an object"
            
            # Check enum
            if "enum" in prop_schema and value not in prop_schema["enum"]:
                enum_values = ", ".join([str(v) for v in prop_schema["enum"]])
                return f"{section}.{key} must be one of: {enum_values}"
            
            # Check minimum/maximum
            if isinstance(value, (int, float)):
                if "minimum" in prop_schema and value < prop_schema["minimum"]:
                    return f"{section}.{key} must be at least {prop_schema['minimum']}"
                if "maximum" in prop_schema and value > prop_schema["maximum"]:
                    return f"{section}.{key} must be at most {prop_schema['maximum']}"
            
            return None
        except Exception as e:
            logger.error(f"Error validating {section}.{key}: {e}")
            return None
    
    def get_server_config(self) -> Dict[str, Any]:
        """
        Get server configuration for use in the forge server.
        
        Returns:
            Server configuration dictionary
        """
        if not self.config_loaded:
            self.load_config()
            
        return {
            "host": self.get("server", "host", "localhost"),
            "port": self.get("server", "port", 9000),
            "log_level": self.get("server", "log_level", "INFO"),
            "max_servers": self.get("server", "max_servers", 100),
            "auto_start": self.get("server", "auto_start", True)
        }
        
    def get_template_config(self) -> Dict[str, Any]:
        """
        Get template configuration for use in the template system.
        
        Returns:
            Template configuration dictionary
        """
        if not self.config_loaded:
            self.load_config()
            
        return {
            "default_capabilities": self.get("templates", "default_capabilities", ["echo", "time", "uptime"]),
            "allow_custom_capabilities": self.get("templates", "allow_custom_capabilities", True),
            "default_handlers": self.get("templates", "default_handlers", []),
            "custom_templates_dir": self.get("templates", "custom_templates_dir", "custom_templates")
        }
    
    def get_security_config(self) -> Dict[str, Any]:
        """
        Get security configuration.
        
        Returns:
            Security configuration dictionary
        """
        if not self.config_loaded:
            self.load_config()
            
        return {
            "enable_authentication": self.get("security", "enable_authentication", False),
            "authentication_type": self.get("security", "authentication_type", "basic"),
            "allowed_ip_ranges": self.get("security", "allowed_ip_ranges", ["127.0.0.1/32", "::1/128"]),
            "ssl": self.get("security", "ssl", {"enabled": False, "cert_file": "", "key_file": ""})
        }
    
    def get_resource_config(self) -> Dict[str, Any]:
        """
        Get resource configuration.
        
        Returns:
            Resource configuration dictionary
        """
        if not self.config_loaded:
            self.load_config()
            
        return {
            "memory_limit_mb": self.get("resources", "memory_limit_mb", 500),
            "cpu_limit_percent": self.get("resources", "cpu_limit_percent", 50),
            "enable_throttling": self.get("resources", "enable_throttling", False),
            "throttling_strategy": self.get("resources", "throttling_strategy", "pause"),
            "monitor_interval_seconds": self.get("resources", "monitor_interval_seconds", 10),
            "alerts": self.get("resources", "alerts", {
                "memory_warning_percent": 80,
                "cpu_warning_percent": 80
            })
        }
        
    def get_persistence_config(self) -> Dict[str, Any]:
        """
        Get persistence configuration.
        
        Returns:
            Persistence configuration dictionary
        """
        if not self.config_loaded:
            self.load_config()
            
        return {
            "save_server_state": self.get("persistence", "save_server_state", True),
            "state_file": self.get("persistence", "state_file", "forge_server_state.json"),
            "backup_count": self.get("persistence", "backup_count", 3),
            "auto_save_interval_minutes": self.get("persistence", "auto_save_interval_minutes", 10),
            "storage_type": self.get("persistence", "storage_type", "file"),
            "storage_options": self.get("persistence", "storage_options", {})
        }
    
    def _merge_configs(self, target: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively merge source config into target config.
        
        Args:
            target: Target configuration dictionary
            source: Source configuration dictionary
            
        Returns:
            Merged configuration dictionary
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                # Recursively merge nested dictionaries
                self._merge_configs(target[key], value)
            else:
                # Overwrite or add the value
                target[key] = value
                
        return target
        
    def export_config(self, file_path: str) -> bool:
        """
        Export the current configuration to a file.
        
        Args:
            file_path: Path to export the configuration to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(file_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info(f"Configuration exported to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting configuration: {e}")
            return False
    
    def import_config(self, file_path: str) -> bool:
        """
        Import configuration from a file.
        
        Args:
            file_path: Path to import the configuration from
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(file_path, 'r') as f:
                imported_config = json.load(f)
            
            # Validate imported config
            old_config = deepcopy(self.config)
            self.config = deepcopy(self.DEFAULT_CONFIG)
            self._merge_configs(self.config, imported_config)
            
            errors = self.validate_config()
            if errors:
                logger.warning(f"Imported configuration has {len(errors)} validation issues")
                logger.warning("Reverting to previous configuration")
                self.config = old_config
                return False
            
            # Save the imported config
            return self.save_config()
        except Exception as e:
            logger.error(f"Error importing configuration: {e}")
            return False 