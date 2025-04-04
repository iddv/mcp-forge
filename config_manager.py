#!/usr/bin/env python
"""
Configuration Manager for MCP-Forge

This module handles configuration loading, validation, and persistence
for the MCP-Forge server framework.
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

# Setup logging
logger = logging.getLogger('config_manager')

class ConfigManager:
    """
    Configuration manager for MCP-Forge.
    Handles configuration loading, validation, and persistence.
    """
    
    # Default configuration values
    DEFAULT_CONFIG = {
        "server": {
            "host": "localhost",
            "port": 9000,
            "log_level": "INFO",
            "max_servers": 100
        },
        "templates": {
            "default_capabilities": ["echo", "time", "uptime"],
            "allow_custom_capabilities": True,
            "default_handlers": []
        },
        "security": {
            "enable_authentication": False,
            "authentication_type": "basic",
            "allowed_ip_ranges": ["127.0.0.1/32", "::1/128"]
        },
        "resources": {
            "memory_limit_mb": 500,
            "cpu_limit_percent": 50,
            "enable_throttling": False
        },
        "persistence": {
            "save_server_state": True,
            "state_file": "forge_server_state.json",
            "backup_count": 3
        }
    }
    
    def __init__(self, config_file: str = "forge_config.json"):
        """
        Initialize the configuration manager.
        
        Args:
            config_file: Path to the configuration file
        """
        self.config_file = config_file
        self.config = self.DEFAULT_CONFIG.copy()
        self.config_loaded = False
        
    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file.
        If the file doesn't exist, create it with default values.
        
        Returns:
            Loaded configuration dictionary
        """
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                
                # Merge loaded config with defaults (to ensure all keys exist)
                self._merge_configs(self.config, loaded_config)
                logger.info(f"Configuration loaded from {self.config_file}")
            else:
                # Create default config file
                self.save_config()
                logger.info(f"Created default configuration at {self.config_file}")
            
            self.config_loaded = True
            return self.config
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            logger.info("Using default configuration")
            return self.config
    
    def save_config(self) -> bool:
        """
        Save current configuration to file.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info(f"Configuration saved to {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
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
            
        return self.config[section].get(key, default)
    
    def set(self, section: str, key: str, value: Any) -> bool:
        """
        Set a configuration value.
        
        Args:
            section: Configuration section
            key: Key within the section
            value: Value to set
            
        Returns:
            True if successful, False otherwise
        """
        if not self.config_loaded:
            self.load_config()
            
        if section not in self.config:
            self.config[section] = {}
            
        self.config[section][key] = value
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
            
        self.config[section].update(values)
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
        
        # Validate server section
        server = self.config.get("server", {})
        if not isinstance(server.get("port"), int) or not (1024 <= server.get("port") <= 65535):
            errors.append("Server port must be an integer between 1024 and 65535")
            
        if not isinstance(server.get("max_servers"), int) or server.get("max_servers") <= 0:
            errors.append("Maximum number of servers must be a positive integer")
            
        # Validate templates section
        templates = self.config.get("templates", {})
        if not isinstance(templates.get("default_capabilities"), list):
            errors.append("Default capabilities must be a list")
            
        if not isinstance(templates.get("allow_custom_capabilities"), bool):
            errors.append("Allow custom capabilities must be a boolean")
            
        # Validate resources section
        resources = self.config.get("resources", {})
        if not isinstance(resources.get("memory_limit_mb"), (int, float)) or resources.get("memory_limit_mb") <= 0:
            errors.append("Memory limit must be a positive number")
            
        if not isinstance(resources.get("cpu_limit_percent"), (int, float)) or not (0 < resources.get("cpu_limit_percent") <= 100):
            errors.append("CPU limit must be a number between 0 and 100")
            
        return errors
    
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
            "max_servers": self.get("server", "max_servers", 100)
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
            "default_handlers": self.get("templates", "default_handlers", [])
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
                self._merge_configs(target[key], value)
            else:
                target[key] = value
                
        return target 