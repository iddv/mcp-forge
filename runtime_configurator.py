#!/usr/bin/env python
"""
Runtime Configurator for MCP-Forge

This module provides capabilities for dynamically updating configuration at runtime
without requiring a server restart.
"""

import json
import logging
import threading
import time
from typing import Dict, Any, Optional, List, Callable, Set, Tuple

# Setup logging
logger = logging.getLogger('runtime_configurator')

class RuntimeConfigurator:
    """
    Runtime configurator for MCP-Forge.
    Allows for dynamic configuration updates without server restart.
    """
    
    def __init__(self, config_manager, storage_manager=None):
        """
        Initialize the runtime configurator.
        
        Args:
            config_manager: ConfigManager instance
            storage_manager: Optional StorageManager instance for persistence
        """
        self.config_manager = config_manager
        self.storage_manager = storage_manager
        self.change_observers = {}  # section:key -> list of observer callbacks
        self.section_observers = {}  # section -> list of observer callbacks
        self.global_observers = []  # list of global observer callbacks
        self._config_watch_thread = None
        self._running = False
        self._lock = threading.RLock()
        self._last_config_hash = self._calculate_config_hash()
        
    def _calculate_config_hash(self) -> str:
        """
        Calculate a hash of the current configuration for change detection.
        
        Returns:
            Hash string of the configuration
        """
        import hashlib
        config_str = json.dumps(self.config_manager.config, sort_keys=True)
        return hashlib.md5(config_str.encode()).hexdigest()
        
    def start_watching(self, interval_seconds: int = 5) -> bool:
        """
        Start a background thread to watch for configuration changes.
        
        Args:
            interval_seconds: Interval in seconds to check for changes
            
        Returns:
            True if started successfully, False otherwise
        """
        with self._lock:
            if self._running:
                logger.warning("Configuration watch thread is already running")
                return False
                
            def watch_config():
                logger.info("Configuration watch thread started")
                self._running = True
                while self._running:
                    try:
                        # Reload configuration from file
                        self.config_manager.load_config()
                        
                        # Check for changes
                        current_hash = self._calculate_config_hash()
                        if current_hash != self._last_config_hash:
                            logger.info("Configuration changes detected, notifying observers")
                            self._notify_observers()
                            self._last_config_hash = current_hash
                    except Exception as e:
                        logger.error(f"Error in configuration watch thread: {e}")
                        
                    # Sleep for the specified interval
                    time.sleep(interval_seconds)
                
                logger.info("Configuration watch thread stopped")
            
            # Start the thread
            self._config_watch_thread = threading.Thread(
                target=watch_config,
                name="ConfigWatchThread",
                daemon=True
            )
            self._config_watch_thread.start()
            
            return True
            
    def stop_watching(self) -> bool:
        """
        Stop the configuration watch thread.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        with self._lock:
            if not self._running:
                logger.warning("Configuration watch thread is not running")
                return False
                
            self._running = False
            if self._config_watch_thread:
                # Wait for the thread to stop
                if self._config_watch_thread != threading.current_thread():
                    self._config_watch_thread.join(timeout=10)
                self._config_watch_thread = None
                
            return True
    
    def register_observer(self, callback: Callable[[Dict[str, Any]], None], 
                          section: Optional[str] = None, 
                          key: Optional[str] = None) -> None:
        """
        Register an observer callback for configuration changes.
        
        Args:
            callback: Function to call when configuration changes
            section: Configuration section to observe (None for all sections)
            key: Configuration key to observe (None for all keys in the section)
        """
        with self._lock:
            if section is None and key is None:
                # Global observer
                self.global_observers.append(callback)
                logger.debug(f"Registered global configuration observer: {callback.__name__}")
            elif section is not None and key is None:
                # Section observer
                if section not in self.section_observers:
                    self.section_observers[section] = []
                self.section_observers[section].append(callback)
                logger.debug(f"Registered section observer for '{section}': {callback.__name__}")
            elif section is not None and key is not None:
                # Specific key observer
                observer_key = f"{section}:{key}"
                if observer_key not in self.change_observers:
                    self.change_observers[observer_key] = []
                self.change_observers[observer_key].append(callback)
                logger.debug(f"Registered key observer for '{observer_key}': {callback.__name__}")
            else:
                # Invalid combination
                logger.error("Invalid observer registration: section must be specified if key is specified")
    
    def unregister_observer(self, callback: Callable[[Dict[str, Any]], None], 
                           section: Optional[str] = None, 
                           key: Optional[str] = None) -> bool:
        """
        Unregister an observer callback.
        
        Args:
            callback: Function to remove
            section: Configuration section of the observer
            key: Configuration key of the observer
            
        Returns:
            True if removed, False if not found
        """
        with self._lock:
            if section is None and key is None:
                # Global observer
                if callback in self.global_observers:
                    self.global_observers.remove(callback)
                    logger.debug(f"Unregistered global configuration observer: {callback.__name__}")
                    return True
            elif section is not None and key is None:
                # Section observer
                if section in self.section_observers and callback in self.section_observers[section]:
                    self.section_observers[section].remove(callback)
                    logger.debug(f"Unregistered section observer for '{section}': {callback.__name__}")
                    return True
            elif section is not None and key is not None:
                # Specific key observer
                observer_key = f"{section}:{key}"
                if observer_key in self.change_observers and callback in self.change_observers[observer_key]:
                    self.change_observers[observer_key].remove(callback)
                    logger.debug(f"Unregistered key observer for '{observer_key}': {callback.__name__}")
                    return True
                    
            return False
    
    def _notify_observers(self) -> None:
        """Notify all relevant observers of configuration changes."""
        # Compare old and new configuration to determine what changed
        changed_sections = set()
        changed_keys = set()
        
        # For now, we'll just assume everything changed since we don't have the old config
        for section in self.config_manager.config:
            changed_sections.add(section)
            for key in self.config_manager.config[section]:
                changed_keys.add(f"{section}:{key}")
        
        # Notify specific key observers
        for key in changed_keys:
            if key in self.change_observers:
                for callback in self.change_observers[key]:
                    try:
                        section, prop = key.split(':', 1)
                        value = self.config_manager.get(section, prop)
                        callback({"section": section, "key": prop, "value": value})
                    except Exception as e:
                        logger.error(f"Error notifying key observer for '{key}': {e}")
        
        # Notify section observers
        for section in changed_sections:
            if section in self.section_observers:
                for callback in self.section_observers[section]:
                    try:
                        section_config = self.config_manager.get(section)
                        callback({"section": section, "config": section_config})
                    except Exception as e:
                        logger.error(f"Error notifying section observer for '{section}': {e}")
        
        # Notify global observers
        for callback in self.global_observers:
            try:
                callback({"config": self.config_manager.config})
            except Exception as e:
                logger.error(f"Error notifying global observer: {e}")
    
    def update_config(self, section: str, key: str, value: Any) -> bool:
        """
        Update a configuration value at runtime.
        
        Args:
            section: Configuration section
            key: Configuration key (can use dot notation for nested values)
            value: New value
            
        Returns:
            True if updated successfully, False otherwise
        """
        try:
            # Update the configuration
            result = self.config_manager.set(section, key, value)
            if result:
                logger.info(f"Runtime configuration updated: {section}.{key}")
                
                # Notify observers
                with self._lock:
                    # Key observers
                    observer_key = f"{section}:{key}"
                    if observer_key in self.change_observers:
                        for callback in self.change_observers[observer_key]:
                            try:
                                callback({"section": section, "key": key, "value": value})
                            except Exception as e:
                                logger.error(f"Error notifying key observer for '{observer_key}': {e}")
                    
                    # Section observers
                    if section in self.section_observers:
                        section_config = self.config_manager.get(section)
                        for callback in self.section_observers[section]:
                            try:
                                callback({"section": section, "config": section_config})
                            except Exception as e:
                                logger.error(f"Error notifying section observer for '{section}': {e}")
                    
                    # Global observers
                    for callback in self.global_observers:
                        try:
                            callback({"config": self.config_manager.config})
                        except Exception as e:
                            logger.error(f"Error notifying global observer: {e}")
                
                # Update hash
                self._last_config_hash = self._calculate_config_hash()
                
                return True
            else:
                logger.error(f"Failed to update configuration: {section}.{key}")
                return False
        except Exception as e:
            logger.error(f"Error updating configuration: {e}")
            return False
    
    def update_section(self, section: str, values: Dict[str, Any]) -> bool:
        """
        Update an entire configuration section at runtime.
        
        Args:
            section: Configuration section
            values: Dictionary of values to set
            
        Returns:
            True if updated successfully, False otherwise
        """
        try:
            # Update the configuration
            result = self.config_manager.update_section(section, values)
            if result:
                logger.info(f"Runtime configuration section updated: {section}")
                
                # Notify observers
                with self._lock:
                    # Notify section observers
                    if section in self.section_observers:
                        section_config = self.config_manager.get(section)
                        for callback in self.section_observers[section]:
                            try:
                                callback({"section": section, "config": section_config})
                            except Exception as e:
                                logger.error(f"Error notifying section observer for '{section}': {e}")
                    
                    # Notify key observers for each updated key
                    for key in values:
                        observer_key = f"{section}:{key}"
                        if observer_key in self.change_observers:
                            for callback in self.change_observers[observer_key]:
                                try:
                                    callback({"section": section, "key": key, "value": values[key]})
                                except Exception as e:
                                    logger.error(f"Error notifying key observer for '{observer_key}': {e}")
                    
                    # Notify global observers
                    for callback in self.global_observers:
                        try:
                            callback({"config": self.config_manager.config})
                        except Exception as e:
                            logger.error(f"Error notifying global observer: {e}")
                
                # Update hash
                self._last_config_hash = self._calculate_config_hash()
                
                return True
            else:
                logger.error(f"Failed to update configuration section: {section}")
                return False
        except Exception as e:
            logger.error(f"Error updating configuration section: {e}")
            return False
    
    def reload_config(self) -> bool:
        """
        Reload the configuration from disk.
        
        Returns:
            True if reloaded successfully, False otherwise
        """
        try:
            old_hash = self._last_config_hash
            
            # Reload the configuration
            self.config_manager.load_config()
            
            # Check if there were changes
            new_hash = self._calculate_config_hash()
            if new_hash != old_hash:
                logger.info("Configuration reloaded with changes")
                
                # Notify observers
                self._notify_observers()
                
                # Update hash
                self._last_config_hash = new_hash
            else:
                logger.info("Configuration reloaded (no changes detected)")
                
            return True
        except Exception as e:
            logger.error(f"Error reloading configuration: {e}")
            return False
    
    def get_modifiable_settings(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get a list of settings that can be modified at runtime.
        
        Returns:
            Dictionary of sections with modifiable settings
        """
        modifiable = {}
        
        # Get the schema if available
        schema = getattr(self.config_manager, 'schema', None)
        if not schema:
            # Without a schema, we just return the current configuration
            return {section: [{"key": key, "value": value, "type": type(value).__name__} 
                             for key, value in self.config_manager.config[section].items()]
                   for section in self.config_manager.config}
        
        # With a schema, we can provide more detailed information
        for section, section_schema in schema.get("properties", {}).items():
            if section not in modifiable:
                modifiable[section] = []
                
            for key, prop_schema in section_schema.get("properties", {}).items():
                value = self.config_manager.get(section, key)
                modifiable[section].append({
                    "key": key,
                    "value": value,
                    "type": prop_schema.get("type", type(value).__name__),
                    "description": prop_schema.get("description", ""),
                    "default": prop_schema.get("default", None),
                    "constraints": self._get_constraints(prop_schema)
                })
                
        return modifiable
    
    def _get_constraints(self, prop_schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract constraints from a property schema.
        
        Args:
            prop_schema: Property schema
            
        Returns:
            Dictionary of constraints
        """
        constraints = {}
        
        if "minimum" in prop_schema:
            constraints["minimum"] = prop_schema["minimum"]
        if "maximum" in prop_schema:
            constraints["maximum"] = prop_schema["maximum"]
        if "enum" in prop_schema:
            constraints["enum"] = prop_schema["enum"]
        if "pattern" in prop_schema:
            constraints["pattern"] = prop_schema["pattern"]
            
        return constraints
    
    def export_config(self, file_path: str) -> bool:
        """
        Export the current configuration to a file.
        
        Args:
            file_path: Path to export the configuration to
            
        Returns:
            True if exported successfully, False otherwise
        """
        return self.config_manager.export_config(file_path)
    
    def import_config(self, file_path: str) -> bool:
        """
        Import configuration from a file.
        
        Args:
            file_path: Path to import the configuration from
            
        Returns:
            True if imported successfully, False otherwise
        """
        result = self.config_manager.import_config(file_path)
        if result:
            # Update hash and notify observers
            self._last_config_hash = self._calculate_config_hash()
            self._notify_observers()
            
        return result 