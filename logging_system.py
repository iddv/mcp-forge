#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Centralized Logging System for MCP-Forge

This module provides a comprehensive logging system for the MCP-Forge framework,
including log aggregation, log rotation, log formatting, and log level management.
It centralizes logs from all child MCP servers and the forge server itself.
"""

import os
import sys
import json
import time
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union, Any

# Configure the logging directory
LOG_DIR = Path("logs")
if not LOG_DIR.exists():
    LOG_DIR.mkdir(exist_ok=True)

# Constants for log configuration
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
DEFAULT_RETENTION_DAYS = 7
MAX_LOG_SIZE_MB = 10
LOG_ROTATION_COUNT = 5


class LoggingSystem:
    """
    Centralized logging system for MCP-Forge that manages logs for
    the forge server and all child MCP servers.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the logging system with the provided configuration.
        
        Args:
            config: Configuration dictionary for logging system
        """
        self.config = config or {}
        self.log_level = self._get_config_value("log_level", DEFAULT_LOG_LEVEL)
        self.log_format = self._get_config_value("log_format", DEFAULT_LOG_FORMAT)
        self.retention_days = self._get_config_value("retention_days", DEFAULT_RETENTION_DAYS)
        self.max_log_size_mb = self._get_config_value("max_log_size_mb", MAX_LOG_SIZE_MB)
        self.log_rotation_count = self._get_config_value("log_rotation_count", LOG_ROTATION_COUNT)
        
        # Dictionary to store all loggers
        self.loggers = {}
        
        # Set up the root logger
        self._setup_root_logger()
        
        # Set up the forge server logger
        self.forge_logger = self.get_logger("forge_mcp_server")
        
        # Initialize structure for child server loggers
        self.child_loggers = {}

    def _get_config_value(self, key: str, default: Any) -> Any:
        """Get a configuration value or return the default if not found."""
        return self.config.get(key, default)

    def _setup_root_logger(self) -> None:
        """Set up the root logger with appropriate handlers and formatters."""
        root_logger = logging.getLogger()
        root_logger.setLevel(self.log_level)
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Create formatter
        formatter = logging.Formatter(self.log_format)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # File handler for aggregated logs
        aggregated_log_path = LOG_DIR / "forge_aggregated.log"
        file_handler = logging.handlers.RotatingFileHandler(
            aggregated_log_path, 
            maxBytes=self.max_log_size_mb * 1024 * 1024,
            backupCount=self.log_rotation_count
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    def get_logger(self, name: str) -> logging.Logger:
        """
        Get or create a logger with the given name.
        
        Args:
            name: Name of the logger
            
        Returns:
            Logger instance
        """
        if name in self.loggers:
            return self.loggers[name]
        
        logger = logging.getLogger(name)
        
        # Create a specific file handler for this logger
        log_file = LOG_DIR / f"{name}.log"
        handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self.max_log_size_mb * 1024 * 1024,
            backupCount=self.log_rotation_count
        )
        formatter = logging.Formatter(self.log_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        self.loggers[name] = logger
        return logger

    def register_child_logger(self, server_id: str, server_name: str) -> logging.Logger:
        """
        Register a new child server logger.
        
        Args:
            server_id: Unique ID of the child server
            server_name: Name of the child server
            
        Returns:
            Logger for the child server
        """
        logger_name = f"child_server_{server_id}"
        logger = self.get_logger(logger_name)
        
        # Store additional metadata
        self.child_loggers[server_id] = {
            "logger": logger,
            "name": server_name,
            "created_at": datetime.now().isoformat(),
            "log_file": str(LOG_DIR / f"{logger_name}.log")
        }
        
        logger.info(f"Registered child server logger for {server_name} (ID: {server_id})")
        return logger

    def unregister_child_logger(self, server_id: str) -> None:
        """
        Unregister a child server logger.
        
        Args:
            server_id: Unique ID of the child server
        """
        if server_id in self.child_loggers:
            logger_info = self.child_loggers[server_id]
            logger_name = f"child_server_{server_id}"
            
            logger = logging.getLogger(logger_name)
            logger.info(f"Unregistering child server logger for {logger_info['name']} (ID: {server_id})")
            
            # Remove handlers to avoid file handle leaks
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)
            
            # Remove from dictionaries
            if logger_name in self.loggers:
                del self.loggers[logger_name]
            del self.child_loggers[server_id]

    def get_all_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get the most recent logs from all sources.
        
        Args:
            limit: Maximum number of log entries to return
            
        Returns:
            List of log entries as dictionaries
        """
        all_logs = []
        
        # Get logs from aggregated log file
        aggregated_log_path = LOG_DIR / "forge_aggregated.log"
        if aggregated_log_path.exists():
            with open(aggregated_log_path, 'r') as f:
                for line in f.readlines()[-limit:]:
                    try:
                        # Parse the log entry
                        timestamp_str = line.split('[')[0].strip()
                        level = line.split('[')[1].split(']')[0].strip()
                        component = line.split('[')[2].split(']')[0].strip()
                        message = line.split(']', 2)[2].strip()
                        
                        all_logs.append({
                            "timestamp": timestamp_str,
                            "level": level,
                            "component": component,
                            "message": message
                        })
                    except (IndexError, ValueError):
                        # Skip malformed log entries
                        continue
        
        return sorted(all_logs, key=lambda x: x["timestamp"], reverse=True)[:limit]

    def get_server_logs(self, server_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get logs for a specific server.
        
        Args:
            server_id: ID of the server (or "forge" for forge server)
            limit: Maximum number of log entries to return
            
        Returns:
            List of log entries as dictionaries
        """
        if server_id == "forge":
            log_file = LOG_DIR / "forge_mcp_server.log"
        elif server_id in self.child_loggers:
            log_file = Path(self.child_loggers[server_id]["log_file"])
        else:
            return []
        
        logs = []
        if log_file.exists():
            with open(log_file, 'r') as f:
                for line in f.readlines()[-limit:]:
                    try:
                        # Parse the log entry
                        timestamp_str = line.split('[')[0].strip()
                        level = line.split('[')[1].split(']')[0].strip()
                        component = line.split('[')[2].split(']')[0].strip()
                        message = line.split(']', 2)[2].strip()
                        
                        logs.append({
                            "timestamp": timestamp_str,
                            "level": level,
                            "component": component,
                            "message": message
                        })
                    except (IndexError, ValueError):
                        # Skip malformed log entries
                        continue
        
        return sorted(logs, key=lambda x: x["timestamp"], reverse=True)[:limit]

    def clean_old_logs(self) -> None:
        """Clean log files older than the retention period."""
        now = time.time()
        retention_seconds = self.retention_days * 24 * 60 * 60
        
        for log_file in LOG_DIR.glob("*.log*"):
            file_modified_time = log_file.stat().st_mtime
            if now - file_modified_time > retention_seconds:
                try:
                    log_file.unlink()
                    logging.info(f"Deleted old log file: {log_file}")
                except OSError as e:
                    logging.error(f"Failed to delete old log file {log_file}: {e}")


# Create singleton instance
logging_system = LoggingSystem()


def configure_logging(config: Optional[Dict[str, Any]] = None) -> LoggingSystem:
    """
    Configure the logging system with the provided configuration.
    
    Args:
        config: Configuration dictionary for logging system
        
    Returns:
        Configured LoggingSystem instance
    """
    global logging_system
    logging_system = LoggingSystem(config)
    return logging_system


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the given name.
    
    Args:
        name: Name of the logger
        
    Returns:
        Logger instance
    """
    return logging_system.get_logger(name)


if __name__ == "__main__":
    # Test the logging system
    configure_logging({"log_level": logging.DEBUG})
    logger = get_logger("test_logger")
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    # Register a child logger
    child_logger = logging_system.register_child_logger("test-server-id", "Test Server")
    child_logger.info("This is a message from a child server")
    
    # Get all logs
    logs = logging_system.get_all_logs()
    print(f"Retrieved {len(logs)} log entries") 