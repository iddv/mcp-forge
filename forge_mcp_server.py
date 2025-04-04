#!/usr/bin/env python
"""
MCP-Forge Server

This server acts as a factory for creating and managing other MCP servers.
It provides a central interface for requesting new server instances with
specific capabilities, and manages their lifecycle.

Built using the official Model Context Protocol (MCP) SDK.
"""

import argparse
import json
import logging
import os
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from mcp.server.fastmcp import FastMCP
from server_manager import ServerManager, ServerInstance
from config_manager import ConfigManager
from shutdown_handler import register_shutdown_hook, set_shutdown_timeout, get_shutdown_handler
from auto_scaler import get_auto_scaler, ScalingRule, ServerGroup, AutoScaler
from logging_system import configure_logging, get_logger
from log_aggregator import initialize_log_aggregator, start_aggregation_service
from status_reporter import get_status_reporter, start_status_reporting
from metrics_collector import get_metrics_collector, start_metrics_collection
from alerting_system import get_alerting_system, start_alerting_service

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('forge_mcp_server.log')
    ]
)
logger = logging.getLogger('forge_mcp_server')

# Initialize configuration manager
config_manager = ConfigManager()

# Create the Forge MCP Server using the official SDK
mcp_server = FastMCP("MCP-Forge Server", description="A server that creates and manages child MCP servers")

# Initialize the server manager
server_manager = ServerManager()
next_port = None  # Will be initialized in main()

@mcp_server.resource("servers://list")
def list_servers_resource() -> str:
    """Return a list of all managed servers."""
    servers_list = []
    for server_id, server in server_manager.get_all_instances().items():
        servers_list.append(server.get_info())
    
    return json.dumps(servers_list, indent=2)

@mcp_server.resource("servers://{server_id}/info")
def server_info_resource(server_id: str) -> str:
    """Return information about a specific server."""
    server = server_manager.get_instance(server_id)
    if not server:
        return json.dumps({"error": f"Server not found: {server_id}"}, indent=2)
    
    return json.dumps(server.get_info(), indent=2)

def validate_create_server_request(name: Optional[str], description: str,
                                capabilities: Optional[List[str]],
                                handlers: Optional[List[str]],
                                options: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validate parameters for server creation request.
    
    Args:
        name: Server name
        description: Server description
        capabilities: List of capabilities
        handlers: List of handlers
        options: Server options
        
    Returns:
        Tuple containing:
        - Boolean indicating if validation passed
        - Error message (empty if validation passed)
        - Dictionary with validated and normalized parameters
    """
    validated_params = {}
    
    # Validate name if provided
    if name is not None:
        if not isinstance(name, str):
            return False, "Name must be a string", {}
        
        if len(name) < 3:
            return False, "Name must be at least 3 characters long", {}
            
        if not re.match(r'^[a-zA-Z0-9_\-]+$', name):
            return False, "Name can only contain alphanumeric characters, hyphens, and underscores", {}
            
        validated_params["name"] = name

    # Validate description
    if not isinstance(description, str):
        return False, "Description must be a string", {}
    
    if len(description) < 5:
        return False, "Description must be at least 5 characters long", {}
        
    validated_params["description"] = description
    
    # Validate capabilities
    if capabilities is not None:
        if not isinstance(capabilities, list):
            return False, "Capabilities must be a list", {}
            
        # Get valid capabilities from template system
        valid_capabilities = ["echo", "time", "uptime"] # Default set
        try:
            from template_system.customization import get_available_capabilities
            valid_capabilities.extend(get_available_capabilities())
        except Exception as e:
            logger.warning(f"Error loading valid capabilities: {e}")
        
        invalid_capabilities = [c for c in capabilities if c not in valid_capabilities]
        if invalid_capabilities:
            return False, f"Invalid capabilities: {', '.join(invalid_capabilities)}", {}
            
        validated_params["capabilities"] = capabilities
    else:
        validated_params["capabilities"] = ["echo", "time", "uptime"]  # Default
    
    # Validate handlers if provided
    if handlers is not None:
        if not isinstance(handlers, list):
            return False, "Handlers must be a list", {}
            
        # Get valid handlers from template system
        valid_handlers = []
        try:
            from template_system.customization import get_available_handlers
            valid_handlers = get_available_handlers()
        except Exception as e:
            logger.warning(f"Error loading valid handlers: {e}")
            
        invalid_handlers = [h for h in handlers if h not in valid_handlers]
        if invalid_handlers:
            return False, f"Invalid handlers: {', '.join(invalid_handlers)}", {}
            
        validated_params["handlers"] = handlers
    
    # Validate options if provided
    if options is not None:
        if not isinstance(options, dict):
            return False, "Options must be a dictionary", {}
            
        # Get valid option keys from template system
        valid_options = {}
        try:
            from template_system.customization import get_available_options
            valid_options = get_available_options()
        except Exception as e:
            logger.warning(f"Error loading valid options: {e}")
            
        for key, value in options.items():
            if key not in valid_options:
                return False, f"Invalid option: {key}", {}
                
            # Check if the option value is valid
            option_spec = valid_options[key]
            if option_spec.get("type") == "enum" and value not in option_spec.get("values", []):
                return False, f"Invalid value for {key}: {value}", {}
        
        validated_params["options"] = options
    
    return True, "", validated_params

@mcp_server.tool()
def create_server(name: Optional[str] = None, description: str = "MCP Server", 
                  capabilities: Optional[List[str]] = None,
                  handlers: Optional[List[str]] = None,
                  options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Create a new MCP server instance.
    
    Args:
        name: Optional name for the server. If not provided, a name will be generated.
        description: Description of the server.
        capabilities: List of capabilities the server should have.
        handlers: List of additional handlers to add to the server.
        options: Dictionary of server options.
        
    Returns:
        Information about the created server.
    """
    global next_port
    
    # Validate request parameters
    is_valid, error_msg, validated_params = validate_create_server_request(
        name, description, capabilities, handlers, options
    )
    
    if not is_valid:
        return {
            "status": "error",
            "error": f"Invalid request: {error_msg}"
        }
    
    # Use validated parameters
    name = validated_params.get("name", name)
    description = validated_params.get("description", description)
    capabilities = validated_params.get("capabilities", capabilities)
    handlers = validated_params.get("handlers", handlers)
    options = validated_params.get("options", options)
    
    # Import template system
    from template_system import get_template_manager, TemplateCustomizer
    from template_system.templates import get_base_template_path
    
    # Generate server ID if name not provided
    server_id = name if name else generate_server_id()
    
    # Create handlers dict (mapping capability to handler function)
    handler_map = {}
    for capability in capabilities:
        # Map standard capabilities to their handlers
        if capability == "echo":
            handler_map["echo"] = "handle_echo"
        elif capability == "time":
            handler_map["time"] = "handle_time"
        elif capability == "uptime":
            handler_map["uptime"] = "handle_uptime"
        else:
            # For custom capabilities, we'll use a standard handler name pattern
            handler_map[capability] = f"handle_{capability}"
    
    # Get template manager
    template_manager = get_template_manager(get_base_template_path())
    
    try:
        # Use ServerManager to instantiate the server
        server_manager.next_port = next_port
        success, error, server = server_manager.instantiate_server(
            template_processor=template_manager,
            server_id=server_id,
            name=name or server_id,
            description=description,
            capabilities=capabilities,
            handlers=handlers,
            options=options
        )
        
        if not success:
            return {
                "status": "error",
                "error": error
            }
            
        # Update next port
        next_port = server_manager.next_port
        
        logger.info(f"Created server instance: {server_id}")
        
        # Start the server automatically
        if not server.start():
            return {
                "status": "warning",
                "message": "Server created but failed to start",
                "error": server.error,
                "server": server.get_info()
            }
        
        return {
            "status": "success",
            "message": "Server created and started",
            "server": server.get_info()
        }
    except Exception as e:
        error_msg = f"Error creating server: {str(e)}"
        logger.error(error_msg)
        return {"status": "error", "error": error_msg}

@mcp_server.tool()
def start_server(server_id: str) -> Dict[str, Any]:
    """
    Start a managed server instance.
    
    Args:
        server_id: ID of the server to start.
        
    Returns:
        Status of the operation.
    """
    server = server_manager.get_instance(server_id)
    if not server:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    if server.status == "running":
        return {
            "status": "warning",
            "message": f"Server {server_id} is already running"
        }
    
    if server.start():
        return {
            "status": "success",
            "message": f"Server {server_id} started successfully"
        }
    else:
        return {
            "status": "error",
            "error": server.error
        }

@mcp_server.tool()
def stop_server(server_id: str) -> Dict[str, Any]:
    """
    Stop a managed server instance.
    
    Args:
        server_id: ID of the server to stop.
        
    Returns:
        Status of the operation.
    """
    server = server_manager.get_instance(server_id)
    if not server:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    if server.status != "running":
        return {
            "status": "warning",
            "message": f"Server {server_id} is not running"
        }
    
    server.stop()
    return {
        "status": "success",
        "message": f"Server {server_id} stopped successfully"
    }

@mcp_server.tool()
def delete_server(server_id: str) -> Dict[str, Any]:
    """
    Delete a managed server instance.
    
    Args:
        server_id: ID of the server to delete.
        
    Returns:
        Status of the operation.
    """
    server = server_manager.get_instance(server_id)
    if not server:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    success = server_manager.delete_instance(server_id)
    if success:
        return {
            "status": "success",
            "message": f"Server {server_id} deleted successfully"
        }
    else:
        return {
            "status": "error",
            "error": f"Error deleting server {server_id}"
        }

@mcp_server.tool()
def restart_server(server_id: str) -> Dict[str, Any]:
    """
    Restart a managed server instance.
    
    Args:
        server_id: ID of the server to restart.
        
    Returns:
        Status of the operation.
    """
    server = server_manager.get_instance(server_id)
    if not server:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    if server.status != "running":
        # Try to start it instead of restarting
        if server.start():
            return {
                "status": "success",
                "message": f"Server {server_id} started successfully"
            }
        else:
            return {
                "status": "error",
                "error": server.error
            }
    
    if server.restart():
        return {
            "status": "success", 
            "message": f"Server {server_id} restarted successfully"
        }
    else:
        return {
            "status": "error",
            "error": server.error
        }

@mcp_server.tool()
def list_servers(include_details: bool = False) -> Dict[str, Any]:
    """
    List all managed server instances.
    
    Args:
        include_details: Whether to include detailed information.
        
    Returns:
        List of servers.
    """
    servers_list = []
    
    for server_id, server in server_manager.get_all_instances().items():
        if include_details:
            servers_list.append(server.get_info())
        else:
            servers_list.append({
                "id": server.id,
                "name": server.name,
                "description": server.description,
                "status": server.status,
                "port": server.port
            })
    
    return {
        "status": "success",
        "count": len(servers_list),
        "servers": servers_list
    }

@mcp_server.tool()
def get_server_logs(server_id: str, log_type: str = "all", max_lines: int = 50) -> Dict[str, Any]:
    """
    Get logs from a server instance.
    
    Args:
        server_id: ID of the server
        log_type: Type of logs to get ("stdout", "stderr", or "all")
        max_lines: Maximum number of lines to return
        
    Returns:
        Server logs
    """
    server = server_manager.get_instance(server_id)
    if not server:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    logs = server.get_logs(log_type, max_lines)
    
    return {
        "status": "success",
        "server_id": server_id,
        "logs": logs
    }

@mcp_server.tool()
def get_server_process_stats(server_id: str) -> Dict[str, Any]:
    """
    Get process statistics for a server.
    
    Args:
        server_id: ID of the server
        
    Returns:
        Process statistics
    """
    server = server_manager.get_instance(server_id)
    if not server:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    stats = server.get_resource_stats()
    if not stats:
        return {
            "status": "warning",
            "message": "Resource monitoring is not available or process is not running",
            "server_id": server_id
        }
    
    return {
        "status": "success",
        "server_id": server_id,
        "stats": stats
    }

@mcp_server.tool()
def get_all_process_stats() -> Dict[str, Any]:
    """
    Get process statistics for all servers.
    
    Returns:
        Process statistics for all servers
    """
    stats = server_manager.get_all_resource_stats()
    if not stats:
        return {
            "status": "warning",
            "message": "Resource monitoring is not available or no processes are running",
            "stats": {}
        }
    
    return {
        "status": "success",
        "count": len(stats),
        "stats": stats
    }

@mcp_server.tool()
def get_system_stats() -> Dict[str, Any]:
    """
    Get system-wide resource statistics.
    
    Returns:
        System statistics
    """
    stats = server_manager.get_system_stats()
    if not stats:
        return {
            "status": "warning",
            "message": "System monitoring is not available"
        }
    
    return {
        "status": "success",
        "stats": stats
    }

@mcp_server.tool()
def get_server_process_history(server_id: str, metric: str = "cpu", points: int = 10) -> Dict[str, Any]:
    """
    Get historical process data for a server.
    
    Args:
        server_id: ID of the server
        metric: Metric to get history for (cpu, memory, io_read, io_write)
        points: Number of data points to return
        
    Returns:
        Historical process data
    """
    server = server_manager.get_instance(server_id)
    if not server:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    history = server.get_process_history(metric, points)
    if history is None:
        return {
            "status": "warning",
            "message": "Process monitoring is not available or no history is available",
            "server_id": server_id
        }
    
    # Format the history data
    formatted_history = [{"timestamp": t, "value": v} for t, v in history]
    
    return {
        "status": "success",
        "server_id": server_id,
        "metric": metric,
        "history": formatted_history
    }

@mcp_server.resource("servers://{server_id}/process")
def server_process_resource(server_id: str) -> str:
    """Return process information about a specific server."""
    server = server_manager.get_instance(server_id)
    if not server:
        return json.dumps({"error": f"Server not found: {server_id}"}, indent=2)
    
    stats = server.get_process_stats()
    if not stats:
        return json.dumps({"error": "Process monitoring not available"}, indent=2)
    
    return json.dumps(stats, indent=2)

@mcp_server.resource("system://stats")
def system_stats_resource() -> str:
    """Return system-wide resource statistics."""
    stats = server_manager.get_system_stats()
    if not stats:
        return json.dumps({"error": "System monitoring not available"}, indent=2)
    
    return json.dumps(stats, indent=2)

@mcp_server.tool()
def get_config(section: Optional[str] = None, key: Optional[str] = None) -> Dict[str, Any]:
    """
    Get server configuration.
    
    Args:
        section: Optional configuration section (if None, returns all sections)
        key: Optional key within the section (if None, returns entire section)
        
    Returns:
        Configuration values
    """
    try:
        if section is None:
            # Return all configuration
            return {
                "status": "success",
                "config": config_manager.config
            }
        
        if key is None:
            # Return section configuration
            section_config = config_manager.get(section)
            if section_config is None:
                return {
                    "status": "error",
                    "error": f"Configuration section not found: {section}"
                }
                
            return {
                "status": "success",
                "config": {section: section_config}
            }
        
        # Return specific key
        value = config_manager.get(section, key)
        if value is None:
            return {
                "status": "error",
                "error": f"Configuration key not found: {section}.{key}"
            }
            
        return {
            "status": "success",
            "config": {section: {key: value}}
        }
    except Exception as e:
        return {
            "status": "error",
            "error": f"Error getting configuration: {str(e)}"
        }

@mcp_server.tool()
def set_config(section: str, key: str, value: Any) -> Dict[str, Any]:
    """
    Set configuration value.
    
    Args:
        section: Configuration section
        key: Key within the section
        value: Value to set
        
    Returns:
        Status of operation
    """
    try:
        success = config_manager.set(section, key, value)
        if success:
            return {
                "status": "success",
                "message": f"Configuration updated: {section}.{key}"
            }
        else:
            return {
                "status": "error",
                "error": "Failed to update configuration"
            }
    except Exception as e:
        return {
            "status": "error",
            "error": f"Error updating configuration: {str(e)}"
        }

@mcp_server.tool()
def update_config_section(section: str, values: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update an entire configuration section.
    
    Args:
        section: Configuration section
        values: Dictionary of values to set
        
    Returns:
        Status of operation
    """
    try:
        success = config_manager.update_section(section, values)
        if success:
            return {
                "status": "success",
                "message": f"Configuration section updated: {section}"
            }
        else:
            return {
                "status": "error",
                "error": "Failed to update configuration section"
            }
    except Exception as e:
        return {
            "status": "error",
            "error": f"Error updating configuration section: {str(e)}"
        }

@mcp_server.tool()
def validate_config() -> Dict[str, Any]:
    """
    Validate the current configuration.
    
    Returns:
        Validation results
    """
    try:
        errors = config_manager.validate_config()
        if errors:
            return {
                "status": "error",
                "valid": False,
                "errors": errors
            }
        else:
            return {
                "status": "success",
                "valid": True
            }
    except Exception as e:
        return {
            "status": "error",
            "valid": False,
            "errors": [f"Error validating configuration: {str(e)}"]
        }

def generate_server_id() -> str:
    """
    Generate a unique ID for a new server.
    
    The ID consists of:
    - A 'mcp-' prefix
    - A timestamp component (YYYYMMDD)
    - A UUID-based component (first 8 chars of a UUID)
    
    Returns:
        A unique server ID string that is guaranteed to be unique.
    """
    # Time-based prefix for human readability
    date_prefix = datetime.now().strftime('%Y%m%d')
    
    # UUID component for uniqueness guarantee
    # Use uuid4 for random UUIDs with no hardware identifiers
    uuid_component = str(uuid.uuid4())[:8]
    
    # Combine components
    server_id = f"mcp-{date_prefix}-{uuid_component}"
    
    # Double-check for collisions (extremely unlikely but good practice)
    while server_id in server_manager.get_all_instances():
        uuid_component = str(uuid.uuid4())[:8]
        server_id = f"mcp-{date_prefix}-{uuid_component}"
    
    logger.debug(f"Generated new server ID: {server_id}")
    return server_id

@mcp_server.tool()
def set_resource_limit(server_id: str, limit_name: str, limit_value: float) -> Dict[str, Any]:
    """
    Set a resource limit for a server.
    
    Args:
        server_id: ID of the server
        limit_name: Limit name (cpu_percent, memory_mb, etc.)
        limit_value: Limit value
        
    Returns:
        Status of operation
    """
    server = server_manager.get_instance(server_id)
    if not server:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    success = server_manager.set_server_resource_limit(server_id, limit_name, limit_value)
    if not success:
        return {
            "status": "error",
            "error": "Resource monitoring is not available or failed to set limit"
        }
    
    return {
        "status": "success",
        "message": f"Resource limit set for server {server_id}: {limit_name}={limit_value}"
    }

@mcp_server.tool()
def set_default_resource_limit(limit_name: str, limit_value: float) -> Dict[str, Any]:
    """
    Set a default resource limit for all servers.
    
    Args:
        limit_name: Limit name (cpu_percent, memory_mb, etc.)
        limit_value: Limit value
        
    Returns:
        Status of operation
    """
    success = server_manager.set_default_resource_limit(limit_name, limit_value)
    if not success:
        return {
            "status": "error",
            "error": "Resource monitoring is not available or failed to set default limit"
        }
    
    return {
        "status": "success",
        "message": f"Default resource limit set: {limit_name}={limit_value}"
    }

@mcp_server.tool()
def get_resource_limits(server_id: str) -> Dict[str, Any]:
    """
    Get resource limits for a server.
    
    Args:
        server_id: ID of the server
        
    Returns:
        Resource limits
    """
    server = server_manager.get_instance(server_id)
    if not server:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    limits = server.get_resource_limits()
    if not limits:
        return {
            "status": "warning",
            "message": "Resource monitoring is not available or no limits set",
            "server_id": server_id
        }
    
    return {
        "status": "success",
        "server_id": server_id,
        "limits": limits
    }

@mcp_server.resource("servers://{server_id}/resources")
def server_resources_resource(server_id: str) -> str:
    """Return resource information about a specific server."""
    server = server_manager.get_instance(server_id)
    if not server:
        return json.dumps({"error": f"Server not found: {server_id}"}, indent=2)
    
    # Get resource stats and limits
    stats = server.get_resource_stats()
    limits = server.get_resource_limits()
    
    if not stats and not limits:
        return json.dumps({"error": "Resource monitoring not available"}, indent=2)
    
    result = {
        "stats": stats or {},
        "limits": limits or {}
    }
    
    return json.dumps(result, indent=2)

@mcp_server.resource("system://resources")
def system_resources_resource() -> str:
    """Return system-wide resource statistics."""
    stats = server_manager.get_system_stats()
    if not stats:
        return json.dumps({"error": "Resource monitoring not available"}, indent=2)
    
    return json.dumps(stats, indent=2)

@mcp_server.tool()
def shutdown_server(timeout: Optional[float] = None, reason: str = "User requested shutdown") -> Dict[str, Any]:
    """
    Initiate a graceful shutdown of the MCP-Forge server.
    
    Args:
        timeout: Optional timeout in seconds (default: use configured timeout)
        reason: Reason for shutdown
        
    Returns:
        Status of operation
    """
    from shutdown_handler import trigger_shutdown
    
    logger.info(f"Shutdown requested: {reason}")
    
    # Set timeout if provided
    if timeout is not None:
        set_shutdown_timeout(timeout)
        
    # Schedule the shutdown to happen after we return a response
    threading.Thread(target=trigger_shutdown, daemon=True).start()
    
    return {
        "status": "success",
        "message": f"Graceful shutdown initiated: {reason}"
    }

@mcp_server.tool()
def manage_auto_scaling(action: str, group_name: str,
                       min_instances: Optional[int] = None,
                       max_instances: Optional[int] = None,
                       server_ids: Optional[List[str]] = None,
                       rule_name: Optional[str] = None,
                       metric: Optional[str] = None,
                       threshold: Optional[float] = None,
                       rule_action: Optional[str] = None,
                       cooldown: Optional[float] = None) -> Dict[str, Any]:
    """
    Manage auto-scaling groups and rules.
    
    Args:
        action: Action to perform (create_group, delete_group, add_instance, 
                remove_instance, add_rule, delete_rule, start, stop)
        group_name: Name of the server group
        min_instances: Minimum number of instances in the group
        max_instances: Maximum number of instances in the group
        server_ids: List of server IDs to add/remove
        rule_name: Name of the rule (for add_rule action)
        metric: Metric to monitor (e.g., cpu_percent, memory_percent)
        threshold: Threshold value for the rule
        rule_action: Action to take (scale_up, scale_down, restart)
        cooldown: Cooldown period in seconds
        
    Returns:
        Result of the operation
    """
    # Get the auto-scaler instance
    auto_scaler = get_auto_scaler()
    
    if action == "create_group":
        if min_instances is None or max_instances is None:
            return {
                "status": "error",
                "error": "min_instances and max_instances are required for create_group action"
            }
        
        # Create a new server group
        group = auto_scaler.create_group(
            name=group_name,
            min_instances=min_instances,
            max_instances=max_instances
        )
        
        return {
            "status": "success",
            "message": f"Created auto-scaling group: {group_name}",
            "group_info": group.get_info()
        }
        
    elif action == "delete_group":
        # Delete a server group
        if auto_scaler.delete_group(group_name):
            return {
                "status": "success",
                "message": f"Deleted auto-scaling group: {group_name}"
            }
        else:
            return {
                "status": "error",
                "error": f"Group not found: {group_name}"
            }
            
    elif action == "add_instance":
        if not server_ids:
            return {
                "status": "error",
                "error": "server_ids is required for add_instance action"
            }
        
        # Add server instances to the group
        results = []
        for server_id in server_ids:
            # Verify the server exists
            server = server_manager.get_instance(server_id)
            if not server:
                results.append({
                    "server_id": server_id,
                    "success": False,
                    "error": f"Server not found: {server_id}"
                })
                continue
                
            # Add to auto-scaling group
            success = auto_scaler.add_instance(group_name, server_id)
            results.append({
                "server_id": server_id,
                "success": success,
                "error": None if success else f"Failed to add server {server_id} to group {group_name}"
            })
            
        return {
            "status": "success",
            "results": results
        }
        
    elif action == "remove_instance":
        if not server_ids:
            return {
                "status": "error",
                "error": "server_ids is required for remove_instance action"
            }
        
        # Remove server instances from the group
        results = []
        for server_id in server_ids:
            success = auto_scaler.remove_instance(group_name, server_id)
            results.append({
                "server_id": server_id,
                "success": success,
                "error": None if success else f"Failed to remove server {server_id} from group {group_name}"
            })
            
        return {
            "status": "success",
            "results": results
        }
        
    elif action == "add_rule":
        if not all([rule_name, metric, threshold is not None, rule_action]):
            return {
                "status": "error",
                "error": "rule_name, metric, threshold, and rule_action are required for add_rule action"
            }
        
        # Validate rule_action
        valid_actions = ["scale_up", "scale_down", "restart"]
        if rule_action not in valid_actions:
            return {
                "status": "error",
                "error": f"Invalid rule_action: {rule_action}. Must be one of: {', '.join(valid_actions)}"
            }
            
        # Add a scaling rule to the group
        cooldown_value = cooldown or 60.0
        success = auto_scaler.add_rule(
            group_name=group_name,
            rule_name=rule_name,
            metric=metric,
            threshold=threshold,
            action=rule_action,
            cooldown=cooldown_value
        )
        
        if success:
            return {
                "status": "success",
                "message": f"Added rule {rule_name} to group {group_name}"
            }
        else:
            return {
                "status": "error",
                "error": f"Failed to add rule to group {group_name}"
            }
            
    elif action == "start":
        # Set up the callbacks
        auto_scaler.set_metrics_callback(_get_server_metrics)
        auto_scaler.set_scale_up_callback(_handle_scale_up)
        auto_scaler.set_scale_down_callback(_handle_scale_down)
        auto_scaler.set_restart_callback(_handle_server_restart)
        
        # Start the auto-scaler
        auto_scaler.start()
        
        return {
            "status": "success",
            "message": "Auto-scaler started"
        }
        
    elif action == "stop":
        # Stop the auto-scaler
        auto_scaler.stop()
        
        return {
            "status": "success",
            "message": "Auto-scaler stopped"
        }
        
    else:
        return {
            "status": "error",
            "error": f"Invalid action: {action}"
        }

@mcp_server.resource("autoscaling://groups")
def autoscaling_groups_resource() -> str:
    """Return information about all auto-scaling groups."""
    auto_scaler = get_auto_scaler()
    groups = auto_scaler.get_all_groups()
    
    result = {
        "groups": [group.get_info() for group in groups.values()]
    }
    
    return json.dumps(result, indent=2)

@mcp_server.resource("autoscaling://groups/{group_name}")
def autoscaling_group_resource(group_name: str) -> str:
    """Return information about a specific auto-scaling group."""
    auto_scaler = get_auto_scaler()
    group = auto_scaler.get_group(group_name)
    
    if not group:
        return json.dumps({"error": f"Group not found: {group_name}"}, indent=2)
    
    return json.dumps(group.get_info(), indent=2)

def _get_server_metrics(server_id: str) -> Dict[str, float]:
    """
    Get metrics for a server instance.
    
    Args:
        server_id: ID of the server
        
    Returns:
        Dictionary of metrics or empty dict if server not found
    """
    server = server_manager.get_instance(server_id)
    if not server:
        return {}
        
    # Get process statistics
    stats = server.get_process_stats()
    if not stats:
        return {}
        
    # Extract the metrics we care about
    metrics = {
        "cpu_percent": stats.get("cpu_percent", 0.0),
        "memory_percent": stats.get("memory_percent", 0.0),
        "num_threads": float(stats.get("num_threads", 0)),
        "uptime_seconds": float(stats.get("uptime_seconds", 0))
    }
    
    return metrics

def _handle_scale_up(instance_id: str, group: ServerGroup) -> bool:
    """
    Handle scaling up a server group.
    
    Args:
        instance_id: ID of the server that triggered the scale-up
        group: ServerGroup to scale up
        
    Returns:
        Boolean indicating success
    """
    logger.info(f"Scaling up group {group.name} (triggered by {instance_id})")
    
    # Get the server that triggered the scale-up
    server = server_manager.get_instance(instance_id)
    if not server:
        logger.error(f"Server not found: {instance_id}")
        return False
        
    try:
        # Create a new server instance with same settings
        result = create_server(
            description=f"Auto-scaled instance for group {group.name}",
            capabilities=server.capabilities,
            handlers=server.handlers,
            options=server.options
        )
        
        if result.get("status") != "success":
            logger.error(f"Failed to create new server: {result.get('error')}")
            return False
            
        # Add the new server to the group
        new_server_id = result["server"]["id"]
        auto_scaler = get_auto_scaler()
        auto_scaler.add_instance(group.name, new_server_id)
        
        logger.info(f"Added new server {new_server_id} to group {group.name}")
        return True
        
    except Exception as e:
        logger.error(f"Error in scale-up handler: {e}")
        return False

def _handle_scale_down(instance_id: str, group: ServerGroup) -> bool:
    """
    Handle scaling down a server group.
    
    Args:
        instance_id: ID of the server that triggered the scale-down
        group: ServerGroup to scale down
        
    Returns:
        Boolean indicating success
    """
    logger.info(f"Scaling down group {group.name} (triggered by {instance_id})")
    
    # Find the server with the lowest load
    auto_scaler = get_auto_scaler()
    lowest_load = None
    server_to_remove = None
    
    for server_id in group.instance_ids:
        metrics = _get_server_metrics(server_id)
        if not metrics:
            continue
            
        # Use CPU as the primary metric
        load = metrics.get("cpu_percent", 0.0)
        
        if lowest_load is None or load < lowest_load:
            lowest_load = load
            server_to_remove = server_id
    
    if not server_to_remove:
        logger.warning(f"No suitable server found for scale-down in group {group.name}")
        return False
        
    # Remove the server from the group first
    auto_scaler.remove_instance(group.name, server_to_remove)
    
    # Then delete the server
    logger.info(f"Removing server {server_to_remove} from group {group.name}")
    result = delete_server(server_to_remove)
    
    return result.get("status") == "success"

def _handle_server_restart(instance_id: str, group: ServerGroup) -> bool:
    """
    Handle restarting a server.
    
    Args:
        instance_id: ID of the server to restart
        group: ServerGroup the server belongs to
        
    Returns:
        Boolean indicating success
    """
    logger.info(f"Restarting server {instance_id} in group {group.name}")
    
    result = restart_server(instance_id)
    return result.get("status") == "success"

@mcp_server.resource("system://logs")
def system_logs_resource() -> str:
    """Return aggregated system logs."""
    try:
        log_aggregator = log_aggregator if 'log_aggregator' in globals() else initialize_log_aggregator(None)
        logs = log_aggregator.get_aggregated_logs(limit=100)
        return json.dumps(logs, indent=2)
    except Exception as e:
        logger.error(f"Error getting system logs: {e}")
        return json.dumps({"error": str(e)}, indent=2)

@mcp_server.resource("system://logs/{level}")
def system_logs_by_level_resource(level: str) -> str:
    """Return aggregated system logs filtered by level."""
    try:
        log_aggregator = log_aggregator if 'log_aggregator' in globals() else initialize_log_aggregator(None)
        logs = log_aggregator.get_aggregated_logs(limit=100, level=level)
        return json.dumps(logs, indent=2)
    except Exception as e:
        logger.error(f"Error getting system logs by level: {e}")
        return json.dumps({"error": str(e)}, indent=2)

@mcp_server.resource("servers://{server_id}/logs")
def server_logs_resource(server_id: str) -> str:
    """Return logs for a specific server."""
    try:
        log_aggregator = log_aggregator if 'log_aggregator' in globals() else initialize_log_aggregator(None)
        logs = log_aggregator.get_server_logs(server_id, limit=100)
        return json.dumps(logs, indent=2)
    except Exception as e:
        logger.error(f"Error getting logs for server {server_id}: {e}")
        return json.dumps({"error": str(e)}, indent=2)

@mcp_server.resource("system://status")
def system_status_resource() -> str:
    """Return system status information."""
    try:
        status_reporter = status_reporter if 'status_reporter' in globals() else get_status_reporter()
        statuses = status_reporter.get_all_server_statuses()
        return json.dumps(statuses, indent=2)
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return json.dumps({"error": str(e)}, indent=2)

@mcp_server.resource("servers://{server_id}/status")
def server_status_resource(server_id: str) -> str:
    """Return status for a specific server."""
    try:
        status_reporter = status_reporter if 'status_reporter' in globals() else get_status_reporter()
        status = status_reporter.get_server_status(server_id)
        if status:
            return json.dumps(status, indent=2)
        else:
            return json.dumps({"error": f"Server not found: {server_id}"}, indent=2)
    except Exception as e:
        logger.error(f"Error getting status for server {server_id}: {e}")
        return json.dumps({"error": str(e)}, indent=2)

@mcp_server.resource("system://metrics")
def system_metrics_resource() -> str:
    """Return system metrics."""
    try:
        metrics_collector = metrics_collector if 'metrics_collector' in globals() else get_metrics_collector()
        metrics = metrics_collector.get_system_metrics(time_period="hour")
        return json.dumps(metrics, indent=2)
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return json.dumps({"error": str(e)}, indent=2)

@mcp_server.resource("servers://{server_id}/metrics")
def server_metrics_resource(server_id: str) -> str:
    """Return metrics for a specific server."""
    try:
        metrics_collector = metrics_collector if 'metrics_collector' in globals() else get_metrics_collector()
        metrics = metrics_collector.get_server_metrics(server_id, time_period="hour")
        return json.dumps(metrics, indent=2)
    except Exception as e:
        logger.error(f"Error getting metrics for server {server_id}: {e}")
        return json.dumps({"error": str(e)}, indent=2)

@mcp_server.resource("system://alerts")
def system_alerts_resource() -> str:
    """Return system alerts."""
    try:
        alerting_system = alerting_system if 'alerting_system' in globals() else get_alerting_system()
        alerts = alerting_system.get_active_alerts()
        return json.dumps(alerts, indent=2)
    except Exception as e:
        logger.error(f"Error getting system alerts: {e}")
        return json.dumps({"error": str(e)}, indent=2)

@mcp_server.resource("system://alerts/history")
def system_alerts_history_resource() -> str:
    """Return system alert history."""
    try:
        alerting_system = alerting_system if 'alerting_system' in globals() else get_alerting_system()
        alert_history = alerting_system.get_alert_history(limit=100)
        return json.dumps(alert_history, indent=2)
    except Exception as e:
        logger.error(f"Error getting system alert history: {e}")
        return json.dumps({"error": str(e)}, indent=2)

@mcp_server.tool()
def acknowledge_alert(alert_id: str, user: str) -> Dict[str, Any]:
    """
    Acknowledge an alert.
    
    Args:
        alert_id: ID of the alert to acknowledge
        user: User acknowledging the alert
        
    Returns:
        Dictionary with acknowledgment status
    """
    try:
        alerting_system = alerting_system if 'alerting_system' in globals() else get_alerting_system()
        success = alerting_system.acknowledge_alert(alert_id, user)
        
        if success:
            return {
                "status": "success",
                "message": f"Alert {alert_id} acknowledged by {user}"
            }
        else:
            return {
                "status": "error",
                "message": f"Alert not found: {alert_id}"
            }
    except Exception as e:
        logger.error(f"Error acknowledging alert {alert_id}: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

@mcp_server.tool()
def resolve_alert(alert_id: str, resolution_message: Optional[str] = None) -> Dict[str, Any]:
    """
    Resolve an alert.
    
    Args:
        alert_id: ID of the alert to resolve
        resolution_message: Optional message explaining the resolution
        
    Returns:
        Dictionary with resolution status
    """
    try:
        alerting_system = alerting_system if 'alerting_system' in globals() else get_alerting_system()
        success = alerting_system.resolve_alert(alert_id, resolution_message)
        
        if success:
            return {
                "status": "success",
                "message": f"Alert {alert_id} resolved"
            }
        else:
            return {
                "status": "error",
                "message": f"Alert not found: {alert_id}"
            }
    except Exception as e:
        logger.error(f"Error resolving alert {alert_id}: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

@mcp_server.tool()
def get_logs(source: str = "system", log_level: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    """
    Get logs from the system or a specific server.
    
    Args:
        source: "system" for aggregated logs or a server ID
        log_level: Optional log level filter (error, warning, info, debug)
        limit: Maximum number of log entries to return
        
    Returns:
        Dictionary with log entries
    """
    try:
        log_aggregator = log_aggregator if 'log_aggregator' in globals() else initialize_log_aggregator(None)
        
        if source == "system":
            logs = log_aggregator.get_aggregated_logs(limit=limit, level=log_level)
            return {
                "status": "success",
                "source": "system",
                "log_level": log_level,
                "count": len(logs),
                "logs": logs
            }
        else:
            # Assume source is a server ID
            logs = log_aggregator.get_server_logs(source, limit=limit)
            
            # Filter by log level if specified
            if log_level and logs:
                logs = [log for log in logs if log.get("level", "").lower() == log_level.lower()]
                
            return {
                "status": "success",
                "source": source,
                "log_level": log_level,
                "count": len(logs),
                "logs": logs
            }
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

@mcp_server.tool()
def get_server_status(server_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get status information for a server or all servers.
    
    Args:
        server_id: Optional server ID. If not provided, status for all servers is returned.
        
    Returns:
        Dictionary with server status information
    """
    try:
        status_reporter = status_reporter if 'status_reporter' in globals() else get_status_reporter()
        
        if server_id:
            status = status_reporter.get_server_status(server_id)
            if status:
                return {
                    "status": "success",
                    "server_id": server_id,
                    "server_status": status
                }
            else:
                return {
                    "status": "error",
                    "message": f"Server not found: {server_id}"
                }
        else:
            # Get status for all servers
            statuses = status_reporter.get_all_server_statuses()
            return {
                "status": "success",
                "count": len(statuses),
                "servers": statuses
            }
    except Exception as e:
        logger.error(f"Error getting server status: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

@mcp_server.tool()
def get_metrics(source: str = "system", time_period: str = "hour") -> Dict[str, Any]:
    """
    Get performance metrics for the system or a specific server.
    
    Args:
        source: "system" for system metrics or a server ID
        time_period: Time period for metrics (hour, day, week, all)
        
    Returns:
        Dictionary with metrics data
    """
    try:
        metrics_collector = metrics_collector if 'metrics_collector' in globals() else get_metrics_collector()
        
        if source == "system":
            metrics = metrics_collector.get_system_metrics(time_period)
            return {
                "status": "success",
                "source": "system",
                "time_period": time_period,
                "count": len(metrics),
                "metrics": metrics
            }
        else:
            # Assume source is a server ID
            metrics = metrics_collector.get_server_metrics(source, time_period)
            return {
                "status": "success",
                "source": source,
                "time_period": time_period,
                "count": len(metrics),
                "metrics": metrics
            }
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

@mcp_server.tool()
def get_alerts(active_only: bool = True, limit: int = 100) -> Dict[str, Any]:
    """
    Get system alerts.
    
    Args:
        active_only: Whether to return only active (unresolved) alerts
        limit: Maximum number of alerts to return
        
    Returns:
        Dictionary with alerts data
    """
    try:
        alerting_system = alerting_system if 'alerting_system' in globals() else get_alerting_system()
        
        if active_only:
            alerts = alerting_system.get_active_alerts()
        else:
            alerts = alerting_system.get_alert_history(limit)
            
        return {
            "status": "success",
            "active_only": active_only,
            "count": len(alerts),
            "alerts": alerts
        }
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

def main():
    """Main entry point."""
    global next_port
    
    # Configure logging system first
    logging_system = configure_logging()
    logger = get_logger('forge_mcp_server')
    
    # Load configuration
    config_manager.load_config()
    server_config = config_manager.get_server_config()
    
    # Set up argument parser with defaults from config
    parser = argparse.ArgumentParser(description="MCP-Forge Server")
    parser.add_argument("--port", type=int, default=server_config["port"], 
                        help=f"Port to listen on (default: {server_config['port']})")
    parser.add_argument("--host", default=server_config["host"], 
                        help=f"Host to bind to (default: {server_config['host']})")
    parser.add_argument("--log-level", default=server_config["log_level"],
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help=f"Logging level (default: {server_config['log_level']})")
    parser.add_argument("--shutdown-timeout", type=float, default=30.0,
                        help="Shutdown timeout in seconds (default: 30.0)")
    args = parser.parse_args()
    
    # Set logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Set environment variables for the MCP SDK
    os.environ["MCP_PORT"] = str(args.port)
    os.environ["MCP_HOST"] = args.host
    
    # Initialize next port number (for child servers)
    next_port = args.port + 1
    server_manager.next_port = next_port
    
    logger.info(f"Starting MCP-Forge Server on {args.host}:{args.port}")
    
    # Initialize monitoring components
    
    # Initialize log aggregator
    log_aggregator = initialize_log_aggregator(logging_system)
    
    # Initialize status reporter
    status_reporter = get_status_reporter()
    status_reporter.register_forge_server(
        "forge-server", 
        "MCP Forge Server", 
        os.getpid()
    )
    
    # Initialize metrics collector
    metrics_collector = get_metrics_collector()
    
    # Initialize alerting system
    alerting_system = get_alerting_system()
    
    # Register alert handlers
    alerting_system.register_alert_handler(
        "resource_monitor",
        lambda: []  # Placeholder - will be replaced with actual handler
    )
    
    logger.info("Logging and monitoring components initialized")
    
    # Recover any existing server instances
    server_manager.recover_instances()
    
    # Update next_port based on recovered instances
    next_port = server_manager.next_port
    
    # Configure shutdown timeout
    set_shutdown_timeout(args.shutdown_timeout)
    
    # Register shutdown hooks
    register_shutdown_hook(
        lambda: logger.info("Shutting down MCP-Forge Server..."),
        priority=100,
        name="shutdown_announcement"
    )
    register_shutdown_hook(
        lambda: server_manager.stop_all_servers(),
        priority=50,
        name="stop_child_servers"
    )
    register_shutdown_hook(
        lambda: get_auto_scaler().stop(),
        priority=75,
        name="stop_auto_scaler"
    )
    register_shutdown_hook(
        lambda: log_aggregator.stop_aggregation(),
        priority=60,
        name="stop_log_aggregator"
    )
    register_shutdown_hook(
        lambda: status_reporter.stop_reporting(),
        priority=60,
        name="stop_status_reporter"
    )
    register_shutdown_hook(
        lambda: metrics_collector.stop_collection(),
        priority=60,
        name="stop_metrics_collector"
    )
    register_shutdown_hook(
        lambda: alerting_system.stop_alerting(),
        priority=60,
        name="stop_alerting_system"
    )
    register_shutdown_hook(
        lambda: logger.info("MCP-Forge Server shutdown complete"),
        priority=-100,
        name="shutdown_complete"
    )
    
    # Start monitoring components
    logger.info("Starting monitoring components")
    import asyncio
    
    # Create background tasks for monitoring components
    asyncio.create_task(start_aggregation_service(
        interval_seconds=server_config.get("logging", {}).get("aggregation_interval", 30)
    ))
    asyncio.create_task(start_status_reporting(
        interval_seconds=server_config.get("monitoring", {}).get("status_interval", 60)
    ))
    asyncio.create_task(start_metrics_collection(
        interval_seconds=server_config.get("monitoring", {}).get("metrics_interval", 60)
    ))
    asyncio.create_task(start_alerting_service(
        interval_seconds=server_config.get("monitoring", {}).get("alert_interval", 60)
    ))
    
    logger.info("Monitoring components started")
    
    # Start the server
    try:
        mcp_server.run()
    except KeyboardInterrupt:
        logger.info("Server shutting down due to keyboard interrupt")
    except Exception as e:
        logger.error(f"Server crashed: {e}")
        
    return 0

if __name__ == "__main__":
    sys.exit(main()) 