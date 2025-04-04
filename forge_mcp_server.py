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
from authentication_system import AuthenticationSystem, Permission, authentication_middleware
from audit_logger import get_audit_logger, AuditEventType, AuditSeverity, log_auth_success, log_auth_failure, log_server_create, log_server_delete, log_permission_denied
from protection_mechanisms import get_protection_mechanisms, protect_endpoint, DEFAULT_CSRF_TOKEN_EXPIRY

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

# Initialize protection mechanisms
protection = get_protection_mechanisms()

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
@protect_endpoint
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
    # Check authentication
    auth_header = mcp_server.current_request.headers.get("Authorization", "")
    client_ip = mcp_server.current_request.client_info.host
    
    # Extract username for audit logging
    username = None
    if auth_header:
        token = None
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif auth_header.startswith("ApiKey "):
            api_key = auth_header[7:].strip()
            token = auth_system.authenticate_api_key(api_key)
        
        if token:
            username = auth_system.validate_token(token)
    
    if not auth_header:
        # Log permission denied for unauthenticated access
        log_permission_denied(username=None, client_ip=client_ip, 
                            details={"action": "create_server", 
                                    "reason": "Authentication required"})
        
        return {
            "status": "error",
            "code": 401,
            "error": "Authentication required to create servers"
        }
    
    # Extract token or API key
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif auth_header.startswith("ApiKey "):
        api_key = auth_header[7:].strip()
        token = auth_system.authenticate_api_key(api_key)
    
    # Validate token
    if not token or not auth_system.validate_token(token):
        # Log permission denied for invalid token
        log_permission_denied(username=username, client_ip=client_ip, 
                            details={"action": "create_server", 
                                    "reason": "Invalid authentication token"})
        
        return {
            "status": "error",
            "code": 401,
            "error": "Invalid authentication token"
        }
    
    # Get username for audit logging
    username = auth_system.validate_token(token)
    
    # Check permission
    if not auth_system.check_permission(token, Permission.SERVER_CREATE):
        # Log permission denied
        log_permission_denied(username=username, client_ip=client_ip, 
                            details={"action": "create_server", 
                                    "permission": Permission.SERVER_CREATE.value})
        
        return {
            "status": "error",
            "code": 403,
            "error": "Permission denied: server:create permission required"
        }
    
    global next_port
    
    # Validate request parameters
    is_valid, error_msg, validated_params = validate_create_server_request(
        name, description, capabilities, handlers, options
    )
    
    if not is_valid:
        # Log validation failure
        get_audit_logger().log_security_event(
            AuditEventType.SEC_INPUT_VALIDATION,
            username=username, 
            client_ip=client_ip,
            details={"action": "create_server", "error": error_msg, 
                    "request_params": {
                        "name": name,
                        "description": description,
                        "capabilities": capabilities,
                        "handlers": handlers,
                        "options": str(options)
                    }}
        )
        
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
            # Log server creation failure
            get_audit_logger().log_server_action(
                AuditEventType.SERVER_CREATE, 
                username=username,
                client_ip=client_ip,
                server_id=server_id,
                details={
                    "name": name or server_id,
                    "description": description,
                    "capabilities": capabilities,
                    "handlers": handlers,
                    "error": error
                },
                success=False
            )
            
            return {
                "status": "error",
                "error": error
            }
            
        # Update next port
        next_port = server_manager.next_port
        
        logger.info(f"Created server instance: {server_id}")
        
        # Log successful server creation
        log_server_create(
            username=username,
            client_ip=client_ip,
            server_id=server_id,
            details={
                "name": name or server_id,
                "description": description,
                "capabilities": capabilities,
                "handlers": handlers,
                "options": str(options)
            }
        )
        
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
        
        # Log server creation error
        get_audit_logger().log_server_action(
            AuditEventType.SERVER_CREATE, 
            username=username,
            client_ip=client_ip,
            server_id=server_id if 'server_id' in locals() else "unknown",
            details={
                "name": name,
                "description": description,
                "error": str(e)
            },
            success=False
        )
        
        return {"status": "error", "error": error_msg}

@mcp_server.tool()
@protect_endpoint
def start_server(server_id: str) -> Dict[str, Any]:
    """
    Start a stopped server instance.
    
    Args:
        server_id: ID of the server to start.
        
    Returns:
        Status of the operation.
    """
    # Check authentication
    auth_header = mcp_server.current_request.headers.get("Authorization", "")
    if not auth_header:
        return {
            "status": "error",
            "code": 401,
            "error": "Authentication required to start servers"
        }
    
    # Extract token or API key
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif auth_header.startswith("ApiKey "):
        api_key = auth_header[7:].strip()
        token = auth_system.authenticate_api_key(api_key)
    
    # Validate token
    if not token or not auth_system.validate_token(token):
        return {
            "status": "error",
            "code": 401,
            "error": "Invalid authentication token"
        }
    
    # Check permission
    if not auth_system.check_permission(token, Permission.SERVER_START):
        return {
            "status": "error",
            "code": 403,
            "error": "Permission denied: server:start permission required"
        }
    
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
@protect_endpoint
def stop_server(server_id: str) -> Dict[str, Any]:
    """
    Stop a running server instance.
    
    Args:
        server_id: ID of the server to stop.
        
    Returns:
        Status of the operation.
    """
    # Check authentication
    auth_header = mcp_server.current_request.headers.get("Authorization", "")
    if not auth_header:
        return {
            "status": "error",
            "code": 401,
            "error": "Authentication required to stop servers"
        }
    
    # Extract token or API key
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif auth_header.startswith("ApiKey "):
        api_key = auth_header[7:].strip()
        token = auth_system.authenticate_api_key(api_key)
    
    # Validate token
    if not token or not auth_system.validate_token(token):
        return {
            "status": "error",
            "code": 401,
            "error": "Invalid authentication token"
        }
    
    # Check permission
    if not auth_system.check_permission(token, Permission.SERVER_STOP):
        return {
            "status": "error",
            "code": 403,
            "error": "Permission denied: server:stop permission required"
        }
    
    server = server_manager.get_instance(server_id)
    if not server:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    if server.status == "stopped":
        return {
            "status": "warning",
            "message": f"Server {server_id} is already stopped"
        }
    
    if server.stop():
        return {
            "status": "success",
            "message": f"Server {server_id} stopped successfully"
        }
    else:
        return {
            "status": "error",
            "error": server.error
        }

@mcp_server.tool()
@protect_endpoint
def delete_server(server_id: str) -> Dict[str, Any]:
    """
    Delete a server instance.
    
    Args:
        server_id: ID of the server to delete.
        
    Returns:
        Status of the operation.
    """
    # Check authentication
    auth_header = mcp_server.current_request.headers.get("Authorization", "")
    client_ip = mcp_server.current_request.client_info.host
    
    # Extract username for audit logging
    username = None
    if auth_header:
        token = None
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif auth_header.startswith("ApiKey "):
            api_key = auth_header[7:].strip()
            token = auth_system.authenticate_api_key(api_key)
        
        if token:
            username = auth_system.validate_token(token)
    
    if not auth_header:
        # Log permission denied for unauthenticated access
        log_permission_denied(username=None, client_ip=client_ip, 
                            details={"action": "delete_server", 
                                    "server_id": server_id,
                                    "reason": "Authentication required"})
        
        return {
            "status": "error",
            "code": 401,
            "error": "Authentication required to delete servers"
        }
    
    # Extract token or API key
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif auth_header.startswith("ApiKey "):
        api_key = auth_header[7:].strip()
        token = auth_system.authenticate_api_key(api_key)
    
    # Validate token
    if not token or not auth_system.validate_token(token):
        # Log permission denied for invalid token
        log_permission_denied(username=username, client_ip=client_ip, 
                            details={"action": "delete_server", 
                                    "server_id": server_id,
                                    "reason": "Invalid authentication token"})
        
        return {
            "status": "error",
            "code": 401,
            "error": "Invalid authentication token"
        }
    
    # Get username for audit logging
    username = auth_system.validate_token(token)
    
    # Check permission
    if not auth_system.check_permission(token, Permission.SERVER_DELETE):
        # Log permission denied
        log_permission_denied(username=username, client_ip=client_ip, 
                            details={"action": "delete_server", 
                                    "server_id": server_id,
                                    "permission": Permission.SERVER_DELETE.value})
        
        return {
            "status": "error",
            "code": 403,
            "error": "Permission denied: server:delete permission required"
        }
    
    server = server_manager.get_instance(server_id)
    if not server:
        # Log server not found
        get_audit_logger().log_server_action(
            AuditEventType.SERVER_DELETE, 
            username=username,
            client_ip=client_ip,
            server_id=server_id,
            details={"error": f"Server not found: {server_id}"},
            success=False
        )
        
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    # Remember server info for logging
    server_info = server.get_info()
    
    if server_manager.delete_instance(server_id):
        # Log successful deletion
        log_server_delete(
            username=username,
            client_ip=client_ip,
            server_id=server_id,
            details=server_info
        )
        
        return {
            "status": "success",
            "message": f"Server {server_id} deleted successfully"
        }
    else:
        # Log failed deletion
        get_audit_logger().log_server_action(
            AuditEventType.SERVER_DELETE, 
            username=username,
            client_ip=client_ip,
            server_id=server_id,
            details={"error": "Failed to delete server instance"},
            success=False
        )
        
        return {
            "status": "error",
            "error": "Failed to delete server instance"
        }

@mcp_server.tool()
@protect_endpoint
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
@protect_endpoint
def list_servers(include_details: bool = False) -> Dict[str, Any]:
    """
    List all managed server instances.
    
    Args:
        include_details: Whether to include detailed information.
        
    Returns:
        List of servers.
    """
    # Check authentication (view permission is required)
    auth_header = mcp_server.current_request.headers.get("Authorization", "")
    
    # For server listing, we'll allow unauthenticated access but limit the details
    authenticated = False
    if auth_header:
        token = None
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif auth_header.startswith("ApiKey "):
            api_key = auth_header[7:].strip()
            token = auth_system.authenticate_api_key(api_key)
        
        if token and auth_system.validate_token(token):
            authenticated = auth_system.check_permission(token, Permission.SERVER_VIEW)
    
    servers_list = []
    
    for server_id, server in server_manager.get_all_instances().items():
        if authenticated and include_details:
            servers_list.append(server.get_info())
        else:
            # Limited information for unauthenticated users
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
        "servers": servers_list,
        "authenticated": authenticated
    }

@mcp_server.tool()
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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
@protect_endpoint
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

# Authentication-related tools
@mcp_server.tool()
@protect_endpoint
def login(username: str, password: str) -> Dict[str, Any]:
    """
    Authenticate a user and return a token.
    
    Args:
        username: Username for authentication
        password: Password for authentication
        
    Returns:
        Authentication result with token if successful
    """
    # Get client IP address
    client_ip = mcp_server.current_request.client_info.host
    
    token = auth_system.authenticate_basic(username, password)
    
    if token:
        # Log successful authentication
        log_auth_success(username, client_ip, details={
            "method": "basic",
            "client_agent": mcp_server.current_request.headers.get("User-Agent", "Unknown")
        })
        
        return {
            "status": "success",
            "token": token,
            "message": "Authentication successful"
        }
    else:
        # Log failed authentication
        log_auth_failure(username, client_ip, details={
            "method": "basic",
            "client_agent": mcp_server.current_request.headers.get("User-Agent", "Unknown")
        })
        
        return {
            "status": "error",
            "code": 401,
            "error": "Invalid username or password"
        }

@mcp_server.tool()
@protect_endpoint
def logout(token: str) -> Dict[str, Any]:
    """
    Invalidate a session token.
    
    Args:
        token: Session token to invalidate
        
    Returns:
        Status of the operation
    """
    # Get client IP address
    client_ip = mcp_server.current_request.client_info.host
    
    # Get username from token before invalidating
    username = None
    for t, data in auth_system.tokens.items():
        if t == token:
            username = data.get("username")
            break
    
    if auth_system.invalidate_token(token):
        # Log successful logout
        if username:
            get_audit_logger().log_event(
                event_type=AuditEventType.AUTH_LOGOUT,
                username=username,
                client_ip=client_ip,
                details={
                    "client_agent": mcp_server.current_request.headers.get("User-Agent", "Unknown")
                },
                severity=AuditSeverity.INFO,
                success=True
            )
        
        return {
            "status": "success",
            "message": "Logged out successfully"
        }
    else:
        return {
            "status": "error",
            "code": 401,
            "error": "Invalid token"
        }

@mcp_server.tool()
@protect_endpoint
def list_users() -> Dict[str, Any]:
    """
    List all users.
    
    Returns:
        List of users
    """
    # Check authentication
    auth_header = mcp_server.current_request.headers.get("Authorization", "")
    if not auth_header:
        return {
            "status": "error",
            "code": 401,
            "error": "Authentication required"
        }
    
    # Extract token
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    
    # Validate token
    username = auth_system.validate_token(token) if token else None
    if not username:
        return {
            "status": "error",
            "code": 401,
            "error": "Invalid authentication token"
        }
    
    # Check if user has admin permission
    if not auth_system.has_permission(username, Permission.ADMIN):
        return {
            "status": "error",
            "code": 403,
            "error": "Permission denied: Admin permission required"
        }
    
    try:
        users = auth_system.list_users()
        return {
            "status": "success",
            "count": len(users),
            "users": users
        }
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        return {
            "status": "error",
            "error": f"Error listing users: {str(e)}"
        }

@mcp_server.tool()
@protect_endpoint
def update_user(target_username: str, 
                password: Optional[str] = None,
                role: Optional[str] = None,
                enabled: Optional[bool] = None,
                metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Update user details.
    
    Args:
        target_username: Username of the user to update
        password: Optional new password
        role: Optional new role
        enabled: Optional enabled/disabled status
        metadata: Optional metadata to update
        
    Returns:
        Status of the operation
    """
    # Check authentication
    auth_header = mcp_server.current_request.headers.get("Authorization", "")
    if not auth_header:
        return {
            "status": "error",
            "code": 401,
            "error": "Authentication required"
        }
    
    # Extract token
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    
    # Validate token
    username = auth_system.validate_token(token) if token else None
    if not username:
        return {
            "status": "error",
            "code": 401,
            "error": "Invalid authentication token"
        }
    
    # Self-update or admin update?
    is_self_update = username == target_username
    
    # For updating other users, admin permission is required
    if not is_self_update and not auth_system.has_permission(username, Permission.ADMIN):
        return {
            "status": "error",
            "code": 403,
            "error": "Permission denied: Admin permission required to update other users"
        }
    
    # For self-update, only password and metadata can be changed
    if is_self_update and (role is not None or enabled is not None):
        return {
            "status": "error",
            "code": 403,
            "error": "Permission denied: Cannot change own role or enabled status"
        }
    
    try:
        # Validate role if provided
        role_enum = None
        if role is not None:
            try:
                from authentication_system import Role
                role_enum = Role(role)
            except ValueError:
                return {
                    "status": "error",
                    "error": f"Invalid role: {role}. Must be one of: admin, operator, developer, viewer, custom"
                }
        
        # Update user
        user = auth_system.update_user(
            username=target_username,
            password=password,
            role=role_enum,
            enabled=enabled,
            metadata=metadata
        )
        
        return {
            "status": "success",
            "message": f"User {target_username} updated successfully",
            "user": user.to_dict(include_sensitive=False)
        }
    except ValueError as e:
        return {
            "status": "error",
            "error": str(e)
        }
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return {
            "status": "error",
            "error": f"Error updating user: {str(e)}"
        }

@mcp_server.tool()
@protect_endpoint
def delete_user(target_username: str) -> Dict[str, Any]:
    """
    Delete a user.
    
    Args:
        target_username: Username of the user to delete
        
    Returns:
        Status of the operation
    """
    # Check authentication
    auth_header = mcp_server.current_request.headers.get("Authorization", "")
    if not auth_header:
        return {
            "status": "error",
            "code": 401,
            "error": "Authentication required"
        }
    
    # Extract token
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    
    # Validate token
    username = auth_system.validate_token(token) if token else None
    if not username:
        return {
            "status": "error",
            "code": 401,
            "error": "Invalid authentication token"
        }
    
    # Cannot delete self
    if username == target_username:
        return {
            "status": "error",
            "error": "Cannot delete your own account"
        }
    
    # Check if user has admin permission
    if not auth_system.has_permission(username, Permission.ADMIN):
        return {
            "status": "error",
            "code": 403,
            "error": "Permission denied: Admin permission required"
        }
    
    try:
        if auth_system.delete_user(target_username):
            return {
                "status": "success",
                "message": f"User {target_username} deleted successfully"
            }
        else:
            return {
                "status": "error",
                "error": f"Failed to delete user {target_username}"
            }
    except ValueError as e:
        return {
            "status": "error",
            "error": str(e)
        }
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return {
            "status": "error",
            "error": f"Error deleting user: {str(e)}"
        }

@mcp_server.tool()
@protect_endpoint
def get_csrf_token(session_id: str) -> Dict[str, Any]:
    """
    Generate a CSRF token for a session.
    
    Args:
        session_id: Session ID to generate a token for
        
    Returns:
        Dictionary with the generated token
    """
    # Validate the session ID
    if not session_id:
        return {
            "status": "error",
            "code": 400,
            "error": "Session ID is required"
        }
    
    # Generate a CSRF token
    token = protection.generate_csrf_token(session_id)
    
    # Log the token generation
    get_audit_logger().log_security_event(
        AuditEventType.SEC_DATA_ENCRYPTION,  # Using data encryption event type as a proxy for token creation
        None,
        "unknown",  # We don't have the client IP in this context
        None,
        {"session_id": session_id, "purpose": "csrf_token_generation"}
    )
    
    return {
        "status": "success",
        "token": token,
        "expires_in": DEFAULT_CSRF_TOKEN_EXPIRY
    }

def main():
    """Main function to initialize and run the MCP-Forge Server."""
    global next_port
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='MCP-Forge Server')
    parser.add_argument('--port', type=int, default=9000, help='Port to listen on')
    parser.add_argument('--host', type=str, default='localhost', help='Host to bind to')
    parser.add_argument('--config', type=str, default='forge_config.json', help='Configuration file path')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--enable-autoscaling', action='store_true', help='Enable auto-scaling')
    args = parser.parse_args()
    
    # Set up logging level based on arguments
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Configure logging system
    configure_logging(log_level="DEBUG" if args.debug else "INFO")
    
    # Load configuration
    config_manager.set_config_file(args.config)
    try:
        config_manager.load_config()
        logger.info(f"Configuration loaded from {args.config}")
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        logger.info("Using default configuration")
    
    # Set base port for child servers
    next_port = args.port + 1
    logger.info(f"Starting port for child servers: {next_port}")
    
    # Initialize the authentication system
    auth_system = AuthenticationSystem()
    
    # Register shutdown hook
    register_shutdown_hook(lambda: logger.info("Shutting down MCP-Forge Server..."))
    
    # Set shutdown timeout
    set_shutdown_timeout(30.0)  # 30 seconds
    
    # Initialize log aggregator
    initialize_log_aggregator()
    
    # Start background services
    start_aggregation_service()
    start_status_reporting()
    start_metrics_collection()
    start_alerting_service()
    
    # Initialize protection mechanisms with server configuration
    protection = get_protection_mechanisms()
    
    # Configure security headers
    security_headers = protection.security_headers.get_security_headers()
    logger.info("Security protection mechanisms initialized")
    
    # Set up server CORS and security settings
    server_hardening = protection.server_hardening.get_hardening_middleware_config()
    
    # Log system startup event
    get_audit_logger().log_system_event(AuditEventType.SYS_STARTUP, {
        "version": "1.0.0",  # Replace with actual version
        "host": args.host,
        "port": args.port,
        "config_file": args.config,
        "debug": args.debug
    })
    
    # Auto-start any previously created servers if configured
    if config_manager.get("server", "auto_start", True):
        _auto_start_servers()
    
    # Enable auto-scaling if requested
    if args.enable_autoscaling or config_manager.get("resources", "enable_auto_scaling", False):
        auto_scaler = get_auto_scaler()
        auto_scaler.start()
        logger.info("Auto-scaling enabled")
    
    # Set up the MCP server headers with secure defaults
    headers = {
        "Content-Security-Policy": security_headers.get("Content-Security-Policy", protection.csp.default_policy),
        "X-Content-Type-Options": security_headers.get("X-Content-Type-Options", "nosniff"),
        "X-Frame-Options": security_headers.get("X-Frame-Options", "DENY"),
        "Strict-Transport-Security": security_headers.get("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    }
    
    # Log server information
    logger.info(f"Starting MCP-Forge Server on {args.host}:{args.port}")
    logger.info(f"Server manager initialized with {len(server_manager.get_all_instances())} servers")
    
    # Start the server
    try:
        mcp_server.start(host=args.host, port=args.port, headers=headers)
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    except Exception as e:
        logger.error(f"Error starting server: {e}")
    finally:
        # Ensure proper shutdown
        get_shutdown_handler().shutdown("Server shutting down", 10.0)
        # Log system shutdown event
        get_audit_logger().log_system_event(AuditEventType.SYS_SHUTDOWN, {
            "reason": "Normal shutdown"
        })

if __name__ == "__main__":
    sys.exit(main()) 