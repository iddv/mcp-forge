#!/usr/bin/env python
"""
Meta-MCP Server

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

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('meta_mcp_server.log')
    ]
)
logger = logging.getLogger('meta_mcp_server')

class ServerInstance:
    """Represents a managed MCP server instance."""
    
    def __init__(self, server_id, name, description, port, script_path):
        """Initialize a server instance."""
        self.id = server_id
        self.name = name
        self.description = description
        self.port = port
        self.script_path = script_path
        self.process = None
        self.started_at = None
        self.status = "initialized"  # initialized, running, stopped, error
        self.capabilities = []
        self.error = None
        
    def start(self):
        """Start the server process."""
        if self.process and self.process.poll() is None:
            logger.warning(f"Server {self.id} is already running")
            return True
            
        try:
            logger.info(f"Starting server {self.id} on port {self.port}")
            
            # Set the MCP_PORT environment variable for the child process
            env = os.environ.copy()
            env["MCP_PORT"] = str(self.port)
            
            self.process = subprocess.Popen(
                [sys.executable, self.script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )
            self.started_at = datetime.now()
            self.status = "running"
            
            # Start threads to monitor stdout/stderr
            threading.Thread(target=self._monitor_output, args=(self.process.stdout, "stdout"), daemon=True).start()
            threading.Thread(target=self._monitor_output, args=(self.process.stderr, "stderr"), daemon=True).start()
            
            # Give it a moment to start up
            time.sleep(1)
            
            # Check if process is still running
            if self.process.poll() is not None:
                self.error = f"Server {self.id} failed to start (exit code: {self.process.poll()})"
                self.status = "error"
                logger.error(self.error)
                return False
                
            return True
        except Exception as e:
            self.error = f"Failed to start server {self.id}: {str(e)}"
            self.status = "error"
            logger.error(self.error)
            return False
            
    def stop(self):
        """Stop the server process."""
        if not self.process:
            logger.warning(f"Server {self.id} is not running")
            return
            
        try:
            logger.info(f"Stopping server {self.id}")
            self.process.terminate()
            
            # Give it a chance to terminate gracefully
            for _ in range(5):
                if self.process.poll() is not None:
                    break
                time.sleep(0.5)
                
            # Force kill if necessary
            if self.process.poll() is None:
                logger.warning(f"Server {self.id} did not terminate gracefully, forcing...")
                self.process.kill()
                
            self.status = "stopped"
            self.process = None
        except Exception as e:
            logger.error(f"Error stopping server {self.id}: {e}")
            self.status = "error"
            self.error = f"Error stopping server: {str(e)}"
            
    def get_info(self):
        """Get information about this server instance."""
        uptime = None
        if self.started_at and self.status == "running":
            uptime = (datetime.now() - self.started_at).total_seconds()
            
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "port": self.port,
            "status": self.status,
            "uptime": uptime,
            "capabilities": self.capabilities,
            "script_path": self.script_path,
            "error": self.error
        }
            
    def _monitor_output(self, pipe, name):
        """Monitor and log output from the server process."""
        for line in pipe:
            logger.info(f"[{self.id}:{name}] {line.strip()}")

# Create the Meta MCP Server using the official SDK
mcp_server = FastMCP("Meta MCP Server", description="A server that creates and manages child MCP servers")

# Store server instances (in-memory database)
server_instances = {}
next_port = None  # Will be initialized in main()

@mcp_server.resource("servers://list")
def list_servers_resource() -> str:
    """Return a list of all managed servers."""
    servers_list = []
    for server_id, server in server_instances.items():
        servers_list.append(server.get_info())
    
    return json.dumps(servers_list, indent=2)

@mcp_server.resource("servers://{server_id}/info")
def server_info_resource(server_id: str) -> str:
    """Return information about a specific server."""
    if server_id not in server_instances:
        return json.dumps({"error": f"Server not found: {server_id}"}, indent=2)
    
    return json.dumps(server_instances[server_id].get_info(), indent=2)

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
    
    # Import template system
    from template_system import get_template_manager, TemplateCustomizer
    from template_system.templates import get_base_template_path
    
    # Generate server ID if name not provided
    server_id = name if name else generate_server_id()
    
    # Default capabilities
    if capabilities is None:
        capabilities = ["echo", "time", "uptime"]
        
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
    
    # Create script file path
    script_filename = f"{server_id.replace('-', '_').replace(' ', '_').lower()}.py"
    servers_dir = os.path.join(os.path.dirname(__file__), 'servers')
    os.makedirs(servers_dir, exist_ok=True)
    script_path = os.path.join(servers_dir, script_filename)
    
    try:
        # First generate the server with basic parameters
        template_manager.generate_server(
            output_path=script_path,
            server_name=server_id,
            server_port=next_port,
            description=description,
            capabilities=capabilities
        )
        
        # Apply customizations if needed
        if handlers or options:
            # Read the generated file
            with open(script_path, 'r') as f:
                content = f.read()
                
            # Apply customizations
            customizer = TemplateCustomizer()
            customized_content = customizer.customize_template(
                template_content=content,
                handlers=handlers,
                options=options
            )
            
            # Write the customized content back
            with open(script_path, 'w') as f:
                f.write(customized_content)
            
        # Create server instance
        server = ServerInstance(
            server_id=server_id,
            name=server_id,
            description=description,
            port=next_port,
            script_path=script_path
        )
        server.capabilities = capabilities
        
        # Add to managed servers
        server_instances[server_id] = server
        
        # Update next port
        next_port += 1
        
        logger.info(f"Created server instance: {server_id} at {script_path}")
        
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
    if server_id not in server_instances:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    server = server_instances[server_id]
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
    if server_id not in server_instances:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    server = server_instances[server_id]
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
    if server_id not in server_instances:
        return {
            "status": "error",
            "error": f"Server not found: {server_id}"
        }
    
    server = server_instances[server_id]
    
    # Stop the server if running
    if server.status == "running":
        server.stop()
    
    # Delete server script
    try:
        if os.path.exists(server.script_path):
            os.remove(server.script_path)
        
        # Remove from managed servers
        del server_instances[server_id]
        
        return {
            "status": "success",
            "message": f"Server {server_id} deleted successfully"
        }
    except Exception as e:
        error_msg = f"Error deleting server: {str(e)}"
        logger.error(error_msg)
        return {"status": "error", "error": error_msg}

@mcp_server.tool()
def list_servers(include_details: bool = False) -> Dict[str, Any]:
    """
    List all managed servers.
    
    Args:
        include_details: Whether to include detailed information about each server.
        
    Returns:
        List of servers.
    """
    servers = []
    for server_id, server in server_instances.items():
        if include_details:
            servers.append(server.get_info())
        else:
            servers.append({
                "id": server.id,
                "name": server.name,
                "status": server.status,
                "port": server.port
            })
    
    return {
        "status": "success",
        "count": len(servers),
        "servers": servers
    }

@mcp_server.tool()
def list_customization_options() -> Dict[str, Any]:
    """
    List available customization options for MCP servers.
    
    Returns:
        Dictionary containing available customizations.
    """
    try:
        from template_system import TemplateCustomizer
        
        # Get customizer
        customizer = TemplateCustomizer()
        
        # Get available customizations
        customizations = customizer.get_available_customizations()
        
        return {
            "status": "success",
            "customizations": customizations
        }
    except Exception as e:
        error_msg = f"Error listing customization options: {str(e)}"
        logger.error(error_msg)
        return {"status": "error", "error": error_msg}

def generate_server_id() -> str:
    """
    Generate a unique ID for a new server.
    
    Returns:
        A unique server ID.
    """
    # Time-based prefix
    prefix = datetime.now().strftime('%Y%m%d')
    
    # Random suffix
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    
    server_id = f"mcp-{prefix}-{suffix}"
    
    # Ensure it's unique
    while server_id in server_instances:
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        server_id = f"mcp-{prefix}-{suffix}"
    
    return server_id

def recover_server_instances() -> None:
    """Recover information about existing server instances."""
    global next_port
    
    try:
        # Look for server script files in the servers directory
        servers_dir = os.path.join(os.path.dirname(__file__), 'servers')
        if not os.path.exists(servers_dir):
            os.makedirs(servers_dir, exist_ok=True)
            return
            
        for script_file in os.listdir(servers_dir):
            if script_file.endswith('.py'):
                script_path = os.path.join(servers_dir, script_file)
                
                # Try to extract server info from the file
                with open(script_path, 'r') as f:
                    content = f.read()
                    
                # Extract server parameters using regex
                server_id_match = re.search(r'SERVER_NAME\s*=\s*["\']([^"\']+)["\']', content)
                port_match = re.search(r'SERVER_PORT\s*=\s*(\d+)', content)
                desc_match = re.search(r'SERVER_DESCRIPTION\s*=\s*["\']([^"\']+)["\']', content)
                capabilities_match = re.search(r'SERVER_CAPABILITIES\s*=\s*(\[.*?\])', content, re.DOTALL)
                
                if server_id_match and port_match:
                    server_id = server_id_match.group(1)
                    port = int(port_match.group(1))
                    description = desc_match.group(1) if desc_match else "Unknown"
                    
                    # Parse capabilities if available
                    capabilities = []
                    if capabilities_match:
                        try:
                            capabilities = json.loads(capabilities_match.group(1))
                        except:
                            logger.warning(f"Failed to parse capabilities for server {server_id}")
                    
                    # Create server instance but don't start it
                    server = ServerInstance(
                        server_id=server_id,
                        name=server_id,
                        description=description,
                        port=port,
                        script_path=script_path
                    )
                    server.capabilities = capabilities
                    server_instances[server_id] = server
                    
                    # Update next port if necessary
                    if port >= next_port:
                        next_port = port + 1
                        
                    logger.info(f"Recovered server instance: {server_id} on port {port}")
    except Exception as e:
        logger.error(f"Error recovering server instances: {e}")

def main():
    """Main entry point."""
    global next_port
    
    parser = argparse.ArgumentParser(description="Meta MCP Server")
    parser.add_argument("--port", type=int, default=9000, help="Port to listen on")
    parser.add_argument("--host", default="localhost", help="Host to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        
    # Set up the next available port for child servers
    global next_port
    next_port = args.port + 1
    
    # Find and recover existing server files
    recover_server_instances()
    
    # Add environment info to logger
    logger.info(f"Meta MCP Server starting on port {args.port}")
    logger.info(f"Child servers will start from port {next_port}")
    
    # Run the server
    mcp_server.run()
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 