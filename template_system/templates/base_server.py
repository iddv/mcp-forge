#!/usr/bin/env python
"""
Template MCP Server

This is a template for dynamically generated MCP servers using the official MCP SDK.
It will be customized by the meta-server based on specific requirements.
"""

import logging
import os
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional

from mcp.server.fastmcp import FastMCP

# Configurable parameters (will be replaced by the meta-server)
SERVER_NAME = "{{SERVER_NAME}}"
SERVER_DESCRIPTION = "{{SERVER_DESCRIPTION}}"
SERVER_PORT = {{SERVER_PORT}}
SERVER_CAPABILITIES = {{SERVER_CAPABILITIES}}
SERVER_HANDLERS = {{SERVER_HANDLERS}}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'{SERVER_NAME.replace(" ", "_").lower()}.log')
    ]
)
logger = logging.getLogger(SERVER_NAME)

# Create the MCP server
mcp_server = FastMCP(SERVER_NAME, description=SERVER_DESCRIPTION)

# Echo handler
@mcp_server.tool()
def handle_echo(message: str) -> str:
    """Echo back the received text."""
    logger.info(f"Echo request: {message}")
    return f"Echo: {message}"

# Time handler
@mcp_server.tool()
def handle_time() -> str:
    """Return the current server time."""
    current_time = datetime.now().isoformat()
    logger.info(f"Time request, returning: {current_time}")
    return f"Server time: {current_time}"

# Uptime handler
@mcp_server.tool()
def handle_uptime() -> str:
    """Return how long the server has been running."""
    global start_time
    uptime = (datetime.now() - start_time).total_seconds()
    logger.info(f"Uptime request, returning: {uptime} seconds")
    return f"Server uptime: {uptime} seconds"

# Sample resource
@mcp_server.resource("server://info")
def server_info() -> str:
    """Return basic information about this server."""
    return f"""
Server Name: {SERVER_NAME}
Description: {SERVER_DESCRIPTION}
Port: {SERVER_PORT}
Capabilities: {', '.join(SERVER_CAPABILITIES)}
Started: {start_time.isoformat()}
    """

# Sample prompt
@mcp_server.prompt()
def help_prompt() -> str:
    """Return a help prompt for using this server."""
    return f"""
# {SERVER_NAME} Help

This is an MCP server that provides the following capabilities:
{', '.join(SERVER_CAPABILITIES)}

## Available Tools:
- echo: Echo back a message
- time: Get the current server time
- uptime: Get how long the server has been running

## Available Resources:
- server://info: Get basic server information
    """

# Additional handlers will be dynamically added based on SERVER_HANDLERS

def main():
    """Main entry point for the server."""
    global start_time
    start_time = datetime.now()
    
    logger.info(f"Starting {SERVER_NAME} MCP server")
    
    # Configure server port
    os.environ["MCP_PORT"] = str(SERVER_PORT)
    
    # Start the server
    mcp_server.run()

if __name__ == "__main__":
    main() 