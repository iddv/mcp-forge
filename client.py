#!/usr/bin/env python
"""
MCP Client

A client for connecting directly to MCP servers created by the MCP-Forge Server.
This client uses the official MCP SDK.
"""

import argparse
import json
import os
import sys
import time
from typing import Dict, Any, Optional, List

import mcp
from mcp import ClientSession

async def connect_to_server(host: str, port: int) -> ClientSession:
    """
    Connect to an MCP server.
    
    Args:
        host: Server host.
        port: Server port.
        
    Returns:
        Connected client.
    """
    import asyncio
    from mcp.client.session import ClientSession
    from mcp.client.sse import sse_client
    from contextlib import aclosing
    
    server_url = f"http://{host}:{port}/sse"
    
    # Create sse client
    sse = await sse_client(server_url).__aenter__()
    read, write = sse
    
    # Create and initialize the client session
    client = ClientSession(read, write)
    await client.initialize()
    return client

async def list_tools(client: ClientSession) -> List[Dict[str, Any]]:
    """
    List available tools on the server.
    
    Args:
        client: Connected client.
        
    Returns:
        List of available tools.
    """
    return await client.list_tools()

async def call_tool(client: ClientSession, tool_name: str, **arguments) -> Any:
    """
    Call a tool on the server.
    
    Args:
        client: Connected client.
        tool_name: Name of the tool to call.
        **arguments: Tool arguments.
        
    Returns:
        Tool result.
    """
    return await client.call_tool(tool_name, arguments)

async def list_resources(client: ClientSession) -> List[Dict[str, Any]]:
    """
    List available resources on the server.
    
    Args:
        client: Connected client.
        
    Returns:
        List of available resources.
    """
    return await client.list_resources()

async def read_resource(client: ClientSession, resource_uri: str) -> str:
    """
    Read a resource from the server.
    
    Args:
        client: Connected client.
        resource_uri: URI of the resource to read.
        
    Returns:
        Resource content.
    """
    content, mime_type = await client.read_resource(resource_uri)
    return content.decode("utf-8") if isinstance(content, bytes) else content

async def list_prompts(client: ClientSession) -> List[Dict[str, Any]]:
    """
    List available prompts on the server.
    
    Args:
        client: Connected client.
        
    Returns:
        List of available prompts.
    """
    return await client.list_prompts()

async def get_prompt(client: ClientSession, prompt_name: str, **arguments) -> Dict[str, Any]:
    """
    Get a prompt from the server.
    
    Args:
        client: Connected client.
        prompt_name: Name of the prompt to get.
        **arguments: Prompt arguments.
        
    Returns:
        Prompt content.
    """
    return await client.get_prompt(prompt_name, arguments or None)

async def meta_server_commands():
    """Run commands against the forge server."""
    forge_port = int(os.environ.get("FORGE_MCP_PORT", "9000"))
    
    try:
        print(f"Connecting to MCP-Forge Server on port {forge_port}...")
        client = await connect_to_server("localhost", forge_port)
    except Exception as e:
        print(f"Error connecting to forge server: {e}")
        print(f"Make sure the forge server is running on localhost:{forge_port}")
        print("You can start it with: python3 forge_mcp_server.py --port 9000")
        return 1
    
    print(f"Connected to MCP-Forge Server on localhost:{forge_port}")
    
    # List available tools
    print("\nAvailable tools on MCP-Forge Server:")
    tools = await list_tools(client)
    for tool in tools:
        print(f"- {tool['name']}: {tool['description']}")
    
    # List available servers
    print("\nListing managed servers:")
    servers = await call_tool(client, "list_servers", include_details=True)
    if servers.get("servers"):
        for i, server in enumerate(servers["servers"]):
            print(f"\n[{i+1}] {server['id']}:")
            print(f"  Status: {server['status']}")
            print(f"  Port: {server['port']}")
            print(f"  Description: {server.get('description', 'No description')}")
    else:
        print("No servers found.")
    
    return 0

async def run_command(args):
    """Run the specified command."""
    if args.command == "meta":
        return await meta_server_commands()
    
    # Connect to specific server
    try:
        print(f"Connecting to MCP server on port {args.port}...")
        client = await connect_to_server(args.host, args.port)
    except Exception as e:
        print(f"Error connecting to server: {e}")
        print(f"Make sure the server is running on {args.host}:{args.port}")
        return 1
    
    print(f"Connected to server on {args.host}:{args.port}")
    
    if args.command == "tools":
        # List available tools
        tools = await list_tools(client)
        
        print("\nAvailable tools:")
        for tool in tools:
            print(f"- {tool['name']}: {tool['description']}")
            if tool.get('parameter_schema'):
                print(f"  Parameters: {json.dumps(tool['parameter_schema'], indent=2)}")
    
    elif args.command == "resources":
        # List available resources
        resources = await list_resources(client)
        
        print("\nAvailable resources:")
        for resource in resources:
            print(f"- {resource['uri']}: {resource['description']}")
    
    elif args.command == "prompts":
        # List available prompts
        prompts = await list_prompts(client)
        
        print("\nAvailable prompts:")
        for prompt in prompts:
            print(f"- {prompt['name']}: {prompt['description']}")
    
    elif args.command == "call":
        # Call a tool
        if not args.tool_name:
            print("Error: tool name is required")
            return 1
        
        tool_args = {}
        if args.arguments:
            for arg in args.arguments:
                if "=" in arg:
                    key, value = arg.split("=", 1)
                    # Try to parse JSON values
                    try:
                        tool_args[key] = json.loads(value)
                    except json.JSONDecodeError:
                        tool_args[key] = value
        
        print(f"Calling tool '{args.tool_name}' with arguments: {tool_args}")
        result = await call_tool(client, args.tool_name, **tool_args)
        print("\nResult:")
        print(json.dumps(result, indent=2))
    
    elif args.command == "read":
        # Read a resource
        if not args.resource_uri:
            print("Error: resource URI is required")
            return 1
        
        print(f"Reading resource '{args.resource_uri}'")
        content = await read_resource(client, args.resource_uri)
        print("\nContent:")
        print(content)
    
    elif args.command == "prompt":
        # Get a prompt
        if not args.prompt_name:
            print("Error: prompt name is required")
            return 1
        
        prompt_args = {}
        if args.arguments:
            for arg in args.arguments:
                if "=" in arg:
                    key, value = arg.split("=", 1)
                    # Try to parse JSON values
                    try:
                        prompt_args[key] = json.loads(value)
                    except json.JSONDecodeError:
                        prompt_args[key] = value
        
        print(f"Getting prompt '{args.prompt_name}' with arguments: {prompt_args}")
        result = await get_prompt(client, args.prompt_name, **prompt_args)
        print("\nPrompt:")
        print(json.dumps(result, indent=2))
    
    # New server management commands
    elif args.command == "create":
        # Create a new server
        server_args = {}
        if args.arguments:
            for arg in args.arguments:
                if "=" in arg:
                    key, value = arg.split("=", 1)
                    # Try to parse JSON values
                    try:
                        server_args[key] = json.loads(value)
                    except json.JSONDecodeError:
                        server_args[key] = value
        
        print(f"Creating server with arguments: {server_args}")
        result = await call_tool(client, "create_server", **server_args)
        print("\nResult:")
        print(json.dumps(result, indent=2))
    
    elif args.command == "start":
        # Start a server
        if not args.server_id:
            print("Error: server_id is required")
            return 1
            
        print(f"Starting server: {args.server_id}")
        result = await call_tool(client, "start_server", server_id=args.server_id)
        print("\nResult:")
        print(json.dumps(result, indent=2))
    
    elif args.command == "stop":
        # Stop a server
        if not args.server_id:
            print("Error: server_id is required")
            return 1
            
        print(f"Stopping server: {args.server_id}")
        result = await call_tool(client, "stop_server", server_id=args.server_id)
        print("\nResult:")
        print(json.dumps(result, indent=2))
    
    elif args.command == "restart":
        # Restart a server
        if not args.server_id:
            print("Error: server_id is required")
            return 1
            
        print(f"Restarting server: {args.server_id}")
        result = await call_tool(client, "restart_server", server_id=args.server_id)
        print("\nResult:")
        print(json.dumps(result, indent=2))
    
    elif args.command == "delete":
        # Delete a server
        if not args.server_id:
            print("Error: server_id is required")
            return 1
            
        print(f"Deleting server: {args.server_id}")
        result = await call_tool(client, "delete_server", server_id=args.server_id)
        print("\nResult:")
        print(json.dumps(result, indent=2))
    
    elif args.command == "logs":
        # Get server logs
        if not args.server_id:
            print("Error: server_id is required")
            return 1
            
        log_args = {"server_id": args.server_id}
        if args.log_type:
            log_args["log_type"] = args.log_type
        if args.max_lines:
            log_args["max_lines"] = args.max_lines
            
        print(f"Getting logs for server: {args.server_id}")
        result = await call_tool(client, "get_server_logs", **log_args)
        print("\nLogs:")
        if result.get("logs", {}).get("stdout"):
            print("\nSTDOUT:")
            for line in result["logs"]["stdout"]:
                print(line)
        if result.get("logs", {}).get("stderr"):
            print("\nSTDERR:")
            for line in result["logs"]["stderr"]:
                print(line)
    
    elif args.command == "list":
        # List servers
        include_details = args.details
        result = await call_tool(client, "list_servers", include_details=include_details)
        print(f"\nFound {result['count']} servers:")
        for i, server in enumerate(result["servers"]):
            print(f"\n[{i+1}] {server['id']}:")
            for key, value in server.items():
                if key != 'id':
                    print(f"  {key}: {value}")
    
    elif args.command == "info":
        # Get server info
        if not args.server_id:
            print("Error: server_id is required")
            return 1
            
        print(f"Getting info for server: {args.server_id}")
        content = await read_resource(client, f"servers://{args.server_id}/info")
        server_info = json.loads(content)
        print("\nServer Info:")
        print(json.dumps(server_info, indent=2))
    
    elif args.command == "stats":
        # Get server process stats
        if not args.server_id:
            print("Error: server_id is required")
            return 1
            
        print(f"Getting process stats for server: {args.server_id}")
        result = await call_tool(client, "get_server_process_stats", server_id=args.server_id)
        print("\nProcess Stats:")
        print(json.dumps(result, indent=2))
    
    return 0

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="MCP Client")
    parser.add_argument("--host", default="localhost", help="Server host")
    parser.add_argument("--port", type=int, default=9001, help="Server port")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Meta server command
    subparsers.add_parser("meta", help="Run commands against the forge server")
    
    # Tools command
    subparsers.add_parser("tools", help="List available tools")
    
    # Resources command
    subparsers.add_parser("resources", help="List available resources")
    
    # Prompts command
    subparsers.add_parser("prompts", help="List available prompts")
    
    # Call command
    call_parser = subparsers.add_parser("call", help="Call a tool")
    call_parser.add_argument("tool_name", help="Name of the tool to call")
    call_parser.add_argument("arguments", nargs="*", help="Tool arguments (key=value)")
    
    # Read command
    read_parser = subparsers.add_parser("read", help="Read a resource")
    read_parser.add_argument("resource_uri", help="URI of the resource to read")
    
    # Prompt command
    prompt_parser = subparsers.add_parser("prompt", help="Get a prompt")
    prompt_parser.add_argument("prompt_name", help="Name of the prompt to get")
    prompt_parser.add_argument("arguments", nargs="*", help="Prompt arguments (key=value)")
    
    # New server management commands
    # Create server command
    create_parser = subparsers.add_parser("create", help="Create a new server")
    create_parser.add_argument("arguments", nargs="*", help="Server arguments (key=value)")
    
    # Start server command
    start_parser = subparsers.add_parser("start", help="Start a server")
    start_parser.add_argument("server_id", help="ID of the server to start")
    
    # Stop server command
    stop_parser = subparsers.add_parser("stop", help="Stop a server")
    stop_parser.add_argument("server_id", help="ID of the server to stop")
    
    # Restart server command
    restart_parser = subparsers.add_parser("restart", help="Restart a server")
    restart_parser.add_argument("server_id", help="ID of the server to restart")
    
    # Delete server command
    delete_parser = subparsers.add_parser("delete", help="Delete a server")
    delete_parser.add_argument("server_id", help="ID of the server to delete")
    
    # List servers command
    list_parser = subparsers.add_parser("list", help="List servers")
    list_parser.add_argument("--details", "-d", action="store_true", help="Include details")
    
    # Get server info command
    info_parser = subparsers.add_parser("info", help="Get server info")
    info_parser.add_argument("server_id", help="ID of the server to get info for")
    
    # Get server logs command
    logs_parser = subparsers.add_parser("logs", help="Get server logs")
    logs_parser.add_argument("server_id", help="ID of the server to get logs for")
    logs_parser.add_argument("--type", dest="log_type", choices=["stdout", "stderr", "all"], 
                           default="all", help="Type of logs to get")
    logs_parser.add_argument("--lines", dest="max_lines", type=int, default=50, 
                           help="Maximum number of lines to return")
    
    # Get server process stats command
    stats_parser = subparsers.add_parser("stats", help="Get server process stats")
    stats_parser.add_argument("server_id", help="ID of the server to get process stats for")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    import asyncio
    return asyncio.run(run_command(args))

if __name__ == "__main__":
    sys.exit(main()) 