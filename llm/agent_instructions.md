# Agent Instructions: MCP-Forge Framework

## Project Overview
MCP-Forge is a powerful framework for dynamically generating, managing, and monitoring Model Context Protocol (MCP) servers. The framework uses the official MCP SDK to create a system where specialized MCP servers can be spawned on demand through a centralized interface.

## Your Task
Continue developing the MCP-Forge framework according to the implementation plan. The progress tracker (`forge_mcp_server_plan.md`) contains the current status of all tasks, so check that first to understand what has been completed and what needs work next.

## How to Approach the Project

1. **Understand the Architecture**:
   - Review the code in `forge_mcp_server.py`, `template_system/`, and `client.py`
   - Understand the relationship between the forge server and child servers
   - Examine the template system in the `template_system/` directory
   - Familiarize yourself with the official MCP SDK and its capabilities

2. **Check Current Progress**:
   - Run `python3 progress_tracker.py stats` to see overall progress
   - Run `python3 progress_tracker.py report` to get detailed status

3. **Continue Implementation**:
   - Find tasks marked "Not Started" or "In Progress" in the phase that's currently active
   - Implement those features according to the project architecture
   - Update progress using `python3 progress_tracker.py update PHASE TASK STATUS --notes "Your notes"`

4. **Testing**:
   - Start the forge server with `python3 forge_mcp_server.py --port 9000`
   - Create and interact with child servers using the client: `python3 client.py`
   - Verify that features work as expected

5. **Documentation**:
   - Update README.md with any significant architectural changes
   - Document new features and how to use them

## Design Principles to Follow

1. **MCP Compliance**: All implementations should follow the MCP specification
2. **Modularity**: Maintain clean separation between components
3. **Error Handling**: Provide meaningful error messages and recovery mechanisms
4. **Scalability**: Design for potential large numbers of child servers
5. **Documentation**: Keep code well-documented for future developers
6. **Terminology**: Use "forge" instead of "meta" in all references
7. **Customizability**: Make sure all components support customization

## Project Structure Reference

```
mcp-forge/
├── forge_mcp_server.py       # Core forge server
├── template_system/          # Template system for generating servers
│   ├── template_manager.py   # Template loading and parsing
│   ├── customization.py      # Customization points
│   ├── handlers/             # Custom handler templates
│   └── templates/            # Server templates
├── client.py                 # Client for interacting with servers
├── servers/                  # Generated server scripts directory
├── progress_tracker.py       # Development progress tracking utility
└── forge_mcp_server_plan.md  # Implementation plan and tracker
```

## Command Reference

- Start forge server: `python3 forge_mcp_server.py --port 9000`
- Create a simple server: `python3 client.py call create_server name="my-server" description="Description" capabilities=["echo","time"]`
- Create a server with custom handlers: `python3 client.py call create_server name="advanced-server" handlers=["file_reader","http_request"]`
- Configure server options: `python3 client.py call create_server name="storage-server" options={"persistence":"sqlite","auth":"basic"}`
- List customization options: `python3 client.py call list_customization_options`
- List servers: `python3 client.py meta`
- Connect to a server: `python3 client.py --port <PORT> tools`
- Update progress: `python3 progress_tracker.py update <PHASE> "<TASK>" "<STATUS>" --notes "Notes"`

## Important Implementation Details

1. **Template System**: We've implemented a comprehensive template system in the `template_system/` directory that supports:
   - Template validation
   - Customization points
   - Custom handlers (file_reader, http_request, database)
   - Server options (persistence, authentication, logging)

2. **Current Status**:
   - Phase 1 (Core Forge Server) is completed
   - Phase 2 (Template-Based Server Generator) is completed
   - Phase 3 (Server Vending Mechanism) is in progress

3. **Next Steps**:
   - Implement request validation for server creation
   - Create server instantiation logic
   - Develop unique ID generation system
   - Add configuration parameter handling

## Dependencies
- Python 3.7+
- MCP SDK: `mcp>=1.6.0`
- HTTP Client: `httpx>=0.28.0`
- Async I/O: `anyio>=4.0.0`

Remember, the project is designed to be extended with additional features and capabilities. When proposing enhancements, ensure they align with the project goals while maintaining the existing architecture. Always use the established naming conventions and avoid using "meta" terminology in favor of "forge". 