# Agent Instructions: Meta-MCP Server Framework

## Project Overview
This project is a Meta-MCP Server Framework that dynamically generates, manages, and monitors Model Context Protocol (MCP) servers. The framework uses the official MCP SDK to create a system where specialized MCP servers can be spawned on demand through a centralized interface.

## Your Task
Continue developing the Meta-MCP Server Framework according to the implementation plan. The progress tracker (`llm/meta_mcp_server_plan.md`) contains the current status of all tasks, so check that first to understand what has been completed and what needs work next.

## How to Approach the Project

1. **Understand the Architecture**:
   - Review the code in `llm/meta_mcp_server.py`, `llm/template_server.py`, and `llm/client.py`
   - Understand the relationship between the meta server and child servers
   - Familiarize yourself with the official MCP SDK and its capabilities

2. **Check Current Progress**:
   - Run `python3 llm/progress_tracker.py stats` to see overall progress
   - Run `python3 llm/progress_tracker.py report` to get detailed status

3. **Continue Implementation**:
   - Find tasks marked "Not Started" or "In Progress" in the phase that's currently active
   - Implement those features according to the project architecture
   - Update progress using `python3 llm/progress_tracker.py update PHASE TASK STATUS --notes "Your notes"`

4. **Testing**:
   - Start the meta server with `python3 llm/meta_mcp_server.py --port 9000`
   - Create and interact with child servers using the client: `python3 llm/client.py`
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

## Project Structure Reference

```
llm/
├── meta_mcp_server.py       # Core meta server
├── template_server.py       # Template for generated servers
├── client.py                # Client application
├── progress_tracker.py      # Progress tracking utility
├── meta_mcp_server_plan.md  # Implementation plan and tracker
├── servers/                 # Directory where generated servers are stored
│   └── mcp_*_*.py           # Generated server scripts
└── README.md                # Documentation
```

## Command Reference

- Start meta server: `python3 llm/meta_mcp_server.py --port 9000`
- Create a server: `python3 llm/client.py call create_server name="my-server" description="Description" capabilities="echo,time"`
- List servers: `python3 llm/client.py meta`
- Connect to a server: `python3 llm/client.py --port <PORT> tools`
- Update progress: `python3 llm/progress_tracker.py update <PHASE> "<TASK>" "<STATUS>" --notes "Notes"`

## Dependencies
- Python 3.7+
- MCP SDK: `mcp>=1.6.0`

Remember, the project is designed to be extended with additional features and capabilities. Feel free to propose enhancements that align with the project goals while maintaining the existing architecture. 