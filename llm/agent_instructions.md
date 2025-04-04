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

6. **Repository Maintenance**:
   - Always review `git status` before committing to identify untracked files
   - Follow the development workflow in `docs/development_workflow.md`
   - Update the .gitignore file when adding new types of generated files
   - Commit documentation alongside code changes
   - ALWAYS update progress tracker BEFORE committing code changes
   - Ensure all generated/runtime files are properly ignored

## Design Principles to Follow

1. **MCP Compliance**: All implementations should follow the MCP specification
2. **Modularity**: Maintain clean separation between components
3. **Error Handling**: Provide meaningful error messages and recovery mechanisms
4. **Scalability**: Design for potential large numbers of child servers
5. **Documentation**: Keep code well-documented for future developers
6. **Terminology**: Use "forge" instead of "meta" in all references
7. **Customizability**: Make sure all components support customization
8. **Repository Cleanliness**: Maintain a clean repository with appropriate .gitignore rules

## Project Structure Reference

```
mcp-forge/
├── forge_mcp_server.py       # Core forge server
├── server_manager.py         # Server instance management
├── config_manager.py         # Configuration management
├── template_system/          # Template system for generating servers
│   ├── template_manager.py   # Template loading and parsing
│   ├── customization.py      # Customization points
│   ├── handlers/             # Custom handler templates
│   └── templates/            # Server templates
├── client.py                 # Client for interacting with servers
├── servers/                  # Generated server scripts directory (gitignored)
├── docs/                     # Documentation directory
│   ├── api_specification.md  # API documentation
│   └── development_workflow.md # Development guidelines
├── progress_tracker.py       # Development progress tracking utility
└── forge_mcp_server_plan.md  # Implementation plan and tracker
```

## Repository Organization

### Files to Commit
- Source code (*.py)
- Documentation (docs/*.md)
- Schema templates (*.schema.json, *_example.json)
- Project configuration (.gitignore, README.md)
- Test files (tests/*)

### Files to Exclude (via .gitignore)
- Runtime configuration files (forge_config.json)
- Generated server files (servers/*)
- Log files (*.log)
- Backup files (config_backups/*)
- Progress data (progress_data.json)
- Python cache (__pycache__/, *.pyc)
- Virtual environment (venv/)

## Command Reference

- Start forge server: `python3 forge_mcp_server.py --port 9000`
- Create a simple server: `python3 client.py create name="my-server" description="Description" capabilities=["echo","time"]`
- Create a server with custom handlers: `python3 client.py create name="advanced-server" handlers=["file_reader","http_request"]`
- Configure server options: `python3 client.py create name="storage-server" options={"persistence":"sqlite","auth":"basic"}`
- List servers: `python3 client.py list --details`
- Get server info: `python3 client.py info <server-id>`
- Connect to a server: `python3 client.py --port <PORT> tools`
- Update progress: `python3 progress_tracker.py update <PHASE> "<TASK>" "<STATUS>" --notes "Notes"`

## Important Implementation Details

1. **Template System**: We've implemented a comprehensive template system in the `template_system/` directory that supports:
   - Template validation
   - Customization points
   - Custom handlers (file_reader, http_request, database)
   - Server options (persistence, authentication, logging)

2. **Current Status**:
   - Phase 1-6 are completed
   - Phase 7 (Logging and Monitoring) is the next phase to implement

3. **Development Workflow**:
   - Select a task from the active phase
   - Update its status to "In Progress"
   - Implement the feature
   - Update progress tracker to "Completed"
   - Review and stage all changes (code + tracker)
   - Commit with a descriptive message
   - Push to the repository

## Dependencies
- Python 3.7+
- MCP SDK: `mcp>=1.6.0`
- HTTP Client: `httpx>=0.28.0`
- Async I/O: `anyio>=4.0.0`
- Process Monitoring: `psutil>=5.9.0`

Remember, the project is designed to be extended with additional features and capabilities. When proposing enhancements, ensure they align with the project goals while maintaining the existing architecture. Always use the established naming conventions and avoid using "meta" terminology in favor of "forge". Keep the repository clean by following the gitignore rules and development workflow. 