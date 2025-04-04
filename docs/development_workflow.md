# MCP-Forge Development Workflow

This document outlines the recommended workflow for developing the MCP-Forge project to ensure consistency and proper tracking of progress.

## Standard Development Workflow

Follow these steps when implementing new features or fixing bugs:

1. **Select a task** from the project plan (`forge_mcp_server_plan.md`)
2. **Update the task status** to "In Progress" using the progress tracker:
   ```bash
   python3 progress_tracker.py update <PHASE> "<TASK>" "In Progress" --notes "Starting implementation"
   ```
3. **Implement the feature or fix** in the appropriate files
4. **Test your changes** thoroughly
5. **Update the task status** to "Completed" using the progress tracker:
   ```bash
   python3 progress_tracker.py update <PHASE> "<TASK>" "Completed" --notes "Implementation details"
   ```
6. **Review all changes** to ensure they're ready for commit:
   ```bash
   git status
   git diff
   ```
7. **Stage all changed files** including the progress tracker updates:
   ```bash
   git add <changed_files> forge_mcp_server_plan.md
   ```
8. **Commit all changes together**:
   ```bash
   git commit -m "Implement feature X - Complete Phase Y Task Z"
   ```
9. **Push the changes**:
   ```bash
   git commit -am "Implement feature X - Complete Phase Y Task Z"
   git push origin main
   ```

## Important Notes

### Order of Operations

- **ALWAYS update the progress tracker BEFORE committing changes**
  - This ensures that code changes and progress updates are committed together
  - Avoids multiple commits for the same logical change

### Configuration Manager

- When testing changes to the configuration manager, be aware of potential recursive loading issues
- Use the `--log-level` option instead of `--verbose` when running the server for more detailed logs:
  ```bash
  python3 forge_mcp_server.py --port 9000 --log-level DEBUG
  ```

### Commit Messages

Use descriptive commit messages that include:
- What was implemented
- Which phase/task was completed
- Any important implementation details

Example:
```
Implement Client API Management Commands - Complete Phase 6

- Added server management commands to client.py
- Enhanced API documentation with examples
- Improved error handling for client connections
- Completed all Phase 6 tasks
```

## Troubleshooting

### Progress Tracker Commit Issues

If you've already committed code changes but forgot to update the progress tracker:

1. Update the progress tracker:
   ```bash
   python3 progress_tracker.py update <PHASE> "<TASK>" "Completed" --notes "Implementation details"
   ```
   
2. Amend your previous commit:
   ```bash
   git add forge_mcp_server_plan.md
   git commit --amend --no-edit
   git push origin main --force
   ```
   
   Note: Only use `--force` if you haven't shared your changes with others yet.

### Configuration Backup Loop

If you encounter repeated configuration loading/backup messages in the logs:

1. Check for recursive calls in the configuration manager
2. Ensure configuration is only loaded once per module initialization
3. Consider adding a debounce mechanism to prevent frequent backups 