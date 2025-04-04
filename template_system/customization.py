#!/usr/bin/env python
"""
MCP Server Template Customization

This module provides functionality for adding customization points to MCP server templates.
These allow for more flexible server configurations beyond the basic capabilities.
"""

import json
import os
from typing import Dict, Any, List, Optional, Set

from .handlers import get_handler_templates

class TemplateCustomizer:
    """
    Adds customization points to MCP server templates.
    """
    
    def __init__(self):
        """Initialize the template customizer."""
        self.handler_templates = get_handler_templates()
        
    def get_available_customizations(self) -> Dict[str, Dict[str, Any]]:
        """
        Get a dictionary of available customization options.
        
        Returns:
            Dictionary of customization categories and their options.
        """
        return {
            "handlers": self.handler_templates,
            "server_options": {
                "persistence": {
                    "name": "Persistence",
                    "description": "Enable data persistence for the server",
                    "options": ["memory", "file", "sqlite"]
                },
                "auth": {
                    "name": "Authentication",
                    "description": "Enable authentication for the server",
                    "options": ["none", "basic", "token"]
                },
                "logging": {
                    "name": "Logging",
                    "description": "Configure logging for the server",
                    "options": ["basic", "detailed", "debug"]
                }
            }
        }
        
    def apply_handler_customizations(self, template_content: str, handler_names: List[str]) -> str:
        """
        Apply handler customizations to a template.
        
        Args:
            template_content: Original template content.
            handler_names: List of handler names to add.
            
        Returns:
            Customized template content.
        """
        if not handler_names:
            return template_content
            
        # Collect handler imports
        imports = []
        handler_functions = []
        
        for handler_name in handler_names:
            if handler_name in self.handler_templates:
                handler = self.handler_templates[handler_name]
                
                # Add imports if any
                if "imports" in handler:
                    imports.extend(handler["imports"])
                    
                # Add handler function
                handler_functions.append(handler["function_template"])
                
        # Add imports to the template
        if imports:
            # Find the import section in the template
            import_section_end = template_content.find("from mcp.server.fastmcp import FastMCP")
            if import_section_end != -1:
                # Find the end of the line
                import_section_end = template_content.find("\n", import_section_end) + 1
                
                # Add our imports
                import_text = "\n".join(imports) + "\n"
                template_content = (
                    template_content[:import_section_end] + 
                    import_text + 
                    template_content[import_section_end:]
                )
                
        # Add handler functions to the template
        if handler_functions:
            # Find the right location to insert handlers
            handler_section = "# Additional handlers will be dynamically added based on SERVER_HANDLERS"
            handler_section_pos = template_content.find(handler_section)
            
            if handler_section_pos != -1:
                handler_text = "\n\n" + "\n\n".join(handler_functions) + "\n"
                template_content = (
                    template_content[:handler_section_pos] + 
                    handler_section + 
                    handler_text + 
                    template_content[handler_section_pos + len(handler_section):]
                )
                
        return template_content
    
    def apply_server_options(self, template_content: str, options: Dict[str, Any]) -> str:
        """
        Apply server options customizations to a template.
        
        Args:
            template_content: Original template content.
            options: Dictionary of server options.
            
        Returns:
            Customized template content.
        """
        if not options:
            return template_content
            
        # Add server options as template variables
        options_text = f"\n# Server options (customized)\nSERVER_OPTIONS = {json.dumps(options, indent=4)}\n"
        
        # Find a good spot to insert the options
        insert_pos = template_content.find("# Setup logging")
        if insert_pos != -1:
            template_content = (
                template_content[:insert_pos] + 
                options_text + 
                "\n" + 
                template_content[insert_pos:]
            )
            
        # Modify the template based on specific options
        if options.get("persistence") in ("file", "sqlite"):
            # Add persistence imports
            if options["persistence"] == "sqlite":
                import_text = "import sqlite3\n"
                template_content = template_content.replace("import os", f"import os\n{import_text}")
                
            # Add persistence setup to main function
            persistence_code = """
    # Initialize persistence
    if SERVER_OPTIONS.get('persistence') == 'file':
        os.makedirs('data', exist_ok=True)
    elif SERVER_OPTIONS.get('persistence') == 'sqlite':
        conn = sqlite3.connect('server_data.db')
        conn.execute('CREATE TABLE IF NOT EXISTS server_data (key TEXT PRIMARY KEY, value TEXT)')
        conn.commit()
        conn.close()
        
"""
            main_start = template_content.find("def main():")
            if main_start != -1:
                # Find where to insert our code
                start_time_line = template_content.find("start_time = datetime.now()", main_start)
                if start_time_line != -1:
                    template_content = (
                        template_content[:start_time_line] + 
                        persistence_code + 
                        template_content[start_time_line:]
                    )
                    
        # Add authentication if needed
        if options.get("auth") in ("basic", "token"):
            # Add auth handler
            auth_handler = """
@mcp_server.tool()
def handle_auth(username: str, password: str = None, token: str = None) -> Dict[str, Any]:
    \"\"\"
    Authenticate with the server.
    
    Args:
        username: User to authenticate as.
        password: Password for basic auth.
        token: Token for token auth.
        
    Returns:
        Authentication status.
    \"\"\"
    auth_type = SERVER_OPTIONS.get('auth', 'none')
    
    if auth_type == 'basic':
        # Simple demo implementation - in production use secure password storage
        if username == 'admin' and password == 'password':
            return {"status": "success", "message": "Authenticated successfully"}
        else:
            return {"status": "error", "error": "Invalid credentials"}
    elif auth_type == 'token':
        # Simple demo implementation - in production use secure token verification
        if token == 'secret-token':
            return {"status": "success", "message": "Authenticated successfully"}
        else:
            return {"status": "error", "error": "Invalid token"}
    else:
        return {"status": "success", "message": "Authentication not required"}
"""
            handler_section = "# Additional handlers will be dynamically added based on SERVER_HANDLERS"
            handler_section_pos = template_content.find(handler_section)
            
            if handler_section_pos != -1:
                template_content = (
                    template_content[:handler_section_pos] + 
                    handler_section + 
                    "\n\n" + auth_handler + 
                    template_content[handler_section_pos + len(handler_section):]
                )
                
        return template_content
        
    def customize_template(self, template_content: str, 
                          handlers: Optional[List[str]] = None, 
                          options: Optional[Dict[str, Any]] = None) -> str:
        """
        Apply all customizations to a template.
        
        Args:
            template_content: Original template content.
            handlers: List of handler names to add.
            options: Dictionary of server options.
            
        Returns:
            Fully customized template content.
        """
        result = template_content
        
        if handlers:
            result = self.apply_handler_customizations(result, handlers)
            
        if options:
            result = self.apply_server_options(result, options)
            
        return result 