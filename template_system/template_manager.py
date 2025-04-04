#!/usr/bin/env python
"""
MCP Server Template Manager

This module provides functionality for managing MCP server templates.
It includes loading, validation, and generation of customized MCP servers
based on template files and configured capabilities.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

logger = logging.getLogger('template_manager')

class TemplateValidator:
    """
    Validates template files and configurations to ensure they will
    produce valid MCP servers.
    """
    
    REQUIRED_PLACEHOLDERS = {
        "{{SERVER_NAME}}",
        "{{SERVER_DESCRIPTION}}",
        "{{SERVER_PORT}}",
        "{{SERVER_CAPABILITIES}}",
        "{{SERVER_HANDLERS}}"
    }
    
    @staticmethod
    def validate_template_file(template_path: str) -> Tuple[bool, Optional[str]]:
        """
        Validate that a template file contains all required placeholders
        and has valid syntax.
        
        Args:
            template_path: Path to the template file.
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not os.path.exists(template_path):
            return False, f"Template file not found: {template_path}"
            
        try:
            with open(template_path, 'r') as f:
                content = f.read()
                
            # Check for required placeholders
            missing_placeholders = []
            for placeholder in TemplateValidator.REQUIRED_PLACEHOLDERS:
                if placeholder not in content:
                    missing_placeholders.append(placeholder)
                    
            if missing_placeholders:
                return False, f"Missing required placeholders: {', '.join(missing_placeholders)}"
                
            # Check for valid Python syntax (rough check)
            try:
                import ast
                ast.parse(content)
            except SyntaxError as e:
                return False, f"Template contains invalid Python syntax: {str(e)}"
                
            return True, None
        except Exception as e:
            return False, f"Error validating template: {str(e)}"
    
    @staticmethod
    def validate_capabilities(capabilities: List[str]) -> Tuple[bool, Optional[str]]:
        """
        Validate a list of capabilities to ensure they are properly formatted
        and contain allowed values.
        
        Args:
            capabilities: List of capability names.
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not capabilities:
            return False, "No capabilities specified"
            
        for capability in capabilities:
            if not re.match(r'^[a-zA-Z0-9_]+$', capability):
                return False, f"Invalid capability name: {capability} (must contain only letters, numbers, and underscores)"
                
        return True, None

class TemplateProcessor:
    """
    Processes template files to generate customized MCP server scripts.
    """
    
    def __init__(self, base_template_path: str):
        """
        Initialize the template processor.
        
        Args:
            base_template_path: Path to the base template file.
        """
        self.base_template_path = base_template_path
        
        # Validate the base template
        is_valid, error = TemplateValidator.validate_template_file(base_template_path)
        if not is_valid:
            raise ValueError(f"Invalid base template: {error}")
            
        # Load the base template
        with open(base_template_path, 'r') as f:
            self.base_template = f.read()
    
    def generate_server(self, 
                        output_path: str,
                        server_name: str,
                        server_port: int,
                        description: str = "MCP Server",
                        capabilities: Optional[List[str]] = None,
                        custom_placeholders: Optional[Dict[str, str]] = None) -> str:
        """
        Generate a customized MCP server script based on the template.
        
        Args:
            output_path: Path where the generated script will be saved.
            server_name: Name of the server.
            server_port: Port the server will listen on.
            description: Description of the server.
            capabilities: List of capabilities the server will support.
            custom_placeholders: Additional custom placeholders to replace.
            
        Returns:
            Path to the generated script.
        """
        # Default capabilities
        if capabilities is None:
            capabilities = ["echo", "time", "uptime"]
            
        # Validate capabilities
        is_valid, error = TemplateValidator.validate_capabilities(capabilities)
        if not is_valid:
            raise ValueError(f"Invalid capabilities: {error}")
            
        # Create handlers dict (mapping capability to handler function)
        handlers = {}
        for capability in capabilities:
            # Map standard capabilities to their handlers
            if capability == "echo":
                handlers["echo"] = "handle_echo"
            elif capability == "time":
                handlers["time"] = "handle_time"
            elif capability == "uptime":
                handlers["uptime"] = "handle_uptime"
            else:
                # For custom capabilities, we'll use a standard handler name pattern
                handlers[capability] = f"handle_{capability}"
                
        # Start with the base template
        server_content = self.base_template
        
        # Replace standard placeholders
        server_content = server_content.replace("{{SERVER_NAME}}", server_name)
        server_content = server_content.replace("{{SERVER_PORT}}", str(server_port))
        server_content = server_content.replace("{{SERVER_DESCRIPTION}}", description)
        server_content = server_content.replace("{{SERVER_CAPABILITIES}}", json.dumps(capabilities))
        server_content = server_content.replace("{{SERVER_HANDLERS}}", json.dumps(handlers))
        
        # Replace any custom placeholders
        if custom_placeholders:
            for placeholder, value in custom_placeholders.items():
                server_content = server_content.replace(f"{{{{{placeholder}}}}}", value)
                
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Write the generated script
        with open(output_path, 'w') as f:
            f.write(server_content)
            
        return output_path
    
    def list_available_templates(self, templates_dir: str) -> List[Dict[str, Any]]:
        """
        List all available templates in the specified directory.
        
        Args:
            templates_dir: Directory containing template files.
            
        Returns:
            List of template information dictionaries.
        """
        templates = []
        
        if not os.path.exists(templates_dir):
            return templates
            
        for filename in os.listdir(templates_dir):
            if filename.endswith('.py') or filename.endswith('.template'):
                template_path = os.path.join(templates_dir, filename)
                
                try:
                    # Extract template metadata
                    with open(template_path, 'r') as f:
                        content = f.read(2048)  # Read just the first part
                        
                    # Extract template name and description using regex
                    name_match = re.search(r'Template Name:\s*([^\n]+)', content)
                    desc_match = re.search(r'Description:\s*([^\n]+)', content)
                    capabilities_match = re.search(r'Supported Capabilities:\s*([^\n]+)', content)
                    
                    templates.append({
                        'filename': filename,
                        'path': template_path,
                        'name': name_match.group(1).strip() if name_match else filename,
                        'description': desc_match.group(1).strip() if desc_match else "No description",
                        'capabilities': capabilities_match.group(1).strip().split(',') if capabilities_match else []
                    })
                except Exception as e:
                    logger.warning(f"Error processing template {filename}: {e}")
        
        return templates

# Singleton instance for application use
_template_manager = None

def get_template_manager(base_template_path: str) -> TemplateProcessor:
    """
    Get or create the singleton template manager instance.
    
    Args:
        base_template_path: Path to the base template file.
        
    Returns:
        The template manager instance.
    """
    global _template_manager
    
    if _template_manager is None:
        _template_manager = TemplateProcessor(base_template_path)
        
    return _template_manager 