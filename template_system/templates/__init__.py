"""
MCP server templates for MCP-Forge.

This package contains templates for generating different types of MCP servers.
"""

import os
import logging
from typing import Dict, Any, List, Optional

# Configure logging
logger = logging.getLogger("mcp_forge.templates")

def get_base_template() -> str:
    """
    Get the contents of the base server template.
    
    Returns:
        The contents of the base server template as a string.
    """
    base_template_path = os.path.join(os.path.dirname(__file__), "base_server.py")
    with open(base_template_path, "r") as f:
        return f.read()

def get_claude_template() -> str:
    """
    Get the contents of the Claude-enabled server template.
    
    Returns:
        The contents of the Claude server template as a string.
    """
    claude_template_path = os.path.join(os.path.dirname(__file__), "claude_server.py")
    with open(claude_template_path, "r") as f:
        return f.read()

def get_template(template_type: str) -> Optional[str]:
    """
    Get a template by type.
    
    Args:
        template_type: The type of template to get
        
    Returns:
        The template contents as a string, or None if not found
    """
    if template_type == "base":
        return get_base_template()
    elif template_type == "claude":
        return get_claude_template()
    else:
        logger.warning(f"Unknown template type: {template_type}")
        return None

def get_available_templates() -> List[str]:
    """
    Get a list of available template types.
    
    Returns:
        List of template type names
    """
    return ["base", "claude"]

def get_template_for_capabilities(capabilities: List[str]) -> str:
    """
    Get the most appropriate template for the given capabilities.
    
    Args:
        capabilities: List of capability names
        
    Returns:
        The template type to use
    """
    if "claude" in capabilities:
        return "claude"
    else:
        return "base"

# Default template variables
default_template_variables = {
    "base": {
        "server_name": "MCP Server",
        "server_description": "A customizable MCP server",
        "additional_tools": ""
    },
    "claude": {
        "server_name": "Claude MCP Server",
        "server_description": "An MCP server with Claude AI capabilities",
        "claude_api_key": "",
        "claude_model": "claude-3-opus-20240229",
        "claude_max_tokens": 4096,
        "claude_temperature": 0.7,
        "claude_top_p": 0.9,
        "claude_request_timeout": 120,
        "claude_enable_streaming": True,
        "additional_tools": ""
    }
} 