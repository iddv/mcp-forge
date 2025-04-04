"""
MCP Server Templates

This module contains template files used to generate MCP servers.
"""

import os
from typing import Dict, Any, List

def get_base_template_path() -> str:
    """
    Get the path to the base server template.
    
    Returns:
        Path to the base server template.
    """
    return os.path.join(os.path.dirname(__file__), 'base_server.py')

def get_available_templates() -> List[Dict[str, Any]]:
    """
    Get a list of available server templates.
    
    Returns:
        List of dictionaries containing template information.
    """
    templates_dir = os.path.dirname(__file__)
    templates = []
    
    for filename in os.listdir(templates_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            templates.append({
                'name': filename.replace('.py', ''),
                'path': os.path.join(templates_dir, filename)
            })
            
    return templates 