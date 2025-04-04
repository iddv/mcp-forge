"""
Template System for MCP Servers

This package provides the template system for generating and managing MCP server
implementations based on customizable templates.
"""

from .template_manager import TemplateProcessor, TemplateValidator, get_template_manager
from .customization import TemplateCustomizer
from .handlers import get_handler_templates

__all__ = [
    "TemplateProcessor", 
    "TemplateValidator", 
    "get_template_manager",
    "TemplateCustomizer",
    "get_handler_templates"
] 