"""
Handler system for MCP-Forge server templates.

This module provides custom handlers that can be included in generated MCP servers.
"""

import os
import logging
from typing import Dict, Any, List, Callable, Optional

# Configure logging
logger = logging.getLogger("mcp_forge.handlers")

# Registry of available handlers
_handlers_registry = {}

def register_handler(name: str, create_func: Callable[[Dict[str, Any]], Any]) -> None:
    """
    Register a handler with the system.
    
    Args:
        name: The name of the handler
        create_func: Function to create a handler instance
    """
    _handlers_registry[name] = create_func
    logger.debug(f"Registered handler: {name}")

def get_handler_creator(name: str) -> Optional[Callable]:
    """
    Get a handler creator function by name.
    
    Args:
        name: The name of the handler
        
    Returns:
        Handler creator function or None if not found
    """
    return _handlers_registry.get(name)

def get_available_handlers() -> List[str]:
    """
    Get a list of available handlers.
    
    Returns:
        List of handler names
    """
    return list(_handlers_registry.keys())

def _register_builtin_handlers() -> None:
    """Register built-in handlers."""
    # File Reader handler
    def create_file_reader(config):
        """Create a file reader handler."""
        from .file_reader_handler import FileReaderHandler
        return FileReaderHandler(config)
    
    register_handler("file_reader", create_file_reader)
    
    # HTTP Request handler
    def create_http_request(config):
        """Create an HTTP request handler."""
        from .http_request_handler import HttpRequestHandler
        return HttpRequestHandler(config)
    
    register_handler("http_request", create_http_request)
    
    # Database handler
    def create_database(config):
        """Create a database handler."""
        from .database_handler import DatabaseHandler
        return DatabaseHandler(config)
    
    register_handler("database", create_database)
    
    # Claude AI handler
    def create_claude(config):
        """Create a Claude AI handler."""
        from .claude_handler import ClaudeHandler
        return ClaudeHandler(config)
    
    register_handler("claude", create_claude)
    
def _discover_custom_handlers() -> None:
    """Discover and register custom handlers from the handlers directory."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    for filename in os.listdir(current_dir):
        if filename.endswith("_handler.py") and filename != "__init__.py":
            module_name = filename[:-3]  # Remove .py
            handler_name = module_name.replace("_handler", "")
            
            try:
                module = __import__(f"template_system.handlers.{module_name}", fromlist=["create_handler"])
                if hasattr(module, "create_handler"):
                    register_handler(handler_name, module.create_handler)
            except ImportError as e:
                logger.warning(f"Could not import handler module {module_name}: {e}")
            except AttributeError as e:
                logger.warning(f"Handler module {module_name} does not have create_handler function: {e}")

# Initialize handlers
_register_builtin_handlers()
_discover_custom_handlers()

# Add capability-handler mapping
capability_handler_map = {
    "file_operations": "file_reader",
    "http_requests": "http_request",
    "database_access": "database",
    "claude": "claude",
}

def get_handlers_for_capabilities(capabilities: List[str]) -> List[str]:
    """
    Get required handlers for a set of capabilities.
    
    Args:
        capabilities: List of capability names
        
    Returns:
        List of handler names needed for the capabilities
    """
    required_handlers = []
    
    for capability in capabilities:
        if capability in capability_handler_map:
            handler = capability_handler_map[capability]
            if handler not in required_handlers:
                required_handlers.append(handler)
    
    return required_handlers

# Handler configuration templates for various types of handlers
handler_config_templates = {
    "file_reader": {
        "allowed_directories": [os.path.expanduser("~")],
        "max_file_size_mb": 10,
        "allow_writes": False
    },
    "http_request": {
        "allowed_domains": ["api.example.com", "data.example.org"],
        "timeout_seconds": 30,
        "max_response_size_mb": 5,
        "verify_ssl": True
    },
    "database": {
        "connection_string": "sqlite:///database.db",
        "pool_size": 5,
        "max_overflow": 10,
        "timeout_seconds": 30
    },
    "claude": {
        "api_key": "",  # Should be set from environment variable or secure config
        "model": "claude-3-opus-20240229",
        "max_tokens": 4096,
        "temperature": 0.7,
        "top_p": 0.9,
        "request_timeout": 120,
        "enable_streaming": True
    }
} 