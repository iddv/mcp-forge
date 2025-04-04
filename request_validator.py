"""
Request Validator for MCP-Forge

This module provides validation functions for securing API endpoints and request handling.
It implements various security checks and validations to protect against common
web vulnerabilities and attacks.
"""

import re
import ipaddress
import logging
import time
from typing import Dict, Any, List, Optional, Tuple, Callable, Union
from functools import wraps

# Configure logging
logger = logging.getLogger("mcp_forge.validator")

# Common validation patterns
PATTERNS = {
    "username": r"^[a-zA-Z0-9_-]{3,50}$",
    "server_id": r"^[a-zA-Z0-9_-]{3,50}$",
    "api_key_id": r"^[a-zA-Z0-9-]{36}$",  # UUID format
    "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    "uri": r"^[a-zA-Z0-9_\-\.\/\:]+$",
    "ip_address": r"^(\d{1,3}\.){3}\d{1,3}$",
    "port": r"^\d+$"
}

# Request rate limiting
class RateLimiter:
    """Rate limiter implementation to prevent abuse."""
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.request_history: Dict[str, List[float]] = {}
        self.cleanup_interval = 5 * 60  # Clean up old entries every 5 minutes
        self.last_cleanup = time.time()
    
    def is_allowed(self, client_id: str) -> bool:
        """
        Check if the client is allowed to make another request.
        
        Args:
            client_id: A unique identifier for the client (IP address, API key, etc.)
            
        Returns:
            True if the request is allowed, False otherwise
        """
        current_time = time.time()
        
        # Clean up old entries periodically
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        # Initialize history for new clients
        if client_id not in self.request_history:
            self.request_history[client_id] = []
        
        # Remove requests older than 1 minute
        one_minute_ago = current_time - 60
        self.request_history[client_id] = [
            timestamp for timestamp in self.request_history[client_id]
            if timestamp > one_minute_ago
        ]
        
        # Check if rate limit is exceeded
        if len(self.request_history[client_id]) >= self.requests_per_minute:
            logger.warning(f"Rate limit exceeded for client {client_id}")
            return False
        
        # Record this request
        self.request_history[client_id].append(current_time)
        return True
    
    def _cleanup_old_entries(self, current_time: float) -> None:
        """Remove entries older than 1 minute to prevent memory growth."""
        one_minute_ago = current_time - 60
        for client_id in list(self.request_history.keys()):
            # Remove old timestamps
            self.request_history[client_id] = [
                timestamp for timestamp in self.request_history[client_id]
                if timestamp > one_minute_ago
            ]
            
            # Remove clients with no recent activity
            if not self.request_history[client_id]:
                del self.request_history[client_id]

# Create a global rate limiter
rate_limiter = RateLimiter()

def validate_input(value: str, pattern_name: str) -> bool:
    """
    Validate input against a predefined pattern.
    
    Args:
        value: The input value to validate
        pattern_name: The name of the pattern to use
        
    Returns:
        True if the input is valid, False otherwise
    """
    if pattern_name not in PATTERNS:
        logger.error(f"Unknown pattern: {pattern_name}")
        return False
    
    pattern = PATTERNS[pattern_name]
    return bool(re.match(pattern, value))

def validate_ip_address(ip: str) -> bool:
    """
    Validate an IP address.
    
    Args:
        ip: The IP address to validate
        
    Returns:
        True if the IP address is valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port(port: int) -> bool:
    """
    Validate a port number.
    
    Args:
        port: The port number to validate
        
    Returns:
        True if the port is valid, False otherwise
    """
    return 1 <= port <= 65535

def sanitize_input(input_str: str) -> str:
    """
    Sanitize input to prevent injection attacks.
    
    Args:
        input_str: The input string to sanitize
        
    Returns:
        Sanitized input string
    """
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[;<>{}$()&|]', '', input_str)
    
    # Remove potential JavaScript/HTML
    sanitized = re.sub(r'<script.*?>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'on\w+\s*=', '', sanitized, flags=re.IGNORECASE)
    
    return sanitized

class RequestValidator:
    """Validator for API requests."""
    
    def __init__(self):
        self.rate_limiter = rate_limiter
    
    def validate_request(self, request: Any) -> Tuple[bool, Optional[str]]:
        """
        Validate a request.
        
        Args:
            request: The request to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # Check rate limiting
        if not self.rate_limiter.is_allowed(client_ip):
            return False, "Rate limit exceeded. Please try again later."
        
        # Basic request validation
        if hasattr(request, 'method') and request.method not in ['GET', 'POST', 'PUT', 'DELETE']:
            return False, "Invalid HTTP method"
        
        # Validate content type if it's a POST/PUT request
        if hasattr(request, 'method') and request.method in ['POST', 'PUT']:
            content_type = request.headers.get('Content-Type', '')
            if 'application/json' not in content_type:
                return False, "Invalid Content-Type, expected application/json"
        
        return True, None
    
    def _get_client_ip(self, request: Any) -> str:
        """Extract client IP from request."""
        if hasattr(request, 'headers'):
            # Try common proxy headers first
            for header in ['X-Forwarded-For', 'X-Real-IP']:
                if header in request.headers:
                    # Get the first IP in the list
                    ip = request.headers[header].split(',')[0].strip()
                    if validate_ip_address(ip):
                        return ip
        
        # Fallback to direct client IP
        if hasattr(request, 'client'):
            if hasattr(request.client, 'host'):
                return request.client.host
        
        # Default fallback
        return "unknown"

def validate_server_id(server_id: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a server ID.
    
    Args:
        server_id: The server ID to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not server_id:
        return False, "Server ID is required"
    
    if not validate_input(server_id, "server_id"):
        return False, "Invalid server ID format"
    
    return True, None

def validate_username(username: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a username.
    
    Args:
        username: The username to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"
    
    if not validate_input(username, "username"):
        return False, "Invalid username format (3-50 alphanumeric characters, underscore, and hyphen only)"
    
    return True, None

def validate_password(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a password.
    
    Args:
        password: The password to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    # Check complexity requirements
    has_uppercase = any(c.isupper() for c in password)
    has_lowercase = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if not (has_uppercase and has_lowercase and has_digit and has_special):
        return False, "Password must contain uppercase, lowercase, digit, and special characters"
    
    return True, None

def validate_email(email: str) -> Tuple[bool, Optional[str]]:
    """
    Validate an email address.
    
    Args:
        email: The email to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email:
        return False, "Email is required"
    
    if not validate_input(email, "email"):
        return False, "Invalid email format"
    
    return True, None

def validate_api_key_id(key_id: str) -> Tuple[bool, Optional[str]]:
    """
    Validate an API key ID.
    
    Args:
        key_id: The API key ID to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not key_id:
        return False, "API key ID is required"
    
    if not validate_input(key_id, "api_key_id"):
        return False, "Invalid API key ID format"
    
    return True, None

def validate_role(role: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a role.
    
    Args:
        role: The role to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not role:
        return False, "Role is required"
    
    valid_roles = ["admin", "operator", "developer", "viewer", "custom"]
    if role not in valid_roles:
        return False, f"Invalid role. Must be one of: {', '.join(valid_roles)}"
    
    return True, None

def validate_permission(permission: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a permission.
    
    Args:
        permission: The permission to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not permission:
        return False, "Permission is required"
    
    valid_permissions = [
        "server:create", "server:delete", "server:modify", "server:view",
        "server:start", "server:stop", "server:restart",
        "config:view", "config:modify",
        "logs:view", "metrics:view",
        "alerts:view", "alerts:modify",
        "admin"
    ]
    
    if permission not in valid_permissions:
        return False, f"Invalid permission. Must be one of: {', '.join(valid_permissions)}"
    
    return True, None

# Create a global request validator
request_validator = RequestValidator()

def require_valid_request(func: Callable) -> Callable:
    """
    Decorator to validate requests.
    
    Args:
        func: The function to decorate
        
    Returns:
        Decorated function
    """
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        # Validate the request
        is_valid, error_message = request_validator.validate_request(request)
        if not is_valid:
            return {
                "status": "error",
                "code": 400,
                "error": error_message
            }
        
        # Call the original function
        return func(request, *args, **kwargs)
    
    return wrapper 