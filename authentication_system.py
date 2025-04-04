"""
Authentication System for MCP-Forge

This module provides authentication capabilities for the MCP-Forge framework,
including user management, authentication methods, and access control.
"""

import json
import os
import time
import uuid
import hashlib
import hmac
import base64
import logging
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from enum import Enum
import secrets
import datetime

# Configure logging
logger = logging.getLogger("mcp_forge.auth")

class AuthMethod(Enum):
    """Authentication methods supported by the system."""
    API_KEY = "api_key"
    BASIC = "basic"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    NONE = "none"

class Permission(Enum):
    """Permission types for access control."""
    SERVER_CREATE = "server:create"
    SERVER_DELETE = "server:delete"
    SERVER_MODIFY = "server:modify"
    SERVER_VIEW = "server:view"
    SERVER_START = "server:start"
    SERVER_STOP = "server:stop"
    SERVER_RESTART = "server:restart"
    
    CONFIG_VIEW = "config:view"
    CONFIG_MODIFY = "config:modify"
    
    LOGS_VIEW = "logs:view"
    METRICS_VIEW = "metrics:view"
    
    ALERTS_VIEW = "alerts:view"
    ALERTS_MODIFY = "alerts:modify"
    
    ADMIN = "admin"  # Special permission that grants all access

class Role(Enum):
    """Predefined roles with associated permissions."""
    ADMIN = "admin"
    OPERATOR = "operator"
    DEVELOPER = "developer"
    VIEWER = "viewer"
    CUSTOM = "custom"  # For custom permission sets

class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass

class AuthorizationError(Exception):
    """Raised when a user does not have permission for an action."""
    pass

class User:
    """Represents a user in the authentication system."""
    
    def __init__(
        self,
        username: str,
        password_hash: Optional[str] = None,
        role: Role = Role.VIEWER,
        permissions: Optional[List[Permission]] = None,
        api_keys: Optional[List[Dict[str, str]]] = None,
        enabled: bool = True,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.id = str(uuid.uuid4())
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.permissions = permissions or []
        self.api_keys = api_keys or []
        self.enabled = enabled
        self.created_at = datetime.datetime.now().isoformat()
        self.last_login = None
        self.metadata = metadata or {}
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert user object to dictionary representation."""
        result = {
            "id": self.id,
            "username": self.username,
            "role": self.role.value,
            "permissions": [perm.value for perm in self.permissions],
            "enabled": self.enabled,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "metadata": self.metadata
        }
        
        if include_sensitive:
            result["password_hash"] = self.password_hash
            result["api_keys"] = self.api_keys
            
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create user object from dictionary representation."""
        user = cls(
            username=data["username"],
            password_hash=data.get("password_hash"),
            role=Role(data.get("role", "viewer")),
            permissions=[Permission(p) for p in data.get("permissions", [])],
            api_keys=data.get("api_keys", []),
            enabled=data.get("enabled", True),
            metadata=data.get("metadata", {})
        )
        user.id = data.get("id", str(uuid.uuid4()))
        user.created_at = data.get("created_at", datetime.datetime.now().isoformat())
        user.last_login = data.get("last_login")
        return user

class AuthenticationSystem:
    """Main authentication system for MCP-Forge."""
    
    def __init__(self, config_path: str = "auth_config.json"):
        self.config_path = config_path
        self.users: Dict[str, User] = {}
        self.role_permissions: Dict[Role, List[Permission]] = self._init_role_permissions()
        self.tokens: Dict[str, Dict[str, Any]] = {}
        self.token_expiration = 3600  # Default token expiration in seconds
        self.load_config()
        
        logger.info("Authentication system initialized")
    
    def _init_role_permissions(self) -> Dict[Role, List[Permission]]:
        """Initialize default permissions for predefined roles."""
        return {
            Role.ADMIN: list(Permission),  # All permissions
            Role.OPERATOR: [
                Permission.SERVER_VIEW, Permission.SERVER_START, 
                Permission.SERVER_STOP, Permission.SERVER_RESTART,
                Permission.LOGS_VIEW, Permission.METRICS_VIEW, 
                Permission.ALERTS_VIEW, Permission.ALERTS_MODIFY
            ],
            Role.DEVELOPER: [
                Permission.SERVER_VIEW, Permission.SERVER_CREATE,
                Permission.SERVER_MODIFY, Permission.LOGS_VIEW,
                Permission.METRICS_VIEW
            ],
            Role.VIEWER: [
                Permission.SERVER_VIEW, Permission.LOGS_VIEW,
                Permission.METRICS_VIEW, Permission.ALERTS_VIEW
            ],
            Role.CUSTOM: []  # Custom roles defined per user
        }
    
    def load_config(self) -> None:
        """Load authentication configuration from file."""
        if not os.path.exists(self.config_path):
            logger.warning(f"Authentication config not found at {self.config_path}, creating default")
            self._create_default_config()
            return
        
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                
            # Load users
            self.users = {
                user_data["username"]: User.from_dict(user_data)
                for user_data in config.get("users", [])
            }
            
            # Load token settings
            self.token_expiration = config.get("token_expiration", 3600)
            
            logger.info(f"Loaded {len(self.users)} users from config")
        except Exception as e:
            logger.error(f"Error loading authentication config: {str(e)}")
            self._create_default_config()
    
    def _create_default_config(self) -> None:
        """Create default authentication configuration."""
        # Create admin user with a random password
        admin_password = secrets.token_urlsafe(12)
        admin_hash = self._hash_password(admin_password)
        
        admin_user = User(
            username="admin",
            password_hash=admin_hash,
            role=Role.ADMIN,
            permissions=list(Permission)
        )
        
        self.users = {"admin": admin_user}
        
        config = {
            "users": [admin_user.to_dict(include_sensitive=True)],
            "token_expiration": self.token_expiration
        }
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(self.config_path)), exist_ok=True)
            
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"Created default authentication config with admin user (password: {admin_password})")
            print(f"Created default admin user with password: {admin_password}")
            print(f"Please change this password immediately using the 'update_user' API")
        except Exception as e:
            logger.error(f"Error creating default authentication config: {str(e)}")
    
    def save_config(self) -> None:
        """Save authentication configuration to file."""
        config = {
            "users": [user.to_dict(include_sensitive=True) for user in self.users.values()],
            "token_expiration": self.token_expiration
        }
        
        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info("Authentication configuration saved")
        except Exception as e:
            logger.error(f"Error saving authentication config: {str(e)}")
    
    def _hash_password(self, password: str) -> str:
        """Hash a password using a secure algorithm."""
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return base64.b64encode(salt + key).decode('utf-8')
    
    def _verify_password(self, stored_hash: str, provided_password: str) -> bool:
        """Verify a password against its stored hash."""
        try:
            decoded = base64.b64decode(stored_hash.encode('utf-8'))
            salt, key = decoded[:32], decoded[32:]
            new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
            return hmac.compare_digest(key, new_key)
        except Exception as e:
            logger.error(f"Password verification error: {str(e)}")
            return False
    
    def create_user(
        self,
        username: str,
        password: str,
        role: Role = Role.VIEWER,
        permissions: Optional[List[Permission]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> User:
        """Create a new user."""
        if username in self.users:
            raise ValueError(f"User {username} already exists")
        
        password_hash = self._hash_password(password)
        
        # Use role-based permissions if not explicitly provided
        if permissions is None:
            permissions = self.role_permissions.get(role, [])
        
        user = User(
            username=username,
            password_hash=password_hash,
            role=role,
            permissions=permissions,
            metadata=metadata
        )
        
        self.users[username] = user
        self.save_config()
        logger.info(f"Created new user: {username} with role {role.value}")
        
        return user
    
    def update_user(
        self,
        username: str,
        password: Optional[str] = None,
        role: Optional[Role] = None,
        permissions: Optional[List[Permission]] = None,
        enabled: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> User:
        """Update an existing user."""
        if username not in self.users:
            raise ValueError(f"User {username} does not exist")
        
        user = self.users[username]
        
        if password is not None:
            user.password_hash = self._hash_password(password)
        
        if role is not None:
            user.role = role
            # Update permissions based on role if explicit permissions not provided
            if permissions is None:
                user.permissions = self.role_permissions.get(role, user.permissions)
        
        if permissions is not None:
            user.permissions = permissions
        
        if enabled is not None:
            user.enabled = enabled
        
        if metadata is not None:
            user.metadata.update(metadata)
        
        self.save_config()
        logger.info(f"Updated user: {username}")
        
        return user
    
    def delete_user(self, username: str) -> bool:
        """Delete a user."""
        if username not in self.users:
            raise ValueError(f"User {username} does not exist")
        
        # Don't allow deleting the last admin
        if self.users[username].role == Role.ADMIN:
            admin_count = sum(1 for user in self.users.values() if user.role == Role.ADMIN)
            if admin_count <= 1:
                raise ValueError("Cannot delete the last admin user")
        
        del self.users[username]
        self.save_config()
        logger.info(f"Deleted user: {username}")
        
        return True
    
    def get_user(self, username: str) -> Optional[User]:
        """Get a user by username."""
        return self.users.get(username)
    
    def list_users(self) -> List[Dict[str, Any]]:
        """List all users without sensitive information."""
        return [user.to_dict(include_sensitive=False) for user in self.users.values()]
    
    def authenticate_basic(self, username: str, password: str) -> Optional[str]:
        """Authenticate a user with username and password, returning a token."""
        user = self.get_user(username)
        
        if not user or not user.enabled:
            logger.warning(f"Authentication failed: User {username} not found or disabled")
            return None
        
        if not user.password_hash or not self._verify_password(user.password_hash, password):
            logger.warning(f"Authentication failed: Invalid password for user {username}")
            return None
        
        # Create a token
        token = secrets.token_urlsafe(32)
        expiration = time.time() + self.token_expiration
        
        self.tokens[token] = {
            "username": username,
            "expiration": expiration,
            "created_at": time.time()
        }
        
        # Update last login
        user.last_login = datetime.datetime.now().isoformat()
        self.save_config()
        
        logger.info(f"User {username} authenticated successfully")
        return token
    
    def authenticate_api_key(self, api_key: str) -> Optional[str]:
        """Authenticate using an API key, returning a session token."""
        for username, user in self.users.items():
            if not user.enabled:
                continue
                
            for key_info in user.api_keys:
                if key_info.get("key") == api_key and key_info.get("enabled", True):
                    if key_info.get("expires_at") and time.time() > key_info.get("expires_at"):
                        continue  # Skip expired keys
                    
                    # Create a token
                    token = secrets.token_urlsafe(32)
                    expiration = time.time() + self.token_expiration
                    
                    self.tokens[token] = {
                        "username": username,
                        "expiration": expiration,
                        "created_at": time.time(),
                        "api_key_id": key_info.get("id")
                    }
                    
                    # Update last login
                    user.last_login = datetime.datetime.now().isoformat()
                    self.save_config()
                    
                    logger.info(f"User {username} authenticated via API key")
                    return token
        
        logger.warning("Authentication failed: Invalid API key")
        return None
    
    def validate_token(self, token: str) -> Optional[str]:
        """Validate a token and return the associated username if valid."""
        if token not in self.tokens:
            return None
        
        token_data = self.tokens[token]
        
        # Check expiration
        if token_data["expiration"] < time.time():
            # Remove expired token
            del self.tokens[token]
            return None
        
        # Check if user is still valid
        username = token_data["username"]
        user = self.get_user(username)
        
        if not user or not user.enabled:
            # Remove token for disabled/deleted user
            del self.tokens[token]
            return None
        
        return username
    
    def invalidate_token(self, token: str) -> bool:
        """Invalidate a token (logout)."""
        if token in self.tokens:
            del self.tokens[token]
            return True
        return False
    
    def invalidate_all_user_tokens(self, username: str) -> int:
        """Invalidate all tokens for a specific user."""
        count = 0
        tokens_to_remove = []
        
        for token, data in self.tokens.items():
            if data["username"] == username:
                tokens_to_remove.append(token)
                count += 1
        
        for token in tokens_to_remove:
            del self.tokens[token]
        
        return count
    
    def create_api_key(self, username: str, description: str = "", expires_in: Optional[int] = None) -> Dict[str, Any]:
        """Create a new API key for a user."""
        if username not in self.users:
            raise ValueError(f"User {username} does not exist")
        
        user = self.users[username]
        
        # Generate API key
        api_key = f"mcp_{secrets.token_urlsafe(32)}"
        key_id = str(uuid.uuid4())
        
        key_data = {
            "id": key_id,
            "key": api_key,
            "description": description,
            "created_at": time.time(),
            "enabled": True
        }
        
        if expires_in:
            key_data["expires_at"] = time.time() + expires_in
        
        user.api_keys.append(key_data)
        self.save_config()
        
        logger.info(f"Created API key for user {username}")
        return key_data
    
    def revoke_api_key(self, username: str, key_id: str) -> bool:
        """Revoke an API key."""
        if username not in self.users:
            raise ValueError(f"User {username} does not exist")
        
        user = self.users[username]
        
        for i, key_data in enumerate(user.api_keys):
            if key_data.get("id") == key_id:
                # Remove the key
                user.api_keys.pop(i)
                self.save_config()
                
                # Invalidate any tokens created with this key
                tokens_to_remove = []
                for token, token_data in self.tokens.items():
                    if (token_data.get("username") == username and 
                        token_data.get("api_key_id") == key_id):
                        tokens_to_remove.append(token)
                
                for token in tokens_to_remove:
                    del self.tokens[token]
                
                logger.info(f"Revoked API key {key_id} for user {username}")
                return True
        
        return False
    
    def has_permission(self, username: str, permission: Permission) -> bool:
        """Check if a user has a specific permission."""
        user = self.get_user(username)
        
        if not user or not user.enabled:
            return False
        
        # Admin role has all permissions
        if user.role == Role.ADMIN or Permission.ADMIN in user.permissions:
            return True
        
        return permission in user.permissions
    
    def check_permission(self, token: str, permission: Permission) -> bool:
        """Check if the token has a specific permission."""
        username = self.validate_token(token)
        if not username:
            return False
        
        return self.has_permission(username, permission)

# Create a middleware for integrating with MCP server
def authentication_middleware(auth_system: AuthenticationSystem, required_permission: Optional[Permission] = None):
    """Create a middleware function for MCP server handlers."""
    
    def middleware(handler):
        """Middleware wrapper for authenticating and authorizing requests."""
        
        def wrapped_handler(request, *args, **kwargs):
            # Extract authentication token from request
            auth_header = request.headers.get("Authorization", "")
            token = None
            
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
            elif auth_header.startswith("ApiKey "):
                api_key = auth_header[7:].strip()
                token = auth_system.authenticate_api_key(api_key)
            
            # Validate token
            username = auth_system.validate_token(token) if token else None
            
            if not username:
                return {
                    "status": "error",
                    "code": 401,
                    "message": "Authentication required"
                }
            
            # Check permission if required
            if required_permission and not auth_system.has_permission(username, required_permission):
                return {
                    "status": "error",
                    "code": 403,
                    "message": f"Permission denied: {required_permission.value} required"
                }
            
            # Add user information to the request
            request.auth_user = auth_system.get_user(username)
            
            # Call the original handler
            return handler(request, *args, **kwargs)
        
        return wrapped_handler
    
    return middleware 