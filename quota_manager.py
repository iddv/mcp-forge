"""
Quota Manager for MCP-Forge

This module provides resource quota management capabilities for the MCP-Forge framework,
allowing administrators to set and enforce limits on resource usage.
"""

import json
import os
import time
import threading
import logging
from typing import Dict, Any, List, Optional, Tuple, Union, Callable
from datetime import datetime, timedelta
import psutil

# Configure logging
logger = logging.getLogger("mcp_forge.quota")

class QuotaExceededError(Exception):
    """Raised when a quota is exceeded."""
    pass

class ResourceQuota:
    """Resource quota definition."""
    
    def __init__(
        self,
        resource_type: str,
        limit: Union[int, float],
        period: str = "hourly",
        description: Optional[str] = None
    ):
        """
        Initialize a resource quota.
        
        Args:
            resource_type: Type of resource being limited (e.g., servers, api_calls)
            limit: Maximum allowed value
            period: Time period for the limit (hourly, daily, monthly, total)
            description: Optional description of the quota
        """
        self.resource_type = resource_type
        self.limit = limit
        self.period = period
        self.description = description or f"Limit of {limit} {resource_type} per {period}"
        self.current_value = 0
        self.last_reset = time.time()
        self.is_active = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert quota to dictionary representation."""
        return {
            "resource_type": self.resource_type,
            "limit": self.limit,
            "period": self.period,
            "description": self.description,
            "current_value": self.current_value,
            "last_reset": self.last_reset,
            "is_active": self.is_active
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ResourceQuota':
        """Create quota from dictionary representation."""
        quota = cls(
            resource_type=data["resource_type"],
            limit=data["limit"],
            period=data["period"],
            description=data.get("description")
        )
        quota.current_value = data.get("current_value", 0)
        quota.last_reset = data.get("last_reset", time.time())
        quota.is_active = data.get("is_active", True)
        return quota

class UserQuotas:
    """Quotas for a specific user."""
    
    def __init__(self, username: str):
        """
        Initialize user quotas.
        
        Args:
            username: Username of the user
        """
        self.username = username
        self.quotas: Dict[str, ResourceQuota] = {}
    
    def add_quota(self, quota: ResourceQuota) -> None:
        """
        Add a quota for the user.
        
        Args:
            quota: The quota to add
        """
        self.quotas[quota.resource_type] = quota
    
    def remove_quota(self, resource_type: str) -> bool:
        """
        Remove a quota.
        
        Args:
            resource_type: Type of resource quota to remove
            
        Returns:
            True if removed, False if not found
        """
        if resource_type in self.quotas:
            del self.quotas[resource_type]
            return True
        return False
    
    def check_quota(self, resource_type: str, increment: Union[int, float] = 1) -> bool:
        """
        Check if a quota allows the requested increment.
        
        Args:
            resource_type: Type of resource to check
            increment: Amount to increment (default: 1)
            
        Returns:
            True if allowed, False if quota would be exceeded
        """
        if resource_type not in self.quotas:
            return True  # No quota defined, so allowed
        
        quota = self.quotas[resource_type]
        
        if not quota.is_active:
            return True  # Inactive quota, so allowed
        
        # Check if we need to reset based on period
        self._maybe_reset_quota(quota)
        
        # Check if would exceed
        if quota.current_value + increment > quota.limit:
            return False
        
        return True
    
    def increment_usage(self, resource_type: str, amount: Union[int, float] = 1) -> bool:
        """
        Increment usage of a resource.
        
        Args:
            resource_type: Type of resource to increment
            amount: Amount to increment (default: 1)
            
        Returns:
            True if incremented, False if quota would be exceeded
        """
        if not self.check_quota(resource_type, amount):
            return False
        
        if resource_type in self.quotas:
            quota = self.quotas[resource_type]
            quota.current_value += amount
        
        return True
    
    def _maybe_reset_quota(self, quota: ResourceQuota) -> None:
        """Reset quota if period has elapsed."""
        now = time.time()
        
        if quota.period == "hourly":
            # Reset if more than an hour has passed
            if now - quota.last_reset > 3600:
                quota.current_value = 0
                quota.last_reset = now
        
        elif quota.period == "daily":
            # Reset if more than a day has passed
            if now - quota.last_reset > 86400:
                quota.current_value = 0
                quota.last_reset = now
        
        elif quota.period == "monthly":
            # Reset if more than 30 days have passed
            if now - quota.last_reset > 2592000:
                quota.current_value = 0
                quota.last_reset = now
        
        # No reset for "total" period
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user quotas to dictionary representation."""
        return {
            "username": self.username,
            "quotas": {name: quota.to_dict() for name, quota in self.quotas.items()}
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserQuotas':
        """Create user quotas from dictionary representation."""
        user_quotas = cls(username=data["username"])
        
        for name, quota_data in data.get("quotas", {}).items():
            user_quotas.add_quota(ResourceQuota.from_dict(quota_data))
        
        return user_quotas

class SystemQuotas:
    """System-wide quotas."""
    
    def __init__(self):
        """Initialize system quotas."""
        self.quotas: Dict[str, ResourceQuota] = {}
    
    def add_quota(self, quota: ResourceQuota) -> None:
        """
        Add a system quota.
        
        Args:
            quota: The quota to add
        """
        self.quotas[quota.resource_type] = quota
    
    def remove_quota(self, resource_type: str) -> bool:
        """
        Remove a system quota.
        
        Args:
            resource_type: Type of resource quota to remove
            
        Returns:
            True if removed, False if not found
        """
        if resource_type in self.quotas:
            del self.quotas[resource_type]
            return True
        return False
    
    def check_quota(self, resource_type: str, increment: Union[int, float] = 1) -> bool:
        """
        Check if a system quota allows the requested increment.
        
        Args:
            resource_type: Type of resource to check
            increment: Amount to increment (default: 1)
            
        Returns:
            True if allowed, False if quota would be exceeded
        """
        if resource_type not in self.quotas:
            return True  # No quota defined, so allowed
        
        quota = self.quotas[resource_type]
        
        if not quota.is_active:
            return True  # Inactive quota, so allowed
        
        # Check if would exceed
        if quota.current_value + increment > quota.limit:
            return False
        
        return True
    
    def increment_usage(self, resource_type: str, amount: Union[int, float] = 1) -> bool:
        """
        Increment usage of a system resource.
        
        Args:
            resource_type: Type of resource to increment
            amount: Amount to increment (default: 1)
            
        Returns:
            True if incremented, False if quota would be exceeded
        """
        if not self.check_quota(resource_type, amount):
            return False
        
        if resource_type in self.quotas:
            quota = self.quotas[resource_type]
            quota.current_value += amount
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert system quotas to dictionary representation."""
        return {
            "quotas": {name: quota.to_dict() for name, quota in self.quotas.items()}
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SystemQuotas':
        """Create system quotas from dictionary representation."""
        system_quotas = cls()
        
        for name, quota_data in data.get("quotas", {}).items():
            system_quotas.add_quota(ResourceQuota.from_dict(quota_data))
        
        return system_quotas

class QuotaManager:
    """Manager for resource quotas."""
    
    def __init__(self, config_path: str = "quota_config.json"):
        """
        Initialize the quota manager.
        
        Args:
            config_path: Path to the configuration file
        """
        self.config_path = config_path
        self.user_quotas: Dict[str, UserQuotas] = {}
        self.system_quotas = SystemQuotas()
        self.lock = threading.RLock()
        
        # Default quotas
        self._init_default_quotas()
        
        # Load configuration
        self.load_config()
    
    def _init_default_quotas(self) -> None:
        """Initialize default quotas."""
        # Default system quotas
        self.system_quotas.add_quota(ResourceQuota(
            resource_type="total_servers",
            limit=50,
            period="total",
            description="Maximum total number of servers"
        ))
        
        self.system_quotas.add_quota(ResourceQuota(
            resource_type="total_api_calls",
            limit=10000,
            period="hourly",
            description="Maximum API calls per hour for the entire system"
        ))
        
        # Default user quotas will be created when users are added
    
    def _create_default_user_quotas(self, username: str, is_admin: bool = False) -> UserQuotas:
        """
        Create default quotas for a user.
        
        Args:
            username: Username of the user
            is_admin: Whether the user is an admin
            
        Returns:
            User quota object
        """
        user_quotas = UserQuotas(username)
        
        # Different limits based on user role
        if is_admin:
            server_limit = 20
            api_call_limit = 5000
        else:
            server_limit = 5
            api_call_limit = 1000
        
        # Add default quotas
        user_quotas.add_quota(ResourceQuota(
            resource_type="servers",
            limit=server_limit,
            period="total",
            description=f"Maximum of {server_limit} servers per user"
        ))
        
        user_quotas.add_quota(ResourceQuota(
            resource_type="api_calls",
            limit=api_call_limit,
            period="hourly",
            description=f"Maximum of {api_call_limit} API calls per hour"
        ))
        
        return user_quotas
    
    def load_config(self) -> None:
        """Load quota configuration from file."""
        if not os.path.exists(self.config_path):
            logger.warning(f"Quota config not found at {self.config_path}, using defaults")
            return
        
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # Load system quotas
            if "system_quotas" in config:
                self.system_quotas = SystemQuotas.from_dict(config["system_quotas"])
            
            # Load user quotas
            self.user_quotas = {}
            for user_data in config.get("user_quotas", []):
                user_quotas = UserQuotas.from_dict(user_data)
                self.user_quotas[user_quotas.username] = user_quotas
            
            logger.info(f"Loaded quota configuration for {len(self.user_quotas)} users")
        except Exception as e:
            logger.error(f"Error loading quota configuration: {str(e)}")
    
    def save_config(self) -> None:
        """Save quota configuration to file."""
        config = {
            "system_quotas": self.system_quotas.to_dict(),
            "user_quotas": [uq.to_dict() for uq in self.user_quotas.values()]
        }
        
        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info("Quota configuration saved")
        except Exception as e:
            logger.error(f"Error saving quota configuration: {str(e)}")
    
    def get_user_quotas(self, username: str) -> UserQuotas:
        """
        Get quotas for a user, creating default ones if needed.
        
        Args:
            username: Username of the user
            
        Returns:
            User quota object
        """
        with self.lock:
            if username not in self.user_quotas:
                # Create default quotas for this user
                is_admin = username == "admin"  # Simple check, should use proper role checking
                self.user_quotas[username] = self._create_default_user_quotas(username, is_admin)
                self.save_config()
            
            return self.user_quotas[username]
    
    def set_user_quota(self, username: str, resource_type: str, limit: Union[int, float], 
                       period: str = "hourly", description: Optional[str] = None) -> None:
        """
        Set a quota for a user.
        
        Args:
            username: Username of the user
            resource_type: Type of resource being limited
            limit: Maximum allowed value
            period: Time period for the limit
            description: Optional description of the quota
        """
        with self.lock:
            user_quotas = self.get_user_quotas(username)
            
            quota = ResourceQuota(
                resource_type=resource_type,
                limit=limit,
                period=period,
                description=description
            )
            
            user_quotas.add_quota(quota)
            self.save_config()
    
    def remove_user_quota(self, username: str, resource_type: str) -> bool:
        """
        Remove a quota for a user.
        
        Args:
            username: Username of the user
            resource_type: Type of resource quota to remove
            
        Returns:
            True if removed, False if not found
        """
        with self.lock:
            if username not in self.user_quotas:
                return False
            
            success = self.user_quotas[username].remove_quota(resource_type)
            
            if success:
                self.save_config()
            
            return success
    
    def set_system_quota(self, resource_type: str, limit: Union[int, float], 
                         period: str = "total", description: Optional[str] = None) -> None:
        """
        Set a system-wide quota.
        
        Args:
            resource_type: Type of resource being limited
            limit: Maximum allowed value
            period: Time period for the limit
            description: Optional description of the quota
        """
        with self.lock:
            quota = ResourceQuota(
                resource_type=resource_type,
                limit=limit,
                period=period,
                description=description
            )
            
            self.system_quotas.add_quota(quota)
            self.save_config()
    
    def remove_system_quota(self, resource_type: str) -> bool:
        """
        Remove a system quota.
        
        Args:
            resource_type: Type of resource quota to remove
            
        Returns:
            True if removed, False if not found
        """
        with self.lock:
            success = self.system_quotas.remove_quota(resource_type)
            
            if success:
                self.save_config()
            
            return success
    
    def check_quota(self, username: str, resource_type: str, increment: Union[int, float] = 1) -> bool:
        """
        Check if a quota allows the requested operation.
        
        Args:
            username: Username of the user
            resource_type: Type of resource to check
            increment: Amount to increment (default: 1)
            
        Returns:
            True if allowed, False if quota would be exceeded
        """
        with self.lock:
            # First check system quotas
            if not self.system_quotas.check_quota(resource_type, increment):
                return False
            
            # Then check user quotas
            user_quotas = self.get_user_quotas(username)
            return user_quotas.check_quota(resource_type, increment)
    
    def increment_usage(self, username: str, resource_type: str, amount: Union[int, float] = 1) -> bool:
        """
        Increment usage of a resource.
        
        Args:
            username: Username of the user
            resource_type: Type of resource to increment
            amount: Amount to increment (default: 1)
            
        Returns:
            True if incremented, False if quota would be exceeded
        """
        with self.lock:
            # First check and update system quotas
            if not self.system_quotas.increment_usage(resource_type, amount):
                return False
            
            # Then check and update user quotas
            user_quotas = self.get_user_quotas(username)
            result = user_quotas.increment_usage(resource_type, amount)
            
            # If we're tracking usage, save the config
            self.save_config()
            
            return result
    
    def get_quotas_status(self, username: str) -> Dict[str, Dict[str, Any]]:
        """
        Get current quota status for a user.
        
        Args:
            username: Username of the user
            
        Returns:
            Dictionary of quota statuses
        """
        with self.lock:
            user_quotas = self.get_user_quotas(username)
            
            result = {}
            for resource_type, quota in user_quotas.quotas.items():
                result[resource_type] = {
                    "limit": quota.limit,
                    "current": quota.current_value,
                    "remaining": quota.limit - quota.current_value,
                    "period": quota.period,
                    "description": quota.description,
                    "is_active": quota.is_active
                }
            
            return result
    
    def get_system_quotas_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get current system quota status.
        
        Returns:
            Dictionary of quota statuses
        """
        with self.lock:
            result = {}
            for resource_type, quota in self.system_quotas.quotas.items():
                result[resource_type] = {
                    "limit": quota.limit,
                    "current": quota.current_value,
                    "remaining": quota.limit - quota.current_value,
                    "period": quota.period,
                    "description": quota.description,
                    "is_active": quota.is_active
                }
            
            return result

# Global instance of quota manager
_quota_manager = None

def get_quota_manager() -> QuotaManager:
    """
    Get the global quota manager instance.
    
    Returns:
        Quota manager instance
    """
    global _quota_manager
    if _quota_manager is None:
        _quota_manager = QuotaManager()
    return _quota_manager 