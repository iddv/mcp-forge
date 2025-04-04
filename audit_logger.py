"""
Audit Logger for MCP-Forge

This module provides comprehensive security audit logging capabilities for the MCP-Forge 
framework, recording security-relevant events for compliance and forensic analysis.
"""

import json
import os
import time
import logging
import threading
import ipaddress
import socket
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Union, Callable
from enum import Enum
import hashlib

# Configure logging
logger = logging.getLogger("mcp_forge.audit")
audit_logger = logging.getLogger("mcp_forge.audit.events")

# Set up a separate handler for audit logs
audit_handler = logging.FileHandler("audit.log")
audit_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False  # Don't propagate to root logger

class AuditEventType(Enum):
    """Types of audit events."""
    # Authentication events
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    AUTH_LOGOUT = "auth.logout"
    
    # User management events
    USER_CREATE = "user.create"
    USER_MODIFY = "user.modify"
    USER_DELETE = "user.delete"
    USER_ENABLE = "user.enable"
    USER_DISABLE = "user.disable"
    
    # Permission events
    PERM_GRANT = "permission.grant"
    PERM_REVOKE = "permission.revoke"
    
    # API key events
    APIKEY_CREATE = "apikey.create"
    APIKEY_REVOKE = "apikey.revoke"
    
    # Server management events
    SERVER_CREATE = "server.create"
    SERVER_START = "server.start"
    SERVER_STOP = "server.stop"
    SERVER_DELETE = "server.delete"
    SERVER_MODIFY = "server.modify"
    
    # Configuration events
    CONFIG_CHANGE = "config.change"
    
    # Security events
    SEC_QUOTA_EXCEED = "security.quota_exceeded"
    SEC_RATE_LIMIT = "security.rate_limit"
    SEC_PERMISSION_DENIED = "security.permission_denied"
    SEC_INPUT_VALIDATION = "security.input_validation"
    SEC_SUSPICIOUS_REQUEST = "security.suspicious_request"
    SEC_IP_BLACKLISTED = "security.ip_blacklisted"
    SEC_CSRF_VIOLATION = "security.csrf_violation"
    SEC_XSS_ATTEMPT = "security.xss_attempt"
    SEC_INJECTION_ATTEMPT = "security.injection_attempt"
    SEC_RATE_LIMIT_EXCEEDED = "security.rate_limit_exceeded"
    SEC_BURST_LIMIT_EXCEEDED = "security.burst_limit_exceeded"
    SEC_GLOBAL_RATE_LIMIT_EXCEEDED = "security.global_rate_limit_exceeded"
    SEC_DATA_ENCRYPTION = "security.data_encryption"
    SEC_DATA_DECRYPTION = "security.data_decryption"
    
    # System events
    SYS_STARTUP = "system.startup"
    SYS_SHUTDOWN = "system.shutdown"
    SYS_ERROR = "system.error"

class AuditSeverity(Enum):
    """Severity levels for audit events."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium" 
    LOW = "low"
    INFO = "info"

class AuditEvent:
    """Represents a security audit event."""
    
    def __init__(
        self,
        event_type: AuditEventType,
        username: Optional[str],
        client_ip: Optional[str],
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        success: bool = True,
        request_id: Optional[str] = None
    ):
        """
        Initialize an audit event.
        
        Args:
            event_type: Type of audit event
            username: Username of the user performing the action (or None for system/anonymous)
            client_ip: IP address of the client (or None if not applicable)
            resource_id: ID of the resource being accessed/modified (if applicable)
            details: Additional details about the event
            severity: Severity level of the event
            success: Whether the action was successful
            request_id: ID of the request (for correlation)
        """
        self.id = str(uuid.uuid4())
        self.timestamp = datetime.now().isoformat()
        self.event_type = event_type
        self.username = username
        self.client_ip = client_ip
        self.resource_id = resource_id
        self.details = details or {}
        self.severity = severity
        self.success = success
        self.request_id = request_id or str(uuid.uuid4())
        self.hostname = socket.gethostname()
        
        # Create checksum for integrity
        self._generate_checksum()
    
    def _generate_checksum(self) -> None:
        """Generate a checksum for the event to ensure integrity."""
        # Create a string with all the fields
        event_str = (
            f"{self.id}{self.timestamp}{self.event_type.value}{self.username or ''}"
            f"{self.client_ip or ''}{self.resource_id or ''}"
            f"{json.dumps(self.details, sort_keys=True)}{self.severity.value}{self.success}"
            f"{self.request_id}{self.hostname}"
        )
        
        # Generate SHA-256 hash
        self.checksum = hashlib.sha256(event_str.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "username": self.username,
            "client_ip": self.client_ip,
            "resource_id": self.resource_id,
            "details": self.details,
            "severity": self.severity.value,
            "success": self.success,
            "request_id": self.request_id,
            "hostname": self.hostname,
            "checksum": self.checksum
        }
    
    def to_json(self) -> str:
        """Convert audit event to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditEvent':
        """Create audit event from dictionary representation."""
        event = cls(
            event_type=AuditEventType(data["event_type"]),
            username=data.get("username"),
            client_ip=data.get("client_ip"),
            resource_id=data.get("resource_id"),
            details=data.get("details", {}),
            severity=AuditSeverity(data.get("severity", "info")),
            success=data.get("success", True),
            request_id=data.get("request_id")
        )
        
        # Override generated values with saved ones
        event.id = data.get("id", event.id)
        event.timestamp = data.get("timestamp", event.timestamp)
        event.hostname = data.get("hostname", event.hostname)
        event.checksum = data.get("checksum", event.checksum)
        
        return event
    
    def __str__(self) -> str:
        """String representation of the audit event."""
        return (
            f"[{self.timestamp}] {self.event_type.value} - "
            f"User: {self.username or 'system/anonymous'} - "
            f"IP: {self.client_ip or 'N/A'} - "
            f"Resource: {self.resource_id or 'N/A'} - "
            f"Success: {self.success} - "
            f"Severity: {self.severity.value}"
        )

class AuditLogger:
    """Security audit logger for MCP-Forge."""
    
    def __init__(self, log_dir: str = "audit_logs"):
        """
        Initialize the audit logger.
        
        Args:
            log_dir: Directory to store audit logs
        """
        self.log_dir = log_dir
        self.current_log_file = None
        self.lock = threading.RLock()
        self.in_memory_events: List[AuditEvent] = []
        self.max_in_memory_events = 1000  # Maximum events to keep in memory
        
        # Create log directory
        os.makedirs(log_dir, exist_ok=True)
        
        # Create current log file based on date
        self._rotate_log_file()
    
    def _rotate_log_file(self) -> None:
        """Rotate log file based on current date."""
        current_date = datetime.now().strftime("%Y-%m-%d")
        self.current_log_file = os.path.join(self.log_dir, f"audit_{current_date}.log")
    
    def log_event(self, event: AuditEvent) -> None:
        """
        Log an audit event.
        
        Args:
            event: The audit event to log
        """
        with self.lock:
            # Check if we need to rotate log file
            current_date = datetime.now().strftime("%Y-%m-%d")
            if not self.current_log_file or current_date not in self.current_log_file:
                self._rotate_log_file()
            
            # Write to log file
            with open(self.current_log_file, 'a') as f:
                f.write(event.to_json() + '\n')
            
            # Add to in-memory events
            self.in_memory_events.append(event)
            
            # Trim in-memory events if needed
            if len(self.in_memory_events) > self.max_in_memory_events:
                self.in_memory_events = self.in_memory_events[-self.max_in_memory_events:]
            
            # Also log to the audit logger
            log_level = logging.INFO if event.success else logging.WARNING
            if event.severity == AuditSeverity.CRITICAL:
                log_level = logging.CRITICAL
            elif event.severity == AuditSeverity.HIGH:
                log_level = logging.ERROR
            elif event.severity == AuditSeverity.MEDIUM:
                log_level = logging.WARNING
            
            audit_logger.log(log_level, str(event))
    
    def log_auth_success(self, username: str, client_ip: str, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a successful authentication event.
        
        Args:
            username: Username of the authenticated user
            client_ip: IP address of the client
            details: Additional details about the event
        """
        event = AuditEvent(
            event_type=AuditEventType.AUTH_SUCCESS,
            username=username,
            client_ip=client_ip,
            details=details,
            severity=AuditSeverity.INFO,
            success=True
        )
        self.log_event(event)
    
    def log_auth_failure(self, username: str, client_ip: str, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a failed authentication event.
        
        Args:
            username: Username that failed authentication
            client_ip: IP address of the client
            details: Additional details about the event
        """
        event = AuditEvent(
            event_type=AuditEventType.AUTH_FAILURE,
            username=username,
            client_ip=client_ip,
            details=details,
            severity=AuditSeverity.MEDIUM,
            success=False
        )
        self.log_event(event)
    
    def log_user_create(self, admin_username: str, client_ip: str, created_username: str, 
                       details: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a user creation event.
        
        Args:
            admin_username: Username of the admin creating the user
            client_ip: IP address of the admin
            created_username: Username of the created user
            details: Additional details about the event
        """
        event = AuditEvent(
            event_type=AuditEventType.USER_CREATE,
            username=admin_username,
            client_ip=client_ip,
            resource_id=created_username,
            details=details,
            severity=AuditSeverity.MEDIUM,
            success=True
        )
        self.log_event(event)
    
    def log_server_action(self, event_type: AuditEventType, username: str, client_ip: str, 
                         server_id: str, details: Optional[Dict[str, Any]] = None,
                         success: bool = True) -> None:
        """
        Log a server management action.
        
        Args:
            event_type: Type of server action
            username: Username performing the action
            client_ip: IP address of the client
            server_id: ID of the server
            details: Additional details about the event
            success: Whether the action was successful
        """
        # Validate event type is a server action
        if not event_type.value.startswith("server."):
            raise ValueError(f"Invalid server action event type: {event_type}")
        
        severity = AuditSeverity.INFO
        if not success:
            severity = AuditSeverity.MEDIUM
        if event_type == AuditEventType.SERVER_DELETE:
            severity = AuditSeverity.MEDIUM
        
        event = AuditEvent(
            event_type=event_type,
            username=username,
            client_ip=client_ip,
            resource_id=server_id,
            details=details,
            severity=severity,
            success=success
        )
        self.log_event(event)
    
    def log_permission_change(self, admin_username: str, client_ip: str, target_username: str,
                             is_grant: bool, permission: str, 
                             details: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a permission change event.
        
        Args:
            admin_username: Username of the admin changing permissions
            client_ip: IP address of the admin
            target_username: Username of the user whose permissions are being changed
            is_grant: True for grant, False for revoke
            permission: The permission being granted/revoked
            details: Additional details about the event
        """
        event_type = AuditEventType.PERM_GRANT if is_grant else AuditEventType.PERM_REVOKE
        
        event_details = details or {}
        event_details["permission"] = permission
        
        event = AuditEvent(
            event_type=event_type,
            username=admin_username,
            client_ip=client_ip,
            resource_id=target_username,
            details=event_details,
            severity=AuditSeverity.MEDIUM,
            success=True
        )
        self.log_event(event)
    
    def log_config_change(self, username: str, client_ip: str, 
                         config_section: str, config_key: str, 
                         old_value: Any, new_value: Any) -> None:
        """
        Log a configuration change event.
        
        Args:
            username: Username making the change
            client_ip: IP address of the client
            config_section: Section of configuration being changed
            config_key: Key being changed
            old_value: Previous value
            new_value: New value
        """
        # Sanitize values for logging (remove sensitive data)
        if "password" in config_key.lower() or "secret" in config_key.lower() or "key" in config_key.lower():
            old_value = "********"
            new_value = "********"
        
        details = {
            "section": config_section,
            "key": config_key,
            "old_value": str(old_value),
            "new_value": str(new_value)
        }
        
        event = AuditEvent(
            event_type=AuditEventType.CONFIG_CHANGE,
            username=username,
            client_ip=client_ip,
            resource_id=f"{config_section}.{config_key}",
            details=details,
            severity=AuditSeverity.MEDIUM,
            success=True
        )
        self.log_event(event)
    
    def log_security_event(self, event_type: AuditEventType, username: Optional[str], 
                          client_ip: str, resource_id: Optional[str] = None,
                          details: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a security-related event.
        
        Args:
            event_type: Type of security event
            username: Username related to the event (if applicable)
            client_ip: IP address of the client
            resource_id: ID of the resource (if applicable)
            details: Additional details about the event
        """
        # Validate event type is a security event
        if not event_type.value.startswith("security."):
            raise ValueError(f"Invalid security event type: {event_type}")
        
        # Determine severity based on event type
        severity = AuditSeverity.MEDIUM
        if event_type == AuditEventType.SEC_PERMISSION_DENIED:
            severity = AuditSeverity.HIGH
        
        event = AuditEvent(
            event_type=event_type,
            username=username,
            client_ip=client_ip,
            resource_id=resource_id,
            details=details,
            severity=severity,
            success=False
        )
        self.log_event(event)
    
    def log_system_event(self, event_type: AuditEventType, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a system event.
        
        Args:
            event_type: Type of system event
            details: Additional details about the event
        """
        # Validate event type is a system event
        if not event_type.value.startswith("system."):
            raise ValueError(f"Invalid system event type: {event_type}")
        
        # Determine severity based on event type
        severity = AuditSeverity.INFO
        success = True
        
        if event_type == AuditEventType.SYS_ERROR:
            severity = AuditSeverity.HIGH
            success = False
        
        event = AuditEvent(
            event_type=event_type,
            username=None,  # System events don't have a user
            client_ip=None,  # System events don't have a client IP
            details=details,
            severity=severity,
            success=success
        )
        self.log_event(event)
    
    def get_events(self, event_types: Optional[List[AuditEventType]] = None, 
                  username: Optional[str] = None, resource_id: Optional[str] = None,
                  start_time: Optional[str] = None, end_time: Optional[str] = None,
                  severity: Optional[AuditSeverity] = None, success: Optional[bool] = None,
                  max_events: int = 100) -> List[AuditEvent]:
        """
        Get filtered audit events from memory.
        
        Args:
            event_types: List of event types to include
            username: Filter by username
            resource_id: Filter by resource ID
            start_time: Filter by start time (ISO format)
            end_time: Filter by end time (ISO format)
            severity: Filter by severity
            success: Filter by success status
            max_events: Maximum number of events to return
            
        Returns:
            List of matching audit events
        """
        with self.lock:
            # Create a copy of in-memory events
            events = list(self.in_memory_events)
        
        # Apply filters
        if event_types:
            event_type_values = [et.value for et in event_types]
            events = [e for e in events if e.event_type.value in event_type_values]
        
        if username:
            events = [e for e in events if e.username == username]
        
        if resource_id:
            events = [e for e in events if e.resource_id == resource_id]
        
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]
        
        if severity:
            events = [e for e in events if e.severity == severity]
        
        if success is not None:
            events = [e for e in events if e.success == success]
        
        # Sort by timestamp (newest first)
        events.sort(key=lambda e: e.timestamp, reverse=True)
        
        # Limit to max_events
        return events[:max_events]
    
    def search_events(self, query: str, max_events: int = 100) -> List[AuditEvent]:
        """
        Search audit events by keyword.
        
        Args:
            query: Search query string
            max_events: Maximum number of events to return
            
        Returns:
            List of matching audit events
        """
        with self.lock:
            # Create a copy of in-memory events
            events = list(self.in_memory_events)
        
        # Convert query to lowercase for case-insensitive search
        query = query.lower()
        
        matching_events = []
        for event in events:
            # Check if query is in any string field
            if (
                query in event.event_type.value.lower() or
                (event.username and query in event.username.lower()) or
                (event.client_ip and query in event.client_ip.lower()) or
                (event.resource_id and query in event.resource_id.lower()) or
                query in event.severity.value.lower() or
                any(
                    isinstance(v, str) and query in v.lower()
                    for v in event.details.values()
                    if isinstance(v, str)
                )
            ):
                matching_events.append(event)
        
        # Sort by timestamp (newest first)
        matching_events.sort(key=lambda e: e.timestamp, reverse=True)
        
        # Limit to max_events
        return matching_events[:max_events]
    
    def verify_event_integrity(self, event: AuditEvent) -> bool:
        """
        Verify the integrity of an audit event.
        
        Args:
            event: The audit event to verify
            
        Returns:
            True if the event integrity is verified, False otherwise
        """
        # Save the original checksum
        original_checksum = event.checksum
        
        # Generate a new checksum
        event._generate_checksum()
        new_checksum = event.checksum
        
        # Restore the original checksum
        event.checksum = original_checksum
        
        # Compare checksums
        return original_checksum == new_checksum

# Global instance of audit logger
_audit_logger = None

def get_audit_logger() -> AuditLogger:
    """
    Get the global audit logger instance.
    
    Returns:
        Audit logger instance
    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger

# Convenience functions for common audit logging operations
def log_auth_success(username: str, client_ip: str, details: Optional[Dict[str, Any]] = None) -> None:
    """Log a successful authentication event."""
    get_audit_logger().log_auth_success(username, client_ip, details)

def log_auth_failure(username: str, client_ip: str, details: Optional[Dict[str, Any]] = None) -> None:
    """Log a failed authentication event."""
    get_audit_logger().log_auth_failure(username, client_ip, details)

def log_user_create(admin_username: str, client_ip: str, created_username: str, 
                  details: Optional[Dict[str, Any]] = None) -> None:
    """Log a user creation event."""
    get_audit_logger().log_user_create(admin_username, client_ip, created_username, details)

def log_server_create(username: str, client_ip: str, server_id: str, 
                    details: Optional[Dict[str, Any]] = None, success: bool = True) -> None:
    """Log a server creation event."""
    get_audit_logger().log_server_action(AuditEventType.SERVER_CREATE, username, client_ip, 
                                        server_id, details, success)

def log_server_delete(username: str, client_ip: str, server_id: str, 
                    details: Optional[Dict[str, Any]] = None, success: bool = True) -> None:
    """Log a server deletion event."""
    get_audit_logger().log_server_action(AuditEventType.SERVER_DELETE, username, client_ip, 
                                        server_id, details, success)

def log_permission_denied(username: Optional[str], client_ip: str, resource_id: Optional[str] = None,
                        details: Optional[Dict[str, Any]] = None) -> None:
    """Log a permission denied security event."""
    get_audit_logger().log_security_event(AuditEventType.SEC_PERMISSION_DENIED, username, client_ip, 
                                         resource_id, details) 