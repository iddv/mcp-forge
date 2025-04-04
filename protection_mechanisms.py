"""
Protection Mechanisms for MCP-Forge

This module implements comprehensive security protection mechanisms to safeguard
the MCP-Forge framework and its child servers against various vulnerabilities and attacks.
It provides defense layers such as:

1. Input validation and sanitization
2. Protection against common web vulnerabilities (XSS, CSRF, SQLi, etc.)
3. Content security policy enforcement
4. Rate limiting and throttling
5. Security headers management
6. Secure cookie handling
7. Server hardening
8. Data encryption
9. DDoS protection
10. Intrusion detection
"""

import os
import re
import time
import uuid
import json
import hashlib
import logging
import ipaddress
import threading
from typing import Dict, List, Any, Optional, Tuple, Set, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps

# Import necessary modules from the project
from request_validator import validate_input, sanitize_input
from audit_logger import AuditLogger, AuditEventType, get_audit_logger

# Configure logging
logger = logging.getLogger("mcp_forge.protection")

# Constants for security settings
DEFAULT_MAX_CONTENT_LENGTH = 1024 * 1024  # 1MB
DEFAULT_CSRF_TOKEN_EXPIRY = 3600  # 1 hour
DEFAULT_CSP_POLICY = "default-src 'self'; script-src 'self'; object-src 'none'; img-src 'self' data:; style-src 'self';"
DEFAULT_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

@dataclass
class SecurityEvent:
    """Represents a security event for tracking potential threats."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    event_type: str = ""
    severity: str = "medium"  # low, medium, high, critical
    source_ip: str = ""
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

class IPBlacklist:
    """Manages blacklisted IP addresses."""
    
    def __init__(self):
        self.blacklisted_ips: Set[str] = set()
        self.blacklist_duration: Dict[str, datetime] = {}
        self.lock = threading.RLock()
        
    def is_blacklisted(self, ip: str) -> bool:
        """Check if an IP is blacklisted."""
        with self.lock:
            if ip not in self.blacklisted_ips:
                return False
                
            # Check if blacklist duration has expired
            if ip in self.blacklist_duration:
                if datetime.now() > self.blacklist_duration[ip]:
                    # Expired, remove from blacklist
                    self.blacklisted_ips.remove(ip)
                    del self.blacklist_duration[ip]
                    return False
            
            return True
    
    def add_to_blacklist(self, ip: str, duration_minutes: int = 60) -> None:
        """Add an IP to the blacklist with expiry time."""
        with self.lock:
            self.blacklisted_ips.add(ip)
            expiry_time = datetime.now() + timedelta(minutes=duration_minutes)
            self.blacklist_duration[ip] = expiry_time
            
            # Log the blacklisting event
            logger.warning(f"IP {ip} blacklisted for {duration_minutes} minutes")
            get_audit_logger().log_security_event(
                AuditEventType.SEC_IP_BLACKLISTED,
                None,
                ip,
                None,
                {"duration_minutes": duration_minutes}
            )
    
    def remove_from_blacklist(self, ip: str) -> None:
        """Remove an IP from the blacklist."""
        with self.lock:
            if ip in self.blacklisted_ips:
                self.blacklisted_ips.remove(ip)
            if ip in self.blacklist_duration:
                del self.blacklist_duration[ip]

class CSRFProtection:
    """Implements CSRF token generation and validation."""
    
    def __init__(self):
        self.tokens: Dict[str, Tuple[str, datetime]] = {}
        self.lock = threading.RLock()
    
    def generate_token(self, session_id: str) -> str:
        """Generate a CSRF token for a session."""
        with self.lock:
            token = hashlib.sha256(f"{session_id}:{uuid.uuid4()}".encode()).hexdigest()
            expiry = datetime.now() + timedelta(seconds=DEFAULT_CSRF_TOKEN_EXPIRY)
            self.tokens[session_id] = (token, expiry)
            return token
    
    def validate_token(self, session_id: str, token: str) -> bool:
        """Validate a CSRF token."""
        with self.lock:
            if session_id not in self.tokens:
                return False
                
            stored_token, expiry = self.tokens[session_id]
            
            # Check if token has expired
            if datetime.now() > expiry:
                del self.tokens[session_id]
                return False
                
            # Validate token (constant-time comparison to prevent timing attacks)
            return hashlib.compare_digest(stored_token, token)
    
    def cleanup_expired_tokens(self) -> None:
        """Clean up expired tokens."""
        with self.lock:
            current_time = datetime.now()
            expired_sessions = []
            
            for session_id, (_, expiry) in self.tokens.items():
                if current_time > expiry:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                del self.tokens[session_id]

class ContentSecurityPolicy:
    """Manages Content Security Policy headers."""
    
    def __init__(self, default_policy: str = DEFAULT_CSP_POLICY):
        self.default_policy = default_policy
        self.custom_policies: Dict[str, str] = {}
    
    def get_policy(self, endpoint: Optional[str] = None) -> str:
        """Get CSP for a specific endpoint or the default policy."""
        if endpoint and endpoint in self.custom_policies:
            return self.custom_policies[endpoint]
        return self.default_policy
    
    def set_policy(self, policy: str, endpoint: Optional[str] = None) -> None:
        """Set CSP for a specific endpoint or update the default policy."""
        if endpoint:
            self.custom_policies[endpoint] = policy
        else:
            self.default_policy = policy

class SecurityHeadersManager:
    """Manages security headers for HTTP responses."""
    
    def __init__(self, default_headers: Dict[str, str] = DEFAULT_SECURITY_HEADERS):
        self.default_headers = default_headers.copy()
        self.csp = ContentSecurityPolicy()
    
    def get_security_headers(self, endpoint: Optional[str] = None) -> Dict[str, str]:
        """Get all security headers including CSP for a specific endpoint."""
        headers = self.default_headers.copy()
        headers["Content-Security-Policy"] = self.csp.get_policy(endpoint)
        return headers
    
    def set_header(self, name: str, value: str) -> None:
        """Set a specific security header."""
        self.default_headers[name] = value
    
    def remove_header(self, name: str) -> None:
        """Remove a specific security header."""
        if name in self.default_headers:
            del self.default_headers[name]

class IntrusionDetectionSystem:
    """Simple intrusion detection system to detect suspicious activities."""
    
    def __init__(self):
        self.suspicious_patterns = [
            r"(?i)(?:union\s+select|select.*from|insert\s+into|update\s+set|delete\s+from)",  # SQL injection
            r"(?i)(?:<script>|javascript:|on\w+\s*=)",  # XSS
            r"(?i)(?:\\x[0-9a-f]{2}|%[0-9a-f]{2})",  # Encoded characters
            r"(?i)(?:\.\.|\/etc\/passwd|\w+\.(?:ini|log|sh|bat))",  # Path traversal
            r"(?i)(?:curl|wget)\s+",  # Command injection
        ]
        self.ip_blacklist = IPBlacklist()
        self.detection_counters: Dict[str, Dict[str, int]] = {}
        self.threshold = 5  # Number of suspicious activities before blacklisting
        self.lock = threading.RLock()
        
    def check_request(self, ip: str, path: str, query_params: Dict[str, Any], 
                     headers: Dict[str, str], body: Optional[Any] = None) -> bool:
        """
        Check a request for suspicious patterns.
        Returns True if the request seems legitimate, False if it looks malicious.
        """
        # Check if IP is already blacklisted
        if self.ip_blacklist.is_blacklisted(ip):
            logger.warning(f"Request from blacklisted IP: {ip}")
            return False
        
        suspicious_activity = False
        description = ""
        
        # Initialize counter for this IP if not exists
        with self.lock:
            if ip not in self.detection_counters:
                self.detection_counters[ip] = {"count": 0, "last_reset": datetime.now()}
        
        # Check path
        for pattern in self.suspicious_patterns:
            if re.search(pattern, path):
                suspicious_activity = True
                description = f"Suspicious pattern in path: {path}"
                break
        
        # Check query parameters
        if not suspicious_activity and query_params:
            for key, value in query_params.items():
                if isinstance(value, str):
                    for pattern in self.suspicious_patterns:
                        if re.search(pattern, value):
                            suspicious_activity = True
                            description = f"Suspicious pattern in query parameter: {key}={value}"
                            break
                if suspicious_activity:
                    break
        
        # Check body if present
        if not suspicious_activity and body:
            body_str = str(body) if not isinstance(body, str) else body
            for pattern in self.suspicious_patterns:
                if re.search(pattern, body_str):
                    suspicious_activity = True
                    description = f"Suspicious pattern in request body"
                    break
        
        # If suspicious activity found, increment counter
        if suspicious_activity:
            with self.lock:
                # Reset counter if it's been more than a day
                if datetime.now() - self.detection_counters[ip]["last_reset"] > timedelta(days=1):
                    self.detection_counters[ip] = {"count": 0, "last_reset": datetime.now()}
                
                self.detection_counters[ip]["count"] += 1
                
                # Log the security event
                security_event = SecurityEvent(
                    event_type="suspicious_request",
                    severity="medium",
                    source_ip=ip,
                    description=description
                )
                
                # Log to audit logger
                get_audit_logger().log_security_event(
                    AuditEventType.SEC_SUSPICIOUS_REQUEST,
                    None,
                    ip,
                    None,
                    {"description": description}
                )
                
                logger.warning(f"Suspicious activity detected from {ip}: {description}")
                
                # Check if threshold is reached
                if self.detection_counters[ip]["count"] >= self.threshold:
                    logger.critical(f"IP {ip} exceeds threshold for suspicious activities. Blacklisting.")
                    self.ip_blacklist.add_to_blacklist(ip, 120)  # Blacklist for 2 hours
                    
                    # Log blacklist event to audit logger
                    get_audit_logger().log_security_event(
                        AuditEventType.SEC_IP_BLACKLISTED,
                        None,
                        ip,
                        None,
                        {"reason": "Exceeded suspicious activity threshold", "count": self.detection_counters[ip]["count"]}
                    )
                    
                    return False
        
        return not suspicious_activity

class SecureCookieManager:
    """Manages secure cookies with encryption and integrity protection."""
    
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or os.urandom(32).hex()
    
    def create_secure_cookie(self, name: str, value: str, expires_days: int = 30, 
                           http_only: bool = True, secure: bool = True, 
                           same_site: str = "Lax") -> Dict[str, Any]:
        """Create a secure cookie with the specified attributes."""
        # Encrypt the value
        encrypted_value = self._encrypt_value(value)
        
        # Calculate expiry time
        expiry = datetime.now() + timedelta(days=expires_days)
        
        return {
            "name": name,
            "value": encrypted_value,
            "expires": expiry.strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "httpOnly": http_only,
            "secure": secure,
            "sameSite": same_site
        }
    
    def validate_and_decode_cookie(self, cookie_value: str) -> Optional[str]:
        """Validate and decrypt cookie value."""
        try:
            return self._decrypt_value(cookie_value)
        except Exception as e:
            logger.error(f"Error decoding cookie: {str(e)}")
            return None
    
    def _encrypt_value(self, value: str) -> str:
        """Encrypt a value for storage in a cookie."""
        # In a real implementation, use a proper encryption library like cryptography
        # This is a simplified version for demonstration purposes
        timestamp = int(time.time())
        signature = hashlib.sha256(f"{value}:{timestamp}:{self.secret_key}".encode()).hexdigest()
        payload = f"{value}:{timestamp}:{signature}"
        return payload
    
    def _decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt and verify a cookie value."""
        try:
            parts = encrypted_value.split(":")
            if len(parts) != 3:
                raise ValueError("Invalid cookie format")
                
            value, timestamp, signature = parts
            expected_signature = hashlib.sha256(f"{value}:{timestamp}:{self.secret_key}".encode()).hexdigest()
            
            # Verify signature (constant-time comparison)
            if not hashlib.compare_digest(signature, expected_signature):
                raise ValueError("Invalid signature")
                
            # Check if cookie is expired (optional)
            # if int(time.time()) - int(timestamp) > EXPIRY_TIME:
            #    raise ValueError("Cookie expired")
                
            return value
        except Exception as e:
            logger.error(f"Error decrypting cookie: {str(e)}")
            raise

class AntiDDoSProtection:
    """Implements protection mechanisms against DDoS attacks."""
    
    def __init__(self):
        # Track request count per IP
        self.request_counts: Dict[str, List[datetime]] = {}
        # Track global request count
        self.global_requests: List[datetime] = []
        self.ip_blacklist = IPBlacklist()
        self.lock = threading.RLock()
        
        # Configuration
        self.ip_rate_limit = 100  # Max requests per IP per minute
        self.global_rate_limit = 1000  # Max global requests per minute
        self.burst_threshold = 30  # Burst threshold per 5 seconds
        
    def is_allowed(self, ip: str) -> bool:
        """Check if a request should be allowed based on rate limiting."""
        # Check if IP is blacklisted
        if self.ip_blacklist.is_blacklisted(ip):
            return False
            
        with self.lock:
            current_time = datetime.now()
            minute_ago = current_time - timedelta(minutes=1)
            five_seconds_ago = current_time - timedelta(seconds=5)
            
            # Clean up old entries
            self._cleanup_old_entries(minute_ago)
            
            # Add current request
            if ip not in self.request_counts:
                self.request_counts[ip] = []
            self.request_counts[ip].append(current_time)
            self.global_requests.append(current_time)
            
            # Check IP-specific rate limit
            ip_count = len(self.request_counts[ip])
            if ip_count > self.ip_rate_limit:
                logger.warning(f"IP {ip} exceeded rate limit ({ip_count} requests/minute)")
                self.ip_blacklist.add_to_blacklist(ip, 30)  # Blacklist for 30 minutes
                
                # Log to audit logger
                get_audit_logger().log_security_event(
                    AuditEventType.SEC_RATE_LIMIT_EXCEEDED,
                    None,
                    ip,
                    None,
                    {"requests_per_minute": ip_count, "threshold": self.ip_rate_limit}
                )
                
                return False
            
            # Check burst rate (many requests in a short time period)
            burst_count = len([t for t in self.request_counts[ip] if t > five_seconds_ago])
            if burst_count > self.burst_threshold:
                logger.warning(f"IP {ip} exceeded burst threshold ({burst_count} requests/5sec)")
                self.ip_blacklist.add_to_blacklist(ip, 15)  # Blacklist for 15 minutes
                
                # Log to audit logger
                get_audit_logger().log_security_event(
                    AuditEventType.SEC_BURST_LIMIT_EXCEEDED,
                    None,
                    ip,
                    None,
                    {"requests_per_5sec": burst_count, "threshold": self.burst_threshold}
                )
                
                return False
            
            # Check global rate limit
            global_count = len(self.global_requests)
            if global_count > self.global_rate_limit:
                logger.warning(f"Global rate limit exceeded ({global_count} requests/minute)")
                
                # Log to audit logger
                get_audit_logger().log_security_event(
                    AuditEventType.SEC_GLOBAL_RATE_LIMIT_EXCEEDED,
                    None,
                    ip,
                    None,
                    {"requests_per_minute": global_count, "threshold": self.global_rate_limit}
                )
                
                # We could implement temporary global throttling here
                
                # Don't blacklist this specific IP since it might not be responsible
                # for the global rate limit being exceeded
                return True
            
            return True
    
    def _cleanup_old_entries(self, cutoff_time: datetime) -> None:
        """Remove entries older than the cutoff time."""
        # Clean up IP-specific entries
        for ip in list(self.request_counts.keys()):
            self.request_counts[ip] = [t for t in self.request_counts[ip] if t > cutoff_time]
            if not self.request_counts[ip]:
                del self.request_counts[ip]
        
        # Clean up global entries
        self.global_requests = [t for t in self.global_requests if t > cutoff_time]

class ServerHardening:
    """Implements server hardening measures."""
    
    def __init__(self):
        # Default secure configuration flags
        self.security_flags = {
            "hide_server_info": True,
            "disable_directory_listing": True,
            "disable_trace_track": True,
            "enforce_https": True,
            "limit_max_content_length": True,
            "enable_cors_protection": True,
        }
        
        # CORS settings
        self.cors_settings = {
            "allowed_origins": ["*"],  # Restrict this in production
            "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
            "allowed_headers": ["Content-Type", "Authorization"],
            "expose_headers": [],
            "allow_credentials": False,
            "max_age": 3600,
        }
        
        self.max_content_length = DEFAULT_MAX_CONTENT_LENGTH
    
    def get_hardening_middleware_config(self) -> Dict[str, Any]:
        """Get configuration for server hardening middleware."""
        return {
            "security_flags": self.security_flags,
            "cors_settings": self.cors_settings,
            "max_content_length": self.max_content_length,
        }
    
    def set_security_flag(self, flag_name: str, value: bool) -> None:
        """Set a specific security flag."""
        if flag_name in self.security_flags:
            self.security_flags[flag_name] = value
    
    def set_cors_setting(self, setting_name: str, value: Any) -> None:
        """Set a specific CORS setting."""
        if setting_name in self.cors_settings:
            self.cors_settings[setting_name] = value
    
    def set_max_content_length(self, max_length: int) -> None:
        """Set maximum allowed content length."""
        self.max_content_length = max_length

class DataEncryption:
    """Handles encryption for sensitive data."""
    
    def __init__(self, encryption_key: Optional[str] = None):
        # In a real application, use a proper key management system
        self.encryption_key = encryption_key or os.urandom(32).hex()
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data."""
        # In a real implementation, use a proper encryption library like cryptography
        # This is a simplified version for demonstration
        if not data:
            return data
            
        # Add a timestamp and random salt for uniqueness
        timestamp = int(time.time())
        salt = os.urandom(8).hex()
        
        # Create a signature
        signature = hashlib.sha256(f"{data}:{salt}:{timestamp}:{self.encryption_key}".encode()).hexdigest()
        
        # Return the combined payload
        return f"{salt}:{timestamp}:{signature}:{data}"
    
    def decrypt_data(self, encrypted_data: str) -> Optional[str]:
        """Decrypt encrypted data."""
        try:
            parts = encrypted_data.split(":", 3)
            if len(parts) != 4:
                return None
                
            salt, timestamp, signature, data = parts
            
            # Verify the signature
            expected_signature = hashlib.sha256(f"{data}:{salt}:{timestamp}:{self.encryption_key}".encode()).hexdigest()
            
            if not hashlib.compare_digest(signature, expected_signature):
                logger.warning("Data integrity check failed during decryption")
                return None
                
            return data
        except Exception as e:
            logger.error(f"Error decrypting data: {str(e)}")
            return None

class ProtectionMechanisms:
    """Main class that orchestrates all protection mechanisms."""
    
    def __init__(self):
        self.intrusion_detection = IntrusionDetectionSystem()
        self.csrf_protection = CSRFProtection()
        self.security_headers = SecurityHeadersManager()
        self.secure_cookies = SecureCookieManager()
        self.anti_ddos = AntiDDoSProtection()
        self.server_hardening = ServerHardening()
        self.data_encryption = DataEncryption()
        
        # Start maintenance threads
        self._start_maintenance_threads()
        
        logger.info("Protection mechanisms initialized")
    
    def _start_maintenance_threads(self) -> None:
        """Start maintenance threads for various protection mechanisms."""
        # Thread to clean up expired CSRF tokens
        def csrf_cleanup_task():
            while True:
                try:
                    self.csrf_protection.cleanup_expired_tokens()
                except Exception as e:
                    logger.error(f"Error in CSRF cleanup task: {str(e)}")
                time.sleep(3600)  # Run every hour
        
        # Start the thread
        threading.Thread(target=csrf_cleanup_task, daemon=True).start()
    
    def protect_request(self, request: Any) -> Tuple[bool, Optional[str], Dict[str, str]]:
        """
        Apply protection mechanisms to an incoming request.
        
        Args:
            request: The incoming request object
            
        Returns:
            Tuple of (allowed, error_message, headers)
        """
        client_ip = self._extract_client_ip(request)
        path = getattr(request, 'path', '')
        query_params = getattr(request, 'query_params', {})
        headers = getattr(request, 'headers', {})
        body = None
        
        # Try to get the request body if available
        try:
            if hasattr(request, 'json'):
                body = request.json
            elif hasattr(request, 'body'):
                body = request.body
        except:
            pass
        
        # Check rate limiting and DDoS protection
        if not self.anti_ddos.is_allowed(client_ip):
            return False, "Rate limit exceeded. Please try again later.", {}
        
        # Check intrusion detection
        if not self.intrusion_detection.check_request(client_ip, path, query_params, headers, body):
            return False, "Request blocked for security reasons.", {}
        
        # For POST/PUT/DELETE requests, verify CSRF token
        if getattr(request, 'method', '').upper() in ['POST', 'PUT', 'DELETE']:
            session_id = self._extract_session_id(request)
            csrf_token = headers.get('X-CSRF-Token', '')
            
            if session_id and not self.csrf_protection.validate_token(session_id, csrf_token):
                return False, "CSRF token validation failed.", {}
        
        # Get security headers for the response
        response_headers = self.security_headers.get_security_headers(path)
        
        # Everything passed, request is allowed
        return True, None, response_headers
    
    def _extract_client_ip(self, request: Any) -> str:
        """Extract the client IP from a request object."""
        if hasattr(request, 'headers'):
            # Try common proxy headers first
            for header in ['X-Forwarded-For', 'X-Real-IP']:
                if header in request.headers:
                    # Get the first IP in the list
                    return request.headers[header].split(',')[0].strip()
        
        # Fallback to direct client IP
        if hasattr(request, 'client'):
            if hasattr(request.client, 'host'):
                return request.client.host
        
        # Default fallback
        return "unknown"
    
    def _extract_session_id(self, request: Any) -> Optional[str]:
        """Extract the session ID from a request object."""
        # Try to get from cookies
        if hasattr(request, 'cookies') and 'session_id' in request.cookies:
            return request.cookies['session_id']
        
        # Try to get from headers
        if hasattr(request, 'headers'):
            return request.headers.get('X-Session-ID')
        
        return None
    
    def generate_csrf_token(self, session_id: str) -> str:
        """Generate a CSRF token for a session."""
        return self.csrf_protection.generate_token(session_id)
    
    def create_secure_cookie(self, name: str, value: str, **kwargs) -> Dict[str, Any]:
        """Create a secure cookie."""
        return self.secure_cookies.create_secure_cookie(name, value, **kwargs)
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data."""
        return self.data_encryption.encrypt_data(data)
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> Optional[str]:
        """Decrypt sensitive data."""
        return self.data_encryption.decrypt_data(encrypted_data)

# Create a global instance of the protection mechanisms
_protection_mechanisms: Optional[ProtectionMechanisms] = None

def get_protection_mechanisms() -> ProtectionMechanisms:
    """Get the global protection mechanisms instance."""
    global _protection_mechanisms
    if _protection_mechanisms is None:
        _protection_mechanisms = ProtectionMechanisms()
    return _protection_mechanisms

def protect_endpoint(func: Callable) -> Callable:
    """
    Decorator to protect an endpoint with security mechanisms.
    
    Args:
        func: The endpoint function to protect
        
    Returns:
        Decorated function
    """
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        # Get the protection mechanisms
        protection = get_protection_mechanisms()
        
        # Apply protection
        allowed, error_message, headers = protection.protect_request(request)
        
        if not allowed:
            # Return error response
            return {
                "status": "error",
                "code": 403,
                "error": error_message or "Access denied"
            }
        
        # Call the original function
        response = func(request, *args, **kwargs)
        
        # Add security headers to the response
        if isinstance(response, dict) and "headers" in response:
            response["headers"].update(headers)
        elif isinstance(response, dict):
            response["headers"] = headers
        
        return response
    
    return wrapper 