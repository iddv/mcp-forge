#!/usr/bin/env python
"""
Server Manager for MCP-Forge

This module handles server instantiation, lifecycle management, and status tracking
for the MCP-Forge server framework.
"""

import logging
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# Setup logging
logger = logging.getLogger('server_manager')

# Optional resource monitoring if psutil is available
try:
    from resource_monitor import ResourceMonitor, create_resource_monitor
    resource_monitoring_available = True
except ImportError:
    resource_monitoring_available = False
    logger.warning("Resource monitoring is not available (psutil not installed)")

# Resource monitor singleton
resource_monitor = None

class ServerInstance:
    """Represents a managed MCP server instance."""
    
    def __init__(self, server_id, name, description, port, script_path):
        """Initialize a server instance."""
        self.id = server_id
        self.name = name
        self.description = description
        self.port = port
        self.script_path = script_path
        self.process = None
        self.started_at = None
        self.status = "initialized"  # initialized, running, stopped, error
        self.capabilities = []
        self.error = None
        self.restart_count = 0
        self.stdout_buffer = []
        self.stderr_buffer = []
        self.max_buffer_size = 100  # Maximum number of log lines to keep
        
    def start(self):
        """Start the server process."""
        if self.process and self.process.poll() is None:
            logger.warning(f"Server {self.id} is already running")
            return True
            
        try:
            logger.info(f"Starting server {self.id} on port {self.port}")
            
            # Set the MCP_PORT environment variable for the child process
            env = os.environ.copy()
            env["MCP_PORT"] = str(self.port)
            
            self.process = subprocess.Popen(
                [sys.executable, self.script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )
            self.started_at = datetime.now()
            self.status = "running"
            
            # Start threads to monitor stdout/stderr
            threading.Thread(target=self._monitor_output, args=(self.process.stdout, "stdout"), daemon=True).start()
            threading.Thread(target=self._monitor_output, args=(self.process.stderr, "stderr"), daemon=True).start()
            
            # Give it a moment to start up
            time.sleep(1)
            
            # Check if process is still running
            if self.process.poll() is not None:
                self.error = f"Server {self.id} failed to start (exit code: {self.process.poll()})"
                self.status = "error"
                logger.error(self.error)
                return False
                
            return True
        except Exception as e:
            self.error = f"Failed to start server {self.id}: {str(e)}"
            self.status = "error"
            logger.error(self.error)
            return False
            
    def stop(self):
        """Stop the server process."""
        if not self.process:
            logger.warning(f"Server {self.id} is not running")
            return
            
        try:
            logger.info(f"Stopping server {self.id}")
            
            self.process.terminate()
            
            # Give it a chance to terminate gracefully
            for _ in range(5):
                if self.process.poll() is not None:
                    break
                time.sleep(0.5)
                
            # Force kill if necessary
            if self.process.poll() is None:
                logger.warning(f"Server {self.id} did not terminate gracefully, forcing...")
                self.process.kill()
                
            self.status = "stopped"
            self.process = None
        except Exception as e:
            logger.error(f"Error stopping server {self.id}: {e}")
            self.status = "error"
            self.error = f"Error stopping server: {str(e)}"
    
    def restart(self):
        """Restart the server process."""
        logger.info(f"Restarting server {self.id}")
        self.stop()
        success = self.start()
        if success:
            self.restart_count += 1
        return success
            
    def get_info(self) -> Dict[str, Any]:
        """Get information about this server instance."""
        uptime = None
        if self.started_at and self.status == "running":
            uptime = (datetime.now() - self.started_at).total_seconds()
        
        info = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "port": self.port,
            "status": self.status,
            "uptime": uptime,
            "capabilities": self.capabilities,
            "script_path": self.script_path,
            "error": self.error,
            "restart_count": self.restart_count,
            "latest_logs": {
                "stdout": self.stdout_buffer[-10:] if self.stdout_buffer else [],
                "stderr": self.stderr_buffer[-10:] if self.stderr_buffer else []
            }
        }
        
        # Add resource monitoring information if available
        if resource_monitoring_available and resource_monitor and self.process:
            stats = resource_monitor.get_server_stats(self.id)
            if stats:
                info["resource_usage"] = {
                    "cpu_percent": stats.get("cpu_percent", 0.0),
                    "memory_mb": stats.get("memory_mb", 0.0),
                    "memory_percent": stats.get("memory_percent", 0.0),
                    "threads": stats.get("threads", 0)
                }
                
                # Add resource limits
                limits = resource_monitor.get_server_limits(self.id)
                if limits:
                    info["resource_limits"] = limits
                
        return info
        
    def get_logs(self, log_type="all", max_lines=50) -> Dict[str, List[str]]:
        """
        Get logs from the server process.
        
        Args:
            log_type: Type of logs to get ("stdout", "stderr", or "all")
            max_lines: Maximum number of lines to return
            
        Returns:
            Dictionary containing logs
        """
        result = {}
        
        if log_type in ("stdout", "all"):
            result["stdout"] = self.stdout_buffer[-max_lines:] if self.stdout_buffer else []
            
        if log_type in ("stderr", "all"):
            result["stderr"] = self.stderr_buffer[-max_lines:] if self.stderr_buffer else []
            
        return result
    
    def get_resource_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get resource statistics if available.
        
        Returns:
            Dictionary of resource statistics or None if not available
        """
        if not resource_monitoring_available or not resource_monitor or not self.process:
            return None
            
        return resource_monitor.get_server_stats(self.id)
    
    def get_resource_history(self, metric="cpu", points=10) -> Optional[List[Tuple[float, float]]]:
        """
        Get resource history for a specific metric if available.
        
        Args:
            metric: Metric to get history for (cpu, memory, io_read, io_write)
            points: Number of data points to return
            
        Returns:
            List of (timestamp, value) tuples or None if not available
        """
        if not resource_monitoring_available or not resource_monitor or not self.process:
            return None
            
        # This relies on the underlying process monitor's history functionality
        if hasattr(resource_monitor.process_monitor, 'get_process_history'):
            return resource_monitor.process_monitor.get_process_history(
                metric, server_id=self.id, points=points
            )
        return None
    
    def set_resource_limit(self, limit_name: str, limit_value: float) -> bool:
        """
        Set a resource limit for this server.
        
        Args:
            limit_name: Limit name (cpu_percent, memory_mb, etc.)
            limit_value: Limit value
            
        Returns:
            Boolean indicating success
        """
        if not resource_monitoring_available or not resource_monitor:
            return False
            
        return resource_monitor.set_server_limit(self.id, limit_name, limit_value)
    
    def get_resource_limits(self) -> Dict[str, float]:
        """
        Get resource limits for this server.
        
        Returns:
            Dictionary mapping limit names to limit values
        """
        if not resource_monitoring_available or not resource_monitor:
            return {}
            
        return resource_monitor.get_server_limits(self.id)
            
    def _monitor_output(self, pipe, name):
        """Monitor and log output from the server process."""
        buffer = self.stdout_buffer if name == "stdout" else self.stderr_buffer
        
        for line in pipe:
            line = line.strip()
            logger.info(f"[{self.id}:{name}] {line}")
            
            # Add to appropriate buffer, maintaining max size
            buffer.append(line)
            if len(buffer) > self.max_buffer_size:
                buffer.pop(0)

class ServerManager:
    """
    Manager for MCP-Forge server instances.
    Handles creation, starting, stopping, and management of server instances.
    """
    
    def __init__(self, servers_dir=None):
        """
        Initialize the server manager.
        
        Args:
            servers_dir: Directory to store server scripts
        """
        self.server_instances = {}
        self.next_port = None  # Will be initialized by the caller
        
        # Set servers directory
        if servers_dir is None:
            self.servers_dir = os.path.join(os.path.dirname(__file__), 'servers')
        else:
            self.servers_dir = servers_dir
            
        # Create servers directory if it doesn't exist
        os.makedirs(self.servers_dir, exist_ok=True)
        
        # Start resource monitor if available
        global resource_monitor
        if resource_monitoring_available and not resource_monitor:
            resource_monitor = create_resource_monitor(update_interval=5.0)
            resource_monitor.register_alert_callback(self._handle_resource_alert)
        
    def _handle_resource_alert(self, alert_type, data):
        """
        Handle alerts from the resource monitor.
        
        Args:
            alert_type: Type of alert
            data: Alert data
        """
        # Process alerts
        if alert_type == "process_ended":
            server_id = data.get("server_id")
            if server_id in self.server_instances:
                logger.warning(f"Process for server {server_id} ended unexpectedly")
                self.server_instances[server_id].status = "stopped"
                self.server_instances[server_id].process = None
        
        # Resource alerts
        elif alert_type == "high_system_cpu":
            logger.warning(f"High system CPU usage: {data.get('value')}% (threshold: {data.get('threshold')}%)")
        elif alert_type == "high_system_memory":
            logger.warning(f"High system memory usage: {data.get('value')}% (threshold: {data.get('threshold')}%)")
        elif alert_type == "high_system_disk":
            logger.warning(f"High system disk usage: {data.get('value')}% (threshold: {data.get('threshold')}%)")
        
        # Server-specific resource alerts
        elif alert_type == "resource_limit_violation":
            server_id = data.get("server_id")
            violations = data.get("violations", {})
            
            if server_id in self.server_instances:
                logger.warning(f"Resource limit violation for server {server_id}: {violations}")
        
        # Process-specific alerts
        elif alert_type == "high_cpu":
            server_id = data.get("server_id")
            if server_id in self.server_instances:
                logger.warning(f"High CPU usage detected for server {server_id}: {data.get('value')}%")
        elif alert_type == "high_memory":
            server_id = data.get("server_id")
            if server_id in self.server_instances:
                logger.warning(f"High memory usage detected for server {server_id}: {data.get('value')}%")
        
    def create_instance(self, server_id, name, description, script_path, capabilities=None) -> ServerInstance:
        """
        Create a new server instance.
        
        Args:
            server_id: Unique ID for the server
            name: Name of the server
            description: Description of the server
            script_path: Path to the server script
            capabilities: List of server capabilities
            
        Returns:
            The created server instance
        """
        server = ServerInstance(
            server_id=server_id,
            name=name,
            description=description,
            port=self.next_port,
            script_path=script_path
        )
        
        if capabilities:
            server.capabilities = capabilities
            
        self.server_instances[server_id] = server
        self.next_port += 1
        
        return server
    
    def instantiate_server(self, template_processor, server_id, name, description, capabilities=None, 
                           handlers=None, options=None) -> Tuple[bool, Optional[str], Optional[ServerInstance]]:
        """
        Instantiate a new server from a template.
        
        Args:
            template_processor: Template processor instance 
            server_id: Unique ID for the server
            name: Name of the server
            description: Description of the server
            capabilities: List of server capabilities
            handlers: List of additional handlers
            options: Dictionary of server options
            
        Returns:
            Tuple containing:
            - Boolean indicating success
            - Error message (None if successful)
            - ServerInstance object (None if failed)
        """
        try:
            # Create script file path
            script_filename = f"{server_id.replace('-', '_').replace(' ', '_').lower()}.py"
            script_path = os.path.join(self.servers_dir, script_filename)
            
            # Generate the server script
            template_processor.generate_server(
                output_path=script_path,
                server_name=server_id,
                server_port=self.next_port,
                description=description,
                capabilities=capabilities
            )
            
            # Apply customizations if needed
            if handlers or options:
                template_processor.customize_server(
                    script_path=script_path,
                    handlers=handlers,
                    options=options
                )
                
            # Create the server instance
            server = self.create_instance(
                server_id=server_id,
                name=name or server_id,
                description=description,
                script_path=script_path,
                capabilities=capabilities
            )
            
            return True, None, server
        except Exception as e:
            error_msg = f"Error creating server instance: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, None
    
    def get_instance(self, server_id) -> Optional[ServerInstance]:
        """
        Get a server instance by ID.
        
        Args:
            server_id: ID of the server
            
        Returns:
            ServerInstance object or None if not found
        """
        return self.server_instances.get(server_id)
    
    def get_all_instances(self) -> Dict[str, ServerInstance]:
        """
        Get all server instances.
        
        Returns:
            Dictionary of server instances
        """
        return self.server_instances
    
    def delete_instance(self, server_id) -> bool:
        """
        Delete a server instance.
        
        Args:
            server_id: ID of the server
            
        Returns:
            Boolean indicating success
        """
        if server_id not in self.server_instances:
            return False
            
        server = self.server_instances[server_id]
        
        # Stop the server if it's running
        if server.status == "running":
            server.stop()
            
        # Delete the server script
        try:
            if os.path.exists(server.script_path):
                os.remove(server.script_path)
        except Exception as e:
            logger.error(f"Error deleting server script: {e}")
            
        # Remove from instances
        del self.server_instances[server_id]
        
        return True
    
    def recover_instances(self):
        """Recover server instances from existing scripts."""
        try:
            # Look for server script files
            for script_file in os.listdir(self.servers_dir):
                if script_file.endswith('.py'):
                    script_path = os.path.join(self.servers_dir, script_file)
                    
                    # Try to extract server info from the file
                    with open(script_path, 'r') as f:
                        content = f.read()
                        
                    # Extract server parameters using regex
                    import re
                    server_id_match = re.search(r'SERVER_NAME\s*=\s*["\']([^"\']+)["\']', content)
                    port_match = re.search(r'SERVER_PORT\s*=\s*(\d+)', content)
                    desc_match = re.search(r'SERVER_DESCRIPTION\s*=\s*["\']([^"\']+)["\']', content)
                    capabilities_match = re.search(r'SERVER_CAPABILITIES\s*=\s*(\[.*?\])', content, re.DOTALL)
                    
                    if server_id_match and port_match:
                        server_id = server_id_match.group(1)
                        port = int(port_match.group(1))
                        description = desc_match.group(1) if desc_match else "Unknown"
                        
                        # Parse capabilities if available
                        capabilities = []
                        if capabilities_match:
                            try:
                                import json
                                capabilities = json.loads(capabilities_match.group(1))
                            except:
                                logger.warning(f"Failed to parse capabilities for server {server_id}")
                        
                        # Create server instance but don't start it
                        server = ServerInstance(
                            server_id=server_id,
                            name=server_id,
                            description=description,
                            port=port,
                            script_path=script_path
                        )
                        server.capabilities = capabilities
                        self.server_instances[server_id] = server
                        
                        # Update next port if necessary
                        if port >= self.next_port:
                            self.next_port = port + 1
                            
                        logger.info(f"Recovered server instance: {server_id} on port {port}")
        except Exception as e:
            logger.error(f"Error recovering server instances: {e}")
    
    def stop_all_servers(self):
        """Stop all running server instances."""
        for server_id, server in self.server_instances.items():
            if server.status == "running":
                server.stop()
        
        # Stop the resource monitor
        global resource_monitor
        if resource_monitoring_available and resource_monitor:
            resource_monitor.stop()
    
    def get_system_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get system-wide resource statistics.
        
        Returns:
            Dictionary containing system statistics or None if not available
        """
        if not resource_monitoring_available or not resource_monitor:
            return None
            
        return resource_monitor.get_current_stats()
    
    def get_all_resource_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Get resource statistics for all servers.
        
        Returns:
            Dictionary mapping server IDs to resource statistics
        """
        if not resource_monitoring_available or not resource_monitor:
            return {}
            
        return resource_monitor.get_all_server_stats()
    
    def set_default_resource_limit(self, limit_name: str, limit_value: float) -> bool:
        """
        Set a default resource limit for all servers.
        
        Args:
            limit_name: Limit name (cpu_percent, memory_mb, etc.)
            limit_value: Limit value
            
        Returns:
            Boolean indicating success
        """
        if not resource_monitoring_available or not resource_monitor:
            return False
            
        return resource_monitor.set_default_limit(limit_name, limit_value)
    
    def set_server_resource_limit(self, server_id: str, limit_name: str, limit_value: float) -> bool:
        """
        Set a resource limit for a specific server.
        
        Args:
            server_id: ID of the server
            limit_name: Limit name (cpu_percent, memory_mb, etc.)
            limit_value: Limit value
            
        Returns:
            Boolean indicating success
        """
        if server_id not in self.server_instances:
            return False
            
        return self.server_instances[server_id].set_resource_limit(limit_name, limit_value) 