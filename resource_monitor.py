#!/usr/bin/env python
"""
Resource Monitor for MCP-Forge

This module provides system-wide resource monitoring, alerts, and limit enforcement
for the MCP-Forge server framework.
"""

import logging
import os
import psutil
import threading
import time
from typing import Dict, List, Optional, Any, Callable, Tuple

from process_monitor import ProcessMonitor, get_system_stats

# Setup logging
logger = logging.getLogger('resource_monitor')

class ResourceMonitor:
    """
    Resource monitor for tracking system resources and enforcing limits.
    """
    
    def __init__(self, process_monitor: Optional[ProcessMonitor] = None, 
                update_interval: float = 10.0,
                memory_threshold: float = 80.0,  # percent
                cpu_threshold: float = 80.0,     # percent
                disk_threshold: float = 80.0):   # percent
        """
        Initialize the resource monitor.
        
        Args:
            process_monitor: Process monitor instance or None to create a new one
            update_interval: Interval in seconds between updates
            memory_threshold: Memory usage threshold percentage for system-wide alerts
            cpu_threshold: CPU usage threshold percentage for system-wide alerts
            disk_threshold: Disk usage threshold percentage for system-wide alerts
        """
        # Set thresholds
        self.memory_threshold = memory_threshold
        self.cpu_threshold = cpu_threshold
        self.disk_threshold = disk_threshold
        
        # Set update interval
        self.update_interval = update_interval
        
        # Initialize process monitor if not provided
        self.process_monitor = process_monitor or ProcessMonitor()
        
        # Monitoring thread
        self.running = False
        self.monitor_thread = None
        
        # Alert callbacks
        self.alert_callbacks = []
        
        # Resource history tracking
        self.history = {
            "cpu": [],
            "memory": [],
            "disk": []
        }
        self.max_history_points = 100
        
        # Resource limits for servers
        self.server_limits = {}  # server_id -> {limit_name: limit_value}
        self.default_limits = {
            "cpu_percent": 50.0,
            "memory_mb": 500.0
        }
        
    def start(self):
        """Start the monitoring thread."""
        if self.running:
            return
            
        # Start process monitor first
        if not self.process_monitor.running:
            self.process_monitor.start()
            
        # Start our monitoring thread
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Resource monitor started")
        
    def stop(self):
        """Stop the monitoring thread."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
            self.monitor_thread = None
            logger.info("Resource monitor stopped")
            
        # Stop process monitor
        if self.process_monitor.running:
            self.process_monitor.stop()
            
    def register_alert_callback(self, callback: Callable[[str, Dict[str, Any]], None]):
        """
        Register a callback function for alerts.
        
        Args:
            callback: Function that takes (alert_type, data) parameters
        """
        self.alert_callbacks.append(callback)
        
        # Also register it with the process monitor
        if self.process_monitor:
            self.process_monitor.register_alert_callback(callback)
        
    def _trigger_alert(self, alert_type: str, data: Dict[str, Any]):
        """
        Trigger an alert.
        
        Args:
            alert_type: Type of alert
            data: Alert data
        """
        for callback in self.alert_callbacks:
            try:
                callback(alert_type, data)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
                
    def get_current_stats(self) -> Dict[str, Any]:
        """
        Get current system resource statistics.
        
        Returns:
            Dictionary containing system resource statistics
        """
        return get_system_stats()
    
    def get_server_stats(self, server_id: str) -> Optional[Dict[str, Any]]:
        """
        Get resource statistics for a specific server.
        
        Args:
            server_id: Server ID
            
        Returns:
            Dictionary containing server resource statistics or None if not found
        """
        if not self.process_monitor:
            return None
            
        return self.process_monitor.get_process_stats(server_id=server_id)
    
    def get_all_server_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Get resource statistics for all servers.
        
        Returns:
            Dictionary mapping server IDs to resource statistics
        """
        if not self.process_monitor:
            return {}
            
        return self.process_monitor.get_all_stats()
    
    def get_history(self, resource_type: str, points: int = 10) -> List[Tuple[float, float]]:
        """
        Get historical data for a specific resource.
        
        Args:
            resource_type: Resource type (cpu, memory, disk)
            points: Number of data points to return
            
        Returns:
            List of (timestamp, value) tuples
        """
        if resource_type not in self.history:
            return []
            
        return self.history[resource_type][-points:]
    
    def set_server_limit(self, server_id: str, limit_name: str, limit_value: float) -> bool:
        """
        Set a resource limit for a specific server.
        
        Args:
            server_id: Server ID
            limit_name: Limit name (cpu_percent, memory_mb, etc.)
            limit_value: Limit value
            
        Returns:
            Boolean indicating success
        """
        if server_id not in self.server_limits:
            self.server_limits[server_id] = {}
            
        self.server_limits[server_id][limit_name] = limit_value
        logger.info(f"Set {limit_name} limit for server {server_id} to {limit_value}")
        return True
    
    def get_server_limits(self, server_id: str) -> Dict[str, float]:
        """
        Get resource limits for a specific server.
        
        Args:
            server_id: Server ID
            
        Returns:
            Dictionary mapping limit names to limit values
        """
        # Return server-specific limits merged with defaults
        result = self.default_limits.copy()
        
        if server_id in self.server_limits:
            result.update(self.server_limits[server_id])
            
        return result
    
    def set_default_limit(self, limit_name: str, limit_value: float) -> bool:
        """
        Set a default resource limit for all servers.
        
        Args:
            limit_name: Limit name (cpu_percent, memory_mb, etc.)
            limit_value: Limit value
            
        Returns:
            Boolean indicating success
        """
        self.default_limits[limit_name] = limit_value
        logger.info(f"Set default {limit_name} limit to {limit_value}")
        return True
    
    def check_resource_limits(self, server_id: str, stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if a server exceeds its resource limits.
        
        Args:
            server_id: Server ID
            stats: Server statistics
            
        Returns:
            Dictionary containing limit violations (empty if none)
        """
        limits = self.get_server_limits(server_id)
        violations = {}
        
        # Check CPU limit
        if "cpu_percent" in limits and "cpu_percent" in stats:
            if stats["cpu_percent"] > limits["cpu_percent"]:
                violations["cpu"] = {
                    "limit": limits["cpu_percent"],
                    "actual": stats["cpu_percent"]
                }
                
        # Check memory limit
        if "memory_mb" in limits and "memory_mb" in stats:
            if stats["memory_mb"] > limits["memory_mb"]:
                violations["memory"] = {
                    "limit": limits["memory_mb"],
                    "actual": stats["memory_mb"]
                }
                
        return violations
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                # Get system stats
                stats = self.get_current_stats()
                current_time = time.time()
                
                # Update history
                self.history["cpu"].append((current_time, stats["cpu_percent"]))
                self.history["memory"].append((current_time, stats["memory_percent"]))
                self.history["disk"].append((current_time, stats["disk_percent"]))
                
                # Trim history if needed
                for key in self.history:
                    if len(self.history[key]) > self.max_history_points:
                        self.history[key] = self.history[key][-self.max_history_points:]
                
                # Check system-wide resource thresholds
                if stats["cpu_percent"] > self.cpu_threshold:
                    self._trigger_alert("high_system_cpu", {
                        "value": stats["cpu_percent"],
                        "threshold": self.cpu_threshold
                    })
                    
                if stats["memory_percent"] > self.memory_threshold:
                    self._trigger_alert("high_system_memory", {
                        "value": stats["memory_percent"],
                        "threshold": self.memory_threshold
                    })
                    
                if stats["disk_percent"] > self.disk_threshold:
                    self._trigger_alert("high_system_disk", {
                        "value": stats["disk_percent"],
                        "threshold": self.disk_threshold
                    })
                
                # Check server resource limits
                self._check_server_limits()
                
                time.sleep(self.update_interval)
            except Exception as e:
                logger.error(f"Error in resource monitor loop: {e}")
                
    def _check_server_limits(self):
        """Check resource limits for all servers."""
        try:
            # Get stats for all servers
            all_stats = self.get_all_server_stats()
            
            for server_id, stats in all_stats.items():
                violations = self.check_resource_limits(server_id, stats)
                
                if violations:
                    self._trigger_alert("resource_limit_violation", {
                        "server_id": server_id,
                        "violations": violations
                    })
        except Exception as e:
            logger.error(f"Error checking server limits: {e}")

def create_resource_monitor(process_monitor=None, update_interval=10.0):
    """
    Create and start a resource monitor.
    
    Args:
        process_monitor: Process monitor instance or None to create a new one
        update_interval: Interval in seconds between updates
        
    Returns:
        Started ResourceMonitor instance
    """
    monitor = ResourceMonitor(
        process_monitor=process_monitor,
        update_interval=update_interval
    )
    monitor.start()
    return monitor 