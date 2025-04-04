#!/usr/bin/env python
"""
Process Monitor for MCP-Forge

This module provides monitoring and tracking of child server processes
for the MCP-Forge server framework.
"""

import logging
import os
import psutil
import subprocess
import threading
import time
from typing import Dict, List, Optional, Any, Tuple, Callable

# Setup logging
logger = logging.getLogger('process_monitor')

class ProcessStats:
    """Represents statistics for a monitored process."""
    
    def __init__(self, pid: int, name: str, server_id: str):
        """
        Initialize process statistics.
        
        Args:
            pid: Process ID
            name: Process name
            server_id: Server ID associated with this process
        """
        self.pid = pid
        self.name = name
        self.server_id = server_id
        self.cpu_percent = 0.0
        self.memory_percent = 0.0
        self.memory_mb = 0.0
        self.threads = 0
        self.uptime = 0.0
        self.io_read_mb = 0.0
        self.io_write_mb = 0.0
        self.status = "unknown"
        self.last_updated = time.time()
        # Collection of historical data points for trending
        self.history = {
            "cpu": [],
            "memory": [],
            "io_read": [],
            "io_write": []
        }
        self.max_history_points = 100  # Number of data points to keep
        self.process = None
        
    def update(self, process: Optional[psutil.Process] = None) -> bool:
        """
        Update process statistics.
        
        Args:
            process: psutil.Process object or None to find by PID
            
        Returns:
            Boolean indicating if the update was successful
        """
        try:
            if process is None:
                # Try to get process by PID
                if not psutil.pid_exists(self.pid):
                    self.status = "not running"
                    return False
                    
                self.process = psutil.Process(self.pid)
            else:
                self.process = process
                
            # Gather basic process info
            self.name = self.process.name()
            self.status = self.process.status()
            self.threads = self.process.num_threads()
            self.uptime = time.time() - self.process.create_time()
            
            # CPU and memory usage
            self.cpu_percent = self.process.cpu_percent(interval=0.1)
            mem_info = self.process.memory_info()
            self.memory_mb = mem_info.rss / (1024 * 1024)  # Convert to MB
            self.memory_percent = self.process.memory_percent()
            
            # I/O statistics
            io_counters = self.process.io_counters() if hasattr(self.process, 'io_counters') else None
            if io_counters:
                self.io_read_mb = io_counters.read_bytes / (1024 * 1024)  # Convert to MB
                self.io_write_mb = io_counters.write_bytes / (1024 * 1024)  # Convert to MB
                
            # Update history
            current_time = time.time()
            time_diff = current_time - self.last_updated
            
            if time_diff >= 1.0:  # Only add a data point if at least 1 second has passed
                self.history["cpu"].append((current_time, self.cpu_percent))
                self.history["memory"].append((current_time, self.memory_mb))
                if io_counters:
                    self.history["io_read"].append((current_time, self.io_read_mb))
                    self.history["io_write"].append((current_time, self.io_write_mb))
                    
                # Trim history if needed
                for key in self.history:
                    if len(self.history[key]) > self.max_history_points:
                        self.history[key] = self.history[key][-self.max_history_points:]
                        
                self.last_updated = current_time
                
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logger.warning(f"Error updating process stats for PID {self.pid}: {e}")
            self.status = "error"
            return False
            
    def get_stats(self) -> Dict[str, Any]:
        """
        Get current process statistics.
        
        Returns:
            Dictionary containing process statistics
        """
        return {
            "pid": self.pid,
            "name": self.name,
            "server_id": self.server_id,
            "status": self.status,
            "uptime": self.uptime,
            "cpu_percent": self.cpu_percent,
            "memory_mb": self.memory_mb,
            "memory_percent": self.memory_percent,
            "threads": self.threads,
            "io_read_mb": self.io_read_mb,
            "io_write_mb": self.io_write_mb,
            "last_updated": self.last_updated
        }
        
    def get_history(self, metric: str, points: int = 10) -> List[Tuple[float, float]]:
        """
        Get historical data for a specific metric.
        
        Args:
            metric: Metric to get history for (cpu, memory, io_read, io_write)
            points: Number of data points to return
            
        Returns:
            List of (timestamp, value) tuples
        """
        if metric not in self.history:
            return []
            
        return self.history[metric][-points:]

class ProcessMonitor:
    """
    Process monitor for tracking server processes.
    """
    
    def __init__(self, update_interval: float = 5.0):
        """
        Initialize the process monitor.
        
        Args:
            update_interval: Interval in seconds between updates
        """
        self.processes = {}  # pid -> ProcessStats
        self.server_processes = {}  # server_id -> pid
        self.update_interval = update_interval
        self.running = False
        self.monitor_thread = None
        self.lock = threading.Lock()
        self.alert_callbacks = []
        
    def start(self):
        """Start the monitoring thread."""
        if self.running:
            return
            
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Process monitor started")
        
    def stop(self):
        """Stop the monitoring thread."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
            self.monitor_thread = None
            logger.info("Process monitor stopped")
            
    def add_process(self, pid: int, server_id: str) -> bool:
        """
        Add a process to monitor.
        
        Args:
            pid: Process ID
            server_id: Server ID associated with this process
            
        Returns:
            Boolean indicating if the process was added successfully
        """
        try:
            if not psutil.pid_exists(pid):
                logger.warning(f"Cannot add non-existent PID {pid}")
                return False
                
            process = psutil.Process(pid)
            name = process.name()
            
            with self.lock:
                # Create and initialize process stats
                stats = ProcessStats(pid, name, server_id)
                stats.update(process)
                
                # Store in mappings
                self.processes[pid] = stats
                self.server_processes[server_id] = pid
                
            logger.info(f"Added process {pid} ({name}) for server {server_id}")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.warning(f"Error adding process {pid}: {e}")
            return False
            
    def remove_process(self, pid: int = None, server_id: str = None) -> bool:
        """
        Remove a process from monitoring.
        
        Args:
            pid: Process ID (or None to use server_id)
            server_id: Server ID (or None to use pid)
            
        Returns:
            Boolean indicating if the process was removed
        """
        with self.lock:
            if pid is not None:
                if pid in self.processes:
                    server_id = self.processes[pid].server_id
                    del self.processes[pid]
                    if server_id in self.server_processes:
                        del self.server_processes[server_id]
                    logger.info(f"Removed process {pid} for server {server_id}")
                    return True
            elif server_id is not None:
                if server_id in self.server_processes:
                    pid = self.server_processes[server_id]
                    del self.server_processes[server_id]
                    if pid in self.processes:
                        del self.processes[pid]
                    logger.info(f"Removed process {pid} for server {server_id}")
                    return True
                    
            return False
            
    def get_process_stats(self, pid: int = None, server_id: str = None) -> Optional[Dict[str, Any]]:
        """
        Get statistics for a specific process.
        
        Args:
            pid: Process ID (or None to use server_id)
            server_id: Server ID (or None to use pid)
            
        Returns:
            Dictionary of process statistics or None if not found
        """
        with self.lock:
            if pid is not None:
                if pid in self.processes:
                    return self.processes[pid].get_stats()
            elif server_id is not None:
                if server_id in self.server_processes:
                    pid = self.server_processes[server_id]
                    if pid in self.processes:
                        return self.processes[pid].get_stats()
                        
            return None
            
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Get statistics for all monitored processes.
        
        Returns:
            Dictionary mapping server IDs to process statistics
        """
        result = {}
        
        with self.lock:
            for server_id, pid in self.server_processes.items():
                if pid in self.processes:
                    result[server_id] = self.processes[pid].get_stats()
                    
        return result
        
    def get_process_history(self, metric: str, pid: int = None, server_id: str = None, 
                           points: int = 10) -> Optional[List[Tuple[float, float]]]:
        """
        Get historical data for a specific process.
        
        Args:
            metric: Metric to get history for (cpu, memory, io_read, io_write)
            pid: Process ID (or None to use server_id)
            server_id: Server ID (or None to use pid)
            points: Number of data points to return
            
        Returns:
            List of (timestamp, value) tuples or None if not found
        """
        with self.lock:
            if pid is not None:
                if pid in self.processes:
                    return self.processes[pid].get_history(metric, points)
            elif server_id is not None:
                if server_id in self.server_processes:
                    pid = self.server_processes[server_id]
                    if pid in self.processes:
                        return self.processes[pid].get_history(metric, points)
                        
            return None
    
    def register_alert_callback(self, callback: Callable[[str, Dict[str, Any]], None]):
        """
        Register a callback function for alerts.
        
        Args:
            callback: Function that takes (alert_type, data) parameters
        """
        self.alert_callbacks.append(callback)
        
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
        
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                self._update_all_processes()
                self._check_resource_limits()
                time.sleep(self.update_interval)
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
                
    def _update_all_processes(self):
        """Update statistics for all monitored processes."""
        with self.lock:
            pids_to_remove = []
            
            for pid, stats in self.processes.items():
                if not stats.update():
                    # Process no longer exists
                    pids_to_remove.append(pid)
                    
            # Clean up dead processes
            for pid in pids_to_remove:
                server_id = self.processes[pid].server_id
                self._trigger_alert("process_ended", {
                    "pid": pid,
                    "server_id": server_id
                })
                self.remove_process(pid=pid)
                
    def _check_resource_limits(self):
        """Check if any processes exceed resource limits."""
        with self.lock:
            for pid, stats in self.processes.items():
                # Check CPU usage
                if stats.cpu_percent > 90:
                    self._trigger_alert("high_cpu", {
                        "pid": pid,
                        "server_id": stats.server_id,
                        "value": stats.cpu_percent
                    })
                    
                # Check memory usage
                if stats.memory_percent > 80:
                    self._trigger_alert("high_memory", {
                        "pid": pid,
                        "server_id": stats.server_id,
                        "value": stats.memory_percent
                    })

def get_system_stats() -> Dict[str, Any]:
    """
    Get system-wide resource statistics.
    
    Returns:
        Dictionary containing system statistics
    """
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_available_mb": memory.available / (1024 * 1024),
            "memory_total_mb": memory.total / (1024 * 1024),
            "disk_percent": disk.percent,
            "disk_free_mb": disk.free / (1024 * 1024),
            "disk_total_mb": disk.total / (1024 * 1024),
            "boot_time": psutil.boot_time(),
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return {
            "error": str(e),
            "timestamp": time.time()
        } 