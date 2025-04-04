#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Status Reporting System for MCP-Forge

This module provides comprehensive status reporting capabilities for the
MCP-Forge framework, including server health checks, resource usage,
and operational metrics for both the forge server and all child MCP servers.
"""

import os
import json
import time
import asyncio
import psutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Union, Tuple

from logging_system import get_logger

# Initialize logger
logger = get_logger("status_reporter")

# Configure the status reports directory
STATUS_DIR = Path("logs/status")
if not STATUS_DIR.exists():
    STATUS_DIR.mkdir(parents=True, exist_ok=True)


class ServerStatus:
    """
    Server status data structure to hold health and resource information
    for a MCP server instance.
    """
    
    def __init__(self, server_id: str, server_name: str, server_type: str = "child"):
        """
        Initialize a ServerStatus instance.
        
        Args:
            server_id: Unique ID of the server
            server_name: Name of the server
            server_type: Type of server ("forge" or "child")
        """
        self.server_id = server_id
        self.server_name = server_name
        self.server_type = server_type
        self.process_id = None
        self.start_time = None
        self.uptime = None
        self.status = "unknown"  # unknown, starting, running, stopping, stopped, error
        self.health = "unknown"  # unknown, healthy, degraded, unhealthy
        self.last_heartbeat = None
        self.cpu_percent = 0.0
        self.memory_percent = 0.0
        self.memory_mb = 0.0
        self.thread_count = 0
        self.open_files = 0
        self.connections = 0
        self.request_count = 0
        self.error_count = 0
        self.success_rate = 0.0
        self.response_time_ms = 0.0
        self.last_updated = datetime.now()
    
    def update_process_info(self, process_id: Optional[int] = None) -> bool:
        """
        Update process information for the server.
        
        Args:
            process_id: Process ID of the server (if known)
            
        Returns:
            True if process info was updated successfully, False otherwise
        """
        if process_id is not None:
            self.process_id = process_id
        
        if self.process_id is None:
            return False
        
        try:
            # Get process object
            process = psutil.Process(self.process_id)
            
            # Update process info
            self.cpu_percent = process.cpu_percent(interval=0.1)
            mem_info = process.memory_info()
            self.memory_mb = mem_info.rss / (1024 * 1024)
            self.memory_percent = process.memory_percent()
            self.thread_count = process.num_threads()
            self.open_files = len(process.open_files())
            self.connections = len(process.connections())
            
            # Update start time and uptime
            self.start_time = datetime.fromtimestamp(process.create_time())
            self.uptime = (datetime.now() - self.start_time).total_seconds()
            
            # Update status
            self.status = "running"
            self.last_updated = datetime.now()
            
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            self.status = "stopped"
            self.last_updated = datetime.now()
            return False
        except Exception as e:
            logger.error(f"Error updating process info for server {self.server_id}: {e}")
            return False
    
    def update_health(self, heartbeat_timeout_seconds: int = 30) -> None:
        """
        Update the health status of the server based on recent metrics.
        
        Args:
            heartbeat_timeout_seconds: Timeout in seconds for heartbeat
        """
        now = datetime.now()
        
        # Check status first
        if self.status != "running":
            self.health = "unhealthy"
            return
        
        # Check heartbeat
        if self.last_heartbeat is None:
            self.health = "unknown"
        elif (now - self.last_heartbeat).total_seconds() > heartbeat_timeout_seconds:
            self.health = "degraded"
        else:
            # Check resource usage thresholds
            if self.cpu_percent > 90 or self.memory_percent > 90:
                self.health = "degraded"
            else:
                # Check error rate
                if self.request_count > 0:
                    error_rate = self.error_count / self.request_count
                    if error_rate > 0.1:  # More than 10% errors
                        self.health = "degraded"
                    else:
                        self.health = "healthy"
                else:
                    self.health = "healthy"
        
        self.last_updated = now
    
    def record_heartbeat(self) -> None:
        """Record a heartbeat from the server."""
        self.last_heartbeat = datetime.now()
        if self.status == "running":
            self.update_health()
    
    def record_request(self, response_time_ms: float, is_error: bool = False) -> None:
        """
        Record a request processed by the server.
        
        Args:
            response_time_ms: Response time in milliseconds
            is_error: Whether the request resulted in an error
        """
        self.request_count += 1
        if is_error:
            self.error_count += 1
        
        # Update success rate
        if self.request_count > 0:
            self.success_rate = (self.request_count - self.error_count) / self.request_count
        
        # Update average response time (simple moving average)
        if self.response_time_ms == 0:
            self.response_time_ms = response_time_ms
        else:
            self.response_time_ms = (self.response_time_ms * 0.9) + (response_time_ms * 0.1)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the server status to a dictionary.
        
        Returns:
            Dictionary representation of the server status
        """
        return {
            "server_id": self.server_id,
            "server_name": self.server_name,
            "server_type": self.server_type,
            "process_id": self.process_id,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "uptime_seconds": self.uptime,
            "status": self.status,
            "health": self.health,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "resource_usage": {
                "cpu_percent": self.cpu_percent,
                "memory_mb": self.memory_mb,
                "memory_percent": self.memory_percent,
                "thread_count": self.thread_count,
                "open_files": self.open_files,
                "connections": self.connections
            },
            "performance": {
                "request_count": self.request_count,
                "error_count": self.error_count,
                "success_rate": self.success_rate,
                "response_time_ms": self.response_time_ms
            },
            "last_updated": self.last_updated.isoformat()
        }


class StatusReporter:
    """
    Status reporting system for MCP-Forge that tracks and reports on the
    health and performance of the forge server and all child MCP servers.
    """
    
    def __init__(self):
        """Initialize the status reporter."""
        self.servers: Dict[str, ServerStatus] = {}
        self.forge_status: Optional[ServerStatus] = None
        self.report_interval_seconds = 60
        self.reporting_running = False
        self.report_history: Dict[str, List[Dict[str, Any]]] = {}
        self.history_max_size = 100  # Maximum number of historical reports to keep per server
        
        # Initialize status report directory
        self._setup_status_directory()
    
    def _setup_status_directory(self) -> None:
        """Set up the status report directory."""
        STATUS_DIR.mkdir(parents=True, exist_ok=True)
        
        # Create status report file
        status_file = STATUS_DIR / "current_status.json"
        if not status_file.exists():
            with open(status_file, 'w') as f:
                json.dump({"timestamp": datetime.now().isoformat(), "servers": {}}, f)
    
    def register_forge_server(self, server_id: str, server_name: str, process_id: Optional[int] = None) -> ServerStatus:
        """
        Register the forge server for status tracking.
        
        Args:
            server_id: Unique ID of the forge server
            server_name: Name of the forge server
            process_id: Process ID of the forge server
            
        Returns:
            ServerStatus object for the forge server
        """
        self.forge_status = ServerStatus(server_id, server_name, server_type="forge")
        if process_id is not None:
            self.forge_status.process_id = process_id
            self.forge_status.update_process_info()
        
        self.report_history[server_id] = []
        logger.info(f"Registered forge server for status reporting: {server_name} (ID: {server_id})")
        return self.forge_status
    
    def register_child_server(self, server_id: str, server_name: str, process_id: Optional[int] = None) -> ServerStatus:
        """
        Register a child server for status tracking.
        
        Args:
            server_id: Unique ID of the child server
            server_name: Name of the child server
            process_id: Process ID of the child server
            
        Returns:
            ServerStatus object for the child server
        """
        server_status = ServerStatus(server_id, server_name, server_type="child")
        if process_id is not None:
            server_status.process_id = process_id
            server_status.update_process_info()
        
        self.servers[server_id] = server_status
        self.report_history[server_id] = []
        logger.info(f"Registered child server for status reporting: {server_name} (ID: {server_id})")
        return server_status
    
    def unregister_server(self, server_id: str) -> None:
        """
        Unregister a server from status tracking.
        
        Args:
            server_id: Unique ID of the server
        """
        if server_id in self.servers:
            server_name = self.servers[server_id].server_name
            logger.info(f"Unregistered child server from status reporting: {server_name} (ID: {server_id})")
            del self.servers[server_id]
    
    def update_server_status(self, server_id: str, **kwargs) -> Optional[ServerStatus]:
        """
        Update status information for a specific server.
        
        Args:
            server_id: Unique ID of the server
            **kwargs: Status attributes to update
            
        Returns:
            Updated ServerStatus object or None if server not found
        """
        if server_id == self.forge_status.server_id:
            server = self.forge_status
        elif server_id in self.servers:
            server = self.servers[server_id]
        else:
            logger.warning(f"Attempted to update unknown server: {server_id}")
            return None
        
        # Update process info if needed
        if "process_id" in kwargs and kwargs["process_id"] != server.process_id:
            server.process_id = kwargs["process_id"]
            server.update_process_info()
        
        # Update simple attributes
        for key, value in kwargs.items():
            if hasattr(server, key) and key != "process_id":  # process_id handled above
                setattr(server, key, value)
        
        # Update health status
        server.update_health()
        
        return server
    
    def record_heartbeat(self, server_id: str) -> None:
        """
        Record a heartbeat from a server.
        
        Args:
            server_id: Unique ID of the server
        """
        if server_id == self.forge_status.server_id:
            self.forge_status.record_heartbeat()
        elif server_id in self.servers:
            self.servers[server_id].record_heartbeat()
    
    def record_request(self, server_id: str, response_time_ms: float, is_error: bool = False) -> None:
        """
        Record a request processed by a server.
        
        Args:
            server_id: Unique ID of the server
            response_time_ms: Response time in milliseconds
            is_error: Whether the request resulted in an error
        """
        if server_id == self.forge_status.server_id:
            self.forge_status.record_request(response_time_ms, is_error)
        elif server_id in self.servers:
            self.servers[server_id].record_request(response_time_ms, is_error)
    
    def get_server_status(self, server_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the current status of a specific server.
        
        Args:
            server_id: Unique ID of the server
            
        Returns:
            Dictionary with server status or None if server not found
        """
        if server_id == self.forge_status.server_id:
            # Update process info before returning
            self.forge_status.update_process_info()
            return self.forge_status.to_dict()
        elif server_id in self.servers:
            # Update process info before returning
            self.servers[server_id].update_process_info()
            return self.servers[server_id].to_dict()
        return None
    
    def get_all_server_statuses(self) -> Dict[str, Dict[str, Any]]:
        """
        Get the current status of all servers.
        
        Returns:
            Dictionary mapping server IDs to status dictionaries
        """
        result = {}
        
        # Add forge server
        if self.forge_status:
            self.forge_status.update_process_info()
            result[self.forge_status.server_id] = self.forge_status.to_dict()
        
        # Add all child servers
        for server_id, server in self.servers.items():
            server.update_process_info()
            result[server_id] = server.to_dict()
        
        return result
    
    async def start_reporting(self, interval_seconds: int = 60) -> None:
        """
        Start the status reporting background task.
        
        Args:
            interval_seconds: Interval in seconds between reports
        """
        if self.reporting_running:
            logger.warning("Status reporting is already running")
            return
        
        self.reporting_running = True
        self.report_interval_seconds = interval_seconds
        logger.info(f"Starting status reporting with interval of {interval_seconds} seconds")
        
        try:
            while self.reporting_running:
                self.generate_status_report()
                await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            logger.info("Status reporting task was cancelled")
            self.reporting_running = False
        except Exception as e:
            logger.error(f"Error in status reporting: {e}")
            self.reporting_running = False
            raise
    
    def stop_reporting(self) -> None:
        """Stop the status reporting process."""
        logger.info("Stopping status reporting")
        self.reporting_running = False
    
    def generate_status_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive status report for all servers.
        
        Returns:
            Dictionary with the status report
        """
        # Update all server statuses
        all_statuses = self.get_all_server_statuses()
        
        # Calculate overall system stats
        total_servers = len(all_statuses)
        running_servers = sum(1 for s in all_statuses.values() if s["status"] == "running")
        healthy_servers = sum(1 for s in all_statuses.values() if s["health"] == "healthy")
        degraded_servers = sum(1 for s in all_statuses.values() if s["health"] == "degraded")
        unhealthy_servers = sum(1 for s in all_statuses.values() if s["health"] == "unhealthy")
        
        total_cpu = sum(s["resource_usage"]["cpu_percent"] for s in all_statuses.values())
        total_memory_mb = sum(s["resource_usage"]["memory_mb"] for s in all_statuses.values())
        
        total_requests = sum(s["performance"]["request_count"] for s in all_statuses.values())
        total_errors = sum(s["performance"]["error_count"] for s in all_statuses.values())
        overall_success_rate = 1.0 if total_requests == 0 else (total_requests - total_errors) / total_requests
        
        # Create the report
        timestamp = datetime.now()
        report = {
            "timestamp": timestamp.isoformat(),
            "overall": {
                "total_servers": total_servers,
                "running_servers": running_servers,
                "healthy_servers": healthy_servers,
                "degraded_servers": degraded_servers,
                "unhealthy_servers": unhealthy_servers,
                "total_cpu_percent": total_cpu,
                "total_memory_mb": total_memory_mb,
                "total_requests": total_requests,
                "total_errors": total_errors,
                "overall_success_rate": overall_success_rate
            },
            "servers": all_statuses
        }
        
        # Save the report
        self._save_status_report(report)
        
        # Update historical data
        self._update_historical_data(report)
        
        logger.info(f"Generated status report: {running_servers}/{total_servers} servers running, "
                   f"{healthy_servers} healthy, {degraded_servers} degraded, {unhealthy_servers} unhealthy")
        
        return report
    
    def _save_status_report(self, report: Dict[str, Any]) -> None:
        """
        Save a status report to disk.
        
        Args:
            report: Status report to save
        """
        # Save current status
        current_status_file = STATUS_DIR / "current_status.json"
        try:
            with open(current_status_file, 'w') as f:
                json.dump(report, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving current status report: {e}")
        
        # Save timestamped report
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        timestamped_file = STATUS_DIR / f"status_{timestamp}.json"
        try:
            with open(timestamped_file, 'w') as f:
                json.dump(report, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving timestamped status report: {e}")
    
    def _update_historical_data(self, report: Dict[str, Any]) -> None:
        """
        Update historical data for trend analysis.
        
        Args:
            report: Status report to add to history
        """
        timestamp = report["timestamp"]
        
        # Extract server-specific data and add to history
        for server_id, server_status in report["servers"].items():
            if server_id not in self.report_history:
                self.report_history[server_id] = []
            
            # Add historical data point
            history_entry = {
                "timestamp": timestamp,
                "status": server_status["status"],
                "health": server_status["health"],
                "cpu_percent": server_status["resource_usage"]["cpu_percent"],
                "memory_mb": server_status["resource_usage"]["memory_mb"],
                "request_count": server_status["performance"]["request_count"],
                "error_count": server_status["performance"]["error_count"],
                "response_time_ms": server_status["performance"]["response_time_ms"]
            }
            
            # Add to history and trim if needed
            self.report_history[server_id].append(history_entry)
            if len(self.report_history[server_id]) > self.history_max_size:
                self.report_history[server_id] = self.report_history[server_id][-self.history_max_size:]
    
    def get_server_history(self, server_id: str, time_period: str = "hour") -> List[Dict[str, Any]]:
        """
        Get historical data for a specific server.
        
        Args:
            server_id: Unique ID of the server
            time_period: Time period to get history for (hour, day, week, all)
            
        Returns:
            List of historical data points
        """
        if server_id not in self.report_history:
            return []
        
        # Determine cutoff time
        now = datetime.now()
        if time_period == "hour":
            cutoff_time = now - timedelta(hours=1)
        elif time_period == "day":
            cutoff_time = now - timedelta(days=1)
        elif time_period == "week":
            cutoff_time = now - timedelta(weeks=1)
        else:
            # Return all history
            return self.report_history[server_id]
        
        # Filter by time period
        filtered_history = []
        for entry in self.report_history[server_id]:
            entry_time = datetime.fromisoformat(entry["timestamp"])
            if entry_time >= cutoff_time:
                filtered_history.append(entry)
        
        return filtered_history
    
    def cleanup_old_reports(self, days_to_keep: int = 7) -> None:
        """
        Clean up old status reports.
        
        Args:
            days_to_keep: Number of days to keep reports
        """
        now = time.time()
        cutoff_time = now - (days_to_keep * 24 * 60 * 60)
        
        for report_file in STATUS_DIR.glob("status_*.json"):
            file_mtime = report_file.stat().st_mtime
            if file_mtime < cutoff_time:
                try:
                    report_file.unlink()
                    logger.info(f"Deleted old status report: {report_file}")
                except Exception as e:
                    logger.error(f"Error deleting old status report {report_file}: {e}")


# Create singleton instance
status_reporter = StatusReporter()


def get_status_reporter() -> StatusReporter:
    """
    Get the singleton status reporter instance.
    
    Returns:
        StatusReporter instance
    """
    global status_reporter
    return status_reporter


async def start_status_reporting(interval_seconds: int = 60) -> None:
    """
    Start the status reporting service.
    
    Args:
        interval_seconds: Interval between status reports
    """
    global status_reporter
    await status_reporter.start_reporting(interval_seconds)


if __name__ == "__main__":
    # Test the status reporter
    import asyncio
    
    async def test_status_reporter():
        # Initialize the status reporter
        reporter = get_status_reporter()
        
        # Register forge server
        forge = reporter.register_forge_server("forge-server", "MCP Forge Server", os.getpid())
        
        # Register some test child servers
        server1 = reporter.register_child_server("test-server-1", "Test Server 1", os.getpid())
        server2 = reporter.register_child_server("test-server-2", "Test Server 2", os.getpid())
        
        # Simulate some activity
        reporter.record_heartbeat("forge-server")
        reporter.record_request("forge-server", 150, False)
        reporter.record_request("forge-server", 250, False)
        reporter.record_request("forge-server", 350, True)
        
        reporter.record_heartbeat("test-server-1")
        reporter.record_request("test-server-1", 100, False)
        reporter.record_request("test-server-1", 200, False)
        
        # Generate a status report
        report = reporter.generate_status_report()
        print(f"Generated status report with {len(report['servers'])} servers")
        
        # Test start/stop reporting
        reporting_task = asyncio.create_task(reporter.start_reporting(interval_seconds=5))
        
        # Let it run for a bit
        await asyncio.sleep(15)
        
        # Stop reporting
        reporter.stop_reporting()
        await reporting_task
        
        print("Status reporting test completed")
    
    asyncio.run(test_status_reporter()) 