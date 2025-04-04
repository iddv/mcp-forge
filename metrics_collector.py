#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Performance Metrics Collection System for MCP-Forge

This module provides metrics collection capabilities for the MCP-Forge framework,
gathering performance data from both the forge server and all child MCP servers.
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
logger = get_logger("metrics_collector")

# Configure the metrics directory
METRICS_DIR = Path("logs/metrics")
if not METRICS_DIR.exists():
    METRICS_DIR.mkdir(parents=True, exist_ok=True)


class MetricsCollector:
    """
    Performance metrics collection system for MCP-Forge that gathers and
    analyzes metrics from the forge server and all child MCP servers.
    """
    
    def __init__(self):
        """Initialize the metrics collector."""
        self.collection_running = False
        self.collection_interval = 60  # seconds
        self.metrics_data = {}
        self.server_metrics = {}
        self.system_metrics = {}
        self.history_retention = 24 * 60 * 60  # 1 day in seconds
        
        # Initialize metrics directory
        self._setup_metrics_directory()
    
    def _setup_metrics_directory(self) -> None:
        """Set up the metrics directory structure."""
        METRICS_DIR.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (METRICS_DIR / "system").mkdir(exist_ok=True)
        (METRICS_DIR / "servers").mkdir(exist_ok=True)
    
    async def start_collection(self, interval_seconds: int = 60) -> None:
        """
        Start metrics collection in a background task.
        
        Args:
            interval_seconds: Interval in seconds between collection runs
        """
        if self.collection_running:
            logger.warning("Metrics collection is already running")
            return
        
        self.collection_running = True
        self.collection_interval = interval_seconds
        logger.info(f"Starting metrics collection with interval of {interval_seconds} seconds")
        
        try:
            while self.collection_running:
                await self.collect_all_metrics()
                await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            logger.info("Metrics collection task was cancelled")
            self.collection_running = False
        except Exception as e:
            logger.error(f"Error in metrics collection: {e}")
            self.collection_running = False
            raise
    
    def stop_collection(self) -> None:
        """Stop the metrics collection process."""
        logger.info("Stopping metrics collection")
        self.collection_running = False
    
    async def collect_all_metrics(self) -> Dict[str, Any]:
        """
        Collect metrics from all available sources.
        
        Returns:
            Dictionary with collected metrics
        """
        # Get timestamp for this collection run
        timestamp = datetime.now().isoformat()
        
        # Collect system metrics
        system_metrics = self.collect_system_metrics()
        
        # Collect server metrics (requires server manager and process monitor)
        server_metrics = await self.collect_server_metrics()
        
        # Combine metrics
        metrics = {
            "timestamp": timestamp,
            "system": system_metrics,
            "servers": server_metrics
        }
        
        # Store metrics
        self.metrics_data[timestamp] = metrics
        self._store_metrics(metrics)
        
        # Clean up old metrics
        self._cleanup_old_metrics()
        
        logger.info(f"Collected metrics for {len(server_metrics)} servers")
        return metrics
    
    def collect_system_metrics(self) -> Dict[str, Any]:
        """
        Collect system-wide metrics.
        
        Returns:
            Dictionary with system metrics
        """
        try:
            # Collect CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.5)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Collect memory metrics
            memory = psutil.virtual_memory()
            
            # Collect disk metrics
            disk = psutil.disk_usage('/')
            
            # Collect network metrics
            net_io = psutil.net_io_counters()
            
            # Create metrics dictionary
            metrics = {
                "cpu": {
                    "percent": cpu_percent,
                    "count": cpu_count,
                    "frequency_mhz": cpu_freq.current if cpu_freq else None
                },
                "memory": {
                    "total_mb": memory.total / (1024 * 1024),
                    "available_mb": memory.available / (1024 * 1024),
                    "used_mb": memory.used / (1024 * 1024),
                    "percent": memory.percent
                },
                "disk": {
                    "total_gb": disk.total / (1024 * 1024 * 1024),
                    "used_gb": disk.used / (1024 * 1024 * 1024),
                    "free_gb": disk.free / (1024 * 1024 * 1024),
                    "percent": disk.percent
                },
                "network": {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                    "error_in": net_io.errin,
                    "error_out": net_io.errout,
                    "drop_in": net_io.dropin,
                    "drop_out": net_io.dropout
                }
            }
            
            # Update system metrics history
            self.system_metrics[datetime.now().isoformat()] = metrics
            
            return metrics
        
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {}
    
    async def collect_server_metrics(self) -> Dict[str, Dict[str, Any]]:
        """
        Collect metrics from all MCP servers.
        
        Returns:
            Dictionary mapping server IDs to metrics
        """
        # This is a placeholder - in actual implementation, this would
        # get metrics from the server_manager and process_monitor
        
        # Simulate collecting server metrics
        server_metrics = {}
        
        # In the real implementation, we would:
        # 1. Get list of servers from server_manager
        # 2. For each server, get its process info from process_monitor
        # 3. Collect metrics for each server process
        
        # For now, just return empty dict - this will be implemented
        # when integrated with the full system
        
        return server_metrics
    
    def get_metrics(self, time_period: str = "hour") -> Dict[str, Any]:
        """
        Get metrics for a specific time period.
        
        Args:
            time_period: Time period to get metrics for (hour, day, week, all)
            
        Returns:
            Dictionary with metrics for the specified time period
        """
        # Determine cutoff time
        now = datetime.now()
        if time_period == "hour":
            cutoff_time = now - timedelta(hours=1)
        elif time_period == "day":
            cutoff_time = now - timedelta(days=1)
        elif time_period == "week":
            cutoff_time = now - timedelta(weeks=1)
        else:
            # Return all metrics
            return self.metrics_data
        
        # Filter metrics by time period
        filtered_metrics = {}
        for timestamp, metrics in self.metrics_data.items():
            metric_time = datetime.fromisoformat(timestamp)
            if metric_time >= cutoff_time:
                filtered_metrics[timestamp] = metrics
        
        return filtered_metrics
    
    def get_server_metrics(self, server_id: str, time_period: str = "hour") -> List[Dict[str, Any]]:
        """
        Get metrics for a specific server over time.
        
        Args:
            server_id: ID of the server to get metrics for
            time_period: Time period to get metrics for (hour, day, week, all)
            
        Returns:
            List of metric data points for the server
        """
        # Get all metrics for the time period
        all_metrics = self.get_metrics(time_period)
        
        # Extract server metrics
        server_metrics = []
        for timestamp, metrics in all_metrics.items():
            if "servers" in metrics and server_id in metrics["servers"]:
                server_data = metrics["servers"][server_id]
                server_data["timestamp"] = timestamp
                server_metrics.append(server_data)
        
        return server_metrics
    
    def get_system_metrics(self, time_period: str = "hour") -> List[Dict[str, Any]]:
        """
        Get system metrics over time.
        
        Args:
            time_period: Time period to get metrics for (hour, day, week, all)
            
        Returns:
            List of system metric data points
        """
        # Get all metrics for the time period
        all_metrics = self.get_metrics(time_period)
        
        # Extract system metrics
        system_metrics = []
        for timestamp, metrics in all_metrics.items():
            if "system" in metrics:
                system_data = metrics["system"]
                system_data["timestamp"] = timestamp
                system_metrics.append(system_data)
        
        return system_metrics
    
    def _store_metrics(self, metrics: Dict[str, Any]) -> None:
        """
        Store metrics to disk.
        
        Args:
            metrics: Metrics to store
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        
        # Store system metrics
        if "system" in metrics:
            system_file = METRICS_DIR / "system" / f"system_{timestamp}.json"
            try:
                with open(system_file, 'w') as f:
                    json.dump(metrics["system"], f, indent=2)
            except Exception as e:
                logger.error(f"Error storing system metrics: {e}")
        
        # Store server metrics
        if "servers" in metrics:
            for server_id, server_metrics in metrics["servers"].items():
                server_dir = METRICS_DIR / "servers" / server_id
                server_dir.mkdir(exist_ok=True)
                
                server_file = server_dir / f"metrics_{timestamp}.json"
                try:
                    with open(server_file, 'w') as f:
                        json.dump(server_metrics, f, indent=2)
                except Exception as e:
                    logger.error(f"Error storing server metrics for {server_id}: {e}")
    
    def _cleanup_old_metrics(self) -> None:
        """Clean up old metrics data and files."""
        now = time.time()
        cutoff_time = now - self.history_retention
        
        # Clean up in-memory metrics
        for timestamp in list(self.metrics_data.keys()):
            try:
                metric_time = datetime.fromisoformat(timestamp).timestamp()
                if metric_time < cutoff_time:
                    del self.metrics_data[timestamp]
            except (ValueError, TypeError):
                # Skip invalid timestamps
                continue
        
        # Clean up metric files
        for system_file in (METRICS_DIR / "system").glob("system_*.json"):
            if system_file.stat().st_mtime < cutoff_time:
                try:
                    system_file.unlink()
                except Exception as e:
                    logger.error(f"Error deleting old system metrics file {system_file}: {e}")
        
        # Clean up server metrics files
        for server_dir in (METRICS_DIR / "servers").glob("*"):
            if server_dir.is_dir():
                for metric_file in server_dir.glob("metrics_*.json"):
                    if metric_file.stat().st_mtime < cutoff_time:
                        try:
                            metric_file.unlink()
                        except Exception as e:
                            logger.error(f"Error deleting old server metrics file {metric_file}: {e}")


# Create singleton instance
metrics_collector = MetricsCollector()


def get_metrics_collector() -> MetricsCollector:
    """
    Get the singleton metrics collector instance.
    
    Returns:
        MetricsCollector instance
    """
    global metrics_collector
    return metrics_collector


async def start_metrics_collection(interval_seconds: int = 60) -> None:
    """
    Start the metrics collection service.
    
    Args:
        interval_seconds: Interval between collection runs
    """
    global metrics_collector
    await metrics_collector.start_collection(interval_seconds)


if __name__ == "__main__":
    # Test the metrics collector
    import asyncio
    
    async def test_metrics_collector():
        # Initialize the metrics collector
        collector = get_metrics_collector()
        
        # Collect metrics once
        metrics = await collector.collect_all_metrics()
        print(f"Collected system metrics: {json.dumps(metrics['system'], indent=2)}")
        
        # Start collection service
        collection_task = asyncio.create_task(collector.start_collection(interval_seconds=5))
        
        # Let it run for a bit
        await asyncio.sleep(15)
        
        # Stop collection
        collector.stop_collection()
        await collection_task
        
        # Get metrics
        hour_metrics = collector.get_system_metrics(time_period="hour")
        print(f"Collected {len(hour_metrics)} system metric data points in the last hour")
        
        print("Metrics collection test completed")
    
    asyncio.run(test_metrics_collector()) 