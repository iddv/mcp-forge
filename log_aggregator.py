#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Log Aggregator for MCP-Forge

This module provides log aggregation capabilities for the MCP-Forge framework,
collecting logs from all child MCP servers and the forge server itself.
It supports real-time aggregation, log filtering, and formatted output.
"""

import os
import re
import json
import time
import shutil
import asyncio
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Union, Tuple

from logging_system import LoggingSystem, get_logger

# Initialize logger
logger = get_logger("log_aggregator")

# Configure the aggregated logs directory
AGGREGATED_LOGS_DIR = Path("logs/aggregated")
if not AGGREGATED_LOGS_DIR.exists():
    AGGREGATED_LOGS_DIR.mkdir(parents=True, exist_ok=True)


class LogAggregator:
    """
    Log aggregation system for MCP-Forge that collects and processes logs
    from the forge server and all child MCP servers.
    """

    def __init__(self, logging_system: LoggingSystem):
        """
        Initialize the log aggregator with the provided logging system.
        
        Args:
            logging_system: The logging system to use for log aggregation
        """
        self.logging_system = logging_system
        self.aggregation_running = False
        self.log_patterns = {
            "error": re.compile(r"\[ERROR\]", re.IGNORECASE),
            "warning": re.compile(r"\[WARNING\]", re.IGNORECASE),
            "info": re.compile(r"\[INFO\]", re.IGNORECASE),
            "debug": re.compile(r"\[DEBUG\]", re.IGNORECASE),
        }
        self.aggregated_file = AGGREGATED_LOGS_DIR / "all_servers.log"
        self.error_file = AGGREGATED_LOGS_DIR / "errors_only.log"
        
        # Last processed positions in log files
        self.log_positions: Dict[str, int] = {}
        
        # Statistics for log entries
        self.stats = {
            "total_entries": 0,
            "error_entries": 0,
            "warning_entries": 0,
            "info_entries": 0,
            "debug_entries": 0,
            "by_component": {}
        }
        
        self._setup_aggregate_files()
    
    def _setup_aggregate_files(self) -> None:
        """Set up the aggregated log files."""
        # Ensure the aggregated logs directory exists
        AGGREGATED_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        
        # Make sure aggregated files exist
        for file_path in [self.aggregated_file, self.error_file]:
            if not file_path.exists():
                file_path.touch()

    async def start_aggregation(self, interval_seconds: int = 10) -> None:
        """
        Start log aggregation in a background task.
        
        Args:
            interval_seconds: Interval in seconds between aggregation runs
        """
        if self.aggregation_running:
            logger.warning("Log aggregation is already running")
            return
        
        self.aggregation_running = True
        logger.info(f"Starting log aggregation with interval of {interval_seconds} seconds")
        
        try:
            while self.aggregation_running:
                self.aggregate_logs()
                await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            logger.info("Log aggregation task was cancelled")
            self.aggregation_running = False
        except Exception as e:
            logger.error(f"Error in log aggregation: {e}")
            self.aggregation_running = False
            raise

    def stop_aggregation(self) -> None:
        """Stop the log aggregation process."""
        logger.info("Stopping log aggregation")
        self.aggregation_running = False

    def aggregate_logs(self) -> Dict[str, Any]:
        """
        Aggregate logs from all sources into centralized log files.
        
        Returns:
            Dictionary with aggregation statistics
        """
        start_time = time.time()
        log_files = self._get_all_log_files()
        
        new_entries = 0
        new_errors = 0
        
        # Process each log file
        for log_file in log_files:
            file_entries, file_errors = self._process_log_file(log_file)
            new_entries += file_entries
            new_errors += file_errors
        
        # Update statistics
        self.stats["total_entries"] += new_entries
        self.stats["error_entries"] += new_errors
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        logger.info(f"Aggregated {new_entries} log entries ({new_errors} errors) in {processing_time:.2f} seconds")
        
        return {
            "new_entries": new_entries,
            "new_errors": new_errors,
            "processing_time": processing_time,
            "total_stats": self.stats
        }

    def _get_all_log_files(self) -> List[Path]:
        """
        Get all log files from the log directory.
        
        Returns:
            List of Path objects for log files
        """
        log_dir = Path("logs")
        log_files = []
        
        # Get all .log files, excluding already aggregated logs
        for file_path in log_dir.glob("**/*.log"):
            if AGGREGATED_LOGS_DIR not in file_path.parents:
                log_files.append(file_path)
        
        return log_files

    def _process_log_file(self, log_file: Path) -> Tuple[int, int]:
        """
        Process a single log file and extract entries.
        
        Args:
            log_file: Path to the log file
            
        Returns:
            Tuple of (new entries count, new error entries count)
        """
        if not log_file.exists():
            return 0, 0
        
        # Get the last position we processed for this file
        last_position = self.log_positions.get(str(log_file), 0)
        current_size = log_file.stat().st_size
        
        # If file was truncated or rotated, reset position
        if current_size < last_position:
            last_position = 0
        
        # If no new content, skip processing
        if current_size <= last_position:
            return 0, 0
        
        new_entries = 0
        new_errors = 0
        
        try:
            with open(log_file, 'r') as f:
                # Skip to the last processed position
                if last_position > 0:
                    f.seek(last_position)
                
                # Process new lines
                new_lines = f.readlines()
                
                with open(self.aggregated_file, 'a') as aggregate_file:
                    with open(self.error_file, 'a') as error_file:
                        for line in new_lines:
                            # Add source file info to the line
                            source_info = f"[{log_file.stem}] "
                            enriched_line = line.rstrip() + "\n"
                            
                            # Write to aggregated log
                            aggregate_file.write(enriched_line)
                            new_entries += 1
                            
                            # Update component stats
                            component_match = re.search(r"\[([^\]]+)\]", line)
                            if component_match:
                                component = component_match.group(1)
                                if component not in self.stats["by_component"]:
                                    self.stats["by_component"][component] = 0
                                self.stats["by_component"][component] += 1
                            
                            # Check for errors and warnings
                            if self.log_patterns["error"].search(line):
                                error_file.write(enriched_line)
                                new_errors += 1
                                self.stats["error_entries"] += 1
                            elif self.log_patterns["warning"].search(line):
                                self.stats["warning_entries"] += 1
                            elif self.log_patterns["info"].search(line):
                                self.stats["info_entries"] += 1
                            elif self.log_patterns["debug"].search(line):
                                self.stats["debug_entries"] += 1
                
                # Update the last processed position
                self.log_positions[str(log_file)] = f.tell()
        
        except Exception as e:
            logger.error(f"Error processing log file {log_file}: {e}")
        
        return new_entries, new_errors

    def get_aggregated_logs(self, limit: int = 100, level: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get the most recent aggregated logs.
        
        Args:
            limit: Maximum number of log entries to return
            level: Filter logs by level (error, warning, info, debug)
            
        Returns:
            List of log entries as dictionaries
        """
        log_file = self.error_file if level == "error" else self.aggregated_file
        
        if not log_file.exists():
            return []
        
        logs = []
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                
                # Apply level filter if specified
                if level and level != "error":  # error already uses the error file
                    pattern = self.log_patterns.get(level.lower())
                    if pattern:
                        lines = [line for line in lines if pattern.search(line)]
                
                # Process the lines (newest first)
                for line in reversed(lines[:limit]):
                    try:
                        # Parse the log entry
                        parts = line.split(']')
                        if len(parts) >= 3:
                            timestamp_str = parts[0].strip('[')
                            level_str = parts[1].strip('[')
                            component = parts[2].strip('[')
                            message = ']'.join(parts[3:]).strip()
                            
                            logs.append({
                                "timestamp": timestamp_str,
                                "level": level_str,
                                "component": component,
                                "message": message
                            })
                    except Exception:
                        # Skip malformed log entries
                        continue
        except Exception as e:
            logger.error(f"Error reading aggregated logs: {e}")
        
        return logs[:limit]

    def get_log_statistics(self, time_period: str = "day") -> Dict[str, Any]:
        """
        Get statistics about the logs.
        
        Args:
            time_period: Time period for statistics (hour, day, week)
            
        Returns:
            Dictionary with log statistics
        """
        # Determine the cutoff time based on the time period
        now = datetime.now()
        if time_period == "hour":
            cutoff_time = now - timedelta(hours=1)
        elif time_period == "day":
            cutoff_time = now - timedelta(days=1)
        elif time_period == "week":
            cutoff_time = now - timedelta(weeks=1)
        else:
            cutoff_time = datetime(1970, 1, 1)  # All time
        
        stats = {
            "total_entries": 0,
            "error_entries": 0,
            "warning_entries": 0,
            "info_entries": 0,
            "debug_entries": 0,
            "by_component": {},
            "by_server": {},
            "time_period": time_period
        }
        
        try:
            with open(self.aggregated_file, 'r') as f:
                for line in f:
                    try:
                        # Parse timestamp
                        timestamp_str = line.split('[')[0].strip()
                        try:
                            log_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
                        except ValueError:
                            log_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        
                        # Skip if before cutoff time
                        if log_time < cutoff_time:
                            continue
                        
                        # Update total count
                        stats["total_entries"] += 1
                        
                        # Update level counts
                        if self.log_patterns["error"].search(line):
                            stats["error_entries"] += 1
                        elif self.log_patterns["warning"].search(line):
                            stats["warning_entries"] += 1
                        elif self.log_patterns["info"].search(line):
                            stats["info_entries"] += 1
                        elif self.log_patterns["debug"].search(line):
                            stats["debug_entries"] += 1
                        
                        # Update component counts
                        component_match = re.search(r"\[([^\]]+)\]", line)
                        if component_match:
                            component = component_match.group(1)
                            if component not in stats["by_component"]:
                                stats["by_component"][component] = 0
                            stats["by_component"][component] += 1
                        
                        # Extract server info (assuming format includes server ID)
                        server_match = re.search(r"child_server_([a-zA-Z0-9-]+)", line)
                        if server_match:
                            server_id = server_match.group(1)
                            if server_id not in stats["by_server"]:
                                stats["by_server"][server_id] = 0
                            stats["by_server"][server_id] += 1
                        elif "forge_mcp_server" in line:
                            if "forge" not in stats["by_server"]:
                                stats["by_server"]["forge"] = 0
                            stats["by_server"]["forge"] += 1
                        
                    except Exception:
                        # Skip malformed log entries
                        continue
        except Exception as e:
            logger.error(f"Error calculating log statistics: {e}")
        
        return stats

    def rotate_aggregated_logs(self, max_size_mb: int = 100) -> None:
        """
        Rotate aggregated log files if they exceed the maximum size.
        
        Args:
            max_size_mb: Maximum size in MB for log files before rotation
        """
        max_bytes = max_size_mb * 1024 * 1024
        
        for log_file in [self.aggregated_file, self.error_file]:
            if log_file.exists() and log_file.stat().st_size > max_bytes:
                # Create a timestamp for the rotated file
                timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                rotated_file = log_file.with_name(f"{log_file.stem}_{timestamp}.log")
                
                try:
                    # Rename the current file
                    shutil.copy2(log_file, rotated_file)
                    # Clear the current file
                    with open(log_file, 'w') as f:
                        f.write(f"# Log rotated at {datetime.now().isoformat()} - previous log at {rotated_file}\n")
                    
                    logger.info(f"Rotated log file {log_file} to {rotated_file}")
                except Exception as e:
                    logger.error(f"Error rotating log file {log_file}: {e}")

    def cleanup_old_aggregated_logs(self, days_to_keep: int = 30) -> None:
        """
        Clean up old aggregated log files.
        
        Args:
            days_to_keep: Number of days to keep rotated log files
        """
        now = time.time()
        cutoff_time = now - (days_to_keep * 24 * 60 * 60)
        
        for log_file in AGGREGATED_LOGS_DIR.glob("*_*.log"):  # Match rotated logs with timestamps
            file_mtime = log_file.stat().st_mtime
            if file_mtime < cutoff_time:
                try:
                    log_file.unlink()
                    logger.info(f"Deleted old aggregated log file: {log_file}")
                except Exception as e:
                    logger.error(f"Error deleting old aggregated log file {log_file}: {e}")


# Create singleton instance - will be used by the server
log_aggregator = None


def initialize_log_aggregator(logging_system: LoggingSystem) -> LogAggregator:
    """
    Initialize the log aggregator with the provided logging system.
    
    Args:
        logging_system: The logging system to use
        
    Returns:
        Initialized LogAggregator instance
    """
    global log_aggregator
    log_aggregator = LogAggregator(logging_system)
    return log_aggregator


async def start_aggregation_service(interval_seconds: int = 10) -> None:
    """
    Start the log aggregation service.
    
    Args:
        interval_seconds: Interval between aggregation runs
    """
    global log_aggregator
    if log_aggregator is None:
        from logging_system import logging_system
        log_aggregator = LogAggregator(logging_system)
    
    await log_aggregator.start_aggregation(interval_seconds)


if __name__ == "__main__":
    # Test the log aggregator
    from logging_system import configure_logging, logging_system
    
    # Configure logging system
    configure_logging({"log_level": logging.DEBUG})
    
    # Initialize log aggregator
    aggregator = LogAggregator(logging_system)
    
    # Test aggregation
    stats = aggregator.aggregate_logs()
    print(f"Aggregation stats: {json.dumps(stats, indent=2)}")
    
    # Get aggregated logs
    logs = aggregator.get_aggregated_logs(limit=10)
    print(f"Retrieved {len(logs)} aggregated log entries")
    
    # Get log statistics
    log_stats = aggregator.get_log_statistics(time_period="day")
    print(f"Log statistics: {json.dumps(log_stats, indent=2)}") 