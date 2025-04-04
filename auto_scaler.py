#!/usr/bin/env python
"""
Auto Scaler for MCP-Forge

This module provides auto-scaling capabilities for MCP-Forge server instances
based on resource usage and custom rules.
"""

import logging
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable, Tuple

# Setup logging
logger = logging.getLogger('auto_scaler')

class ScalingRule:
    """Represents a rule for auto-scaling server instances."""
    
    def __init__(self, name: str, metric: str, threshold: float, 
                action: str, cooldown: float = 60.0):
        """
        Initialize a scaling rule.
        
        Args:
            name: Rule name
            metric: Metric to monitor (cpu_percent, memory_percent, etc.)
            threshold: Threshold value for triggering the rule
            action: Action to take (scale_up, scale_down, restart, etc.)
            cooldown: Cooldown period in seconds between rule executions
        """
        self.name = name
        self.metric = metric
        self.threshold = threshold
        self.action = action
        self.cooldown = cooldown
        self.last_executed = 0.0  # timestamp
        self.execution_count = 0
        
    def check(self, metric_value: float) -> bool:
        """
        Check if the rule should be triggered.
        
        Args:
            metric_value: Current value of the metric
            
        Returns:
            Boolean indicating if the rule should be triggered
        """
        # Check if we're in the cooldown period
        if time.time() - self.last_executed < self.cooldown:
            return False
            
        # Check if the threshold is exceeded
        if self.action == "scale_up" and metric_value >= self.threshold:
            return True
        elif self.action == "scale_down" and metric_value <= self.threshold:
            return True
        elif self.action == "restart" and metric_value >= self.threshold:
            return True
            
        return False
        
    def execute(self) -> bool:
        """
        Execute the rule.
        
        Returns:
            Boolean indicating success
        """
        self.last_executed = time.time()
        self.execution_count += 1
        logger.info(f"Executed scaling rule: {self.name} (count: {self.execution_count})")
        return True
        
    def get_info(self) -> Dict[str, Any]:
        """
        Get information about the rule.
        
        Returns:
            Dictionary containing rule information
        """
        return {
            "name": self.name,
            "metric": self.metric,
            "threshold": self.threshold,
            "action": self.action,
            "cooldown": self.cooldown,
            "last_executed": self.last_executed,
            "execution_count": self.execution_count
        }

class ServerGroup:
    """Represents a group of server instances that can be scaled together."""
    
    def __init__(self, name: str, min_instances: int = 1, max_instances: int = 5,
                template_id: Optional[str] = None):
        """
        Initialize a server group.
        
        Args:
            name: Group name
            min_instances: Minimum number of instances
            max_instances: Maximum number of instances
            template_id: ID of the template to use for new instances
        """
        self.name = name
        self.min_instances = min_instances
        self.max_instances = max_instances
        self.template_id = template_id
        self.instance_ids = []  # List of server IDs in this group
        self.scaling_rules = []  # List of scaling rules for this group
        
    def add_rule(self, rule: ScalingRule) -> None:
        """
        Add a scaling rule to the group.
        
        Args:
            rule: Scaling rule to add
        """
        self.scaling_rules.append(rule)
        
    def add_instance(self, instance_id: str) -> None:
        """
        Add a server instance to the group.
        
        Args:
            instance_id: Server ID to add
        """
        if instance_id not in self.instance_ids:
            self.instance_ids.append(instance_id)
            
    def remove_instance(self, instance_id: str) -> None:
        """
        Remove a server instance from the group.
        
        Args:
            instance_id: Server ID to remove
        """
        if instance_id in self.instance_ids:
            self.instance_ids.remove(instance_id)
            
    def get_instance_count(self) -> int:
        """
        Get the number of instances in the group.
        
        Returns:
            Number of instances
        """
        return len(self.instance_ids)
        
    def can_scale_up(self) -> bool:
        """
        Check if the group can scale up.
        
        Returns:
            Boolean indicating if scaling up is possible
        """
        return self.get_instance_count() < self.max_instances
        
    def can_scale_down(self) -> bool:
        """
        Check if the group can scale down.
        
        Returns:
            Boolean indicating if scaling down is possible
        """
        return self.get_instance_count() > self.min_instances
        
    def get_info(self) -> Dict[str, Any]:
        """
        Get information about the group.
        
        Returns:
            Dictionary containing group information
        """
        return {
            "name": self.name,
            "min_instances": self.min_instances,
            "max_instances": self.max_instances,
            "template_id": self.template_id,
            "instance_count": self.get_instance_count(),
            "instances": self.instance_ids.copy(),
            "rules": [rule.get_info() for rule in self.scaling_rules]
        }

class AutoScaler:
    """
    Auto-scaler for MCP-Forge server instances.
    
    Monitors resource usage and applies scaling rules to keep resources
    within specified limits.
    """
    
    def __init__(self, update_interval: float = 30.0):
        """
        Initialize the auto-scaler.
        
        Args:
            update_interval: Interval in seconds between updates
        """
        self.server_groups = {}  # name -> ServerGroup
        self.update_interval = update_interval
        self.running = False
        self.monitor_thread = None
        self.lock = threading.Lock()
        
        # Callbacks
        self.scale_up_callback = None
        self.scale_down_callback = None
        self.restart_callback = None
        self.get_metrics_callback = None
        
    def start(self):
        """Start the auto-scaler."""
        if self.running:
            return
            
        if not self.get_metrics_callback:
            logger.warning("No metrics callback set, auto-scaler will not be effective")
            
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Auto-scaler started")
        
    def stop(self):
        """Stop the auto-scaler."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
            self.monitor_thread = None
            logger.info("Auto-scaler stopped")
            
    def create_group(self, name: str, min_instances: int = 1, max_instances: int = 5,
                    template_id: Optional[str] = None) -> ServerGroup:
        """
        Create a new server group.
        
        Args:
            name: Group name
            min_instances: Minimum number of instances
            max_instances: Maximum number of instances
            template_id: ID of the template to use for new instances
            
        Returns:
            The created ServerGroup
        """
        with self.lock:
            group = ServerGroup(
                name=name,
                min_instances=min_instances,
                max_instances=max_instances,
                template_id=template_id
            )
            self.server_groups[name] = group
            logger.info(f"Created server group: {name} (min={min_instances}, max={max_instances})")
            return group
            
    def delete_group(self, name: str) -> bool:
        """
        Delete a server group.
        
        Args:
            name: Group name
            
        Returns:
            Boolean indicating success
        """
        with self.lock:
            if name in self.server_groups:
                del self.server_groups[name]
                logger.info(f"Deleted server group: {name}")
                return True
            return False
            
    def add_rule(self, group_name: str, rule_name: str, metric: str, 
                threshold: float, action: str, cooldown: float = 60.0) -> bool:
        """
        Add a scaling rule to a group.
        
        Args:
            group_name: Group name
            rule_name: Rule name
            metric: Metric to monitor
            threshold: Threshold value
            action: Action to take
            cooldown: Cooldown period in seconds
            
        Returns:
            Boolean indicating success
        """
        with self.lock:
            if group_name not in self.server_groups:
                logger.warning(f"Cannot add rule to non-existent group: {group_name}")
                return False
                
            group = self.server_groups[group_name]
            rule = ScalingRule(
                name=rule_name,
                metric=metric,
                threshold=threshold,
                action=action,
                cooldown=cooldown
            )
            group.add_rule(rule)
            logger.info(f"Added scaling rule to group {group_name}: {rule_name} ({metric} {threshold} -> {action})")
            return True
            
    def add_instance(self, group_name: str, instance_id: str) -> bool:
        """
        Add a server instance to a group.
        
        Args:
            group_name: Group name
            instance_id: Server ID
            
        Returns:
            Boolean indicating success
        """
        with self.lock:
            if group_name not in self.server_groups:
                logger.warning(f"Cannot add instance to non-existent group: {group_name}")
                return False
                
            group = self.server_groups[group_name]
            group.add_instance(instance_id)
            logger.info(f"Added instance {instance_id} to group {group_name}")
            return True
            
    def remove_instance(self, group_name: str, instance_id: str) -> bool:
        """
        Remove a server instance from a group.
        
        Args:
            group_name: Group name
            instance_id: Server ID
            
        Returns:
            Boolean indicating success
        """
        with self.lock:
            if group_name not in self.server_groups:
                logger.warning(f"Cannot remove instance from non-existent group: {group_name}")
                return False
                
            group = self.server_groups[group_name]
            group.remove_instance(instance_id)
            logger.info(f"Removed instance {instance_id} from group {group_name}")
            return True
            
    def get_group(self, name: str) -> Optional[ServerGroup]:
        """
        Get a server group.
        
        Args:
            name: Group name
            
        Returns:
            ServerGroup or None if not found
        """
        with self.lock:
            return self.server_groups.get(name)
            
    def get_all_groups(self) -> Dict[str, ServerGroup]:
        """
        Get all server groups.
        
        Returns:
            Dictionary mapping group names to ServerGroup objects
        """
        with self.lock:
            return self.server_groups.copy()
            
    def set_scale_up_callback(self, callback: Callable[[str, ServerGroup], bool]) -> None:
        """
        Set the callback for scaling up.
        
        Args:
            callback: Function that takes (instance_id, group) parameters and returns success boolean
        """
        self.scale_up_callback = callback
        
    def set_scale_down_callback(self, callback: Callable[[str, ServerGroup], bool]) -> None:
        """
        Set the callback for scaling down.
        
        Args:
            callback: Function that takes (instance_id, group) parameters and returns success boolean
        """
        self.scale_down_callback = callback
        
    def set_restart_callback(self, callback: Callable[[str, ServerGroup], bool]) -> None:
        """
        Set the callback for restarting instances.
        
        Args:
            callback: Function that takes (instance_id, group) parameters and returns success boolean
        """
        self.restart_callback = callback
        
    def set_metrics_callback(self, callback: Callable[[str], Dict[str, float]]) -> None:
        """
        Set the callback for getting instance metrics.
        
        Args:
            callback: Function that takes (instance_id) parameter and returns metrics dictionary
        """
        self.get_metrics_callback = callback
        
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                self._check_scaling_rules()
                time.sleep(self.update_interval)
            except Exception as e:
                logger.error(f"Error in auto-scaler loop: {e}")
                
    def _check_scaling_rules(self):
        """Check scaling rules for all groups."""
        with self.lock:
            for group_name, group in self.server_groups.items():
                try:
                    self._check_group_rules(group)
                except Exception as e:
                    logger.error(f"Error checking rules for group {group_name}: {e}")
                    
    def _check_group_rules(self, group: ServerGroup):
        """
        Check scaling rules for a specific group.
        
        Args:
            group: ServerGroup to check
        """
        # Skip if no metrics callback
        if not self.get_metrics_callback:
            return
            
        # Check scaling rules for each instance
        for instance_id in group.instance_ids:
            try:
                # Get metrics for the instance
                metrics = self.get_metrics_callback(instance_id)
                if not metrics:
                    continue
                    
                # Check each rule
                for rule in group.scaling_rules:
                    if rule.metric not in metrics:
                        continue
                        
                    metric_value = metrics[rule.metric]
                    if rule.check(metric_value):
                        self._apply_rule(rule, instance_id, group)
            except Exception as e:
                logger.error(f"Error checking rules for instance {instance_id}: {e}")
                
    def _apply_rule(self, rule: ScalingRule, instance_id: str, group: ServerGroup) -> bool:
        """
        Apply a scaling rule.
        
        Args:
            rule: ScalingRule to apply
            instance_id: Server ID
            group: ServerGroup
            
        Returns:
            Boolean indicating success
        """
        # Execute the rule and update its state
        rule.execute()
        
        # Apply the action
        if rule.action == "scale_up" and self.scale_up_callback and group.can_scale_up():
            logger.info(f"Scaling up group {group.name} due to rule {rule.name}")
            return self.scale_up_callback(instance_id, group)
        elif rule.action == "scale_down" and self.scale_down_callback and group.can_scale_down():
            logger.info(f"Scaling down group {group.name} due to rule {rule.name}")
            return self.scale_down_callback(instance_id, group)
        elif rule.action == "restart" and self.restart_callback:
            logger.info(f"Restarting instance {instance_id} due to rule {rule.name}")
            return self.restart_callback(instance_id, group)
            
        return False

# Global auto-scaler instance
_auto_scaler = None

def get_auto_scaler() -> AutoScaler:
    """
    Get the global auto-scaler instance.
    
    Returns:
        AutoScaler instance
    """
    global _auto_scaler
    if _auto_scaler is None:
        _auto_scaler = AutoScaler()
    return _auto_scaler 