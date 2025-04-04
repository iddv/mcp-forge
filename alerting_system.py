#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Alerting System for MCP-Forge

This module provides an alerting system for the MCP-Forge framework,
detecting critical issues and sending notifications through various channels.
It monitors server health, resource usage, and performance metrics.
"""

import os
import json
import time
import asyncio
import smtplib
import requests
from email.message import EmailMessage
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Union, Tuple, Callable

from logging_system import get_logger

# Initialize logger
logger = get_logger("alerting_system")

# Configure the alerts directory
ALERTS_DIR = Path("logs/alerts")
if not ALERTS_DIR.exists():
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)


class Alert:
    """Alert data structure to store information about an alert."""
    
    def __init__(self, 
                 alert_id: str,
                 severity: str,
                 source: str,
                 title: str,
                 message: str,
                 server_id: Optional[str] = None,
                 context: Optional[Dict[str, Any]] = None):
        """
        Initialize an Alert instance.
        
        Args:
            alert_id: Unique ID for the alert
            severity: Severity level (critical, high, medium, low, info)
            source: Source of the alert (e.g., "resource_monitor", "server_manager")
            title: Short title for the alert
            message: Detailed alert message
            server_id: ID of the server related to the alert (if applicable)
            context: Additional context information for the alert
        """
        self.alert_id = alert_id
        self.severity = severity
        self.source = source
        self.title = title
        self.message = message
        self.server_id = server_id
        self.context = context or {}
        self.timestamp = datetime.now()
        self.acknowledged = False
        self.acknowledged_by = None
        self.acknowledged_at = None
        self.resolved = False
        self.resolved_at = None
        self.resolution_message = None
    
    def acknowledge(self, user: str) -> None:
        """
        Acknowledge the alert.
        
        Args:
            user: User acknowledging the alert
        """
        self.acknowledged = True
        self.acknowledged_by = user
        self.acknowledged_at = datetime.now()
    
    def resolve(self, message: Optional[str] = None) -> None:
        """
        Mark the alert as resolved.
        
        Args:
            message: Resolution message
        """
        self.resolved = True
        self.resolved_at = datetime.now()
        self.resolution_message = message
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the alert to a dictionary.
        
        Returns:
            Dictionary representation of the alert
        """
        return {
            "alert_id": self.alert_id,
            "severity": self.severity,
            "source": self.source,
            "title": self.title,
            "message": self.message,
            "server_id": self.server_id,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "acknowledged": self.acknowledged,
            "acknowledged_by": self.acknowledged_by,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved": self.resolved,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution_message": self.resolution_message
        }


class NotificationChannel:
    """Base class for notification channels."""
    
    def __init__(self, name: str):
        """
        Initialize a notification channel.
        
        Args:
            name: Name of the notification channel
        """
        self.name = name
        self.enabled = True
    
    async def send_notification(self, alert: Alert) -> bool:
        """
        Send a notification through this channel.
        
        Args:
            alert: Alert to send notification for
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        raise NotImplementedError("NotificationChannel subclasses must implement send_notification")


class EmailNotificationChannel(NotificationChannel):
    """Email notification channel."""
    
    def __init__(self, 
                 name: str, 
                 smtp_server: str, 
                 smtp_port: int, 
                 username: str, 
                 password: str,
                 from_address: str,
                 to_addresses: List[str],
                 use_tls: bool = True):
        """
        Initialize an email notification channel.
        
        Args:
            name: Name of the notification channel
            smtp_server: SMTP server hostname
            smtp_port: SMTP server port
            username: SMTP username
            password: SMTP password
            from_address: Email address to send from
            to_addresses: List of email addresses to send to
            use_tls: Whether to use TLS for SMTP connection
        """
        super().__init__(name)
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_address = from_address
        self.to_addresses = to_addresses
        self.use_tls = use_tls
    
    async def send_notification(self, alert: Alert) -> bool:
        """
        Send an email notification.
        
        Args:
            alert: Alert to send notification for
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.enabled:
            return False
        
        # Build email message
        msg = EmailMessage()
        msg['Subject'] = f"[{alert.severity.upper()}] {alert.title}"
        msg['From'] = self.from_address
        msg['To'] = ', '.join(self.to_addresses)
        
        # Create email body
        body = f"""
        ALERT: {alert.title}
        SEVERITY: {alert.severity.upper()}
        SOURCE: {alert.source}
        TIME: {alert.timestamp.isoformat()}
        
        MESSAGE:
        {alert.message}
        """
        
        if alert.server_id:
            body += f"\nSERVER: {alert.server_id}"
        
        if alert.context:
            body += "\n\nCONTEXT:\n"
            for key, value in alert.context.items():
                body += f"{key}: {value}\n"
        
        msg.set_content(body)
        
        # Send email
        try:
            # Use asyncio to run SMTP operations in a thread pool
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._send_email, msg)
            return result
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
            return False
    
    def _send_email(self, msg: EmailMessage) -> bool:
        """
        Send an email message.
        
        Args:
            msg: Email message to send
            
        Returns:
            True if email was sent successfully, False otherwise
        """
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.send_message(msg)
            return True
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return False


class WebhookNotificationChannel(NotificationChannel):
    """Webhook notification channel for services like Slack, Discord, etc."""
    
    def __init__(self, name: str, webhook_url: str, custom_template: Optional[Dict[str, Any]] = None):
        """
        Initialize a webhook notification channel.
        
        Args:
            name: Name of the notification channel
            webhook_url: URL of the webhook
            custom_template: Custom template for formatting the webhook payload
        """
        super().__init__(name)
        self.webhook_url = webhook_url
        self.custom_template = custom_template
    
    async def send_notification(self, alert: Alert) -> bool:
        """
        Send a webhook notification.
        
        Args:
            alert: Alert to send notification for
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.enabled:
            return False
        
        # Create payload based on custom template or default
        if self.custom_template:
            payload = self._format_custom_payload(alert)
        else:
            payload = self._format_default_payload(alert)
        
        # Send webhook request
        try:
            # Use asyncio to run HTTP request in a thread pool
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._send_webhook, payload)
            return result
        except Exception as e:
            logger.error(f"Error sending webhook notification: {e}")
            return False
    
    def _format_default_payload(self, alert: Alert) -> Dict[str, Any]:
        """
        Format a default webhook payload.
        
        Args:
            alert: Alert to format payload for
            
        Returns:
            Formatted webhook payload
        """
        # Basic payload that works with most webhook services
        return {
            "text": f"[{alert.severity.upper()}] {alert.title}",
            "attachments": [
                {
                    "title": alert.title,
                    "color": self._get_color_for_severity(alert.severity),
                    "fields": [
                        {"title": "Severity", "value": alert.severity.upper(), "short": True},
                        {"title": "Source", "value": alert.source, "short": True},
                        {"title": "Server", "value": alert.server_id or "N/A", "short": True},
                        {"title": "Time", "value": alert.timestamp.isoformat(), "short": True}
                    ],
                    "text": alert.message
                }
            ]
        }
    
    def _format_custom_payload(self, alert: Alert) -> Dict[str, Any]:
        """
        Format a custom webhook payload using the provided template.
        
        Args:
            alert: Alert to format payload for
            
        Returns:
            Formatted webhook payload
        """
        # Start with a copy of the custom template
        payload = self.custom_template.copy()
        
        # Replace placeholders in the template
        self._replace_placeholders_recursive(payload, alert)
        
        return payload
    
    def _replace_placeholders_recursive(self, obj: Any, alert: Alert) -> None:
        """
        Recursively replace placeholders in an object with alert values.
        
        Args:
            obj: Object to replace placeholders in
            alert: Alert to get values from
        """
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, (dict, list)):
                    self._replace_placeholders_recursive(value, alert)
                elif isinstance(value, str):
                    obj[key] = self._replace_placeholders(value, alert)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    self._replace_placeholders_recursive(item, alert)
                elif isinstance(item, str):
                    obj[i] = self._replace_placeholders(item, alert)
    
    def _replace_placeholders(self, text: str, alert: Alert) -> str:
        """
        Replace placeholders in a string with alert values.
        
        Args:
            text: String to replace placeholders in
            alert: Alert to get values from
            
        Returns:
            String with placeholders replaced
        """
        # Replace alert attributes
        placeholders = {
            "{{alert_id}}": alert.alert_id,
            "{{severity}}": alert.severity,
            "{{severity_upper}}": alert.severity.upper(),
            "{{source}}": alert.source,
            "{{title}}": alert.title,
            "{{message}}": alert.message,
            "{{server_id}}": alert.server_id or "N/A",
            "{{timestamp}}": alert.timestamp.isoformat(),
            "{{color}}": self._get_color_for_severity(alert.severity)
        }
        
        # Replace context values
        for key, value in alert.context.items():
            placeholders[f"{{{{context.{key}}}}}"] = str(value)
        
        # Perform replacements
        result = text
        for placeholder, value in placeholders.items():
            result = result.replace(placeholder, value)
        
        return result
    
    def _send_webhook(self, payload: Dict[str, Any]) -> bool:
        """
        Send a webhook request.
        
        Args:
            payload: Webhook payload to send
            
        Returns:
            True if webhook was sent successfully, False otherwise
        """
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code < 400:
                return True
            else:
                logger.error(f"Webhook request failed with status {response.status_code}: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error sending webhook request: {e}")
            return False
    
    def _get_color_for_severity(self, severity: str) -> str:
        """
        Get a color code for a severity level.
        
        Args:
            severity: Severity level
            
        Returns:
            Color code for the severity
        """
        severity_colors = {
            "critical": "#FF0000",  # Red
            "high": "#FFA500",      # Orange
            "medium": "#FFFF00",    # Yellow
            "low": "#00FF00",       # Green
            "info": "#0000FF"       # Blue
        }
        
        return severity_colors.get(severity.lower(), "#808080")  # Default to gray


class AlertingSystem:
    """
    Alerting system for MCP-Forge that monitors the system for issues
    and sends notifications through configured channels.
    """
    
    def __init__(self):
        """Initialize the alerting system."""
        self.alerts: Dict[str, Alert] = {}
        self.notification_channels: Dict[str, NotificationChannel] = {}
        self.alerting_running = False
        self.alert_check_interval = 60  # seconds
        
        # Alert handlers for different types of checks
        self.alert_handlers: Dict[str, Callable] = {}
        
        # Alert history
        self.alert_history: List[Dict[str, Any]] = []
        self.max_history_size = 1000
        
        # Set up alerts directory
        self._setup_alerts_directory()
    
    def _setup_alerts_directory(self) -> None:
        """Set up the alerts directory."""
        ALERTS_DIR.mkdir(parents=True, exist_ok=True)
        
        # Create alerts history file
        history_file = ALERTS_DIR / "alert_history.json"
        if not history_file.exists():
            with open(history_file, 'w') as f:
                json.dump([], f)
    
    def register_notification_channel(self, channel: NotificationChannel) -> None:
        """
        Register a notification channel.
        
        Args:
            channel: Notification channel to register
        """
        self.notification_channels[channel.name] = channel
        logger.info(f"Registered notification channel: {channel.name}")
    
    def register_alert_handler(self, name: str, handler: Callable) -> None:
        """
        Register an alert handler function.
        
        Args:
            name: Name of the alert handler
            handler: Alert handler function
        """
        self.alert_handlers[name] = handler
        logger.info(f"Registered alert handler: {name}")
    
    async def start_alerting(self, interval_seconds: int = 60) -> None:
        """
        Start the alerting system background task.
        
        Args:
            interval_seconds: Interval in seconds between alert checks
        """
        if self.alerting_running:
            logger.warning("Alerting system is already running")
            return
        
        self.alerting_running = True
        self.alert_check_interval = interval_seconds
        logger.info(f"Starting alerting system with interval of {interval_seconds} seconds")
        
        try:
            while self.alerting_running:
                await self.check_all_alerts()
                await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            logger.info("Alerting system task was cancelled")
            self.alerting_running = False
        except Exception as e:
            logger.error(f"Error in alerting system: {e}")
            self.alerting_running = False
            raise
    
    def stop_alerting(self) -> None:
        """Stop the alerting system."""
        logger.info("Stopping alerting system")
        self.alerting_running = False
    
    async def check_all_alerts(self) -> List[Alert]:
        """
        Check all alert conditions.
        
        Returns:
            List of new alerts triggered
        """
        new_alerts = []
        
        # Run all alert handlers
        for handler_name, handler_func in self.alert_handlers.items():
            try:
                # Call the handler function
                handler_alerts = await self._run_alert_handler(handler_func)
                
                if handler_alerts:
                    new_alerts.extend(handler_alerts)
            except Exception as e:
                logger.error(f"Error running alert handler {handler_name}: {e}")
        
        # Process new alerts
        for alert in new_alerts:
            self._process_alert(alert)
        
        if new_alerts:
            logger.info(f"Generated {len(new_alerts)} new alerts")
        
        return new_alerts
    
    async def _run_alert_handler(self, handler: Callable) -> List[Alert]:
        """
        Run an alert handler function.
        
        Args:
            handler: Alert handler function
            
        Returns:
            List of alerts generated by the handler
        """
        # Handle both sync and async handlers
        if asyncio.iscoroutinefunction(handler):
            # Async handler
            return await handler()
        else:
            # Sync handler
            return handler()
    
    def _process_alert(self, alert: Alert) -> None:
        """
        Process a new alert.
        
        Args:
            alert: Alert to process
        """
        # Store alert
        self.alerts[alert.alert_id] = alert
        
        # Add to history
        alert_dict = alert.to_dict()
        self.alert_history.append(alert_dict)
        
        # Trim history if needed
        if len(self.alert_history) > self.max_history_size:
            self.alert_history = self.alert_history[-self.max_history_size:]
        
        # Save alert to disk
        self._save_alert(alert)
        
        # Update alert history file
        self._update_alert_history()
        
        # Send notifications
        asyncio.create_task(self._send_alert_notifications(alert))
    
    def _save_alert(self, alert: Alert) -> None:
        """
        Save an alert to disk.
        
        Args:
            alert: Alert to save
        """
        alert_file = ALERTS_DIR / f"alert_{alert.alert_id}.json"
        try:
            with open(alert_file, 'w') as f:
                json.dump(alert.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Error saving alert {alert.alert_id}: {e}")
    
    def _update_alert_history(self) -> None:
        """Update the alert history file."""
        history_file = ALERTS_DIR / "alert_history.json"
        try:
            with open(history_file, 'w') as f:
                json.dump(self.alert_history, f, indent=2)
        except Exception as e:
            logger.error(f"Error updating alert history: {e}")
    
    async def _send_alert_notifications(self, alert: Alert) -> None:
        """
        Send notifications for an alert through all channels.
        
        Args:
            alert: Alert to send notifications for
        """
        for channel_name, channel in self.notification_channels.items():
            try:
                success = await channel.send_notification(alert)
                if success:
                    logger.info(f"Sent alert notification through channel {channel_name}")
                else:
                    logger.warning(f"Failed to send alert notification through channel {channel_name}")
            except Exception as e:
                logger.error(f"Error sending notification through channel {channel_name}: {e}")
    
    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """
        Acknowledge an alert.
        
        Args:
            alert_id: ID of the alert to acknowledge
            user: User acknowledging the alert
            
        Returns:
            True if alert was acknowledged, False if alert not found
        """
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.acknowledge(user)
            
            # Update alert file
            self._save_alert(alert)
            
            # Update alert in history
            for entry in self.alert_history:
                if entry["alert_id"] == alert_id:
                    entry["acknowledged"] = True
                    entry["acknowledged_by"] = user
                    entry["acknowledged_at"] = alert.acknowledged_at.isoformat()
            
            # Update history file
            self._update_alert_history()
            
            logger.info(f"Alert {alert_id} acknowledged by {user}")
            return True
        else:
            logger.warning(f"Attempted to acknowledge unknown alert: {alert_id}")
            return False
    
    def resolve_alert(self, alert_id: str, message: Optional[str] = None) -> bool:
        """
        Resolve an alert.
        
        Args:
            alert_id: ID of the alert to resolve
            message: Resolution message
            
        Returns:
            True if alert was resolved, False if alert not found
        """
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.resolve(message)
            
            # Update alert file
            self._save_alert(alert)
            
            # Update alert in history
            for entry in self.alert_history:
                if entry["alert_id"] == alert_id:
                    entry["resolved"] = True
                    entry["resolved_at"] = alert.resolved_at.isoformat()
                    entry["resolution_message"] = message
            
            # Update history file
            self._update_alert_history()
            
            logger.info(f"Alert {alert_id} resolved")
            return True
        else:
            logger.warning(f"Attempted to resolve unknown alert: {alert_id}")
            return False
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """
        Get all active (unresolved) alerts.
        
        Returns:
            List of active alerts
        """
        active_alerts = []
        for alert in self.alerts.values():
            if not alert.resolved:
                active_alerts.append(alert.to_dict())
        
        # Sort by timestamp (newest first)
        active_alerts.sort(key=lambda a: a["timestamp"], reverse=True)
        
        return active_alerts
    
    def get_alert_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get alert history.
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of alerts from history
        """
        # Sort by timestamp (newest first)
        sorted_history = sorted(self.alert_history, key=lambda a: a["timestamp"], reverse=True)
        
        return sorted_history[:limit]
    
    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Get an alert by ID.
        
        Args:
            alert_id: ID of the alert to get
            
        Returns:
            Alert dictionary or None if not found
        """
        if alert_id in self.alerts:
            return self.alerts[alert_id].to_dict()
        return None


# Create singleton instance
alerting_system = AlertingSystem()


def get_alerting_system() -> AlertingSystem:
    """
    Get the singleton alerting system instance.
    
    Returns:
        AlertingSystem instance
    """
    global alerting_system
    return alerting_system


async def start_alerting_service(interval_seconds: int = 60) -> None:
    """
    Start the alerting service.
    
    Args:
        interval_seconds: Interval between alert checks
    """
    global alerting_system
    await alerting_system.start_alerting(interval_seconds)


if __name__ == "__main__":
    # Test the alerting system
    import asyncio
    import uuid
    
    async def test_alerting_system():
        # Initialize the alerting system
        alerter = get_alerting_system()
        
        # Register a webhook notification channel (replace with your webhook URL)
        webhook_url = "https://example.com/webhook"
        webhook_channel = WebhookNotificationChannel("test-webhook", webhook_url)
        alerter.register_notification_channel(webhook_channel)
        
        # Register a test alert handler
        def test_alert_handler():
            # Create a test alert
            alert_id = str(uuid.uuid4())
            alert = Alert(
                alert_id=alert_id,
                severity="high",
                source="test_handler",
                title="Test Alert",
                message="This is a test alert from the alerting system.",
                context={"test_key": "test_value"}
            )
            return [alert]
        
        alerter.register_alert_handler("test_handler", test_alert_handler)
        
        # Check alerts once
        new_alerts = await alerter.check_all_alerts()
        print(f"Generated {len(new_alerts)} test alerts")
        
        # Get active alerts
        active_alerts = alerter.get_active_alerts()
        print(f"Active alerts: {len(active_alerts)}")
        
        # Acknowledge and resolve an alert
        if new_alerts:
            alert_id = new_alerts[0].alert_id
            alerter.acknowledge_alert(alert_id, "test_user")
            alerter.resolve_alert(alert_id, "Test resolution")
        
        # Start alerting service
        alerting_task = asyncio.create_task(alerter.start_alerting(interval_seconds=5))
        
        # Let it run for a bit
        await asyncio.sleep(15)
        
        # Stop alerting
        alerter.stop_alerting()
        await alerting_task
        
        print("Alerting system test completed")
    
    asyncio.run(test_alerting_system()) 