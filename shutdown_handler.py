#!/usr/bin/env python
"""
Shutdown Handler for MCP-Forge

This module provides graceful shutdown mechanisms for the MCP-Forge server
and its child processes.
"""

import atexit
import logging
import os
import signal
import sys
import threading
import time
from typing import Dict, List, Optional, Any, Callable

# Setup logging
logger = logging.getLogger('shutdown_handler')

class ShutdownHandler:
    """
    Handler for graceful shutdowns of the MCP-Forge server and child processes.
    """
    
    def __init__(self):
        """Initialize the shutdown handler."""
        self.shutdown_hooks = []
        self.shutdown_in_progress = False
        self.shutdown_timeout = 30.0  # seconds
        self.shutdown_hooks_lock = threading.Lock()
        
        # Flag to indicate if shutdown was already reported to avoid duplicate logs
        self.shutdown_reported = False
        
        # Store original signal handlers
        self._original_sigint_handler = signal.getsignal(signal.SIGINT)
        self._original_sigterm_handler = signal.getsignal(signal.SIGTERM)
        if hasattr(signal, 'SIGHUP'):
            self._original_sighup_handler = signal.getsignal(signal.SIGHUP)
        else:
            self._original_sighup_handler = None
        
        # Register signal handlers
        self._register_signal_handlers()
        
        # Register atexit handler
        atexit.register(self.execute_shutdown)
        
    def _register_signal_handlers(self):
        """Register signal handlers for graceful shutdown."""
        try:
            # Register SIGTERM handler (termination signal)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            # Register SIGINT handler (interrupt from keyboard)
            signal.signal(signal.SIGINT, self._signal_handler)
            
            # On Unix-like systems, also register SIGHUP
            if hasattr(signal, 'SIGHUP'):
                signal.signal(signal.SIGHUP, self._signal_handler)
                
            logger.info("Registered shutdown signal handlers")
        except Exception as e:
            logger.error(f"Error registering signal handlers: {e}")
            
    def _signal_handler(self, signum, frame):
        """
        Handle shutdown signals.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        if not self.shutdown_reported:
            signal_names = {
                signal.SIGTERM: "SIGTERM",
                signal.SIGINT: "SIGINT"
            }
            if hasattr(signal, 'SIGHUP'):
                signal_names[signal.SIGHUP] = "SIGHUP"
                
            signal_name = signal_names.get(signum, str(signum))
            logger.info(f"Received {signal_name} signal, initiating graceful shutdown")
            self.shutdown_reported = True
            
        # Execute shutdown hooks
        self.execute_shutdown()
        
        # If we're handling SIGINT (Ctrl+C), we should also call the original handler
        if signum == signal.SIGINT and self._original_sigint_handler:
            self._original_sigint_handler(signum, frame)
            
    def register_hook(self, hook: Callable[[], None], priority: int = 0, name: str = None) -> None:
        """
        Register a shutdown hook.
        
        Args:
            hook: Function to call during shutdown
            priority: Hook priority (higher values run first)
            name: Optional name for the hook
        """
        with self.shutdown_hooks_lock:
            self.shutdown_hooks.append({
                "hook": hook,
                "priority": priority,
                "name": name or f"hook_{len(self.shutdown_hooks)}"
            })
            # Sort hooks by priority (higher first)
            self.shutdown_hooks.sort(key=lambda h: h["priority"], reverse=True)
            
    def execute_shutdown(self) -> None:
        """Execute all registered shutdown hooks."""
        # Avoid duplicate execution
        with self.shutdown_hooks_lock:
            if self.shutdown_in_progress:
                return
                
            self.shutdown_in_progress = True
            
        # Execute hooks in order of priority
        logger.info(f"Executing {len(self.shutdown_hooks)} shutdown hooks (timeout: {self.shutdown_timeout}s)")
        
        start_time = time.time()
        try:
            for hook_info in self.shutdown_hooks:
                hook_name = hook_info["name"]
                hook_func = hook_info["hook"]
                
                # Skip if we've already exceeded the timeout
                elapsed = time.time() - start_time
                if elapsed >= self.shutdown_timeout:
                    logger.warning(f"Shutdown timeout ({self.shutdown_timeout}s) exceeded, skipping remaining hooks")
                    break
                    
                # Execute the hook with a timeout
                remaining_time = self.shutdown_timeout - elapsed
                logger.debug(f"Executing shutdown hook: {hook_name} (remaining time: {remaining_time:.1f}s)")
                
                try:
                    # Create a thread to execute the hook
                    hook_thread = threading.Thread(target=hook_func)
                    hook_thread.daemon = True
                    hook_thread.start()
                    
                    # Wait for the hook to complete with timeout
                    hook_thread.join(timeout=min(remaining_time, 5.0))  # Max 5 seconds per hook
                    
                    if hook_thread.is_alive():
                        logger.warning(f"Shutdown hook {hook_name} did not complete in time")
                except Exception as e:
                    logger.error(f"Error executing shutdown hook {hook_name}: {e}")
        except Exception as e:
            logger.error(f"Error during shutdown sequence: {e}")
            
        elapsed = time.time() - start_time
        logger.info(f"Shutdown sequence completed in {elapsed:.1f}s")
        
    def set_timeout(self, timeout: float) -> None:
        """
        Set shutdown timeout.
        
        Args:
            timeout: Timeout in seconds
        """
        self.shutdown_timeout = max(1.0, timeout)  # Minimum 1 second
        logger.info(f"Shutdown timeout set to {self.shutdown_timeout}s")

# Global shutdown handler instance
_shutdown_handler = None

def get_shutdown_handler() -> ShutdownHandler:
    """
    Get the global shutdown handler instance.
    
    Returns:
        ShutdownHandler instance
    """
    global _shutdown_handler
    if _shutdown_handler is None:
        _shutdown_handler = ShutdownHandler()
    return _shutdown_handler

def register_shutdown_hook(hook: Callable[[], None], priority: int = 0, name: str = None) -> None:
    """
    Register a shutdown hook with the global handler.
    
    Args:
        hook: Function to call during shutdown
        priority: Hook priority (higher values run first)
        name: Optional name for the hook
    """
    handler = get_shutdown_handler()
    handler.register_hook(hook, priority, name)

def set_shutdown_timeout(timeout: float) -> None:
    """
    Set shutdown timeout for the global handler.
    
    Args:
        timeout: Timeout in seconds
    """
    handler = get_shutdown_handler()
    handler.set_timeout(timeout)

def trigger_shutdown() -> None:
    """Manually trigger the shutdown sequence."""
    handler = get_shutdown_handler()
    if not handler.shutdown_in_progress:
        logger.info("Manually triggering shutdown sequence")
        handler.execute_shutdown() 