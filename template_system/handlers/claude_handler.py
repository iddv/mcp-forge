"""
Claude AI Integration Handler for MCP-Forge

This handler provides integration with Claude AI models from Anthropic,
allowing MCP servers to use Claude for text generation, completion, and other AI tasks.
"""

import os
import json
import logging
import httpx
from typing import Dict, Any, List, Optional, Union

logger = logging.getLogger("mcp_forge.handlers.claude")

class ClaudeHandler:
    """Handler for integrating with Claude AI models."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the Claude handler.
        
        Args:
            config: Configuration dictionary with Claude settings
        """
        self.config = config or {}
        self.api_key = self.config.get("api_key") or os.environ.get("ANTHROPIC_API_KEY")
        self.model = self.config.get("model", "claude-3-opus-20240229")
        self.max_tokens = self.config.get("max_tokens", 4096)
        self.temperature = self.config.get("temperature", 0.7)
        self.top_p = self.config.get("top_p", 0.9)
        self.timeout = self.config.get("request_timeout", 120)
        self.streaming = self.config.get("enable_streaming", True)
        
        if not self.api_key:
            logger.warning("No Claude API key provided. Claude functionality will be unavailable.")
        else:
            logger.info(f"Claude handler initialized with model: {self.model}")
    
    async def generate_text(self, 
                          prompt: str,
                          system_prompt: Optional[str] = None,
                          max_tokens: Optional[int] = None,
                          temperature: Optional[float] = None,
                          top_p: Optional[float] = None,
                          stop_sequences: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Generate text using Claude.
        
        Args:
            prompt: The user message/prompt to send to Claude
            system_prompt: Optional system prompt to guide Claude's behavior
            max_tokens: Maximum number of tokens to generate
            temperature: Temperature for text generation
            top_p: Top-p sampling parameter
            stop_sequences: Sequences where generation should stop
            
        Returns:
            Response from Claude with generated text
        """
        if not self.api_key:
            return {
                "error": "Claude API key not configured",
                "status": "error"
            }
        
        # Prepare the API request
        url = "https://api.anthropic.com/v1/messages"
        
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        
        # Build message object
        messages = [{
            "role": "user",
            "content": prompt
        }]
        
        # Prepare request body
        data = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature if temperature is not None else self.temperature,
            "top_p": top_p if top_p is not None else self.top_p
        }
        
        # Add system prompt if provided
        if system_prompt:
            data["system"] = system_prompt
            
        # Add stop sequences if provided
        if stop_sequences:
            data["stop_sequences"] = stop_sequences
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, headers=headers, json=data)
                response.raise_for_status()
                
                result = response.json()
                
                # Extract and return the content
                return {
                    "status": "success",
                    "text": result["content"][0]["text"],
                    "model": result["model"],
                    "usage": result.get("usage", {})
                }
                
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error from Claude API: {e}")
            return {
                "error": f"Claude API error: {e.response.status_code}",
                "details": e.response.text,
                "status": "error"
            }
        except httpx.RequestError as e:
            logger.error(f"Request error to Claude API: {e}")
            return {
                "error": f"Request error: {str(e)}",
                "status": "error"
            }
        except Exception as e:
            logger.error(f"Unexpected error with Claude API: {e}")
            return {
                "error": f"Unexpected error: {str(e)}",
                "status": "error"
            }
            
    async def stream_text(self,
                        prompt: str,
                        system_prompt: Optional[str] = None,
                        max_tokens: Optional[int] = None,
                        temperature: Optional[float] = None,
                        top_p: Optional[float] = None,
                        stop_sequences: Optional[List[str]] = None):
        """
        Stream text generation using Claude.
        
        Args:
            Same parameters as generate_text
            
        Yields:
            Chunks of generated text
        """
        if not self.api_key:
            yield {
                "error": "Claude API key not configured",
                "status": "error"
            }
            return
        
        # Prepare the API request
        url = "https://api.anthropic.com/v1/messages"
        
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        
        # Build message object
        messages = [{
            "role": "user",
            "content": prompt
        }]
        
        # Prepare request body
        data = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature if temperature is not None else self.temperature,
            "top_p": top_p if top_p is not None else self.top_p,
            "stream": True
        }
        
        # Add system prompt if provided
        if system_prompt:
            data["system"] = system_prompt
            
        # Add stop sequences if provided
        if stop_sequences:
            data["stop_sequences"] = stop_sequences
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream("POST", url, headers=headers, json=data) as response:
                    response.raise_for_status()
                    
                    # Process the streamed response
                    buffer = ""
                    async for chunk in response.aiter_text():
                        buffer += chunk
                        
                        # Find complete events in the buffer
                        while "\n\n" in buffer:
                            event, buffer = buffer.split("\n\n", 1)
                            
                            if event.startswith("data: "):
                                data = event[6:]
                                if data.strip() == "[DONE]":
                                    break
                                    
                                try:
                                    parsed = json.loads(data)
                                    if parsed.get("type") == "content_block_delta":
                                        yield {
                                            "status": "streaming",
                                            "text": parsed["delta"]["text"],
                                            "model": self.model,
                                        }
                                    elif parsed.get("type") == "message_stop":
                                        yield {
                                            "status": "complete",
                                            "stop_reason": parsed.get("stop_reason", "stop_sequence"),
                                            "model": self.model,
                                            "usage": parsed.get("usage", {})
                                        }
                                except json.JSONDecodeError:
                                    logger.warning(f"Failed to parse streaming response: {data}")
                    
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error from Claude API: {e}")
            yield {
                "error": f"Claude API error: {e.response.status_code}",
                "details": e.response.text,
                "status": "error"
            }
        except httpx.RequestError as e:
            logger.error(f"Request error to Claude API: {e}")
            yield {
                "error": f"Request error: {str(e)}",
                "status": "error"
            }
        except Exception as e:
            logger.error(f"Unexpected error with Claude API: {e}")
            yield {
                "error": f"Unexpected error: {str(e)}",
                "status": "error"
            }

def create_handler(config: Dict[str, Any]) -> ClaudeHandler:
    """
    Factory function to create a Claude handler.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Initialized Claude handler
    """
    return ClaudeHandler(config.get("claude", {})) 