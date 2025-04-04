"""
Claude-enabled MCP Server Template

This template creates an MCP server with Claude AI capabilities for text generation,
completion, summarization, and other AI tasks.
"""

import os
import sys
import json
import logging
import asyncio
from typing import Dict, Any, List, Optional, Union
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('claude_server.log')
    ]
)
logger = logging.getLogger('claude_server')

# Import MCP SDK
from mcp.server.fastmcp import FastMCP

# Import Claude handler
from template_system.handlers.claude_handler import ClaudeHandler

# Create the MCP server
mcp_server = FastMCP("{{server_name}}", description="{{server_description}}")

# Initialize Claude handler with configuration
config = {
    "claude": {
        "api_key": os.environ.get("ANTHROPIC_API_KEY", "{{claude_api_key}}"),
        "model": "{{claude_model}}",
        "max_tokens": {{claude_max_tokens}},
        "temperature": {{claude_temperature}},
        "top_p": {{claude_top_p}},
        "request_timeout": {{claude_request_timeout}},
        "enable_streaming": {{claude_enable_streaming}}
    }
}
claude_handler = ClaudeHandler(config)

@mcp_server.tool()
async def generate_text(prompt: str, system_prompt: Optional[str] = None, 
                      max_tokens: Optional[int] = None, temperature: Optional[float] = None,
                      top_p: Optional[float] = None) -> Dict[str, Any]:
    """
    Generate text using Claude AI.
    
    Args:
        prompt: The main text prompt to send to Claude
        system_prompt: Optional system prompt to guide Claude's behavior
        max_tokens: Maximum number of tokens to generate (default: 4096)
        temperature: Temperature parameter (0.0-1.0, higher is more creative)
        top_p: Top-p sampling parameter (default: 0.9)
        
    Returns:
        Generated text and metadata
    """
    logger.info(f"Generating text for prompt: {prompt[:50]}...")
    
    result = await claude_handler.generate_text(
        prompt=prompt,
        system_prompt=system_prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p
    )
    
    return result

@mcp_server.tool()
async def stream_text(prompt: str, system_prompt: Optional[str] = None,
                    max_tokens: Optional[int] = None, temperature: Optional[float] = None,
                    top_p: Optional[float] = None) -> Dict[str, Any]:
    """
    Stream text generation from Claude AI.
    
    Note: This function initiates streaming but in the MCP protocol, you'll receive
    the complete result. For true streaming, use a WebSocket connection.
    
    Args:
        Same parameters as generate_text
        
    Returns:
        Complete generated text and metadata
    """
    logger.info(f"Streaming text for prompt: {prompt[:50]}...")
    
    # Since MCP doesn't support true streaming in the basic protocol,
    # we collect all chunks and return the complete result
    result = {"status": "success", "text": "", "model": ""}
    usage = {}
    
    async for chunk in claude_handler.stream_text(
        prompt=prompt,
        system_prompt=system_prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p
    ):
        if chunk["status"] == "streaming":
            result["text"] += chunk["text"]
            result["model"] = chunk["model"]
        elif chunk["status"] == "complete":
            usage = chunk.get("usage", {})
        elif chunk["status"] == "error":
            return chunk
    
    result["usage"] = usage
    return result

@mcp_server.tool()
async def summarize(text: str, max_length: Optional[int] = None) -> Dict[str, Any]:
    """
    Summarize text using Claude AI.
    
    Args:
        text: The text to summarize
        max_length: Optional maximum summary length in words
        
    Returns:
        Summary and metadata
    """
    logger.info(f"Summarizing text: {text[:50]}...")
    
    # Create a prompting specifically designed for summarization
    system_prompt = "You are a helpful assistant that provides concise, accurate summaries."
    
    max_length_instruction = ""
    if max_length:
        max_length_instruction = f" Your summary should be no longer than {max_length} words."
    
    prompt = f"Please summarize the following text.{max_length_instruction}\n\n{text}"
    
    result = await claude_handler.generate_text(
        prompt=prompt,
        system_prompt=system_prompt
    )
    
    return result

@mcp_server.tool()
async def answer_question(question: str, context: Optional[str] = None) -> Dict[str, Any]:
    """
    Answer a question using Claude AI, optionally with context.
    
    Args:
        question: The question to answer
        context: Optional context to help answer the question
        
    Returns:
        Answer and metadata
    """
    logger.info(f"Answering question: {question}")
    
    system_prompt = "You are a helpful assistant that provides accurate, concise answers to questions."
    
    if context:
        prompt = f"Please answer the following question using the provided context.\n\nContext: {context}\n\nQuestion: {question}"
    else:
        prompt = f"Please answer the following question: {question}"
    
    result = await claude_handler.generate_text(
        prompt=prompt,
        system_prompt=system_prompt
    )
    
    return result

@mcp_server.tool()
async def classify_text(text: str, categories: List[str]) -> Dict[str, Any]:
    """
    Classify text into one of the provided categories using Claude AI.
    
    Args:
        text: The text to classify
        categories: List of categories to classify into
        
    Returns:
        Classification result and metadata
    """
    logger.info(f"Classifying text: {text[:50]}...")
    
    system_prompt = "You are a helpful assistant that classifies text accurately."
    
    categories_str = ", ".join(categories)
    prompt = f"Please classify the following text into exactly one of these categories: {categories_str}.\n\nText: {text}\n\nThe category is:"
    
    result = await claude_handler.generate_text(
        prompt=prompt,
        system_prompt=system_prompt,
        max_tokens=50  # Short response for classification
    )
    
    return result

@mcp_server.tool()
async def translate(text: str, target_language: str) -> Dict[str, Any]:
    """
    Translate text to the target language using Claude AI.
    
    Args:
        text: Text to translate
        target_language: Target language (e.g., "French", "Spanish", "Japanese")
        
    Returns:
        Translated text and metadata
    """
    logger.info(f"Translating text to {target_language}: {text[:50]}...")
    
    system_prompt = f"You are a helpful assistant that translates text accurately to {target_language}."
    
    prompt = f"Please translate the following text to {target_language}:\n\n{text}"
    
    result = await claude_handler.generate_text(
        prompt=prompt,
        system_prompt=system_prompt
    )
    
    return result

@mcp_server.tool()
async def code_completion(code: str, language: str, instruction: Optional[str] = None) -> Dict[str, Any]:
    """
    Complete or modify code using Claude AI.
    
    Args:
        code: Existing code to complete or modify
        language: Programming language (e.g., "python", "javascript")
        instruction: Optional specific instruction for code modification
        
    Returns:
        Completed code and metadata
    """
    logger.info(f"Code completion for {language}")
    
    system_prompt = f"You are an expert {language} programmer. Provide working, efficient, and well-commented code."
    
    if instruction:
        prompt = f"Please modify or complete the following {language} code according to these instructions: {instruction}\n\n```{language}\n{code}\n```"
    else:
        prompt = f"Please complete the following {language} code:\n\n```{language}\n{code}\n```"
    
    result = await claude_handler.generate_text(
        prompt=prompt,
        system_prompt=system_prompt
    )
    
    return result

{{additional_tools}}

def main():
    """Start the MCP server."""
    try:
        # Log startup
        logger.info(f"Starting Claude-enabled MCP server: {{server_name}}")
        
        # Start the server
        mcp_server.run()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Error running server: {e}")

if __name__ == "__main__":
    main() 