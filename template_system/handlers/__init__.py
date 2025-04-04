"""
Custom Handler Templates

This module contains templates for custom handlers that can be added to MCP servers.
"""

from typing import Dict, Any, List

def get_handler_templates() -> Dict[str, Dict[str, Any]]:
    """
    Get a dictionary of available handler templates.
    
    Returns:
        Dictionary mapping handler names to their templates.
    """
    return {
        "file_reader": {
            "name": "File Reader",
            "description": "Reads files from the server's filesystem",
            "function_template": """
@mcp_server.tool()
def handle_file_reader(file_path: str) -> Dict[str, Any]:
    \"\"\"
    Read a file from the server's filesystem.
    
    Args:
        file_path: Path to the file to read.
        
    Returns:
        Dictionary containing file content or error.
    \"\"\"
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            
        return {
            "status": "success",
            "content": content
        }
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return {
            "status": "error",
            "error": str(e)
        }
"""
        },
        "http_request": {
            "name": "HTTP Request",
            "description": "Makes HTTP requests to external services",
            "imports": ["import httpx"],
            "function_template": """
@mcp_server.tool()
def handle_http_request(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, data: Optional[str] = None) -> Dict[str, Any]:
    \"\"\"
    Make an HTTP request to an external service.
    
    Args:
        url: URL to request.
        method: HTTP method to use (GET, POST, etc.).
        headers: Optional request headers.
        data: Optional request data.
        
    Returns:
        Dictionary containing response information.
    \"\"\"
    try:
        if headers is None:
            headers = {}
            
        # Create HTTP client
        client = httpx.Client(timeout=10.0)
        
        # Make request
        response = client.request(
            method=method,
            url=url,
            headers=headers,
            content=data
        )
        
        return {
            "status": "success",
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content": response.text
        }
    except Exception as e:
        logger.error(f"Error making HTTP request: {e}")
        return {
            "status": "error",
            "error": str(e)
        }
"""
        },
        "database": {
            "name": "Database",
            "description": "Provides simple database functionality with SQLite",
            "imports": ["import sqlite3"],
            "function_template": """
@mcp_server.tool()
def handle_database(query: str, params: Optional[List[Any]] = None) -> Dict[str, Any]:
    \"\"\"
    Execute a database query.
    
    Args:
        query: SQL query to execute.
        params: Query parameters.
        
    Returns:
        Dictionary containing query results or error.
    \"\"\"
    try:
        if params is None:
            params = []
            
        # Connect to database
        conn = sqlite3.connect('server_data.db')
        cursor = conn.cursor()
        
        # Execute query
        cursor.execute(query, params)
        
        # Check if query returns data
        if query.strip().upper().startswith('SELECT'):
            columns = [col[0] for col in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
            conn.close()
            
            return {
                "status": "success",
                "results": results
            }
        else:
            # For non-SELECT queries
            conn.commit()
            conn.close()
            
            return {
                "status": "success",
                "rows_affected": cursor.rowcount
            }
    except Exception as e:
        logger.error(f"Error executing database query: {e}")
        return {
            "status": "error",
            "error": str(e)
        }
"""
        }
    } 