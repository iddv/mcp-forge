#!/usr/bin/env python
"""
Test Script for MCP-Forge Protection Mechanisms

This script tests various security protection mechanisms implemented in the MCP-Forge framework,
including CSRF protection, XSS prevention, injection prevention, rate limiting, and more.
"""

import argparse
import json
import time
import threading
import requests
import sys
import os
from typing import Dict, Any, List, Optional

def banner(title):
    """Display a banner for test sections."""
    print("\n" + "=" * 80)
    print(f" {title} ".center(80, '='))
    print("=" * 80)

def make_request(endpoint, method="GET", data=None, headers=None, auth=None, expected_success=True):
    """Make a request to the server and display the result."""
    url = f"http://{server_host}:{server_port}{endpoint}"
    headers = headers or {}
    
    # Print request details
    print(f"\n--> {method} {url}")
    if data:
        print(f"Data: {json.dumps(data, indent=2)}")
    if headers:
        print(f"Headers: {json.dumps(headers, indent=2)}")
    
    try:
        # Make the request
        response = requests.request(
            method,
            url,
            json=data,
            headers=headers,
            auth=auth
        )
        
        # Print response details
        print(f"<-- Status: {response.status_code}")
        try:
            resp_json = response.json()
            print(f"Response: {json.dumps(resp_json, indent=2)}")
        except:
            print(f"Response: {response.text[:200]}")
        
        # Check if success/failure matches expectations
        if expected_success and response.status_code >= 400:
            print(f"ERROR: Expected success but got status {response.status_code}")
        elif not expected_success and response.status_code < 400:
            print(f"ERROR: Expected failure but got status {response.status_code}")
        
        return response
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return None

def test_csrf_protection():
    """Test CSRF protection."""
    banner("CSRF Protection Test")
    
    # Login to get a session
    login_response = make_request(
        "/api/v1/login",
        method="POST",
        data={"username": "admin", "password": "admin"}
    )
    
    if not login_response or login_response.status_code >= 400:
        print("Failed to login, skipping CSRF test")
        return
    
    token = login_response.json().get("token")
    session_id = login_response.json().get("session_id")
    
    # Try to make a POST request without CSRF token
    print("\nTest 1: POST without CSRF token (should fail)")
    make_request(
        "/api/v1/servers",
        method="POST",
        data={"name": "test-server", "description": "Test server"},
        headers={"Authorization": f"Bearer {token}"},
        expected_success=False
    )
    
    # Get a valid CSRF token
    print("\nGetting CSRF token")
    csrf_response = make_request(
        "/api/v1/csrf-token",
        headers={"Authorization": f"Bearer {token}", "X-Session-ID": session_id}
    )
    
    if not csrf_response or csrf_response.status_code >= 400:
        print("Failed to get CSRF token, skipping remainder of test")
        return
    
    csrf_token = csrf_response.json().get("token")
    
    # Make a request with the CSRF token
    print("\nTest 2: POST with valid CSRF token (should succeed)")
    make_request(
        "/api/v1/servers",
        method="POST",
        data={"name": "test-server", "description": "Test server"},
        headers={
            "Authorization": f"Bearer {token}",
            "X-CSRF-Token": csrf_token,
            "X-Session-ID": session_id
        }
    )
    
    # Try with an invalid CSRF token
    print("\nTest 3: POST with invalid CSRF token (should fail)")
    make_request(
        "/api/v1/servers",
        method="POST",
        data={"name": "test-server2", "description": "Test server 2"},
        headers={
            "Authorization": f"Bearer {token}",
            "X-CSRF-Token": "invalid-token",
            "X-Session-ID": session_id
        },
        expected_success=False
    )

def test_xss_protection():
    """Test XSS protection."""
    banner("XSS Protection Test")
    
    # Try to inject script tags in server name
    print("Test 1: Script tag in server name")
    make_request(
        "/api/v1/servers",
        method="POST",
        data={
            "name": "test-<script>alert('xss')</script>",
            "description": "Test server with XSS attempt"
        },
        expected_success=False
    )
    
    # Try to inject script tags in description
    print("\nTest 2: Script tag in description")
    make_request(
        "/api/v1/servers",
        method="POST",
        data={
            "name": "test-server",
            "description": "Test <script>alert('xss')</script> server"
        },
        expected_success=False
    )
    
    # Try encoded script tags
    print("\nTest 3: Encoded script tags")
    make_request(
        "/api/v1/servers",
        method="POST",
        data={
            "name": "test-server",
            "description": "Test %3Cscript%3Ealert('xss')%3C/script%3E server"
        },
        expected_success=False
    )

def test_sql_injection():
    """Test SQL injection protection."""
    banner("SQL Injection Protection Test")
    
    # Try to inject SQL in the server name
    print("Test 1: SQL injection in server name")
    make_request(
        "/api/v1/servers",
        method="POST",
        data={
            "name": "test'; DROP TABLE servers; --",
            "description": "Test server with SQL injection attempt"
        },
        expected_success=False
    )
    
    # Try to inject SQL in the description
    print("\nTest 2: SQL injection in description")
    make_request(
        "/api/v1/servers",
        method="POST",
        data={
            "name": "test-server",
            "description": "Test server'; SELECT * FROM users WHERE 1=1; --"
        },
        expected_success=False
    )
    
    # Try to use a UNION attack
    print("\nTest 3: UNION-based SQL injection")
    make_request(
        "/api/v1/servers/search",
        method="GET",
        data={
            "query": "test' UNION SELECT username, password FROM users; --"
        },
        expected_success=False
    )

def test_rate_limiting():
    """Test rate limiting protection."""
    banner("Rate Limiting Protection Test")
    
    print("Sending multiple requests in rapid succession...")
    
    # Make a bunch of requests in quick succession
    for i in range(15):
        print(f"\nRequest {i+1}")
        resp = make_request(
            "/api/v1/servers",
            method="GET",
            expected_success=(i < 10)  # Expect first 10 to succeed
        )
        # Small delay to make output readable
        time.sleep(0.1)
    
    print("\nWaiting 30 seconds for rate limit to reset...")
    time.sleep(30)
    
    print("\nTrying again after waiting (should succeed)")
    make_request("/api/v1/servers", method="GET")

def test_ddos_protection():
    """Test DDoS protection by making too many concurrent requests."""
    banner("DDoS Protection Test")
    
    print("Simulating a DDoS attack with 20 concurrent threads...")
    
    # Function to run in each thread
    def make_requests():
        for i in range(10):
            make_request(
                "/api/v1/servers",
                method="GET",
                expected_success=False  # We expect most to fail
            )
            time.sleep(0.01)
    
    # Create and start threads
    threads = []
    for i in range(20):
        t = threading.Thread(target=make_requests)
        threads.append(t)
        t.start()
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    print("\nWaiting 60 seconds for IP to be removed from blacklist...")
    time.sleep(60)
    
    print("\nTrying again after waiting (should succeed)")
    make_request("/api/v1/servers", method="GET")

def test_security_headers():
    """Test security headers in responses."""
    banner("Security Headers Test")
    
    response = requests.get(f"http://{server_host}:{server_port}/api/v1/servers")
    
    print("Checking response headers:")
    headers_to_check = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "Referrer-Policy"
    ]
    
    for header in headers_to_check:
        if header in response.headers:
            print(f"✓ {header}: {response.headers[header]}")
        else:
            print(f"✗ {header}: Not found")

def main():
    """Main function to run the tests."""
    global server_host, server_port
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Test MCP-Forge Protection Mechanisms")
    parser.add_argument("--host", default="localhost", help="Server host")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    parser.add_argument("--test", choices=["csrf", "xss", "sql", "rate", "ddos", "headers", "all"], 
                       default="all", help="Test to run")
    args = parser.parse_args()
    
    server_host = args.host
    server_port = args.port
    
    print(f"Testing MCP-Forge protection mechanisms against server at {server_host}:{server_port}")
    
    # Run the specified test
    if args.test == "csrf" or args.test == "all":
        test_csrf_protection()
    
    if args.test == "xss" or args.test == "all":
        test_xss_protection()
    
    if args.test == "sql" or args.test == "all":
        test_sql_injection()
    
    if args.test == "rate" or args.test == "all":
        test_rate_limiting()
    
    if args.test == "ddos" or args.test == "all":
        test_ddos_protection()
    
    if args.test == "headers" or args.test == "all":
        test_security_headers()
    
    print("\nTest(s) completed!")

if __name__ == "__main__":
    server_host = "localhost"
    server_port = 9000
    main() 