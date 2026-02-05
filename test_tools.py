#!/usr/bin/env python3
"""Test Vulners MCP tools via SSE/HTTP"""

import json
import requests
import sys
from typing import Dict, Any, Optional

MCP_URL = "http://localhost:8000/mcp"

# Session management
SESSION_ID = None


def send_mcp_request(method: str, params: Optional[Dict[str, Any]], request_id: Optional[int], session_id: Optional[str] = None) -> Optional[Dict]:
    """Send MCP request and display response"""
    
    payload = {
        "jsonrpc": "2.0",
        "method": method
    }
    
    # Only add ID for requests (not for notifications)
    if request_id is not None:
        payload["id"] = request_id
    
    # Only add params if they're not None and not empty
    if params:
        payload["params"] = params
    
    print(f"🔍 Request payload:")
    print(json.dumps(payload, indent=2))
    
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json"
    }
    
    # Add session ID as MCP header if provided
    if session_id:
        headers["mcp-session-id"] = session_id
    
    result_data = None
    
    try:
        # Try without streaming first
        response = requests.post(
            MCP_URL,
            json=payload,
            headers=headers,
            timeout=10
        )
        
        print(f"📊 Status: {response.status_code}")
        print(f"📋 Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print(f"📋 Response:")
        
        # Check content type
        content_type = response.headers.get('Content-Type', '')
        
        if 'text/event-stream' in content_type:
            # Parse SSE response - may contain multiple data events
            lines = response.text.strip().split('\n')
            data_events = []
            for line in lines:
                if line.startswith('data: '):
                    data = line[6:]  # Remove 'data: ' prefix
                    if data and data != '[DONE]':
                        try:
                            parsed = json.loads(data)
                            data_events.append(parsed)
                            print(json.dumps(parsed, indent=2))
                        except json.JSONDecodeError:
                            print(f"SSE data: {data}")
            
            # Return the last data event (usually the result)
            if data_events:
                result_data = data_events[-1]
        else:
            # Try to parse as JSON
            try:
                result_data = response.json()
                print(json.dumps(result_data, indent=2))
            except json.JSONDecodeError:
                print(f"Raw response ({len(response.text)} bytes):")
                print(f"'{response.text[:500]}'")
                
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed - server might not be running")
        print("   Try: docker-compose up -d")
    except requests.exceptions.Timeout:
        print("⏱️  Request timed out")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    return result_data


def main():
    global SESSION_ID
    
    print("=== Testing Vulners MCP Tools ===")
    print()
    
    # Step 0: Get session ID from server
    print("0. Getting session ID from server...")
    try:
        response = requests.get(
            MCP_URL,
            headers={"Accept": "text/event-stream"},
            timeout=5
        )
        SESSION_ID = response.headers.get("mcp-session-id")
        
        if SESSION_ID:
            print(f"✅ Session ID received: {SESSION_ID}")
        else:
            print("❌ No session ID in response headers")
            print(f"   Headers: {dict(response.headers)}")
            return
    except Exception as e:
        print(f"❌ Failed to get session: {e}")
        return
    
    print()
    print("-" * 80)
    print()
    
    # Step 1: Initialize the MCP protocol
    print("1. Initializing MCP protocol...")
    print("   Method: initialize")
    init_result = send_mcp_request(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "vulners-mcp-test",
                "version": "1.0.0"
            }
        },
        1,
        SESSION_ID
    )
    
    if not init_result or "error" in init_result:
        print("❌ Failed to initialize protocol")
        return
    
    print("✅ Protocol initialized successfully")
    print()
    
    # Send initialized notification (required by MCP protocol)
    print("   Sending initialized notification...")
    send_mcp_request("notifications/initialized", None, None, SESSION_ID)
    print("✅ Handshake complete")
    print()
    print("-" * 80)
    print()
    
    # Test 2: List available tools
    print("2. Listing available tools...")
    print("   Method: tools/list")
    send_mcp_request("tools/list", {}, 2, SESSION_ID)
    print()
    print("-" * 80)
    print()
    
    # Test 3: Search by CVE ID
    print("3. Searching for CVE-2021-44228 (Log4Shell)...")
    print("   Method: tools/call -> search_by_id")
    send_mcp_request(
        "tools/call",
        {
            "name": "search_by_id",
            "arguments": {"id": "CVE-2021-44228"}
        },
        3,
        SESSION_ID
    )
    print()
    print("-" * 80)
    print()
    
    # Test 4: Search using Lucene
    print("4. Searching for recent critical CVEs...")
    print("   Method: tools/call -> search_lucene")
    send_mcp_request(
        "tools/call",
        {
            "name": "search_lucene",
            "arguments": {
                "query": "type:cve AND cvss.score:[9 TO 10]",
                "size": 3
            }
        },
        4,
        SESSION_ID
    )
    print()
    print("-" * 80)
    print()
    
    # Test 5: Single ID (bulletin_by_id now only accepts single IDs)
    print("5. Testing single CVE ID...")
    print("   Method: tools/call -> bulletin_by_id")
    send_mcp_request(
        "tools/call",
        {
            "name": "bulletin_by_id",
            "arguments": {
                "id": "CVE-2021-44228"
            }
        },
        5,
        SESSION_ID
    )
    print()
    print("-" * 80)
    print()
    
    print("=== Done ===")
    print()
    print("💡 For full interactive testing, use Claude Desktop with MCP support")
    print("🔍 Server health: curl http://localhost:8000/health")


if __name__ == "__main__":
    try:
        # Quick health check first
        print("🔍 Checking server health...")
        response = requests.get("http://localhost:8000/health", timeout=2)
        if response.status_code == 200:
            print("✅ Server is running")
        else:
            print(f"⚠️  Server returned status {response.status_code}")
        print()
    except requests.exceptions.ConnectionError:
        print("❌ Server not accessible at http://localhost:8000")
        print("   Start it with: docker-compose up -d")
        sys.exit(1)
    except Exception as e:
        print(f"⚠️  Health check failed: {e}")
        print()
    
    main()

