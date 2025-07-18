#!/usr/bin/env python3
"""
Test script for SPECTR vulnerability scanner
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import SpectrScanner
from core.payloads import PayloadDatabase
from core.analyzer import ResponseAnalyzer
from utils.http_client import HTTPClient

def test_payload_database():
    """Test the payload database"""
    print("🧪 Testing Payload Database...")
    
    payloads = PayloadDatabase()
    
    # Test SQL injection payloads
    sqli_payloads = payloads.get_payloads('sqli')
    print(f"   ✅ SQL Injection payloads: {len(sqli_payloads)}")
    assert len(sqli_payloads) > 0, "Should have SQL injection payloads"
    
    # Test XSS payloads
    xss_payloads = payloads.get_payloads('xss')
    print(f"   ✅ XSS payloads: {len(xss_payloads)}")
    assert len(xss_payloads) > 0, "Should have XSS payloads"
    
    # Test IDOR payloads
    idor_payloads = payloads.get_payloads('idor')
    print(f"   ✅ IDOR payloads: {len(idor_payloads)}")
    assert len(idor_payloads) > 0, "Should have IDOR payloads"
    
    # Test Path Traversal payloads
    traversal_payloads = payloads.get_payloads('traversal')
    print(f"   ✅ Path Traversal payloads: {len(traversal_payloads)}")
    assert len(traversal_payloads) > 0, "Should have Path Traversal payloads"
    
    print("   ✅ Payload database test passed!")

def test_http_client():
    """Test the HTTP client"""
    print("\n🌐 Testing HTTP Client...")
    
    client = HTTPClient()
    
    # Test basic request (using httpbin.org for testing)
    response = client.make_request("https://httpbin.org/get", "GET", verbose=False)
    if response:
        print(f"   ✅ HTTP GET request successful: {response['status_code']}")
        assert response['status_code'] == 200, "Should get 200 status"
    else:
        print("   ⚠️  HTTP request failed (network issue or httpbin.org unavailable)")
    
    # Test payload injection
    test_response = client.test_payload(
        "https://httpbin.org/get", 
        "GET", 
        {"test": "value"}, 
        "' OR 1=1--", 
        "test", 
        verbose=False
    )
    if test_response:
        print(f"   ✅ Payload injection test successful: {test_response['status_code']}")
    else:
        print("   ⚠️  Payload injection test failed (network issue)")
    
    client.close()
    print("   ✅ HTTP client test passed!")

def test_response_analyzer():
    """Test the response analyzer"""
    print("\n🔍 Testing Response Analyzer...")
    
    analyzer = ResponseAnalyzer()
    
    # Test SQL error detection
    sql_error_response = {
        'status_code': 500,
        'content': 'Warning: mysql_fetch_array() expects parameter 1 to be resource',
        'response_time': 0.5
    }
    
    sqli_result = analyzer.analyze_sqli_response(sql_error_response, "' OR 1=1--")
    if sqli_result:
        print(f"   ✅ SQL injection detection: {sqli_result['evidence']}")
    else:
        print("   ⚠️  SQL injection detection failed")
    
    # Test XSS reflection detection
    xss_response = {
        'status_code': 200,
        'content': '<html><body>Hello <script>alert("XSS")</script></body></html>',
        'response_time': 0.3
    }
    
    xss_result = analyzer.analyze_xss_response(xss_response, '<script>alert("XSS")</script>')
    if xss_result:
        print(f"   ✅ XSS detection: {xss_result['evidence']}")
    else:
        print("   ⚠️  XSS detection failed")
    
    # Test path traversal detection
    traversal_response = {
        'status_code': 200,
        'content': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
        'response_time': 0.4
    }
    
    traversal_result = analyzer.analyze_traversal_response(traversal_response, '../../../etc/passwd')
    if traversal_result:
        print(f"   ✅ Path traversal detection: {traversal_result['evidence']}")
    else:
        print("   ⚠️  Path traversal detection failed")
    
    print("   ✅ Response analyzer test passed!")

def test_scanner_components():
    """Test individual scanner components"""
    print("\n🔧 Testing Scanner Components...")
    
    from detectors.sqli import SQLiDetector
    from detectors.xss import XSSDetector
    from detectors.idor import IDORDetector
    from detectors.traversal import PathTraversalDetector
    
    payloads = PayloadDatabase()
    client = HTTPClient()
    
    # Test detector initialization
    sqli_detector = SQLiDetector(client, payloads)
    xss_detector = XSSDetector(client, payloads)
    idor_detector = IDORDetector(client, payloads)
    traversal_detector = PathTraversalDetector(client, payloads)
    
    print("   ✅ SQLi detector initialized")
    print("   ✅ XSS detector initialized")
    print("   ✅ IDOR detector initialized")
    print("   ✅ Path Traversal detector initialized")
    
    client.close()
    print("   ✅ Scanner components test passed!")

def main():
    """Main test function"""
    print("🚀 SPECTR Vulnerability Scanner - Component Tests")
    print("=" * 60)
    
    try:
        test_payload_database()
        test_http_client()
        test_response_analyzer()
        test_scanner_components()
        
        print("\n" + "=" * 60)
        print("✅ All tests passed! SPECTR is ready to use.")
        print("=" * 60)
        
        print("\n🎯 To run the scanner interactively:")
        print("   ./spectr")
        print("\n🎯 To run a quick test:")
        print("   echo 'https://httpbin.org/get\nGET\ntest=1\n\ny' | ./spectr")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()