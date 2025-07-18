#!/usr/bin/env python3
"""
SPECTR Demo - Demonstrates the vulnerability scanner functionality
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import SpectrScanner
from core.banner import display_banner

def demo_scan():
    """Demonstrate SPECTR with a safe test target"""
    
    # Display banner
    display_banner()
    
    print("🎯 SPECTR DEMO - Testing with httpbin.org")
    print("=" * 60)
    
    # Initialize scanner
    scanner = SpectrScanner()
    
    # Set up demo configuration
    scanner.scan_config = {
        'url': 'https://httpbin.org/get',
        'method': 'GET',
        'params': {'test': 'value', 'id': '1'},
        'headers': {'User-Agent': 'SPECTR-Demo'},
        'verbose': True
    }
    
    print("📋 Demo Scan Configuration:")
    print(f"   🎯 Target: {scanner.scan_config['url']}")
    print(f"   📡 Method: {scanner.scan_config['method']}")
    print(f"   📤 Parameters: {scanner.scan_config['params']}")
    print(f"   🧾 Headers: {scanner.scan_config['headers']}")
    print(f"   🔍 Verbose: {scanner.scan_config['verbose']}")
    
    print(f"\n⏳ Starting demo scan...")
    
    # Perform scan
    scanner._perform_scan()
    
    # Display results
    print(f"\n{'='*60}")
    print("🎯 DEMO SCAN RESULTS")
    print(f"{'='*60}")
    
    if scanner.results:
        print(f"⚠️  Found {len(scanner.results)} potential vulnerabilities:")
        
        # Group results by type
        vuln_groups = {}
        for result in scanner.results:
            vuln_type = result['type']
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append(result)
        
        for vuln_type, vulns in vuln_groups.items():
            print(f"\n🔴 {vuln_type.upper()} ({len(vulns)} found)")
            for vuln in vulns[:3]:  # Show first 3 results
                print(f"   └── Parameter: {vuln['parameter']}")
                print(f"       Payload: {vuln['payload']}")
                print(f"       Evidence: {vuln['evidence']}")
                print()
            if len(vulns) > 3:
                print(f"   ... and {len(vulns) - 3} more")
    else:
        print("✅ No vulnerabilities found!")
    
    print(f"\n{'='*60}")
    print("🎯 DEMO COMPLETED")
    print(f"{'='*60}")
    
    print("\n📚 Note: This is a demo using httpbin.org - a safe testing service.")
    print("    Real vulnerabilities would be found on vulnerable applications.")
    print("    Always ensure you have permission before testing real applications!")

if __name__ == "__main__":
    try:
        demo_scan()
    except KeyboardInterrupt:
        print("\n\n🛑 Demo interrupted by user.")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()