#!/usr/bin/env python3
"""
SPECTR Setup and Usage Guide
"""

import os
import sys

def print_banner():
    """Print SPECTR banner"""
    banner = """
  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ 
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝
   
   SPECTR - Scanner for Payloads, Endpoints, Configs,
             Traversals, and Requests
   
   🔍 Web Vulnerability Scanner v1.0
   ⚡ Python CLI-based Security Testing Tool
   
"""
    print(banner)

def check_installation():
    """Check if SPECTR is properly installed"""
    print("🔍 Checking SPECTR Installation...")
    
    # Check if executable exists
    if os.path.exists('/app/spectr'):
        print("   ✅ SPECTR executable found")
        
        # Check if it's executable
        if os.access('/app/spectr', os.X_OK):
            print("   ✅ SPECTR is executable")
        else:
            print("   ❌ SPECTR is not executable")
            print("   💡 Run: chmod +x /app/spectr")
    else:
        print("   ❌ SPECTR executable not found")
        return False
    
    # Check core modules
    modules = ['core', 'detectors', 'utils']
    for module in modules:
        if os.path.exists(f'/app/{module}'):
            print(f"   ✅ {module} module found")
        else:
            print(f"   ❌ {module} module not found")
            return False
    
    # Check dependencies
    try:
        import requests
        print("   ✅ requests library available")
    except ImportError:
        print("   ❌ requests library not found")
        print("   💡 Run: pip install -r requirements.txt")
        return False
    
    return True

def show_usage():
    """Show usage instructions"""
    print("\n🚀 SPECTR Usage Instructions:")
    print("=" * 50)
    
    print("\n1. Interactive Mode:")
    print("   ./spectr")
    print("   (Follow the prompts to enter target URL, method, parameters, etc.)")
    
    print("\n2. Quick Test:")
    print("   python3 test_spectr.py")
    print("   (Runs component tests to verify functionality)")
    
    print("\n3. Demo Mode:")
    print("   python3 demo_spectr.py")
    print("   (Safe demonstration using httpbin.org)")
    
    print("\n📋 Vulnerability Types Detected:")
    print("   🔴 SQL Injection (SQLi)")
    print("   🟡 Cross-Site Scripting (XSS)")
    print("   🟣 Insecure Direct Object Reference (IDOR)")
    print("   🔵 Path Traversal")
    
    print("\n⚠️  Important Notes:")
    print("   • Only test applications you own or have permission to test")
    print("   • SPECTR is for educational and authorized security testing")
    print("   • Unauthorized testing is illegal and unethical")
    print("   • Results may include false positives - verify manually")
    
    print("\n📊 Payload Statistics:")
    sys.path.insert(0, '/app')
    try:
        from core.payloads import PayloadDatabase
        payloads = PayloadDatabase()
        print(f"   • SQL Injection: {len(payloads.get_payloads('sqli'))} payloads")
        print(f"   • XSS: {len(payloads.get_payloads('xss'))} payloads")
        print(f"   • IDOR: {len(payloads.get_payloads('idor'))} payloads")
        print(f"   • Path Traversal: {len(payloads.get_payloads('traversal'))} payloads")
    except Exception as e:
        print(f"   ❌ Error loading payloads: {e}")

def main():
    """Main function"""
    print_banner()
    
    if check_installation():
        print("\n✅ SPECTR is properly installed and ready to use!")
        show_usage()
        
        print("\n🎯 Ready to scan? Run one of these commands:")
        print("   ./spectr                # Interactive mode")
        print("   python3 test_spectr.py  # Component tests")
        print("   python3 demo_spectr.py  # Safe demo")
        
    else:
        print("\n❌ SPECTR installation incomplete.")
        print("   Please check the errors above and fix them.")
        sys.exit(1)

if __name__ == "__main__":
    main()