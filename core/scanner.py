"""
Main scanner orchestrator for SPECTR
"""

import sys
from urllib.parse import urlparse
from .payloads import PayloadDatabase
from .analyzer import ResponseAnalyzer
from .reporter import Reporter
from detectors.sqli import SQLiDetector
from detectors.xss import XSSDetector
from detectors.idor import IDORDetector
from detectors.traversal import PathTraversalDetector
from detectors.command_injection import CommandInjectionDetector
from detectors.xxe import XXEDetector
from detectors.ssrf import SSRFDetector
from utils.http_client import HTTPClient

class SpectrScanner:
    """Main scanner class that orchestrates all vulnerability detection"""
    
    def __init__(self):
        self.payloads = PayloadDatabase()
        self.analyzer = ResponseAnalyzer()
        self.reporter = Reporter()
        self.http_client = HTTPClient()
        
        # Initialize detectors
        self.detectors = {
            'sqli': SQLiDetector(self.http_client, self.payloads),
            'xss': XSSDetector(self.http_client, self.payloads),
            'idor': IDORDetector(self.http_client, self.payloads),
            'traversal': PathTraversalDetector(self.http_client, self.payloads),
            'command_injection': CommandInjectionDetector(self.http_client, self.payloads),
            'xxe': XXEDetector(self.http_client, self.payloads),
            'ssrf': SSRFDetector(self.http_client, self.payloads),
        }
        
        self.scan_config = {}
        self.results = []
    
    def run(self):
        """Run the interactive scanner"""
        print("🚀 Welcome to SPECTR - Web Vulnerability Scanner\n")
        
        # Get user input
        self._get_user_input()
        
        # Validate inputs
        if not self._validate_inputs():
            print("❌ Invalid inputs provided. Please try again.")
            return
        
        # Start scanning
        print(f"\n⏳ Starting scan on {self.scan_config['url']}...")
        self._perform_scan()
        
        # Display results
        self._display_results()
        
        # Generate report
        self._generate_report()
    
    def _get_user_input(self):
        """Get user input for scan configuration"""
        # Target URL
        while True:
            url = input("🔗 Enter target URL: ").strip()
            if url:
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                self.scan_config['url'] = url
                break
            print("❌ URL is required!")
        
        # HTTP Method
        while True:
            method = input("📡 HTTP method (GET/POST) [GET]: ").strip().upper()
            if not method:
                method = 'GET'
            if method in ['GET', 'POST']:
                self.scan_config['method'] = method
                break
            print("❌ Please enter GET or POST")
        
        # Parameters
        params_input = input("📤 Parameters (e.g., id=1&user=admin) [optional]: ").strip()
        if params_input:
            self.scan_config['params'] = self._parse_params(params_input)
        else:
            self.scan_config['params'] = {}
        
        # Headers
        headers_input = input("🧾 Headers (key:value,key:value) [optional]: ").strip()
        if headers_input:
            self.scan_config['headers'] = self._parse_headers(headers_input)
        else:
            self.scan_config['headers'] = {}
        
        # Verbose mode
        verbose = input("🔍 Verbose mode? (y/n) [n]: ").strip().lower()
        self.scan_config['verbose'] = verbose in ['y', 'yes', '1', 'true']
        
        print(f"\n📋 Scan Configuration:")
        print(f"   🎯 Target: {self.scan_config['url']}")
        print(f"   📡 Method: {self.scan_config['method']}")
        print(f"   📤 Parameters: {len(self.scan_config['params'])} params")
        print(f"   🧾 Headers: {len(self.scan_config['headers'])} headers")
        print(f"   🔍 Verbose: {'Yes' if self.scan_config['verbose'] else 'No'}")
    
    def _parse_params(self, params_str):
        """Parse parameter string into dictionary"""
        params = {}
        for param in params_str.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key.strip()] = value.strip()
        return params
    
    def _parse_headers(self, headers_str):
        """Parse headers string into dictionary"""
        headers = {}
        for header in headers_str.split(','):
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers
    
    def _validate_inputs(self):
        """Validate user inputs"""
        try:
            parsed_url = urlparse(self.scan_config['url'])
            if not parsed_url.scheme or not parsed_url.netloc:
                print("❌ Invalid URL format")
                return False
            return True
        except Exception as e:
            print(f"❌ URL validation error: {e}")
            return False
    
    def _perform_scan(self):
        """Perform vulnerability scanning"""
        url = self.scan_config['url']
        method = self.scan_config['method']
        params = self.scan_config['params']
        headers = self.scan_config['headers']
        verbose = self.scan_config['verbose']
        
        # If no parameters provided, try to extract from URL
        if not params and '?' in url:
            base_url, query_string = url.split('?', 1)
            params = self._parse_params(query_string)
            self.scan_config['params'] = params
            self.scan_config['url'] = base_url
        
        total_detectors = len(self.detectors)
        current_detector = 0
        
        for detector_name, detector in self.detectors.items():
            current_detector += 1
            print(f"\n[{current_detector}/{total_detectors}] 🔍 Running {detector_name.upper()} detector...")
            
            try:
                detector_results = detector.scan(
                    url=self.scan_config['url'],
                    method=method,
                    params=params,
                    headers=headers,
                    verbose=verbose
                )
                
                if detector_results:
                    self.results.extend(detector_results)
                    if verbose:
                        print(f"   ✅ Found {len(detector_results)} potential {detector_name.upper()} vulnerabilities")
                else:
                    if verbose:
                        print(f"   ✅ No {detector_name.upper()} vulnerabilities detected")
                        
            except Exception as e:
                print(f"   ❌ Error in {detector_name.upper()} detector: {e}")
                if verbose:
                    import traceback
                    traceback.print_exc()
    
    def _display_results(self):
        """Display scan results"""
        print(f"\n{'='*60}")
        print("🎯 SCAN RESULTS")
        print(f"{'='*60}")
        
        if not self.results:
            print("✅ No vulnerabilities found!")
            return
        
        print(f"⚠️  Found {len(self.results)} potential vulnerabilities:\n")
        
        # Group results by vulnerability type
        vuln_groups = {}
        for result in self.results:
            vuln_type = result['type']
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append(result)
        
        # Display grouped results
        for vuln_type, vulns in vuln_groups.items():
            print(f"🔴 {vuln_type.upper()} ({len(vulns)} found)")
            for vuln in vulns:
                print(f"   └── Parameter: {vuln['parameter']}")
                print(f"       Payload: {vuln['payload']}")
                print(f"       Evidence: {vuln['evidence']}")
                print()
    
    def _generate_report(self):
        """Generate and save JSON report"""
        if not self.results:
            return
        
        save_report = input("💾 Save detailed report to JSON? (y/n) [y]: ").strip().lower()
        if save_report not in ['n', 'no', '0', 'false']:
            report_path = self.reporter.generate_json_report(
                self.scan_config,
                self.results
            )
            print(f"📄 Report saved to: {report_path}")