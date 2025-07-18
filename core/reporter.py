"""
Reporter module for SPECTR vulnerability scanner
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any

class Reporter:
    """Handles result reporting and output formatting"""
    
    def __init__(self):
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'bold': '\033[1m',
            'underline': '\033[4m',
            'reset': '\033[0m'
        }
    
    def colorize(self, text: str, color: str) -> str:
        """Apply color to text"""
        return f"{self.colors.get(color, '')}{text}{self.colors['reset']}"
    
    def format_vulnerability_result(self, result: Dict[str, Any]) -> str:
        """Format a single vulnerability result for display"""
        vuln_type = result.get('type', 'unknown').upper()
        method = result.get('method', 'unknown')
        payload = result.get('payload', '')
        evidence = result.get('evidence', '')
        
        # Color coding by vulnerability type
        type_colors = {
            'SQLI': 'red',
            'XSS': 'yellow',
            'IDOR': 'magenta',
            'TRAVERSAL': 'cyan'
        }
        
        color = type_colors.get(vuln_type, 'white')
        
        output = []
        output.append(self.colorize(f"🔴 {vuln_type} Vulnerability Detected", color))
        output.append(f"   Method: {method}")
        output.append(f"   Payload: {payload}")
        output.append(f"   Evidence: {evidence}")
        
        if 'response_code' in result:
            output.append(f"   Response Code: {result['response_code']}")
        
        if 'response_time' in result:
            output.append(f"   Response Time: {result['response_time']:.2f}s")
        
        return '\n'.join(output)
    
    def generate_summary_report(self, results: List[Dict[str, Any]]) -> str:
        """Generate a summary report of all results"""
        if not results:
            return self.colorize("✅ No vulnerabilities found!", 'green')
        
        # Group results by type
        vuln_groups = {}
        for result in results:
            vuln_type = result.get('type', 'unknown').upper()
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append(result)
        
        output = []
        output.append(self.colorize(f"⚠️  VULNERABILITY SUMMARY", 'bold'))
        output.append(self.colorize("=" * 50, 'white'))
        
        total_vulns = len(results)
        output.append(f"Total Vulnerabilities Found: {self.colorize(str(total_vulns), 'red')}")
        output.append("")
        
        # Summary by type
        for vuln_type, vulns in vuln_groups.items():
            count = len(vulns)
            type_colors = {
                'SQLI': 'red',
                'XSS': 'yellow',
                'IDOR': 'magenta',
                'TRAVERSAL': 'cyan'
            }
            color = type_colors.get(vuln_type, 'white')
            output.append(f"{self.colorize(vuln_type, color)}: {count} vulnerabilities")
        
        return '\n'.join(output)
    
    def generate_json_report(self, scan_config: Dict[str, Any], results: List[Dict[str, Any]]) -> str:
        """Generate a detailed JSON report"""
        timestamp = datetime.now().isoformat()
        
        report = {
            'scan_info': {
                'timestamp': timestamp,
                'scanner': 'SPECTR',
                'version': '1.0',
                'target': scan_config.get('url', ''),
                'method': scan_config.get('method', 'GET'),
                'parameters': scan_config.get('params', {}),
                'headers': scan_config.get('headers', {}),
                'total_vulnerabilities': len(results)
            },
            'vulnerabilities': results,
            'summary': self._generate_summary_stats(results)
        }
        
        # Generate filename with timestamp
        timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"spectr_scan_report_{timestamp_str}.json"
        filepath = os.path.join(os.getcwd(), filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            return filepath
        except Exception as e:
            print(f"Error saving report: {e}")
            return ""
    
    def _generate_summary_stats(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for the report"""
        if not results:
            return {'total': 0, 'by_type': {}}
        
        summary = {
            'total': len(results),
            'by_type': {},
            'by_method': {},
            'severity_distribution': {}
        }
        
        # Group by type
        for result in results:
            vuln_type = result.get('type', 'unknown')
            method = result.get('method', 'unknown')
            
            # Count by type
            if vuln_type not in summary['by_type']:
                summary['by_type'][vuln_type] = 0
            summary['by_type'][vuln_type] += 1
            
            # Count by method
            if method not in summary['by_method']:
                summary['by_method'][method] = 0
            summary['by_method'][method] += 1
        
        # Assign severity levels
        severity_mapping = {
            'sqli': 'High',
            'xss': 'Medium',
            'idor': 'High',
            'traversal': 'Medium'
        }
        
        for vuln_type, count in summary['by_type'].items():
            severity = severity_mapping.get(vuln_type, 'Medium')
            if severity not in summary['severity_distribution']:
                summary['severity_distribution'][severity] = 0
            summary['severity_distribution'][severity] += count
        
        return summary
    
    def print_banner_result(self, scan_config: Dict[str, Any], results: List[Dict[str, Any]]):
        """Print a formatted banner with scan results"""
        print(f"\n{self.colorize('='*70, 'cyan')}")
        print(f"{self.colorize('🎯 SPECTR SCAN COMPLETED', 'bold')}")
        print(f"{self.colorize('='*70, 'cyan')}")
        
        print(f"\n📊 {self.colorize('SCAN SUMMARY', 'bold')}")
        print(f"   Target: {scan_config.get('url', 'N/A')}")
        print(f"   Method: {scan_config.get('method', 'N/A')}")
        print(f"   Parameters: {len(scan_config.get('params', {}))}")
        print(f"   Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if results:
            print(f"\n⚠️  {self.colorize('VULNERABILITIES FOUND', 'red')}")
            vuln_counts = {}
            for result in results:
                vuln_type = result.get('type', 'unknown').upper()
                vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
            
            for vuln_type, count in vuln_counts.items():
                print(f"   {vuln_type}: {count}")
        else:
            print(f"\n✅ {self.colorize('NO VULNERABILITIES FOUND', 'green')}")
        
        print(f"\n{self.colorize('='*70, 'cyan')}")