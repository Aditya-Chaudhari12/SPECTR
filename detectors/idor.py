"""
Insecure Direct Object Reference (IDOR) detector for SPECTR vulnerability scanner
"""

from typing import Dict, List, Any, Optional
from utils.http_client import HTTPClient
from core.payloads import PayloadDatabase
from core.analyzer import ResponseAnalyzer

class IDORDetector:
    """Insecure Direct Object Reference vulnerability detector"""
    
    def __init__(self, http_client: HTTPClient, payloads: PayloadDatabase):
        self.http_client = http_client
        self.payloads = payloads
        self.analyzer = ResponseAnalyzer()
    
    def scan(self, url: str, method: str, params: Dict[str, Any], 
             headers: Optional[Dict[str, str]] = None, verbose: bool = False) -> List[Dict[str, Any]]:
        """Scan for IDOR vulnerabilities"""
        
        results = []
        idor_payloads = self.payloads.get_payloads('idor')
        
        if not params:
            if verbose:
                print("   ℹ️  No parameters to test for IDOR")
            return results
        
        # Get baseline response for comparison
        baseline_response = self.http_client.get_baseline_response(
            url=url, method=method, params=params, headers=headers, verbose=verbose
        )
        
        if not baseline_response:
            if verbose:
                print("   ❌ Could not get baseline response")
            return results
        
        # Test each parameter for IDOR
        for param_name, param_value in params.items():
            if verbose:
                print(f"   🔍 Testing parameter '{param_name}' for IDOR")
            
            # Test numeric IDOR
            numeric_results = self._test_numeric_idor(
                url, method, params, param_name, baseline_response, headers, verbose
            )
            results.extend(numeric_results)
            
            # Test string/UUID IDOR
            string_results = self._test_string_idor(
                url, method, params, param_name, baseline_response, headers, verbose
            )
            results.extend(string_results)
            
            # Test path-based IDOR
            path_results = self._test_path_idor(
                url, method, params, param_name, baseline_response, headers, verbose
            )
            results.extend(path_results)
        
        if verbose and results:
            print(f"   ✅ Found {len(results)} potential IDOR vulnerabilities")
        
        return results
    
    def _test_numeric_idor(self, url: str, method: str, params: Dict[str, Any], 
                          param_name: str, baseline_response: Dict[str, Any], 
                          headers: Optional[Dict[str, str]] = None, 
                          verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for numeric IDOR vulnerabilities"""
        
        results = []
        original_value = params.get(param_name, '')
        
        # Only test if the original value looks numeric
        if not str(original_value).isdigit():
            return results
        
        numeric_payloads = [
            str(int(original_value) + 1),
            str(int(original_value) - 1),
            str(int(original_value) + 10),
            str(int(original_value) - 10),
            "1", "2", "3", "4", "5", "10", "100", "1000",
            "0", "-1", "-2", "999999", "1000000"
        ]
        
        for payload in numeric_payloads:
            if payload == original_value:
                continue  # Skip testing the original value
            
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                analysis = self.analyzer.analyze_idor_response(baseline_response, response, payload)
                if analysis:
                    results.append({
                        'type': 'idor',
                        'parameter': param_name,
                        'payload': payload,
                        'method': analysis.get('method', 'numeric'),
                        'evidence': analysis.get('evidence', ''),
                        'response_code': analysis.get('response_code', 0),
                        'original_value': original_value
                    })
                    
                    if verbose:
                        print(f"   🔴 IDOR vulnerability found: {analysis.get('evidence', '')}")
        
        return results
    
    def _test_string_idor(self, url: str, method: str, params: Dict[str, Any], 
                         param_name: str, baseline_response: Dict[str, Any], 
                         headers: Optional[Dict[str, str]] = None, 
                         verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for string/UUID IDOR vulnerabilities"""
        
        results = []
        original_value = params.get(param_name, '')
        
        string_payloads = [
            "admin", "administrator", "root", "user", "test",
            "demo", "guest", "public", "anonymous", "system",
            "00000000-0000-0000-0000-000000000001",
            "11111111-1111-1111-1111-111111111111",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "12345678-1234-1234-1234-123456789012",
            "ABC123", "123ABC", "TOKEN123", "SESSION123",
            "null", "undefined", "NaN", "*", "%"
        ]
        
        for payload in string_payloads:
            if payload == original_value:
                continue  # Skip testing the original value
            
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                analysis = self.analyzer.analyze_idor_response(baseline_response, response, payload)
                if analysis:
                    results.append({
                        'type': 'idor',
                        'parameter': param_name,
                        'payload': payload,
                        'method': analysis.get('method', 'string'),
                        'evidence': analysis.get('evidence', ''),
                        'response_code': analysis.get('response_code', 0),
                        'original_value': original_value
                    })
                    
                    if verbose:
                        print(f"   🔴 IDOR vulnerability found: {analysis.get('evidence', '')}")
        
        return results
    
    def _test_path_idor(self, url: str, method: str, params: Dict[str, Any], 
                       param_name: str, baseline_response: Dict[str, Any], 
                       headers: Optional[Dict[str, str]] = None, 
                       verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for path-based IDOR vulnerabilities"""
        
        results = []
        original_value = params.get(param_name, '')
        
        path_payloads = [
            "../", "../../", "../../../",
            "..", "..%2F", "..%5c",
            "config.php", "config.json", "settings.ini",
            "users.txt", "passwords.txt", "database.sql",
            ".env", ".htaccess", "web.config",
            "wp-config.php", "config/database.yml"
        ]
        
        for payload in path_payloads:
            if payload == original_value:
                continue  # Skip testing the original value
            
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                analysis = self.analyzer.analyze_idor_response(baseline_response, response, payload)
                if analysis:
                    results.append({
                        'type': 'idor',
                        'parameter': param_name,
                        'payload': payload,
                        'method': analysis.get('method', 'path_based'),
                        'evidence': analysis.get('evidence', ''),
                        'response_code': analysis.get('response_code', 0),
                        'original_value': original_value
                    })
                    
                    if verbose:
                        print(f"   🔴 Path-based IDOR vulnerability found: {analysis.get('evidence', '')}")
        
        return results
    
    def _test_file_idor(self, url: str, method: str, params: Dict[str, Any], 
                       param_name: str, baseline_response: Dict[str, Any], 
                       headers: Optional[Dict[str, str]] = None, 
                       verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for file-based IDOR vulnerabilities"""
        
        results = []
        original_value = params.get(param_name, '')
        
        file_payloads = [
            "file1.txt", "file2.txt", "document1.pdf", "document2.pdf",
            "image1.jpg", "image2.jpg", "report.pdf", "backup.zip",
            "config.xml", "settings.json", "data.csv", "export.xlsx",
            "private.txt", "confidential.doc", "secret.pdf"
        ]
        
        for payload in file_payloads:
            if payload == original_value:
                continue  # Skip testing the original value
            
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                analysis = self.analyzer.analyze_idor_response(baseline_response, response, payload)
                if analysis:
                    results.append({
                        'type': 'idor',
                        'parameter': param_name,
                        'payload': payload,
                        'method': analysis.get('method', 'file_based'),
                        'evidence': analysis.get('evidence', ''),
                        'response_code': analysis.get('response_code', 0),
                        'original_value': original_value
                    })
                    
                    if verbose:
                        print(f"   🔴 File-based IDOR vulnerability found: {analysis.get('evidence', '')}")
        
        return results