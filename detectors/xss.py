"""
Cross-Site Scripting (XSS) detector for SPECTR vulnerability scanner
"""

from typing import Dict, List, Any, Optional
from utils.http_client import HTTPClient
from core.payloads import PayloadDatabase
from core.analyzer import ResponseAnalyzer

class XSSDetector:
    """Cross-Site Scripting vulnerability detector"""
    
    def __init__(self, http_client: HTTPClient, payloads: PayloadDatabase):
        self.http_client = http_client
        self.payloads = payloads
        self.analyzer = ResponseAnalyzer()
    
    def scan(self, url: str, method: str, params: Dict[str, Any], 
             headers: Optional[Dict[str, str]] = None, verbose: bool = False) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities"""
        
        results = []
        xss_payloads = self.payloads.get_payloads('xss')
        
        if not params:
            if verbose:
                print("   ℹ️  No parameters to test for XSS")
            return results
        
        # Test each parameter
        for param_name, param_value in params.items():
            if verbose:
                print(f"   🔍 Testing parameter '{param_name}' for XSS")
            
            # Test reflected XSS
            reflected_results = self._test_reflected_xss(
                url, method, params, param_name, headers, verbose
            )
            results.extend(reflected_results)
        
        if verbose and results:
            print(f"   ✅ Found {len(results)} potential XSS vulnerabilities")
        
        return results
    
    def _test_reflected_xss(self, url: str, method: str, params: Dict[str, Any], 
                           param_name: str, headers: Optional[Dict[str, str]] = None, 
                           verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for reflected XSS vulnerabilities"""
        
        results = []
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>confirm('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<<script>alert('XSS')</script>",
            "<Script>alert('XSS')</Script>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "<style>@import'javascript:alert(\"XSS\")';</style>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "javascript:alert('XSS');//",
            "<marquee onstart=alert('XSS')>",
            "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
            "<table background=javascript:alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
            "<base href=javascript:alert('XSS')//>"
        ]
        
        for payload in xss_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                analysis = self.analyzer.analyze_xss_response(response, payload)
                if analysis:
                    results.append({
                        'type': 'xss',
                        'parameter': param_name,
                        'payload': payload,
                        'method': analysis.get('method', 'reflected'),
                        'evidence': analysis.get('evidence', ''),
                        'response_code': analysis.get('response_code', 0),
                        'reflection_found': analysis.get('reflection_found', False)
                    })
                    
                    if verbose:
                        print(f"   🔴 XSS vulnerability found: {analysis.get('evidence', '')}")
        
        return results
    
    def _test_dom_xss(self, url: str, method: str, params: Dict[str, Any], 
                     param_name: str, headers: Optional[Dict[str, str]] = None, 
                     verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for DOM-based XSS vulnerabilities"""
        
        results = []
        dom_payloads = [
            "#<script>alert('DOM-XSS')</script>",
            "#javascript:alert('DOM-XSS')",
            "#<img src=x onerror=alert('DOM-XSS')>",
            "#<svg onload=alert('DOM-XSS')>",
            "#<iframe src=javascript:alert('DOM-XSS')>",
        ]
        
        for payload in dom_payloads:
            # For DOM XSS, we append payload to URL fragment
            test_url = f"{url}#{payload}"
            
            response = self.http_client.make_request(
                url=test_url, method=method, 
                params=params if method.upper() == 'GET' else None,
                data=params if method.upper() == 'POST' else None,
                headers=headers, verbose=verbose
            )
            
            if response:
                analysis = self.analyzer.analyze_xss_response(response, payload)
                if analysis:
                    results.append({
                        'type': 'xss',
                        'parameter': 'URL_fragment',
                        'payload': payload,
                        'method': 'dom_based',
                        'evidence': analysis.get('evidence', ''),
                        'response_code': analysis.get('response_code', 0),
                        'reflection_found': analysis.get('reflection_found', False)
                    })
                    
                    if verbose:
                        print(f"   🔴 DOM-based XSS vulnerability found: {analysis.get('evidence', '')}")
        
        return results
    
    def _test_stored_xss_indicators(self, url: str, method: str, params: Dict[str, Any], 
                                   param_name: str, headers: Optional[Dict[str, str]] = None, 
                                   verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for potential stored XSS indicators"""
        
        results = []
        # Note: True stored XSS testing requires multiple requests and state management
        # This is a simplified check for potential stored XSS
        
        stored_payloads = [
            "<script>alert('STORED-XSS')</script>",
            "<img src=x onerror=alert('STORED-XSS')>",
            "<svg onload=alert('STORED-XSS')>",
        ]
        
        for payload in stored_payloads:
            # First, submit the payload
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response and response.get('status_code') == 200:
                # Then, make a follow-up request to see if payload is stored
                followup_response = self.http_client.make_request(
                    url=url, method='GET', headers=headers, verbose=verbose
                )
                
                if followup_response:
                    analysis = self.analyzer.analyze_xss_response(followup_response, payload)
                    if analysis:
                        results.append({
                            'type': 'xss',
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'stored_potential',
                            'evidence': f"Payload may be stored: {analysis.get('evidence', '')}",
                            'response_code': followup_response.get('status_code', 0),
                            'reflection_found': analysis.get('reflection_found', False)
                        })
                        
                        if verbose:
                            print(f"   🔴 Potential stored XSS found: {analysis.get('evidence', '')}")
        
        return results