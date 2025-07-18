"""
SQL Injection detector for SPECTR vulnerability scanner
"""

import time
from typing import Dict, List, Any, Optional
from utils.http_client import HTTPClient
from core.payloads import PayloadDatabase
from core.analyzer import ResponseAnalyzer

class SQLiDetector:
    """SQL Injection vulnerability detector"""
    
    def __init__(self, http_client: HTTPClient, payloads: PayloadDatabase):
        self.http_client = http_client
        self.payloads = payloads
        self.analyzer = ResponseAnalyzer()
    
    def scan(self, url: str, method: str, params: Dict[str, Any], 
             headers: Optional[Dict[str, str]] = None, verbose: bool = False) -> List[Dict[str, Any]]:
        """Scan for SQL injection vulnerabilities"""
        
        results = []
        sqli_payloads = self.payloads.get_payloads('sqli')
        
        if not params:
            if verbose:
                print("   ℹ️  No parameters to test for SQL injection")
            return results
        
        # Get baseline response for comparison
        baseline_response = self.http_client.get_baseline_response(
            url=url, method=method, params=params, headers=headers, verbose=verbose
        )
        
        if not baseline_response:
            if verbose:
                print("   ❌ Could not get baseline response")
            return results
        
        # Test each parameter
        for param_name, param_value in params.items():
            if verbose:
                print(f"   🔍 Testing parameter '{param_name}' for SQL injection")
            
            # Test error-based SQL injection
            error_results = self._test_error_based_sqli(
                url, method, params, param_name, headers, verbose
            )
            results.extend(error_results)
            
            # Test time-based SQL injection
            time_results = self._test_time_based_sqli(
                url, method, params, param_name, headers, verbose
            )
            results.extend(time_results)
            
            # Test boolean-based SQL injection
            boolean_results = self._test_boolean_based_sqli(
                url, method, params, param_name, baseline_response, headers, verbose
            )
            results.extend(boolean_results)
        
        if verbose and results:
            print(f"   ✅ Found {len(results)} potential SQL injection vulnerabilities")
        
        return results
    
    def _test_error_based_sqli(self, url: str, method: str, params: Dict[str, Any], 
                              param_name: str, headers: Optional[Dict[str, str]] = None, 
                              verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for error-based SQL injection"""
        
        results = []
        error_payloads = [
            "'", "\"", "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", 
            "admin'--", "admin' #", "') OR ('1'='1", "' UNION SELECT 1,2,3--"
        ]
        
        for payload in error_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                analysis = self.analyzer.analyze_sqli_response(response, payload)
                if analysis:
                    results.append({
                        'type': 'sqli',
                        'parameter': param_name,
                        'payload': payload,
                        'method': analysis.get('method', 'error_based'),
                        'evidence': analysis.get('evidence', ''),
                        'response_code': analysis.get('response_code', 0),
                        'response_time': analysis.get('response_time', 0)
                    })
                    
                    if verbose:
                        print(f"   🔴 SQL injection found: {analysis.get('evidence', '')}")
        
        return results
    
    def _test_time_based_sqli(self, url: str, method: str, params: Dict[str, Any], 
                             param_name: str, headers: Optional[Dict[str, str]] = None, 
                             verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for time-based SQL injection"""
        
        results = []
        time_payloads = [
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)--",
            "' OR pg_sleep(5)--",
            "'; SELECT pg_sleep(5)--",
            "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) AS x) = 3 AND SLEEP(5)--"
        ]
        
        for payload in time_payloads:
            start_time = time.time()
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                analysis = self.analyzer.analyze_sqli_response(response, payload)
                if analysis and analysis.get('method') == 'time_based':
                    results.append({
                        'type': 'sqli',
                        'parameter': param_name,
                        'payload': payload,
                        'method': 'time_based',
                        'evidence': analysis.get('evidence', ''),
                        'response_code': analysis.get('response_code', 0),
                        'response_time': analysis.get('response_time', 0)
                    })
                    
                    if verbose:
                        print(f"   🔴 Time-based SQL injection found: {analysis.get('evidence', '')}")
        
        return results
    
    def _test_boolean_based_sqli(self, url: str, method: str, params: Dict[str, Any], 
                                param_name: str, baseline_response: Dict[str, Any], 
                                headers: Optional[Dict[str, str]] = None, 
                                verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for boolean-based SQL injection"""
        
        results = []
        boolean_payloads = [
            ("' AND 1=1--", "' AND 1=2--"),  # True vs False
            ("' OR 'a'='a", "' OR 'a'='b"),  # True vs False
            ("' AND 1=1#", "' AND 1=2#"),    # True vs False
        ]
        
        for true_payload, false_payload in boolean_payloads:
            # Test true condition
            true_response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=true_payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            # Test false condition
            false_response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=false_payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if true_response and false_response:
                # Compare responses
                differences = self.analyzer.compare_responses(true_response, false_response)
                
                # If responses are different, it might indicate boolean-based SQLi
                if differences and ('status_code' in differences or 'content_length' in differences):
                    results.append({
                        'type': 'sqli',
                        'parameter': param_name,
                        'payload': f"{true_payload} vs {false_payload}",
                        'method': 'boolean_based',
                        'evidence': f"Different responses for true/false conditions: {differences}",
                        'response_code': true_response.get('status_code', 0),
                        'response_time': true_response.get('response_time', 0)
                    })
                    
                    if verbose:
                        print(f"   🔴 Boolean-based SQL injection found: Different responses detected")
        
        return results