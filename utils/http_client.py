"""
HTTP client utility for SPECTR vulnerability scanner
"""

import requests
import time
import urllib3
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
import warnings

# Suppress SSL warnings for security testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HTTPClient:
    """HTTP client for making requests during vulnerability scanning"""
    
    def __init__(self, timeout: int = 10, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        
        # Set default headers to mimic a real browser
        self.session.headers.update({
            'User-Agent': 'SPECTR/1.0 (Security Scanner)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Configure session for security testing
        self.session.verify = False  # Disable SSL verification for testing
        self.session.allow_redirects = True
        self.session.max_redirects = 3
    
    def make_request(self, url: str, method: str = 'GET', params: Optional[Dict[str, Any]] = None, 
                    headers: Optional[Dict[str, str]] = None, data: Optional[Dict[str, Any]] = None,
                    verbose: bool = False) -> Optional[Dict[str, Any]]:
        """Make HTTP request and return response details"""
        
        # Prepare request parameters
        req_params = params or {}
        req_headers = headers or {}
        req_data = data or {}
        
        # Merge custom headers with default headers
        merged_headers = {**self.session.headers, **req_headers}
        
        start_time = time.time()
        
        try:
            if verbose:
                print(f"   → Making {method} request to {url}")
                if req_params:
                    print(f"   → Parameters: {req_params}")
                if req_headers:
                    print(f"   → Headers: {req_headers}")
            
            # Make the request
            if method.upper() == 'GET':
                response = self.session.get(
                    url, 
                    params=req_params, 
                    headers=merged_headers,
                    timeout=self.timeout
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    url,
                    params=req_params,
                    data=req_data,
                    headers=merged_headers,
                    timeout=self.timeout
                )
            else:
                if verbose:
                    print(f"   ⚠️  Unsupported method: {method}")
                return None
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # Extract response details
            response_data = {
                'status_code': response.status_code,
                'content': response.text,
                'headers': dict(response.headers),
                'response_time': response_time,
                'url': response.url,
                'history': [r.status_code for r in response.history]
            }
            
            if verbose:
                print(f"   ← Response: {response.status_code} ({response_time:.2f}s)")
                print(f"   ← Content length: {len(response.text)} bytes")
            
            return response_data
            
        except requests.exceptions.Timeout:
            if verbose:
                print(f"   ❌ Request timeout after {self.timeout}s")
            return {
                'status_code': 0,
                'content': '',
                'headers': {},
                'response_time': self.timeout,
                'url': url,
                'error': 'timeout'
            }
        except requests.exceptions.ConnectionError:
            if verbose:
                print(f"   ❌ Connection error")
            return {
                'status_code': 0,
                'content': '',
                'headers': {},
                'response_time': time.time() - start_time,
                'url': url,
                'error': 'connection_error'
            }
        except requests.exceptions.RequestException as e:
            if verbose:
                print(f"   ❌ Request error: {e}")
            return {
                'status_code': 0,
                'content': '',
                'headers': {},
                'response_time': time.time() - start_time,
                'url': url,
                'error': str(e)
            }
        except Exception as e:
            if verbose:
                print(f"   ❌ Unexpected error: {e}")
            return None
    
    def test_payload(self, url: str, method: str, params: Dict[str, Any], 
                    payload: str, target_param: str, headers: Optional[Dict[str, str]] = None,
                    verbose: bool = False) -> Optional[Dict[str, Any]]:
        """Test a specific payload by injecting it into a parameter"""
        
        # Create a copy of parameters and inject payload
        test_params = params.copy()
        original_value = test_params.get(target_param, '')
        
        # Inject payload into the target parameter
        test_params[target_param] = payload
        
        if verbose:
            print(f"   🧪 Testing payload '{payload}' in parameter '{target_param}'")
        
        # Make the request with injected payload
        response = self.make_request(
            url=url,
            method=method,
            params=test_params if method.upper() == 'GET' else None,
            data=test_params if method.upper() == 'POST' else None,
            headers=headers,
            verbose=verbose
        )
        
        if response:
            response['payload'] = payload
            response['target_parameter'] = target_param
            response['original_value'] = original_value
        
        return response
    
    def get_baseline_response(self, url: str, method: str, params: Dict[str, Any], 
                             headers: Optional[Dict[str, str]] = None, verbose: bool = False) -> Optional[Dict[str, Any]]:
        """Get baseline response for comparison"""
        
        if verbose:
            print(f"   📊 Getting baseline response")
        
        return self.make_request(
            url=url,
            method=method,
            params=params if method.upper() == 'GET' else None,
            data=params if method.upper() == 'POST' else None,
            headers=headers,
            verbose=verbose
        )
    
    def batch_test_payloads(self, url: str, method: str, params: Dict[str, Any], 
                           payloads: list, target_param: str, 
                           headers: Optional[Dict[str, str]] = None, 
                           verbose: bool = False) -> list:
        """Test multiple payloads against a target parameter"""
        
        results = []
        
        if verbose:
            print(f"   🚀 Testing {len(payloads)} payloads against parameter '{target_param}'")
        
        for i, payload in enumerate(payloads, 1):
            if verbose:
                print(f"   [{i}/{len(payloads)}] Testing: {payload[:50]}{'...' if len(payload) > 50 else ''}")
            
            response = self.test_payload(
                url=url,
                method=method,
                params=params,
                payload=payload,
                target_param=target_param,
                headers=headers,
                verbose=False  # Reduce verbosity for batch operations
            )
            
            if response:
                results.append(response)
            
            # Small delay to avoid overwhelming the server
            time.sleep(0.1)
        
        return results
    
    def close(self):
        """Close the HTTP session"""
        self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()