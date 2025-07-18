"""
Response analyzer for SPECTR vulnerability scanner
"""

import re
import time
from typing import Dict, List, Any, Optional

class ResponseAnalyzer:
    """Analyzes HTTP responses for vulnerability indicators"""
    
    def __init__(self):
        self.sql_error_patterns = [
            r"mysql_fetch_array\(\)",
            r"ORA-\d+",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"PostgreSQL.*ERROR",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"Microsoft Access Driver",
            r"Microsoft JET Database Engine",
            r"Error Occurred While Processing Request",
            r"Server Error in .* Application",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark after the character string",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"SQL command not properly ended",
            r"unexpected end of SQL command",
            r"Warning.*PostgreSQL",
            r"Error.*SQLite",
            r"sqlite3.OperationalError",
            r"Oracle error",
            r"Oracle.*ORA-\d+",
            r"quoted string not properly terminated",
        ]
        
        self.xss_reflection_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"alert\s*\(",
            r"confirm\s*\(",
            r"prompt\s*\(",
            r"eval\s*\(",
            r"setTimeout\s*\(",
            r"setInterval\s*\(",
        ]
        
        self.path_traversal_patterns = [
            r"root:.*:0:0:",
            r"daemon:.*:1:1:",
            r"bin:.*:2:2:",
            r"sys:.*:3:3:",
            r"\[system\]",
            r"\[boot loader\]",
            r"Directory of",
            r"Volume in drive",
            r"Volume Serial Number",
            r"<DIR>",
            r"total \d+",
            r"drwxr-xr-x",
            r"-rw-r--r--",
            r"Permission denied",
            r"No such file or directory",
            r"is a directory",
            r"cannot access",
        ]
    
    def analyze_sqli_response(self, response: Dict[str, Any], payload: str) -> Optional[Dict[str, Any]]:
        """Analyze response for SQL injection indicators"""
        if not response:
            return None
        
        content = response.get('content', '').lower()
        status_code = response.get('status_code', 200)
        response_time = response.get('response_time', 0)
        
        # Check for SQL error patterns
        for pattern in self.sql_error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    'type': 'sqli',
                    'method': 'error_based',
                    'payload': payload,
                    'evidence': f"SQL error pattern detected: {pattern}",
                    'response_code': status_code,
                    'response_time': response_time
                }
        
        # Check for time-based SQL injection
        if response_time > 5 and any(delay_keyword in payload.lower() for delay_keyword in ['sleep', 'waitfor', 'pg_sleep']):
            return {
                'type': 'sqli',
                'method': 'time_based',
                'payload': payload,
                'evidence': f"Response time delay detected: {response_time:.2f}s",
                'response_code': status_code,
                'response_time': response_time
            }
        
        # Check for boolean-based indicators
        if status_code != 200:
            return {
                'type': 'sqli',
                'method': 'boolean_based',
                'payload': payload,
                'evidence': f"Unexpected status code: {status_code}",
                'response_code': status_code,
                'response_time': response_time
            }
        
        return None
    
    def analyze_xss_response(self, response: Dict[str, Any], payload: str) -> Optional[Dict[str, Any]]:
        """Analyze response for XSS indicators"""
        if not response:
            return None
        
        content = response.get('content', '')
        status_code = response.get('status_code', 200)
        
        # Check if payload is reflected in response
        if payload in content:
            return {
                'type': 'xss',
                'method': 'reflected',
                'payload': payload,
                'evidence': f"Payload reflected in response",
                'response_code': status_code,
                'reflection_found': True
            }
        
        # Check for XSS patterns in response
        for pattern in self.xss_reflection_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return {
                    'type': 'xss',
                    'method': 'pattern_based',
                    'payload': payload,
                    'evidence': f"XSS pattern detected: {matches[0]}",
                    'response_code': status_code,
                    'reflection_found': False
                }
        
        return None
    
    def analyze_idor_response(self, baseline_response: Dict[str, Any], test_response: Dict[str, Any], payload: str) -> Optional[Dict[str, Any]]:
        """Analyze response for IDOR indicators"""
        if not baseline_response or not test_response:
            return None
        
        baseline_content = baseline_response.get('content', '')
        test_content = test_response.get('content', '')
        baseline_status = baseline_response.get('status_code', 200)
        test_status = test_response.get('status_code', 200)
        
        # Check for status code differences
        if baseline_status != test_status:
            # 200 vs 403/401 might indicate access control
            if baseline_status == 200 and test_status in [401, 403]:
                return None  # This is expected behavior, not a vulnerability
            
            # Different content with same success status might indicate IDOR
            if test_status == 200 and baseline_status == 200:
                content_diff = abs(len(test_content) - len(baseline_content))
                if content_diff > 100:  # Significant content difference
                    return {
                        'type': 'idor',
                        'method': 'content_diff',
                        'payload': payload,
                        'evidence': f"Content length difference: {content_diff} bytes",
                        'response_code': test_status,
                        'baseline_code': baseline_status
                    }
        
        # Check for different content with same status
        if baseline_status == test_status == 200:
            # Simple content difference check
            if test_content != baseline_content:
                content_diff = abs(len(test_content) - len(baseline_content))
                if content_diff > 50:  # Significant difference
                    return {
                        'type': 'idor',
                        'method': 'content_variation',
                        'payload': payload,
                        'evidence': f"Different content returned for modified parameter",
                        'response_code': test_status,
                        'content_diff': content_diff
                    }
        
        return None
    
    def analyze_traversal_response(self, response: Dict[str, Any], payload: str) -> Optional[Dict[str, Any]]:
        """Analyze response for path traversal indicators"""
        if not response:
            return None
        
        content = response.get('content', '')
        status_code = response.get('status_code', 200)
        
        # Check for path traversal patterns
        for pattern in self.path_traversal_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return {
                    'type': 'traversal',
                    'method': 'pattern_based',
                    'payload': payload,
                    'evidence': f"Path traversal pattern detected: {matches[0]}",
                    'response_code': status_code,
                    'pattern_match': matches[0]
                }
        
        # Check for file content indicators
        if status_code == 200:
            # Check for common Unix file patterns
            if re.search(r'root:.*:0:0:', content):
                return {
                    'type': 'traversal',
                    'method': 'file_access',
                    'payload': payload,
                    'evidence': "Unix passwd file content detected",
                    'response_code': status_code,
                    'file_type': 'passwd'
                }
            
            # Check for Windows file patterns
            if re.search(r'\[system\]|\[boot loader\]', content, re.IGNORECASE):
                return {
                    'type': 'traversal',
                    'method': 'file_access',
                    'payload': payload,
                    'evidence': "Windows system file content detected",
                    'response_code': status_code,
                    'file_type': 'windows_system'
                }
        
        return None
    
    def compare_responses(self, response1: Dict[str, Any], response2: Dict[str, Any]) -> Dict[str, Any]:
        """Compare two responses for differences"""
        if not response1 or not response2:
            return {'different': True, 'reason': 'Missing response'}
        
        content1 = response1.get('content', '')
        content2 = response2.get('content', '')
        status1 = response1.get('status_code', 200)
        status2 = response2.get('status_code', 200)
        
        differences = {}
        
        # Status code difference
        if status1 != status2:
            differences['status_code'] = {
                'response1': status1,
                'response2': status2
            }
        
        # Content length difference
        len_diff = abs(len(content1) - len(content2))
        if len_diff > 0:
            differences['content_length'] = {
                'response1': len(content1),
                'response2': len(content2),
                'difference': len_diff
            }
        
        # Content similarity
        if content1 != content2:
            differences['content_different'] = True
        
        return differences