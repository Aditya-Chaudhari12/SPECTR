"""
Configuration management for SPECTR vulnerability scanner
"""

import os
import json
import yaml
from typing import Dict, Any, Optional, List
from pathlib import Path

class SpectrConfig:
    """Configuration manager for SPECTR scanner"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.config = self._load_default_config()
        
        if config_file and os.path.exists(config_file):
            self._load_config_file(config_file)
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            'scanner': {
                'timeout': 10,
                'max_retries': 3,
                'delay_between_requests': 0.1,
                'user_agent': 'SPECTR/1.0 (Security Scanner)',
                'follow_redirects': True,
                'max_redirects': 3,
                'verify_ssl': False,
                'concurrent_requests': 1,
                'rate_limit': 0,  # 0 = no limit
                'stealth_mode': False,
            },
            'detectors': {
                'enabled': ['sqli', 'xss', 'idor', 'traversal', 'command_injection', 'xxe', 'ssrf'],
                'sqli': {
                    'test_error_based': True,
                    'test_time_based': True,
                    'test_boolean_based': True,
                    'test_union_based': True,
                    'time_delay': 5,
                    'max_payloads': 50,
                },
                'xss': {
                    'test_reflected': True,
                    'test_stored': True,
                    'test_dom_based': True,
                    'test_encoded': True,
                    'max_payloads': 50,
                },
                'idor': {
                    'test_numeric': True,
                    'test_string': True,
                    'test_path_based': True,
                    'test_file_based': True,
                    'max_payloads': 50,
                },
                'traversal': {
                    'test_basic': True,
                    'test_encoded': True,
                    'test_file_access': True,
                    'test_filter_bypass': True,
                    'max_payloads': 50,
                },
                'command_injection': {
                    'test_basic': True,
                    'test_time_based': True,
                    'test_blind': True,
                    'time_delay': 5,
                    'max_payloads': 50,
                },
                'xxe': {
                    'test_basic': True,
                    'test_blind': True,
                    'test_dos': False,  # Disabled by default
                    'max_payloads': 30,
                },
                'ssrf': {
                    'test_internal': True,
                    'test_cloud_metadata': True,
                    'test_port_scanning': True,
                    'test_blind': True,
                    'max_payloads': 50,
                },
            },
            'reporting': {
                'output_format': 'json',
                'save_to_file': True,
                'output_directory': './reports',
                'filename_format': 'spectr_scan_{timestamp}',
                'include_false_positives': True,
                'color_output': True,
                'verbose_output': False,
                'generate_html_report': False,
                'generate_csv_report': False,
            },
            'authentication': {
                'enabled': False,
                'type': 'basic',  # basic, bearer, cookie, custom
                'username': '',
                'password': '',
                'token': '',
                'cookies': {},
                'custom_headers': {},
            },
            'proxy': {
                'enabled': False,
                'http_proxy': '',
                'https_proxy': '',
                'proxy_auth': '',
            },
            'logging': {
                'enabled': True,
                'level': 'INFO',
                'file': './logs/spectr.log',
                'max_size': '10MB',
                'backup_count': 5,
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            },
            'custom_payloads': {
                'enabled': False,
                'sqli_file': '',
                'xss_file': '',
                'idor_file': '',
                'traversal_file': '',
                'command_injection_file': '',
                'xxe_file': '',
                'ssrf_file': '',
            },
            'scan_profiles': {
                'quick': {
                    'description': 'Quick scan with basic payloads',
                    'detectors': ['sqli', 'xss'],
                    'max_payloads_per_detector': 10,
                    'delay_between_requests': 0.05,
                },
                'comprehensive': {
                    'description': 'Comprehensive scan with all detectors',
                    'detectors': ['sqli', 'xss', 'idor', 'traversal', 'command_injection', 'xxe', 'ssrf'],
                    'max_payloads_per_detector': 100,
                    'delay_between_requests': 0.2,
                },
                'stealth': {
                    'description': 'Stealth scan with delays and rate limiting',
                    'detectors': ['sqli', 'xss', 'idor', 'traversal'],
                    'max_payloads_per_detector': 25,
                    'delay_between_requests': 1.0,
                    'stealth_mode': True,
                    'rate_limit': 10,  # requests per minute
                },
            },
        }
    
    def _load_config_file(self, config_file: str) -> None:
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.json'):
                    file_config = json.load(f)
                elif config_file.endswith(('.yml', '.yaml')):
                    file_config = yaml.safe_load(f)
                else:
                    raise ValueError(f"Unsupported config file format: {config_file}")
            
            # Merge with default config
            self._merge_config(self.config, file_config)
            
        except Exception as e:
            print(f"Warning: Could not load config file {config_file}: {e}")
    
    def _merge_config(self, default: Dict[str, Any], override: Dict[str, Any]) -> None:
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_config(default[key], value)
            else:
                default[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def get_scan_profile(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """Get scan profile configuration"""
        return self.get(f'scan_profiles.{profile_name}')
    
    def get_detector_config(self, detector_name: str) -> Dict[str, Any]:
        """Get detector-specific configuration"""
        return self.get(f'detectors.{detector_name}', {})
    
    def is_detector_enabled(self, detector_name: str) -> bool:
        """Check if detector is enabled"""
        enabled_detectors = self.get('detectors.enabled', [])
        return detector_name in enabled_detectors
    
    def get_scanner_config(self) -> Dict[str, Any]:
        """Get scanner configuration"""
        return self.get('scanner', {})
    
    def get_reporting_config(self) -> Dict[str, Any]:
        """Get reporting configuration"""
        return self.get('reporting', {})
    
    def get_authentication_config(self) -> Dict[str, Any]:
        """Get authentication configuration"""
        return self.get('authentication', {})
    
    def get_proxy_config(self) -> Dict[str, Any]:
        """Get proxy configuration"""
        return self.get('proxy', {})
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return self.get('logging', {})
    
    def save_config(self, output_file: str) -> None:
        """Save current configuration to file"""
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with open(output_file, 'w') as f:
                if output_file.endswith('.json'):
                    json.dump(self.config, f, indent=2)
                elif output_file.endswith(('.yml', '.yaml')):
                    yaml.dump(self.config, f, default_flow_style=False)
                else:
                    raise ValueError(f"Unsupported output format: {output_file}")
            
            print(f"Configuration saved to {output_file}")
            
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def create_sample_config(self, output_file: str) -> None:
        """Create a sample configuration file"""
        self.save_config(output_file)
        print(f"Sample configuration created at {output_file}")
        print("Edit this file to customize SPECTR settings")
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        # Validate scanner settings
        timeout = self.get('scanner.timeout')
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            errors.append("scanner.timeout must be a positive number")
        
        max_retries = self.get('scanner.max_retries')
        if not isinstance(max_retries, int) or max_retries < 0:
            errors.append("scanner.max_retries must be a non-negative integer")
        
        # Validate detectors
        enabled_detectors = self.get('detectors.enabled', [])
        valid_detectors = ['sqli', 'xss', 'idor', 'traversal', 'command_injection', 'xxe', 'ssrf']
        
        for detector in enabled_detectors:
            if detector not in valid_detectors:
                errors.append(f"Unknown detector: {detector}")
        
        # Validate reporting
        output_format = self.get('reporting.output_format')
        valid_formats = ['json', 'csv', 'html', 'xml']
        if output_format not in valid_formats:
            errors.append(f"Invalid output format: {output_format}")
        
        # Validate authentication
        auth_enabled = self.get('authentication.enabled')
        if auth_enabled:
            auth_type = self.get('authentication.type')
            valid_auth_types = ['basic', 'bearer', 'cookie', 'custom']
            if auth_type not in valid_auth_types:
                errors.append(f"Invalid authentication type: {auth_type}")
        
        return errors
    
    def print_config(self) -> None:
        """Print current configuration"""
        print("Current SPECTR Configuration:")
        print("=" * 50)
        self._print_dict(self.config, indent=0)
    
    def _print_dict(self, d: Dict[str, Any], indent: int = 0) -> None:
        """Recursively print dictionary with indentation"""
        for key, value in d.items():
            if isinstance(value, dict):
                print("  " * indent + f"{key}:")
                self._print_dict(value, indent + 1)
            else:
                print("  " * indent + f"{key}: {value}")