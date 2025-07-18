"""
Advanced logging system for SPECTR vulnerability scanner
"""

import logging
import os
import sys
from datetime import datetime
from typing import Optional, Dict, Any
from logging.handlers import RotatingFileHandler
import json

class SpectrLogger:
    """Advanced logger for SPECTR scanner"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger('SPECTR')
        
        # Configure logger
        self._setup_logger()
        
        # Statistics
        self.stats = {
            'requests_made': 0,
            'vulnerabilities_found': 0,
            'errors_encountered': 0,
            'start_time': None,
            'end_time': None,
            'scan_duration': 0,
            'targets_scanned': 0,
            'detectors_used': [],
            'payloads_tested': 0,
        }
    
    def _setup_logger(self):
        """Setup logger with handlers and formatters"""
        
        # Clear existing handlers
        self.logger.handlers = []
        
        # Set log level
        log_level = self.config.get('level', 'INFO').upper()
        self.logger.setLevel(getattr(logging, log_level))
        
        # Create formatter
        formatter = logging.Formatter(
            self.config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler (if enabled)
        if self.config.get('enabled', True):
            log_file = self.config.get('file', './logs/spectr.log')
            
            # Create logs directory if it doesn't exist
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            
            # Parse max size
            max_size = self._parse_size(self.config.get('max_size', '10MB'))
            backup_count = self.config.get('backup_count', 5)
            
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_size,
                backupCount=backup_count
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string like '10MB' to bytes"""
        size_str = size_str.upper()
        
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def start_scan(self, target: str, config: Dict[str, Any]):
        """Log scan start"""
        self.stats['start_time'] = datetime.now()
        self.stats['targets_scanned'] += 1
        
        self.logger.info(f"Starting SPECTR scan")
        self.logger.info(f"Target: {target}")
        self.logger.info(f"Method: {config.get('method', 'GET')}")
        self.logger.info(f"Parameters: {len(config.get('params', {}))}")
        self.logger.info(f"Headers: {len(config.get('headers', {}))}")
        self.logger.info(f"Verbose: {config.get('verbose', False)}")
        
        # Log enabled detectors
        enabled_detectors = config.get('detectors', [])
        self.stats['detectors_used'] = enabled_detectors
        self.logger.info(f"Enabled detectors: {', '.join(enabled_detectors)}")
    
    def end_scan(self, results: list):
        """Log scan end"""
        self.stats['end_time'] = datetime.now()
        self.stats['scan_duration'] = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        self.stats['vulnerabilities_found'] = len(results)
        
        self.logger.info(f"Scan completed in {self.stats['scan_duration']:.2f} seconds")
        self.logger.info(f"Vulnerabilities found: {self.stats['vulnerabilities_found']}")
        self.logger.info(f"Requests made: {self.stats['requests_made']}")
        self.logger.info(f"Payloads tested: {self.stats['payloads_tested']}")
        
        # Log vulnerability summary
        if results:
            vuln_types = {}
            for result in results:
                vuln_type = result.get('type', 'unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            self.logger.info("Vulnerability breakdown:")
            for vuln_type, count in vuln_types.items():
                self.logger.info(f"  {vuln_type.upper()}: {count}")
    
    def log_detector_start(self, detector_name: str, param_count: int):
        """Log detector start"""
        self.logger.info(f"Starting {detector_name.upper()} detector on {param_count} parameters")
    
    def log_detector_end(self, detector_name: str, results: list):
        """Log detector end"""
        self.logger.info(f"Completed {detector_name.upper()} detector - found {len(results)} vulnerabilities")
    
    def log_request(self, url: str, method: str, params: dict, response_code: int, response_time: float):
        """Log HTTP request"""
        self.stats['requests_made'] += 1
        self.logger.debug(f"Request: {method} {url} - {response_code} ({response_time:.2f}s)")
    
    def log_payload_test(self, payload: str, param: str, detector: str):
        """Log payload test"""
        self.stats['payloads_tested'] += 1
        self.logger.debug(f"Testing {detector} payload on {param}: {payload[:50]}...")
    
    def log_vulnerability_found(self, vuln_type: str, param: str, payload: str, evidence: str):
        """Log vulnerability found"""
        self.logger.warning(f"VULNERABILITY FOUND: {vuln_type.upper()} in parameter '{param}'")
        self.logger.warning(f"  Payload: {payload}")
        self.logger.warning(f"  Evidence: {evidence}")
    
    def log_error(self, error: str, context: str = ""):
        """Log error"""
        self.stats['errors_encountered'] += 1
        self.logger.error(f"Error{' in ' + context if context else ''}: {error}")
    
    def log_warning(self, warning: str, context: str = ""):
        """Log warning"""
        self.logger.warning(f"Warning{' in ' + context if context else ''}: {warning}")
    
    def log_info(self, info: str, context: str = ""):
        """Log info"""
        self.logger.info(f"{context + ': ' if context else ''}{info}")
    
    def log_debug(self, debug: str, context: str = ""):
        """Log debug"""
        self.logger.debug(f"{context + ': ' if context else ''}{debug}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scan statistics"""
        return self.stats.copy()
    
    def export_logs(self, output_file: str):
        """Export logs to file"""
        try:
            with open(output_file, 'w') as f:
                json.dump({
                    'statistics': self.stats,
                    'timestamp': datetime.now().isoformat(),
                    'scanner': 'SPECTR',
                    'version': '1.0'
                }, f, indent=2, default=str)
            
            self.logger.info(f"Logs exported to {output_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to export logs: {e}")
    
    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            'requests_made': 0,
            'vulnerabilities_found': 0,
            'errors_encountered': 0,
            'start_time': None,
            'end_time': None,
            'scan_duration': 0,
            'targets_scanned': 0,
            'detectors_used': [],
            'payloads_tested': 0,
        }
        
        self.logger.info("Statistics reset")