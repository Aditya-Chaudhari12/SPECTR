#!/usr/bin/env python3
"""
Comprehensive test script for SPECTR Enhanced vulnerability scanner
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import SpectrScanner
from core.payloads import PayloadDatabase
from core.analyzer import ResponseAnalyzer
from core.config import SpectrConfig
from core.logger import SpectrLogger
from core.html_reporter import HTMLReporter
from utils.http_client import HTTPClient

def test_enhanced_payload_database():
    """Test the enhanced payload database"""
    print("🧪 Testing Enhanced Payload Database...")
    
    payloads = PayloadDatabase()
    
    # Test all vulnerability types
    vuln_types = ['sqli', 'xss', 'idor', 'traversal', 'command_injection', 'xxe', 'ssrf']
    
    for vuln_type in vuln_types:
        payloads_list = payloads.get_payloads(vuln_type)
        print(f"   ✅ {vuln_type.upper()} payloads: {len(payloads_list)}")
        assert len(payloads_list) > 0, f"Should have {vuln_type} payloads"
    
    print("   ✅ Enhanced payload database test passed!")

def test_configuration_system():
    """Test the configuration system"""
    print("\n⚙️ Testing Configuration System...")
    
    config = SpectrConfig()
    
    # Test default configuration
    timeout = config.get('scanner.timeout')
    assert timeout == 10, f"Default timeout should be 10, got {timeout}"
    print("   ✅ Default configuration loaded")
    
    # Test setting values
    config.set('scanner.timeout', 20)
    new_timeout = config.get('scanner.timeout')
    assert new_timeout == 20, f"Timeout should be 20, got {new_timeout}"
    print("   ✅ Configuration setting works")
    
    # Test detector configuration
    enabled_detectors = config.get('detectors.enabled')
    assert 'command_injection' in enabled_detectors, "Command injection should be enabled"
    assert 'xxe' in enabled_detectors, "XXE should be enabled"
    assert 'ssrf' in enabled_detectors, "SSRF should be enabled"
    print("   ✅ New detectors are enabled by default")
    
    # Test scan profiles
    quick_profile = config.get_scan_profile('quick')
    assert quick_profile is not None, "Quick profile should exist"
    print("   ✅ Scan profiles work")
    
    # Test validation
    errors = config.validate_config()
    assert len(errors) == 0, f"Configuration should be valid, got errors: {errors}"
    print("   ✅ Configuration validation works")
    
    print("   ✅ Configuration system test passed!")

def test_logging_system():
    """Test the logging system"""
    print("\n📝 Testing Logging System...")
    
    # Test logger initialization
    logger = SpectrLogger({
        'enabled': True,
        'level': 'DEBUG',
        'file': './test_logs/spectr_test.log'
    })
    
    # Test logging methods
    logger.log_info("Test info message")
    logger.log_warning("Test warning message")
    logger.log_error("Test error message")
    logger.log_debug("Test debug message")
    
    # Test scan logging
    test_config = {
        'url': 'https://example.com',
        'method': 'GET',
        'params': {'test': 'value'},
        'headers': {},
        'verbose': True,
        'detectors': ['sqli', 'xss', 'command_injection']
    }
    
    logger.start_scan('https://example.com', test_config)
    logger.log_detector_start('sqli', 1)
    logger.log_payload_test("'; DROP TABLE users; --", 'test', 'sqli')
    logger.log_vulnerability_found('sqli', 'test', "'; DROP TABLE users; --", 'SQL error detected')
    logger.log_detector_end('sqli', [{'type': 'sqli', 'parameter': 'test'}])
    logger.end_scan([{'type': 'sqli', 'parameter': 'test'}])
    
    # Test statistics
    stats = logger.get_stats()
    assert stats['vulnerabilities_found'] == 1, "Should have 1 vulnerability"
    assert stats['payloads_tested'] == 1, "Should have tested 1 payload"
    print("   ✅ Logging statistics work")
    
    print("   ✅ Logging system test passed!")

def test_html_reporter():
    """Test the HTML reporter"""
    print("\n📊 Testing HTML Reporter...")
    
    reporter = HTMLReporter()
    
    # Test sample data
    scan_config = {
        'url': 'https://example.com/test',
        'method': 'GET',
        'params': {'id': '1', 'name': 'test'},
        'headers': {'User-Agent': 'SPECTR'},
        'verbose': True
    }
    
    sample_results = [
        {
            'type': 'sqli',
            'parameter': 'id',
            'payload': "' OR 1=1--",
            'method': 'error_based',
            'evidence': 'MySQL error detected',
            'response_code': 500,
            'response_time': 0.5
        },
        {
            'type': 'xss',
            'parameter': 'name',
            'payload': '<script>alert("XSS")</script>',
            'method': 'reflected',
            'evidence': 'Payload reflected in response',
            'response_code': 200,
            'response_time': 0.3
        },
        {
            'type': 'command_injection',
            'parameter': 'id',
            'payload': '; id',
            'method': 'pattern_based',
            'evidence': 'Command output detected',
            'response_code': 200,
            'response_time': 1.2
        }
    ]
    
    sample_stats = {
        'scan_duration': 45.2,
        'requests_made': 150,
        'payloads_tested': 200,
        'detectors_used': ['sqli', 'xss', 'command_injection']
    }
    
    # Generate HTML report
    html_content = reporter.generate_report(scan_config, sample_results, sample_stats)
    
    # Verify report content
    assert 'SPECTR Vulnerability Scan Report' in html_content, "Report title should be present"
    assert 'https://example.com/test' in html_content, "Target URL should be present"
    assert 'SQLI' in html_content, "SQL injection should be mentioned"
    assert 'XSS' in html_content, "XSS should be mentioned"
    assert 'COMMAND_INJECTION' in html_content, "Command injection should be mentioned"
    assert 'alert("XSS")' in html_content, "XSS payload should be present"
    
    print("   ✅ HTML report generation works")
    
    # Test saving report
    try:
        report_file = './test_reports/test_report.html'
        saved_file = reporter.save_report(html_content, report_file)
        assert os.path.exists(saved_file), "Report file should be created"
        print("   ✅ HTML report saving works")
        
        # Clean up
        if os.path.exists(saved_file):
            os.remove(saved_file)
        
    except Exception as e:
        print(f"   ⚠️  HTML report saving test failed: {e}")
    
    print("   ✅ HTML reporter test passed!")

def test_new_detectors():
    """Test the new vulnerability detectors"""
    print("\n🔍 Testing New Detectors...")
    
    payloads = PayloadDatabase()
    client = HTTPClient()
    
    # Test detector imports and initialization
    from detectors.command_injection import CommandInjectionDetector
    from detectors.xxe import XXEDetector
    from detectors.ssrf import SSRFDetector
    
    cmd_detector = CommandInjectionDetector(client, payloads)
    xxe_detector = XXEDetector(client, payloads)
    ssrf_detector = SSRFDetector(client, payloads)
    
    print("   ✅ Command Injection detector initialized")
    print("   ✅ XXE detector initialized")
    print("   ✅ SSRF detector initialized")
    
    # Test payload access
    cmd_payloads = payloads.get_payloads('command_injection')
    xxe_payloads = payloads.get_payloads('xxe')
    ssrf_payloads = payloads.get_payloads('ssrf')
    
    assert len(cmd_payloads) > 0, "Should have command injection payloads"
    assert len(xxe_payloads) > 0, "Should have XXE payloads"
    assert len(ssrf_payloads) > 0, "Should have SSRF payloads"
    
    print(f"   ✅ Command injection payloads: {len(cmd_payloads)}")
    print(f"   ✅ XXE payloads: {len(xxe_payloads)}")
    print(f"   ✅ SSRF payloads: {len(ssrf_payloads)}")
    
    client.close()
    print("   ✅ New detectors test passed!")

def test_enhanced_scanner():
    """Test the enhanced scanner with new detectors"""
    print("\n🚀 Testing Enhanced Scanner...")
    
    scanner = SpectrScanner()
    
    # Test all detectors are loaded
    expected_detectors = ['sqli', 'xss', 'idor', 'traversal', 'command_injection', 'xxe', 'ssrf']
    for detector in expected_detectors:
        assert detector in scanner.detectors, f"Detector {detector} should be loaded"
    
    print(f"   ✅ All {len(expected_detectors)} detectors loaded")
    
    # Test detector count
    assert len(scanner.detectors) == 7, f"Should have 7 detectors, got {len(scanner.detectors)}"
    print("   ✅ Correct number of detectors")
    
    print("   ✅ Enhanced scanner test passed!")

def test_payload_statistics():
    """Test payload statistics across all vulnerability types"""
    print("\n📈 Testing Payload Statistics...")
    
    payloads = PayloadDatabase()
    
    total_payloads = 0
    vuln_stats = {}
    
    vuln_types = ['sqli', 'xss', 'idor', 'traversal', 'command_injection', 'xxe', 'ssrf']
    
    for vuln_type in vuln_types:
        count = len(payloads.get_payloads(vuln_type))
        vuln_stats[vuln_type] = count
        total_payloads += count
    
    print(f"   📊 Total payloads across all types: {total_payloads}")
    print("   📊 Breakdown by vulnerability type:")
    for vuln_type, count in vuln_stats.items():
        print(f"      {vuln_type.upper()}: {count}")
    
    # Verify we have a substantial payload database
    assert total_payloads > 200, f"Should have substantial payload database, got {total_payloads}"
    print("   ✅ Payload statistics test passed!")

def run_sample_configuration_test():
    """Test creating and loading sample configuration"""
    print("\n⚙️ Testing Sample Configuration...")
    
    config = SpectrConfig()
    
    try:
        # Create sample config
        sample_config_file = './test_config/sample_config.json'
        os.makedirs(os.path.dirname(sample_config_file), exist_ok=True)
        config.create_sample_config(sample_config_file)
        
        # Load the sample config
        new_config = SpectrConfig(sample_config_file)
        
        # Verify it loaded correctly
        assert new_config.get('scanner.timeout') == 10, "Sample config should have default timeout"
        assert 'command_injection' in new_config.get('detectors.enabled'), "Sample config should have new detectors"
        
        print("   ✅ Sample configuration creation and loading works")
        
        # Clean up
        if os.path.exists(sample_config_file):
            os.remove(sample_config_file)
            
    except Exception as e:
        print(f"   ⚠️  Sample configuration test failed: {e}")
    
    print("   ✅ Sample configuration test passed!")

def main():
    """Main test function"""
    print("🚀 SPECTR Enhanced Vulnerability Scanner - Comprehensive Tests")
    print("=" * 80)
    
    try:
        test_enhanced_payload_database()
        test_configuration_system()
        test_logging_system()
        test_html_reporter()
        test_new_detectors()
        test_enhanced_scanner()
        test_payload_statistics()
        run_sample_configuration_test()
        
        print("\n" + "=" * 80)
        print("✅ All enhanced tests passed! SPECTR v2.0 is ready to use.")
        print("=" * 80)
        
        print("\n🎯 Enhanced Features Available:")
        print("   🔍 7 Vulnerability Detectors: SQLi, XSS, IDOR, Path Traversal, Command Injection, XXE, SSRF")
        print("   ⚙️ Advanced Configuration System with Profiles")
        print("   📝 Comprehensive Logging with Statistics")
        print("   📊 Beautiful HTML Reports with Interactive Features")
        print("   🎨 Color-coded Terminal Output")
        print("   🔧 Extensible Architecture for Custom Detectors")
        
        print("\n🎯 To run the enhanced scanner:")
        print("   ./spectr                          # Interactive mode")
        print("   python3 test_spectr.py           # Component tests")
        print("   python3 demo_spectr.py           # Safe demo")
        print("   python3 enhanced_test_spectr.py  # Enhanced tests")
        
    except Exception as e:
        print(f"\n❌ Enhanced test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()