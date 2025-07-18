# SPECTR v2.0 - Enhanced Web Vulnerability Scanner

```
  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ 
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝
```

**SPECTR v2.0** - Scanner for Payloads, Endpoints, Configs, Traversals, and Requests

An advanced Python CLI-based web vulnerability scanner with comprehensive detection capabilities, beautiful HTML reporting, and enterprise-grade features.

## 🎯 Enhanced Features

### 🔍 **7 Vulnerability Detectors**
- **SQL Injection (SQLi)** - Error-based, time-based, boolean-based, and union-based detection
- **Cross-Site Scripting (XSS)** - Reflected, stored, and DOM-based XSS detection
- **Insecure Direct Object Reference (IDOR)** - Numeric, string, and file-based access control bypass
- **Path Traversal** - Directory traversal with encoding bypass techniques
- **Command Injection** - OS command injection with time-based and pattern-based detection
- **XML External Entity (XXE)** - File disclosure and out-of-band XXE detection
- **Server-Side Request Forgery (SSRF)** - Internal network and cloud metadata access

### ⚙️ **Advanced Configuration System**
- JSON and YAML configuration file support
- Pre-defined scan profiles (Quick, Comprehensive, Stealth)
- Per-detector configuration options
- Authentication and proxy support
- Custom payload files

### 📊 **Professional Reporting**
- **Interactive HTML Reports** with search and filtering
- **Color-coded Terminal Output** with severity levels
- **JSON Export** for integration with other tools
- **CSV Export** for spreadsheet analysis
- **Detailed Statistics** and scan metrics

### 📝 **Enterprise Logging**
- **Rotating Log Files** with size limits
- **Structured Logging** with different levels
- **Scan Statistics** and performance metrics
- **Request/Response Logging** for debugging
- **Vulnerability Tracking** with evidence

### 🎨 **User Experience**
- **Beautiful ASCII Banner** with color support
- **Interactive CLI** with smart prompts
- **Progress Indicators** for long scans
- **Verbose Mode** for detailed output
- **Error Handling** with helpful messages

## 🚀 Quick Start

### Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x spectr

# Run basic scan
./spectr
```

### Usage Examples

#### Interactive Mode
```bash
./spectr
```

#### Configuration File
```bash
# Create sample config
python3 -c "from core.config import SpectrConfig; SpectrConfig().create_sample_config('config.json')"

# Use config file
./spectr --config config.json
```

#### Scan Profiles
```bash
# Quick scan (basic payloads)
./spectr --profile quick

# Comprehensive scan (all detectors)
./spectr --profile comprehensive

# Stealth scan (with delays)
./spectr --profile stealth
```

## 🛡️ Vulnerability Detection Capabilities

### 📊 **Payload Statistics**
- **Total Payloads**: 308+ across all vulnerability types
- **SQL Injection**: 33 payloads (error-based, time-based, boolean-based)
- **XSS**: 32 payloads (reflected, stored, DOM-based, encoded)
- **IDOR**: 51 payloads (numeric, string, UUID, file-based)
- **Path Traversal**: 49 payloads (basic, encoded, filter bypass)
- **Command Injection**: 69 payloads (Unix/Linux, Windows, time-based)
- **XXE**: 13 payloads (file disclosure, out-of-band, DoS)
- **SSRF**: 61 payloads (internal network, cloud metadata, port scanning)

### 🔍 **Detection Methods**

#### SQL Injection
- **Error-based**: Detects SQL errors in responses
- **Time-based**: Identifies time delays from SQL sleep functions
- **Boolean-based**: Compares responses from true/false conditions
- **Union-based**: Tests for UNION SELECT vulnerabilities

#### Cross-Site Scripting
- **Reflected**: Checks if payloads are reflected in responses
- **Stored**: Attempts to detect persistent XSS
- **DOM-based**: Tests URL fragment-based XSS
- **Filter bypass**: Tests various encoding techniques

#### Command Injection
- **Pattern-based**: Looks for command output in responses
- **Time-based**: Detects delays from sleep commands
- **Blind**: Tests for out-of-band command execution
- **OS-specific**: Supports both Unix/Linux and Windows

#### XXE (XML External Entity)
- **File disclosure**: Attempts to read local files
- **Out-of-band**: Tests for external entity processing
- **DoS attacks**: Billion laughs and quadratic blowup
- **Protocol testing**: HTTP, FTP, file, and other protocols

#### SSRF (Server-Side Request Forgery)
- **Internal network**: Tests access to private IP ranges
- **Cloud metadata**: AWS, Google Cloud, Azure metadata endpoints
- **Port scanning**: Identifies open ports on internal hosts
- **Protocol bypass**: Tests various URL schemes

### Test Results
```
✅ All 7 detectors loaded and functional
✅ 308+ payloads across all vulnerability types
✅ Configuration system with validation
✅ HTML report generation with interactive features
✅ Advanced logging with statistics
✅ Professional CLI interface
```

## 🎨 Output Examples

### Terminal Output
```
🚀 SPECTR v2.0 - Web Vulnerability Scanner

🔗 Enter target URL: https://example.com/search?q=test
📡 HTTP method (GET/POST): GET
🔍 Verbose mode? (y/n): y

⏳ Starting scan...

[1/7] 🔍 Running SQLI detector...
   🔴 SQL injection found: MySQL error detected
[2/7] 🔍 Running XSS detector...
   🔴 XSS vulnerability found: Payload reflected
[3/7] 🔍 Running COMMAND_INJECTION detector...
   🔴 Command injection found: Command output detected

======================================================================
🎯 SCAN RESULTS
======================================================================
⚠️  Found 3 vulnerabilities:

🔴 SQLI (1 found)
   └── Parameter: q
       Payload: ' OR 1=1--
       Evidence: MySQL error detected

🟡 XSS (1 found)
   └── Parameter: q
       Payload: <script>alert('XSS')</script>
       Evidence: Payload reflected in response

🔴 COMMAND_INJECTION (1 found)
   └── Parameter: q
       Payload: ; id
       Evidence: Command output detected

📄 HTML report saved to: spectr_scan_2025-07-18_10-15-30.html
```

## 📜 License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## 📞 Support

For questions, issues, or contributions:
- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Comprehensive guides and examples
- **Community**: Join discussions and share experiences

---

**SPECTR v2.0** - Professional Web Vulnerability Scanner
*Remember: Only test applications you own or have explicit permission to test.*
