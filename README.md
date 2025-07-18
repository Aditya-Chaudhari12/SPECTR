# SPECTR - Web Vulnerability Scanner

```
  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ 
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝
```

**SPECTR** - Scanner for Payloads, Endpoints, Configs, Traversals, and Requests

A Python CLI-based web vulnerability scanner that detects common web application security vulnerabilities through automated payload injection and response analysis.

## 🎯 Features

- **Interactive CLI Interface**: Simple command-line interface with ASCII banner
- **Multiple Vulnerability Detection**: 
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Insecure Direct Object Reference (IDOR)
  - Path Traversal
- **Comprehensive Payload Database**: Custom payloads for each vulnerability type
- **Response Analysis**: Advanced response analysis and pattern matching
- **Detailed Reporting**: Color-coded terminal output and JSON report generation
- **Configurable Options**: Support for custom HTTP methods, headers, and parameters

## 🛡️ Supported Vulnerabilities

### SQL Injection (SQLi)
- Error-based SQL injection detection
- Time-based blind SQL injection
- Boolean-based blind SQL injection
- Union-based SQL injection indicators

### Cross-Site Scripting (XSS)
- Reflected XSS detection
- DOM-based XSS indicators
- Potential stored XSS detection
- Multiple payload encoding techniques

### Insecure Direct Object Reference (IDOR)
- Numeric parameter manipulation
- String/UUID parameter fuzzing
- Path-based object reference testing
- File-based access control bypass

### Path Traversal
- Basic directory traversal
- Encoded path traversal (URL, Unicode, Mixed)
- File access attempts
- Filter bypass techniques

## 🚀 Installation

1. **Clone or download the SPECTR scanner**
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Make the scanner executable:**
   ```bash
   chmod +x spectr
   ```

## 🔧 Usage

### Basic Usage
```bash
./spectr
```

### Interactive Prompts
When you run SPECTR, it will prompt you for:

1. **Target URL**: The web application endpoint to test
2. **HTTP Method**: GET or POST (default: GET)
3. **Parameters**: URL parameters in key=value&key=value format
4. **Headers**: Custom HTTP headers in key:value,key:value format
5. **Verbose Mode**: Enable detailed output (y/n)

### Example Session
```bash
$ ./spectr

  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ 
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝
   
   SPECTR - Scanner for Payloads, Endpoints, Configs,
             Traversals, and Requests
   
   🔍 Web Vulnerability Scanner v1.0
   ⚡ Python CLI-based Security Testing Tool

🚀 Welcome to SPECTR - Web Vulnerability Scanner

🔗 Enter target URL: https://example.com/profile?id=1
📡 HTTP method (GET/POST): GET
📤 Parameters (e.g., id=1&user=admin): id=1
🧾 Headers (key:value,key:value) [optional]: Authorization:Bearer xyz
🔍 Verbose mode? (y/n): y

⏳ Starting scan on https://example.com/profile...

[1/4] 🔍 Running SQLI detector...
[2/4] 🔍 Running XSS detector...
[3/4] 🔍 Running IDOR detector...
[4/4] 🔍 Running TRAVERSAL detector...

======================================================================
🎯 SCAN RESULTS
======================================================================
⚠️  Found 2 potential vulnerabilities:

🔴 SQLI (1 found)
   └── Parameter: id
       Payload: ' OR 1=1--
       Evidence: SQL error pattern detected: mysql_fetch_array()

🔴 XSS (1 found)
   └── Parameter: id
       Payload: <script>alert('XSS')</script>
       Evidence: Payload reflected in response

💾 Save detailed report to JSON? (y/n) [y]: y
📄 Report saved to: spectr_scan_report_2025-01-16_14-30-25.json
```

## 📁 Project Structure

```
spectr/
├── spectr                 # Main executable entry point
├── core/                  # Core scanning engine
│   ├── scanner.py         # Main scanner orchestrator
│   ├── payloads.py        # Payload database
│   ├── analyzer.py        # Response analysis logic
│   ├── reporter.py        # Result reporting and formatting
│   └── banner.py          # ASCII banner display
├── detectors/             # Vulnerability detection modules
│   ├── sqli.py            # SQL injection detector
│   ├── xss.py             # XSS detector
│   ├── idor.py            # IDOR detector
│   └── traversal.py       # Path traversal detector
├── utils/                 # Utility modules
│   └── http_client.py     # HTTP request handling
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🔍 Detection Methods

### SQL Injection
- **Error-based**: Detects SQL errors in responses
- **Time-based**: Identifies time delays from SQL sleep functions
- **Boolean-based**: Compares responses from true/false conditions
- **Union-based**: Tests for UNION SELECT vulnerabilities

### Cross-Site Scripting
- **Reflected**: Checks if payloads are reflected in responses
- **DOM-based**: Tests URL fragment-based XSS
- **Stored**: Attempts to detect persistent XSS
- **Filter bypass**: Tests various encoding techniques

### IDOR
- **Numeric**: Increments/decrements numeric parameters
- **String**: Tests common usernames and identifiers
- **Path-based**: Tests directory traversal in parameters
- **File-based**: Tests file access through parameters

### Path Traversal
- **Basic**: Tests standard ../ patterns
- **Encoded**: Tests URL, Unicode, and mixed encoding
- **File access**: Attempts to access common system files
- **Filter bypass**: Tests various bypass techniques

## 🎨 Output Features

### Color-coded Results
- **🔴 Red**: Critical vulnerabilities (SQLi, IDOR)
- **🟡 Yellow**: Medium vulnerabilities (XSS)
- **🔵 Cyan**: Low vulnerabilities (Path Traversal)
- **✅ Green**: No vulnerabilities found

### JSON Report Format
```json
{
  "scan_info": {
    "timestamp": "2025-01-16T14:30:25",
    "scanner": "SPECTR",
    "version": "1.0",
    "target": "https://example.com/profile",
    "method": "GET",
    "parameters": {"id": "1"},
    "headers": {},
    "total_vulnerabilities": 2
  },
  "vulnerabilities": [
    {
      "type": "sqli",
      "parameter": "id",
      "payload": "' OR 1=1--",
      "method": "error_based",
      "evidence": "SQL error pattern detected",
      "response_code": 500,
      "response_time": 0.25
    }
  ],
  "summary": {
    "total": 2,
    "by_type": {"sqli": 1, "xss": 1},
    "severity_distribution": {"High": 1, "Medium": 1}
  }
}
```

## ⚠️ Important Notes

### Legal and Ethical Use
- **Only test applications you own or have explicit permission to test**
- **SPECTR is for educational and authorized security testing purposes only**
- **Unauthorized testing of web applications is illegal and unethical**
- **Users are responsible for complying with applicable laws and regulations**

### Technical Limitations
- **False positives**: Some results may be false positives and require manual verification
- **Limited scope**: SPECTR tests common vulnerabilities but may not catch all security issues
- **Network dependent**: Results depend on network connectivity and target responsiveness
- **No authentication**: Currently doesn't handle authenticated sessions

### Security Considerations
- **SSL verification is disabled** for security testing purposes
- **May generate significant traffic** to target applications
- **Payloads are logged** in reports - ensure secure storage
- **Some tests may trigger security controls** or monitoring systems

## 🔧 Configuration

### Environment Variables
- `SPECTR_TIMEOUT`: Request timeout in seconds (default: 10)
- `SPECTR_RETRIES`: Maximum retries for failed requests (default: 3)
- `SPECTR_DELAY`: Delay between requests in seconds (default: 0.1)

### Custom Payloads
You can extend the payload database by modifying `core/payloads.py`:

```python
def _get_custom_sqli_payloads(self):
    return [
        "' OR 1=1--",
        "' UNION SELECT version()--",
        # Add your custom payloads here
    ]
```

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   chmod +x spectr
   ```

2. **Module Not Found**
   ```bash
   pip install -r requirements.txt
   ```

3. **Connection Errors**
   - Check target URL accessibility
   - Verify network connectivity
   - Consider firewall restrictions

4. **SSL Certificate Errors**
   - SSL verification is disabled by default for testing
   - Use HTTPS URLs when possible

### Debug Mode
Enable verbose mode for detailed output:
```bash
./spectr
# Select 'y' for verbose mode when prompted
```

## 📈 Future Enhancements

- **Authentication support** for testing authenticated endpoints
- **Session management** for multi-step vulnerability testing
- **Custom payload importing** from external files
- **Parallel scanning** for improved performance
- **Web interface** for easier usage
- **Plugin system** for custom vulnerability tests
- **Database storage** for scan history
- **CI/CD integration** capabilities

## 🤝 Contributing

SPECTR is built for educational and security testing purposes. Feel free to:
- Report bugs and issues
- Suggest new features
- Contribute vulnerability detection modules
- Improve documentation

## 📜 License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## 📞 Support

For questions, issues, or contributions, please refer to the project documentation or create an issue in the project repository.

---

**Remember: Only test applications you own or have explicit permission to test. Unauthorized testing is illegal and unethical.**