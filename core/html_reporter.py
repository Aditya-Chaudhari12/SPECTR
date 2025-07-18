"""
HTML report generator for SPECTR vulnerability scanner
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

class HTMLReporter:
    """HTML report generator for SPECTR"""
    
    def __init__(self):
        self.template = self._get_html_template()
        self.css_styles = self._get_css_styles()
        self.js_scripts = self._get_js_scripts()
    
    def generate_report(self, scan_config: Dict[str, Any], results: List[Dict[str, Any]], 
                       stats: Dict[str, Any] = None) -> str:
        """Generate HTML report"""
        
        # Generate report content
        report_content = {
            'title': 'SPECTR Vulnerability Scan Report',
            'scan_info': self._generate_scan_info(scan_config, stats),
            'summary': self._generate_summary(results),
            'vulnerabilities': self._generate_vulnerabilities_section(results),
            'payload_breakdown': self._generate_payload_breakdown(results),
            'recommendations': self._generate_recommendations(results),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'css_styles': self.css_styles,
            'js_scripts': self.js_scripts,
        }
        
        # Replace template variables
        html_content = self.template.format(**report_content)
        
        return html_content
    
    def save_report(self, html_content: str, output_file: str) -> str:
        """Save HTML report to file"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return output_file
            
        except Exception as e:
            raise Exception(f"Failed to save HTML report: {e}")
    
    def _generate_scan_info(self, scan_config: Dict[str, Any], stats: Dict[str, Any] = None) -> str:
        """Generate scan information section"""
        stats = stats or {}
        
        return f"""
        <div class="scan-info">
            <h2>Scan Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <label>Target URL:</label>
                    <span>{scan_config.get('url', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <label>HTTP Method:</label>
                    <span>{scan_config.get('method', 'GET')}</span>
                </div>
                <div class="info-item">
                    <label>Parameters:</label>
                    <span>{len(scan_config.get('params', {}))}</span>
                </div>
                <div class="info-item">
                    <label>Headers:</label>
                    <span>{len(scan_config.get('headers', {}))}</span>
                </div>
                <div class="info-item">
                    <label>Scan Duration:</label>
                    <span>{stats.get('scan_duration', 'N/A')} seconds</span>
                </div>
                <div class="info-item">
                    <label>Requests Made:</label>
                    <span>{stats.get('requests_made', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <label>Payloads Tested:</label>
                    <span>{stats.get('payloads_tested', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <label>Detectors Used:</label>
                    <span>{', '.join(stats.get('detectors_used', []))}</span>
                </div>
            </div>
        </div>
        """
    
    def _generate_summary(self, results: List[Dict[str, Any]]) -> str:
        """Generate summary section"""
        total_vulns = len(results)
        
        if total_vulns == 0:
            return """
            <div class="summary no-vulns">
                <h2>Summary</h2>
                <div class="summary-card success">
                    <h3>✅ No Vulnerabilities Found</h3>
                    <p>The scan completed successfully without finding any vulnerabilities.</p>
                </div>
            </div>
            """
        
        # Group vulnerabilities by type
        vuln_types = {}
        severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
        
        for result in results:
            vuln_type = result.get('type', 'unknown').upper()
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            # Assign severity
            severity = self._get_severity(vuln_type)
            severity_counts[severity] += 1
        
        # Generate summary cards
        summary_cards = []
        for vuln_type, count in vuln_types.items():
            severity = self._get_severity(vuln_type)
            severity_class = severity.lower()
            
            summary_cards.append(f"""
                <div class="summary-card {severity_class}">
                    <h3>{vuln_type}</h3>
                    <div class="count">{count}</div>
                    <div class="severity">Severity: {severity}</div>
                </div>
            """)
        
        return f"""
        <div class="summary">
            <h2>Summary</h2>
            <div class="summary-overview">
                <div class="total-vulns">
                    <h3>Total Vulnerabilities Found</h3>
                    <div class="count">{total_vulns}</div>
                </div>
                <div class="severity-breakdown">
                    <h3>Severity Breakdown</h3>
                    <div class="severity-counts">
                        <span class="high">High: {severity_counts['High']}</span>
                        <span class="medium">Medium: {severity_counts['Medium']}</span>
                        <span class="low">Low: {severity_counts['Low']}</span>
                    </div>
                </div>
            </div>
            <div class="summary-cards">
                {''.join(summary_cards)}
            </div>
        </div>
        """
    
    def _generate_vulnerabilities_section(self, results: List[Dict[str, Any]]) -> str:
        """Generate vulnerabilities section"""
        if not results:
            return ""
        
        # Group vulnerabilities by type
        vuln_groups = {}
        for result in results:
            vuln_type = result.get('type', 'unknown').upper()
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append(result)
        
        # Generate vulnerability sections
        vuln_sections = []
        for vuln_type, vulns in vuln_groups.items():
            severity = self._get_severity(vuln_type)
            severity_class = severity.lower()
            
            vuln_items = []
            for i, vuln in enumerate(vulns, 1):
                vuln_items.append(f"""
                    <div class="vulnerability-item">
                        <div class="vuln-header">
                            <h4>#{i} - Parameter: {vuln.get('parameter', 'N/A')}</h4>
                            <span class="severity-badge {severity_class}">{severity}</span>
                        </div>
                        <div class="vuln-details">
                            <div class="detail-row">
                                <label>Method:</label>
                                <span>{vuln.get('method', 'N/A')}</span>
                            </div>
                            <div class="detail-row">
                                <label>Payload:</label>
                                <code>{self._escape_html(vuln.get('payload', 'N/A'))}</code>
                            </div>
                            <div class="detail-row">
                                <label>Evidence:</label>
                                <span>{self._escape_html(vuln.get('evidence', 'N/A'))}</span>
                            </div>
                            <div class="detail-row">
                                <label>Response Code:</label>
                                <span>{vuln.get('response_code', 'N/A')}</span>
                            </div>
                            <div class="detail-row">
                                <label>Response Time:</label>
                                <span>{vuln.get('response_time', 'N/A')} seconds</span>
                            </div>
                        </div>
                    </div>
                """)
            
            vuln_sections.append(f"""
                <div class="vulnerability-section">
                    <h3 class="vuln-type-header {severity_class}">
                        {vuln_type} ({len(vulns)} found)
                    </h3>
                    <div class="vulnerability-list">
                        {''.join(vuln_items)}
                    </div>
                </div>
            """)
        
        return f"""
        <div class="vulnerabilities">
            <h2>Detailed Vulnerabilities</h2>
            {''.join(vuln_sections)}
        </div>
        """
    
    def _generate_payload_breakdown(self, results: List[Dict[str, Any]]) -> str:
        """Generate payload breakdown section"""
        if not results:
            return ""
        
        # Analyze payloads
        payload_stats = {}
        method_stats = {}
        
        for result in results:
            payload = result.get('payload', 'N/A')
            method = result.get('method', 'N/A')
            
            # Count payloads (truncate long payloads)
            payload_key = payload[:50] + '...' if len(payload) > 50 else payload
            payload_stats[payload_key] = payload_stats.get(payload_key, 0) + 1
            
            # Count methods
            method_stats[method] = method_stats.get(method, 0) + 1
        
        # Generate payload table
        payload_rows = []
        for payload, count in sorted(payload_stats.items(), key=lambda x: x[1], reverse=True):
            payload_rows.append(f"""
                <tr>
                    <td><code>{self._escape_html(payload)}</code></td>
                    <td>{count}</td>
                </tr>
            """)
        
        # Generate method table
        method_rows = []
        for method, count in sorted(method_stats.items(), key=lambda x: x[1], reverse=True):
            method_rows.append(f"""
                <tr>
                    <td>{method}</td>
                    <td>{count}</td>
                </tr>
            """)
        
        return f"""
        <div class="payload-breakdown">
            <h2>Payload Analysis</h2>
            <div class="breakdown-grid">
                <div class="breakdown-section">
                    <h3>Most Effective Payloads</h3>
                    <table class="payload-table">
                        <thead>
                            <tr>
                                <th>Payload</th>
                                <th>Success Count</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(payload_rows)}
                        </tbody>
                    </table>
                </div>
                <div class="breakdown-section">
                    <h3>Detection Methods</h3>
                    <table class="method-table">
                        <thead>
                            <tr>
                                <th>Method</th>
                                <th>Success Count</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(method_rows)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """
    
    def _generate_recommendations(self, results: List[Dict[str, Any]]) -> str:
        """Generate recommendations section"""
        if not results:
            return """
            <div class="recommendations">
                <h2>Recommendations</h2>
                <div class="recommendation-card success">
                    <h3>✅ Good Security Posture</h3>
                    <p>No vulnerabilities were found during this scan. Continue to:</p>
                    <ul>
                        <li>Regularly update your applications and dependencies</li>
                        <li>Implement proper input validation</li>
                        <li>Use parameterized queries for database operations</li>
                        <li>Implement proper access controls</li>
                        <li>Conduct regular security assessments</li>
                    </ul>
                </div>
            </div>
            """
        
        # Generate recommendations based on vulnerabilities found
        vuln_types = set(result.get('type', 'unknown') for result in results)
        recommendations = []
        
        if 'sqli' in vuln_types:
            recommendations.append("""
                <div class="recommendation-card high">
                    <h3>🔴 SQL Injection Vulnerabilities</h3>
                    <p>SQL injection vulnerabilities were found. Take immediate action:</p>
                    <ul>
                        <li>Use parameterized queries or prepared statements</li>
                        <li>Implement proper input validation and sanitization</li>
                        <li>Use stored procedures where appropriate</li>
                        <li>Apply principle of least privilege to database accounts</li>
                        <li>Regular security code reviews</li>
                    </ul>
                </div>
            """)
        
        if 'xss' in vuln_types:
            recommendations.append("""
                <div class="recommendation-card medium">
                    <h3>🟡 Cross-Site Scripting (XSS) Vulnerabilities</h3>
                    <p>XSS vulnerabilities were found. Implement these fixes:</p>
                    <ul>
                        <li>Implement proper output encoding/escaping</li>
                        <li>Use Content Security Policy (CSP) headers</li>
                        <li>Validate and sanitize all user input</li>
                        <li>Use HTTP-only cookies for session management</li>
                        <li>Implement proper input validation</li>
                    </ul>
                </div>
            """)
        
        if 'command_injection' in vuln_types:
            recommendations.append("""
                <div class="recommendation-card high">
                    <h3>🔴 Command Injection Vulnerabilities</h3>
                    <p>Command injection vulnerabilities were found. Take immediate action:</p>
                    <ul>
                        <li>Avoid using user input in system commands</li>
                        <li>Use safe APIs instead of shell commands</li>
                        <li>Implement strict input validation</li>
                        <li>Use sandboxing or containers to limit damage</li>
                        <li>Apply principle of least privilege</li>
                    </ul>
                </div>
            """)
        
        if 'xxe' in vuln_types:
            recommendations.append("""
                <div class="recommendation-card high">
                    <h3>🔴 XML External Entity (XXE) Vulnerabilities</h3>
                    <p>XXE vulnerabilities were found. Implement these fixes:</p>
                    <ul>
                        <li>Disable external entity processing in XML parsers</li>
                        <li>Use less complex data formats like JSON when possible</li>
                        <li>Implement proper input validation for XML data</li>
                        <li>Use whitelist-based validation for XML schemas</li>
                        <li>Keep XML processors updated</li>
                    </ul>
                </div>
            """)
        
        if 'ssrf' in vuln_types:
            recommendations.append("""
                <div class="recommendation-card high">
                    <h3>🔴 Server-Side Request Forgery (SSRF) Vulnerabilities</h3>
                    <p>SSRF vulnerabilities were found. Implement these fixes:</p>
                    <ul>
                        <li>Validate and sanitize all URLs before making requests</li>
                        <li>Use whitelist-based URL validation</li>
                        <li>Implement network segmentation</li>
                        <li>Disable unused URL schemes and protocols</li>
                        <li>Use DNS filtering to prevent access to internal resources</li>
                    </ul>
                </div>
            """)
        
        return f"""
        <div class="recommendations">
            <h2>Security Recommendations</h2>
            {''.join(recommendations)}
        </div>
        """
    
    def _get_severity(self, vuln_type: str) -> str:
        """Get severity level for vulnerability type"""
        severity_map = {
            'SQLI': 'High',
            'COMMAND_INJECTION': 'High',
            'XXE': 'High',
            'SSRF': 'High',
            'XSS': 'Medium',
            'IDOR': 'Medium',
            'TRAVERSAL': 'Medium',
        }
        return severity_map.get(vuln_type, 'Medium')
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        import html
        return html.escape(str(text))
    
    def _get_html_template(self) -> str:
        """Get HTML template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        {css_styles}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 {title}</h1>
            <p class="timestamp">Generated on {timestamp}</p>
        </header>
        
        <main>
            {scan_info}
            {summary}
            {vulnerabilities}
            {payload_breakdown}
            {recommendations}
        </main>
        
        <footer>
            <p>Report generated by SPECTR v1.0 - Web Vulnerability Scanner</p>
            <p>⚠️ This report is for authorized security testing purposes only</p>
        </footer>
    </div>
    
    <script>
        {js_scripts}
    </script>
</body>
</html>
        """
    
    def _get_css_styles(self) -> str:
        """Get CSS styles"""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .timestamp {
            opacity: 0.8;
            font-size: 1.1em;
        }
        
        main {
            padding: 30px;
        }
        
        h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        
        h3 {
            color: #34495e;
            margin-bottom: 15px;
        }
        
        .scan-info {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .info-item {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .info-item label {
            font-weight: bold;
            color: #2c3e50;
        }
        
        .summary {
            margin-bottom: 30px;
        }
        
        .summary-overview {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .total-vulns, .severity-breakdown {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .total-vulns .count {
            font-size: 3em;
            font-weight: bold;
            color: #e74c3c;
            margin: 10px 0;
        }
        
        .severity-counts {
            display: flex;
            justify-content: space-around;
            margin-top: 15px;
        }
        
        .severity-counts span {
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            color: white;
        }
        
        .severity-counts .high {
            background: #e74c3c;
        }
        
        .severity-counts .medium {
            background: #f39c12;
        }
        
        .severity-counts .low {
            background: #27ae60;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        
        .summary-card {
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
            font-weight: bold;
        }
        
        .summary-card.high {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
        }
        
        .summary-card.medium {
            background: linear-gradient(135deg, #f39c12, #d68910);
        }
        
        .summary-card.low {
            background: linear-gradient(135deg, #27ae60, #229954);
        }
        
        .summary-card.success {
            background: linear-gradient(135deg, #27ae60, #229954);
        }
        
        .summary-card .count {
            font-size: 2em;
            margin: 10px 0;
        }
        
        .vulnerability-section {
            margin-bottom: 30px;
        }
        
        .vuln-type-header {
            padding: 15px;
            border-radius: 8px;
            color: white;
            font-weight: bold;
            margin-bottom: 20px;
        }
        
        .vuln-type-header.high {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
        }
        
        .vuln-type-header.medium {
            background: linear-gradient(135deg, #f39c12, #d68910);
        }
        
        .vuln-type-header.low {
            background: linear-gradient(135deg, #27ae60, #229954);
        }
        
        .vulnerability-item {
            background: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 0 8px 8px 0;
        }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        
        .severity-badge.high {
            background: #e74c3c;
        }
        
        .severity-badge.medium {
            background: #f39c12;
        }
        
        .severity-badge.low {
            background: #27ae60;
        }
        
        .detail-row {
            display: flex;
            margin-bottom: 10px;
        }
        
        .detail-row label {
            min-width: 120px;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .detail-row code {
            background: #e8f4f8;
            padding: 5px 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            word-break: break-all;
        }
        
        .payload-breakdown {
            margin-bottom: 30px;
        }
        
        .breakdown-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }
        
        .breakdown-section {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
        }
        
        .payload-table, .method-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        .payload-table th, .method-table th,
        .payload-table td, .method-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        .payload-table th, .method-table th {
            background: #3498db;
            color: white;
            font-weight: bold;
        }
        
        .payload-table tr:hover, .method-table tr:hover {
            background: #f0f8ff;
        }
        
        .recommendations {
            margin-bottom: 30px;
        }
        
        .recommendation-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #3498db;
        }
        
        .recommendation-card.high {
            border-left-color: #e74c3c;
        }
        
        .recommendation-card.medium {
            border-left-color: #f39c12;
        }
        
        .recommendation-card.success {
            border-left-color: #27ae60;
        }
        
        .recommendation-card h3 {
            margin-bottom: 15px;
            color: #2c3e50;
        }
        
        .recommendation-card ul {
            margin-left: 20px;
            margin-top: 10px;
        }
        
        .recommendation-card li {
            margin-bottom: 8px;
            color: #34495e;
        }
        
        .no-vulns {
            text-align: center;
            padding: 40px;
        }
        
        .no-vulns h3 {
            color: #27ae60;
            font-size: 2em;
            margin-bottom: 20px;
        }
        
        footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
        }
        
        footer p {
            margin: 5px 0;
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 10px;
            }
            
            main {
                padding: 20px;
            }
            
            .summary-overview,
            .breakdown-grid {
                grid-template-columns: 1fr;
            }
            
            .info-grid {
                grid-template-columns: 1fr;
            }
        }
        """
    
    def _get_js_scripts(self) -> str:
        """Get JavaScript scripts"""
        return """
        // Add interactivity
        document.addEventListener('DOMContentLoaded', function() {
            // Add click handlers for collapsible sections
            const vulnHeaders = document.querySelectorAll('.vuln-type-header');
            vulnHeaders.forEach(header => {
                header.style.cursor = 'pointer';
                header.addEventListener('click', function() {
                    const section = this.nextElementSibling;
                    if (section.style.display === 'none') {
                        section.style.display = 'block';
                        this.innerHTML = this.innerHTML.replace('▶', '▼');
                    } else {
                        section.style.display = 'none';
                        this.innerHTML = this.innerHTML.replace('▼', '▶');
                    }
                });
            });
            
            // Add search functionality
            const searchInput = document.createElement('input');
            searchInput.type = 'text';
            searchInput.placeholder = 'Search vulnerabilities...';
            searchInput.style.cssText = `
                width: 100%;
                padding: 10px;
                margin-bottom: 20px;
                border: 2px solid #3498db;
                border-radius: 5px;
                font-size: 16px;
            `;
            
            const vulnSection = document.querySelector('.vulnerabilities');
            if (vulnSection) {
                vulnSection.insertBefore(searchInput, vulnSection.firstChild.nextSibling);
                
                searchInput.addEventListener('input', function() {
                    const searchTerm = this.value.toLowerCase();
                    const vulnItems = document.querySelectorAll('.vulnerability-item');
                    
                    vulnItems.forEach(item => {
                        const text = item.textContent.toLowerCase();
                        if (text.includes(searchTerm)) {
                            item.style.display = 'block';
                        } else {
                            item.style.display = 'none';
                        }
                    });
                });
            }
            
            // Add print functionality
            const printBtn = document.createElement('button');
            printBtn.textContent = '🖨️ Print Report';
            printBtn.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                background: #3498db;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 14px;
                z-index: 1000;
            `;
            
            printBtn.addEventListener('click', function() {
                window.print();
            });
            
            document.body.appendChild(printBtn);
        });
        """