from flask import Blueprint, request, jsonify, send_file, make_response
import subprocess
import json
import os
import datetime
import tempfile
from models.user import User
from __init__ import db
import random
import io
import html
import re
import uuid
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import socket
import time
import shutil

# PDF için gerekli kütüphaneler
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("ReportLab kütüphanesi bulunamadı. PDF raporlama devre dışı.")

dast_bp = Blueprint('dast_bp', __name__)

# Temporary storage for scan history (in-memory database)
# In a real implementation, you would store this in a database
scan_history = []

# Store full scan results for report download
# In a real implementation, you would store this in a database
scan_results_store = {}

# AI önerileri için örnek çözümler - zafiyet tipine göre
ai_solution_suggestions = {
    "SQL Injection": [
        "Use parameterized queries (prepared statements) for all database queries.",
        "Consider using an ORM which provides secure abstractions instead of writing manual SQL.",
        "Apply input validation and use whitelist approach for filtering user inputs.",
        "Apply the principle of least privilege to database users.",
        "Use a Web Application Firewall (WAF) to block attack signatures."
    ],
    "Cross-Site Scripting (XSS)": [
        "Escape all user inputs, especially when displaying HTML content.",
        "Use Content-Security-Policy (CSP) headers to specify trusted sources.",
        "Modern JavaScript frameworks (React, Vue, Angular) provide protection against XSS.",
        "Protect cookies using HttpOnly and Secure flags.",
        "Implement input validation and output encoding principles."
    ],
    "Cross-Site Request Forgery": [
        "Use unique CSRF tokens for each form and validate them on every request.",
        "Utilize Same-Site cookie attribute (in Strict or Lax mode).",
        "Require re-authentication for important operations.",
        "Consider using custom headers for JSON APIs.",
        "Integrate anti-CSRF libraries."
    ],
    "Content Security Policy Not Set": [
        "Add CSP headers and specify trusted sources.",
        "Restrict inline script and style usage.",
        "Use nonce or hash-based CSP methods.",
        "Start with CSP Report-Only mode to fix issues.",
        "Set up a reporting endpoint to monitor CSP violations."
    ],
    "Missing X-Frame-Options Header": [
        "Set X-Frame-Options header to DENY or SAMEORIGIN.",
        "Use CSP frame-ancestors directive for modern browsers.",
        "Add frame-busting JavaScript to prevent clickjacking attacks.",
        "Set X-Frame-Options to DENY on critical pages.",
        "Apply protection on all user-interactive pages."
    ],
    "Cookie Without Secure Flag": [
        "Enable Secure flag for all cookies.",
        "Use HttpOnly flag for sensitive cookies.",
        "Set Same-Site attribute to Strict or Lax.",
        "Encrypt or sign cookie values.",
        "Set cookie expiration times to the shortest necessary period."
    ]
}

# Varsayılan AI önerileri
default_ai_suggestions = [
    "Regularly review the OWASP Top 10 list for application security.",
    "Integrate security testing into your CI/CD pipeline.",
    "Regularly scan for and patch security vulnerabilities.",
    "Prioritize security in the software development process.",
    "Regularly update third-party libraries and dependencies."
]

def get_ai_solution_for_vulnerability(vulnerability_name):
    """Zafiyet için AI önerileri döndürür"""
    if vulnerability_name in ai_solution_suggestions:
        # Rastgele 3 öneri seç
        suggestions = random.sample(ai_solution_suggestions[vulnerability_name], 
                                   min(3, len(ai_solution_suggestions[vulnerability_name])))
    else:
        # Varsayılan öneriler
        suggestions = random.sample(default_ai_suggestions, min(3, len(default_ai_suggestions)))
    
    return suggestions

def create_pdf_report(scan_data):
    """Tarama sonuçlarından PDF raporu oluşturur."""
    if not PDF_AVAILABLE:
        return None
        
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []
    
    # Başlık stili
    title_style = styles["Heading1"]
    title_style.alignment = 1  # Ortalama
    
    # Alt başlık stili
    subtitle_style = styles["Heading2"]
    
    # Normal metin stili
    normal_style = styles["Normal"]
    
    # Özel metin stilleri
    redBold = ParagraphStyle(
        name='RedBold',
        parent=styles['Normal'],
        textColor=colors.red,
        fontName='Helvetica-Bold',
    )
    
    yellowBold = ParagraphStyle(
        name='YellowBold',
        parent=styles['Normal'],
        textColor=colors.orange,
        fontName='Helvetica-Bold',
    )
    
    blueBold = ParagraphStyle(
        name='BlueBold',
        parent=styles['Normal'],
        textColor=colors.blue,
        fontName='Helvetica-Bold',
    )
    
    # Rapor başlığı
    elements.append(Paragraph(f"DAST Scan Report", title_style))
    elements.append(Spacer(1, 0.25*inch))
    
    # Tarama bilgileri
    elements.append(Paragraph(f"Target URL: {html.escape(scan_data['target_url'])}", subtitle_style))
    elements.append(Paragraph(f"Scan Date: {scan_data['scan_date']}", normal_style))
    elements.append(Paragraph(f"Scan ID: {scan_data['scan_id']}", normal_style))
    elements.append(Spacer(1, 0.25*inch))
    
    # Özet bilgiler
    elements.append(Paragraph("Summary", subtitle_style))
    summary_data = [
        ["Risk Level", "Count"],
        ["High", str(scan_data['summary']['high_alerts'])],
        ["Medium", str(scan_data['summary']['medium_alerts'])],
        ["Low", str(scan_data['summary']['low_alerts'])],
        ["Info", str(scan_data['summary']['info_alerts'])]
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (0, 1), colors.red),
        ('BACKGROUND', (0, 2), (0, 2), colors.orange),
        ('BACKGROUND', (0, 3), (0, 3), colors.blue),
        ('BACKGROUND', (0, 4), (0, 4), colors.grey),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.5*inch))
    
    # Zafiyet detayları
    elements.append(Paragraph("Detailed Findings", subtitle_style))
    elements.append(Spacer(1, 0.25*inch))
    
    for idx, alert in enumerate(scan_data['alerts']):
        # Risk seviyesine göre stil seç
        if alert['risk'] == "High":
            risk_style = redBold
        elif alert['risk'] == "Medium":
            risk_style = yellowBold
        else:
            risk_style = blueBold
            
        # HTML özel karakterleri escape et
        alert_name = html.escape(alert['name'])
        alert_description = html.escape(alert['description'])
        alert_url = html.escape(alert['url'])
        alert_solution = html.escape(alert['solution'])
            
        # Zafiyet başlığı - özel karakterleri escape et
        elements.append(Paragraph(f"{idx+1}. {alert_name} ({alert['risk']} Risk)", risk_style))
        elements.append(Spacer(1, 0.1*inch))
        
        # Zafiyet açıklaması - özel karakterleri escape et
        elements.append(Paragraph(f"<b>Description:</b> {alert_description}", normal_style))
        elements.append(Paragraph(f"<b>URL:</b> {alert_url}", normal_style))
        elements.append(Paragraph(f"<b>Solution:</b> {alert_solution}", normal_style))
        
        # AI önerileri
        elements.append(Paragraph("<b>AI Recommendations:</b>", subtitle_style))
        ai_solutions = get_ai_solution_for_vulnerability(alert['name'])
        for solution in ai_solutions:
            # AI önerilerini de escape et
            escaped_solution = html.escape(solution)
            elements.append(Paragraph(f"• {escaped_solution}", normal_style))
            
        elements.append(Spacer(1, 0.25*inch))
    
    # Rapor altbilgisi
    elements.append(Spacer(1, 0.5*inch))
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(Paragraph(f"Report generated at: {current_time}", normal_style))
    elements.append(Paragraph("This report was automatically generated by AIronSafe DAST Scanner", normal_style))
    
    # PDF oluştur
    try:
        doc.build(elements)
        buffer.seek(0)
        return buffer
    except Exception as e:
        print(f"PDF oluşturma hatası: {str(e)}")
        return None

def create_html_report(scan_data):
    """Tarama sonuçlarından HTML raporu oluşturur."""
    
    # HTML başlık ve CSS stilleri
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DAST Scan Report - {html.escape(scan_data['target_url'])}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            padding-bottom: 10px;
            border-bottom: 2px solid #ecf0f1;
        }}
        h2 {{
            color: #2c3e50;
            padding-bottom: 5px;
            border-bottom: 1px solid #ecf0f1;
        }}
        .scan-info {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }}
        th {{
            background-color: #f8f9fa;
        }}
        .risk-high {{
            color: white;
            background-color: #e74c3c;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .risk-medium {{
            color: white;
            background-color: #f39c12;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .risk-low {{
            color: white;
            background-color: #3498db;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .alert-details {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .alert-high {{
            border-left: 5px solid #e74c3c;
        }}
        .alert-medium {{
            border-left: 5px solid #f39c12;
        }}
        .alert-low {{
            border-left: 5px solid #3498db;
        }}
        .recommendations {{
            margin-top: 10px;
            padding-left: 20px;
        }}
        .recommendation-item {{
            margin-bottom: 8px;
        }}
        footer {{
            margin-top: 30px;
            padding-top: 10px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            font-size: 0.8em;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <h1>DAST Scan Report</h1>
    
    <div class="scan-info">
        <h2>Scan Information</h2>
        <p><strong>Target URL:</strong> {html.escape(scan_data['target_url'])}</p>
        <p><strong>Scan Date:</strong> {scan_data['scan_date']}</p>
        <p><strong>Scan ID:</strong> {scan_data['scan_id']}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Risk Level</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><span class="risk-high">High</span></td>
                    <td>{scan_data['summary']['high_alerts']}</td>
                </tr>
                <tr>
                    <td><span class="risk-medium">Medium</span></td>
                    <td>{scan_data['summary']['medium_alerts']}</td>
                </tr>
                <tr>
                    <td><span class="risk-low">Low</span></td>
                    <td>{scan_data['summary']['low_alerts']}</td>
                </tr>
                <tr>
                    <td>Info</td>
                    <td>{scan_data['summary']['info_alerts']}</td>
                </tr>
            </tbody>
        </table>
    </div>
    
    <div class="findings">
        <h2>Detailed Findings</h2>
    """
    
    # Zafiyet detayları
    for idx, alert in enumerate(scan_data['alerts']):
        risk_level = alert['risk'].lower()
        alert_name = html.escape(alert['name'])
        alert_description = html.escape(alert['description'])
        alert_url = html.escape(alert['url'])
        alert_solution = html.escape(alert['solution'])
        
        html_content += f"""
        <div class="alert-details alert-{risk_level}">
            <h3>{idx+1}. {alert_name} <span class="risk-{risk_level}">{alert['risk']} Risk</span></h3>
            <p><strong>Description:</strong> {alert_description}</p>
            <p><strong>URL:</strong> {alert_url}</p>
            <p><strong>Solution:</strong> {alert_solution}</p>
            
            <div class="recommendations">
                <h4>AI Recommendations:</h4>
                <ul>
        """
        
        # AI önerileri
        ai_solutions = get_ai_solution_for_vulnerability(alert['name'])
        for solution in ai_solutions:
            escaped_solution = html.escape(solution)
            html_content += f"""
                    <li class="recommendation-item">{escaped_solution}</li>
            """
        
        html_content += """
                </ul>
            </div>
        </div>
        """
    
    # Rapor altbilgisi
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content += f"""
    <footer>
        <p>Report generated at: {current_time}</p>
        <p>This report was automatically generated by AIronSafe DAST Scanner</p>
    </footer>
</body>
</html>
    """
    
    return html_content

def parse_zap_output(output_text):
    """ZAP tarama çıktısını parse eder ve yapılandırılmış veri döndürür"""
    results = {
        "alerts": [],
        "summary": {
            "high_alerts": 0,
            "medium_alerts": 0,
            "low_alerts": 0,
            "info_alerts": 0
        }
    }
    
    # Parse the ZAP output line by line to ensure we catch all warnings
    lines = output_text.split('\n')
    
    # First, find all WARN-NEW lines
    warn_new_pattern = r"WARN-NEW:\s+(.*?)\s+\[(\d+)\]\s+x\s+(\d+)"
    
    # Track the current alert being processed
    current_alert = None
    current_urls = []
    
    # Process line by line
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Check for WARN-NEW pattern
        match = re.search(warn_new_pattern, line)
        if match:
            # If we were processing a previous alert, add it with its URLs
            if current_alert and current_urls:
                for url in current_urls:
                    alert_copy = current_alert.copy()
                    alert_copy["url"] = url
                    results["alerts"].append(alert_copy)
                    
                    # Update summary counts
                    if alert_copy["risk"] == "High":
                        results["summary"]["high_alerts"] += 1
                    elif alert_copy["risk"] == "Medium":
                        results["summary"]["medium_alerts"] += 1
                    elif alert_copy["risk"] == "Low":
                        results["summary"]["low_alerts"] += 1
                    else:
                        results["summary"]["info_alerts"] += 1
            
            # Extract alert details
            alert_name = match.group(1).strip()
            alert_id = match.group(2).strip()
            count = int(match.group(3).strip())
            
            # Create new alert
            risk = map_zap_alert_to_risk(alert_name, alert_id)
            
            current_alert = {
                "id": f"zap-{alert_id}",
                "name": alert_name,
                "description": f"ZAP detected {alert_name}",
                "risk": risk,
                "confidence": "High",
                "solution": get_solution_for_alert(alert_name, alert_id)
            }
            
            # Reset URLs for new alert
            current_urls = []
            
            # Look for URLs in subsequent lines
            j = i + 1
            while j < len(lines) and j < i + count + 10:  # Look at next few lines, but not too many
                url_line = lines[j].strip()
                # URL pattern is indented and contains http/https URL followed by status in parentheses
                url_match = re.search(r'\s+(https?://[^\s]+)\s+\((.*?)\)', url_line)
                if url_match:
                    current_urls.append(url_match.group(1).strip())
                elif re.search(warn_new_pattern, url_line):
                    # If we hit another WARN-NEW, stop
                    break
                j += 1
            
            # Move i to the last processed line
            i = j - 1
        
        i += 1
    
    # Don't forget to add the last alert
    if current_alert and current_urls:
        for url in current_urls:
            alert_copy = current_alert.copy()
            alert_copy["url"] = url
            results["alerts"].append(alert_copy)
            
            # Update summary counts
            if alert_copy["risk"] == "High":
                results["summary"]["high_alerts"] += 1
            elif alert_copy["risk"] == "Medium":
                results["summary"]["medium_alerts"] += 1
            elif alert_copy["risk"] == "Low":
                results["summary"]["low_alerts"] += 1
            else:
                results["summary"]["info_alerts"] += 1
    
    # Extract stats from the last line
    for line in reversed(lines):
        if "FAIL-NEW:" in line:
            stats_match = re.search(r'FAIL-NEW:\s+(\d+)\s+FAIL-INPROG:\s+(\d+)\s+WARN-NEW:\s+(\d+)\s+WARN-INPROG:\s+(\d+)', line)
            if stats_match:
                results["stats"] = {
                    "fail_new": int(stats_match.group(1)),
                    "fail_inprog": int(stats_match.group(2)),
                    "warn_new": int(stats_match.group(3)),
                    "warn_inprog": int(stats_match.group(4))
                }
                # Verify our counts match ZAP's reported counts
                warn_new_count = int(stats_match.group(3))
                if len(results["alerts"]) != warn_new_count:
                    print(f"Warning: Parsed {len(results['alerts'])} alerts but ZAP reported {warn_new_count} WARN-NEW items")
                break
    
    print(f"Parsed {len(results['alerts'])} alerts from ZAP output")
    return results

def map_zap_alert_to_risk(alert_name, alert_id):
    """Map ZAP alert to risk level based on name or ID"""
    # Map common critical/high vulnerabilities
    high_risk_patterns = [
        'Cross Site Scripting', 'SQL Injection', 'Remote Code Execution',
        'XXE', 'Command Injection', 'Path Traversal', 'Server Side Request Forgery'
    ]
    
    # Map common medium vulnerabilities
    medium_risk_patterns = [
        'Missing Anti-clickjacking Header', 'Content Security Policy',
        'X-Content-Type-Options', 'Information Disclosure', 'Insecure Configuration',
        'Source Code Disclosure', 'Insufficient Site Isolation'
    ]
    
    # Map common low vulnerabilities
    low_risk_patterns = [
        'Cookie Without Secure Flag', 'Cookie No HttpOnly', 'HTTP Only Site',
        'Server Leaks Version', 'Permissions Policy'
    ]
    
    # Check for high risk patterns
    for pattern in high_risk_patterns:
        if pattern.lower() in alert_name.lower():
            return "High"
    
    # Check for medium risk patterns
    for pattern in medium_risk_patterns:
        if pattern.lower() in alert_name.lower():
            return "Medium"
    
    # Check for low risk patterns
    for pattern in low_risk_patterns:
        if pattern.lower() in alert_name.lower():
            return "Low"
    
    # Default to Medium if we can't determine
    return "Medium"

def get_solution_for_alert(alert_name, alert_id):
    """Get recommended solution for a ZAP alert"""
    solutions = {
        "Missing Anti-clickjacking Header": "Implement X-Frame-Options header with DENY or SAMEORIGIN value to prevent clickjacking attacks.",
        "X-Content-Type-Options Header Missing": "Add X-Content-Type-Options header with 'nosniff' value to prevent MIME type sniffing.",
        "Server Leaks Version Information": "Configure your server to suppress version information in HTTP headers.",
        "Content Security Policy (CSP) Header Not Set": "Implement a strong Content Security Policy to prevent XSS and data injection attacks.",
        "Permissions Policy Header Not Set": "Add a Permissions Policy header to control browser features and APIs.",
        "HTTP Only Site": "Implement HTTPS and redirect all HTTP traffic to HTTPS using HSTS.",
        "Cross Site Scripting": "Implement proper input validation and output encoding to prevent XSS attacks.",
        "Source Code Disclosure": "Configure your server to prevent source code disclosure and ensure sensitive files are not accessible.",
        "Insufficient Site Isolation": "Implement proper Site Isolation protections against Spectre vulnerability."
    }
    
    # Look for exact matches
    for key in solutions:
        if key in alert_name:
            return solutions[key]
    
    # Default solution if no specific one is found
    return "Review the vulnerability details and implement appropriate security controls based on OWASP recommendations."

def parse_zap_xml(xml_file_path):
    """ZAP XML rapor çıktısını parse eder"""
    results = {
        "alerts": [],
        "summary": {
            "high_alerts": 0,
            "medium_alerts": 0,
            "low_alerts": 0,
            "info_alerts": 0
        }
    }
    
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        
        # ZAP XML'deki <alertitem> etiketlerini bul
        for item in root.findall(".//alertitem"):
            risk = item.find("riskcode").text
            name = item.find("name").text
            desc = item.find("desc").text
            solution = item.find("solution").text
            
            # URL'leri bul
            instances = item.findall(".//instance")
            urls = []
            if instances:
                for instance in instances:
                    url_element = instance.find("uri")
                    if url_element is not None and url_element.text:
                        urls.append(url_element.text)
            
            # Risk seviyesini dönüştür
            risk_mapping = {
                "3": "High",
                "2": "Medium", 
                "1": "Low",
                "0": "Info"
            }
            risk_level = risk_mapping.get(risk, "Info")
            
            # Özet bilgisini güncelle
            if risk_level == "High":
                results["summary"]["high_alerts"] += 1
            elif risk_level == "Medium":
                results["summary"]["medium_alerts"] += 1
            elif risk_level == "Low":
                results["summary"]["low_alerts"] += 1
            else:
                results["summary"]["info_alerts"] += 1
            
            # Her URL için bir zafiyet uyarısı ekle
            for url in urls:
                alert = {
                    "risk": risk_level,
                    "name": name,
                    "description": desc,
                    "url": url,
                    "solution": solution
                }
                results["alerts"].append(alert)
            
            # Eğer URL yoksa genel bir uyarı ekle
            if not urls:
                alert = {
                    "risk": risk_level,
                    "name": name,
                    "description": desc,
                    "url": "N/A",
                    "solution": solution
                }
                results["alerts"].append(alert)
    
    except Exception as e:
        print(f"XML parse hatası: {str(e)}")
    
    return results

# Simple scanner implementation for when ZAP isn't available
def simple_dast_scan(url):
    """
    Performs a simple DAST scan on the given URL without relying on OWASP ZAP.
    Returns a simplified scan result similar to ZAP format.
    """
    scan_id = str(uuid.uuid4())[:8]
    scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Initialize results structure
    results = {
        "scan_id": scan_id,
        "target_url": url,
        "scan_date": scan_date,
        "status": "completed",
        "alerts": [],
        "summary": {
            "high_alerts": 0,
            "medium_alerts": 0,
            "low_alerts": 0,
            "info_alerts": 0
        }
    }
    
    # Parse URL for checking
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Check if URL is valid and reachable
        if not parsed_url.scheme or not domain:
            raise ValueError("Invalid URL format")
            
        # Basic connectivity test
        try:
            start_time = time.time()
            response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            response_time = time.time() - start_time
            
            # Check HTTP headers for common security issues
            check_security_headers(results, response)
            
            # Check for common web vulnerabilities
            check_common_vulnerabilities(results, response, url)
            
            # Basic port scan on the domain
            check_open_ports(results, domain)
            
            # Add response time information
            if response_time > 2.0:
                results["alerts"].append({
                    "id": f"perf-{len(results['alerts'])+1}",
                    "name": "Slow Response Time",
                    "description": f"The server responded slowly ({response_time:.2f} seconds), which might indicate performance issues.",
                    "risk": "Info",
                    "confidence": "Medium",
                    "url": url,
                    "solution": "Optimize server response time through caching, code optimization, or infrastructure improvements."
                })
                results["summary"]["info_alerts"] += 1
                
        except requests.RequestException as e:
            results["alerts"].append({
                "id": f"conn-{len(results['alerts'])+1}",
                "name": "Connection Error",
                "description": f"Failed to connect to the target URL: {str(e)}",
                "risk": "High",
                "confidence": "High",
                "url": url,
                "solution": "Ensure the target URL is valid and the server is running."
            })
            results["summary"]["high_alerts"] += 1
            
    except Exception as e:
        results["alerts"].append({
            "id": f"err-{len(results['alerts'])+1}",
            "name": "Scan Error",
            "description": f"An error occurred during the scan: {str(e)}",
            "risk": "Info",
            "confidence": "High",
            "url": url,
            "solution": "Check the URL format and try again."
        })
        results["summary"]["info_alerts"] += 1
    
    # Always add some common vulnerabilities for demonstration
    # This simulates finding common issues for educational purposes
    add_sample_vulnerabilities(results, url)
    
    return results

def check_security_headers(results, response):
    """Check for missing security headers"""
    headers = response.headers
    
    # Check for Content-Security-Policy
    if "Content-Security-Policy" not in headers:
        results["alerts"].append({
            "id": f"header-{len(results['alerts'])+1}",
            "name": "Content Security Policy Not Set",
            "description": "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.",
            "risk": "Medium",
            "confidence": "High",
            "url": response.url,
            "solution": "Implement a Content Security Policy header to restrict resource loading to trusted sources."
        })
        results["summary"]["medium_alerts"] += 1
    
    # Check for X-Frame-Options
    if "X-Frame-Options" not in headers:
        results["alerts"].append({
            "id": f"header-{len(results['alerts'])+1}",
            "name": "Missing X-Frame-Options Header",
            "description": "The X-Frame-Options header is not set, which means the site could be at risk from clickjacking attacks.",
            "risk": "Medium",
            "confidence": "High",
            "url": response.url,
            "solution": "Set the X-Frame-Options header to DENY or SAMEORIGIN."
        })
        results["summary"]["medium_alerts"] += 1
    
    # Check for X-Content-Type-Options
    if "X-Content-Type-Options" not in headers:
        results["alerts"].append({
            "id": f"header-{len(results['alerts'])+1}",
            "name": "Missing X-Content-Type-Options Header",
            "description": "The X-Content-Type-Options header is not set to 'nosniff', which means browsers could MIME-sniff the content type, potentially leading to security issues.",
            "risk": "Low",
            "confidence": "High",
            "url": response.url,
            "solution": "Set the X-Content-Type-Options header to 'nosniff'."
        })
        results["summary"]["low_alerts"] += 1
    
    # Check for Strict-Transport-Security
    if "Strict-Transport-Security" not in headers and response.url.startswith("https"):
        results["alerts"].append({
            "id": f"header-{len(results['alerts'])+1}",
            "name": "Missing HTTP Strict Transport Security Header",
            "description": "HSTS is not enabled for this site, which means it could be vulnerable to SSL stripping attacks.",
            "risk": "Medium",
            "confidence": "High",
            "url": response.url,
            "solution": "Add Strict-Transport-Security header with appropriate max-age value."
        })
        results["summary"]["medium_alerts"] += 1

def check_common_vulnerabilities(results, response, url):
    """Perform basic checks for common vulnerabilities"""
    # Check for potential information disclosure
    if "X-Powered-By" in response.headers:
        results["alerts"].append({
            "id": f"info-{len(results['alerts'])+1}",
            "name": "Server Technology Information Disclosure",
            "description": f"The server reveals technology information via headers: {response.headers.get('X-Powered-By')}",
            "risk": "Low",
            "confidence": "High",
            "url": url,
            "solution": "Configure the server to suppress the X-Powered-By header."
        })
        results["summary"]["low_alerts"] += 1
    
    # Check for cookies without security flags
    for cookie in response.cookies:
        if not cookie.secure:
            results["alerts"].append({
                "id": f"cookie-{len(results['alerts'])+1}",
                "name": "Cookie Without Secure Flag",
                "description": f"A cookie ({cookie.name}) is set without the Secure flag, which means it can be transmitted over unencrypted connections.",
                "risk": "Medium",
                "confidence": "High",
                "url": url,
                "solution": "Set the Secure flag on all cookies that are sent over HTTPS."
            })
            results["summary"]["medium_alerts"] += 1
            
        if not cookie.has_nonstandard_attr('HttpOnly'):
            results["alerts"].append({
                "id": f"cookie-{len(results['alerts'])+1}",
                "name": "Cookie Without HttpOnly Flag",
                "description": f"A cookie ({cookie.name}) is set without the HttpOnly flag, which means it can be accessed by JavaScript.",
                "risk": "Low",
                "confidence": "High",
                "url": url,
                "solution": "Set the HttpOnly flag on cookies containing sensitive data."
            })
            results["summary"]["low_alerts"] += 1

def check_open_ports(results, domain):
    """Perform a basic port scan on common ports"""
    common_ports = [21, 22, 23, 25, 53, 80, 443, 8080, 8443]
    open_ports = []
    
    try:
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        
        if len(open_ports) > 3 and any(port not in [80, 443] for port in open_ports):
            results["alerts"].append({
                "id": f"port-{len(results['alerts'])+1}",
                "name": "Multiple Open Ports Detected",
                "description": f"The server has multiple open ports: {', '.join(map(str, open_ports))}. Unnecessary open ports increase attack surface.",
                "risk": "Low",
                "confidence": "Medium",
                "url": f"http://{domain}",
                "solution": "Close unnecessary ports and restrict access to required services."
            })
            results["summary"]["low_alerts"] += 1
    except socket.gaierror:
        # Can't resolve hostname
        pass
    except Exception:
        # Other socket errors
        pass

def add_sample_vulnerabilities(results, url):
    """Add sample vulnerabilities for demonstration purposes"""
    
    # For other URLs, we DON'T add SQL Injection and XSS vulnerabilities by default
    # Instead, only add vulnerabilities that are more likely to be legitimate concerns
    
    # If the URL is HTTP (not HTTPS), add an HTTPS enforcement warning
    if url.startswith("http://") and not "localhost" in url and not "127.0.0.1" in url:
        results["alerts"].append({
            "id": f"sample-{len(results['alerts'])+1}",
            "name": "No HTTPS Enforcement",
            "description": "The application does not use HTTPS, allowing insecure communication over plain HTTP.",
            "risk": "Medium",
            "confidence": "High",
            "url": f"{url}",
            "solution": "Enforce HTTPS using HSTS headers. Redirect all HTTP traffic to HTTPS. Configure secure cookies."
        })
        results["summary"]["medium_alerts"] += 1

# Create necessary directories for reports
DAST_REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'dastReports')
os.makedirs(DAST_REPORTS_DIR, exist_ok=True)

def run_zap_scan(target_url, scan_id):
    """Run ZAP full scan on the target URL and save report to dastReports directory"""
    try:
        # Create unique report filename
        html_report_path = os.path.join(DAST_REPORTS_DIR, f"{scan_id}_dast-report.html")
        results_txt_path = os.path.join(DAST_REPORTS_DIR, f"{scan_id}_zap_output.txt")
        
        # Clear previous reports
        clear_old_reports()
        
        # Get current working directory - use os.getcwd() for the actual working directory
        current_dir = os.getcwd()
        
        # Create a debug file to log process information
        debug_log_path = os.path.join(DAST_REPORTS_DIR, f"{scan_id}_debug.log")
        with open(debug_log_path, 'w', encoding='utf-8') as f:
            f.write(f"Starting ZAP scan for {target_url}\n")
            f.write(f"Current directory: {current_dir}\n")
        
        # Check if running in Docker container
        is_in_container = os.path.exists('/.dockerenv')
        
        # Log information about Docker
        with open(debug_log_path, 'a', encoding='utf-8') as f:
            f.write(f"Running in Docker container: {is_in_container}\n")
        
        if is_in_container:
            # When running in a container, Docker-in-Docker is often problematic
            # Raise an exception to trigger the fallback scanner
            with open(debug_log_path, 'a', encoding='utf-8') as f:
                f.write("Running in container - using fallback scanner instead of ZAP\n")
            raise Exception("Running in Docker container - ZAP scan (Docker-in-Docker) not supported")
        
        # Prepare ZAP command exactly as the user runs it manually, but with dynamic paths
        # For Windows compatibility, use forward slashes in the volume path
        windows_path = current_dir.replace('\\', '/')
        
        # This format follows: docker run --rm -v %cd%:/zap/wrk/:rw -t zaproxy/zap-stable zap-full-scan.py -t URL
        cmd = f'docker run --rm -v {windows_path}:/zap/wrk/:rw -t zaproxy/zap-stable zap-full-scan.py -t {target_url} -r /zap/wrk/dastReports/{scan_id}_dast-report.html'
        
        # Log the command
        with open(debug_log_path, 'a', encoding='utf-8') as f:
            f.write(f"Command: {cmd}\n")
        
        # Use subprocess.run with shell=True to execute exactly as the user would manually
        # This provides better compatibility with the exact command format
        try:
            # First check if Docker is running
            docker_check = subprocess.run(
                'docker ps',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            if docker_check.returncode != 0:
                with open(debug_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"Docker check failed: {docker_check.stderr}\n")
                raise Exception("Docker does not appear to be running. Please start Docker and try again.")
            
            # Start the ZAP scan process
            with open(debug_log_path, 'a', encoding='utf-8') as f:
                f.write("Starting ZAP process...\n")
            
            process = subprocess.Popen(
                cmd,
                shell=True,  # Use shell execution for exact command reproduction
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            with open(debug_log_path, 'a', encoding='utf-8') as f:
                f.write(f"Process started with PID: {process.pid}\n")
                f.write("Waiting for process to complete...\n")
            
            # Wait for process to complete with timeout (30 minutes)
            stdout, stderr = process.communicate(timeout=1800)
            
            # Save the raw output for debugging
            with open(results_txt_path, 'w', encoding='utf-8') as f:
                f.write(stdout)
            
            if stderr:
                with open(os.path.join(DAST_REPORTS_DIR, f"{scan_id}_zap_errors.txt"), 'w', encoding='utf-8') as f:
                    f.write(stderr)
            
            with open(debug_log_path, 'a', encoding='utf-8') as f:
                f.write(f"Process completed with return code: {process.returncode}\n")
                f.write(f"Output size: {len(stdout)} bytes\n")
                f.write(f"Error size: {len(stderr)} bytes\n")
                
        except subprocess.TimeoutExpired:
            process.kill()
            with open(debug_log_path, 'a', encoding='utf-8') as f:
                f.write("Process timed out after 30 minutes\n")
            raise Exception("ZAP scan timed out after 30 minutes")
        except Exception as e:
            with open(debug_log_path, 'a', encoding='utf-8') as f:
                f.write(f"Process error: {str(e)}\n")
            raise
        
        # Check if scan completed successfully
        if process.returncode != 0:
            with open(debug_log_path, 'a', encoding='utf-8') as f:
                f.write(f"ZAP scan failed with return code {process.returncode}\n")
                f.write(f"Error: {stderr}\n")
            raise Exception(f"ZAP scan failed with return code {process.returncode}: {stderr}")
        
        # Check if the HTML report was created
        if not os.path.exists(html_report_path):
            with open(debug_log_path, 'a', encoding='utf-8') as f:
                f.write(f"HTML report not found at {html_report_path}\n")
                f.write("Checking dastReports directory contents:\n")
                for file in os.listdir(DAST_REPORTS_DIR):
                    f.write(f" - {file}\n")
            
            # Try to find any HTML report that might have been created with a different name
            html_files = [f for f in os.listdir(DAST_REPORTS_DIR) if f.endswith('.html') and scan_id in f]
            if html_files:
                html_report_path = os.path.join(DAST_REPORTS_DIR, html_files[0])
                with open(debug_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"Found alternative HTML report: {html_files[0]}\n")
        
        # Parse ZAP output to get alerts
        with open(debug_log_path, 'a', encoding='utf-8') as f:
            f.write("Parsing ZAP output...\n")
        
        zap_results = parse_zap_output(stdout)
        
        # Add report path to results
        zap_results["report_path"] = html_report_path
        zap_results["raw_output_path"] = results_txt_path
        
        with open(debug_log_path, 'a', encoding='utf-8') as f:
            f.write(f"Parsed {len(zap_results['alerts'])} alerts from ZAP output\n")
            f.write("Scan completed successfully\n")
        
        return zap_results
    except Exception as e:
        error_msg = f"Error running ZAP scan: {str(e)}"
        print(error_msg)
        # Try to log the error to debug file
        try:
            with open(os.path.join(DAST_REPORTS_DIR, f"{scan_id}_debug.log"), 'a', encoding='utf-8') as f:
                f.write(f"FATAL ERROR: {error_msg}\n")
        except:
            pass
        # Re-raise the exception to be handled by the caller
        raise

def clear_old_reports():
    """Delete all files in the dastReports directory"""
    try:
        for filename in os.listdir(DAST_REPORTS_DIR):
            file_path = os.path.join(DAST_REPORTS_DIR, filename)
            if os.path.isfile(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
    except Exception as e:
        print(f"Error clearing old reports: {str(e)}")

@dast_bp.route('/scan', methods=['POST'])
def start_zap_scan():
    """Start a ZAP scan against a target URL"""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({
            'message': 'No URL provided',
            'status': 'error'
        }), 400
        
    target_url = data['url']
    scan_id = f"dast_{uuid.uuid4().hex[:8]}"
    scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        # Start with ZAP scan - don't try/except here, let it fail if it fails
        print(f"Starting ZAP scan for {target_url}")
        
        # Add initial record to scan history to show "in progress" status
        scan_history.insert(0, {
            "scan_id": scan_id,
            "target_url": target_url,
            "scan_date": scan_date,
            "status": "in_progress",
            "message": "ZAP scan in progress. This may take several minutes."
        })
        
        # Check if we're running in a container and need to use the fallback scanner
        is_in_container = os.path.exists('/.dockerenv')
        
        if is_in_container:
            # When running in a container, always use the fallback scanner
            raise Exception("Running in Docker container - using fallback scanner")
        
        # Try the ZAP scan first
        try:
            # Run the actual ZAP scan - this will take time (1-2 minutes typically)
            results = run_zap_scan(target_url, scan_id)
            
            # Add scan metadata
            results["scan_id"] = scan_id
            results["target_url"] = target_url
            results["scan_date"] = scan_date
            results["status"] = "completed"
            
            # Store scan results for report download
            scan_results_store[scan_id] = results
            
            # Save report for future reference
            html_report_path = results.get("report_path")
            if html_report_path and os.path.exists(html_report_path):
                # Also generate our own format reports
                save_report_in_all_formats(scan_id, results)
            
            # Update scan history entry
            for i, entry in enumerate(scan_history):
                if entry["scan_id"] == scan_id:
                    scan_history[i] = {
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "scan_date": scan_date,
                        "status": "completed",
                        "alerts_count": {
                            "high": results["summary"]["high_alerts"],
                            "medium": results["summary"]["medium_alerts"],
                            "low": results["summary"]["low_alerts"]
                        },
                        "report_path": html_report_path
                    }
                    break
            
            return jsonify({
                'message': 'ZAP scan completed successfully',
                'scan_id': scan_id,
                'results': results
            }), 200
        except Exception as zap_error:
            # Log the ZAP error and continue to fallback
            print(f"ZAP scan failed: {str(zap_error)}. Using fallback scanner.")
            raise zap_error  # Re-raise to be caught by the outer try/except
            
    except Exception as e:
        # If there's an error, log it and update scan history as failed
        print(f"ZAP scan error: {str(e)}. Falling back to simple scanner.")
        
        # Update scan history entry if it exists to show switching to fallback
        scan_entry_updated = False
        for i, entry in enumerate(scan_history):
            if entry["scan_id"] == scan_id:
                scan_history[i]["message"] = "ZAP scan failed. Switching to fallback scanner..."
                scan_entry_updated = True
                break
        
        # Fall back to simple scanner if ZAP failed
        try:
            print("Using fallback scanner")
            
            # Simulate delay to give more realistic scanning time
            time.sleep(5)  # Add a 5-second delay to simulate processing time
            
            # Run the fallback scanner
            results = simple_dast_scan(target_url)
            results["scan_id"] = scan_id
            results["target_url"] = target_url
            results["scan_date"] = scan_date
            results["status"] = "completed"
            
            # Store scan results for report download
            scan_results_store[scan_id] = results
            
            # Save simple scan report
            html_report_path = os.path.join(DAST_REPORTS_DIR, f"{scan_id}_dast-report.html")
            html_content = create_html_report(results)
            with open(html_report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            save_report_in_all_formats(scan_id, results)
            
            # Update scan history entry
            for i, entry in enumerate(scan_history):
                if entry["scan_id"] == scan_id:
                    scan_history[i] = {
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "scan_date": scan_date,
                        "status": "completed",
                        "alerts_count": {
                            "high": results["summary"]["high_alerts"],
                            "medium": results["summary"]["medium_alerts"],
                            "low": results["summary"]["low_alerts"]
                        },
                        "report_path": html_report_path
                    }
                    break
            
            return jsonify({
                'message': 'Scan completed using fallback scanner',
                'scan_id': scan_id,
                'results': results
            }), 200
            
        except Exception as fallback_error:
            print(f"Fallback scanner also failed: {str(fallback_error)}")
            
            # Update scan history as failed
            for i, entry in enumerate(scan_history):
                if entry["scan_id"] == scan_id:
                    scan_history[i] = {
                        "scan_id": scan_id,
                        "target_url": target_url,
                        "scan_date": scan_date,
                        "status": "failed",
                        "error": f"ZAP scan failed: {str(e)}. Fallback also failed: {str(fallback_error)}"
                    }
                    break
                    
            return jsonify({
                'message': f'Scan failed: {str(e)}. Fallback also failed: {str(fallback_error)}',
                'scan_id': scan_id,
                'status': 'error'
            }), 500

@dast_bp.route('/scan_status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get the status of a scan by ID"""
    for entry in scan_history:
        if entry["scan_id"] == scan_id:
            return jsonify({
                "status": entry["status"],
                "message": entry.get("message", ""),
                "error": entry.get("error", ""),
                "scan_id": scan_id
            }), 200
    
    return jsonify({
        "status": "not_found",
        "message": "Scan not found",
        "scan_id": scan_id
    }), 404

def save_report_in_all_formats(scan_id, results):
    """Save scan report in all formats (HTML, PDF, JSON)"""
    try:
        # Generate and save HTML report
        html_report_path = os.path.join(DAST_REPORTS_DIR, f"{scan_id}_dast-report.html")
        html_content = create_html_report(results)
        with open(html_report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Generate and save PDF report if available
        if PDF_AVAILABLE:
            pdf_buffer = create_pdf_report(results)
            if pdf_buffer:
                pdf_report_path = os.path.join(DAST_REPORTS_DIR, f"{scan_id}_dast-report.pdf")
                with open(pdf_report_path, 'wb') as f:
                    f.write(pdf_buffer.getvalue())
        
        # Save JSON report
        json_report_path = os.path.join(DAST_REPORTS_DIR, f"{scan_id}_dast-report.json")
        with open(json_report_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        
    except Exception as e:
        print(f"Error saving reports: {str(e)}")

@dast_bp.route('/scan_history', methods=['GET'])
def get_scan_history():
    global scan_history
    
    # If no scans yet, use sample data for demo
    if not scan_history:
        # Initialize with sample data
        scan_history = [
            {
                "scan_id": "scan_1617123456",
                "target_url": "https://example.com",
                "scan_date": "2023-09-14 14:30:45",
                "status": "completed",
                "high_alerts": 2,
                "medium_alerts": 3,
                "low_alerts": 5
            },
            {
                "scan_id": "scan_1617123789",
                "target_url": "https://staging.site",
                "scan_date": "2023-05-10 09:15:22",
                "status": "failed",
                "error": "Connection timed out"
            }
        ]
        
        # Initialize sample scan results
        scan_results_store["scan_1617123456"] = {
            "scan_id": "scan_1617123456",
            "target_url": "https://example.com",
            "scan_date": "2023-09-14 14:30:45",
            "status": "completed",
            "summary": {
                "high_alerts": 2,
                "medium_alerts": 3,
                "low_alerts": 5,
                "info_alerts": 7
            },
            "alerts": [
                {
                    "risk": "High",
                    "name": "SQL Injection",
                    "description": "SQL injection may be possible",
                    "url": "https://example.com/search?q=test",
                    "solution": "Use parameterized queries"
                },
                {
                    "risk": "High",
                    "name": "Cross-Site Scripting (XSS)",
                    "description": "Reflected XSS detected",
                    "url": "https://example.com/page?id=<script>",
                    "solution": "Filter special characters and use CSP"
                }
            ]
        }
    
    # Return the actual scan history
    return jsonify({
        "message": "Scan history retrieved successfully",
        "history": scan_history
    }), 200

@dast_bp.route('/report/<scan_id>', methods=['GET'])
def get_scan_report(scan_id):
    """Generates and returns a downloadable report for a specific scan"""
    
    # First, check if we have an existing report file in dastReports directory
    for report_format in ['html', 'pdf', 'json']:
        report_path = os.path.join(DAST_REPORTS_DIR, f"{scan_id}_dast-report.{report_format}")
        if os.path.exists(report_path) and report_format == request.args.get('format', 'json'):
            try:
                mime_types = {
                    'html': 'text/html',
                    'pdf': 'application/pdf',
                    'json': 'application/json'
                }
                return send_file(
                    report_path,
                    mimetype=mime_types[report_format],
                    as_attachment=True,
                    download_name=f"dast_report_{scan_id}.{report_format}"
                )
            except Exception as e:
                print(f"Error sending report file: {str(e)}")
    
    # Continue with the existing logic if file not found or error occurs
    # Check if scan exists in our store
    if scan_id not in scan_results_store:
        # For demo - create a simulated result if it doesn't exist
        if scan_id in [scan["scan_id"] for scan in scan_history if scan["status"] == "completed"]:
            # Find the scan in history
            for scan in scan_history:
                if scan["scan_id"] == scan_id:
                    # Create mock detailed results
                    scan_results_store[scan_id] = {
                        "scan_id": scan_id,
                        "target_url": scan["target_url"],
                        "scan_date": scan["scan_date"],
                        "status": "completed",
                        "summary": {
                            "high_alerts": scan.get("high_alerts", 0),
                            "medium_alerts": scan.get("medium_alerts", 0),
                            "low_alerts": scan.get("low_alerts", 0),
                            "info_alerts": 5
                        },
                        "alerts": [
                            {
                                "risk": "High",
                                "name": "SQL Injection",
                                "description": "SQL injection may be possible",
                                "url": f"{scan['target_url']}/search?q=test",
                                "solution": "Use parameterized queries"
                            },
                            {
                                "risk": "Medium",
                                "name": "Cross-Site Request Forgery",
                                "description": "No CSRF tokens found",
                                "url": f"{scan['target_url']}/profile",
                                "solution": "Implement CSRF tokens for all state-changing operations"
                            }
                        ]
                    }
                    break
        else:
            return jsonify({"message": "Scan report not found"}), 404
    
    # Rapor formatını kontrol et (json, pdf, html)
    report_format = request.args.get('format', 'json')
    
    # PDF raporu
    if report_format == 'pdf':
        try:
            pdf_buffer = create_pdf_report(scan_results_store[scan_id])
            
            if not pdf_buffer:
                return jsonify({
                    "message": "PDF generation failed. Returning JSON report instead.",
                    "report_id": f"report_{scan_id}",
                    "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "scan_data": scan_results_store[scan_id]
                }), 200
                
            response = make_response(pdf_buffer.getvalue())
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename=dast_report_{scan_id}.pdf'
            return response
            
        except Exception as e:
            print(f"Error generating PDF: {str(e)}")
            return jsonify({
                "message": f"Error generating PDF: {str(e)}. Returning JSON report instead.",
                "report_id": f"report_{scan_id}",
                "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_data": scan_results_store[scan_id]
            }), 200
    
    # HTML raporu
    elif report_format == 'html':
        try:
            html_content = create_html_report(scan_results_store[scan_id])
            
            response = make_response(html_content)
            response.headers['Content-Type'] = 'text/html'
            response.headers['Content-Disposition'] = f'attachment; filename=dast_report_{scan_id}.html'
            return response
            
        except Exception as e:
            print(f"Error generating HTML report: {str(e)}")
            return jsonify({
                "message": f"Error generating HTML report: {str(e)}. Returning JSON report instead.",
                "report_id": f"report_{scan_id}",
                "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_data": scan_results_store[scan_id]
            }), 200
    
    # Varsayılan JSON raporu
    report = {
        "report_id": f"report_{scan_id}",
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_data": scan_results_store[scan_id]
    }
    
    return jsonify(report), 200 