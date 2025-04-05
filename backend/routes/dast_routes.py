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
import urllib.parse
import socket

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
    
    # ZAP Alert Lines: WARN-NEW: [risk_level] [alert_name] [url]
    alert_pattern = r"WARN-NEW:\s+\[(.*?)\]\s+(.*?)\s+\[(.*?)\]"
    
    # Her bir zafiyet uyarısını bul
    for line in output_text.split('\n'):
        match = re.search(alert_pattern, line)
        if match:
            risk_level = match.group(1).strip()
            alert_name = match.group(2).strip()
            url = match.group(3).strip()
            
            # Risk seviyesini düzgün formata dönüştür
            risk_mapping = {
                "High": "High",
                "Medium": "Medium",
                "Low": "Low",
                "Informational": "Info"
            }
            
            risk = risk_mapping.get(risk_level, "Info")
            
            # Özet bilgisini güncelle
            if risk == "High":
                results["summary"]["high_alerts"] += 1
            elif risk == "Medium":
                results["summary"]["medium_alerts"] += 1
            elif risk == "Low":
                results["summary"]["low_alerts"] += 1
            else:
                results["summary"]["info_alerts"] += 1
            
            # Zafiyet detayını ekle
            alert = {
                "risk": risk,
                "name": alert_name,
                "description": f"ZAP detected a potential {alert_name} vulnerability",
                "url": url,
                "solution": f"Investigate and fix the {alert_name} vulnerability in the application"
            }
            results["alerts"].append(alert)
    
    return results

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

@dast_bp.route('/scan', methods=['POST'])
def start_zap_scan():
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'message': 'URL is required'}), 400
    
    target_url = data['url']
    
    # Check if URL is valid
    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        return jsonify({'message': 'URL must start with http:// or https://'}), 400
    
    try:
        # Scan başlangıç zamanı ve ID'si
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_id = f"scan_{int(datetime.datetime.now().timestamp())}"
        
        print(f"Starting scan for URL: {target_url}")
        
        # Basit bir HTTP tarayıcı implementasyonu
        import requests
        from bs4 import BeautifulSoup
        import re
        import urllib.parse
        
        # Güvenli Request yapın (SSL doğrulama hatalarını yok sayma)
        try:
            headers = {
                'User-Agent': 'AIronSafe DAST Scanner/1.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            print(f"Sending HTTP request to {target_url}")
            response = requests.get(target_url, headers=headers, timeout=30, verify=True)
            response.raise_for_status()  # HTTP hatalarını kontrol et
            
            print(f"Received response with status code: {response.status_code}")
            
            # Başarılı yanıt aldık, HTML içeriğini parse et
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Başlık, meta etiketleri ve header bilgilerini topla
            page_title = soup.title.text if soup.title else "No Title"
            meta_tags = len(soup.find_all('meta'))
            found_headers = dict(response.headers)
            
            print(f"Page title: {page_title}, Meta tags: {meta_tags}")
            
            # Güvenlik başlıklarını kontrol et
            alerts = []
            summary = {
                "high_alerts": 0,
                "medium_alerts": 0,
                "low_alerts": 0,
                "info_alerts": 0
            }
            
            # 1. Content-Security-Policy kontrolü
            if 'Content-Security-Policy' not in found_headers:
                alerts.append({
                    "risk": "Medium",
                    "name": "Content Security Policy Not Set",
                    "description": "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.",
                    "url": target_url,
                    "solution": "Implement a Content Security Policy header."
                })
                summary["medium_alerts"] += 1
            
            # 2. X-Frame-Options kontrolü
            if 'X-Frame-Options' not in found_headers:
                alerts.append({
                    "risk": "Medium",
                    "name": "Missing X-Frame-Options Header",
                    "description": "The X-Frame-Options header is not set which can lead to clickjacking attacks.",
                    "url": target_url,
                    "solution": "Set the X-Frame-Options header to DENY or SAMEORIGIN."
                })
                summary["medium_alerts"] += 1
            
            # 3. X-XSS-Protection kontrolü
            if 'X-XSS-Protection' not in found_headers:
                alerts.append({
                    "risk": "Low",
                    "name": "Missing X-XSS-Protection Header",
                    "description": "The X-XSS-Protection header is not set which can lead to XSS attacks.",
                    "url": target_url,
                    "solution": "Set the X-XSS-Protection header to '1; mode=block'."
                })
                summary["low_alerts"] += 1
                
            # 4. X-Content-Type-Options kontrolü
            if 'X-Content-Type-Options' not in found_headers:
                alerts.append({
                    "risk": "Low",
                    "name": "Missing X-Content-Type-Options Header",
                    "description": "The X-Content-Type-Options header is not set to 'nosniff' which can lead to MIME type sniffing attacks.",
                    "url": target_url,
                    "solution": "Set the X-Content-Type-Options header to 'nosniff'."
                })
                summary["low_alerts"] += 1
            
            # 5. HTTPS Strict Transport Security kontrolü
            if 'Strict-Transport-Security' not in found_headers and target_url.startswith('https://'):
                alerts.append({
                    "risk": "Medium",
                    "name": "Missing Strict-Transport-Security Header",
                    "description": "HTTP Strict Transport Security (HSTS) is not set which can lead to SSL stripping attacks.",
                    "url": target_url,
                    "solution": "Set the Strict-Transport-Security header with an appropriate max-age value."
                })
                summary["medium_alerts"] += 1
                
            # 6. Server bilgisi kontrolü
            if 'Server' in found_headers and found_headers['Server'] != '':
                alerts.append({
                    "risk": "Low",
                    "name": "Server Information Disclosure",
                    "description": f"The server is revealing its identity: {found_headers['Server']}",
                    "url": target_url,
                    "solution": "Configure the server to suppress the Server header or provide minimal information."
                })
                summary["low_alerts"] += 1
                
            # 7. Formlar için CSRF kontrolü
            forms = soup.find_all('form')
            if forms:
                has_csrf = False
                for form in forms:
                    # CSRF token olup olmadığını kontrol et
                    inputs = form.find_all('input')
                    for input_tag in inputs:
                        input_name = input_tag.get('name', '').lower()
                        input_id = input_tag.get('id', '').lower()
                        if 'csrf' in input_name or 'token' in input_name or 'csrf' in input_id or 'token' in input_id:
                            has_csrf = True
                            break
                
                if not has_csrf:
                    alerts.append({
                        "risk": "Medium",
                        "name": "Cross-Site Request Forgery",
                        "description": "A form was found without a CSRF token, which can lead to CSRF attacks.",
                        "url": target_url,
                        "solution": "Implement CSRF tokens for all forms."
                    })
                    summary["medium_alerts"] += 1
            
            # 8. Inline JavaScript kontrolü
            scripts = soup.find_all('script')
            inline_scripts = 0
            for script in scripts:
                if not script.get('src') and script.string:
                    inline_scripts += 1
            
            if inline_scripts > 0:
                alerts.append({
                    "risk": "Low",
                    "name": "Inline JavaScript Found",
                    "description": f"Found {inline_scripts} inline JavaScript block(s) which can be a security risk if they process user input.",
                    "url": target_url,
                    "solution": "Move JavaScript to external files and use a Content Security Policy to restrict execution."
                })
                summary["low_alerts"] += 1
                
            # 9. Input kontrolü (XSS potansiyeli)
            inputs = soup.find_all('input')
            if inputs:
                alerts.append({
                    "risk": "Info",
                    "name": "Input Fields Found",
                    "description": f"Found {len(inputs)} input field(s) which should be validated on the server-side to prevent XSS attacks.",
                    "url": target_url,
                    "solution": "Ensure all user inputs are properly validated and sanitized both on client and server side."
                })
                summary["info_alerts"] += 1

            # 10. Cookie güvenliği kontrolü
            if 'Set-Cookie' in found_headers:
                secure_cookie = 'secure' in found_headers['Set-Cookie'].lower()
                httponly_cookie = 'httponly' in found_headers['Set-Cookie'].lower()
                
                if not secure_cookie and target_url.startswith('https://'):
                    alerts.append({
                        "risk": "Medium",
                        "name": "Cookie Without Secure Flag",
                        "description": "Cookies are not marked as secure, which means they can be transmitted over unencrypted connections.",
                        "url": target_url,
                        "solution": "Set the secure flag on all cookies that are sent over HTTPS."
                    })
                    summary["medium_alerts"] += 1
                
                if not httponly_cookie:
                    alerts.append({
                        "risk": "Low",
                        "name": "Cookie Without HttpOnly Flag",
                        "description": "Cookies are not marked as HttpOnly, which means they can be accessed by JavaScript.",
                        "url": target_url,
                        "solution": "Set the HttpOnly flag on all cookies that don't need to be accessed by JavaScript."
                    })
                    summary["low_alerts"] += 1
            
            # 11. SSL/TLS kontrolü
            if target_url.startswith('https://'):
                import ssl
                from urllib.parse import urlparse
                
                parsed_url = urlparse(target_url)
                hostname = parsed_url.netloc
                
                # SSL version ve cipher bilgisini al
                try:
                    ctx = ssl.create_default_context()
                    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                        s.connect((hostname, 443))
                        ssl_version = s.version()
                        cipher = s.cipher()
                    
                    # TLS 1.0/1.1 kullanımı kontrolü
                    if ssl_version in ['TLSv1', 'TLSv1.1']:
                        alerts.append({
                            "risk": "Medium",
                            "name": "Obsolete SSL/TLS Version",
                            "description": f"The server is using an obsolete SSL/TLS version: {ssl_version}",
                            "url": target_url,
                            "solution": "Configure the server to use TLSv1.2 or higher only."
                        })
                        summary["medium_alerts"] += 1
                        
                except Exception as e:
                    # SSL kontrolü başarısız - bilgilendirme amaçlı bir uyarı ekle
                    alerts.append({
                        "risk": "Info",
                        "name": "SSL/TLS Check Failed",
                        "description": f"Could not check SSL/TLS configuration: {str(e)}",
                        "url": target_url,
                        "solution": "Manually check the SSL/TLS configuration using tools like SSL Labs."
                    })
                    summary["info_alerts"] += 1
            
            # 12. HTTP sadece uygulama kontrolü
            if target_url.startswith('http://') and not target_url.startswith('http://localhost'):
                alerts.append({
                    "risk": "High",
                    "name": "Unencrypted HTTP Connection",
                    "description": "The application is using unencrypted HTTP which can lead to data exposure and man-in-the-middle attacks.",
                    "url": target_url,
                    "solution": "Migrate to HTTPS by obtaining and configuring an SSL/TLS certificate."
                })
                summary["high_alerts"] += 1

            # Bulunan linklerin kontrolü (sadece domain içi linkler)
            links = soup.find_all('a', href=True)
            
            base_domain = urllib.parse.urlparse(target_url).netloc
            
            # Maksimum 5 link kontrolü yap
            checked_links = 0
            for link in links:
                if checked_links >= 5:
                    break
                    
                href = link['href']
                
                # Tam URL oluştur
                if href.startswith('/'):
                    full_url = f"{urllib.parse.urlparse(target_url).scheme}://{base_domain}{href}"
                elif href.startswith('http'):
                    full_url = href
                else:
                    # Göreceli link, tam URL oluştur
                    full_url = urllib.parse.urljoin(target_url, href)
                
                # Sadece aynı domain'deki linkleri kontrol et
                if urllib.parse.urlparse(full_url).netloc == base_domain:
                    checked_links += 1
                    
                    # Error sayfası test et (XSS testi)
                    test_url = f"{full_url}{'&' if '?' in full_url else '?'}test=<script>alert(1)</script>"
                    
                    try:
                        test_response = requests.get(test_url, headers=headers, timeout=5, verify=True)
                        
                        # XSS yansıması kontrol et
                        if "<script>alert(1)</script>" in test_response.text:
                            alerts.append({
                                "risk": "High",
                                "name": "Reflected Cross-Site Scripting (XSS)",
                                "description": "A reflected XSS vulnerability was found. The application is echoing user input without proper encoding.",
                                "url": test_url,
                                "solution": "Properly encode all user input before including it in the response."
                            })
                            summary["high_alerts"] += 1
                            break  # Bir XSS bulunca diğer kontrolleri atla
                    except:
                        # Link kontrolü hatası - önemli değil
                        pass
            
            # Sonuçları oluştur
            print(f"Found {len(alerts)} potential security issues")
            
            # Scan sonuç veri yapısı
            full_results = {
                "scan_id": scan_id,
                "target_url": target_url,
                "scan_date": current_time,
                "status": "completed",
                "summary": summary,
                "alerts": alerts
            }
            
        except requests.exceptions.RequestException as e:
            # HTTP istek hatası
            error_msg = str(e)
            print(f"HTTP request error: {error_msg}")
            
            full_results = {
                "scan_id": scan_id,
                "target_url": target_url,
                "scan_date": current_time,
                "status": "error",
                "error_details": error_msg,
                "summary": {
                    "high_alerts": 0,
                    "medium_alerts": 0,
                    "low_alerts": 0,
                    "info_alerts": 1
                },
                "alerts": [
                    {
                        "risk": "Info",
                        "name": "Request Error",
                        "description": f"Error making HTTP request: {error_msg}",
                        "url": target_url,
                        "solution": "Check if the URL is correct and the server is accessible."
                    }
                ]
            }
        except Exception as e:
            # Genel hata
            error_msg = str(e)
            print(f"General scanning error: {error_msg}")
            
            full_results = {
                "scan_id": scan_id,
                "target_url": target_url,
                "scan_date": current_time,
                "status": "error",
                "error_details": error_msg,
                "summary": {
                    "high_alerts": 0,
                    "medium_alerts": 0, 
                    "low_alerts": 0,
                    "info_alerts": 1
                },
                "alerts": [
                    {
                        "risk": "Info",
                        "name": "Scanning Error",
                        "description": f"Error during scanning: {error_msg}",
                        "url": target_url,
                        "solution": "Check the error details and try again."
                    }
                ]
            }
            
        # Scan history'ye ekle
        scan_history_entry = {
            "scan_id": full_results["scan_id"],
            "target_url": full_results["target_url"],
            "scan_date": full_results["scan_date"],
            "status": full_results["status"],
            "high_alerts": full_results["summary"]["high_alerts"],
            "medium_alerts": full_results["summary"]["medium_alerts"],
            "low_alerts": full_results["summary"]["low_alerts"]
        }
        
        # Hata durumunda error mesajını ekle
        if "error_details" in full_results:
            scan_history_entry["error"] = full_results["error_details"]
        
        # Global scan geçmişine ekle
        scan_history.insert(0, scan_history_entry)
        
        # Tam sonuçları daha sonraki rapor indirmeleri için sakla
        scan_results_store[scan_id] = full_results
        
        return jsonify({
            "message": "Scan completed successfully",
            "scan_id": full_results["scan_id"],
            "scan_date": full_results["scan_date"],
            "results": full_results
        }), 200
        
    except Exception as e:
        error_msg = str(e)
        print(f"Error during scan: {error_msg}")
        
        # Add failed scan to history
        failed_scan = {
            "scan_id": f"scan_{int(datetime.datetime.now().timestamp())}",
            "target_url": target_url,
            "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "failed",
            "error": error_msg
        }
        scan_history.insert(0, failed_scan)
        
        return jsonify({
            'message': 'Error during scan', 
            'error': error_msg,
        }), 500

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