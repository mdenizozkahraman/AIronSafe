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
        # Simulate ZAP scan with mock results for testing
        # In a real implementation, you would use Python-OWASP-ZAP or subprocess to call ZAP CLI
        
        # Mock results
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_id = f"scan_{int(datetime.datetime.now().timestamp())}"
        
        scan_results = {
            "scan_id": scan_id,
            "target_url": target_url,
            "scan_date": current_time,
            "status": "completed",
            "summary": {
                "high_alerts": 2,
                "medium_alerts": 3,
                "low_alerts": 5,
                "info_alerts": 8
            },
            "alerts": [
                {
                    "risk": "High",
                    "name": "SQL Injection",
                    "description": "SQL injection may be possible",
                    "url": f"{target_url}/search?q=test",
                    "solution": "Use parameterized queries"
                },
                {
                    "risk": "High",
                    "name": "Cross-Site Scripting (XSS)",
                    "description": "Reflected XSS detected",
                    "url": f"{target_url}/page?id=<script>",
                    "solution": "Filter special characters and use CSP"
                },
                {
                    "risk": "Medium", 
                    "name": "Cross-Site Request Forgery",
                    "description": "No CSRF tokens found",
                    "url": f"{target_url}/profile",
                    "solution": "Implement CSRF tokens for all state-changing operations"
                },
                {
                    "risk": "Medium",
                    "name": "Content Security Policy Not Set",
                    "description": "CSP header is not set",
                    "url": target_url,
                    "solution": "Implement a CSP header"
                },
                {
                    "risk": "Medium",
                    "name": "Missing X-Frame-Options Header",
                    "description": "Clickjacking may be possible",
                    "url": target_url,
                    "solution": "Add X-Frame-Options header"
                },
                {
                    "risk": "Low",
                    "name": "Cookie Without Secure Flag",
                    "description": "Cookies are not marked as secure",
                    "url": target_url,
                    "solution": "Set secure flag on all cookies"
                }
            ]
        }
        
        # Add to scan history
        scan_history_entry = {
            "scan_id": scan_id,
            "target_url": target_url,
            "scan_date": current_time,
            "status": "completed",
            "high_alerts": scan_results["summary"]["high_alerts"],
            "medium_alerts": scan_results["summary"]["medium_alerts"],
            "low_alerts": scan_results["summary"]["low_alerts"]
        }
        
        # Add to the global scan history
        scan_history.insert(0, scan_history_entry)  # Add at the beginning of the list
        
        # Store full scan results for later report download
        scan_results_store[scan_id] = scan_results
        
        # In a real implementation, you would store scan results in a database
        
        return jsonify({
            "message": "Scan completed successfully",
            "scan_id": scan_results["scan_id"],
            "scan_date": scan_results["scan_date"],
            "results": scan_results
        }), 200
        
    except Exception as e:
        print(f"Error during ZAP scan: {str(e)}")
        
        # Add failed scan to history
        failed_scan = {
            "scan_id": f"scan_{int(datetime.datetime.now().timestamp())}",
            "target_url": target_url,
            "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "failed",
            "error": str(e)
        }
        scan_history.insert(0, failed_scan)
        
        return jsonify({'message': 'Error during scan', 'error': str(e)}), 500

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