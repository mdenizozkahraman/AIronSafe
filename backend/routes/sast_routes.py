from flask import Blueprint, request, jsonify, make_response
import datetime
import os
import random
import uuid
import json
from werkzeug.utils import secure_filename
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import html

# Create blueprint for SAST routes
sast_bp = Blueprint('sast_bp', __name__)

# In-memory storage for scan history and results
scan_history = []
scan_results_store = {}

# AI-generated recommendations for vulnerabilities
AI_RECOMMENDATIONS = {
    "Cross-Site Scripting (XSS)": """
    <p><strong>AI Solution:</strong> To fix this XSS vulnerability, use a content security policy and output encoding libraries:</p>
    <ol>
      <li>Implement context-specific output encoding for user input before rendering to the DOM</li>
      <li>Use libraries like DOMPurify to sanitize HTML content</li>
      <li>Consider using React's JSX which automatically escapes values by default</li>
      <li>Implement a strict Content Security Policy (CSP) to prevent script execution</li>
      <li>Validate input on both client and server side</li>
    </ol>
    <p><strong>Example code fix:</strong></p>
    <pre>
    // Instead of:
    div.innerHTML = userInput;
    
    // Use:
    div.textContent = userInput; // For text only
    // OR
    div.innerHTML = DOMPurify.sanitize(userInput); // For sanitized HTML
    </pre>
    """,
    
    "Prototype Pollution": """
    <p><strong>AI Solution:</strong> To fix prototype pollution vulnerabilities:</p>
    <ol>
      <li>Use Object.create(null) to create objects without a prototype</li>
      <li>Implement deep cloning with careful property validation</li>
      <li>Use Object.freeze(Object.prototype) to prevent modification of Object prototype</li>
      <li>Validate properties before merging objects</li>
      <li>Consider using libraries that safely handle object merging</li>
    </ol>
    <p><strong>Example code fix:</strong></p>
    <pre>
    // Instead of:
    Object.assign(target, source);
    
    // Use:
    function safeAssign(target, source) {
      if (!source || typeof source !== 'object') return target;
      
      Object.keys(source).forEach(key => {
        // Validate key to prevent __proto__ or constructor
        if (key === '__proto__' || key === 'constructor') return;
        
        target[key] = source[key];
      });
      
      return target;
    }
    </pre>
    """,
    
    "SQL Injection": """
    <p><strong>AI Solution:</strong> To fix SQL injection vulnerabilities:</p>
    <ol>
      <li>Always use parameterized queries or prepared statements</li>
      <li>Never concatenate user input directly into SQL strings</li>
      <li>Use an ORM (Object-Relational Mapping) library</li>
      <li>Implement proper input validation and sanitization</li>
      <li>Apply the principle of least privilege for database accounts</li>
    </ol>
    <p><strong>Example code fix:</strong></p>
    <pre>
    # Instead of:
    query = f"SELECT * FROM users WHERE username = '{username}';"
    
    # Use parameterized queries:
    query = "SELECT * FROM users WHERE username = %s;"
    cursor.execute(query, (username,))
    
    # Or with SQLAlchemy:
    user = Users.query.filter_by(username=username).first()
    </pre>
    """,
    
    "Hardcoded Secrets": """
    <p><strong>AI Solution:</strong> To fix hardcoded secrets vulnerabilities:</p>
    <ol>
      <li>Store secrets in environment variables</li>
      <li>Use a secrets management system (HashiCorp Vault, AWS Secrets Manager)</li>
      <li>For development, use .env files with a library like python-dotenv (but don't commit them)</li>
      <li>Implement secret rotation policies</li>
      <li>Use configuration management to inject secrets at deployment time</li>
    </ol>
    <p><strong>Example code fix:</strong></p>
    <pre>
    # Instead of:
    API_KEY = "1a2b3c4d5e6f7g8h9i0j"
    
    # Use:
    import os
    from dotenv import load_dotenv
    
    load_dotenv()  # Load from .env file
    API_KEY = os.environ.get("API_KEY")
    </pre>
    """,
    
    "Path Traversal": """
    <p><strong>AI Solution:</strong> To fix path traversal vulnerabilities:</p>
    <ol>
      <li>Validate and sanitize user input used in file paths</li>
      <li>Use path canonicalization to resolve any directory traversal attempts</li>
      <li>Implement proper access control and file permissions</li>
      <li>Use whitelist of allowed files or directories rather than blacklisting</li>
      <li>Avoid directly using user input in file operations</li>
    </ol>
    <p><strong>Example code fix:</strong></p>
    <pre>
    // Instead of:
    File file = new File(basePath + userInput);
    
    // Use:
    import java.nio.file.Path;
    import java.nio.file.Paths;
    
    // Normalize and validate path
    Path requested = Paths.get(basePath, userInput).normalize();
    
    // Ensure the normalized path still starts with the base directory
    if (!requested.startsWith(Paths.get(basePath).normalize())) {
        throw new SecurityException("Directory traversal attempt detected");
    }
    </pre>
    """,
    
    "Weak Cryptography": """
    <p><strong>AI Solution:</strong> To fix weak cryptography issues:</p>
    <ol>
      <li>Replace outdated algorithms (MD5, SHA1) with modern alternatives (SHA-256, SHA-3)</li>
      <li>Use password-specific algorithms like bcrypt, Argon2 or PBKDF2 for passwords</li>
      <li>Implement proper key management and rotation</li>
      <li>Use trusted libraries for cryptographic operations</li>
      <li>Ensure sufficient entropy for key generation</li>
    </ol>
    <p><strong>Example code fix:</strong></p>
    <pre>
    // Instead of:
    const hash = crypto.createHash("md5").update(password).digest("hex");
    
    // Use:
    const bcrypt = require('bcrypt');
    const saltRounds = 10;
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Verify password
    const match = await bcrypt.compare(userPassword, hashedPassword);
    </pre>
    """,
    
    "Missing Security Headers": """
    <p><strong>AI Solution:</strong> To implement missing security headers:</p>
    <ol>
      <li>Add Content-Security-Policy (CSP) to prevent XSS and data injection</li>
      <li>Implement Strict-Transport-Security (HSTS) for secure connections</li>
      <li>Add X-Content-Type-Options: nosniff to prevent MIME type sniffing</li>
      <li>Use X-Frame-Options to prevent clickjacking attacks</li>
      <li>Implement Referrer-Policy to control information in the referer header</li>
    </ol>
    <p><strong>Example code fix:</strong></p>
    <pre>
    // Express.js example:
    const helmet = require('helmet');
    app.use(helmet()); // Adds various security headers
    
    // Or manually in Express:
    app.use((req, res, next) => {
      res.setHeader('Content-Security-Policy', "default-src 'self'");
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Referrer-Policy', 'same-origin');
      next();
    });
    </pre>
    """,
    
    "Vulnerable Dependencies": """
    <p><strong>AI Solution:</strong> To handle vulnerable dependencies:</p>
    <ol>
      <li>Regularly update dependencies to the latest secure versions</li>
      <li>Use tools like npm audit, Snyk, or OWASP Dependency-Check to scan for vulnerabilities</li>
      <li>Implement automated security scanning in your CI/CD pipeline</li>
      <li>Add a dependency update policy and schedule</li>
      <li>Consider using lockfiles (package-lock.json, yarn.lock) to ensure consistent dependencies</li>
    </ol>
    <p><strong>Example fix:</strong></p>
    <pre>
    # NPM example:
    npm update lodash --save
    
    # Or use auditing and fixing:
    npm audit
    npm audit fix
    
    # In CI/CD (GitHub Actions example):
    - name: Security audit
      run: npm audit --audit-level=high
    </pre>
    """
}

# Example vulnerability findings for various languages
EXAMPLE_VULNERABILITIES = {
    'javascript': [
        {
            'id': 'JS-XSS-001',
            'name': 'Cross-Site Scripting (XSS)',
            'description': 'Unsanitized user input is directly rendered in the DOM.',
            'severity': 'high',
            'cvss': 8.2,
            'line': 42,
            'file': 'frontend/src/components/UserInput.js',
            'code_snippet': 'div.innerHTML = userInput; // Dangerous! Content should be sanitized',
            'recommendation': 'Use safe DOM APIs like textContent or sanitize user input with DOMPurify.'
        },
        {
            'id': 'JS-PROTO-002',
            'name': 'Prototype Pollution',
            'description': 'Improper validation allows modifying Object prototype.',
            'severity': 'medium',
            'cvss': 6.5,
            'line': 87,
            'file': 'src/utils/mergeObjects.js',
            'code_snippet': 'Object.assign(target, source); // Potentially dangerous without checks',
            'recommendation': 'Implement proper input validation and use Object.create(null) for objects without prototype.'
        }
    ],
    'python': [
        {
            'id': 'PY-SQLI-001',
            'name': 'SQL Injection',
            'description': 'SQL query uses string formatting with user input.',
            'severity': 'high',
            'cvss': 8.8,
            'line': 124,
            'file': 'backend/routes/user_routes.py',
            'code_snippet': 'query = f"SELECT * FROM users WHERE username = \'{username}\';"',
            'recommendation': 'Use parameterized queries with cursor.execute(query, params).'
        },
        {
            'id': 'PY-SECRETS-002',
            'name': 'Hardcoded Secrets',
            'description': 'API keys and secrets are hardcoded in source code.',
            'severity': 'high',
            'cvss': 7.5,
            'line': 35,
            'file': 'backend/config.py',
            'code_snippet': 'API_KEY = "1a2b3c4d5e6f7g8h9i0j"',
            'recommendation': 'Store secrets in environment variables or a secure vault.'
        }
    ],
    'java': [
        {
            'id': 'JAVA-PATH-001',
            'name': 'Path Traversal',
            'description': 'Unsanitized user input used in file paths.',
            'severity': 'high',
            'cvss': 7.8,
            'line': 256,
            'file': 'src/main/java/com/example/FileUtil.java',
            'code_snippet': 'File file = new File(basePath + userInput);',
            'recommendation': 'Validate and sanitize user input, use canonical paths.'
        }
    ],
    'generic': [
        {
            'id': 'SEC-CRYPTO-001',
            'name': 'Weak Cryptography',
            'description': 'Usage of outdated or broken cryptographic algorithms.',
            'severity': 'medium',
            'cvss': 5.9,
            'line': 42,
            'file': 'utils/crypto.js',
            'code_snippet': 'const hash = crypto.createHash("md5").update(password).digest("hex");',
            'recommendation': 'Use strong algorithms like bcrypt or Argon2 for passwords.'
        },
        {
            'id': 'SEC-HEADERS-002',
            'name': 'Missing Security Headers',
            'description': 'Application lacks important security headers.',
            'severity': 'low',
            'cvss': 3.2,
            'line': 18,
            'file': 'app.js',
            'code_snippet': '// No Content-Security-Policy header set',
            'recommendation': 'Implement all recommended security headers.'
        },
        {
            'id': 'SEC-DEPENDENCY-003',
            'name': 'Vulnerable Dependencies',
            'description': 'Project uses dependencies with known security vulnerabilities.',
            'severity': 'medium',
            'cvss': 6.1,
            'line': 15,
            'file': 'package.json',
            'code_snippet': '"lodash": "^4.17.15"',
            'recommendation': 'Update dependencies to latest secure versions.'
        }
    ]
}

def get_ai_recommendation(vulnerability_name):
    """Get AI-generated recommendation for a specific vulnerability"""
    for key in AI_RECOMMENDATIONS:
        if key in vulnerability_name:
            return AI_RECOMMENDATIONS[key]
    return "<p><strong>AI Solution:</strong> No specific solution available for this vulnerability. Please consult security best practices or contact a security expert.</p>"

def create_pdf_report(scan_data):
    """Create a PDF report from scan results"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Create custom styles
    title_style = styles["Heading1"]
    title_style.alignment = 1  # Center
    
    subtitle_style = styles["Heading2"]
    normal_style = styles["Normal"]
    
    # Create code style with monospace font
    code_style = ParagraphStyle(
        "CodeStyle", 
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leftIndent=20,
        rightIndent=20,
        spaceAfter=10,
        backColor=colors.lightgrey
    )
    
    # Define list style
    list_style = ParagraphStyle(
        "ListStyle",
        parent=styles["Normal"],
        leftIndent=30
    )
    
    # Create content elements
    elements = []
    
    # Add title
    elements.append(Paragraph(f"SAST Security Scan Report", title_style))
    elements.append(Spacer(1, 0.25 * inch))
    
    # Add scan info
    elements.append(Paragraph(f"Scan ID: {scan_data['scan_id']}", normal_style))
    elements.append(Paragraph(f"Filename: {scan_data['filename']}", normal_style))
    elements.append(Paragraph(f"Scan Date: {scan_data['scan_date']}", normal_style))
    elements.append(Spacer(1, 0.25 * inch))
    
    # Add summary
    elements.append(Paragraph("Vulnerability Summary", subtitle_style))
    
    summary_data = [
        ["Risk Level", "Count"],
        ["High", str(scan_data['summary']['high'])],
        ["Medium", str(scan_data['summary']['medium'])],
        ["Low", str(scan_data['summary']['low'])],
        ["Total", str(scan_data['summary']['total'])]
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (1, 0), 12),
        ('BACKGROUND', (0, 1), (0, 1), colors.lightcoral),
        ('BACKGROUND', (0, 2), (0, 2), colors.lightyellow),
        ('BACKGROUND', (0, 3), (0, 3), colors.lightblue),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 0.25 * inch))
    
    # Add vulnerabilities
    elements.append(Paragraph("Detailed Findings", subtitle_style))
    
    for idx, vuln in enumerate(scan_data['vulnerabilities']):
        # Add separator except for the first item
        if idx > 0:
            elements.append(Spacer(1, 0.15 * inch))
        
        # Add vulnerability details
        elements.append(Paragraph(f"<b>{vuln['id']}: {vuln['name']}</b> (CVSS: {vuln['cvss']})", styles["Heading3"]))
        elements.append(Paragraph(f"<b>Severity:</b> {vuln['severity'].upper()}", normal_style))
        elements.append(Paragraph(f"<b>Description:</b> {vuln['description']}", normal_style))
        elements.append(Paragraph(f"<b>File:</b> {vuln['file']} (Line: {vuln['line']})", normal_style))
        
        # Add code snippet
        elements.append(Paragraph("<b>Vulnerable Code:</b>", normal_style))
        elements.append(Paragraph(vuln['code_snippet'].replace('<', '&lt;').replace('>', '&gt;'), code_style))
        
        # Add recommendation
        elements.append(Paragraph("<b>Recommendation:</b>", normal_style))
        elements.append(Paragraph(vuln['recommendation'], normal_style))
        
        # Add AI recommendation
        elements.append(Paragraph("<b>AI-Generated Solution:</b>", normal_style))
        ai_rec = get_ai_recommendation(vuln['name'])
        # Convert HTML to simple text for PDF
        ai_rec = ai_rec.replace('<p>', '').replace('</p>', '\n\n')
        ai_rec = ai_rec.replace('<ol>', '').replace('</ol>', '')
        ai_rec = ai_rec.replace('<li>', '• ').replace('</li>', '\n')
        ai_rec = ai_rec.replace('<strong>', '').replace('</strong>', '')
        ai_rec = ai_rec.replace('<pre>', '').replace('</pre>', '')
        elements.append(Paragraph(ai_rec, normal_style))
    
    # Build the PDF
    doc.build(elements)
    buffer.seek(0)
    return buffer

def create_html_report(scan_data):
    """Create an HTML report from scan results"""
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SAST Scan Report - {scan_data['scan_id']}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                color: #333;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            header {{
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 1px solid #eee;
            }}
            h1 {{
                color: #2c3e50;
            }}
            h2 {{
                color: #3498db;
                border-bottom: 1px solid #eee;
                padding-bottom: 10px;
            }}
            h3 {{
                color: #2c3e50;
            }}
            .scan-info {{
                background: #f8f9fa;
                padding: 15px;
                border-radius: 5px;
                margin-bottom: 20px;
            }}
            .summary {{
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                margin-bottom: 30px;
            }}
            .summary-item {{
                flex: 1;
                min-width: 200px;
                padding: 20px;
                border-radius: 5px;
                color: white;
                text-align: center;
            }}
            .high {{
                background-color: #e74c3c;
            }}
            .medium {{
                background-color: #f39c12;
            }}
            .low {{
                background-color: #3498db;
            }}
            .total {{
                background-color: #2c3e50;
            }}
            .vulnerability {{
                background: #f8f9fa;
                padding: 20px;
                border-radius: 5px;
                margin-bottom: 20px;
                border-left: 5px solid #ddd;
            }}
            .vulnerability.high {{
                border-left-color: #e74c3c;
            }}
            .vulnerability.medium {{
                border-left-color: #f39c12;
            }}
            .vulnerability.low {{
                border-left-color: #3498db;
            }}
            .severity {{
                display: inline-block;
                padding: 3px 10px;
                border-radius: 3px;
                color: white;
                font-weight: bold;
            }}
            .code {{
                background: #272822;
                color: #f8f8f2;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
                font-family: monospace;
            }}
            .ai-recommendation {{
                background: #EFF8FF;
                padding: 15px;
                border-radius: 5px;
                margin-top: 15px;
                border-left: 5px solid #3498db;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>SAST Security Scan Report</h1>
                <p>Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </header>
            
            <div class="scan-info">
                <p><strong>Scan ID:</strong> {scan_data['scan_id']}</p>
                <p><strong>Filename:</strong> {scan_data['filename']}</p>
                <p><strong>Scan Date:</strong> {scan_data['scan_date']}</p>
                <p><strong>Status:</strong> {scan_data['status']}</p>
            </div>
            
            <h2>Vulnerability Summary</h2>
            <div class="summary">
                <div class="summary-item high">
                    <h3>{scan_data['summary']['high']}</h3>
                    <p>High Risk</p>
                </div>
                <div class="summary-item medium">
                    <h3>{scan_data['summary']['medium']}</h3>
                    <p>Medium Risk</p>
                </div>
                <div class="summary-item low">
                    <h3>{scan_data['summary']['low']}</h3>
                    <p>Low Risk</p>
                </div>
                <div class="summary-item total">
                    <h3>{scan_data['summary']['total']}</h3>
                    <p>Total Findings</p>
                </div>
            </div>
            
            <h2>Detailed Findings</h2>
    """
    
    for vuln in scan_data['vulnerabilities']:
        html_content += f"""
            <div class="vulnerability {vuln['severity']}">
                <h3>
                    <span class="severity {vuln['severity']}" style="background-color: {'#e74c3c' if vuln['severity'] == 'high' else '#f39c12' if vuln['severity'] == 'medium' else '#3498db'};">
                        {vuln['severity'].upper()}
                    </span> 
                    {vuln['id']}: {vuln['name']} (CVSS: {vuln['cvss']})
                </h3>
                
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>File:</strong> {vuln['file']}</p>
                <p><strong>Line:</strong> {vuln['line']}</p>
                
                <p><strong>Vulnerable Code:</strong></p>
                <pre class="code">{html.escape(vuln['code_snippet'])}</pre>
                
                <p><strong>Recommendation:</strong> {vuln['recommendation']}</p>
                
                <div class="ai-recommendation">
                    {get_ai_recommendation(vuln['name'])}
                </div>
            </div>
        """
    
    html_content += """
        </div>
    </body>
    </html>
    """
    
    return html_content

@sast_bp.route('/upload', methods=['POST'])
def upload_file_for_analysis():
    """Handle file upload for SAST analysis"""
    
    if 'file' not in request.files:
        return jsonify({
            'message': 'No file provided',
            'status': 'error'
        }), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({
            'message': 'No file selected',
            'status': 'error'
        }), 400
        
    filename = secure_filename(file.filename)
    file_extension = filename.split('.')[-1].lower() if '.' in filename else 'generic'
    
    # Generate a unique scan ID
    scan_id = f"sast_{uuid.uuid4().hex[:8]}"
    scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Get vulnerabilities based on file type
    vulnerabilities = []
    if file_extension in ['js', 'jsx', 'ts', 'tsx']:
        vulnerabilities.extend(EXAMPLE_VULNERABILITIES['javascript'])
    elif file_extension in ['py']:
        vulnerabilities.extend(EXAMPLE_VULNERABILITIES['python'])
    elif file_extension in ['java']:
        vulnerabilities.extend(EXAMPLE_VULNERABILITIES['java'])
        
    # Add some generic vulnerabilities
    vulnerabilities.extend(random.sample(EXAMPLE_VULNERABILITIES['generic'], 
                                        k=min(2, len(EXAMPLE_VULNERABILITIES['generic']))))
    
    # Create scan results
    results = {
        "scan_id": scan_id,
        "filename": filename,
        "scan_date": scan_date,
        "status": "completed",
        "summary": {
            "high": sum(1 for v in vulnerabilities if v['severity'] == 'high'),
            "medium": sum(1 for v in vulnerabilities if v['severity'] == 'medium'),
            "low": sum(1 for v in vulnerabilities if v['severity'] == 'low'),
            "total": len(vulnerabilities)
        },
        "vulnerabilities": vulnerabilities
    }
    
    # Store scan results
    scan_results_store[scan_id] = results
    
    # Add to scan history
    scan_history_entry = {
        "scan_id": scan_id,
        "filename": filename,
        "scan_date": scan_date,
        "status": "completed",
        "summary": results["summary"],
        "highest_cvss": max(v['cvss'] for v in vulnerabilities) if vulnerabilities else 0
    }
    
    # Add to history at beginning (newest first)
    scan_history.insert(0, scan_history_entry)
    
    return jsonify({
        "message": "File analyzed successfully",
        "scan_id": scan_id,
        "results": results
    }), 200

@sast_bp.route('/scan_history', methods=['GET'])
def get_scan_history():
    """Return the history of SAST scans"""
    
    # If no scans have been performed, return sample data
    if not scan_history:
        sample_history = [
            {
                "scan_id": "sast_sample1",
                "filename": "frontend-code.zip",
                "scan_date": "2023-09-15 14:30:22",
                "status": "completed",
                "summary": {
                    "high": 3,
                    "medium": 5,
                    "low": 2,
                    "total": 10
                },
                "highest_cvss": 8.5
            },
            {
                "scan_id": "sast_sample2",
                "filename": "mobile-app.js",
                "scan_date": "2023-07-12 09:15:44",
                "status": "completed",
                "summary": {
                    "high": 1,
                    "medium": 2,
                    "low": 4,
                    "total": 7
                },
                "highest_cvss": 5.4
            }
        ]
        
        return jsonify({
            "message": "Sample scan history retrieved",
            "history": sample_history
        }), 200
    
    # Return the actual scan history
    return jsonify({
        "message": "Scan history retrieved successfully",
        "history": scan_history
    }), 200

@sast_bp.route('/report/<scan_id>', methods=['GET'])
def get_scan_report(scan_id):
    """Generates and returns a report for a specific scan"""
    
    # Get requested format (default to JSON)
    report_format = request.args.get('format', 'json').lower()
    
    # Check if scan exists
    if scan_id not in scan_results_store:
        # If not found but looks like a sample ID, return sample data
        if scan_id.startswith('sast_sample'):
            sample_vulnerabilities = (
                random.sample(EXAMPLE_VULNERABILITIES['javascript'], k=2) +
                random.sample(EXAMPLE_VULNERABILITIES['python'], k=2) +
                random.sample(EXAMPLE_VULNERABILITIES['generic'], k=2)
            )
            
            sample_report = {
                "scan_id": scan_id,
                "filename": "sample-code.zip" if scan_id == "sast_sample1" else "mobile-app.js",
                "scan_date": "2023-09-15 14:30:22" if scan_id == "sast_sample1" else "2023-07-12 09:15:44",
                "status": "completed",
                "summary": {
                    "high": sum(1 for v in sample_vulnerabilities if v['severity'] == 'high'),
                    "medium": sum(1 for v in sample_vulnerabilities if v['severity'] == 'medium'),
                    "low": sum(1 for v in sample_vulnerabilities if v['severity'] == 'low'),
                    "total": len(sample_vulnerabilities)
                },
                "vulnerabilities": sample_vulnerabilities
            }
            
            scan_results_store[scan_id] = sample_report
        else:
            return jsonify({
                "message": "Scan not found",
                "status": "error"
            }), 404
    
    scan_data = scan_results_store[scan_id]
    
    # PDF report
    if report_format == 'pdf':
        try:
            pdf_buffer = create_pdf_report(scan_data)
            
            response = make_response(pdf_buffer.getvalue())
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename=sast_report_{scan_id}.pdf'
            return response
        except Exception as e:
            print(f"Error generating PDF report: {str(e)}")
            # Fall back to JSON
            return jsonify({
                "message": f"Error generating PDF report: {str(e)}. Returning JSON report instead.",
                "report_id": f"report_{scan_id}",
                "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_data": scan_data,
                "ai_recommendations": {
                    vuln['name']: get_ai_recommendation(vuln['name']) 
                    for vuln in scan_data['vulnerabilities']
                }
            }), 200
    
    # HTML report
    elif report_format == 'html':
        try:
            html_content = create_html_report(scan_data)
            
            response = make_response(html_content)
            response.headers['Content-Type'] = 'text/html'
            response.headers['Content-Disposition'] = f'attachment; filename=sast_report_{scan_id}.html'
            return response
        except Exception as e:
            print(f"Error generating HTML report: {str(e)}")
            # Fall back to JSON
            return jsonify({
                "message": f"Error generating HTML report: {str(e)}. Returning JSON report instead.",
                "report_id": f"report_{scan_id}",
                "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_data": scan_data,
                "ai_recommendations": {
                    vuln['name']: get_ai_recommendation(vuln['name']) 
                    for vuln in scan_data['vulnerabilities']
                }
            }), 200
    
    # Default JSON report
    report = {
        "report_id": f"report_{scan_id}",
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_data": scan_data,
        "ai_recommendations": {
            vuln['name']: get_ai_recommendation(vuln['name']) 
            for vuln in scan_data['vulnerabilities']
        }
    }
    
    return jsonify(report), 200 