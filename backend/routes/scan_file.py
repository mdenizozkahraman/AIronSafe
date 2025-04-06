import os
import json
import datetime

def simple_scan_file(file_path, output_json_path):
    """A simple security scanner that checks a file for common vulnerabilities and saves results as JSON"""
    try:
        print(f"Running simple scan on {file_path}, saving results to {output_json_path}")
        vulnerabilities = []
        
        with open(file_path, 'r') as f:
            content = f.read()
            lines = content.split('\n')
        
        # Define patterns to look for
        patterns = [
            {
                'pattern': 'os.system(',
                'name': 'Command Injection Risk',
                'description': 'Direct use of os.system() can lead to command injection vulnerabilities if user input is not properly sanitized.',
                'severity': 'high',
                'cvss': 8.5,
                'recommendation': 'Use subprocess module with shell=False, or properly sanitize input.'
            },
            {
                'pattern': 'subprocess.call(',
                'name': 'Potential Command Injection',
                'description': 'Using subprocess.call can be dangerous if shell=True is specified or if user input is included.',
                'severity': 'medium',
                'cvss': 6.8,
                'recommendation': 'Use subprocess with shell=False and pass arguments as a list.'
            },
            {
                'pattern': 'eval(',
                'name': 'Code Injection Risk',
                'description': 'Using eval() can lead to arbitrary code execution if user input is included.',
                'severity': 'high',
                'cvss': 9.2,
                'recommendation': 'Avoid using eval() for user-supplied input. Use safer alternatives.'
            },
            {
                'pattern': 'exec(',
                'name': 'Code Injection Risk',
                'description': 'Using exec() can lead to arbitrary code execution if user input is included.',
                'severity': 'high',
                'cvss': 9.2,
                'recommendation': 'Avoid using exec() for user-supplied input. Use safer alternatives.'
            },
            {
                'pattern': 'pickle.load',
                'name': 'Insecure Deserialization',
                'description': 'Unpickling data from untrusted sources can lead to remote code execution.',
                'severity': 'high',
                'cvss': 8.8,
                'recommendation': 'Avoid using pickle for untrusted data. Consider JSON or more secure serialization methods.'
            },
            {
                'pattern': 'md5',
                'name': 'Weak Cryptography',
                'description': 'MD5 is a cryptographically broken algorithm and should not be used for security purposes.',
                'severity': 'medium',
                'cvss': 5.9,
                'recommendation': 'Use secure hashing algorithms like SHA-256 or bcrypt for passwords.'
            },
            {
                'pattern': 'sha1',
                'name': 'Weak Cryptography',
                'description': 'SHA1 is a cryptographically broken algorithm and should not be used for security purposes.',
                'severity': 'medium',
                'cvss': 5.7,
                'recommendation': 'Use secure hashing algorithms like SHA-256 or bcrypt for passwords.'
            },
            {
                'pattern': 'SELECT',
                'name': 'Potential SQL Injection',
                'description': 'SQL statements constructed with user input can lead to SQL injection attacks.',
                'severity': 'high',
                'cvss': 8.5,
                'recommendation': 'Use parameterized queries or an ORM instead of string concatenation.'
            },
            {
                'pattern': 'verify=False',
                'name': 'SSL Certificate Validation Disabled',
                'description': 'Disabling SSL certificate validation can lead to man-in-the-middle attacks.',
                'severity': 'medium',
                'cvss': 6.5,
                'recommendation': 'Always validate SSL certificates in production. Fix certificate issues instead of bypassing validation.'
            },
            {
                'pattern': 'yaml.load(',
                'name': 'Unsafe YAML Loading',
                'description': 'Using yaml.load() can lead to arbitrary code execution with maliciously crafted YAML.',
                'severity': 'high',
                'cvss': 8.0,
                'recommendation': 'Use yaml.safe_load() instead to prevent code execution.'
            },
            {
                'pattern': 'password',
                'name': 'Potential Hardcoded Password',
                'description': 'Hardcoded passwords can lead to unauthorized access if code is leaked.',
                'severity': 'medium',
                'cvss': 6.5,
                'recommendation': 'Store passwords in environment variables or a secure credential store.'
            },
            {
                'pattern': 'api_key',
                'name': 'Potential Hardcoded API Key',
                'description': 'Hardcoded API keys can lead to unauthorized access if code is leaked.',
                'severity': 'medium',
                'cvss': 6.5,
                'recommendation': 'Store API keys in environment variables or a secure credential store.'
            }
        ]
        
        # Scan for vulnerabilities
        for pattern_data in patterns:
            pattern = pattern_data['pattern']
            pattern_lower = pattern.lower()
            
            for i, line in enumerate(lines):
                line_lower = line.lower()
                if pattern_lower in line_lower:
                    # Create a vulnerability entry
                    vuln_id = f"CUSTOM-{len(vulnerabilities) + 1}"
                    context_start = max(0, i - 2)
                    context_end = min(len(lines), i + 3)
                    code_context = '\n'.join(lines[context_start:context_end])
                    
                    vuln = {
                        'id': vuln_id,
                        'name': pattern_data['name'],
                        'description': pattern_data['description'],
                        'severity': pattern_data['severity'],
                        'cvss': pattern_data['cvss'],
                        'line': i + 1,  # 1-indexed line number
                        'file': os.path.basename(file_path),
                        'code_snippet': code_context,
                        'recommendation': pattern_data['recommendation']
                    }
                    vulnerabilities.append(vuln)
        
        # Create results data
        results = {
            "results": [
                {
                    "check_id": vuln["name"],
                    "path": vuln["file"],
                    "start": {
                        "line": vuln["line"],
                        "col": 1
                    },
                    "end": {
                        "line": vuln["line"],
                        "col": 100
                    },
                    "extra": {
                        "message": vuln["description"],
                        "severity": "ERROR" if vuln["severity"] == "high" else "WARNING",
                        "lines": vuln["code_snippet"]
                    }
                }
                for vuln in vulnerabilities
            ],
            "errors": [],
            "paths": {
                "scanned": [file_path]
            },
            "summary": {
                "findings": len(vulnerabilities),
                "errors": 0
            },
            "version": "1.0.0",
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Write results to file
        with open(output_json_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"Found {len(vulnerabilities)} vulnerabilities. Results saved to {output_json_path}")
        return vulnerabilities
    
    except Exception as e:
        print(f"Error in simple_scan: {str(e)}")
        return []

# Allow running as a standalone script
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else "result.json"
        simple_scan_file(input_file, output_file) 