import re
import requests
from urllib.parse import urlparse
import os

def scan_url(url):
    """Basic URL safety scan"""
    try:
        # Validate URL format
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return {
                'safe': False,
                'message': 'Invalid URL format',
                'risk_level': 'high'
            }
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'bit\.ly', r'tinyurl', r'shortened',  # URL shorteners
            r'phishing', r'malware', r'virus',     # Obvious bad words
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return {
                    'safe': False,
                    'message': f'Suspicious pattern detected: {pattern}',
                    'risk_level': 'medium'
                }
        
        # Try to fetch headers (basic connectivity check)
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code >= 400:
                return {
                    'safe': False,
                    'message': f'HTTP error: {response.status_code}',
                    'risk_level': 'medium'
                }
        except requests.RequestException:
            return {
                'safe': False,
                'message': 'Unable to connect to URL',
                'risk_level': 'medium'
            }
        
        return {
            'safe': True,
            'message': 'URL appears safe (basic checks passed)',
            'risk_level': 'low'
        }
        
    except Exception as e:
        return {
            'safe': False,
            'message': f'Scan error: {str(e)}',
            'risk_level': 'unknown'
        }

def scan_file_for_malware(file_path):
    """Basic file malware scan using signatures"""
    try:
        # Malware signatures (basic examples)
        malware_signatures = [
            b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',  # EICAR test string
            b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR',  # EICAR alternative
        ]
        
        # Suspicious file extensions
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif']
        
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # Check file extension
        if file_ext in suspicious_extensions:
            return {
                'clean': False,
                'message': f'Suspicious file extension: {file_ext}',
                'risk_level': 'high'
            }
        
        # Read file and check for signatures
        with open(file_path, 'rb') as f:
            content = f.read()
        
        for signature in malware_signatures:
            if signature in content:
                return {
                    'clean': False,
                    'message': 'Known malware signature detected',
                    'risk_level': 'high'
                }
        
        # Check file size (suspiciously large files)
        file_size = os.path.getsize(file_path)
        if file_size > 100 * 1024 * 1024:  # 100MB
            return {
                'clean': True,
                'message': 'File is large but no threats detected',
                'risk_level': 'low'
            }
        
        return {
            'clean': True,
            'message': 'No threats detected (basic scan)',
            'risk_level': 'low'
        }
        
    except Exception as e:
        return {
            'clean': False,
            'message': f'Scan error: {str(e)}',
            'risk_level': 'unknown'
        }

def vulnerability_scan(url):
    """Basic vulnerability scan for common web vulnerabilities"""
    try:
        vulnerabilities = []
        
        # Test for SQL Injection (basic)
        sqli_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users; --"]
        
        for payload in sqli_payloads:
            test_url = f"{url}?id={payload}"
            try:
                response = requests.get(test_url, timeout=5)
                if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax error', 'database']):
                    vulnerabilities.append('Potential SQL Injection')
                    break
            except:
                pass
        
        # Test for XSS (basic)
        xss_payload = "<script>alert('XSS')</script>"
        try:
            test_url = f"{url}?search={xss_payload}"
            response = requests.get(test_url, timeout=5)
            if xss_payload in response.text:
                vulnerabilities.append('Potential XSS')
        except:
            pass
        
        # Check for common security headers
        try:
            response = requests.head(url, timeout=5)
            headers = response.headers
            
            security_headers = [
                'X-Frame-Options',
                'X-XSS-Protection',
                'X-Content-Type-Options',
                'Strict-Transport-Security'
            ]
            
            missing_headers = [h for h in security_headers if h not in headers]
            if missing_headers:
                vulnerabilities.append(f'Missing security headers: {", ".join(missing_headers)}')
        except:
            pass
        
        risk_level = 'high' if len(vulnerabilities) > 2 else 'medium' if vulnerabilities else 'low'
        
        return {
            'vulnerabilities': vulnerabilities,
            'risk_level': risk_level,
            'message': f'Found {len(vulnerabilities)} potential issues'
        }
        
    except Exception as e:
        return {
            'vulnerabilities': [],
            'risk_level': 'unknown',
            'message': f'Scan error: {str(e)}'
        }
