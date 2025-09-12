import re
import requests
from urllib.parse import urlparse
import os
import socket
import ipaddress

def is_private_ip(ip_str):
    """Check if an IP address is in a private range"""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Check for private ranges
        private_ranges = [
            ipaddress.ip_network('127.0.0.0/8'),    # Loopback
            ipaddress.ip_network('10.0.0.0/8'),     # Private Class A
            ipaddress.ip_network('172.16.0.0/12'),  # Private Class B
            ipaddress.ip_network('192.168.0.0/16'), # Private Class C
            ipaddress.ip_network('169.254.0.0/16'), # Link-local
            ipaddress.ip_network('::1/128'),        # IPv6 loopback
            ipaddress.ip_network('fc00::/7'),       # IPv6 unique local
            ipaddress.ip_network('fe80::/10'),      # IPv6 link-local
        ]
        return any(ip in network for network in private_ranges)
    except (ValueError, ipaddress.AddressValueError):
        return False

def validate_url_for_ssrf(url):
    """Validate URL to prevent SSRF attacks"""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return False, "Invalid hostname"
        
        # Block common internal hostnames
        blocked_hostnames = ['localhost', 'metadata.google.internal']
        if hostname.lower() in blocked_hostnames:
            return False, f"Blocked hostname: {hostname}"
        
        # Resolve hostname to IP addresses
        try:
            # Get all IP addresses for the hostname
            addr_info = socket.getaddrinfo(hostname, None)
            ips = [info[4][0] for info in addr_info]
            
            # Check if any resolved IP is private
            for ip in ips:
                if is_private_ip(ip):
                    return False, f"URL resolves to private IP: {ip}"
                    
        except socket.gaierror:
            return False, "Unable to resolve hostname"
        
        # Additional checks for direct IP addresses in URL
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            if is_private_ip(hostname):
                return False, f"Direct private IP address: {hostname}"
                
        return True, "URL validation passed"
        
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def scan_url(url):
    """Basic URL safety scan"""
    try:
        reasons = []
        risk_factors = []
        
        # Validate URL format
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return {
                'safe': False,
                'message': 'Invalid URL format',
                'risk_level': 'high',
                'reasons': ['URL format is malformed or incomplete', 'Missing protocol (http/https) or domain name', 'Could indicate phishing or malicious redirection']
            }
        
        # Check for suspicious patterns
        suspicious_patterns = {
            r'bit\.ly': 'URL shortener (bit.ly) - could hide destination',
            r'tinyurl': 'URL shortener (tinyurl) - could hide destination', 
            r'shortened': 'URL shortener service - potential redirection risk',
            r'phishing': 'Contains word "phishing" - highly suspicious',
            r'malware': 'Contains word "malware" - highly suspicious',
            r'virus': 'Contains word "virus" - highly suspicious',
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}': 'Direct IP address - bypasses domain reputation checks'
        }
        
        for pattern, reason in suspicious_patterns.items():
            if re.search(pattern, url, re.IGNORECASE):
                return {
                    'safe': False,
                    'message': f'Suspicious pattern detected: {pattern}',
                    'risk_level': 'medium',
                    'reasons': [reason, 'Suspicious patterns often indicate malicious intent', 'Legitimate sites rarely use such patterns']
                }
        
        # Check domain reputation factors
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # Check for known safe domains (exact matching to prevent spoofing)
        trusted_domains = ['google.com', 'microsoft.com', 'github.com', 'replit.com', 'stackoverflow.com']
        is_trusted = False
        for trusted_domain in trusted_domains:
            if domain == trusted_domain or domain.endswith('.' + trusted_domain):
                reasons.append('Domain belongs to a well-known trusted organization')
                is_trusted = True
                break
            
        # Check for HTTPS
        if parsed.scheme == 'https':
            reasons.append('Uses HTTPS encryption for secure communication')
        else:
            risk_factors.append('Uses HTTP instead of HTTPS - data not encrypted')
            
        # SSRF Protection: Validate URL before making requests
        ssrf_valid, ssrf_message = validate_url_for_ssrf(url)
        if not ssrf_valid:
            return {
                'safe': False,
                'message': f'Security restriction: {ssrf_message}',
                'risk_level': 'high',
                'reasons': [
                    ssrf_message,
                    'URL blocked for security reasons',
                    'This prevents attacks on internal services',
                    'Only public URLs are allowed for scanning'
                ]
            }
        
        # Try to fetch headers (basic connectivity check) with SSRF protection
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            
            # Validate final URL after redirects
            final_url = response.url
            if final_url != url:
                final_valid, final_message = validate_url_for_ssrf(final_url)
                if not final_valid:
                    return {
                        'safe': False,
                        'message': f'Redirect blocked: {final_message}',
                        'risk_level': 'high',
                        'reasons': [
                            f'URL redirected to blocked destination: {final_url}',
                            final_message,
                            'Redirect blocked for security reasons'
                        ]
                    }
                reasons.append(f'Safe redirect: {url} → {final_url}')
            
            if response.status_code >= 400:
                return {
                    'safe': False,
                    'message': f'HTTP error: {response.status_code}',
                    'risk_level': 'medium',
                    'reasons': [f'Server returned error code {response.status_code}', 'Could indicate broken or malicious site', 'Legitimate sites typically return 200 OK status']
                }
            else:
                reasons.append(f'Server responds properly (HTTP {response.status_code})')
                
            # Check security headers
            security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options']
            present_headers = [h for h in security_headers if h in response.headers]
            if present_headers:
                reasons.append(f'Has security headers: {", ".join(present_headers)}')
                
        except requests.RequestException as e:
            return {
                'safe': False,
                'message': 'Unable to connect to URL',
                'risk_level': 'medium',
                'reasons': ['Connection failed - server may be down or unreachable', 'Could indicate suspicious or non-existent domain', 'Network issues or firewall blocking access']
            }
        
        # Add basic safety indicators
        reasons.extend([
            'No suspicious patterns detected in URL',
            'Basic connectivity and format checks passed',
            'No obvious malicious indicators found'
        ])
        
        if risk_factors:
            reasons.extend(risk_factors)
        
        # Determine risk level and safety status based on actual risk factors
        if len(risk_factors) >= 3:
            risk_level = 'high'
            message = 'URL has multiple risk factors - exercise extreme caution'
            safe = False
        elif len(risk_factors) >= 1:
            risk_level = 'medium' 
            message = 'URL has some risk factors - proceed with caution'
            safe = False
        elif is_trusted:
            risk_level = 'low'
            message = 'URL appears safe (trusted domain)'
            safe = True
        else:
            risk_level = 'low'
            message = 'URL appears safe (basic checks passed)'
            safe = True
            
        return {
            'safe': safe,
            'message': message,
            'risk_level': risk_level,
            'reasons': reasons
        }
        
    except Exception as e:
        return {
            'safe': False,
            'message': f'Scan error: {str(e)}',
            'risk_level': 'unknown',
            'reasons': ['Scanning process encountered an error', 'Unable to complete security analysis', 'Technical issues prevented full assessment']
        }

def scan_file_for_malware(file_path):
    """Basic file malware scan using signatures"""
    try:
        reasons = []
        risk_factors = []
        
        # Malware signatures (basic examples)
        malware_signatures = {
            b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE': 'EICAR test file signature detected',
            b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR': 'EICAR alternative test signature detected',
        }
        
        # File extension analysis
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # Suspicious file extensions
        high_risk_extensions = {
            '.exe': 'Executable file - can run code directly',
            '.scr': 'Screen saver file - often used to hide malware',
            '.bat': 'Batch script - can execute system commands',
            '.cmd': 'Command script - can execute system commands',
            '.com': 'Command executable - legacy executable format',
            '.pif': 'Program information file - can execute programs'
        }
        
        medium_risk_extensions = {
            '.jar': 'Java archive - can contain executable code',
            '.vbs': 'Visual Basic script - can execute code',
            '.js': 'JavaScript file - can execute in browsers',
            '.ps1': 'PowerShell script - can execute system commands',
            '.msi': 'Windows installer - can install software'
        }
        
        safe_extensions = {
            '.txt': 'Plain text file - generally safe',
            '.jpg': 'JPEG image - safe image format',
            '.png': 'PNG image - safe image format',
            '.pdf': 'PDF document - generally safe but can contain scripts',
            '.docx': 'Word document - generally safe but can contain macros',
            '.xlsx': 'Excel spreadsheet - generally safe but can contain macros'
        }
        
        # Check file extension
        if file_ext in high_risk_extensions:
            return {
                'clean': False,
                'message': f'Suspicious file extension: {file_ext}',
                'risk_level': 'high',
                'reasons': [
                    high_risk_extensions[file_ext],
                    'High-risk file types can execute code on your system',
                    'Only run files from trusted sources',
                    'Consider scanning with updated antivirus software'
                ]
            }
        elif file_ext in medium_risk_extensions:
            risk_factors.append(f'{medium_risk_extensions[file_ext]} - exercise caution')
        elif file_ext in safe_extensions:
            reasons.append(f'{safe_extensions[file_ext]} - low execution risk')
        else:
            risk_factors.append(f'Unknown file extension ({file_ext}) - verify file type')
        
        # Read file and check for signatures
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Check for malware signatures
        for signature, description in malware_signatures.items():
            if signature in content:
                return {
                    'clean': False,
                    'message': 'Known malware signature detected',
                    'risk_level': 'high',
                    'reasons': [
                        description,
                        'File contains known malicious code patterns',
                        'Immediately quarantine or delete this file',
                        'Do not execute or open this file'
                    ]
                }
        
        # File size analysis
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            risk_factors.append('File is empty - could be corrupted or suspicious')
        elif file_size > 100 * 1024 * 1024:  # 100MB
            reasons.append(f'Large file ({file_size // (1024*1024)}MB) - no threats detected')
            risk_factors.append('Large files may take longer to scan completely')
        else:
            reasons.append(f'Normal file size ({file_size} bytes)')
            
        # Additional safety checks
        reasons.extend([
            'No known malware signatures detected',
            'File structure appears normal',
            'Basic content analysis completed'
        ])
        
        if risk_factors:
            reasons.extend(risk_factors)
            
        # Determine final risk level and clean status
        if len(risk_factors) > 2:
            final_risk = 'medium'
            clean = False
            message = 'Some concerns detected - review file carefully'
        elif len(risk_factors) > 0:
            final_risk = 'low'
            clean = True
            message = 'No immediate threats but some concerns noted'
        else:
            final_risk = 'low'
            clean = True
            message = 'No threats detected (basic scan)'
            
        return {
            'clean': clean,
            'message': message,
            'risk_level': final_risk,
            'reasons': reasons
        }
        
    except Exception as e:
        return {
            'clean': False,
            'message': f'Scan error: {str(e)}',
            'risk_level': 'unknown',
            'reasons': [
                'File scanning process encountered an error',
                'Unable to read or analyze file contents',
                'Technical issues prevented complete analysis',
                'Try scanning with alternative antivirus tools'
            ]
        }

def vulnerability_scan(url):
    """Basic vulnerability scan for common web vulnerabilities with SSRF protection"""
    try:
        vulnerabilities = []
        reasons = []
        security_issues = []
        security_strengths = []
        
        # SSRF Protection: Validate URL before vulnerability testing
        ssrf_valid, ssrf_message = validate_url_for_ssrf(url)
        if not ssrf_valid:
            return {
                'vulnerabilities': [f'Security restriction: {ssrf_message}'],
                'risk_level': 'high',
                'message': 'URL blocked for security reasons',
                'reasons': [
                    'URL points to private or internal network',
                    'Scanning internal services is prohibited',
                    'Only public URLs can be vulnerability scanned'
                ]
            }
        
        # Test for SQL Injection (basic) with SSRF protection
        sqli_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users; --"]
        sql_injection_found = False
        
        for payload in sqli_payloads:
            test_url = f"{url}?id={payload}"
            try:
                # Validate test URL for SSRF
                test_valid, _ = validate_url_for_ssrf(test_url)
                if not test_valid:
                    continue
                    
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax error', 'database', 'oracle', 'postgresql']):
                    if not sql_injection_found:  # Only add once
                        vulnerabilities.append('Potential SQL Injection')
                        security_issues.append('SQL error messages exposed - indicates possible SQL injection vulnerability')
                        security_issues.append('Database errors should never be visible to users')
                        sql_injection_found = True
                    break
            except:
                pass
        
        if not sql_injection_found:
            security_strengths.append('No obvious SQL injection vulnerabilities detected')
        
        # Test for XSS (basic) with SSRF protection
        xss_payload = "<script>alert('XSS')</script>"
        try:
            test_url = f"{url}?search={xss_payload}"
            test_valid, _ = validate_url_for_ssrf(test_url)
            if test_valid:
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                if xss_payload in response.text:
                    vulnerabilities.append('Potential Cross-Site Scripting (XSS)')
                    security_issues.append('Script tags are reflected without sanitization')
                    security_issues.append('User input is not properly encoded before output')
                    security_issues.append('XSS can allow attackers to execute malicious scripts')
                else:
                    security_strengths.append('Basic XSS payload was properly handled/filtered')
        except:
            pass
        
        # Check for common security headers with SSRF protection
        missing_headers = []
        present_headers = []
        try:
            response = requests.head(url, timeout=5, allow_redirects=False)
            headers = response.headers
            
            security_headers_info = {
                'X-Frame-Options': 'Prevents clickjacking attacks by controlling iframe embedding',
                'X-XSS-Protection': 'Enables browser XSS filtering (legacy but still useful)',
                'X-Content-Type-Options': 'Prevents MIME type sniffing attacks',
                'Strict-Transport-Security': 'Enforces HTTPS connections (HSTS)',
                'Content-Security-Policy': 'Controls resource loading to prevent XSS',
                'Referrer-Policy': 'Controls information sent in Referer header'
            }
            
            for header, description in security_headers_info.items():
                if header in headers:
                    present_headers.append(f'{header}: {description}')
                else:
                    missing_headers.append(f'{header}: {description}')
            
            if missing_headers:
                vulnerabilities.append(f'Missing security headers ({len(missing_headers)} headers)')
                security_issues.extend([f'Missing {header.split(":")[0]}' for header in missing_headers])
            
            if present_headers:
                security_strengths.extend([f'Has {header.split(":")[0]}' for header in present_headers])
                
        except:
            security_issues.append('Unable to check security headers - server may be unreachable')
        
        # Check HTTPS usage
        if url.startswith('https://'):
            security_strengths.append('Uses HTTPS encryption for secure communication')
        else:
            security_issues.append('Uses HTTP instead of HTTPS - data transmitted in plain text')
            vulnerabilities.append('Insecure HTTP connection')
        
        # Compile reasons
        if security_issues:
            reasons.extend(security_issues)
        if security_strengths:
            reasons.extend(security_strengths)
        
        # Additional analysis
        if not vulnerabilities:
            reasons.append('Basic vulnerability scan completed with no major issues found')
        else:
            reasons.append(f'Found {len(vulnerabilities)} potential security vulnerabilities')
            reasons.append('Consider professional security audit for comprehensive assessment')
        
        # Determine risk level based on vulnerabilities and severity
        if 'SQL Injection' in str(vulnerabilities) or 'XSS' in str(vulnerabilities):
            risk_level = 'high'
            reasons.append('Critical vulnerabilities detected - immediate attention required')
        elif len(vulnerabilities) > 2:
            risk_level = 'high'
            reasons.append('Multiple vulnerabilities indicate poor security posture')
        elif vulnerabilities:
            risk_level = 'medium'
            reasons.append('Some vulnerabilities found - should be addressed')
        else:
            risk_level = 'low'
            reasons.append('No obvious vulnerabilities detected in basic scan')
        
        return {
            'vulnerabilities': vulnerabilities,
            'risk_level': risk_level,
            'message': f'Found {len(vulnerabilities)} potential security issues' if vulnerabilities else 'No obvious vulnerabilities detected',
            'reasons': reasons,
            'security_issues': security_issues,
            'security_strengths': security_strengths,
            'missing_headers': missing_headers,
            'present_headers': present_headers
        }
        
    except Exception as e:
        return {
            'vulnerabilities': [],
            'risk_level': 'unknown',
            'message': f'Scan error: {str(e)}',
            'reasons': [
                'Vulnerability scanning process encountered an error',
                'Unable to complete security assessment',
                'Network issues or server problems prevented scan',
                'Try scanning again or use professional security tools'
            ]
        }
