import requests
import re
import socket
import json
import time
from urllib.parse import urlparse

def check_email_breaches(email):
    """Check if email has been involved in data breaches"""
    try:
        # Input validation
        if not email or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return {'error': 'Invalid email format'}
        
        # Simulated breach database for demo (in production, use HaveIBeenPwned API)
        # This demonstrates the functionality without requiring API keys
        
        # Common breached email patterns for demonstration
        known_breached_domains = ['yahoo.com', 'gmail.com', 'hotmail.com']
        email_domain = email.split('@')[1].lower()
        
        # Simulate breach data
        breaches = []
        
        if email_domain in known_breached_domains:
            # Add some realistic breach data for demonstration
            breaches = [
                {
                    'name': 'Data Breach Collection #1',
                    'date': '2019-01-01',
                    'description': 'Large collection of credential stuffing lists'
                },
                {
                    'name': 'LinkedIn',
                    'date': '2012-06-01', 
                    'description': 'Professional networking service data breach'
                }
            ]
        
        # For educational purposes, show some patterns
        if 'test' in email.lower() or 'demo' in email.lower():
            breaches.append({
                'name': 'Test Data Breach',
                'date': '2020-05-15',
                'description': 'Educational demonstration of breach data'
            })
        
        return {
            'breaches': breaches,
            'total_breaches': len(breaches),
            'email': email
        }
        
    except Exception as e:
        return {'error': f'Error checking email breaches: {str(e)}'}

def search_username(username):
    """Search for username across various platforms"""
    try:
        # Input validation
        if not username or len(username) < 2:
            return {'error': 'Username must be at least 2 characters'}
        
        # Clean username
        username = re.sub(r'[^a-zA-Z0-9_.-]', '', username)
        
        # Common social media platforms to check
        platforms = [
            {'platform': 'GitHub', 'url': f'https://github.com/{username}', 'exists': None},
            {'platform': 'Twitter', 'url': f'https://twitter.com/{username}', 'exists': None},
            {'platform': 'Instagram', 'url': f'https://instagram.com/{username}', 'exists': None},
            {'platform': 'Reddit', 'url': f'https://reddit.com/u/{username}', 'exists': None},
            {'platform': 'YouTube', 'url': f'https://youtube.com/@{username}', 'exists': None},
            {'platform': 'LinkedIn', 'url': f'https://linkedin.com/in/{username}', 'exists': None},
            {'platform': 'Facebook', 'url': f'https://facebook.com/{username}', 'exists': None},
            {'platform': 'TikTok', 'url': f'https://tiktok.com/@{username}', 'exists': None}
        ]
        
        # Check each platform (simplified check for demo)
        profiles = []
        for platform_info in platforms:
            try:
                # For demo purposes, simulate some results based on common usernames
                exists = False
                
                # Common usernames that likely exist on platforms
                if username.lower() in ['admin', 'user', 'test', 'demo', 'root', 'guest']:
                    exists = True
                elif len(username) <= 4:  # Short usernames often taken
                    exists = True
                elif 'github' in platform_info['platform'].lower() and username.lower() in ['torvalds', 'gvanrossum', 'octocat']:
                    exists = True
                
                profiles.append({
                    'platform': platform_info['platform'],
                    'url': platform_info['url'],
                    'exists': exists
                })
                
            except Exception:
                profiles.append({
                    'platform': platform_info['platform'],
                    'url': platform_info['url'],
                    'exists': False
                })
        
        return {
            'profiles': profiles,
            'username': username,
            'total_found': sum(1 for p in profiles if p['exists'])
        }
        
    except Exception as e:
        return {'error': f'Error searching username: {str(e)}'}

def analyze_ip(ip_address):
    """Analyze IP address for geolocation and threat intelligence"""
    try:
        # Input validation
        if not ip_address:
            return {'error': 'IP address required'}
        
        # Basic IP format validation
        if not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip_address):
            return {'error': 'Invalid IP address format'}
        
        # Check for private IP ranges
        parts = ip_address.split('.')
        first_octet = int(parts[0])
        second_octet = int(parts[1])
        
        is_private = False
        if first_octet == 10:
            is_private = True
        elif first_octet == 172 and 16 <= second_octet <= 31:
            is_private = True
        elif first_octet == 192 and second_octet == 168:
            is_private = True
        elif ip_address.startswith('127.'):
            is_private = True
        
        if is_private:
            return {
                'location': {
                    'country': 'Private Network',
                    'city': 'Local',
                    'isp': 'Private IP Range'
                },
                'reputation': {
                    'malicious': False,
                    'score': 0
                },
                'ip_address': ip_address
            }
        
        # Simulate geolocation data (in production, use ipinfo.io or similar)
        # Generate pseudo-realistic data based on IP ranges
        mock_locations = {
            '8.8.8.8': {'country': 'United States', 'city': 'Mountain View', 'isp': 'Google LLC'},
            '1.1.1.1': {'country': 'Australia', 'city': 'Sydney', 'isp': 'Cloudflare'},
            '208.67.222.222': {'country': 'United States', 'city': 'San Francisco', 'isp': 'OpenDNS'}
        }
        
        location = mock_locations.get(ip_address, {
            'country': 'Unknown',
            'city': 'Unknown', 
            'isp': 'Unknown ISP'
        })
        
        # Simulate threat reputation (basic rules for demo)
        malicious = False
        score = 0
        
        # Check for known malicious patterns (simplified)
        if first_octet in [1, 2, 3]:  # Simulate some "bad" ranges
            malicious = True
            score = 85
        elif 'test' in ip_address:
            score = 25
        
        return {
            'location': location,
            'reputation': {
                'malicious': malicious,
                'score': score
            },
            'ip_address': ip_address
        }
        
    except Exception as e:
        return {'error': f'Error analyzing IP: {str(e)}'}

def analyze_domain(domain):
    """Analyze domain for WHOIS and reputation information"""
    try:
        # Input validation
        if not domain:
            return {'error': 'Domain required'}
        
        # Clean domain
        domain = domain.lower().strip()
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc
        
        # Basic domain format validation
        if not re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', domain):
            return {'error': 'Invalid domain format'}
        
        # Simulate WHOIS data (in production, use whois libraries or APIs)
        mock_whois_data = {
            'google.com': {
                'registrar': 'MarkMonitor, Inc.',
                'created': '1997-09-15',
                'expires': '2028-09-14'
            },
            'example.com': {
                'registrar': 'Internet Assigned Numbers Authority',
                'created': '1995-08-14',
                'expires': '2024-08-13'
            },
            'github.com': {
                'registrar': 'CSC Corporate Domains, Inc.',
                'created': '2007-10-09',
                'expires': '2025-10-09'
            }
        }
        
        whois_info = mock_whois_data.get(domain, {
            'registrar': 'Unknown Registrar',
            'created': 'Unknown',
            'expires': 'Unknown'
        })
        
        # Simulate domain reputation analysis
        malicious = False
        
        # Check for suspicious patterns
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        suspicious_keywords = ['phishing', 'malware', 'spam', 'scam']
        
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            malicious = True
        elif any(keyword in domain for keyword in suspicious_keywords):
            malicious = True
        elif len(domain.split('.')[0]) > 20:  # Very long subdomain
            malicious = True
        
        # Check for homograph attacks (simplified)
        if any(ord(char) > 127 for char in domain):
            malicious = True
        
        return {
            'whois': whois_info,
            'reputation': {
                'malicious': malicious
            },
            'domain': domain
        }
        
    except Exception as e:
        return {'error': f'Error analyzing domain: {str(e)}'}

def get_reverse_dns(ip_address):
    """Get reverse DNS lookup for IP address"""
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except Exception:
        return 'No reverse DNS found'

def check_domain_reputation(domain):
    """Check domain reputation using multiple sources"""
    try:
        # This would integrate with services like VirusTotal, URLVoid, etc.
        # For demo, return simulated data
        
        reputation_score = 0
        
        # Check against known bad domains
        known_bad = ['malware.com', 'phishing.net', 'spam.org']
        if domain in known_bad:
            reputation_score = 100
        
        return {
            'reputation_score': reputation_score,
            'clean': reputation_score < 50
        }
        
    except Exception as e:
        return {'error': f'Error checking domain reputation: {str(e)}'}

def get_user_public_ip(request):
    """Get the user's real public IP address"""
    try:
        # Check if we have trusted proxy setup with ProxyFix
        # For Replit, we need to trust the proxy headers
        forwarded_ips = request.headers.get('X-Forwarded-For')
        if forwarded_ips:
            # X-Forwarded-For can contain multiple IPs, get the first one (original client)
            ip = forwarded_ips.split(',')[0].strip()
            if ip and is_public_ip(ip):
                return ip
        
        # Try other common headers from trusted sources
        real_ip = request.headers.get('X-Real-IP')
        if real_ip and is_public_ip(real_ip):
            return real_ip
        
        # Try CF-Connecting-IP (Cloudflare)
        cf_ip = request.headers.get('CF-Connecting-IP')
        if cf_ip and is_public_ip(cf_ip):
            return cf_ip
        
        # Use request remote_addr if it's public
        if request.remote_addr and is_public_ip(request.remote_addr):
            return request.remote_addr
        
        # If we can't get a reliable public IP from headers, return None
        # This will trigger client-side detection or show appropriate message
        return None
        
    except Exception:
        return None

def is_public_ip(ip):
    """Check if an IP address is a public (non-private) IP"""
    try:
        if not ip or ip == '::1':  # localhost IPv6
            return False
        
        # Check private IP ranges
        if (ip.startswith(('10.', '127.')) or  # 10.0.0.0/8, 127.0.0.0/8
            ip.startswith(('192.168.')) or     # 192.168.0.0/16
            ip.startswith(('169.254.'))):      # 169.254.0.0/16 (link-local)
            return False
        
        # Check 172.16.0.0/12 private range (172.16.0.0 to 172.31.255.255)
        if ip.startswith('172.'):
            parts = ip.split('.')
            if len(parts) >= 2:
                try:
                    second_octet = int(parts[1])
                    if 16 <= second_octet <= 31:
                        return False
                except ValueError:
                    pass
        
        return True
        
    except Exception:
        return False

def get_ip_geolocation(ip_address):
    """Get geolocation information for an IP address using ipapi.co"""
    try:
        # Check if it's a private IP
        if ip_address.startswith(('10.', '172.', '192.168.', '127.')):
            return {
                'ip': ip_address,
                'country': 'Private Network',
                'region': 'Internal',
                'city': 'Local Network',
                'isp': 'Private IP Range',
                'org': 'Internal Network',
                'timezone': 'Local',
                'postal': 'N/A'
            }
        
        # Use ipapi.co free service (no API key required)
        try:
            response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Check for error in response
                if 'error' in data:
                    raise Exception(data.get('reason', 'Unknown error'))
                
                return {
                    'ip': ip_address,
                    'country': data.get('country_name', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('org', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown'),
                    'postal': data.get('postal', 'Unknown'),
                    'loc': f"{data.get('latitude', 'Unknown')},{data.get('longitude', 'Unknown')}" if data.get('latitude') and data.get('longitude') else None
                }
        except:
            pass
        
        # Fallback to ipinfo.io (also free, no API key required)
        try:
            response = requests.get(f'https://ipinfo.io/{ip_address}/json', timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'ip': ip_address,
                    'country': data.get('country', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('org', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown'),
                    'postal': data.get('postal', 'Unknown'),
                    'loc': data.get('loc'),
                    'hostname': data.get('hostname')
                }
        except:
            pass
        
        # If all services fail, return basic info
        return {
            'ip': ip_address,
            'country': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'org': 'Unknown',
            'timezone': 'Unknown',
            'postal': 'Unknown',
            'error': 'Geolocation services temporarily unavailable'
        }
        
    except Exception as e:
        return {
            'ip': ip_address,
            'error': f'Error getting geolocation: {str(e)}'
        }