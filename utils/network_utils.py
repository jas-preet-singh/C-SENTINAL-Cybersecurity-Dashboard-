import socket
import subprocess
import re
import requests
import time
from urllib.parse import urlparse

def ping_host(hostname, count=4):
    """Ping a hostname or IP address"""
    try:
        # Clean hostname
        hostname = hostname.strip()
        if not hostname:
            return {'success': False, 'error': 'Hostname cannot be empty'}
        
        # Use ping command
        cmd = ['ping', '-c', str(count), hostname]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            # Parse ping output
            output = result.stdout
            
            # Extract statistics
            stats = {}
            if 'packet loss' in output:
                loss_match = re.search(r'(\d+)% packet loss', output)
                if loss_match:
                    stats['packet_loss'] = f"{loss_match.group(1)}%"
            
            if 'round-trip' in output or 'rtt' in output:
                rtt_match = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
                if rtt_match:
                    stats['min_rtt'] = f"{rtt_match.group(1)}ms"
                    stats['avg_rtt'] = f"{rtt_match.group(2)}ms"
                    stats['max_rtt'] = f"{rtt_match.group(3)}ms"
                    stats['stddev_rtt'] = f"{rtt_match.group(4)}ms"
            
            return {
                'success': True,
                'output': output,
                'statistics': stats,
                'reachable': True
            }
        else:
            return {
                'success': False,
                'output': result.stderr,
                'reachable': False,
                'error': 'Host unreachable'
            }
            
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Ping timeout (30s exceeded)'}
    except Exception as e:
        return {'success': False, 'error': f'Ping failed: {str(e)}'}

def dns_lookup(hostname, record_type='A'):
    """Perform DNS lookup for various record types"""
    try:
        import dns.resolver
        
        # Clean hostname
        hostname = hostname.strip()
        if not hostname:
            return {'success': False, 'error': 'Hostname cannot be empty'}
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        
        results = []
        
        try:
            answers = resolver.resolve(hostname, record_type)
            for answer in answers:
                results.append(str(answer))
            
            return {
                'success': True,
                'hostname': hostname,
                'record_type': record_type,
                'results': results,
                'count': len(results)
            }
            
        except dns.resolver.NXDOMAIN:
            return {'success': False, 'error': 'Domain not found (NXDOMAIN)'}
        except dns.resolver.NoAnswer:
            return {'success': False, 'error': f'No {record_type} record found'}
        except dns.resolver.Timeout:
            return {'success': False, 'error': 'DNS query timeout'}
            
    except ImportError:
        # Fallback to socket for basic A record lookup
        if record_type == 'A':
            try:
                ip_address = socket.gethostbyname(hostname)
                return {
                    'success': True,
                    'hostname': hostname,
                    'record_type': 'A',
                    'results': [ip_address],
                    'count': 1
                }
            except socket.gaierror as e:
                return {'success': False, 'error': f'DNS resolution failed: {str(e)}'}
        else:
            return {'success': False, 'error': 'DNS library not available for this record type'}
    except Exception as e:
        return {'success': False, 'error': f'DNS lookup failed: {str(e)}'}

def port_scan(hostname, ports, timeout=3):
    """Scan specific ports on a hostname"""
    try:
        # Clean hostname
        hostname = hostname.strip()
        if not hostname:
            return {'success': False, 'error': 'Hostname cannot be empty'}
        
        # Parse ports
        if isinstance(ports, str):
            port_list = []
            for port_range in ports.split(','):
                port_range = port_range.strip()
                if '-' in port_range:
                    start, end = port_range.split('-')
                    port_list.extend(range(int(start), int(end) + 1))
                else:
                    port_list.append(int(port_range))
        else:
            port_list = ports
        
        # Limit port scanning for security
        if len(port_list) > 50:
            return {'success': False, 'error': 'Too many ports specified (max 50)'}
        
        open_ports = []
        closed_ports = []
        
        for port in port_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((hostname, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
                    
            except Exception:
                closed_ports.append(port)
        
        return {
            'success': True,
            'hostname': hostname,
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'total_scanned': len(port_list),
            'open_count': len(open_ports)
        }
        
    except Exception as e:
        return {'success': False, 'error': f'Port scan failed: {str(e)}'}

def traceroute(hostname, max_hops=15):
    """Perform traceroute to hostname"""
    try:
        # Clean hostname
        hostname = hostname.strip()
        if not hostname:
            return {'success': False, 'error': 'Hostname cannot be empty'}
        
        # Use traceroute command
        cmd = ['traceroute', '-m', str(max_hops), hostname]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            output = result.stdout
            hops = []
            
            # Parse traceroute output
            lines = output.split('\n')
            for line in lines[1:]:  # Skip first line (header)
                if line.strip():
                    hop_match = re.match(r'\s*(\d+)\s+(.+)', line)
                    if hop_match:
                        hop_num = hop_match.group(1)
                        hop_info = hop_match.group(2).strip()
                        hops.append({'hop': hop_num, 'info': hop_info})
            
            return {
                'success': True,
                'hostname': hostname,
                'output': output,
                'hops': hops,
                'hop_count': len(hops)
            }
        else:
            return {
                'success': False,
                'output': result.stderr,
                'error': 'Traceroute failed'
            }
            
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Traceroute timeout (60s exceeded)'}
    except FileNotFoundError:
        return {'success': False, 'error': 'Traceroute command not available'}
    except Exception as e:
        return {'success': False, 'error': f'Traceroute failed: {str(e)}'}

def whois_lookup(domain):
    """Perform WHOIS lookup for domain"""
    try:
        # Clean domain
        domain = domain.strip().lower()
        if not domain:
            return {'success': False, 'error': 'Domain cannot be empty'}
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc
        
        # Use whois command
        cmd = ['whois', domain]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            output = result.stdout
            
            # Parse basic info
            info = {}
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                if ':' in line and not line.startswith('%') and not line.startswith('#'):
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key in ['registrar', 'creation date', 'expiry date', 'updated date', 'status']:
                        info[key.replace(' ', '_')] = value
            
            return {
                'success': True,
                'domain': domain,
                'output': output,
                'parsed_info': info
            }
        else:
            return {
                'success': False,
                'output': result.stderr,
                'error': 'WHOIS lookup failed'
            }
            
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'WHOIS timeout (30s exceeded)'}
    except FileNotFoundError:
        return {'success': False, 'error': 'WHOIS command not available'}
    except Exception as e:
        return {'success': False, 'error': f'WHOIS lookup failed: {str(e)}'}

def network_info():
    """Get basic network information"""
    try:
        info = {}
        
        # Get local IP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            info['local_ip'] = local_ip
        except:
            info['local_ip'] = 'Unable to determine'
        
        # Get hostname
        try:
            info['hostname'] = socket.gethostname()
        except:
            info['hostname'] = 'Unable to determine'
        
        # Test internet connectivity
        try:
            response = requests.get('https://8.8.8.8', timeout=5)
            info['internet_connectivity'] = 'Connected'
        except:
            info['internet_connectivity'] = 'No internet access'
        
        # Test DNS resolution
        try:
            socket.gethostbyname('google.com')
            info['dns_resolution'] = 'Working'
        except:
            info['dns_resolution'] = 'DNS issues detected'
        
        return {
            'success': True,
            'network_info': info
        }
        
    except Exception as e:
        return {'success': False, 'error': f'Network info failed: {str(e)}'}