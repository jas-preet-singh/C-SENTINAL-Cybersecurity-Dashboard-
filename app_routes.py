import os
import hashlib
from datetime import datetime
from flask import session, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from app import app, db
from replit_auth import require_login, make_replit_blueprint
from flask_login import current_user
from models import User, Upload, Job, ScanResult, ActivityLog
from utils.hash_utils import calculate_hash, compare_hashes
from utils.crypto_utils import encrypt_file, decrypt_file
from utils.password_cracker import start_brute_force, check_job_status
from utils.scanner_utils import scan_url, scan_file_for_malware, vulnerability_scan
from utils.password_analyzer import analyze_password_strength, generate_password_suggestions
from utils.network_utils import ping_host, dns_lookup, port_scan, traceroute, whois_lookup, network_info
from utils.osint_utils import check_email_breaches, search_username, analyze_ip, analyze_domain, get_user_public_ip, get_ip_geolocation
from utils.steganography import encode_text_in_any_file, decode_text_from_any_file, get_file_capacity, validate_file_format, create_stego_filename

app.register_blueprint(make_replit_blueprint(), url_prefix="/auth")

# Make session permanent
@app.before_request
def make_session_permanent():
    session.permanent = True

def log_activity(action, details=None):
    """Log user activity"""
    # Get the user's real public IP address
    public_ip = get_user_public_ip(request)
    
    log = ActivityLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        details=details,
        ip_address=request.remote_addr,  # Keep internal IP for debugging
        user_public_ip=public_ip,  # Store real public IP
        user_agent=request.headers.get('User-Agent')
    )
    db.session.add(log)
    db.session.commit()

@app.route('/')
def index():
    """Home page with service modules for authenticated users, landing page for anonymous users"""
    return render_template('index.html')

@app.route('/services')
def services():
    """Services provided page"""
    return render_template('services.html')

@app.route('/about')
def about():
    """About us page"""
    return render_template('about.html')

# Individual service GET routes for direct access from home page
@app.route('/hash-calculator')
@require_login
def hash_calculator_page():
    """Hash Calculator service page"""
    return render_template('services/hash_calculator.html')

@app.route('/file-encryption')
@require_login  
def file_encryption_page():
    """File Encryption service page"""
    return render_template('services/file_encryption.html')

@app.route('/password-cracker')
@require_login
def password_cracker_page():
    """Password Cracker service page"""
    return render_template('services/password_cracker.html')

@app.route('/hash-comparison')
@require_login
def hash_comparison_page():
    """Hash Comparison service page"""
    return render_template('services/hash_comparison.html')

@app.route('/url-scanner')
@require_login
def url_scanner_page():
    """URL & Malware Scanner service page"""
    return render_template('services/url_scanner.html')

@app.route('/vulnerability-scanner')
@require_login
def vulnerability_scanner_page():
    """Vulnerability Scanner service page"""
    return render_template('services/vulnerability_scanner.html')

@app.route('/password-analyzer')
@require_login
def password_analyzer_page():
    """Password Strength Analyzer service page"""
    return render_template('services/password_analyzer.html')

@app.route('/network-tools')
@require_login
def network_tools_page():
    """Network Diagnostic Tools service page"""
    return render_template('services/network_tools.html')

@app.route('/osint')
@require_login
def osint_page():
    """OSINT Intelligence Gathering service page"""
    return render_template('services/osint.html')

@app.route('/osint/analyze', methods=['POST'])
@require_login
def osint_analyze():
    """Analyze OSINT data based on type"""
    try:
        data = request.get_json()
        osint_type = data.get('type')
        osint_data = data.get('data')
        
        if not osint_type or not osint_data:
            return jsonify({'error': 'Missing type or data'}), 400
        
        result = {}
        
        if osint_type == 'email':
            email = osint_data.get('email')
            if not email:
                return jsonify({'error': 'Email address required'}), 400
            
            result = check_email_breaches(email)
            log_activity('osint_email', f'Email: {email}')
            
        elif osint_type == 'username':
            username = osint_data.get('username')
            if not username:
                return jsonify({'error': 'Username required'}), 400
                
            result = search_username(username)
            log_activity('osint_username', f'Username: {username}')
            
        elif osint_type == 'ip':
            ip_address = osint_data.get('ip_address')
            if not ip_address:
                return jsonify({'error': 'IP address required'}), 400
                
            result = analyze_ip(ip_address)
            log_activity('osint_ip', f'IP: {ip_address}')
            
        elif osint_type == 'domain':
            domain = osint_data.get('domain')
            if not domain:
                return jsonify({'error': 'Domain required'}), 400
                
            result = analyze_domain(domain)
            log_activity('osint_domain', f'Domain: {domain}')
            
        else:
            return jsonify({'error': 'Invalid OSINT type'}), 400
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/osint/system-ip', methods=['POST'])
@require_login
def osint_system_ip():
    """Get user's system IP information"""
    try:
        # Get the user's real public IP address from headers
        public_ip = get_user_public_ip(request)
        
        if not public_ip:
            # If we can't detect from headers, return a message for client-side detection
            return jsonify({
                'error': 'Server cannot detect your public IP from headers. Please use client-side detection.',
                'use_client_detection': True
            }), 200
        
        # Get geolocation information for the IP
        ip_info = get_ip_geolocation(public_ip)
        
        # Log the activity
        log_activity('osint_system_ip', f'System IP detected: {public_ip}')
        
        return jsonify(ip_info)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/steganography')
@require_login
def steganography_page():
    """Steganography Tool service page"""
    return render_template('services/steganography.html')

@app.route('/steganography/capacity', methods=['POST'])
@require_login
def steganography_capacity():
    """Check image capacity for steganography"""
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        file = request.files['image']
        if not file.filename or file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save temporary file to check capacity
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config.get('UPLOAD_FOLDER', 'uploads'), f"temp_{filename}")
        os.makedirs(os.path.dirname(temp_path), exist_ok=True)
        file.save(temp_path)
        
        try:
            capacity = get_file_capacity(temp_path)
            return jsonify({
                'success': True,
                'capacity': capacity
            })
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/steganography/encode', methods=['POST'])
@require_login
def steganography_encode():
    """Encode text in image using steganography"""
    try:
        if 'cover_image' not in request.files or 'secret_text' not in request.form:
            return jsonify({'error': 'Missing image file or secret text'}), 400
        
        file = request.files['cover_image']
        secret_text = request.form['secret_text']
        
        if not file.filename or file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not secret_text.strip():
            return jsonify({'error': 'Secret text cannot be empty'}), 400
        
        # Validate file format
        filename = secure_filename(file.filename)
        temp_input_path = os.path.join(app.config.get('UPLOAD_FOLDER', 'uploads'), f"input_{filename}")
        os.makedirs(os.path.dirname(temp_input_path), exist_ok=True)
        file.save(temp_input_path)
        
        try:
            # Validate image format
            if not validate_file_format(temp_input_path):
                return jsonify({'error': 'Unsupported file format or corrupted file'}), 400
            
            # Create output filename
            stego_filename = create_stego_filename(filename)
            output_path = os.path.join(app.config.get('UPLOAD_FOLDER', 'uploads'), stego_filename)
            
            # Encode text in image
            success, message = encode_text_in_any_file(temp_input_path, secret_text, output_path)
            
            if success:
                # Get file statistics
                original_size = os.path.getsize(temp_input_path)
                stego_size = os.path.getsize(output_path)
                capacity = get_file_capacity(temp_input_path)
                capacity_used = (len(secret_text) / capacity * 100) if capacity > 0 else 0
                
                log_activity('steganography_encode', f'Text length: {len(secret_text)} chars')
                
                return jsonify({
                    'success': True,
                    'message': message,
                    'download_url': url_for('uploaded_file', filename=stego_filename),
                    'original_size': f"{original_size:,} bytes",
                    'stego_size': f"{stego_size:,} bytes",
                    'text_length': len(secret_text),
                    'capacity_used': f"{capacity_used:.1f}"
                })
            else:
                return jsonify({'error': message}), 400
                
        finally:
            # Clean up temp input file
            if os.path.exists(temp_input_path):
                os.remove(temp_input_path)
                
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/steganography/decode', methods=['POST'])
@require_login
def steganography_decode():
    """Decode text from stego image"""
    try:
        if 'stego_image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        file = request.files['stego_image']
        
        if not file.filename or file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save temporary file
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config.get('UPLOAD_FOLDER', 'uploads'), f"decode_{filename}")
        os.makedirs(os.path.dirname(temp_path), exist_ok=True)
        file.save(temp_path)
        
        try:
            # Decode text from image
            success, result = decode_text_from_any_file(temp_path)
            
            if success:
                log_activity('steganography_decode', f'Extracted {len(result)} chars')
                
                return jsonify({
                    'success': True,
                    'hidden_text': result,
                    'text_length': len(result)
                })
            else:
                return jsonify({
                    'success': False,
                    'error': result
                })
                
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dashboard')
@require_login
def dashboard():
    """Main dashboard with all security modules"""
    # Get service usage statistics from ActivityLog
    service_usage = {}
    
    # Define all 10 services with their action names and display info
    services = {
        'hash_calculation': {'name': 'Hash Calculator', 'icon': 'fas fa-calculator'},
        'file_encryption': {'name': 'File Encryption', 'icon': 'fas fa-lock'},
        'file_decryption': {'name': 'File Decryption', 'icon': 'fas fa-unlock'},
        'brute_force_start': {'name': 'Password Cracker', 'icon': 'fas fa-hammer'},
        'hash_comparison': {'name': 'Hash Comparison', 'icon': 'fas fa-balance-scale'},
        'url_scan': {'name': 'URL Scanner', 'icon': 'fas fa-link'},
        'file_scan': {'name': 'Malware Scanner', 'icon': 'fas fa-shield-virus'},
        'vulnerability_scan': {'name': 'Vulnerability Scanner', 'icon': 'fas fa-bug'},
        'password_analysis': {'name': 'Password Analyzer', 'icon': 'fas fa-key'},
        'network_tools': {'name': 'Network Tools', 'icon': 'fas fa-network-wired'},
        'osint_email': {'name': 'OSINT Email', 'icon': 'fas fa-envelope'},
        'osint_username': {'name': 'OSINT Username', 'icon': 'fas fa-user'},
        'osint_ip': {'name': 'OSINT IP', 'icon': 'fas fa-globe'},
        'osint_domain': {'name': 'OSINT Domain', 'icon': 'fas fa-server'}
    }
    
    # Count usage for each service from ActivityLog
    for action_name, service_info in services.items():
        count = ActivityLog.query.filter_by(action=action_name).count()
        
        # Also count network tool specific actions for the network tools category
        if action_name == 'network_tools':
            network_actions = ['network_ping', 'network_dns', 'network_portscan', 
                             'network_traceroute', 'network_whois', 'network_info']
            network_count = 0
            for net_action in network_actions:
                network_count += ActivityLog.query.filter_by(action=net_action).count()
            count = network_count
        
        service_usage[action_name] = {
            'name': service_info['name'],
            'icon': service_info['icon'],
            'count': count
        }
    
    # Sort services by usage count (descending)
    sorted_services = sorted(service_usage.items(), key=lambda x: x[1]['count'], reverse=True)
    
    # Get real-time statistics 
    total_scans_today = ScanResult.query.filter(
        db.func.date(ScanResult.created_at) == db.func.current_date()
    ).count()
    
    active_jobs_count = Job.query.filter_by(status='running').count()
    
    total_activities = ActivityLog.query.count()
    successful_activities = ActivityLog.query.filter(
        ~ActivityLog.details.ilike('%error%'),
        ~ActivityLog.details.ilike('%fail%'),
        ~ActivityLog.details.ilike('%unable%'),
        ~ActivityLog.details.ilike('%denied%')
    ).count()
    
    success_rate = round((successful_activities / max(total_activities, 1)) * 100, 1)
    
    # Get activity timeline data (last 7 days)
    activity_timeline = db.session.query(
        db.func.date(ActivityLog.created_at).label('date'),
        db.func.count(ActivityLog.id).label('count')
    ).filter(
        ActivityLog.created_at >= db.func.current_date() - db.text('INTERVAL \'6 days\'')
    ).group_by(
        db.func.date(ActivityLog.created_at)
    ).order_by('date').all()
    
    # Convert to list of dictionaries for easier JSON serialization
    timeline_data = [{'date': str(day.date), 'count': day.count} for day in activity_timeline]
    
    # Get service usage data for charts
    chart_data = []
    chart_labels = []
    for service_key, service_data in sorted_services[:10]:  # Top 10 services
        if service_data['count'] > 0:
            chart_data.append(service_data['count'])
            chart_labels.append(service_data['name'])
    
    return render_template('dashboard.html', 
                         service_usage=sorted_services,
                         total_scans_today=total_scans_today,
                         active_jobs_count=active_jobs_count,
                         success_rate=success_rate,
                         total_activities=total_activities,
                         timeline_data=timeline_data,
                         chart_data=chart_data,
                         chart_labels=chart_labels)

@app.route('/activity')
@require_login
def activity():
    """Activity history page"""
    # Get recent jobs for current user (background tasks like brute force)
    recent_jobs = Job.query.filter_by(user_id=current_user.id).order_by(Job.created_at.desc()).limit(10).all()
    
    # Get recent activities for current user (all other operations)
    recent_activities = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.created_at.desc()).limit(15).all()
    
    # Combine jobs and activities into a unified list
    all_recent_tasks = []
    
    # Add jobs to the list
    for job in recent_jobs:
        all_recent_tasks.append({
            'type': 'job',
            'title': job.job_type.replace('_', ' ').title(),
            'details': f"Status: {job.status.title()}",
            'timestamp': job.created_at,
            'status': job.status,
            'icon': 'fa-hammer' if 'brute' in job.job_type.lower() else 'fa-cog'
        })
    
    # Add activities to the list
    activity_icons = {
        'hash_calculation': 'fa-calculator',
        'file_encryption': 'fa-lock',
        'file_decryption': 'fa-unlock',
        'hash_comparison': 'fa-balance-scale',
        'url_scan': 'fa-link',
        'file_scan': 'fa-shield-virus',
        'vulnerability_scan': 'fa-bug',
        'password_analysis': 'fa-key',
        'network_ping': 'fa-satellite-dish',
        'network_dns': 'fa-search',
        'network_portscan': 'fa-door-open',
        'network_traceroute': 'fa-route',
        'network_whois': 'fa-info-circle',
        'network_info': 'fa-network-wired'
    }
    
    for activity in recent_activities:
        # Get friendly name for the activity
        activity_names = {
            'hash_calculation': 'Hash Calculation',
            'file_encryption': 'File Encryption',
            'file_decryption': 'File Decryption',
            'hash_comparison': 'Hash Comparison',
            'url_scan': 'URL Scan',
            'file_scan': 'Malware Scan',
            'vulnerability_scan': 'Vulnerability Scan',
            'password_analysis': 'Password Analysis',
            'network_ping': 'Network Ping',
            'network_dns': 'DNS Lookup',
            'network_portscan': 'Port Scan',
            'network_traceroute': 'Traceroute',
            'network_whois': 'WHOIS Lookup',
            'network_info': 'Network Info'
        }
        
        all_recent_tasks.append({
            'type': 'activity',
            'title': activity_names.get(activity.action, activity.action.replace('_', ' ').title()),
            'details': activity.details or 'Task completed',
            'timestamp': activity.created_at,
            'status': 'completed',
            'icon': activity_icons.get(activity.action, 'fa-cog')
        })
    
    # Sort all tasks by timestamp (most recent first)
    all_recent_tasks.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Limit to 20 most recent tasks
    all_recent_tasks = all_recent_tasks[:20]
    
    # Get recent scans for current user
    recent_scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.created_at.desc()).limit(10).all()
    
    # Get statistics
    total_jobs = Job.query.filter_by(user_id=current_user.id).count()
    completed_jobs = Job.query.filter_by(user_id=current_user.id, status='completed').count()
    running_jobs = Job.query.filter_by(user_id=current_user.id, status='running').count()
    total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    total_activities = ActivityLog.query.filter_by(user_id=current_user.id).count()
    
    # Calculate successful activities (activities without error keywords)
    successful_activities = ActivityLog.query.filter(
        ActivityLog.user_id == current_user.id,
        ~ActivityLog.details.ilike('%error%'),
        ~ActivityLog.details.ilike('%fail%'),
        ~ActivityLog.details.ilike('%unable%'),
        ~ActivityLog.details.ilike('%denied%')
    ).count()
    
    return render_template('activity.html', 
                         recent_jobs=all_recent_tasks,  # Now contains unified task list
                         recent_scans=recent_scans,
                         total_jobs=total_jobs,
                         completed_jobs=completed_jobs,
                         running_jobs=running_jobs,
                         total_scans=total_scans,
                         total_activities=total_activities,
                         successful_activities=successful_activities)

@app.route('/hash', methods=['GET', 'POST'])
@require_login
def hash_calculator():
    """Calculate file or text hashes"""
    if request.method == 'GET':
        return render_template('services/hash_calculator.html')
    
    try:
        hash_type = request.form.get('hash_type', 'sha256')
        input_method = request.form.get('input_method', 'file')
        
        if input_method == 'file' and 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            file_content = file.read()
            result = calculate_hash(file_content, hash_type)
            input_source = f"File: {file.filename}"
            input_size = f"{len(file_content):,} bytes"
            log_activity('hash_calculation', f'File: {file.filename}, Type: {hash_type}')
        else:
            text = request.form.get('text', '')
            if not text.strip():
                return jsonify({'success': False, 'error': 'Please provide text to hash'})
            result = calculate_hash(text.encode(), hash_type)
            input_source = "Text input"
            input_size = f"{len(text):,} characters"
            log_activity('hash_calculation', f'Text hash, Type: {hash_type}')
        
        return jsonify({
            'success': True,
            'hash_type': hash_type.upper(),
            'hash_result': result,
            'input_source': input_source,
            'input_size': input_size,
            'hash_length': len(result)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error calculating hash: {str(e)}'})

@app.route('/encrypt', methods=['POST'])
@require_login
def encrypt():
    """Encrypt a file with AES"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file selected'})
        
        file = request.files['file']
        password = request.form.get('password')
        
        if not password:
            return jsonify({'success': False, 'error': 'Password is required for encryption'})
        
        if not file.filename:
            return jsonify({'success': False, 'error': 'No file selected'})
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Get original file size
        original_size = os.path.getsize(file_path)
        
        # Encrypt file
        encrypted_path = encrypt_file(file_path, password)
        encrypted_filename = os.path.basename(encrypted_path)
        encrypted_size = os.path.getsize(encrypted_path)
        
        # Log upload
        upload = Upload(
            user_id=current_user.id,
            filename=encrypted_filename,
            original_filename=file.filename,
            file_size=encrypted_size
        )
        db.session.add(upload)
        db.session.commit()
        
        log_activity('file_encryption', f'File: {file.filename}')
        
        return jsonify({
            'success': True,
            'message': f'File encrypted successfully!',
            'download_url': url_for('uploaded_file', filename=encrypted_filename),
            'original_filename': file.filename,
            'encrypted_filename': encrypted_filename,
            'original_size': f"{original_size:,} bytes",
            'encrypted_size': f"{encrypted_size:,} bytes"
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Encryption failed: {str(e)}'})

@app.route('/decrypt', methods=['POST'])
@require_login
def decrypt():
    """Decrypt a file with AES"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file selected'})
        
        file = request.files['file']
        password = request.form.get('password')
        
        if not password:
            return jsonify({'success': False, 'error': 'Password is required for decryption'})
        
        if not file.filename:
            return jsonify({'success': False, 'error': 'No file selected'})
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Get encrypted file size
        encrypted_size = os.path.getsize(file_path)
        
        # Decrypt file
        decrypted_path = decrypt_file(file_path, password)
        decrypted_filename = os.path.basename(decrypted_path)
        decrypted_size = os.path.getsize(decrypted_path)
        
        log_activity('file_decryption', f'File: {file.filename}')
        
        return jsonify({
            'success': True,
            'message': f'File decrypted successfully!',
            'download_url': url_for('uploaded_file', filename=decrypted_filename),
            'original_filename': file.filename,
            'decrypted_filename': decrypted_filename,
            'encrypted_size': f"{encrypted_size:,} bytes",
            'decrypted_size': f"{decrypted_size:,} bytes"
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Decryption failed: {str(e)}'})

@app.route('/brute/start', methods=['POST'])
@require_login
def start_brute():
    """Start brute force password cracking"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        
        file = request.files['file']
        wordlist_type = request.form.get('wordlist', 'common')
        
        # Save uploaded file
        filename = secure_filename(file.filename or 'unknown')
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Handle custom wordlist upload
        custom_wordlist_path = None
        if wordlist_type == 'custom' and 'wordlist_file' in request.files:
            wordlist_file = request.files['wordlist_file']
            if wordlist_file.filename:
                wordlist_filename = secure_filename(wordlist_file.filename)
                custom_wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], f'wordlist_{wordlist_filename}')
                wordlist_file.save(custom_wordlist_path)
        
        # Create job
        job = Job(
            user_id=current_user.id,
            job_type='brute_force',
            status='running'
        )
        db.session.add(job)
        db.session.commit()
        
        # Start brute force (in background)
        start_brute_force(job.id, file_path, wordlist_type, custom_wordlist_path)
        
        log_activity('brute_force_start', f'File: {file.filename}')
        
        return jsonify({'job_id': job.id, 'message': 'Brute force attack started'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/job_status/<int:job_id>')
@require_login
def api_job_status(job_id):
    """Get status of a job"""
    job = Job.query.get_or_404(job_id)
    
    # Ensure user owns this job
    if job.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({
        'status': job.status,
        'progress': job.progress,
        'result': job.result,
        'job_type': job.job_type
    })

@app.route('/api/cancel_job/<int:job_id>', methods=['POST'])
@require_login
def api_cancel_job(job_id):
    """Cancel a running job"""
    job = Job.query.get_or_404(job_id)
    
    # Ensure user owns this job
    if job.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    job.status = 'cancelled'
    db.session.commit()
    
    return jsonify({'message': 'Job cancelled'})

@app.route('/analyze_password', methods=['POST'])
@require_login
def analyze_password():
    """Analyze password strength"""
    try:
        password = request.form.get('password', '')
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        analysis = analyze_password_strength(password)
        suggestions = generate_password_suggestions()
        
        # Log activity (without storing the actual password)
        log_activity('password_analysis', f'Password length: {len(password)} chars')
        
        return jsonify({
            'analysis': analysis,
            'suggestions': suggestions
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/compare', methods=['POST'])
@require_login
def compare():
    """Compare hashes of two files"""
    try:
        if 'file1' not in request.files or 'file2' not in request.files:
            flash('Please select both files for comparison', 'error')
            return redirect(url_for('dashboard'))
        
        file1 = request.files['file1']
        file2 = request.files['file2']
        hash_type = request.form.get('hash_type', 'sha256')
        
        content1 = file1.read()
        content2 = file2.read()
        
        result = compare_hashes(content1, content2, hash_type)
        
        log_activity('hash_comparison', f'Files: {file1.filename} vs {file2.filename}')
        
        if result['match']:
            flash(f'Files match! Both have {hash_type.upper()} hash: {result["hash1"]}', 'success')
        else:
            flash(f'Files do not match.\n{file1.filename}: {result["hash1"]}\n{file2.filename}: {result["hash2"]}', 'warning')
        
    except Exception as e:
        flash(f'Comparison failed: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/scan/url', methods=['POST'])
@require_login
def scan_url_route():
    """Scan URL for safety"""
    try:
        url = request.form.get('url')
        if not url:
            return jsonify({'success': False, 'error': 'Please enter a URL to scan'})
        
        result = scan_url(url)
        
        scan_result = ScanResult(
            user_id=current_user.id,
            scan_type='url',
            target=url,
            result=str(result),
            risk_level=result.get('risk_level', 'unknown')
        )
        db.session.add(scan_result)
        db.session.commit()
        
        log_activity('url_scan', f'URL: {url}')
        
        return jsonify({
            'success': True,
            'url': url,
            'safe': result['safe'],
            'message': result['message'],
            'risk_level': result['risk_level'],
            'reasons': result.get('reasons', [])
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'URL scan failed: {str(e)}'})

@app.route('/scan/file', methods=['POST'])
@require_login
def scan_file_route():
    """Scan file for malware"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file selected'})
        
        file = request.files['file']
        
        # Save uploaded file
        filename = secure_filename(file.filename or 'unknown')
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        result = scan_file_for_malware(file_path)
        
        scan_result = ScanResult(
            user_id=current_user.id,
            scan_type='file',
            target=file.filename,
            result=str(result),
            risk_level=result.get('risk_level', 'unknown')
        )
        db.session.add(scan_result)
        db.session.commit()
        
        log_activity('file_scan', f'File: {file.filename}')
        
        return jsonify({
            'success': True,
            'filename': file.filename,
            'clean': result['clean'],
            'message': result['message'],
            'risk_level': result['risk_level'],
            'reasons': result.get('reasons', [])
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'File scan failed: {str(e)}'})

@app.route('/scan/vulnerability', methods=['POST'])
@require_login
def vulnerability_scan_route():
    """Perform vulnerability scan on URL"""
    try:
        url = request.form.get('url')
        if not url:
            return jsonify({'success': False, 'error': 'Please enter a URL to scan'})
        
        result = vulnerability_scan(url)
        
        scan_result = ScanResult(
            user_id=current_user.id,
            scan_type='vulnerability',
            target=url,
            result=str(result),
            risk_level=result.get('risk_level', 'unknown')
        )
        db.session.add(scan_result)
        db.session.commit()
        
        log_activity('vulnerability_scan', f'URL: {url}')
        
        vulnerabilities = result.get('vulnerabilities', [])
        return jsonify({
            'success': True,
            'url': url,
            'vulnerabilities': vulnerabilities,
            'risk_level': result.get('risk_level', 'unknown'),
            'message': result.get('message', 'Scan completed'),
            'vulnerability_count': len(vulnerabilities),
            'reasons': result.get('reasons', []),
            'security_issues': result.get('security_issues', []),
            'security_strengths': result.get('security_strengths', []),
            'missing_headers': result.get('missing_headers', []),
            'present_headers': result.get('present_headers', [])
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Vulnerability scan failed: {str(e)}'})

@app.route('/network/ping', methods=['POST'])
@require_login
def network_ping():
    """Ping a hostname or IP address"""
    try:
        hostname = request.form.get('hostname')
        count = int(request.form.get('count', 4))
        
        if not hostname:
            return jsonify({'success': False, 'error': 'Hostname is required'})
        
        result = ping_host(hostname, count)
        log_activity('network_ping', f'Host: {hostname}')
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Ping failed: {str(e)}'})

@app.route('/network/dns', methods=['POST'])
@require_login
def network_dns():
    """DNS lookup for hostname"""
    try:
        hostname = request.form.get('hostname')
        record_type = request.form.get('record_type', 'A')
        
        if not hostname:
            return jsonify({'success': False, 'error': 'Hostname is required'})
        
        result = dns_lookup(hostname, record_type)
        log_activity('network_dns', f'Host: {hostname}, Type: {record_type}')
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'DNS lookup failed: {str(e)}'})

@app.route('/network/portscan', methods=['POST'])
@require_login
def network_portscan():
    """Port scan for hostname"""
    try:
        hostname = request.form.get('hostname')
        ports = request.form.get('ports', '80,443,22,21,25,53,110,143,993,995')
        
        if not hostname:
            return jsonify({'success': False, 'error': 'Hostname is required'})
        
        result = port_scan(hostname, ports)
        log_activity('network_portscan', f'Host: {hostname}, Ports: {ports}')
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Port scan failed: {str(e)}'})

@app.route('/network/traceroute', methods=['POST'])
@require_login
def network_traceroute():
    """Traceroute to hostname"""
    try:
        hostname = request.form.get('hostname')
        max_hops = int(request.form.get('max_hops', 15))
        
        if not hostname:
            return jsonify({'success': False, 'error': 'Hostname is required'})
        
        result = traceroute(hostname, max_hops)
        log_activity('network_traceroute', f'Host: {hostname}')
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Traceroute failed: {str(e)}'})

@app.route('/network/whois', methods=['POST'])
@require_login
def network_whois():
    """WHOIS lookup for domain"""
    try:
        domain = request.form.get('domain')
        
        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'})
        
        result = whois_lookup(domain)
        log_activity('network_whois', f'Domain: {domain}')
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'WHOIS lookup failed: {str(e)}'})

@app.route('/network/info', methods=['GET'])
@require_login
def network_info_route():
    """Get network information"""
    try:
        result = network_info()
        log_activity('network_info', 'Network information retrieved')
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Network info failed: {str(e)}'})

@app.route('/admin')
@require_login
def admin_panel():
    """Admin panel for viewing logs and user management"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    logs = ActivityLog.query.order_by(ActivityLog.created_at.desc()).limit(100).all()
    users = User.query.all()
    return render_template('admin.html', logs=logs, users=users)


@app.route('/uploads/<filename>')
@require_login
def uploaded_file(filename):
    """Serve uploaded files"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
