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

app.register_blueprint(make_replit_blueprint(), url_prefix="/auth")

# Make session permanent
@app.before_request
def make_session_permanent():
    session.permanent = True

def log_activity(action, details=None):
    """Log user activity"""
    log = ActivityLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        details=details,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    db.session.add(log)
    db.session.commit()

@app.route('/')
def index():
    """Landing page for anonymous users, dashboard for authenticated users"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/services')
def services():
    """Services provided page"""
    return render_template('services.html')

@app.route('/about')
def about():
    """About us page"""
    return render_template('about.html')

@app.route('/dashboard')
@require_login
def dashboard():
    """Main dashboard with all security modules"""
    return render_template('dashboard.html')

@app.route('/activity')
@require_login
def activity():
    """Activity history page"""
    # Get recent jobs for current user
    recent_jobs = Job.query.filter_by(user_id=current_user.id).order_by(Job.created_at.desc()).limit(10).all()
    
    # Get recent scans for current user
    recent_scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.created_at.desc()).limit(10).all()
    
    # Get statistics
    total_jobs = Job.query.filter_by(user_id=current_user.id).count()
    completed_jobs = Job.query.filter_by(user_id=current_user.id, status='completed').count()
    running_jobs = Job.query.filter_by(user_id=current_user.id, status='running').count()
    total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    
    return render_template('activity.html', 
                         recent_jobs=recent_jobs, 
                         recent_scans=recent_scans,
                         total_jobs=total_jobs,
                         completed_jobs=completed_jobs,
                         running_jobs=running_jobs,
                         total_scans=total_scans)

@app.route('/hash', methods=['POST'])
@require_login
def hash_calculator():
    """Calculate file or text hashes"""
    try:
        hash_type = request.form.get('hash_type', 'sha256')
        
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            file_content = file.read()
            result = calculate_hash(file_content, hash_type)
            log_activity('hash_calculation', f'File: {file.filename}, Type: {hash_type}')
        else:
            text = request.form.get('text', '')
            result = calculate_hash(text.encode(), hash_type)
            log_activity('hash_calculation', f'Text hash, Type: {hash_type}')
        
        flash(f'{hash_type.upper()} Hash: {result}', 'success')
    except Exception as e:
        flash(f'Error calculating hash: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/encrypt', methods=['POST'])
@require_login
def encrypt():
    """Encrypt a file with AES"""
    try:
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('dashboard'))
        
        file = request.files['file']
        password = request.form.get('password')
        
        if not password:
            flash('Password is required for encryption', 'error')
            return redirect(url_for('dashboard'))
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Encrypt file
        encrypted_path = encrypt_file(file_path, password)
        
        # Log upload
        upload = Upload(
            user_id=current_user.id,
            filename=os.path.basename(encrypted_path),
            original_filename=file.filename,
            file_size=os.path.getsize(encrypted_path)
        )
        db.session.add(upload)
        db.session.commit()
        
        log_activity('file_encryption', f'File: {file.filename}')
        flash(f'File encrypted successfully: {os.path.basename(encrypted_path)}', 'success')
        
    except Exception as e:
        flash(f'Encryption failed: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/decrypt', methods=['POST'])
@require_login
def decrypt():
    """Decrypt a file with AES"""
    try:
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('dashboard'))
        
        file = request.files['file']
        password = request.form.get('password')
        
        if not password:
            flash('Password is required for decryption', 'error')
            return redirect(url_for('dashboard'))
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Decrypt file
        decrypted_path = decrypt_file(file_path, password)
        
        log_activity('file_decryption', f'File: {file.filename}')
        flash(f'File decrypted successfully: {os.path.basename(decrypted_path)}', 'success')
        
    except Exception as e:
        flash(f'Decryption failed: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

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
        filename = secure_filename(file.filename)
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
            flash('Please enter a URL to scan', 'error')
            return redirect(url_for('dashboard'))
        
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
        
        if result['safe']:
            flash(f'URL appears safe: {result["message"]}', 'success')
        else:
            flash(f'URL may be unsafe: {result["message"]}', 'warning')
        
    except Exception as e:
        flash(f'URL scan failed: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/scan/file', methods=['POST'])
@require_login
def scan_file_route():
    """Scan file for malware"""
    try:
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('dashboard'))
        
        file = request.files['file']
        
        # Save uploaded file
        filename = secure_filename(file.filename)
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
        
        if result['clean']:
            flash(f'File appears clean: {result["message"]}', 'success')
        else:
            flash(f'Potential threats detected: {result["message"]}', 'warning')
        
    except Exception as e:
        flash(f'File scan failed: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/scan/vulnerability', methods=['POST'])
@require_login
def vulnerability_scan_route():
    """Perform vulnerability scan on URL"""
    try:
        url = request.form.get('url')
        if not url:
            flash('Please enter a URL to scan', 'error')
            return redirect(url_for('dashboard'))
        
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
        if vulnerabilities:
            flash(f'Vulnerabilities found: {", ".join(vulnerabilities)}', 'warning')
        else:
            flash('No obvious vulnerabilities detected', 'success')
        
    except Exception as e:
        flash(f'Vulnerability scan failed: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

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
