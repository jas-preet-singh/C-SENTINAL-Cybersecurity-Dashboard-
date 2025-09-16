import os
import time
import threading
import zipfile
import PyPDF2
from docx import Document
from app import db
from models import Job

# Common passwords for brute force
COMMON_PASSWORDS = [
    'password', '123456', 'password123', 'admin', 'letmein', 'welcome',
    'monkey', '1234567890', 'qwerty', 'abc123', 'Password1', '123123',
    'hello', 'login', 'pass', 'test', 'guest', 'user', 'root', 'default'
]

WORDLIST_PASSWORDS = {
    'common': COMMON_PASSWORDS,
    'numbers': [str(i).zfill(4) for i in range(10000)],
    'years': [str(year) for year in range(1900, 2030)]
}

def check_file_unlocked(file_path):
    """Check if file is already unlocked/has no password"""
    file_type = detect_file_type(file_path)
    
    if file_type == 'zip':
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                # Try to get file info without password
                zip_file.infolist()
                return True  # File is not password protected
        except (RuntimeError, zipfile.BadZipFile):
            return False  # File is encrypted or corrupted
            
    elif file_type == 'pdf':
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                return not pdf_reader.is_encrypted  # True if not encrypted
        except:
            return False
            
    elif file_type == 'office':
        try:
            doc = Document(file_path)
            return True  # File opened successfully without password
        except:
            return False  # File is encrypted or corrupted
    
    return False

def try_password_zip(file_path, password):
    """Try to extract a ZIP file with given password"""
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_file:
            zip_file.extractall(pwd=password.encode())
        return True
    except (RuntimeError, zipfile.BadZipFile):
        return False

def try_password_pdf(file_path, password):
    """Try to open a PDF file with given password"""
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            if pdf_reader.is_encrypted:
                return pdf_reader.decrypt(password)
            else:
                return False  # File is not encrypted, so password attempt is meaningless
    except:
        return False

def try_password_docx(file_path, password):
    """Try to open a DOCX file with given password"""
    try:
        # For DOCX, if it opens without error, it's not password protected
        # We need to actually try with password for encrypted files
        doc = Document(file_path)
        return False  # File is not password protected, so password attempt is meaningless
    except:
        return False

def detect_file_type(file_path):
    """Detect file type based on extension"""
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext == '.zip':
        return 'zip'
    elif ext == '.pdf':
        return 'pdf'
    elif ext in ['.docx', '.pptx', '.xlsx']:
        return 'office'
    else:
        return 'unknown'

def load_custom_wordlist(file_path):
    """Load custom wordlist from file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            passwords = [line.strip() for line in f.readlines() if line.strip()]
        return passwords
    except Exception as e:
        print(f"Error loading wordlist: {e}")
        return COMMON_PASSWORDS

def brute_force_worker(job_id, file_path, wordlist_type, custom_wordlist_path=None):
    """Background worker for brute force attack"""
    from app import app
    
    with app.app_context():
        try:
            job = Job.query.get(job_id)
            if not job:
                return
            
            # First check if file is already unlocked
            if check_file_unlocked(file_path):
                job.status = 'completed'
                job.result = 'File is already unlocked - no password required'
                job.progress = 100
                db.session.commit()
                return
            
            file_type = detect_file_type(file_path)
            
            # Load passwords based on type
            if wordlist_type == 'custom' and custom_wordlist_path:
                passwords = load_custom_wordlist(custom_wordlist_path)
            else:
                passwords = WORDLIST_PASSWORDS.get(wordlist_type, COMMON_PASSWORDS)
            
            total_passwords = len(passwords)
            
            for i, password in enumerate(passwords):
                # Check if job was cancelled
                job = Job.query.get(job_id)
                if not job or job.status == 'cancelled':
                    break
                
                # Update current password being tested
                job.result = f'Trying: {password}'
                
                # Try password based on file type
                success = False
                if file_type == 'zip':
                    success = try_password_zip(file_path, password)
                elif file_type == 'pdf':
                    success = try_password_pdf(file_path, password)
                elif file_type == 'office':
                    success = try_password_docx(file_path, password)
                
                if success:
                    if job:
                        job.status = 'completed'
                        job.result = f'Password found: {password}'
                        job.progress = 100
                        db.session.commit()
                    return
                
                # Update progress
                if job:
                    progress = int((i + 1) / total_passwords * 100)
                    job.progress = progress
                    db.session.commit()
                
                time.sleep(0.1)  # Small delay for better UX
            
            # If we get here, no password was found
            job = Job.query.get(job_id)
            if job:
                job.status = 'completed'
                job.result = 'Password not found in wordlist'
                job.progress = 100
                db.session.commit()
            
        except Exception as e:
            job = Job.query.get(job_id)
            if job:
                job.status = 'failed'
                job.result = f'Error: {str(e)}'
                db.session.commit()

def start_brute_force(job_id, file_path, wordlist_type, custom_wordlist_path=None):
    """Start brute force attack in background thread"""
    thread = threading.Thread(
        target=brute_force_worker,
        args=(job_id, file_path, wordlist_type, custom_wordlist_path)
    )
    thread.daemon = True
    thread.start()

def check_job_status(job_id):
    """Check status of brute force job"""
    job = Job.query.get(job_id)
    if not job:
        return None
    
    return {
        'status': job.status,
        'progress': job.progress,
        'result': job.result
    }
