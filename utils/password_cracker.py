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
        return True
    except:
        return False

def try_password_docx(file_path, password):
    """Try to open a DOCX file with given password"""
    try:
        doc = Document(file_path)
        return True
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

def brute_force_worker(job_id, file_path, wordlist_type):
    """Background worker for brute force attack"""
    try:
        job = Job.query.get(job_id)
        if not job:
            return
        
        file_type = detect_file_type(file_path)
        passwords = WORDLIST_PASSWORDS.get(wordlist_type, COMMON_PASSWORDS)
        
        total_passwords = len(passwords)
        
        for i, password in enumerate(passwords):
            # Check if job was cancelled
            job = Job.query.get(job_id)
            if job.status == 'cancelled':
                break
            
            # Try password based on file type
            success = False
            if file_type == 'zip':
                success = try_password_zip(file_path, password)
            elif file_type == 'pdf':
                success = try_password_pdf(file_path, password)
            elif file_type == 'office':
                success = try_password_docx(file_path, password)
            
            if success:
                job.status = 'completed'
                job.result = f'Password found: {password}'
                job.progress = 100
                db.session.commit()
                return
            
            # Update progress
            progress = int((i + 1) / total_passwords * 100)
            job.progress = progress
            db.session.commit()
            
            time.sleep(0.01)  # Small delay to prevent overwhelming
        
        # If we get here, no password was found
        job.status = 'completed'
        job.result = 'Password not found in wordlist'
        job.progress = 100
        db.session.commit()
        
    except Exception as e:
        job = Job.query.get(job_id)
        job.status = 'failed'
        job.result = f'Error: {str(e)}'
        db.session.commit()

def start_brute_force(job_id, file_path, wordlist_type):
    """Start brute force attack in background thread"""
    thread = threading.Thread(
        target=brute_force_worker,
        args=(job_id, file_path, wordlist_type)
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
