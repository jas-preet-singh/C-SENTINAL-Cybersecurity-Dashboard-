import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key_from_password(password, salt=None):
    """Generate encryption key from password"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(file_path, password):
    """Encrypt a file with AES using password"""
    key, salt = generate_key_from_password(password)
    fernet = Fernet(key)
    
    # Read original file
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # Encrypt data
    encrypted_data = fernet.encrypt(file_data)
    
    # Write encrypted file with salt prefix
    encrypted_path = file_path + '.encrypted'
    with open(encrypted_path, 'wb') as f:
        f.write(salt + encrypted_data)
    
    # Remove original file for security
    os.remove(file_path)
    
    return encrypted_path

def decrypt_file(file_path, password):
    """Decrypt a file with AES using password"""
    # Read encrypted file
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Extract salt and encrypted content
    salt = encrypted_data[:16]
    encrypted_content = encrypted_data[16:]
    
    # Generate key from password and salt
    key, _ = generate_key_from_password(password, salt)
    fernet = Fernet(key)
    
    try:
        # Decrypt data
        decrypted_data = fernet.decrypt(encrypted_content)
        
        # Write decrypted file
        decrypted_path = file_path.replace('.encrypted', '.decrypted')
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)
        
        return decrypted_path
        
    except Exception as e:
        raise Exception("Invalid password or corrupted file")
