import hashlib

def calculate_hash(data, hash_type):
    """Calculate hash of data"""
    if isinstance(data, str):
        data = data.encode()
    
    hash_type = hash_type.lower()
    
    if hash_type == 'md5':
        return hashlib.md5(data).hexdigest()
    elif hash_type == 'sha1':
        return hashlib.sha1(data).hexdigest()
    elif hash_type == 'sha256':
        return hashlib.sha256(data).hexdigest()
    elif hash_type == 'sha512':
        return hashlib.sha512(data).hexdigest()
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")

def compare_hashes(data1, data2, hash_type='sha256'):
    """Compare hashes of two data sets"""
    hash1 = calculate_hash(data1, hash_type)
    hash2 = calculate_hash(data2, hash_type)
    
    return {
        'hash1': hash1,
        'hash2': hash2,
        'match': hash1 == hash2
    }
