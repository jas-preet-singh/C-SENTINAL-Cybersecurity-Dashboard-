import re
import math
from collections import Counter

# Common weak passwords
COMMON_PASSWORDS = [
    'password', '123456', 'password123', 'admin', 'letmein', 'welcome',
    'monkey', '1234567890', 'qwerty', 'abc123', 'Password1', '123123',
    'hello', 'login', 'pass', 'test', 'guest', 'user', 'root', 'default',
    '12345', 'password1', 'admin123', 'iloveyou', 'princess', 'rockyou',
    'football', 'baseball', 'basketball', 'dragon', 'superman', 'michael',
    'jennifer', 'jordan', 'michelle', 'daniel', 'jessica', 'matthew'
]

# Common keyboard patterns
KEYBOARD_PATTERNS = [
    'qwerty', 'asdf', 'zxcv', '1234', 'abcd', '!@#$',
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890'
]

def calculate_entropy(password):
    """Calculate password entropy"""
    if not password:
        return 0
    
    # Character set size
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'[0-9]', password):
        charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset_size += 32  # Common special characters
    
    # Calculate entropy
    entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
    return round(entropy, 2)

def check_password_patterns(password):
    """Check for common patterns in password"""
    patterns_found = []
    
    # Check for keyboard patterns
    for pattern in KEYBOARD_PATTERNS:
        if pattern.lower() in password.lower():
            patterns_found.append(f"Keyboard pattern: {pattern}")
    
    # Check for repeated characters
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            patterns_found.append(f"Repeated character: {password[i]*3}")
            break
    
    # Check for sequential numbers
    for i in range(len(password) - 2):
        if password[i:i+3].isdigit():
            nums = [int(password[i+j]) for j in range(3)]
            if nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1:
                patterns_found.append(f"Sequential numbers: {password[i:i+3]}")
                break
    
    # Check for sequential letters
    for i in range(len(password) - 2):
        if password[i:i+3].isalpha():
            chars = password[i:i+3].lower()
            if ord(chars[1]) == ord(chars[0]) + 1 and ord(chars[2]) == ord(chars[1]) + 1:
                patterns_found.append(f"Sequential letters: {password[i:i+3]}")
                break
    
    return patterns_found

def analyze_password_strength(password):
    """Comprehensive password strength analysis"""
    if not password:
        return {
            'score': 0,
            'strength': 'Very Weak',
            'feedback': ['Password cannot be empty'],
            'details': {},
            'entropy': 0,
            'estimated_crack_time': 'Instant'
        }
    
    score = 0
    feedback = []
    details = {}
    
    # Length check
    length = len(password)
    details['length'] = length
    if length >= 12:
        score += 25
        details['length_score'] = 'Excellent'
    elif length >= 8:
        score += 15
        details['length_score'] = 'Good'
        feedback.append('Consider using 12+ characters for better security')
    elif length >= 6:
        score += 8
        details['length_score'] = 'Fair'
        feedback.append('Password should be at least 8 characters long')
    else:
        score += 0
        details['length_score'] = 'Poor'
        feedback.append('Password is too short (minimum 6 characters)')
    
    # Character variety checks
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    
    char_variety = sum([has_lower, has_upper, has_digit, has_special])
    details['character_variety'] = {
        'lowercase': has_lower,
        'uppercase': has_upper,
        'digits': has_digit,
        'special_chars': has_special,
        'variety_count': char_variety
    }
    
    if char_variety >= 4:
        score += 25
        details['variety_score'] = 'Excellent'
    elif char_variety >= 3:
        score += 18
        details['variety_score'] = 'Good'
        if not has_special:
            feedback.append('Add special characters for better security')
    elif char_variety >= 2:
        score += 10
        details['variety_score'] = 'Fair'
        feedback.append('Include more character types (uppercase, digits, symbols)')
    else:
        score += 0
        details['variety_score'] = 'Poor'
        feedback.append('Use a mix of uppercase, lowercase, numbers, and symbols')
    
    # Common password check
    is_common = password.lower() in [p.lower() for p in COMMON_PASSWORDS]
    details['is_common_password'] = is_common
    if is_common:
        score -= 30
        feedback.append('This is a commonly used password - avoid it!')
    else:
        score += 15
    
    # Pattern detection
    patterns = check_password_patterns(password)
    details['patterns_found'] = patterns
    if patterns:
        score -= len(patterns) * 10
        feedback.extend([f"Avoid predictable patterns: {p}" for p in patterns])
    else:
        score += 10
    
    # Dictionary word check (simple)
    words = re.findall(r'[a-zA-Z]{4,}', password)
    common_words = ['love', 'hate', 'work', 'home', 'life', 'time', 'year', 'good', 'best']
    found_words = [word for word in words if word.lower() in common_words]
    details['dictionary_words'] = found_words
    if found_words:
        score -= len(found_words) * 5
        feedback.append('Avoid using common dictionary words')
    
    # Character frequency analysis
    char_freq = Counter(password.lower())
    most_common_char, freq = char_freq.most_common(1)[0]
    details['most_frequent_char'] = {'char': most_common_char, 'frequency': freq}
    if freq > len(password) * 0.3:  # More than 30% of password is same character
        score -= 15
        feedback.append('Avoid repeating the same character too often')
    
    # Calculate entropy
    entropy = calculate_entropy(password)
    details['entropy'] = entropy
    
    # Estimate crack time (simplified)
    if entropy < 30:
        crack_time = 'Less than 1 hour'
    elif entropy < 40:
        crack_time = 'Few hours to days'
    elif entropy < 50:
        crack_time = 'Weeks to months'
    elif entropy < 60:
        crack_time = 'Years to decades'
    else:
        crack_time = 'Centuries or more'
    
    # Normalize score
    score = max(0, min(100, score))
    
    # Determine strength level
    if score >= 80:
        strength = 'Very Strong'
        strength_color = 'success'
    elif score >= 60:
        strength = 'Strong'
        strength_color = 'info'
    elif score >= 40:
        strength = 'Fair'
        strength_color = 'warning'
    elif score >= 20:
        strength = 'Weak'
        strength_color = 'warning'
    else:
        strength = 'Very Weak'
        strength_color = 'danger'
    
    # Generate positive feedback for strong passwords
    if score >= 70 and not feedback:
        feedback.append('Great password! Strong and secure.')
    
    return {
        'score': score,
        'strength': strength,
        'strength_color': strength_color,
        'feedback': feedback if feedback else ['Password meets basic security requirements'],
        'details': details,
        'entropy': entropy,
        'estimated_crack_time': crack_time
    }

def generate_password_suggestions():
    """Generate suggestions for creating strong passwords"""
    return [
        "Use a passphrase with 4+ random words (e.g., 'Coffee-Tree-Moon-42!')",
        "Combine unrelated words with numbers and symbols",
        "Use the first letters of a memorable sentence",
        "Replace some letters with numbers or symbols (but avoid obvious substitutions)",
        "Make it at least 12 characters long",
        "Avoid personal information (names, birthdays, addresses)",
        "Don't use keyboard patterns or repeated characters",
        "Consider using a password manager to generate strong passwords"
    ]