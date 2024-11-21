import secrets
import string

def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, 
                     use_punctuation=True, exclude_similar=False, custom_words=None):
    """Generate a password based on the specified criteria."""
    chars = ''
    if use_upper:
        chars += string.ascii_uppercase
    if use_lower:
        chars += string.ascii_lowercase
    if use_digits:
        chars += string.digits
    if use_punctuation:
        chars += string.punctuation
        
    if exclude_similar:
        chars = chars.translate(str.maketrans('', '', 'Il1O0'))
        
    if not chars:
        raise ValueError("At least one character type must be selected")
        
    if custom_words:
        # Calculate remaining length after including custom words
        remaining_length = length - sum(len(word) for word in custom_words)
        if remaining_length < 0:
            raise ValueError("Custom words exceed desired password length")
            
        # Generate random characters for remaining length
        password = ''.join(secrets.choice(chars) for _ in range(remaining_length))
        
        # Insert custom words at random positions
        for word in custom_words:
            pos = secrets.randbelow(len(password) + 1)
            password = password[:pos] + word + password[pos:]
            
        return password
    else:
        return ''.join(secrets.choice(chars) for _ in range(length))

def assess_strength(password):
    """Assess the strength of a password."""
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    # Calculate entropy
    char_set_size = (
        (26 if has_upper else 0) +
        (26 if has_lower else 0) +
        (10 if has_digit else 0) +
        (32 if has_special else 0)
    )
    entropy = length * (char_set_size.bit_length() if char_set_size > 0 else 0)
    
    # Determine strength
    if length < 8 or entropy < 35:
        return "Weak", 25, "danger", entropy
    elif length < 12 or entropy < 60:
        return "Moderate", 50, "warning", entropy
    elif length < 16 or entropy < 80:
        return "Strong", 75, "success", entropy
    else:
        return "Very Strong", 100, "success", entropy

def get_password_recommendations(password, settings):
    """Get recommendations for improving password strength."""
    recommendations = []
    
    if len(password) < 12:
        recommendations.append("Increase password length to at least 12 characters")
    
    if not any(c.isupper() for c in password) and settings.get('use_upper', True):
        recommendations.append("Include uppercase letters")
    
    if not any(c.islower() for c in password) and settings.get('use_lower', True):
        recommendations.append("Include lowercase letters")
    
    if not any(c.isdigit() for c in password) and settings.get('use_digits', True):
        recommendations.append("Include numbers")
    
    if not any(not c.isalnum() for c in password) and settings.get('use_punctuation', True):
        recommendations.append("Include special characters")
    
    return recommendations
