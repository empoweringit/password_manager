# password_utils.py

import secrets
import string
import math

SIMILAR_CHARACTERS = "il1Lo0O"

def generate_password(length: int = 16,
                      use_upper: bool = True,
                      use_lower: bool = True,
                      use_digits: bool = True,
                      use_punctuation: bool = True,
                      exclude_similar: bool = False,
                      custom_words: list = None) -> str:
    """
    Generates a secure password based on specified criteria.
    """
    if not any([use_upper, use_lower, use_digits, use_punctuation]):
        raise ValueError("At least one character type must be selected.")

    # Build character pool based on selected categories
    character_pools = {
        'upper': string.ascii_uppercase if use_upper else '',
        'lower': string.ascii_lowercase if use_lower else '',
        'digits': string.digits if use_digits else '',
        'punctuation': string.punctuation if use_punctuation else ''
    }
    characters = ''.join(character_pools.values())

    if exclude_similar:
        characters = ''.join(c for c in characters if c not in SIMILAR_CHARACTERS)

    if not characters and not custom_words:
        raise ValueError("No characters available to generate password.")

    # Calculate total length of custom words
    total_custom_length = sum(len(word) for word in custom_words) if custom_words else 0
    if total_custom_length > length:
        raise ValueError("Combined length of custom words exceeds the total password length.")

    remaining_length = length - total_custom_length

    # Ensure inclusion of at least one character from each selected category
    required_chars = []
    if use_upper:
        required_chars.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        required_chars.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        required_chars.append(secrets.choice(string.digits))
    if use_punctuation:
        required_chars.append(secrets.choice(string.punctuation))

    if remaining_length < len(required_chars):
        raise ValueError("Password length too short for the selected character types.")

    # Initialize password with required characters
    password = required_chars.copy()

    # Fill the rest of the password length with random choices from the pool
    if characters:
        password += [secrets.choice(characters) for _ in range(remaining_length - len(required_chars))]

    # Insert custom words at random positions
    if custom_words:
        for word in custom_words:
            insert_pos = secrets.randbelow(len(password) + 1)
            password.insert(insert_pos, word)

    # Shuffle to prevent predictable sequences
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)


def calculate_password_entropy(length: int, pool_size: int) -> float:
    """
    Calculates the entropy of a password.
    """
    if pool_size <= 0:
        return 0.0
    return length * math.log2(pool_size)


def assess_strength(password: str) -> tuple:
    """
    Assesses the strength of the password based on entropy.
    Returns a tuple of (strength_label, progress_value, color, entropy).
    """
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_punct = any(c in string.punctuation for c in password)

    # Calculate pool size based on character sets used
    pool_size = (
        (26 if has_lower else 0) +
        (26 if has_upper else 0) +
        (10 if has_digit else 0) +
        (len(string.punctuation) if has_punct else 0)
    )

    entropy = calculate_password_entropy(length, pool_size)

    # Define strength thresholds
    if entropy >= 90:
        return "Very Strong", 100, "success", entropy
    elif entropy >= 70:
        return "Strong", 75, "warning", entropy
    elif entropy >= 50:
        return "Moderate", 50, "info", entropy
    else:
        return "Weak", 25, "danger", entropy


def get_password_recommendations(password: str, settings: dict) -> list:
    """
    Generates recommendations to improve password strength based on current settings.
    """
    recommendations = []
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_punct = any(c in string.punctuation for c in password)

    if length < 12:
        recommendations.append("Increase password length to 12 or more characters.")
    if settings.get('use_upper') and not has_upper:
        recommendations.append("Include uppercase letters.")
    if settings.get('use_lower') and not has_lower:
        recommendations.append("Include lowercase letters.")
    if settings.get('use_digits') and not has_digit:
        recommendations.append("Include digits.")
    if settings.get('use_punctuation') and not has_punct:
        recommendations.append("Include punctuation symbols.")
    if settings.get('exclude_similar'):
        recommendations.append("Avoid excluding similar characters to increase character pool size.")

    return recommendations
