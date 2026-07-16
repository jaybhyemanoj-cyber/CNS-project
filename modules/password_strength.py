"""
password_strength.py
Module to analyze password strength and provide improvement suggestions.
Educational use only - demonstrates what makes a password strong or weak.
"""

import re
import string

# Common/weak passwords list (dummy educational dataset)
COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein", "qwerty",
    "abc123", "monkey", "1234567890", "dragon", "master", "hello",
    "football", "shadow", "sunshine", "princess", "welcome", "login",
    "solo", "passw0rd", "starwars", "pass", "test123", "iloveyou",
    "admin123", "root", "toor", "password1", "123456789", "12345678",
    "111111", "000000", "1234", "12345", "123123", "654321",
    "superman", "batman", "password12", "password!", "qwerty123"
]


def check_password_strength(password: str) -> dict:
    """
    Evaluate password strength and return score, label, and suggestions.

    Args:
        password (str): The password to analyze.

    Returns:
        dict: {
            'score': int (0-100),
            'level': str ('Weak' | 'Medium' | 'Strong' | 'Very Strong'),
            'suggestions': list[str],
            'checks': dict of individual checks
        }
    """
    suggestions = []
    checks = {}
    score = 0

    # --- Length checks ---
    length = len(password)
    checks['length'] = length >= 12
    if length == 0:
        return {
            'score': 0,
            'level': 'Weak',
            'suggestions': ['Password cannot be empty.'],
            'checks': checks
        }
    if length < 8:
        suggestions.append('Use at least 8 characters (12+ recommended).')
        score += 5
    elif length < 12:
        suggestions.append('Use at least 12 characters for better security.')
        score += 20
    elif length < 16:
        score += 30
    else:
        score += 40

    # --- Character variety checks ---
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', password))

    checks['uppercase'] = has_upper
    checks['lowercase'] = has_lower
    checks['digit'] = has_digit
    checks['special'] = has_special

    if has_upper:
        score += 10
    else:
        suggestions.append('Add at least one uppercase letter (A-Z).')

    if has_lower:
        score += 10
    else:
        suggestions.append('Add at least one lowercase letter (a-z).')

    if has_digit:
        score += 10
    else:
        suggestions.append('Add at least one number (0-9).')

    if has_special:
        score += 15
    else:
        suggestions.append('Add special characters (e.g., !, @, #, $).')

    # --- Common password check ---
    if password.lower() in COMMON_PASSWORDS:
        checks['not_common'] = False
        suggestions.append('Avoid common passwords like "password123" or "qwerty".')
        score = max(0, score - 30)
    else:
        checks['not_common'] = True
        score += 15

    # --- Repetition / sequential patterns ---
    has_repeat = bool(re.search(r'(.)\1{2,}', password))
    checks['no_repeat'] = not has_repeat
    if has_repeat:
        suggestions.append('Avoid repeated characters (e.g., "aaa", "111").')
        score = max(0, score - 10)

    sequential_patterns = ['012', '123', '234', '345', '456', '567', '678',
                           '789', '890', 'abc', 'bcd', 'cde', 'def', 'efg',
                           'qwe', 'asd', 'zxc']
    has_seq = any(p in password.lower() for p in sequential_patterns)
    checks['no_sequential'] = not has_seq
    if has_seq:
        suggestions.append('Avoid sequential patterns (e.g., "123", "abc", "qwe").')
        score = max(0, score - 5)

    # --- Clamp score ---
    score = max(0, min(score, 100))

    # --- Determine level ---
    if score < 30:
        level = 'Weak'
    elif score < 55:
        level = 'Medium'
    elif score < 80:
        level = 'Strong'
    else:
        level = 'Very Strong'

    if not suggestions:
        suggestions.append('Great password! Consider using a password manager to store it safely.')

    return {
        'score': score,
        'level': level,
        'suggestions': suggestions,
        'checks': checks
    }


def is_common_password(password: str) -> bool:
    """Return True if the password is in the common passwords list."""
    return password.lower() in COMMON_PASSWORDS


def get_common_passwords() -> list:
    """Return the list of common weak passwords (for educational audit only)."""
    return COMMON_PASSWORDS.copy()
