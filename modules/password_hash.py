"""
password_hash.py
Module for password hashing and verification using bcrypt.
Educational demonstration of secure password storage.
"""

import bcrypt
import hashlib
import base64


def hash_password(plain_password: str) -> str:
    """
    Hash a plaintext password using bcrypt with automatic salt generation.

    bcrypt automatically:
    - Generates a unique random salt per password
    - Applies the salt + hash 2^cost iterations (default cost=12)
    - Embeds the salt in the resulting hash string

    Args:
        plain_password (str): The plaintext password to hash.

    Returns:
        str: The bcrypt hash string (includes algorithm, cost, salt, hash).
    """
    password_bytes = plain_password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a stored bcrypt hash.
    Uses constant-time comparison to prevent timing attacks.

    Args:
        plain_password (str): The plaintext password to verify.
        hashed_password (str): The stored bcrypt hash.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    try:
        password_bytes = plain_password.encode('utf-8')
        hash_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except Exception:
        return False


def extract_hash_info(bcrypt_hash: str) -> dict:
    """
    Parse and extract educational information from a bcrypt hash string.

    A bcrypt hash has the format:
    $2b$[cost]$[22-char salt][31-char hash]

    Args:
        bcrypt_hash (str): The full bcrypt hash string.

    Returns:
        dict: Parsed hash components for educational display.
    """
    try:
        parts = bcrypt_hash.split('$')
        if len(parts) < 4:
            return {'error': 'Invalid bcrypt hash format'}

        algorithm = f"${parts[1]}$"  # e.g., $2b$
        cost_factor = int(parts[2])  # e.g., 12
        salt_and_hash = parts[3]     # 53-char string: 22 salt + 31 hash

        salt_portion = salt_and_hash[:22]   # First 22 chars = salt
        hash_portion = salt_and_hash[22:]   # Remaining 31 chars = hash

        return {
            'full_hash': bcrypt_hash,
            'algorithm': f'bcrypt ({algorithm})',
            'cost_factor': cost_factor,
            'iterations': 2 ** cost_factor,
            'salt': salt_portion,
            'hash_portion': hash_portion,
            'total_length': len(bcrypt_hash),
            'algorithm_version': parts[1],
        }
    except Exception as e:
        return {'error': str(e)}


def demo_hash_comparison() -> dict:
    """
    Educational demonstration showing how the same password produces
    different hashes due to unique salts (rainbow table resistance).

    Returns:
        dict: Demo data showing two different hashes for the same password.
    """
    demo_password = "DemoP@ss2024!"
    hash1 = hash_password(demo_password)
    hash2 = hash_password(demo_password)

    return {
        'password': demo_password,
        'hash_1': hash1,
        'hash_2': hash2,
        'are_different': hash1 != hash2,
        'both_verify': (
            verify_password(demo_password, hash1) and
            verify_password(demo_password, hash2)
        ),
        'lesson': (
            'Even the same password produces a completely different hash each time '
            'due to the random salt embedded in bcrypt. This makes rainbow table '
            'attacks impossible.'
        )
    }


def compare_algorithms(plain_password: str) -> dict:
    """
    Compare bcrypt with weaker/older hashing algorithms for education.
    This demonstrates WHY bcrypt is preferred over MD5/SHA1.

    Args:
        plain_password (str): The password to hash with multiple algorithms.

    Returns:
        dict: Hash outputs from different algorithms with security notes.
    """
    md5_hash = hashlib.md5(plain_password.encode()).hexdigest()
    sha1_hash = hashlib.sha1(plain_password.encode()).hexdigest()
    sha256_hash = hashlib.sha256(plain_password.encode()).hexdigest()
    bcrypt_hash_val = hash_password(plain_password)

    return {
        'password': plain_password,
        'algorithms': [
            {
                'name': 'MD5',
                'hash': md5_hash,
                'length': len(md5_hash),
                'secure': False,
                'reason': 'Extremely fast — vulnerable to brute-force & rainbow tables. DO NOT USE for passwords.',
                'crack_time': 'Seconds'
            },
            {
                'name': 'SHA-1',
                'hash': sha1_hash,
                'length': len(sha1_hash),
                'secure': False,
                'reason': 'Fast computation — no salt, vulnerable to pre-computed rainbow tables.',
                'crack_time': 'Minutes'
            },
            {
                'name': 'SHA-256',
                'hash': sha256_hash,
                'length': len(sha256_hash),
                'secure': False,
                'reason': 'Still fast without salt/key-stretching. Not suitable as standalone for passwords.',
                'crack_time': 'Hours–Days'
            },
            {
                'name': 'bcrypt',
                'hash': bcrypt_hash_val,
                'length': len(bcrypt_hash_val),
                'secure': True,
                'reason': 'Adaptive cost factor, built-in unique salt, intentionally slow. Industry standard.',
                'crack_time': 'Years–Centuries'
            }
        ]
    }
