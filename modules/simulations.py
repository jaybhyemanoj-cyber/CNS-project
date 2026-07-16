"""Educational simulation helpers for password security demos.

These functions intentionally use dummy/anonymized data only and never
perform real credential attacks against real accounts.
"""

from __future__ import annotations

from typing import Dict, List


def get_credential_stuffing_demo() -> Dict[str, object]:
    """Return dummy leaked-style credentials for educational simulation."""
    sample_accounts = [
        {"email": "demo1@gmail.com", "password": "password123"},
        {"email": "demo2@gmail.com", "password": "admin123"},
        {"email": "demo3@gmail.com", "password": "welcome123"},
    ]

    attempted_logins = [
        {"email": "demo1@gmail.com", "password": "password123", "result": "Successful Login"},
        {"email": "demo2@gmail.com", "password": "Password123!", "result": "Failed Login"},
        {"email": "demo3@gmail.com", "password": "welcome123", "result": "Successful Login"},
        {"email": "demo1@gmail.com", "password": "password1234", "result": "Failed Login"},
        {"email": "demo2@gmail.com", "password": "admin123", "result": "Successful Login"},
        {"email": "demo3@gmail.com", "password": "Welcome321", "result": "Failed Login"},
    ]

    successful = sum(1 for attempt in attempted_logins if attempt["result"] == "Successful Login")
    failed = len(attempted_logins) - successful
    detected = successful >= 2

    return {
        "sample_accounts": sample_accounts,
        "attempts": attempted_logins,
        "total_attempts": len(attempted_logins),
        "successful_logins": successful,
        "failed_logins": failed,
        "credential_stuffing_detected": detected,
        "warning": (
            "Credential stuffing uses reused usernames and passwords from prior breaches "
            "to try many accounts quickly. This demo only shows the concept with dummy data."
        ),
    }


def get_offline_cracking_demo(mode: str) -> Dict[str, object]:
    """Return educational offline cracking examples with fake timing."""
    if mode == "bcrypt":
        return {
            "title": "bcrypt Hash Demo",
            "hash": "$2b$12$demo.simulated.hash.for.education.12345",
            "attack_type": "Dictionary Attack + Brute Force",
            "passwords_tried": 42000,
            "time_taken": "14.8s",
            "recovered_password": "Not Recovered",
            "attack_failed": True,
            "message": "bcrypt resisted the simulated attack because it is intentionally slow and cost-adjusted.",
        }

    return {
        "title": "Weak MD5 Hash Demo",
        "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
        "attack_type": "Dictionary Attack",
        "passwords_tried": 184,
        "time_taken": "0.3s",
        "recovered_password": "password",
        "attack_failed": False,
        "message": "A weak hash like MD5 can be recovered quickly with a small dictionary of common passwords.",
    }


def get_hash_comparison_data() -> List[Dict[str, str]]:
    """Return comparison data for password hashing algorithms."""
    return [
        {
            "name": "MD5",
            "purpose": "Legacy checksums and non-password use",
            "security_level": "Very Weak",
            "speed": "Very Fast",
            "resistance": "Very Low",
            "recommended": "Avoid for passwords",
            "score": 20,
        },
        {
            "name": "SHA-1",
            "purpose": "Legacy hashing; not recommended for passwords",
            "security_level": "Weak",
            "speed": "Fast",
            "resistance": "Low",
            "recommended": "Avoid for password storage",
            "score": 35,
        },
        {
            "name": "SHA-256",
            "purpose": "General hashing with better resistance",
            "security_level": "Moderate",
            "speed": "Fast",
            "resistance": "Medium",
            "recommended": "Better than MD5/SHA-1, but still not ideal for passwords",
            "score": 55,
        },
        {
            "name": "bcrypt",
            "purpose": "Password hashing with salt and work factor",
            "security_level": "Strong",
            "speed": "Slow",
            "resistance": "High",
            "recommended": "Recommended for password storage",
            "score": 85,
        },
        {
            "name": "Argon2",
            "purpose": "Memory-hard password hashing",
            "security_level": "Very Strong",
            "speed": "Very Slow",
            "resistance": "Very High",
            "recommended": "Best modern choice for password hashing",
            "score": 95,
        },
    ]
