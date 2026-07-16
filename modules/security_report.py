"""
security_report.py
Module for generating security audit reports from the SQLite database.
Uses only dummy/anonymized test data — no real user passwords are exposed.
"""

from datetime import datetime


def generate_full_report(db_conn) -> dict:
    """
    Generate a complete security audit report from the database.

    Args:
        db_conn: SQLite database connection object.

    Returns:
        dict: Full security report data.
    """
    cursor = db_conn.cursor()

    # --- User Statistics ---
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    from datetime import date
    today = date.today().isoformat()
    cursor.execute("SELECT COUNT(*) FROM users WHERE DATE(created_at) = ?", (today,))
    registered_today = cursor.fetchone()[0]

    # --- Password Strength Breakdown ---
    cursor.execute("SELECT COUNT(*) FROM users WHERE password_strength = 'Weak'")
    weak_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users WHERE password_strength = 'Medium'")
    medium_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users WHERE password_strength IN ('Strong', 'Very Strong')")
    strong_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users WHERE password_strength = 'Very Strong'")
    very_strong_count = cursor.fetchone()[0]

    # --- MFA Statistics ---
    cursor.execute("SELECT COUNT(*) FROM users WHERE mfa_enabled = 1")
    mfa_enabled_count = cursor.fetchone()[0]

    # --- Dummy account audit (offline only, anonymized) ---
    cursor.execute("SELECT COUNT(*) FROM dummy_accounts WHERE is_weak = 1")
    dummy_weak = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM dummy_accounts")
    dummy_total = cursor.fetchone()[0]

    # --- Security score calculation ---
    security_score = _calculate_security_score(
        total_users, weak_count, strong_count, mfa_enabled_count
    )

    weak_percentage = round((weak_count / total_users * 100), 1) if total_users > 0 else 0
    mfa_percentage = round((mfa_enabled_count / total_users * 100), 1) if total_users > 0 else 0

    return {
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_users': total_users,
        'registered_today': registered_today,
        'password_stats': {
            'weak': weak_count,
            'medium': medium_count,
            'strong': strong_count,
            'very_strong': very_strong_count,
            'weak_percentage': weak_percentage,
        },
        'mfa_stats': {
            'enabled': mfa_enabled_count,
            'disabled': total_users - mfa_enabled_count,
            'percentage': mfa_percentage,
        },
        'dummy_audit': {
            'total': dummy_total,
            'weak': dummy_weak,
            'strong': dummy_total - dummy_weak,
            'weak_percentage': round((dummy_weak / dummy_total * 100), 1) if dummy_total > 0 else 0
        },
        'security_score': security_score,
        'hash_algorithm': 'bcrypt (cost factor: 12)',
        'policy_status': {
            'min_length_12': True,
            'requires_uppercase': True,
            'requires_lowercase': True,
            'requires_digit': True,
            'requires_special': True,
            'common_password_check': True,
            'bcrypt_hashing': True,
            'session_timeout': True,
            'mfa_available': True,
        },
        'recommendations': _get_recommendations(weak_percentage, mfa_percentage)
    }


def _calculate_security_score(total, weak, strong, mfa_enabled) -> dict:
    """Calculate an overall security score (0-100)."""
    if total == 0:
        return {'score': 0, 'grade': 'N/A', 'color': 'secondary'}

    # Weight: 50% password strength, 30% MFA adoption, 20% baseline policy
    password_score = max(0, 50 - (weak / total * 50))
    mfa_score = (mfa_enabled / total) * 30
    policy_score = 20  # Baseline for having bcrypt + policy

    total_score = round(password_score + mfa_score + policy_score)

    if total_score >= 85:
        grade, color = 'A', 'success'
    elif total_score >= 70:
        grade, color = 'B', 'info'
    elif total_score >= 55:
        grade, color = 'C', 'warning'
    else:
        grade, color = 'D', 'danger'

    return {'score': total_score, 'grade': grade, 'color': color}


def _get_recommendations(weak_pct: float, mfa_pct: float) -> list:
    """Generate contextual security recommendations."""
    recs = [
        {
            'priority': 'High',
            'icon': 'shield-alt',
            'title': 'Enforce bcrypt with Cost Factor ≥ 12',
            'description': 'Ensure all passwords are hashed with bcrypt (rounds=12) to resist brute-force attacks.'
        },
        {
            'priority': 'High',
            'icon': 'key',
            'title': 'Enable Multi-Factor Authentication (MFA)',
            'description': 'MFA adds a second layer of defense against credential stuffing and phishing attacks.'
        },
        {
            'priority': 'Medium',
            'icon': 'lock',
            'title': 'Implement Account Lockout Policy',
            'description': 'Lock accounts after 5 failed login attempts for 15 minutes to prevent brute-force.'
        },
        {
            'priority': 'Medium',
            'icon': 'tachometer-alt',
            'title': 'Rate Limiting on Login Endpoint',
            'description': 'Apply rate limiting (e.g., 10 requests/minute) to prevent credential stuffing attacks.'
        },
        {
            'priority': 'High' if weak_pct > 20 else 'Medium',
            'icon': 'exclamation-triangle',
            'title': 'Enforce Strong Password Policy',
            'description': f'{weak_pct}% of users have weak passwords. Enforce 12+ chars with complexity requirements.'
        },
        {
            'priority': 'Low',
            'icon': 'history',
            'title': 'Password History Enforcement',
            'description': 'Prevent users from reusing their last 5 passwords during password changes.'
        },
        {
            'priority': 'Medium',
            'icon': 'user-secret',
            'title': 'Consider Argon2 for New Systems',
            'description': 'Argon2 (winner of the Password Hashing Competition) offers memory-hard hashing.'
        },
        {
            'priority': 'Low',
            'icon': 'clock',
            'title': 'Session Timeout Configuration',
            'description': 'Implement 30-minute idle session timeout with secure, httpOnly, SameSite cookies.'
        },
    ]
    return recs
