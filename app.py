"""
app.py - Password Security Analyzer for FinTech Authentication
Educational Flask application demonstrating password security concepts.
For educational purposes only. Uses only dummy/anonymized datasets.
"""

import os
import sqlite3
import random
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify)

from modules.password_strength import check_password_strength, get_common_passwords
from modules.password_hash import (hash_password, verify_password,
                                   extract_hash_info, demo_hash_comparison,
                                   compare_algorithms)
from modules.security_report import generate_full_report
from modules.simulations import (
    get_credential_stuffing_demo,
    get_offline_cracking_demo,
    get_hash_comparison_data,
)

# ---------------------------------------------------------------------------
# App Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cynsec-fintech-2024-!@#$%SecretKey')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

DATABASE = os.path.join(os.path.dirname(__file__), 'database.db')

# ---------------------------------------------------------------------------
# Database Helpers
# ---------------------------------------------------------------------------

def get_db():
    """Get a database connection with row_factory for dict-like access."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables and seed dummy audit accounts."""
    conn = get_db()
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_strength TEXT NOT NULL DEFAULT 'Unknown',
            mfa_enabled INTEGER NOT NULL DEFAULT 0,
            mfa_secret TEXT,
            login_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    ''')

    # Dummy accounts for offline audit demonstration only
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dummy_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alias TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            original_password TEXT NOT NULL,
            is_weak INTEGER NOT NULL DEFAULT 0,
            strength_level TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    ''')

    # Seed dummy accounts if table is empty
    cursor.execute("SELECT COUNT(*) FROM dummy_accounts")
    if cursor.fetchone()[0] == 0:
        _seed_dummy_accounts(cursor)

    conn.commit()
    conn.close()


def _seed_dummy_accounts(cursor):
    """
    Seed dummy/anonymized test accounts for the offline password audit demo.
    These are intentionally crafted weak AND strong passwords for educational display.
    """
    dummy_data = [
        # (alias, password, is_weak)
        ('demo_user_001', 'password123', True),
        ('demo_user_002', 'qwerty', True),
        ('demo_user_003', 'admin', True),
        ('demo_user_004', '123456', True),
        ('demo_user_005', 'letmein', True),
        ('demo_user_006', 'welcome1', True),
        ('demo_user_007', 'monkey123', True),
        ('demo_user_008', 'sunshine', True),
        ('demo_user_009', 'iloveyou', True),
        ('demo_user_010', 'dragon99', True),
        ('demo_user_011', 'Tr0ub4dor&3!Secure', False),
        ('demo_user_012', 'C0rr3ctH0rs3B@tt3ry!', False),
        ('demo_user_013', 'FinT3ch$ecure2024!', False),
        ('demo_user_014', 'L0ng&Str0ng#Pass!2024', False),
        ('demo_user_015', 'Xk9#mP2!vQr&nL5@', False),
    ]

    for alias, pwd, is_weak in dummy_data:
        strength_info = check_password_strength(pwd)
        hashed = hash_password(pwd)
        cursor.execute(
            '''INSERT INTO dummy_accounts (alias, password_hash, original_password, is_weak, strength_level)
               VALUES (?, ?, ?, ?, ?)''',
            (alias, hashed, pwd, 1 if is_weak else 0, strength_info['level'])
        )


# ---------------------------------------------------------------------------
# Auth Decorator
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    """Landing page."""
    return render_template('index.html')


# ── Registration ────────────────────────────────────────────────────────────

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        # Input validation
        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if not email or '@' not in email:
            errors.append('Please enter a valid email address.')
        if password != confirm:
            errors.append('Passwords do not match.')

        strength = check_password_strength(password)
        if strength['score'] < 30:
            errors.append('Password is too weak. Please follow the requirements.')
        if not strength['checks'].get('length'):
            errors.append('Password must be at least 12 characters.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('register.html', username=username, email=email)

        # Hash and store — NEVER store plain text
        pw_hash = hash_password(password)

        conn = get_db()
        try:
            conn.execute(
                '''INSERT INTO users (username, email, password_hash, password_strength)
                   VALUES (?, ?, ?, ?)''',
                (username, email, pw_hash, strength['level'])
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')
        finally:
            conn.close()

    return render_template('register.html')


# ── Login ────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()

        if user is None:
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')

        # Check account lockout
        if user['locked_until']:
            locked_until = datetime.fromisoformat(user['locked_until'])
            if datetime.now() < locked_until:
                remaining = (locked_until - datetime.now()).seconds // 60
                flash(f'Account locked. Try again in {remaining + 1} minute(s).', 'danger')
                return render_template('login.html')

        if verify_password(password, user['password_hash']):
            # Reset failed attempts
            conn = get_db()
            conn.execute('UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = ?',
                         (user['id'],))
            conn.commit()
            conn.close()

            # MFA demo flow
            session['pre_mfa_user_id'] = user['id']
            session['pre_mfa_username'] = user['username']

            if user['mfa_enabled']:
                otp = _generate_otp()
                session['mfa_otp'] = otp
                session['mfa_expires'] = (datetime.now() + timedelta(minutes=5)).isoformat()
                flash(f'🔐 MFA Demo – Your OTP is: <strong>{otp}</strong> (valid 5 min)', 'info')
                return redirect(url_for('mfa_verify'))
            else:
                _complete_login(user['id'], user['username'])
                flash(f'Welcome back, {user["username"]}! 🎉', 'success')
                return redirect(url_for('dashboard'))
        else:
            # Increment failed attempts
            attempts = (user['login_attempts'] or 0) + 1
            locked_until = None
            if attempts >= 5:
                locked_until = (datetime.now() + timedelta(minutes=15)).isoformat()
                flash('Too many failed attempts. Account locked for 15 minutes.', 'danger')
            else:
                flash(f'Invalid password. {5 - attempts} attempt(s) remaining.', 'danger')

            conn = get_db()
            conn.execute(
                'UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?',
                (attempts, locked_until, user['id'])
            )
            conn.commit()
            conn.close()

    return render_template('login.html')


def _generate_otp() -> str:
    """Generate a 6-digit numeric OTP for demo purposes."""
    return ''.join(random.choices(string.digits, k=6))


def _complete_login(user_id: int, username: str):
    """Finalize session after successful authentication."""
    session.permanent = True
    session['user_id'] = user_id
    session['username'] = username
    session.pop('pre_mfa_user_id', None)
    session.pop('pre_mfa_username', None)


# ── MFA Verification ─────────────────────────────────────────────────────────

@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    if 'pre_mfa_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        stored_otp = session.get('mfa_otp')
        expires_str = session.get('mfa_expires')

        if not stored_otp or not expires_str:
            flash('OTP session expired. Please log in again.', 'danger')
            return redirect(url_for('login'))

        expires = datetime.fromisoformat(expires_str)
        if datetime.now() > expires:
            flash('OTP has expired. Please log in again.', 'danger')
            return redirect(url_for('login'))

        if entered_otp == stored_otp:
            user_id = session.pop('pre_mfa_user_id')
            username = session.pop('pre_mfa_username')
            session.pop('mfa_otp', None)
            session.pop('mfa_expires', None)
            _complete_login(user_id, username)
            flash(f'MFA successful! Welcome, {username}! 🔐✅', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('mfa_verify.html')


# ── Logout ────────────────────────────────────────────────────────────────────

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out securely.', 'info')
    return redirect(url_for('index'))


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    today = datetime.now().date().isoformat()
    today_count = conn.execute(
        "SELECT COUNT(*) FROM users WHERE DATE(created_at) = ?", (today,)
    ).fetchone()[0]
    weak = conn.execute(
        "SELECT COUNT(*) FROM users WHERE password_strength = 'Weak'"
    ).fetchone()[0]
    medium = conn.execute(
        "SELECT COUNT(*) FROM users WHERE password_strength = 'Medium'"
    ).fetchone()[0]
    strong = conn.execute(
        "SELECT COUNT(*) FROM users WHERE password_strength IN ('Strong','Very Strong')"
    ).fetchone()[0]
    very_strong = conn.execute(
        "SELECT COUNT(*) FROM users WHERE password_strength = 'Very Strong'"
    ).fetchone()[0]
    mfa_on = conn.execute(
        'SELECT COUNT(*) FROM users WHERE mfa_enabled = 1'
    ).fetchone()[0]
    conn.close()

    security_score = max(0, 100 - int((weak / total * 60) if total else 0))

    return render_template('dashboard.html',
        username=session['username'],
        total_users=total,
        today_count=today_count,
        weak_count=weak,
        medium_count=medium,
        strong_count=strong,
        very_strong_count=very_strong,
        mfa_enabled=mfa_on,
        credential_stuffing_attempts=6,
        offline_attack_simulations=2,
        security_score=security_score
    )


# ── Password Strength API ─────────────────────────────────────────────────────

@app.route('/api/check-password', methods=['POST'])
def api_check_password():
    """REST endpoint for live password strength checking."""
    data = request.get_json()
    password = data.get('password', '') if data else ''
    result = check_password_strength(password)
    return jsonify(result)


# ── Hash Demo ─────────────────────────────────────────────────────────────────

@app.route('/hash-demo')
@login_required
def hash_demo():
    demo = demo_hash_comparison()
    comparison = compare_algorithms('DemoP@ss2024!')
    return render_template('hash_demo.html',
        demo=demo,
        comparison=comparison,
        username=session['username']
    )


# ── Hash Algorithm API ────────────────────────────────────────────────────────

@app.route('/api/hash-password', methods=['POST'])
@login_required
def api_hash_password():
    """Generate hash info for a typed password (educational display only)."""
    data = request.get_json()
    password = data.get('password', '') if data else ''
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    hashed = hash_password(password)
    info = extract_hash_info(hashed)
    return jsonify({'hash': hashed, 'info': info})


# ── Credential Stuffing Simulator ──────────────────────────────────────────

@app.route('/credential-stuffing-simulator')
@login_required
def credential_stuffing_simulator():
    demo = get_credential_stuffing_demo()
    return render_template('credential_stuffing_simulator.html',
        demo=demo,
        username=session['username']
    )


# ── Offline Password Cracking Simulator ───────────────────────────────────

@app.route('/offline-password-cracking')
@login_required
def offline_password_cracking():
    md5_demo = get_offline_cracking_demo('md5')
    bcrypt_demo = get_offline_cracking_demo('bcrypt')
    return render_template('offline_password_cracking.html',
        md5_demo=md5_demo,
        bcrypt_demo=bcrypt_demo,
        username=session['username']
    )


# ── Password Hash Comparison ───────────────────────────────────────────────

@app.route('/hash-comparison')
@login_required
def hash_comparison():
    comparison_data = get_hash_comparison_data()
    return render_template('hash_comparison.html',
        comparison_data=comparison_data,
        username=session['username']
    )


# ── Password Audit ────────────────────────────────────────────────────────────

@app.route('/audit')
@login_required
def audit():
    """
    Controlled offline password audit using ONLY dummy test accounts.
    No real user passwords are accessed or exposed.
    """
    conn = get_db()
    dummy_accounts = conn.execute(
        'SELECT * FROM dummy_accounts ORDER BY is_weak DESC'
    ).fetchall()
    total = len(dummy_accounts)
    weak_count = sum(1 for a in dummy_accounts if a['is_weak'])
    strong_count = total - weak_count
    weak_pct = round((weak_count / total * 100), 1) if total else 0
    conn.close()

    common_passwords = get_common_passwords()

    return render_template('audit.html',
        dummy_accounts=dummy_accounts,
        total=total,
        weak_count=weak_count,
        strong_count=strong_count,
        weak_pct=weak_pct,
        common_passwords=common_passwords[:20],
        username=session['username']
    )


# ── MFA Enable Toggle ─────────────────────────────────────────────────────────

@app.route('/toggle-mfa', methods=['POST'])
@login_required
def toggle_mfa():
    conn = get_db()
    user = conn.execute(
        'SELECT mfa_enabled FROM users WHERE id = ?', (session['user_id'],)
    ).fetchone()
    new_state = 0 if user['mfa_enabled'] else 1
    conn.execute(
        'UPDATE users SET mfa_enabled = ? WHERE id = ?',
        (new_state, session['user_id'])
    )
    conn.commit()
    conn.close()
    status = 'enabled' if new_state else 'disabled'
    flash(f'MFA has been {status} for your account.', 'success')
    return redirect(url_for('dashboard'))


# ── Security Report ───────────────────────────────────────────────────────────

@app.route('/report')
@login_required
def report():
    conn = get_db()
    report_data = generate_full_report(conn)
    conn.close()
    return render_template('report.html',
        report=report_data,
        username=session['username']
    )


# ── Recommendations ───────────────────────────────────────────────────────────

@app.route('/recommendations')
@login_required
def recommendations():
    return render_template('recommendations.html',
        username=session['username']
    )


# ---------------------------------------------------------------------------
# App Entry Point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    print("=" * 55)
    print("  Password Security Analyzer — FinTech Edition")
    print("  Educational Tool | Dummy Data Only")
    print("  Running at: http://127.0.0.1:5000")
    print("=" * 55)
    app.run(debug=True, host='0.0.0.0', port=5000)
