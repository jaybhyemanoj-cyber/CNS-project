# Password Security Analyzer — FinTech Authentication

> **Educational Tool | Dummy Data Only | No Real Attacks**

A complete Flask web application demonstrating password security concepts for a FinTech micro-lending context: bcrypt hashing, live strength analysis, MFA simulation, offline password audit (dummy accounts), and security reporting.

---

## Features

| Module | Description |
|--------|-------------|
| 🔐 Registration | bcrypt-hashed accounts, live strength meter, policy enforcement |
| 🔑 Secure Login | bcrypt verification, account lockout, session management |
| 📊 Dashboard | KPI cards, Pie/Bar charts, security score |
| #️⃣ Hash Demo | Interactive bcrypt generator, salt breakdown, algorithm comparison |
| 🔍 Password Audit | Offline audit on pre-seeded dummy accounts only |
| 📱 MFA Simulation | 6-digit OTP demo flow (no SMS API required) |
| 📄 Report | Executive summary, policy status, prioritized recommendations |
| 💡 Recommendations | Threat landscape, best-practice cards, MFA flow diagram |

---

## Quick Start

### Prerequisites
- Python 3.8+
- pip

### Installation

```bash
# 1. Navigate to project folder
cd Password-Security-Analyzer

# 2. Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

Open your browser at **http://127.0.0.1:5000**

---

## Project Structure

```
Password-Security-Analyzer/
├── app.py                   # Flask application, all routes
├── database.db              # SQLite DB (auto-created on first run)
├── requirements.txt
├── modules/
│   ├── password_strength.py # Strength analysis & scoring
│   ├── password_hash.py     # bcrypt hashing & hash parsing
│   └── security_report.py  # Report generation
├── templates/
│   ├── base.html            # Shared layout, navbar, flash toasts
│   ├── index.html           # Landing page
│   ├── register.html        # Registration + live strength meter
│   ├── login.html           # Login with bcrypt verification
│   ├── mfa_verify.html      # OTP verification demo
│   ├── dashboard.html       # Charts + KPI dashboard
│   ├── hash_demo.html       # Interactive hash demo
│   ├── audit.html           # Dummy account password audit
│   ├── report.html          # Security Assessment Report
│   └── recommendations.html # Best practices & threat landscape
└── static/
    ├── css/style.css        # Dark cyber glassmorphism theme
    └── js/main.js           # Theme toggle, particles, animations
```

---

## How bcrypt Works

bcrypt is an **adaptive hashing function** designed specifically for passwords:

1. **Salt Generation** — A unique 22-character random salt is generated per password.
2. **Blowfish Cipher** — The password + salt is processed through the Blowfish cipher.
3. **Cost Factor (rounds)** — The process is repeated **2^cost** times (cost=12 → 4096 iterations).
4. **Output** — A 60-character string embedding the algorithm version, cost, salt, and hash.

```
$2b$12$SomeSalt22CharsHere..HashPortion31CharsHere.........x
│   │  │                    │
│   │  salt (22 chars)      hash (31 chars)
│   cost factor (12)
algorithm version (2b)
```

### Why bcrypt vs MD5/SHA-1?

| Algorithm | Speed | Salt | Attackability |
|-----------|-------|------|---------------|
| MD5       | Instant | None | Seconds |
| SHA-1     | Very fast | None | Minutes |
| SHA-256   | Fast | None | Hours–Days |
| **bcrypt** | **Slow by design** | **Built-in unique** | **Years–Centuries** |

---

## Hashing vs Encryption

| | Hashing | Encryption |
|---|---------|-----------|
| Reversible | ❌ One-way | ✅ Two-way |
| Key required | No | Yes |
| Use case | Password storage | Data in transit |
| Example | bcrypt, SHA-256 | AES-256, RSA |

**Passwords must always be hashed, never encrypted** — encryption implies the original can be recovered if the key is compromised.

---

## How Credential Stuffing Works

1. **Data Breach** — Attacker obtains leaked username/password pairs from a breached site.
2. **Automation** — Tools automatically replay these credentials against other sites.
3. **Success Rate** — Because many users reuse passwords, ~0.1–2% of attempts succeed.
4. **Mitigation** — Strong unique passwords + MFA + rate limiting + account lockout defeat this attack.

---

## How MFA Prevents Attacks

Even if an attacker has the correct password, MFA adds a second factor:

```
Credential Stuffing → Correct Username + Password ✅
                                                   ↓
                                 MFA challenge →  OTP Required ❌
                                 Attacker blocked (no phone access)
```

---

## Security Best Practices Implemented

- ✅ bcrypt with cost factor 12
- ✅ Parameterized SQL queries (no SQL injection)
- ✅ Input validation on all forms
- ✅ Account lockout (5 attempts → 15 min)
- ✅ Flask session with 30-minute timeout
- ✅ HttpOnly + SameSite session cookies
- ✅ Passwords never stored or logged in plain text
- ✅ Constant-time comparison via `bcrypt.checkpw()`

---

## Educational Disclaimer

This tool is for **educational purposes only**. All password audits are performed against pre-seeded **dummy/anonymized test accounts** created specifically for demonstration. No real user passwords are exposed, and no brute-force or unauthorized access capabilities are included.

---

## Future Enhancements

- [ ] TOTP-based MFA with QR code (pyotp + qrcode)
- [ ] Argon2 hashing option comparison
- [ ] Email OTP delivery via SMTP
- [ ] Password change history tracking
- [ ] Export report as PDF (WeasyPrint)
- [ ] Admin panel for managing dummy audit accounts
- [ ] Redis-based rate limiting
- [ ] HTTPS/TLS configuration guide
