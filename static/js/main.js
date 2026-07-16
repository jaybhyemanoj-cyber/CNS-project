/**
 * main.js — CynSecAnalyze Interactive Features
 * Password Security Analyzer for FinTech Authentication
 * Educational use only.
 */

// ── Theme Toggle ──────────────────────────────────────────────
(function initTheme() {
    const saved = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    updateThemeIcon(saved);
})();

function updateThemeIcon(theme) {
    const icon = document.getElementById('themeIcon');
    if (!icon) return;
    icon.className = theme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
}

const themeToggle = document.getElementById('themeToggle');
if (themeToggle) {
    themeToggle.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
        updateThemeIcon(next);
    });
}

// ── Password Visibility Toggle ────────────────────────────────
function togglePwd(inputId, eyeId) {
    const input = document.getElementById(inputId);
    const icon  = document.getElementById(eyeId);
    if (!input || !icon) return;
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'fas fa-eye';
    }
}

// ── Toast Notification ────────────────────────────────────────
function showToast(message, type = 'info') {
    const container = document.getElementById('flashContainer') || createFlashContainer();
    const icons = { success: 'fa-check-circle', danger: 'fa-exclamation-circle',
                    warning: 'fa-exclamation-triangle', info: 'fa-info-circle' };
    const toast = document.createElement('div');
    toast.className = `toast-notification toast-${type} show`;
    toast.innerHTML = `
        <div class="toast-icon"><i class="fas ${icons[type] || icons.info}"></i></div>
        <div class="toast-message">${message}</div>
        <button class="toast-close" onclick="this.parentElement.remove()"><i class="fas fa-times"></i></button>
    `;
    container.appendChild(toast);
    setTimeout(() => toast && toast.remove(), 5000);
}

function createFlashContainer() {
    const div = document.createElement('div');
    div.id = 'flashContainer';
    div.className = 'flash-container';
    document.body.appendChild(div);
    return div;
}

// Auto-dismiss existing flash toasts after 5 seconds
document.addEventListener('DOMContentLoaded', () => {
    const toasts = document.querySelectorAll('.toast-notification');
    toasts.forEach((t, i) => {
        setTimeout(() => { t && t.remove(); }, 5000 + i * 500);
    });

    // Animate elements on scroll
    initScrollAnimations();

    // Particle background
    initParticles();
});

// ── Scroll Animations ─────────────────────────────────────────
function initScrollAnimations() {
    if (!window.IntersectionObserver) return;
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
            }
        });
    }, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });

    document.querySelectorAll('.glass-card, .kpi-card, .feature-card').forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
        observer.observe(el);
    });

    document.addEventListener('animateIn', () => {});
    const style = document.createElement('style');
    style.textContent = `.animate-in { opacity: 1 !important; transform: translateY(0) !important; }`;
    document.head.appendChild(style);
}

// ── Particle Background ───────────────────────────────────────
function initParticles() {
    const container = document.getElementById('particles');
    if (!container) return;

    const count = window.innerWidth < 768 ? 15 : 30;
    for (let i = 0; i < count; i++) {
        const particle = document.createElement('div');
        particle.style.cssText = `
            position: absolute;
            width: ${Math.random() * 3 + 1}px;
            height: ${Math.random() * 3 + 1}px;
            background: ${Math.random() > 0.5 ? 'rgba(0,180,255,0.4)' : 'rgba(0,255,136,0.35)'};
            border-radius: 50%;
            left: ${Math.random() * 100}%;
            top: ${Math.random() * 100}%;
            animation: particle-float ${Math.random() * 8 + 6}s ease-in-out infinite;
            animation-delay: ${Math.random() * 5}s;
            pointer-events: none;
        `;
        container.appendChild(particle);
    }

    const pStyle = document.createElement('style');
    pStyle.textContent = `
        @keyframes particle-float {
            0%, 100% { transform: translateY(0) translateX(0); opacity: 0.4; }
            25% { transform: translateY(-30px) translateX(15px); opacity: 0.8; }
            50% { transform: translateY(-60px) translateX(-10px); opacity: 0.2; }
            75% { transform: translateY(-30px) translateX(20px); opacity: 0.6; }
        }
    `;
    document.head.appendChild(pStyle);
}

// ── Security Progress Bar Animation ──────────────────────────
window.addEventListener('load', () => {
    const fill = document.getElementById('secProgressFill');
    if (fill) {
        const target = fill.dataset.target || 0;
        setTimeout(() => { fill.style.width = target + '%'; }, 400);
    }
});

// ── Navbar Scroll Effect ──────────────────────────────────────
window.addEventListener('scroll', () => {
    const navbar = document.querySelector('.cyber-navbar');
    if (!navbar) return;
    navbar.style.background = window.scrollY > 50
        ? 'rgba(6,13,26,0.98)'
        : 'rgba(6,13,26,0.92)';
});
