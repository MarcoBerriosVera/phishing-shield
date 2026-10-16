/* ============================================================
   PHISHING SHIELD — Landing micro-interactions
   Scroll-reveal + ripple feedback for a more premium feel.
   ============================================================ */

document.addEventListener('DOMContentLoaded', () => {
    initScrollReveal();
    initRipple();
    initNavbarScrollState();
});

/* ─── Scroll Reveal ─── */
function initScrollReveal() {
    const targets = document.querySelectorAll(
        '.component-card, .plan-card, .law-document-glass, ' +
        '.compliance-content > *, .c-feat, .downloads-box, .section-header'
    );

    if (!targets.length) return;

    targets.forEach((el, i) => {
        el.classList.add('reveal');
        el.style.transitionDelay = ((i % 6) * 0.08).toFixed(2) + 's';
    });

    if (!('IntersectionObserver' in window)) {
        targets.forEach(el => el.classList.add('in-view'));
        return;
    }

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('in-view');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.15, rootMargin: '0px 0px -60px 0px' });

    targets.forEach(el => observer.observe(el));
}

/* ─── Ripple Click Feedback ─── */
function initRipple() {
    document.querySelectorAll('.btn').forEach(btn => {
        btn.classList.add('ripple-container');
        btn.addEventListener('click', (e) => {
            const rect = btn.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const ripple = document.createElement('span');
            ripple.className = 'ripple';
            ripple.style.width = ripple.style.height = size + 'px';
            ripple.style.left = (e.clientX - rect.left - size / 2) + 'px';
            ripple.style.top = (e.clientY - rect.top - size / 2) + 'px';
            btn.appendChild(ripple);
            ripple.addEventListener('animationend', () => ripple.remove());
        });
    });
}

/* ─── Navbar subtle state change on scroll ─── */
function initNavbarScrollState() {
    const navbar = document.querySelector('.navbar');
    if (!navbar) return;

    let ticking = false;
    window.addEventListener('scroll', () => {
        if (ticking) return;
        ticking = true;
        requestAnimationFrame(() => {
            navbar.classList.toggle('scrolled', window.scrollY > 40);
            ticking = false;
        });
    });
}
