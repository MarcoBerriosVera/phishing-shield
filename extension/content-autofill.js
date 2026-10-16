/**
 * content-autofill.js — Phishing Shield Vault Autofill
 *
 * Detects login forms on any page and shows a small autofill overlay
 * near the username/password fields. Only runs on non-blocked pages.
 * Never requests credentials from the vault directly — always asks
 * the background SW (which holds the DEK).
 */

'use strict';

// ── Config ────────────────────────────────────────────────────────────────────
const OVERLAY_ID   = '__ps_autofill_overlay';
const BADGE_ID     = '__ps_autofill_badge';

// ── Login form detection ──────────────────────────────────────────────────────
function isLoginForm(form) {
  const inputs = [...form.querySelectorAll('input')];
  const hasPassword = inputs.some(i => i.type === 'password');
  const hasText     = inputs.some(i => ['text', 'email', 'tel'].includes(i.type));
  return hasPassword && hasText;
}

function getLoginForms() {
  return [...document.querySelectorAll('form')].filter(isLoginForm);
}

// Find the first visible password input on the page (may not be in a <form>)
function getPasswordInput() {
  return [...document.querySelectorAll('input[type="password"]')]
    .find(el => el.offsetParent !== null);
}

// ── Overlay UI ────────────────────────────────────────────────────────────────
function createOverlay() {
  if (document.getElementById(OVERLAY_ID)) return;
  const div = document.createElement('div');
  div.id = OVERLAY_ID;
  div.setAttribute('role', 'dialog');
  div.setAttribute('aria-label', 'Phishing Shield — Autorrelleno');
  div.style.cssText = `
    position: fixed;
    z-index: 2147483647;
    background: #1a1b2e;
    border: 1px solid #00e5a0;
    border-radius: 8px;
    padding: 8px 10px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.5);
    font-family: system-ui, sans-serif;
    font-size: 13px;
    color: #e2e8f0;
    max-width: 280px;
    min-width: 200px;
    display: none;
  `;
  document.body.appendChild(div);
  return div;
}

function positionNear(overlay, target) {
  const rect = target.getBoundingClientRect();
  const top  = rect.bottom + window.scrollY + 4;
  const left = Math.min(rect.left + window.scrollX, window.innerWidth - 290);
  overlay.style.top  = `${top}px`;
  overlay.style.left = `${left}px`;
  overlay.style.position = 'absolute';
}

function renderEntries(overlay, entries, onSelect, onAddNew) {
  overlay.innerHTML = '';

  if (!entries.length) {
    const empty = document.createElement('div');
    empty.style.cssText = 'display:flex;align-items:center;gap:6px;margin-bottom:8px;';
    empty.innerHTML = `
      <span style="color:#00e5a0">🔑</span>
      <span style="color:#94a3b8;font-size:12px">No hay credenciales guardadas para este sitio</span>`;
    overlay.appendChild(empty);

    const addBtn = document.createElement('button');
    addBtn.type = 'button';
    addBtn.style.cssText = `
      display:flex; align-items:center; justify-content:center; gap:6px;
      width:100%; background:#0f2e22; border:1px solid #00e5a0; border-radius:6px;
      padding:7px 8px; color:#00e5a0; cursor:pointer; font-size:12px; font-weight:600;
    `;
    addBtn.innerHTML = `<span aria-hidden="true">➕</span><span>Guardar contraseña para este sitio</span>`;
    addBtn.addEventListener('click', onAddNew);
    addBtn.addEventListener('mouseenter', () => addBtn.style.background = '#123a2c');
    addBtn.addEventListener('mouseleave', () => addBtn.style.background = '#0f2e22');
    overlay.appendChild(addBtn);
    return;
  }

  const header = document.createElement('div');
  header.textContent = '🔑 Phishing Shield — Credenciales guardadas';
  header.style.cssText = 'font-size:11px;color:#00e5a0;margin-bottom:6px;font-weight:600;';
  overlay.appendChild(header);

  entries.forEach(entry => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.style.cssText = `
      display:block; width:100%; text-align:left; background:#252641;
      border:1px solid #334155; border-radius:6px; padding:6px 8px;
      color:#e2e8f0; cursor:pointer; font-size:12px; margin-bottom:4px;
    `;
    btn.innerHTML = `
      <div style="font-weight:600">${escHtml(entry.name)}</div>
      <div style="color:#94a3b8">${escHtml(entry.username || '')}</div>`;
    btn.addEventListener('click', () => onSelect(entry));
    btn.addEventListener('mouseenter', () => btn.style.borderColor = '#00e5a0');
    btn.addEventListener('mouseleave', () => btn.style.borderColor = '#334155');
    overlay.appendChild(btn);
  });
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Autofill ──────────────────────────────────────────────────────────────────
function findUsernameInput(form) {
  return form
    ? form.querySelector('input[type="email"], input[type="text"], input[name*="user"], input[name*="email"], input[id*="user"], input[id*="email"]')
    : document.querySelector('input[type="email"], input[type="text"]');
}

function autofillEntry(form, entry) {
  // Fill username / email
  const userInput = findUsernameInput(form);

  if (userInput) {
    setInputValue(userInput, entry.username || '');
  }

  // Fill password
  const passInput = form
    ? form.querySelector('input[type="password"]')
    : getPasswordInput();

  if (passInput) {
    setInputValue(passInput, entry.password);
    passInput.focus();
  }
}

/** Trigger framework-compatible change events after setting value */
function setInputValue(input, value) {
  const nativeInputValueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  if (nativeInputValueSetter) {
    nativeInputValueSetter.call(input, value);
  } else {
    input.value = value;
  }
  input.dispatchEvent(new Event('input',  { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

// ── Badge icon ────────────────────────────────────────────────────────────────
function createBadge(passwordInput) {
  if (document.getElementById(BADGE_ID)) return;

  const badge = document.createElement('button');
  badge.id    = BADGE_ID;
  badge.type  = 'button';
  badge.title = 'Autorrelleno — Phishing Shield';
  badge.setAttribute('aria-label', 'Autorrelleno de contraseña');
  badge.style.cssText = `
    position: absolute;
    z-index: 2147483646;
    background: #1a1b2e;
    border: 1px solid #00e5a0;
    border-radius: 4px;
    padding: 2px 5px;
    font-size: 12px;
    cursor: pointer;
    color: #00e5a0;
    line-height: 1;
    box-shadow: 0 2px 6px rgba(0,0,0,0.4);
  `;
  badge.textContent = '🔑';

  // Position badge inside/beside the password input
  const rect = passwordInput.getBoundingClientRect();
  badge.style.top  = `${rect.top  + window.scrollY + (rect.height - 20) / 2}px`;
  badge.style.left = `${rect.right + window.scrollX - 28}px`;
  badge.style.position = 'absolute';

  document.body.appendChild(badge);
  return badge;
}

// ── Save new credential (empty state "+ Guardar contraseña") ───────────────────
// El vault nunca se toca desde el content script: solo se arma un "prefill"
// (sitio, usuario, contraseña ya tipeada si existe) y se entrega al SW, que lo
// guarda de forma efímera en chrome.storage.session para que vault-popup.html
// lo recoja y lo borre inmediatamente. Así la contraseña nunca queda expuesta
// en una URL ni en el historial de navegación.
function queueVaultPrefill(passwordInput, form) {
  const userInput = findUsernameInput(form);

  const prefill = {
    name:     location.hostname.replace(/^www\./, ''),
    url:      location.href,
    username: userInput?.value || '',
    password: passwordInput?.value || '',
  };

  chrome.runtime.sendMessage({ action: 'vaultQueuePrefill', prefill }).catch(() => {});
}

// ── Main ──────────────────────────────────────────────────────────────────────
let overlay = null;
let currentForm = null;

function hideOverlay() {
  if (overlay) overlay.style.display = 'none';
}

async function showAutofillFor(target, form) {
  const host = location.hostname;

  let entries;
  try {
    const res = await chrome.runtime.sendMessage({ action: 'vaultGetAutofill', host });
    entries = res?.entries || [];
  } catch {
    return; // vault offline o bloqueado
  }

  if (!overlay) overlay = createOverlay();
  if (!overlay) return;

  currentForm = form;
  positionNear(overlay, target);
  renderEntries(
    overlay,
    entries,
    entry => {
      autofillEntry(currentForm, entry);
      hideOverlay();
    },
    () => {
      queueVaultPrefill(target, form);
      hideOverlay();
    }
  );
  overlay.style.display = 'block';
}

function init() {
  // Close overlay on outside click
  document.addEventListener('click', e => {
    if (overlay && !overlay.contains(e.target) && e.target.id !== BADGE_ID) {
      hideOverlay();
    }
  });

  // Monitorear cuando el usuario termina de escribir una contraseña de forma manual
  document.addEventListener('change', async e => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement)) return;
    if (el.type !== 'password') return;

    const password = el.value;
    if (!password) return;

    const host = location.hostname;
    try {
      const res = await chrome.runtime.sendMessage({ action: 'vaultCheckManualPassword', password, host });
      if (res?.match) {
        alert(
          `⚠️ ADVERTENCIA DE SEGURIDAD (Phishing Shield):\n\n` +
          `Detectamos que acabas de ingresar la contraseña correspondiente a tu cuenta de "${res.matchedName}" (${res.matchedHost}) en este dominio (${host}).\n\n` +
          `Reutilizar contraseñas en sitios no autorizados aumenta drásticamente el riesgo de phishing y robo de credenciales.\n\n` +
          `Por favor, asegúrate de que este sitio web sea legítimo y de confianza antes de continuar.`
        );
      }
    } catch (err) {
      console.warn('[PhishingShield] Error al verificar credencial escrita manualmente:', err);
    }
  });

  // Show badge near password inputs on focus
  document.addEventListener('focusin', e => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement)) return;
    if (el.type !== 'password') return;

    const form = el.closest('form') || null;
    // Remove old badge
    document.getElementById(BADGE_ID)?.remove();

    const badge = createBadge(el);
    if (!badge) return;

    badge.addEventListener('click', async ev => {
      ev.stopPropagation();
      await showAutofillFor(el, form);
    });

    // Also trigger on focus of the password field itself
    showAutofillFor(el, form);
  });

  // Observe dynamically injected forms (SPAs)
  const observer = new MutationObserver(() => {
    const passInput = getPasswordInput();
    if (passInput && !document.getElementById(BADGE_ID)) {
      // Re-trigger badge setup on next focus
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

// Only run if the page is not the extension's own block page
if (!location.href.includes(chrome.runtime.id)) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
}
