/**
 * vault-popup.js — Phishing Shield Vault UI
 *
 * All crypto operations are delegated to the background service worker via
 * chrome.runtime.sendMessage to keep the DEK isolated in SW memory.
 * This script handles only UI state and user interaction.
 */

'use strict';

import { generatePassword, passwordEntropy, assessPasswordStrength, checkPwnedPassword } from './vault-crypto.js';

// ── State ─────────────────────────────────────────────────────────────────────
let state = {
  screen:   'loading',
  entries:  [],       // decrypted, only in memory
  editId:   null,
  totpSecret: null,   // only during setup
};

// ── Temporizador de Autobloqueo por Inactividad ──
let inactivityTimer;
const INACTIVITY_TIMEOUT = 180 * 1000; // 3 minutos (180 segundos)

function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  const isUnlocked = state.screen === 'main' || state.screen === 'form';
  if (isUnlocked) {
    inactivityTimer = setTimeout(async () => {
      console.log("Vault bloqueado automáticamente por inactividad");
      await msg('vaultLock');
      document.getElementById('unlockPass').value = '';
      document.getElementById('unlockTotpCode').value = '';
      if (typeof clearAlert === 'function') clearAlert('unlockAlert');
      setScreen('unlock');
      showToast('Bóveda bloqueada por inactividad');
    }, INACTIVITY_TIMEOUT);
  }
}

// Registrar eventos de interacción para resetear el contador de inactividad
['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(evt => {
  window.addEventListener(evt, resetInactivityTimer);
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function msg(action, payload = {}) {
  return chrome.runtime.sendMessage({ action, ...payload });
}

function showToast(text = '✓ Copiado') {
  const el = document.getElementById('copyToast');
  el.textContent = text;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2000);
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); } catch { /* ignore */ }
  showToast();
}

function showAlert(id, text, type = 'error') {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.className = `alert ${type}`;
}
function clearAlert(id) {
  const el = document.getElementById(id);
  if (el) el.className = 'alert';
}

function setScreen(name) {
  // Force display:none on ALL screens (overrides any inline style)
  document.querySelectorAll('.screen').forEach(s => {
    s.classList.remove('active');
    s.style.display = 'none';
  });
  const el = document.getElementById(`screen-${name}`);
  if (el) {
    el.classList.add('active');
    el.style.display = name === 'loading' ? 'flex' : 'block';
  }
  state.screen = name;

  // Header controls visibility
  const isMain = name === 'main' || name === 'form';
  document.getElementById('btnLock').style.display      = isMain ? '' : 'none';
  document.getElementById('btnGenerator').style.display = isMain ? '' : 'none';
  document.getElementById('lockDot').className          = 'dot' + (isMain ? '' : ' locked');
  document.getElementById('lockLabel').textContent      = isMain ? 'Desbloqueado' : 'Bloqueado';

  // Reiniciar temporizador de inactividad
  if (typeof resetInactivityTimer === 'function') {
    resetInactivityTimer();
  }
}

const SCORE_PCT = [8, 30, 55, 78, 100];

function updateStrength(inputId, fillId, labelId, tipsId) {
  const val   = document.getElementById(inputId)?.value || '';
  const fill  = document.getElementById(fillId);
  const label = document.getElementById(labelId);
  const tips  = tipsId ? document.getElementById(tipsId) : null;

  if (!val) {
    if (fill)  { fill.style.width = '0%'; }
    if (label) label.textContent = '—';
    if (tips)  tips.textContent  = '';
    return;
  }

  const info = assessPasswordStrength(val);
  if (fill)  {
    fill.style.width = `${SCORE_PCT[info.score]}%`;
    fill.style.background = info.color;
    fill.style.boxShadow = `0 0 10px ${info.color}`;
  }
  if (label) label.textContent = `${info.label} (${info.entropy} bits)`;
  if (tips && info.suggestions.length) {
    tips.textContent = '💡 ' + info.suggestions[0];
  } else if (tips) {
    tips.textContent = '';
  }
}

// ── Eye toggle ────────────────────────────────────────────────────────────────
document.addEventListener('click', e => {
  const btn = e.target.closest('.eye-btn');
  if (!btn) return;
  const input = document.getElementById(btn.dataset.target);
  if (!input) return;
  input.type = input.type === 'password' ? 'text' : 'password';
  btn.textContent = input.type === 'password' ? '👁' : '🙈';
});

// ── Ripple feedback en todos los botones ────────────────────────────────────────
document.addEventListener('click', e => {
  const el = e.target.closest('.btn, .btn-icon, .opt-chip');
  if (!el) return;

  const rect = el.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const size = Math.max(rect.width, rect.height);

  el.classList.add('ripple-container');
  const ripple = document.createElement('span');
  ripple.className = 'ripple';
  ripple.style.width  = ripple.style.height = size + 'px';
  ripple.style.left = ((e.clientX ?? rect.left + rect.width / 2) - rect.left - size / 2) + 'px';
  ripple.style.top  = ((e.clientY ?? rect.top + rect.height / 2) - rect.top - size / 2) + 'px';
  el.appendChild(ripple);
  ripple.addEventListener('animationend', () => ripple.remove());
});

// ── Partículas flotantes de fondo ────────────────────────────────────────────────
function initParticles() {
  const container = document.getElementById('particlesBg');
  if (!container) return;
  if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;

  const COUNT = 16;
  for (let i = 0; i < COUNT; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    const size = 3 + Math.random() * 6;
    p.style.width  = size + 'px';
    p.style.height = size + 'px';
    p.style.left   = Math.random() * 100 + '%';
    p.style.setProperty('--drift', (Math.random() * 60 - 30) + 'px');
    const duration = 14 + Math.random() * 14;
    p.style.animationDuration = duration + 's';
    p.style.animationDelay = (Math.random() * duration) + 's';
    container.appendChild(p);
  }
}

// ── Init ──────────────────────────────────────────────────────────────────────
async function init() {
  setScreen('loading');
  try {
    const { initialized, unlocked, totpEnabled } = await msg('vaultStatus');
    if (!initialized) return setScreen('setup');
    if (unlocked) {
      await loadEntries();
      setScreen('main');
      await maybeApplyPendingPrefill();
      return;
    }
    if (totpEnabled) document.getElementById('unlockTotpField').style.display = '';
    setScreen('unlock');
  } catch (err) {
    console.error('[Vault] init error:', err);
    setScreen('setup');
  }
}

// ── Prefill entrante desde content-autofill.js ("+ Guardar contraseña") ────────
// El content script deja un prefill efímero en chrome.storage.session cuando el
// usuario pide guardar una credencial de un sitio nuevo. Lo recogemos apenas la
// bóveda queda desbloqueada, lo borramos de inmediato (nunca queda persistido) y
// abrimos el formulario de nueva credencial ya completado para que el usuario
// solo tenga que confirmar (pasando por las validaciones de duplicados y HIBP).
async function maybeApplyPendingPrefill() {
  const params = new URLSearchParams(location.search);
  if (params.get('prefill') !== '1') return;

  // Limpia el parámetro de la URL para que un refresh no vuelva a disparar esto.
  history.replaceState(null, '', location.pathname);

  try {
    const res = await chrome.storage.session.get('vault_prefill');
    const prefill = res?.vault_prefill;
    await chrome.storage.session.remove('vault_prefill');

    if (!prefill || (!prefill.url && !prefill.username && !prefill.password)) return;

    openForm({
      name:     prefill.name || '',
      url:      prefill.url || '',
      username: prefill.username || '',
      password: prefill.password || '',
    });

    showAlert(
      'formAlert',
      '🔑 Detectamos un inicio de sesión en este sitio. Revisa los datos y guarda tu contraseña.',
      'success'
    );
  } catch (err) {
    console.warn('[Vault] Error aplicando prefill:', err);
  }
}

// Cache para almacenar el estado de filtración (ID -> conteo de filtraciones)
const pwnedCache = new Map();

async function checkPwnedForEntries() {
  for (const entry of state.entries) {
    if (pwnedCache.has(entry.id)) continue;
    
    // Escaneo asíncrono no bloqueante contra la API de HIBP (K-anonymity)
    checkPwnedPassword(entry.password).then(count => {
      if (count > 0) {
        pwnedCache.set(entry.id, count);
        // Volver a renderizar la lista para mostrar el distintivo
        renderEntries(document.getElementById('searchInput')?.value || '');
      } else if (count === 0) {
        pwnedCache.set(entry.id, 0); // No filtrada, cacheada para evitar llamadas duplicadas
      }
    }).catch(err => {
      console.warn('[Vault] Error al verificar HIBP para:', entry.name, err);
    });
  }
}

// ── Load entries from background ──────────────────────────────────────────────
async function loadEntries() {
  const res = await msg('vaultGetEntries');
  if (res?.error) { console.error('[Vault]', res.error); return; }
  state.entries = res?.entries || [];
  renderEntries();
  checkPwnedForEntries();
}

// ── Render entry list ─────────────────────────────────────────────────────────
function renderEntries(filter = '') {
  const list  = document.getElementById('entryList');
  const empty = document.getElementById('emptyState');
  const q     = filter.toLowerCase();

  const visible = state.entries.filter(e =>
    !q || e.name.toLowerCase().includes(q) || (e.username || '').toLowerCase().includes(q)
  );

  list.innerHTML = '';

  if (!visible.length) {
    empty.style.display = '';
    return;
  }
  empty.style.display = 'none';

  const now = Date.now();
  const AGE_WARN_MS  = 90  * 24 * 60 * 60 * 1000; // 90 days
  const AGE_CRIT_MS  = 180 * 24 * 60 * 60 * 1000; // 180 days

  visible.forEach((entry, idx) => {
    const ageDays = entry.updatedAt ? Math.floor((now - entry.updatedAt) / 86400000) : null;
    let ageBadge = '';
    if (ageDays !== null && ageDays >= 180) {
      ageBadge = `<span style="font-size:10px;background:#7f1d1d;color:#fca5a5;padding:1px 5px;border-radius:4px;margin-left:4px" title="${ageDays} días sin cambiar">⏰ ${ageDays}d</span>`;
    } else if (ageDays !== null && ageDays >= 90) {
      ageBadge = `<span style="font-size:10px;background:#78350f;color:#fcd34d;padding:1px 5px;border-radius:4px;margin-left:4px" title="${ageDays} días sin cambiar">⏰ ${ageDays}d</span>`;
    }

    let pwnedBadge = '';
    if (pwnedCache.has(entry.id)) {
      const count = pwnedCache.get(entry.id);
      if (count > 0) {
        pwnedBadge = `<span style="font-size:10px;background:#dc2626;color:#ffffff;padding:1px 5px;border-radius:4px;margin-left:4px;font-weight:600" title="Esta contraseña ha sido expuesta ${count.toLocaleString()} veces en filtraciones de datos públicas.">⚠️ Filtrada</span>`;
      }
    }

    const item = document.createElement('div');
    item.className = 'entry-item';
    item.style.animationDelay = (idx * 0.045) + 's';
    item.innerHTML = `
      <div class="entry-favicon">${entry.name.charAt(0).toUpperCase()}</div>
      <div class="entry-info">
        <div class="entry-name">${escHtml(entry.name)}${ageBadge}${pwnedBadge}</div>
        <div class="entry-user">${escHtml(entry.username || '')}</div>
      </div>
      <div class="entry-actions">
        <button class="btn-icon" data-action="copy" data-id="${entry.id}" data-tooltip="Copiar contraseña" title="Copiar contraseña">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
        </button>
        <button class="btn-icon" data-action="edit" data-id="${entry.id}" data-tooltip="Editar" title="Editar">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
          </svg>
        </button>
        <button class="btn-icon" data-action="delete" data-id="${entry.id}" data-tooltip="Eliminar" title="Eliminar" style="color:var(--danger)">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/>
          </svg>
        </button>
      </div>`;
    list.appendChild(item);
  });
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

document.getElementById('entryList').addEventListener('click', async e => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const { action, id } = btn.dataset;
  const entry = state.entries.find(e => e.id === id);
  if (!entry) return;

  if (action === 'copy') {
    await copyText(entry.password);
  } else if (action === 'edit') {
    openForm(entry);
  } else if (action === 'delete') {
    if (!confirm(`¿Eliminar "${entry.name}"?`)) return;
    await msg('vaultDeleteEntry', { id });
    await loadEntries();
  }
});

document.getElementById('searchInput').addEventListener('input', e => {
  renderEntries(e.target.value);
});

// ── Setup flow ────────────────────────────────────────────────────────────────
document.getElementById('setupPass').addEventListener('input', () => {
  updateStrength('setupPass', 'strengthFill', 'strengthLabel', 'strengthTips');
});

document.getElementById('btnSetupNext').addEventListener('click', async () => {
  clearAlert('setupAlert');
  const pass    = document.getElementById('setupPass').value;
  const confirm = document.getElementById('setupPassConfirm').value;

  if (pass.length < 12) return showAlert('setupAlert', 'La contraseña debe tener al menos 12 caracteres.');
  if (pass !== confirm)  return showAlert('setupAlert', 'Las contraseñas no coinciden.');

  // 2FA (TOTP) deshabilitado — mejora futura
  await createVault(pass, false, null);
});

// Handlers de TOTP mantenidos pero inactivos (mejora futura)
document.getElementById('btnSetupBack').addEventListener('click', () => {});
document.getElementById('btnSetupCreate').addEventListener('click', () => {});

async function createVault(masterPassword, totpEnabled, totp) {
  const btn = document.getElementById('btnSetupNext');
  btn.disabled = true;
  btn.textContent = 'Creando…';
  try {
    const res = await msg('vaultSetup', { masterPassword, totpEnabled, totp });
    if (res?.error) { showAlert('setupAlert', res.error); return; }
    showAlert('setupAlert', '¡Vault creado exitosamente!', 'success');
    setTimeout(() => { setScreen('unlock'); }, 1200);
  } catch (err) {
    showAlert('setupAlert', 'Error al crear el vault: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Crear Vault';
  }
}

// ── Unlock flow ───────────────────────────────────────────────────────────────
document.getElementById('btnUnlock').addEventListener('click', async () => {
  clearAlert('unlockAlert');
  const pass = document.getElementById('unlockPass').value;
  const code = document.getElementById('unlockTotpCode').value.trim();
  if (!pass) return showAlert('unlockAlert', 'Ingresa tu contraseña maestra.');

  const btn = document.getElementById('btnUnlock');
  btn.disabled = true; btn.textContent = 'Desbloqueando…';
  try {
    const res = await msg('vaultUnlock', { masterPassword: pass, totpCode: code });
    if (res?.error) return showAlert('unlockAlert', res.error);
    await loadEntries();
    setScreen('main');
    await maybeApplyPendingPrefill();
  } catch (err) {
    showAlert('unlockAlert', 'Error: ' + err.message);
  } finally {
    btn.disabled = false; btn.textContent = 'Desbloquear';
  }
});

document.getElementById('btnResetVault').addEventListener('click', async () => {
  if (!confirm('⚠️ Esto borrará TODAS tus contraseñas guardadas. ¿Continuar?')) return;
  await msg('vaultReset');
  state.entries = [];
  // Hide TOTP field in case it was shown
  document.getElementById('unlockTotpField').style.display = 'none';
  document.getElementById('unlockTotpCode').value = '';
  document.getElementById('unlockPass').value = '';
  clearAlert('unlockAlert');
  setScreen('setup');
});

// ── Lock ──────────────────────────────────────────────────────────────────────
document.getElementById('btnLock').addEventListener('click', async () => {
  await msg('vaultLock');
  state.entries = [];
  document.getElementById('unlockPass').value = '';
  document.getElementById('unlockTotpCode').value = '';
  clearAlert('unlockAlert');
  setScreen('unlock');
});

// ── Add / Edit form ───────────────────────────────────────────────────────────
document.getElementById('btnAddEntry').addEventListener('click', () => openForm(null));

function openForm(entry) {
  state.editId = entry?.id || null;
  document.getElementById('formTitle').textContent = entry ? 'Editar credencial' : 'Nueva credencial';
  document.getElementById('fId').value       = entry?.id || '';
  document.getElementById('fName').value     = entry?.name || '';
  document.getElementById('fUrl').value      = entry?.url || '';
  document.getElementById('fUsername').value = entry?.username || '';
  document.getElementById('fPassword').value = entry?.password || '';
  document.getElementById('fNotes').value    = entry?.notes || '';
  clearAlert('formAlert');
  updateStrength('fPassword', 'formStrengthFill', 'formStrengthLabel', 'formStrengthTips');
  setScreen('form');
}

document.getElementById('fPassword').addEventListener('input', () => {
  updateStrength('fPassword', 'formStrengthFill', 'formStrengthLabel', 'formStrengthTips');
});

document.getElementById('btnFormCancel').addEventListener('click',  () => setScreen('main'));
document.getElementById('btnFormCancel2').addEventListener('click', () => setScreen('main'));

document.getElementById('btnFormSave').addEventListener('click', async () => {
  clearAlert('formAlert');
  const name     = document.getElementById('fName').value.trim();
  const url      = document.getElementById('fUrl').value.trim();
  const username = document.getElementById('fUsername').value.trim();
  const password = document.getElementById('fPassword').value;
  const notes    = document.getElementById('fNotes').value.trim();

  if (!name)     return showAlert('formAlert', 'El nombre del sitio es obligatorio.');
  if (!password) return showAlert('formAlert', 'La contraseña es obligatoria.');

  const entry = {
    id:       state.editId || crypto.randomUUID(),
    name, url, username, password, notes,
    updatedAt: Date.now(),
    createdAt: state.editId
      ? (state.entries.find(e => e.id === state.editId)?.createdAt || Date.now())
      : Date.now(),
  };

  const btn = document.getElementById('btnFormSave');
  btn.disabled = true; btn.textContent = 'Verificando…';
  try {
    // ── Duplicate password detection ──
    const dupEntry = state.entries.find(e => e.id !== entry.id && e.password === password);
    if (dupEntry) {
      const proceed = confirm(
        `⚠️ Esta contraseña ya está siendo usada en "${dupEntry.name}".\n\n` +
        `Reutilizar contraseñas entre sitios es un riesgo de seguridad.\n\n` +
        `¿Guardar de todas formas?`
      );
      if (!proceed) { btn.disabled = false; btn.textContent = 'Guardar'; return; }
    }

    // ── HIBP breach check (k-anonymity) ──
    const pwnedCount = await checkPwnedPassword(password);
    if (pwnedCount > 0) {
      const times = pwnedCount.toLocaleString();
      const proceed = confirm(
        `⚠️ Esta contraseña fue encontrada ${times} veces en brechas de datos conocidas.\n\n` +
        `Se recomienda usar una contraseña diferente.\n\n` +
        `¿Guardar de todas formas?`
      );
      if (!proceed) { btn.disabled = false; btn.textContent = 'Guardar'; return; }
    } else if (pwnedCount === 0) {
      // Not breached — show subtle confirmation in alert
      showAlert('formAlert', '✅ Contraseña no encontrada en brechas conocidas (HIBP).', 'success');
    }
    // pwnedCount === -1 means network error, proceed silently

    btn.textContent = 'Guardando…';
    const res = await msg('vaultSaveEntry', { entry });
    if (res?.error) return showAlert('formAlert', res.error);
    await loadEntries();
    setScreen('main');
  } catch (err) {
    showAlert('formAlert', 'Error al guardar: ' + err.message);
  } finally {
    btn.disabled = false; btn.textContent = 'Guardar';
  }
});

// ── Generator ─────────────────────────────────────────────────────────────────
const genOpts = { upper: true, lower: true, numbers: true, symbols: true };
let lastGenerated = '';

function regenerate() {
  const length = parseInt(document.getElementById('genLength').value, 10);
  const pass   = generatePassword(length, genOpts);
  lastGenerated = pass;
  document.getElementById('generatedPass').textContent = pass;
  const info = assessPasswordStrength(pass);
  const fill = document.getElementById('entropyFill');
  fill.style.width      = `${SCORE_PCT[info.score]}%`;
  fill.style.background = info.color;
  fill.style.boxShadow  = `0 0 10px ${info.color}`;
  document.getElementById('entropyLabel').textContent =
    `${info.label} — ${info.entropy} bits de entropía`;
}

document.getElementById('btnGenerator').addEventListener('click', () => {
  document.getElementById('generatorModal').classList.add('open');
  regenerate();
});

document.getElementById('genLength').addEventListener('input', e => {
  document.getElementById('genLengthVal').textContent = e.target.value;
  regenerate();
});

document.querySelectorAll('.opt-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    const opt = chip.dataset.opt;
    genOpts[opt] = !genOpts[opt];
    chip.classList.toggle('on', genOpts[opt]);
    regenerate();
  });
});

document.getElementById('btnRegenerate').addEventListener('click', regenerate);
document.getElementById('btnCopyGen').addEventListener('click', () => copyText(lastGenerated));
document.getElementById('btnCloseGen').addEventListener('click', () => {
  document.getElementById('generatorModal').classList.remove('open');
});
document.getElementById('btnUsePassword').addEventListener('click', () => {
  const pwd = lastGenerated;
  document.getElementById('generatorModal').classList.remove('open');
  // Open form FIRST so the fields exist, then set password (openForm clears them)
  if (state.screen !== 'form') { openForm(null); }
  document.getElementById('fPassword').value = pwd;
  updateStrength('fPassword', 'formStrengthFill', 'formStrengthLabel', 'formStrengthTips');
});

// Quick generate from form
document.getElementById('btnQuickGen').addEventListener('click', () => {
  document.getElementById('generatorModal').classList.add('open');
  regenerate();
});

// ── Start ─────────────────────────────────────────────────────────────────────
initParticles();
init();
