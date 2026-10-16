'use strict';

// ── Vault — cifrado local (chrome.storage.local) ───────────────────────────
import {
  deriveKEK, generateSalt, generateDEK, encryptDEK, decryptDEK,
  exportDEK, importDEK, encryptData, decryptData,
  generateTOTPSecret, verifyTOTP,
} from './vault-crypto.js';

const VAULT_STORAGE_KEY = 'ps_vault';
const VAULT_DEK_KEY     = 'vault_dek_b64';

let vaultDEK = null;

async function vaultRead() {
  const res = await chrome.storage.local.get(VAULT_STORAGE_KEY);
  return res[VAULT_STORAGE_KEY] || { initialized: false };
}
async function vaultWrite(data) {
  await chrome.storage.local.set({ [VAULT_STORAGE_KEY]: data });
}
async function saveDEKToSession(dek) {
  await chrome.storage.session.set({ [VAULT_DEK_KEY]: await exportDEK(dek) });
}
async function restoreDEKFromSession() {
  if (vaultDEK) return true;
  const res = await chrome.storage.session.get(VAULT_DEK_KEY);
  if (!res[VAULT_DEK_KEY]) return false;
  vaultDEK = await importDEK(res[VAULT_DEK_KEY]);
  return true;
}
async function lockVault() {
  vaultDEK = null;
  await chrome.storage.session.remove(VAULT_DEK_KEY);
}
function resetAutoLock() {
  chrome.alarms.create('vaultAutoLock', { delayInMinutes: 15 });
}
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'vaultAutoLock') lockVault();
});

async function handleVaultMessage(msg) {
  switch (msg.action) {
    case 'vaultStatus': {
      const data = await vaultRead();
      const initialized = data.initialized === true;
      const unlocked = initialized && !!(await restoreDEKFromSession());
      return { initialized, unlocked, totpEnabled: data.totp_enabled || false };
    }
    case 'vaultSetup': {
      const { masterPassword, totpEnabled, totp } = msg;
      if (totpEnabled && totp?.secret) {
        if (!(await verifyTOTP(totp.secret, totp.code))) return { error: 'Código TOTP inválido.' };
      }
      const salt = generateSalt();
      const kek  = await deriveKEK(masterPassword, salt);
      const dek  = await generateDEK();
      const { enc: dekEnc, iv: dekIV }   = await encryptDEK(dek, kek);
      const { enc: blobEnc, iv: blobIV } = await encryptData(dek, JSON.stringify([]));
      const payload = { initialized: true, salt, dek_enc: dekEnc, dek_iv: dekIV,
                        blob_enc: blobEnc, blob_iv: blobIV,
                        totp_enabled: totpEnabled, totp_enc: '', totp_iv: '' };
      if (totpEnabled && totp?.secret) {
        const { enc, iv } = await encryptData(dek, totp.secret);
        payload.totp_enc = enc; payload.totp_iv = iv;
      }
      await vaultWrite(payload);
      vaultDEK = dek; await saveDEKToSession(dek); resetAutoLock();
      return { ok: true };
    }
    case 'vaultUnlock': {
      const { masterPassword, totpCode } = msg;
      const data = await vaultRead();
      if (!data.initialized) return { error: 'Vault no inicializado.' };
      let kek, dek;
      try { kek = await deriveKEK(masterPassword, data.salt); } catch { return { error: 'Error al derivar clave.' }; }
      try { dek = await decryptDEK(data.dek_enc, data.dek_iv, kek); } catch { return { error: 'Contraseña maestra incorrecta.' }; }
      if (data.totp_enabled) {
        if (!totpCode) return { error: 'Se requiere código TOTP.' };
        const secret = await decryptData(dek, data.totp_enc, data.totp_iv);
        if (!(await verifyTOTP(secret, totpCode))) return { error: 'Código TOTP incorrecto.' };
      }
      vaultDEK = dek; await saveDEKToSession(dek); resetAutoLock();
      return { ok: true };
    }
    case 'vaultLock':
      await lockVault(); return { ok: true };
    case 'vaultReset':
      await lockVault(); await chrome.storage.local.remove(VAULT_STORAGE_KEY); return { ok: true };
    case 'vaultGetEntries': {
      if (!(await restoreDEKFromSession())) return { error: 'Vault bloqueado.' };
      const data = await vaultRead();
      if (!data.initialized) return { entries: [] };
      const json = await decryptData(vaultDEK, data.blob_enc, data.blob_iv);
      resetAutoLock(); return { entries: JSON.parse(json) };
    }
    case 'vaultSaveEntry': {
      if (!(await restoreDEKFromSession())) return { error: 'Vault bloqueado.' };
      const data = await vaultRead();
      const entries = JSON.parse(await decryptData(vaultDEK, data.blob_enc, data.blob_iv));
      const idx = entries.findIndex(e => e.id === msg.entry.id);
      if (idx >= 0) entries[idx] = msg.entry; else entries.push(msg.entry);
      const { enc: blobEnc, iv: blobIV } = await encryptData(vaultDEK, JSON.stringify(entries));
      await vaultWrite({ ...data, blob_enc: blobEnc, blob_iv: blobIV });
      resetAutoLock(); return { ok: true };
    }
    case 'vaultDeleteEntry': {
      if (!(await restoreDEKFromSession())) return { error: 'Vault bloqueado.' };
      const data = await vaultRead();
      const entries = JSON.parse(await decryptData(vaultDEK, data.blob_enc, data.blob_iv))
                        .filter(e => e.id !== msg.id);
      const { enc: blobEnc, iv: blobIV } = await encryptData(vaultDEK, JSON.stringify(entries));
      await vaultWrite({ ...data, blob_enc: blobEnc, blob_iv: blobIV });
      resetAutoLock(); return { ok: true };
    }
    case 'vaultGetAutofill': {
      if (!(await restoreDEKFromSession())) return { entries: [] };
      const data = await vaultRead();
      if (!data.initialized) return { entries: [] };
      const all  = JSON.parse(await decryptData(vaultDEK, data.blob_enc, data.blob_iv));
      const host = msg.host?.toLowerCase() || '';
      return { entries: all.filter(e => { try { return new URL(e.url).hostname.toLowerCase() === host; } catch { return false; } }) };
    }
    case 'vaultGenerateTOTP':
      return { totpSecret: generateTOTPSecret() };
    case 'vaultCheckManualPassword': {
      if (!(await restoreDEKFromSession())) return { match: false };
      const data = await vaultRead();
      if (!data.initialized) return { match: false };
      const all = JSON.parse(await decryptData(vaultDEK, data.blob_enc, data.blob_iv));
      
      const { password, host } = msg;
      if (!password || !host) return { match: false };

      const targetHost = host.toLowerCase();
      const match = all.find(e => {
        if (e.password !== password) return false;
        try {
          const entryHost = new URL(e.url).hostname.toLowerCase();
          return entryHost && entryHost !== targetHost;
        } catch {
          return true;
        }
      });

      if (match) {
        let matchedHost = '';
        try { matchedHost = new URL(match.url).hostname; } catch { matchedHost = match.name; }
        return { 
          match: true, 
          matchedName: match.name, 
          matchedHost: matchedHost 
        };
      }
      return { match: false };
    }
    case 'vaultQueuePrefill': {
      // Guarda el prefill (sitio/usuario/contraseña) de forma efímera en
      // chrome.storage.session — nunca en una URL ni en storage persistente —
      // y abre/enfoca la pestaña de la bóveda para que el usuario la revise
      // y confirme el guardado (con las validaciones de duplicados y HIBP).
      await chrome.storage.session.set({ vault_prefill: msg.prefill || {} });
      const vaultUrl = chrome.runtime.getURL('vault-popup.html');
      const tabs = await chrome.tabs.query({});
      const existing = tabs.find(t => t.url && t.url.startsWith(vaultUrl));
      if (existing) {
        await chrome.tabs.update(existing.id, { active: true, url: vaultUrl + '?prefill=1' }).catch(() => {});
        await chrome.windows.update(existing.windowId, { focused: true }).catch(() => {});
      } else {
        await chrome.tabs.create({ url: vaultUrl + '?prefill=1' }).catch(() => {});
      }
      return { ok: true };
    }
    default:
      return null;
  }
}

async function getBackendSettings() {
  const settings = await chrome.storage.local.get({
    backend_url: 'http://localhost:8080',
    client_key: 'demo-key-123'
  });
  if (!settings.client_key) {
    settings.client_key = 'demo-key-123';
  }
  return settings;
}
const THRESHOLD_SAFE = 0.75;
const THRESHOLD_SUSPICIOUS = 0.55;
async function isUrlAllowed(url) {
  const cleanUrl = getCleanUrl(url);
  try {
    const res = await chrome.storage.session.get('ps_allowed_urls');
    const allowed = res.ps_allowed_urls || [];
    return allowed.includes(cleanUrl);
  } catch (e) {
    console.error('Error reading session storage:', e);
    return false;
  }
}

async function addUrlToAllowed(url) {
  const cleanUrl = getCleanUrl(url);
  try {
    const res = await chrome.storage.session.get('ps_allowed_urls');
    const allowed = res.ps_allowed_urls || [];
    if (!allowed.includes(cleanUrl)) {
      allowed.push(cleanUrl);
      await chrome.storage.session.set({ ps_allowed_urls: allowed });
    }
  } catch (e) {
    console.error('Error writing to session storage:', e);
  }
}

function getCleanUrl(url) {
  if (!url) return '';
  try {
    let decoded = url;
    if (decoded.includes('%')) {
      decoded = decodeURIComponent(decoded);
    }
    if (decoded.includes('%')) {
      decoded = decodeURIComponent(decoded);
    }
    return decoded.trim().replace(/\/$/, '').toLowerCase();
  } catch {
    return url.trim().replace(/\/$/, '').toLowerCase();
  }
}

let stats = { safe: 0, suspicious: 0, danger: 0, blocked: 0 };

chrome.storage.local.get('ps_stats', (res) => {
  if (res.ps_stats) stats = res.ps_stats;
});

function saveStats() {
  chrome.storage.local.set({ ps_stats: stats });
}

async function addHistory(entry) {
  const { ps_history = [] } = await chrome.storage.local.get('ps_history');
  ps_history.unshift(entry);
  if (ps_history.length > 50) ps_history.splice(50);
  await chrome.storage.local.set({ ps_history });
}

// ── Listener principal — intercepta ANTES de cargar ──
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const url = details.url;
  const tabId = details.tabId;

  if (!url || !url.startsWith('http')) return;
  if (url.startsWith('chrome-extension://')) return;
  if (await isUrlAllowed(url)) return;

  // Respetar el toggle de protección
  const { ps_protection_active = true } = await chrome.storage.local.get('ps_protection_active');
  if (!ps_protection_active) return;

  // Notificar estado analizando
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: 'SHIELD_RESULT',
      payload: { status: 'analyzing', url }
    });
  } catch {}

  let result;
  try {
    const settings = await getBackendSettings();
    const domData = await getDomFromTab(tabId);
    const resp = await fetch(`${settings.backend_url}/analyze`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'X-Client-Key': settings.client_key
      },
      body: JSON.stringify({ 
        url, 
        dom: domData.dom,
        behavioral_warnings: domData.warnings 
      }),
      signal: AbortSignal.timeout(8000),
    });
    result = await resp.json();
  } catch (err) {
    console.warn('[PhishingShield] Backend no disponible:', err.message);
    return;
  }

  const { score, status, services, id } = result;

  // Actualizar stats
  if (status === 'safe') stats.safe++;
  else if (status === 'suspicious') stats.suspicious++;
  else if (status === 'danger') { stats.danger++; stats.blocked++; }
  saveStats();

  // Guardar historial
  await addHistory({
    url, score: score ?? 0, status: status ?? 'unknown',
    timestamp: Date.now(), services: services ?? {},
  });

  // Actualizar badge
  updateBadge(tabId, status, score);

  // Mostrar notificación flotante
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: 'SHIELD_RESULT',
      payload: { score, status, services, url, id },
    });
  } catch {}

  // Guardar resultado en caché para onCommitted (ventana de 15s)
  const cacheKey = `ps_cached_${getCleanUrl(url)}`;
  chrome.storage.session.set({ [cacheKey]: { score, status, services, id, timestamp: Date.now() } }).catch(() => {});

  // ── BLOQUEAR si es peligroso ──
  if (status === 'danger') {
    await blockTab(tabId, { url, score, services, id });
  }
});

// Captura navegaciones directas desde barra de direcciones.
// onBeforeNavigate ya analizó esta URL; aquí reenviamos el resultado cacheado
// a los content scripts del nuevo documento (que aún no existían en onBeforeNavigate).
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (details.transitionType !== 'typed' && details.transitionType !== 'generated') return;

  const url = details.url;
  const tabId = details.tabId;

  if (!url || !url.startsWith('http')) return;
  if (url.startsWith('chrome-extension://')) return;
  if (await isUrlAllowed(url)) return;

  // Intentar usar resultado ya calculado por onBeforeNavigate (evita doble llamada al backend)
  const cacheKey = `ps_cached_${getCleanUrl(url)}`;
  const cached = (await chrome.storage.session.get(cacheKey))[cacheKey];
  if (cached && (Date.now() - cached.timestamp) < 15000) {
    const { score, status, services, id } = cached;
    updateBadge(tabId, status, score);
    try {
      await chrome.tabs.sendMessage(tabId, {
        type: 'SHIELD_RESULT',
        payload: { score, status, services, url, id },
      });
    } catch {}
    if (status === 'danger') {
      await blockTab(tabId, { url, score, services, id });
    }
    return;
  }

  // Sin caché: analizar normalmente (caso poco frecuente)
  try {
    const settings = await getBackendSettings();
    const domData = await getDomFromTab(tabId);
    const resp = await fetch(`${settings.backend_url}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Key': settings.client_key
      },
      body: JSON.stringify({ 
        url, 
        dom: domData.dom,
        behavioral_warnings: domData.warnings
      }),
      signal: AbortSignal.timeout(8000),
    });
    const result = await resp.json();
    const { score, status, services, id } = result;

    updateBadge(tabId, status, score);
    try {
      await chrome.tabs.sendMessage(tabId, {
        type: 'SHIELD_RESULT',
        payload: { score, status, services, url, id },
      });
    } catch {}
    if (status === 'danger') {
      await blockTab(tabId, { url, score, services, id });
    }
  } catch (err) {
    console.warn('[PhishingShield] Backend no disponible:', err.message);
  }
});

// --- Capturar HTML DOM del cliente y warnings (REQ-ARQ-01 / REQ-ARQ-04) ---
async function getDomFromTab(tabId) {
  try {
    const response = await chrome.tabs.sendMessage(tabId, { action: "getDOM" });
    return {
      dom: response?.dom || "",
      warnings: response?.warnings || []
    };
  } catch (e) {
    return { dom: "", warnings: [] };
  }
}

// ── Bloquear pestaña ──
async function blockTab(tabId, data) {
  const { url, score, services, id } = data;

  try {
    await chrome.tabs.sendMessage(tabId, {
      action: 'blockPage',
      data: buildBlockData(url, score, services, id),
    });
    return;
  } catch {}

  // Fallback: navegar a block.html
  const blockUrl = buildBlockUrl(url, score, services, id);
  try {
    await chrome.tabs.update(tabId, { url: blockUrl });
  } catch {}
}

function buildBlockData(url, score, services, id) {
  return {
    url,
    score: String(score ?? 0),
    heuristics: String(services?.heuristics?.score ?? 0),
    similarity:  String(services?.similarity?.score  ?? 0),
    reputation:  String(services?.reputation?.score  ?? 0),
    ml:          String(services?.ml?.score          ?? 0),
    reasons: buildReasons(services),
    id: id || ''
  };
}

function buildBlockUrl(url, score, services, id) {
  const params = new URLSearchParams({
    url:        url,
    score:      score ?? 0,
    heuristics: services?.heuristics?.score ?? 0,
    similarity: services?.similarity?.score  ?? 0,
    reputation: services?.reputation?.score  ?? 0,
    ml:         services?.ml?.score          ?? 0,
    reasons:    buildReasons(services).join('|'),
    id:         id || ''
  });
  return chrome.runtime.getURL(`block.html?${params.toString()}`);
}

function buildReasons(services) {
  const reasons = [];
  if (!services) return reasons;
  if ((services.heuristics?.score ?? 1) < THRESHOLD_SUSPICIOUS)
    reasons.push('Patrones de URL sospechosos detectados.');
  if ((services.similarity?.score  ?? 1) < THRESHOLD_SUSPICIOUS)
    reasons.push('Alta similitud con dominios de phishing conocidos.');
  if ((services.reputation?.score  ?? 1) < THRESHOLD_SUSPICIOUS)
    reasons.push('Dominio con mala reputación en VirusTotal.');
  if ((services.ml?.score          ?? 1) < THRESHOLD_SUSPICIOUS)
    reasons.push('Modelo ML clasifica la URL como amenaza.');
  return reasons;
}

function updateBadge(tabId, status, score) {
  const map = {
    safe:       { text: '✓', color: '#22c55e' },
    suspicious: { text: '!', color: '#f59e0b' },
    danger:     { text: '✕', color: '#dc2626' },
  };
  const b = map[status] ?? { text: '?', color: '#6b7280' };
  chrome.action.setBadgeText({ text: b.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: b.color, tabId });
}

// ── Mensajes desde popup y content scripts ──
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action?.startsWith('vault')) {
    handleVaultMessage(msg).then(sendResponse).catch(err => sendResponse({ error: err.message }));
    return true;
  }
  if (msg.action === 'getStats') {
    sendResponse(stats);
    return true;
  }
  if (msg.action === 'getHistory') {
    chrome.storage.local.get('ps_history', (res) => {
      sendResponse(res.ps_history ?? []);
    });
    return true;
  }
  if (msg.action === 'allowOnce') {
    addUrlToAllowed(msg.url).then(async () => {
      try {
        const settings = await getBackendSettings();
        fetch(`${settings.backend_url}/bypass`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Client-Key': settings.client_key
          },
          body: JSON.stringify({ url: msg.url })
        }).catch(err => console.warn('Error sending bypass log:', err));
      } catch (e) {}

      if (sender.tab) {
        chrome.tabs.update(sender.tab.id, { url: msg.url }).catch(() => {});
      }
      sendResponse({ ok: true });
    });
    return true;
  }
  if (msg.action === 'reportFalsePositive') {
    addUrlToAllowed(msg.url).then(() => {
      sendResponse({ ok: true });
    });
    return true;
  }
  if (msg.action === 'addToAllowed') {
    addUrlToAllowed(msg.url).then(async () => {
      try {
        const settings = await getBackendSettings();
        fetch(`${settings.backend_url}/bypass`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Client-Key': settings.client_key
          },
          body: JSON.stringify({ url: msg.url })
        }).catch(err => console.warn('Error sending bypass log:', err));
      } catch (e) {}

      sendResponse({ ok: true });
    });
    return true;
  }
  if (msg.action === 'navigateTab') {
    if (sender.tab) {
      chrome.tabs.update(sender.tab.id, { url: msg.url }).catch(() => {});
    }
    sendResponse({ ok: true });
    return true;
  }
  if (msg.action === 'goBack') {
    if (sender.tab) {
      chrome.tabs.goBack(sender.tab.id).catch(() => {
        chrome.tabs.update(sender.tab.id, { url: 'https://google.com' }).catch(() => {});
      });
    }
    sendResponse({ ok: true });
    return true;
  }
  if (msg.action === 'openPopup') {
    chrome.action.openPopup?.().catch(() => {});
    sendResponse({ ok: true });
    return true;
  }
  if (msg.action === 'openDashboard') {
    const dashboardUrl = chrome.runtime.getURL('dashboard/index.html');
    chrome.tabs.query({}, (tabs) => {
      const dashboardTab = tabs.find(t => t.url && (t.url === dashboardUrl || t.url.includes('dashboard/index.html') || t.title.includes('Phishing Shield')));
      if (dashboardTab) {
        chrome.tabs.update(dashboardTab.id, { active: true }).catch(() => {});
        chrome.windows.update(dashboardTab.windowId, { focused: true }).catch(() => {});
      } else {
        chrome.tabs.create({ url: dashboardUrl }).catch(() => {});
      }
    });
    sendResponse({ ok: true });
    return true;
  }
  if (msg.action === 'captureVisual') {
    chrome.tabs.captureVisibleTab(null, { format: 'png' }, async (dataUrl) => {
      if (!dataUrl) return;
      
      // Calcular hash visual y enviarlo al servidor
      try {
        const hash = await computeImageHash(dataUrl);
        const domain = new URL(msg.url).hostname;
        
        const settings = await getBackendSettings();
        const resp = await fetch(`${settings.backend_url}/analyze-hash`, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'X-Client-Key': settings.client_key
          },
          body: JSON.stringify({ hash, domain })
        });
        
        const result = await resp.json();
        
        if (result.score < 0.55 && sender.tab) {
          // Actualizar estadísticas de bloqueo
          stats.danger++;
          stats.blocked++;
          saveStats();

          // Notificar el toast
          try {
            await chrome.tabs.sendMessage(sender.tab.id, {
              type: 'SHIELD_RESULT',
              payload: { 
                status: 'danger', 
                score: result.score, 
                url: msg.url,
                message: result.reasons[0] || 'Suplantación visual detectada'
              }
            });
          } catch {}

          // Bloquear la pestaña
          await blockTab(sender.tab.id, {
            url: msg.url,
            score: result.score,
            services: { visual: { score: result.score } }
          });
        }
      } catch(e) {
        console.log('Error análisis visual:', e);
      }
    });
    return true;
  }
});

// Hash perceptual simple compatible con Service Worker (MV3)
async function computeImageHash(dataUrl) {
  const response = await fetch(dataUrl);
  const blob = await response.blob();
  const img = await createImageBitmap(blob);
  
  const canvas = new OffscreenCanvas(8, 8);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0, 8, 8);
  const data = ctx.getImageData(0, 0, 8, 8).data;
  
  // Calcular luminancia promedio
  let pixels = [];
  for (let i = 0; i < data.length; i += 4) {
    const lum = 0.299 * data[i] + 0.587 * data[i+1] + 0.114 * data[i+2];
    pixels.push(lum);
  }
  
  const avg = pixels.reduce((a, b) => a + b) / pixels.length;
  
  // Generar hash binario
  let hash = '';
  for (let p of pixels) {
    hash += p >= avg ? '1' : '0';
  }
  
  // Convertir a hex
  let hexHash = '';
  for (let i = 0; i < hash.length; i += 4) {
    hexHash += parseInt(hash.slice(i, i+4), 2).toString(16);
  }
  
  return hexHash;
}