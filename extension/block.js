// Obtener parámetros de la URL
function getParam(key) {
  try {
    const search = window.location.search || location.search;
    const params = new URLSearchParams(search);
    const val = params.get(key);
    if (val) return val;
    const full = new URL(window.location.href);
    return full.searchParams.get(key) || '';
  } catch { return ''; }
}

// Clasificación de seguridad amigable para no informáticos
function classifyFriendly(score) {
  const s = parseFloat(score);
  if (s >= 0.75) return { text: 'SEGURO', class: 'safe' };
  if (s >= 0.55) return { text: 'SOSPECHOSO', class: 'warning' };
  return { text: 'PELIGROSO', class: 'danger' };
}

let blockedUrl = '';
try {
  const rawUrl = getParam('url') || '';
  blockedUrl = decodeURIComponent(rawUrl);
  if (blockedUrl.includes('%')) {
    blockedUrl = decodeURIComponent(blockedUrl);
  }
  blockedUrl = blockedUrl.trim();
} catch {
  blockedUrl = getParam('url') || '';
}

const overallScore = getParam('score') || '0';
const heuristics   = getParam('heuristics') || '0';
const similarity   = getParam('similarity') || '0';
const reputation   = getParam('reputation') || '0';
const ml           = getParam('ml') || '0';
const rawReasons   = (getParam('reasons') || '').split('|').filter(Boolean);
const incidentId   = getParam('id') || '';

// --- Generar/Cargar ID de Trazabilidad (REQ-UI-01) ---
function generateTracebackId(urlStr, explicitId) {
  if (explicitId) return explicitId.startsWith('#') ? explicitId : '#' + explicitId;
  // Hash determinista básico a partir del URL
  let hash = 0;
  for (let i = 0; i < urlStr.length; i++) {
    hash = (hash << 5) - hash + urlStr.charCodeAt(i);
    hash |= 0; // Convertir a entero de 32 bits
  }
  const hex = Math.abs(hash).toString(16).toUpperCase().substring(0, 5);
  return `#PS-${hex}-A`;
}
const tracebackId = generateTracebackId(blockedUrl, incidentId);
const tracebackEl = document.getElementById('traceback-id');
if (tracebackEl) {
  tracebackEl.textContent = tracebackId;
}

// --- Lenguaje de Concientización No Técnico (REQ-UI-02) ---
const friendlyReasons = {
  'patrones de url sospechosos detectados.': 'Análisis de dirección de enlace detectó patrones de escritura anómalos.',
  'alta similitud con dominios de phishing conocidos.': 'El nombre de este dominio imita la marca corporativa de una entidad legítima.',
  'dominio con mala reputación en virustotal.': 'Este sitio se encuentra reportado activamente en bases de datos de reputación e inteligencia global.',
  'modelo ml clasifica la url como amenaza.': 'El análisis de comportamiento automatizado identificó un alto riesgo de suplantación.',
  'exceso de guiones en dominio': 'El nombre del sitio contiene demasiados guiones seguidos, patrón típico de fraude.',
  'tld sospechoso: .xyz': 'El dominio utiliza una extensión de bajo costo (.xyz) frecuentemente explotada para ataques.',
  'tld sospechoso: .tk': 'El dominio utiliza una extensión de bajo costo (.tk) de baja reputación corporativa.',
  'tld sospechoso: .ml': 'El dominio utiliza una extensión de bajo costo (.ml) asociada a riesgos.',
  'tld sospechoso: .ga': 'El dominio utiliza una extensión de bajo costo (.ga) asociada a riesgos.',
  'tld sospechoso: .cf': 'El dominio utiliza una extensión de bajo costo (.cf) asociada a riesgos.',
  'tld sospechoso: .gq': 'El dominio utiliza una extensión de bajo costo (.gq) asociada a riesgos.',
  'tld sospechoso: .top': 'El dominio utiliza una extensión no convencional (.top) sospechosa.',
  'tld sospechoso: .click': 'El dominio utiliza una extensión no convencional (.click) sospechosa.',
  'sin cifrado https': 'El canal de comunicación no está cifrado (sin HTTPS), permitiendo espionaje de datos.',
  'suplanta a paypal': 'Intento de suplantación de la plataforma de pagos PayPal.',
  'suplanta a google': 'Intento de suplantación del portal de acceso a servicios Google.',
  'suplanta a facebook': 'Intento de suplantación de la red social Facebook.',
  'suplanta a microsoft': 'Intento de suplantación del sistema de cuentas corporativas Microsoft.',
  'suplanta a apple': 'Intento de suplantación de servicios Apple Cloud.',
  'suplanta a amazon': 'Intento de suplantación de la plataforma comercial Amazon.',
  'suplanta a netflix': 'Intento de suplantación del portal de streaming Netflix.',
  'suplanta a instagram': 'Intento de suplantación de la red social Instagram.',
  'suplanta a twitter': 'Intento de suplantación de la plataforma de comunicación Twitter/X.',
  'suplanta a santander': 'Intento de suplantación del portal de banca en línea Banco Santander.',
  'suplanta a bci': 'Intento de suplantación del portal de banca en línea Banco BCI.',
  'suplanta a scotiabank': 'Intento de suplantación del portal de banca en línea Scotiabank.',
  'suplanta a falabella': 'Intento de suplantación del portal financiero o retail Falabella.',
  'suplanta a mercadolibre': 'Intento de suplantación de la plataforma comercial MercadoLibre.',
  'dominio en lista negra local — phishing confirmado': 'Dominio bloqueado directamente por políticas de seguridad interna de la organización.'
};

function translateReasonFriendly(rawReason) {
  const clean = rawReason.trim().toLowerCase();
  for (let key in friendlyReasons) {
    if (clean.includes(key) || key.includes(clean)) {
      return friendlyReasons[key];
    }
  }
  return rawReason.replace('VirusTotal', 'Base de datos de reputación global').replace('ML', 'Modelo de inteligencia artificial');
}

// Cargar enlace bloqueado
if (blockedUrl) {
  document.getElementById('blocked-url').textContent = blockedUrl;
}

// Calcular y mostrar porcentaje de riesgo general
const risk = Math.round((1 - parseFloat(overallScore)) * 100);
if (overallScore) {
  document.getElementById('overall-score').textContent = `Nivel de riesgo: ${risk}%`;
}

// --- Bloqueo Dinámico (Hard Block vs. Soft Block) (REQ-UI-03) ---
const isHardBlock = risk > 85; // Umbral crítico mayor a 85% de riesgo
if (isHardBlock) {
  const btnProceed = document.getElementById('btn-proceed');
  if (btnProceed) {
    btnProceed.style.display = 'none'; // Ocultar el bypass completamente
  }
  const subDesc = document.getElementById('sub-desc');
  if (subDesc) {
    subDesc.innerHTML = 'Este sitio ha sido bloqueado de forma absoluta por las políticas de seguridad de tu organización debido a un <strong>riesgo de fraude crítico e inminente</strong>. Por motivos de seguridad de datos, el acceso bajo propio riesgo ha sido inhabilitado.';
  }
}

// Configurar grilla de módulos de seguridad amigables
const friendlyNames = {
  'Heurísticas': 'Análisis de Enlace',
  'Similitud URL': 'Verificación de Marca',
  'Reputación': 'Reputación Global',
  'ML': 'Inteligencia Artificial'
};

const scores = [
  { name: 'Heurísticas', val: heuristics },
  { name: 'Similitud URL', val: similarity },
  { name: 'Reputación',   val: reputation },
  { name: 'ML',           val: ml         },
];

const grid = document.getElementById('scores-grid');
scores.forEach(({ name, val }) => {
  if (!val || val === '0') return;
  const friendlyName = friendlyNames[name] || name;
  const statusInfo = classifyFriendly(val);
  const item = document.createElement('div');
  item.className = 'score-item';
  item.innerHTML = `<span class="score-name">${friendlyName}</span>
    <span class="score-val ${statusInfo.class}">${statusInfo.text}</span>`;
  grid.appendChild(item);
});

// Cargar razones específicas del bloqueo traducidas a lenguaje amigable
if (rawReasons.length > 0) {
  document.getElementById('reasons-section').style.display = 'block';
  const ul = document.getElementById('reason-list');
  rawReasons.forEach(r => {
    const li = document.createElement('li');
    li.textContent = translateReasonFriendly(decodeURIComponent(r));
    ul.appendChild(li);
  });
}

/* ==========================================================================
   MANEJADORES DE ACCIONES CON SOPORTE DE CONTEXTO IFRAME Y MODALES PERSONALIZADOS
   ========================================================================== */

function goBack() {
  chrome?.runtime?.sendMessage({ action: 'goBack' });
}

async function reportFalsePositive() {
  // Enviar reporte de falso positivo real al orquestador (REQ-BE-03)
  try {
    let backendUrl = 'http://localhost:8080';
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      const stored = await chrome.storage.local.get({
        backend_url: 'http://localhost:8080'
      });
      backendUrl = stored.backend_url;
    }
    
    await fetch(`${backendUrl.trim().replace(/\/$/, '')}/api/reports`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url: blockedUrl,
        incident_id: tracebackId.replace('#', '')
      })
    });
  } catch (err) {
    console.warn('[PhishingShield] Error enviando reporte de falso positivo:', err);
  }

  const alertModal = document.getElementById('alertModal');
  if (alertModal) {
    alertModal.style.display = 'flex';
  }
}

function proceedAnyway() {
  const confirmModal = document.getElementById('confirmModal');
  if (confirmModal) {
    confirmModal.style.display = 'flex';
  }
}

// Configurar los escuchadores de eventos cuando el DOM esté cargado (Requerido por CSP de Chrome)
document.addEventListener('DOMContentLoaded', () => {
  // Botones principales en la pantalla de bloqueo
  const btnBack = document.getElementById('btn-back');
  const btnReport = document.getElementById('btn-report');
  const btnProceed = document.getElementById('btn-proceed');

  if (btnBack) btnBack.addEventListener('click', goBack);
  if (btnReport) btnReport.addEventListener('click', reportFalsePositive);
  if (btnProceed) btnProceed.addEventListener('click', proceedAnyway);

  // Botones del modal de confirmación personalizado
  const btnCancelProceed = document.getElementById('btnCancelProceed');
  const btnConfirmProceed = document.getElementById('btnConfirmProceed');
  const confirmModal = document.getElementById('confirmModal');

  if (btnCancelProceed) {
    btnCancelProceed.addEventListener('click', () => {
      if (confirmModal) confirmModal.style.display = 'none';
    });
  }

  if (btnConfirmProceed) {
    btnConfirmProceed.addEventListener('click', () => {
      if (confirmModal) confirmModal.style.display = 'none';
      chrome?.runtime?.sendMessage({ action: 'allowOnce', url: blockedUrl });
    });
  }

  // Botón del modal de alerta (Cerrar modal de reporte de error)
  const btnAlertOk = document.getElementById('btnAlertOk');
  const alertModal = document.getElementById('alertModal');

  if (btnAlertOk) {
    btnAlertOk.addEventListener('click', () => {
      if (alertModal) alertModal.style.display = 'none';
    });
  }
});