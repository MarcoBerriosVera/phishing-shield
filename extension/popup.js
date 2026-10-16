// Verificar estado del backend consultando el orquestador.
// Marca todos los servicios como online/offline según la respuesta.
async function checkServices() {
  const serviceIds = ['heuristics', 'similarity', 'reputation', 'ml'];
  const setAll = (online) => {
    for (const id of serviceIds) {
      const el = document.getElementById(`svc-${id}`);
      if (!el) continue;
      el.className = `service-status ${online ? 'online' : 'offline'}`;
      el.innerHTML = `<div class="service-dot"></div> ${online ? 'Online' : 'Offline'}`;
    }
  };

  try {
    const { backend_url, client_key } = await chrome.storage.local.get({
      backend_url: 'http://localhost:8080',
      client_key: 'demo-key-123'
    });
    const key = client_key || 'demo-key-123';
    const res = await fetch(`${backend_url}/health`, {
      headers: { 'X-Client-Key': key },
      signal: AbortSignal.timeout(3000)
    });
    setAll(res.ok);
  } catch {
    setAll(false);
  }
}

// Cargar estadísticas e historial desde el almacenamiento local de Chrome
async function loadStats() {
  const data = await chrome.storage.local.get(['ps_stats', 'ps_history']);
  const isProtectionActive = document.getElementById('chkActive').checked;
  
  if (data.ps_stats) {
    const s = data.ps_stats;
    const total = (s.safe || 0) + (s.suspicious || 0) + (s.danger || 0);
    document.getElementById('totalScanned').textContent = total;
    document.getElementById('totalSafe').textContent = s.safe || 0;
    document.getElementById('totalDanger').textContent = s.blocked || s.danger || 0;
  }

  let lastUrlStatus = 'safe';
  let lastUrlScore = 1.0;

  if (data.ps_history && data.ps_history.length > 0) {
    const r = data.ps_history[0];
    lastUrlStatus = r.status || 'safe';
    lastUrlScore = r.score ?? 1.0;

    document.getElementById('lastUrl').textContent = r.url;
    document.getElementById('lastUrlScore').style.display = 'flex';
    
    const badge = document.getElementById('lastUrlBadge');
    const scoreVal = document.getElementById('lastUrlScoreVal');
    
    // Configurar etiqueta amigable de última URL
    if (r.status === 'safe') {
      badge.textContent = '✓ Seguro';
      badge.className = 'score-badge badge-safe';
    } else if (r.status === 'suspicious') {
      badge.textContent = '⚠ Sospechoso';
      badge.className = 'score-badge badge-suspicious';
    } else {
      badge.textContent = '✕ Bloqueado';
      badge.className = 'score-badge badge-danger';
    }
    
    scoreVal.textContent = `Confianza: ${(lastUrlScore * 100).toFixed(0)}%`;
  } else {
    document.getElementById('lastUrl').textContent = 'Ninguna página analizada en esta sesión';
    document.getElementById('lastUrlScore').style.display = 'none';
  }

  // Si la protección está activa, actualizar el escudo central basado en el último resultado
  if (isProtectionActive) {
    updateShieldState(lastUrlStatus);
  }
}

// Actualizar el estado visual del escudo principal
function updateShieldState(status) {
  const outer = document.getElementById('shieldOuter');
  const title = document.getElementById('statusTitle');
  const desc = document.getElementById('statusDesc');
  const icon = outer.querySelector('.shield-icon');

  // Limpiar clases previas
  outer.className = 'shield-outer';
  title.className = '';
  
  if (status === 'safe') {
    outer.classList.add('state-safe');
    title.classList.add('state-safe-text');
    title.textContent = 'Navegación Segura';
    desc.textContent = 'Tu protección está activa y vigilando';
    icon.innerHTML = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 11 11 13 15 9"/>';
  } else if (status === 'suspicious') {
    outer.classList.add('state-warning');
    title.classList.add('state-warning-text');
    title.textContent = 'Sitio Sospechoso';
    desc.textContent = 'Se detectaron algunas anomalías en la página';
    icon.innerHTML = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>';
  } else if (status === 'danger') {
    outer.classList.add('state-danger');
    title.classList.add('state-danger-text');
    title.textContent = 'Amenaza Bloqueada';
    desc.textContent = 'Hemos evitado un intento de phishing';
    icon.innerHTML = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>';
  } else if (status === 'off') {
    outer.classList.add('state-off');
    title.classList.add('state-off-text');
    title.textContent = 'Protección Pausada';
    desc.textContent = 'Tu navegación no está protegida actualmente';
    icon.innerHTML = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="8" y1="12" x2="16" y2="12"/>';
  }
}

// Inicialización de componentes y escuchadores de eventos
document.addEventListener('DOMContentLoaded', () => {
  // 1. Verificar estado del backend
  checkServices();

  // 2. Cargar estadísticas iniciales
  loadStats();

  // 3. Manejador del colapsable de detalles avanzados
  const btnToggle = document.getElementById('btnToggleDetails');
  const advDetails = document.getElementById('advancedDetails');
  const chevron = document.getElementById('chevronIcon');

  btnToggle.addEventListener('click', () => {
    const isExpanded = advDetails.classList.toggle('expanded');
    btnToggle.setAttribute('aria-expanded', isExpanded);
    chevron.style.transform = isExpanded ? 'rotate(180deg)' : 'rotate(0deg)';
    btnToggle.querySelector('span').textContent = isExpanded 
      ? 'Ocultar detalles avanzados' 
      : 'Mostrar detalles avanzados';
  });

  // 4. Botón del gestor de contraseñas
  const btnVault = document.getElementById('btnOpenVault');
  if (btnVault) {
    btnVault.addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('vault-popup.html') });
    });
  }

  // 5. Manejador del Switch de Encendido / Apagado
  const chkActive = document.getElementById('chkActive');
  const toggleLabel = document.getElementById('toggleLabel');

  // Cargar estado persistido desde storage
  chrome.storage.local.get({ ps_protection_active: true }, ({ ps_protection_active }) => {
    chkActive.checked = ps_protection_active;
    if (!ps_protection_active) {
      toggleLabel.textContent = 'Desactivado';
      toggleLabel.style.color = 'var(--text-muted)';
      updateShieldState('off');
    }
  });

  chkActive.addEventListener('change', () => {
    chrome.storage.local.set({ ps_protection_active: chkActive.checked });
    if (chkActive.checked) {
      toggleLabel.textContent = 'Activo';
      toggleLabel.style.color = 'var(--success)';
      loadStats(); // Recarga stats y aplica estado según última URL
    } else {
      toggleLabel.textContent = 'Desactivado';
      toggleLabel.style.color = 'var(--text-muted)';
      updateShieldState('off'); // Cambia a estado apagado (gris)
    }
  });
});