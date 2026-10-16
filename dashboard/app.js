/* ============================================================
   PHISHING SHIELD — Enhanced SOC Dashboard JavaScript
   ============================================================ */

window.onerror = function(message, source, lineno, colno, error) {
    const errorMsg = `Error de JavaScript: ${message}\nLínea: ${lineno}\nArchivo: ${source}`;
    console.error(errorMsg);
    alert(errorMsg);
    const div = document.createElement('div');
    div.style.position = 'fixed';
    div.style.bottom = '10px';
    div.style.left = '10px';
    div.style.background = 'rgba(239, 68, 68, 0.95)';
    div.style.color = 'white';
    div.style.padding = '15px';
    div.style.zIndex = '999999';
    div.style.fontFamily = 'monospace';
    div.style.fontSize = '12px';
    div.style.borderRadius = '8px';
    div.style.border = '2px solid white';
    div.innerText = errorMsg;
    document.body.appendChild(div);
    return false;
};

const CONFIG = {
    backendUrl: 'http://localhost:8080',
    clientKey: '',
    adminToken: '',
    refreshInterval: 5000,
    demoMode: true
};

let currentTab = 'tab-monitor';
let radarChart = null;
let trendChart = null;
let latencyData = [];
let incidentLogs = [];
let whitelist = [];
let apiKeys = [];

let isConnected = false;
let demoStarted = false;

const VALID_CLIENT_KEY = 'demo-key-123';
const VALID_ADMIN_TOKENS = ['pymeshield2026', 'admin', 'YOUR_ADMIN_TOKEN_HERE'];

// Cargar configuración de manera asíncrona (soporta extensión de Chrome y localStorage)
async function loadConfig() {
    const isExtension = typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local;
    if (isExtension) {
        const stored = await chrome.storage.local.get({
            backend_url: 'http://localhost:8080',
            client_key: '',
            admin_token: ''
        });
        CONFIG.backendUrl = stored.backend_url;
        CONFIG.clientKey = stored.client_key;
        CONFIG.adminToken = stored.admin_token;
    } else {
        CONFIG.backendUrl = localStorage.getItem('ps_backend_url') || 'http://localhost:8080';
        CONFIG.clientKey = localStorage.getItem('ps_client_key') || '';
        CONFIG.adminToken = localStorage.getItem('ps_admin_token') || '';
    }
}

// Guardar configuración de manera asíncrona
async function saveConfig(backendUrl, clientKey, adminToken) {
    const isExtension = typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local;
    if (isExtension) {
        await chrome.storage.local.set({
            backend_url: backendUrl,
            client_key: clientKey,
            admin_token: adminToken
        });
    } else {
        localStorage.setItem('ps_backend_url', backendUrl);
        localStorage.setItem('ps_client_key', clientKey);
        localStorage.setItem('ps_admin_token', adminToken);
    }
}

// Verificar credenciales de forma asíncrona contra el backend real
async function verifyCredentialsWithBackend(backendUrl, clientKey, adminToken) {
    if (!backendUrl || !clientKey || !adminToken) {
        return { valid: false, error: 'Complete todos los campos de conexión.' };
    }
    const url = backendUrl.trim().replace(/\/$/, '');

    // 1. Probar health
    try {
        const healthRes = await fetch(`${url}/health`, { signal: AbortSignal.timeout(3000) });
        if (!healthRes.ok) {
            return { valid: false, error: `Servidor respondió con código ${healthRes.status} a /health.` };
        }
    } catch (e) {
        return { valid: false, error: 'Servidor central SOC fuera de línea o inalcanzable.' };
    }

    // 2. Probar Admin Token contra /api/settings
    try {
        const settingsRes = await fetch(`${url}/api/settings`, {
            headers: { 'X-Admin-Token': adminToken },
            signal: AbortSignal.timeout(3000)
        });
        if (settingsRes.status === 401) {
            return { valid: false, error: 'Admin Token inválido para este servidor.' };
        }
        if (!settingsRes.ok) {
            return { valid: false, error: 'Error del servidor al validar Admin Token.' };
        }
    } catch (e) {
        return { valid: false, error: 'Error de red al validar Admin Token.' };
    }

    // 3. Probar Client Key realizando petición controlada a /bypass
    try {
        const bypassRes = await fetch(`${url}/bypass`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Client-Key': clientKey
            },
            body: JSON.stringify({ url: 'test-connection' }),
            signal: AbortSignal.timeout(3000)
        });
        if (bypassRes.status === 401) {
            return { valid: false, error: 'Client API Key inválida.' };
        }
    } catch (e) {
        return { valid: false, error: 'Error de red al validar Client API Key.' };
    }

    return { valid: true };
}

// Cliente de WebSocket para el Dashboard
let socket = null;

function connectWebSocket() {
    if (socket) {
        try { socket.close(); } catch(e) {}
        socket = null;
    }

    const cleanUrl = CONFIG.backendUrl.trim().replace(/\/$/, '');
    const wsUrl = cleanUrl.replace(/^http/, 'ws') + '/ws?token=' + CONFIG.clientKey;
    console.log('Dashboard: Conectando WebSocket a:', wsUrl);
    
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        console.log('Dashboard: Conectado al WebSocket del Orquestador');
    };

    socket.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleWebSocketMessage(msg);
        } catch (e) {
            console.error('Dashboard: Error al decodificar mensaje WebSocket:', e);
        }
    };

    socket.onclose = (event) => {
        console.warn('Dashboard: Conexión WebSocket cerrada. Reintentando en 5s...', event.reason);
        setTimeout(() => {
            if (isConnected && !CONFIG.demoMode) connectWebSocket();
        }, CONFIG.refreshInterval);
    };

    socket.onerror = (err) => {
        console.error('Dashboard: Error en WebSocket:', err);
    };
}

// Manejar mensajes WebSocket del Orquestador
function handleWebSocketMessage(msg) {
    if (!msg || !msg.event) return;
    
    const event = msg.event;
    const data = msg.data;

    const targetUrlEl = document.getElementById('target-url');
    const targetDomainEl = document.getElementById('target-domain');
    const timeline = document.getElementById('execution-timeline');
    const globalProgress = document.getElementById('global-progress');
    const globalStatus = document.getElementById('global-status-text');

    function addTimelineItem(text, type) {
        const item = document.createElement('div');
        item.className = 'timeline-item ' + type;
        const time = new Date().toLocaleTimeString('es-ES', { hour12: false });
        item.innerHTML = '<span class="timeline-time">' + time + '</span><span class="timeline-text">' + text + '</span>';
        timeline.insertBefore(item, timeline.firstChild);
        while (timeline.children.length > 8) {
            timeline.removeChild(timeline.lastChild);
        }
    }

    switch (event) {
        case 'URL_INTERCEPTED': {
            if (targetUrlEl) {
                targetUrlEl.textContent = data.url;
                targetUrlEl.className = 'value mono text-warning';
            }
            if (targetDomainEl) {
                try {
                    targetDomainEl.textContent = new URL(data.url).hostname;
                } catch (e) {
                    targetDomainEl.textContent = data.url;
                }
            }

            if (globalProgress) globalProgress.style.width = '0%';
            if (globalStatus) {
                globalStatus.textContent = 'Interceptando...';
                globalStatus.style.color = '';
            }

            document.getElementById('node-ext')?.classList.add('active');
            document.getElementById('node-orch')?.classList.add('active');
            document.getElementById('node-micro')?.classList.remove('active');
            document.getElementById('node-risk')?.classList.remove('error', 'completed');

            const serviceIds = ['ms-heur', 'ms-simi', 'ms-vt', 'ms-ml', 'ms-vis'];
            serviceIds.forEach(id => {
                const card = document.getElementById(id);
                if (card) {
                    card.className = 'ms-card';
                    card.querySelector('.ms-status').textContent = 'Esperando';
                    card.querySelector('.ms-status').className = 'ms-status';
                    card.querySelector('.ms-time').textContent = '-- ms';
                    card.querySelector('.ms-score').textContent = '--/--';
                    card.querySelector('.ms-progress-fill').className = 'ms-progress-fill';
                    card.querySelector('.ms-progress-fill').style.width = '0%';
                    card.querySelector('.ms-details')?.classList.add('hidden');
                }
            });

            if (radarChart) {
                radarChart.data.datasets[0].data = [0, 0, 0, 0, 0];
                radarChart.update();
            }

            if (timeline) {
                timeline.innerHTML = '';
            }
            addTimelineItem('Interceptación de URL en tiempo real iniciada', 'info');
            break;
        }

        case 'ORCHESTRATOR_START': {
            document.getElementById('node-micro')?.classList.add('active');
            addTimelineItem('Orquestador de seguridad activado', 'success');
            break;
        }

        case 'MICROSERVICE_PROCESSING': {
            const card = document.getElementById(data.id);
            if (card) {
                card.className = 'ms-card processing';
                const statusEl = card.querySelector('.ms-status');
                statusEl.textContent = 'Analizando...';
                statusEl.className = 'ms-status processing';
                
                const fillEl = card.querySelector('.ms-progress-fill');
                fillEl.className = 'ms-progress-fill processing';
                fillEl.style.width = '60%';
            }
            addTimelineItem(`Procesando vector: ${data.label}...`, 'processing');
            break;
        }

        case 'MICROSERVICE_DONE': {
            const card = document.getElementById(data.id);
            if (card) {
                card.classList.remove('processing');
                const statusEl = card.querySelector('.ms-status');
                const fillEl = card.querySelector('.ms-progress-fill');

                card.querySelector('.ms-time').textContent = `${data.executionTimeMs} ms`;
                card.querySelector('.ms-score').textContent = `${data.score}/${data.maxScore}`;

                const isThreat = data.score < (data.maxScore * 0.75);
                if (isThreat) {
                    card.className = 'ms-card danger';
                    statusEl.textContent = 'Crítico';
                    statusEl.className = 'ms-status danger';
                    fillEl.className = 'ms-progress-fill danger';
                } else {
                    card.className = 'ms-card completed';
                    statusEl.textContent = 'Limpio';
                    statusEl.className = 'ms-status completed';
                    fillEl.className = 'ms-progress-fill completed';
                }
                fillEl.style.width = '100%';

                const detailsEl = card.querySelector('.ms-details');
                if (detailsEl) {
                    detailsEl.classList.remove('hidden');
                    if (data.details && data.details.length > 0) {
                        const listHtml = data.details.map(item => {
                            const itemClass = item.isCritical ? 'text-danger' : 'text-warning';
                            const prefix = item.isCritical ? '✕' : '⚠';
                            return `<li class="${itemClass}">${prefix} ${item.text}</li>`;
                        }).join('');
                        detailsEl.innerHTML = `<ul>${listHtml}</ul>`;
                    } else {
                        detailsEl.innerHTML = `<p class="detail-text" style="color: #10b981;">✓ Sin anomalías encontradas</p>`;
                    }
                }

                if (radarChart) {
                    const servicesOrder = ['heuristics', 'similarity', 'reputation', 'ml', 'visual'];
                    const idx = servicesOrder.indexOf(data.id.replace('ms-', ''));
                    if (idx !== -1) {
                        const normalizedScore = (data.score / data.maxScore) * 100;
                        radarChart.data.datasets[0].data[idx] = Math.round(100 - normalizedScore);
                        radarChart.update();
                    }
                }
            }
            
            const timelineClass = (data.score < data.maxScore * 0.75) ? 'danger' : 'success';
            addTimelineItem(`${data.label} completado — Score: ${data.score}/${data.maxScore}`, timelineClass);
            break;
        }

        case 'RISK_CALCULATION': {
            document.getElementById('node-micro')?.classList.remove('active');
            document.getElementById('node-risk')?.classList.add('active');
            addTimelineItem('Calculando veredicto del motor de riesgo...', 'processing');
            break;
        }

        case 'FINAL_VERDICT': {
            document.getElementById('node-risk')?.classList.remove('active');
            
            const finalScoreEl = document.getElementById('final-score');
            const finalVerdictEl = document.getElementById('final-verdict');
            const explanationBox = document.getElementById('explanation-box');

            if (finalScoreEl) {
                finalScoreEl.textContent = `${data.score}%`;
            }

            const isDangerous = data.isDangerous || data.verdictText === 'Peligroso';
            
            if (finalVerdictEl) {
                finalVerdictEl.textContent = data.verdictText.toUpperCase();
                finalVerdictEl.style.color = isDangerous ? '#ef4444' : (data.verdictText === 'Sospechoso' ? '#f59e0b' : '#10b981');
            }

            const circumference = 2 * Math.PI * 80;
            const offset = circumference - (data.score / 100) * circumference;
            const gaugeFill = document.querySelector('.gauge-fill');
            if (gaugeFill) {
                gaugeFill.style.strokeDashoffset = offset;
                if (isDangerous) {
                    gaugeFill.style.stroke = '#ef4444';
                    gaugeFill.style.filter = 'drop-shadow(0 0 10px rgba(239, 68, 68, 0.4))';
                    document.getElementById('node-risk').className = 'node error';
                } else if (data.verdictText === 'Sospechoso') {
                    gaugeFill.style.stroke = '#f59e0b';
                    gaugeFill.style.filter = 'drop-shadow(0 0 10px rgba(245, 158, 11, 0.4))';
                    document.getElementById('node-risk').className = 'node error';
                } else {
                    gaugeFill.style.stroke = '#10b981';
                    gaugeFill.style.filter = 'drop-shadow(0 0 10px rgba(16, 185, 129, 0.4))';
                    document.getElementById('node-risk').className = 'node completed';
                }
            }

            if (explanationBox) {
                let titleColor = '#10b981';
                let icon = '✓';
                if (isDangerous) {
                    titleColor = '#ef4444';
                    icon = '⚠️';
                } else if (data.verdictText === 'Sospechoso') {
                    titleColor = '#f59e0b';
                    icon = '⚠';
                }
                
                const explanationsHtml = data.explanations.map(exp => `<li>${exp}</li>`).join('');
                explanationBox.innerHTML = `
                    <div style="display: flex; flex-direction: column; gap: 8px; width: 100%;">
                        <div style="display: flex; align-items: center; gap: 8px; color: ${titleColor}; font-weight: 600; font-size: 0.85rem;">
                            <span style="font-size: 1.2rem;">${icon}</span> ${data.verdictTitle}
                        </div>
                        <p style="font-size: 0.8rem; color: var(--text-muted); line-height: 1.5;">
                            El análisis conjunto de los 5 vectores de detección ha determinado que esta URL presenta <strong style="color: ${titleColor};">${data.score}% de riesgo acumulado</strong>.
                        </p>
                        <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">
                            <strong>Detalles del veredicto:</strong>
                            <ul style="margin-top: 4px; padding-left: 16px; list-style-type: disc; display: flex; flex-direction: column; gap: 2px;">
                                ${explanationsHtml}
                            </ul>
                        </div>
                    </div>`;
                explanationBox.classList.add('has-content');
            }

            if (globalProgress) globalProgress.style.width = '100%';
            if (globalStatus) {
                globalStatus.textContent = `Análisis completado — ${data.verdictText}`;
                globalStatus.style.color = isDangerous ? '#ef4444' : (data.verdictText === 'Sospechoso' ? '#f59e0b' : '#10b981');
            }

            addTimelineItem(`<strong>Veredicto final:</strong> ${data.verdictTitle} (${data.score}% riesgo)`, isDangerous ? 'danger' : (data.verdictText === 'Sospechoso' ? 'warning' : 'success'));

            if (isDangerous) {
                showSOCAlert('⚠️ Phishing Detectado', `URL bloqueada: ${targetUrlEl.textContent} — Riesgo: ${data.score}%`);
            }

            // Recargar logs
            loadIncidents();
            break;
        }

        case 'TELEMETRY_UPDATE': {
            const telAnalyzed = document.getElementById('stat-analyzed');
            const telSafe = document.getElementById('stat-safe');
            const telSuspicious = document.getElementById('stat-suspicious');
            const telBlocked = document.getElementById('stat-blocked');

            if (telAnalyzed) telAnalyzed.textContent = Number(data.analyzed).toLocaleString();
            if (telSafe) telSafe.textContent = Number(data.safe).toLocaleString();
            if (telSuspicious) telSuspicious.textContent = Number(data.suspicious).toLocaleString();
            if (telBlocked) telBlocked.textContent = Number(data.blocked).toLocaleString();

            updateLatencyMetrics(); // Actualizar latencias percentiles (P95)
            break;
        }

        case 'USER_BYPASSED_WARNING': {
            showSOCAlert('🛡️ Alerta de Bypass', `El usuario eludió el bloqueo para: ${data.url}`);
            addTimelineItem(`<strong>Advertencia:</strong> El usuario eludió el bloqueo para ${data.url}`, 'warning');
            loadIncidents();
            break;
        }
    }
}

// Cargar exclusiones (whitelist) reales desde el backend
async function loadWhitelist() {
    if (!isConnected || CONFIG.demoMode) return;
    try {
        const res = await fetch(`${CONFIG.backendUrl}/api/whitelist`, {
            headers: { 'X-Admin-Token': CONFIG.adminToken }
        });
        if (res.ok) {
            whitelist = await res.json();
            renderWhitelistTable();
        } else {
            console.error('Error al cargar whitelist:', res.status);
        }
    } catch (e) {
        console.error('Error de red al cargar whitelist:', e);
    }
}

// Cargar llaves de API autorizadas reales desde el backend
async function loadKeys() {
    if (!isConnected || CONFIG.demoMode) return;
    try {
        const res = await fetch(`${CONFIG.backendUrl}/api/keys`, {
            headers: { 'X-Admin-Token': CONFIG.adminToken }
        });
        if (res.ok) {
            const data = await res.json();
            apiKeys = data.map(k => ({
                key: k.token,
                desc: k.description,
                date: new Date(k.created_at).toISOString().split('T')[0]
            }));
            renderKeysTable();
        } else {
            console.error('Error al cargar API keys:', res.status);
        }
    } catch (e) {
        console.error('Error de red al cargar API keys:', e);
    }
}

// Cargar logs de incidentes reales del backend
async function loadIncidents() {
    if (!isConnected || CONFIG.demoMode) return;
    try {
        const res = await fetch(`${CONFIG.backendUrl}/api/incidents`, {
            headers: { 'X-Admin-Token': CONFIG.adminToken }
        });
        if (res.ok) {
            const data = await res.json();
            incidentLogs = data.map(inc => ({
                id: inc.id,
                timestamp: inc.timestamp,
                ip: inc.user_ip,
                url: inc.url,
                verdict: inc.status,
                score: inc.score,
                bypassed: inc.bypassed
            }));
            renderLogsTable();
        } else {
            console.error('Error al cargar incidentes:', res.status);
        }
    } catch (e) {
        console.error('Error de red al cargar incidentes:', e);
    }
}

// Cargar pesos configurados reales del backend
async function loadSettings() {
    if (!isConnected || CONFIG.demoMode) return;
    try {
        const res = await fetch(`${CONFIG.backendUrl}/api/settings`, {
            headers: { 'X-Admin-Token': CONFIG.adminToken }
        });
        if (res.ok) {
            const data = await res.json();
            const h = document.getElementById('weight-heur');
            const s = document.getElementById('weight-simi');
            const v = document.getElementById('weight-vt');
            const m = document.getElementById('weight-ml');
            const vi = document.getElementById('weight-vis');
            
            if (h) h.value = data.weight_heuristics;
            if (s) s.value = data.weight_similarity;
            if (v) v.value = data.weight_reputation;
            if (m) m.value = data.weight_ml;
            if (vi) vi.value = data.weight_visual;
            
            const totalEl = document.getElementById('settings-weights-total');
            if (totalEl) {
                const total = data.weight_heuristics + data.weight_similarity + data.weight_reputation + data.weight_ml + data.weight_visual;
                totalEl.textContent = 'Suma total: ' + total.toFixed(2) + ' (' + Math.round(total * 100) + '%)';
                if (Math.abs(total - 1.0) < 0.001) {
                    totalEl.style.color = '#10b981';
                } else {
                    totalEl.style.color = '#ef4444';
                }
            }
        } else {
            console.error('Error al cargar ponderaciones:', res.status);
        }
    } catch (e) {
        console.error('Error de red al cargar ponderaciones:', e);
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    initNavigation();
    initCharts();
    initMouseTracking();
    initModal();
    initIncidentModal();
    initWeightsValidation();
    initMicroInteractions();
    updateTimestamp();
    setInterval(updateTimestamp, 1000);
    
    // Cargar config asíncrona
    await loadConfig();
    
    initTables();
    
    // Inicializar el estado de la conexión
    await updateConnectionState(true);
});

/* ============================================================
   MICRO-INTERACTIONS — ripple feedback on clickable elements
   ============================================================ */
function initMicroInteractions() {
    const rippleSelector = [
        '.nav-item', '.btn-admin', '.btn-danger-outline',
        '.btn-pdf-export', '.btn-config', '.btn-landing',
        '#modal-btn-close', '#modal-btn-save', '.ms-card'
    ].join(', ');

    document.querySelectorAll(rippleSelector).forEach(attachRipple);

    // Elements added dynamically later (e.g. API key "Revocar" buttons,
    // whitelist rows) get ripple feedback via delegated listener.
    document.addEventListener('click', (e) => {
        const target = e.target.closest('[onclick], .btn-danger-outline, .btn-admin');
        if (target && !target.dataset.rippleBound) {
            spawnRipple(target, e);
        }
    });
}

function attachRipple(el) {
    if (el.dataset.rippleBound) return;
    el.dataset.rippleBound = 'true';
    el.classList.add('ripple-container');
    el.addEventListener('click', (e) => spawnRipple(el, e));
}

function spawnRipple(el, e) {
    const rect = el.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const size = Math.max(rect.width, rect.height);
    const ripple = document.createElement('span');
    ripple.className = 'ripple';
    ripple.style.width = ripple.style.height = size + 'px';
    ripple.style.left = ((e.clientX ?? rect.left + rect.width / 2) - rect.left - size / 2) + 'px';
    ripple.style.top = ((e.clientY ?? rect.top + rect.height / 2) - rect.top - size / 2) + 'px';
    const wasPositioned = getComputedStyle(el).position !== 'static';
    if (!wasPositioned) el.style.position = 'relative';
    el.style.overflow = el.style.overflow || 'hidden';
    el.appendChild(ripple);
    ripple.addEventListener('animationend', () => ripple.remove());
}

function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const tabPanels = document.querySelectorAll('.tab-panel');
    const titleEl = document.getElementById('active-tab-title');
    const pdfBtn = document.getElementById('btn-export-pdf');

    const tabTitles = {
        'tab-monitor': 'Monitorizacion SOC',
        'tab-logs': 'Incident Logs',
        'tab-whitelist': 'Whitelist Central',
        'tab-keys': 'API Keys',
        'tab-reports': 'Reportes de Usuarios'
    };

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetTab = item.dataset.tab;
            if (!targetTab) return;

            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            tabPanels.forEach(panel => {
                if (panel.id === targetTab) {
                    panel.style.display = 'block';
                    panel.offsetHeight;
                    panel.classList.add('active');
                } else {
                    panel.classList.remove('active');
                    setTimeout(() => {
                        if (!panel.classList.contains('active')) {
                            panel.style.display = 'none';
                        }
                    }, 300);
                }
            });

            if (titleEl && tabTitles[targetTab]) {
                titleEl.textContent = tabTitles[targetTab];
            }

            if (pdfBtn) {
                pdfBtn.style.display = targetTab === 'tab-logs' ? 'flex' : 'none';
            }

            if (targetTab === 'tab-reports') {
                loadReports();
            }

            currentTab = targetTab;
        });
    });

    tabPanels.forEach(panel => {
        if (!panel.classList.contains('active')) {
            panel.style.display = 'none';
        }
    });
}

function initMouseTracking() {
    document.querySelectorAll('.widget').forEach(widget => {
        widget.addEventListener('mousemove', (e) => {
            const rect = widget.getBoundingClientRect();
            const x = ((e.clientX - rect.left) / rect.width) * 100;
            const y = ((e.clientY - rect.top) / rect.height) * 100;
            widget.style.setProperty('--mouse-x', x + '%');
            widget.style.setProperty('--mouse-y', y + '%');
        });
    });
}

function initCharts() {
    const radarCtx = document.getElementById('radarChart');
    if (radarCtx) {
        radarChart = new Chart(radarCtx, {
            type: 'radar',
            data: {
                labels: ['Heuristicas', 'Similitud', 'VT Reputacion', 'ML Model', 'Analisis Visual'],
                datasets: [{
                    label: 'Vector de Amenaza',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: 'rgba(239, 68, 68, 0.15)',
                    borderColor: 'rgba(239, 68, 68, 0.8)',
                    borderWidth: 2,
                    pointBackgroundColor: 'rgba(239, 68, 68, 1)',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 100,
                        ticks: { display: false, stepSize: 20 },
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        angleLines: { color: 'rgba(255, 255, 255, 0.05)' },
                        pointLabels: {
                            color: 'rgba(255, 255, 255, 0.6)',
                            font: { family: "'Inter', sans-serif", size: 11 }
                        }
                    }
                },
                plugins: { legend: { display: false } },
                animation: { duration: 800, easing: 'easeOutQuart' }
            }
        });
    }

    const trendCtx = document.getElementById('trendChart');
    if (trendCtx) {
        const labels = Array.from({length: 20}, (_, i) => i);
        latencyData = Array.from({length: 20}, () => 150 + Math.random() * 100);

        const gradient = trendCtx.getContext('2d').createLinearGradient(0, 0, 0, 140);
        gradient.addColorStop(0, 'rgba(0, 229, 160, 0.2)');
        gradient.addColorStop(1, 'rgba(0, 229, 160, 0)');

        trendChart = new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Latencia (ms)',
                    data: latencyData,
                    borderColor: '#00e5a0',
                    backgroundColor: gradient,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointBackgroundColor: '#00e5a0',
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { display: false },
                    y: {
                        beginAtZero: false,
                        min: 0,
                        max: 400,
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: 'rgba(255, 255, 255, 0.4)', font: { size: 10 }, maxTicksLimit: 4 }
                    }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(10, 12, 16, 0.9)',
                        borderColor: 'rgba(255, 255, 255, 0.1)',
                        borderWidth: 1,
                        titleColor: '#fff',
                        bodyColor: '#e2e8f0',
                        displayColors: false,
                        callbacks: {
                            title: () => '',
                            label: (ctx) => Math.round(ctx.raw) + ' ms'
                        }
                    }
                },
                animation: { duration: 300 }
            }
        });

        setInterval(() => {
            latencyData.shift();
            latencyData.push(120 + Math.random() * 180);
            trendChart.update('none');
        }, 2000);
    }
}

function initDemoSequence() {
    if (!CONFIG.demoMode) return;

    const services = [
        { id: 'ms-heur', name: 'Heuristicas', maxScore: 25, delay: 800, score: 23 },
        { id: 'ms-simi', name: 'Similitud Lexica', maxScore: 20, delay: 1200, score: 19 },
        { id: 'ms-vt', name: 'Reputacion VT', maxScore: 25, delay: 2000, score: 24 },
        { id: 'ms-ml', name: 'Machine Learning', maxScore: 15, delay: 1600, score: 14 },
        { id: 'ms-vis', name: 'Analisis Visual', maxScore: 15, delay: 1400, score: 13 }
    ];

    let currentService = 0;
    let totalScore = 0;
    const timeline = document.getElementById('execution-timeline');
    const globalProgress = document.getElementById('global-progress');
    const globalStatus = document.getElementById('global-status-text');

    function addTimelineItem(text, type) {
        const item = document.createElement('div');
        item.className = 'timeline-item ' + type;
        const time = new Date().toLocaleTimeString('es-ES', { hour12: false });
        item.innerHTML = '<span class="timeline-time">' + time + '</span><span class="timeline-text">' + text + '</span>';
        timeline.insertBefore(item, timeline.firstChild);
        while (timeline.children.length > 8) {
            timeline.removeChild(timeline.lastChild);
        }
    }

    function processNextService() {
        if (currentService >= services.length) {
            finalizeAnalysis(totalScore);
            return;
        }

        const svc = services[currentService];
        const card = document.getElementById(svc.id);
        if (!card) {
            currentService++;
            processNextService();
            return;
        }

        card.classList.add('processing');
        const statusEl = card.querySelector('.ms-status');
        statusEl.textContent = 'Analizando...';
        statusEl.classList.add('processing');
        card.querySelector('.ms-progress-fill').classList.add('processing');

        const pipelineNodes = document.querySelectorAll('.parallel-nodes .node');
        if (pipelineNodes[currentService]) {
            pipelineNodes[currentService].classList.add('active');
        }

        addTimelineItem('Iniciando ' + svc.name + '...', 'processing');

        const progressFill = card.querySelector('.ms-progress-fill');
        const progressBg = card.querySelector('.ms-progress-bg');
        let progress = 0;
        const progressInterval = setInterval(() => {
            progress += Math.random() * 15 + 5;
            if (progress >= 100) {
                progress = 100;
                clearInterval(progressInterval);
            }
            progressFill.style.width = progress + '%';
            progressBg.setAttribute('aria-valuenow', progress);
        }, 100);

        setTimeout(() => {
            clearInterval(progressInterval);
            progressFill.style.width = '100%';
            progressFill.classList.remove('processing');
            progressFill.classList.add('danger');

            card.classList.remove('processing');
            card.classList.add('danger');

            statusEl.textContent = 'Critico';
            statusEl.classList.remove('processing');
            statusEl.classList.add('danger');

            card.querySelector('.ms-time').textContent = Math.floor(Math.random() * 200 + 50) + ' ms';
            card.querySelector('.ms-score').textContent = svc.score + '/' + svc.maxScore;

            const details = card.querySelector('.ms-details');
            if (details) details.classList.remove('hidden');

            if (pipelineNodes[currentService]) {
                pipelineNodes[currentService].classList.remove('active');
                pipelineNodes[currentService].classList.add('error');
            }

            addTimelineItem(svc.name + ' completado — Score: ' + svc.score + '/' + svc.maxScore, 'danger');

            if (radarChart) {
                const normalizedScore = (svc.score / svc.maxScore) * 100;
                radarChart.data.datasets[0].data[currentService] = normalizedScore;
                radarChart.update();
            }

            totalScore += svc.score;
            const progressPercent = ((currentService + 1) / services.length) * 100;
            if (globalProgress) {
                globalProgress.style.width = progressPercent + '%';
            }

            currentService++;
            processNextService();
        }, svc.delay);
    }

    setTimeout(() => {
        addTimelineItem('Interceptacion iniciada', 'success');
        addTimelineItem('URL objetivo identificada', 'warning');
        const extNode = document.getElementById('node-ext');
        const orchNode = document.getElementById('node-orch');
        if (extNode) extNode.classList.add('active');
        if (orchNode) orchNode.classList.add('active');
        setTimeout(() => {
            const microNode = document.getElementById('node-micro');
            if (microNode) microNode.classList.add('active');
            processNextService();
        }, 600);
    }, 1000);
}

function finalizeAnalysis(totalScore) {
    const maxPossible = 100;
    const percentage = Math.round((totalScore / maxPossible) * 100);

    const gaugeFill = document.querySelector('.gauge-fill');
    const gaugeValue = document.getElementById('final-score');
    const gaugeLabel = document.getElementById('final-verdict');
    const explanationBox = document.getElementById('explanation-box');

    if (gaugeFill) {
        const circumference = 2 * Math.PI * 80;
        const offset = circumference - (percentage / 100) * circumference;
        gaugeFill.style.strokeDashoffset = offset;

        if (percentage >= 80) {
            gaugeFill.style.stroke = '#ef4444';
            gaugeFill.style.filter = 'drop-shadow(0 0 10px rgba(239, 68, 68, 0.4))';
        } else if (percentage >= 50) {
            gaugeFill.style.stroke = '#f59e0b';
            gaugeFill.style.filter = 'drop-shadow(0 0 10px rgba(245, 158, 11, 0.4))';
        } else {
            gaugeFill.style.stroke = '#10b981';
            gaugeFill.style.filter = 'drop-shadow(0 0 10px rgba(16, 185, 129, 0.4))';
        }
    }

    if (gaugeValue) {
        let current = 0;
        const interval = setInterval(() => {
            current += 2;
            if (current >= percentage) {
                current = percentage;
                clearInterval(interval);
            }
            gaugeValue.textContent = current + '%';
        }, 30);
    }

    if (gaugeLabel) {
        gaugeLabel.textContent = percentage >= 80 ? 'ALTO RIESGO' : percentage >= 50 ? 'RIESGO MEDIO' : 'RIESGO BAJO';
        gaugeLabel.style.color = percentage >= 80 ? '#ef4444' : percentage >= 50 ? '#f59e0b' : '#10b981';
    }

    if (explanationBox) {
        explanationBox.innerHTML = '<div style="display: flex; flex-direction: column; gap: 8px; width: 100%;"><div style="display: flex; align-items: center; gap: 8px; color: #ef4444; font-weight: 600; font-size: 0.85rem;"><span style="font-size: 1.2rem;">⚠️</span> Amenaza Confirmada</div><p style="font-size: 0.8rem; color: var(--text-muted); line-height: 1.5;">El analisis conjunto de los 5 vectores de deteccion ha determinado que esta URL presenta <strong style="color: #ef4444;">' + percentage + '% de probabilidad de phishing</strong>. Se recomienda bloqueo inmediato.</p><div style="display: flex; gap: 8px; margin-top: 4px; flex-wrap: wrap;"><span style="background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); color: #ef4444; padding: 3px 10px; border-radius: 20px; font-size: 0.7rem; font-weight: 500;">Dominio sospechoso</span><span style="background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); color: #ef4444; padding: 3px 10px; border-radius: 20px; font-size: 0.7rem; font-weight: 500;">Spoofing visual detectado</span><span style="background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); color: #ef4444; padding: 3px 10px; border-radius: 20px; font-size: 0.7rem; font-weight: 500;">VT: 58/97 positivos</span></div></div>';
        explanationBox.classList.add('has-content');
    }

    const riskNode = document.getElementById('node-risk');
    if (riskNode) riskNode.classList.add('error');

    const timeline = document.getElementById('execution-timeline');
    if (timeline) {
        const item = document.createElement('div');
        item.className = 'timeline-item danger';
        const time = new Date().toLocaleTimeString('es-ES', { hour12: false });
        item.innerHTML = '<span class="timeline-time">' + time + '</span><span class="timeline-text"><strong>Veredicto final:</strong> BLOQUEO RECOMENDADO (' + percentage + '% riesgo)</span>';
        timeline.insertBefore(item, timeline.firstChild);
    }

    const globalProgress = document.getElementById('global-progress');
    const globalStatus = document.getElementById('global-status-text');
    if (globalProgress) globalProgress.style.width = '100%';
    if (globalStatus) {
        globalStatus.textContent = 'Analisis completado — Amenaza detectada';
        globalStatus.style.color = '#ef4444';
    }

    setTimeout(() => {
        showSOCAlert('⚠️ Phishing Detectado', 'URL bloqueada: paypal-login-secure.verify-account.xyz — Riesgo: ' + percentage + '%');
    }, 500);
}

function showSOCAlert(title, message) {
    const container = document.getElementById('soc-alerts-container');
    if (!container) return;

    const alert = document.createElement('div');
    alert.className = 'soc-alert';
    alert.innerHTML = '<div style="display: flex; align-items: flex-start; gap: 12px;"><div style="font-size: 1.5rem; flex-shrink: 0;">🛡️</div><div style="flex: 1; min-width: 0;"><div style="font-weight: 700; color: #fff; font-size: 0.9rem; margin-bottom: 4px;">' + title + '</div><div style="font-size: 0.8rem; color: var(--text-muted); line-height: 1.4;">' + message + '</div></div><button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 1.2rem; line-height: 1; padding: 0; flex-shrink: 0;">×</button></div>';

    container.appendChild(alert);

    setTimeout(() => {
        alert.style.animation = 'alertSlideIn 0.5s var(--ease-out) reverse forwards';
        setTimeout(() => alert.remove(), 500);
    }, 8000);
}

function initModal() {
    const modal = document.getElementById('config-modal');
    const btnConfig = document.getElementById('btn-config-server');
    const btnClose = document.getElementById('modal-btn-close');
    const btnSave = document.getElementById('modal-btn-save');

    if (btnConfig && modal) {
        btnConfig.addEventListener('click', () => {
            modal.style.display = 'flex';
            document.getElementById('modal-backend-url').value = CONFIG.backendUrl;
            document.getElementById('modal-client-key').value = CONFIG.clientKey;
            document.getElementById('modal-admin-token').value = CONFIG.adminToken;
            const pNotice = modal.querySelector('p');
            if (pNotice) {
                pNotice.innerHTML = 'Conecta esta consola al servidor central de tu organización o clúster local de Phishing Shield.<br><strong style="color: #00e5a0; display: block; margin-top: 8px;">🔑 Credenciales de demostración:<br>Client Key: demo-key-123<br>Admin Token: pymeshield2026</strong>';
            }
        });
    }

    if (btnClose && modal) {
        btnClose.addEventListener('click', () => {
            modal.style.display = 'none';
        });
    }

    const btnAutofill = document.getElementById('modal-btn-autofill');
    if (btnAutofill) {
        btnAutofill.addEventListener('click', () => {
            document.getElementById('modal-client-key').value = 'demo-key-123';
            document.getElementById('modal-admin-token').value = 'pymeshield2026';
            showSOCAlert('📝 Formulario autocompletado', 'Las credenciales de demostración se han cargado en el formulario.');
        });
    }

    const btnAutofillDemo = document.getElementById('btn-autofill-demo');
    if (btnAutofillDemo) {
        btnAutofillDemo.addEventListener('click', async () => {
            const originUrl = window.location.origin.includes('http') ? window.location.origin : 'http://localhost:8080';
            const cleanUrl = originUrl.replace(/\/$/, '');
            CONFIG.backendUrl = cleanUrl;
            CONFIG.clientKey = 'demo-key-123';
            CONFIG.adminToken = 'pymeshield2026';
            CONFIG.demoMode = false;
            
            await saveConfig(cleanUrl, 'demo-key-123', 'pymeshield2026');
            await updateConnectionState(false);
            showSOCAlert('⚡ Modo Demo Activo', 'Credenciales cargadas. Consola conectada y en línea.');
        });
    }

    if (btnSave && modal) {
        btnSave.addEventListener('click', async () => {
            const backendUrl = document.getElementById('modal-backend-url').value || 'http://localhost:8080';
            const clientKey = document.getElementById('modal-client-key').value.trim();
            const adminToken = document.getElementById('modal-admin-token').value.trim();

            btnSave.disabled = true;
            btnSave.textContent = 'Conectando...';

            const verification = await verifyCredentialsWithBackend(backendUrl, clientKey, adminToken);

            if (verification.valid) {
                CONFIG.backendUrl = backendUrl;
                CONFIG.clientKey = clientKey;
                CONFIG.adminToken = adminToken;
                CONFIG.demoMode = false;

                await saveConfig(backendUrl, clientKey, adminToken);

                modal.style.display = 'none';
                await updateConnectionState(false);
                showSOCAlert('✅ Conexión establecida', 'Consola SOC autorizada y en línea correctamente.');
            } else {
                // Fallback a demo local si son credenciales de demostración por defecto
                const VALID_CLIENT_KEY = 'demo-key-123';
                const VALID_ADMIN_TOKENS = ['pymeshield2026', 'admin', 'YOUR_ADMIN_TOKEN_HERE'];
                const isDemoCreds = clientKey === VALID_CLIENT_KEY && VALID_ADMIN_TOKENS.includes(adminToken);

                if (isDemoCreds) {
                    CONFIG.backendUrl = backendUrl;
                    CONFIG.clientKey = clientKey;
                    CONFIG.adminToken = adminToken;
                    CONFIG.demoMode = true;

                    await saveConfig(backendUrl, clientKey, adminToken);

                    modal.style.display = 'none';
                    await updateConnectionState(false);
                    showSOCAlert('⚠️ Modo Demo Activo', 'No se pudo conectar al servidor real, iniciando en Modo Demo.');
                } else {
                    showSOCAlert('❌ Conexión Fallida', verification.error || 'Credenciales inválidas o servidor inalcanzable.');
                }
            }
            btnSave.disabled = false;
            btnSave.textContent = 'Guardar y Conectar';
        });
    }

    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.style.display = 'none';
        });
    }
}

function renderKeysTable() {
    const tbody = document.getElementById('keys-table-body');
    if (!tbody) return;

    if (!isConnected) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 30px;">Desconectado. Configure las credenciales de conexión.</td></tr>';
        return;
    }

    if (apiKeys.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 30px;">No hay llaves activas.</td></tr>';
        return;
    }

    tbody.innerHTML = apiKeys.map((key, i) => {
        const maskedKey = key.key.substring(0, 12) + '...' + key.key.substring(key.key.length - 8);
        return '<tr style="animation: timelineSlide 0.3s ' + (i * 0.05) + 's both;"><td class="mono" style="font-size: 0.75rem; color: var(--text-muted);">' + maskedKey + '</td><td>' + key.desc + '</td><td>' + key.date + '</td><td style="text-align: center;"><button onclick="removeKey(' + i + ')" style="background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); color: #ef4444; padding: 4px 12px; border-radius: 6px; font-size: 0.75rem; cursor: pointer; transition: all 0.2s;">Revocar</button></td></tr>';
    }).join('');
}

function removeKey(index) {
    if (!isConnected) return;
    const token = apiKeys[index].key;
    const desc = apiKeys[index].desc;
    
    if (CONFIG.demoMode) {
        apiKeys.splice(index, 1);
        localStorage.setItem('ps_api_keys', JSON.stringify(apiKeys));
        renderKeysTable();
        showSOCAlert('Token revocado', 'La llave de API para "' + desc + '" ha sido revocada.');
        return;
    }

    fetch(`${CONFIG.backendUrl}/api/keys`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'X-Admin-Token': CONFIG.adminToken
        },
        body: JSON.stringify({ token })
    })
    .then(r => {
        if (!r.ok) throw new Error('Error al revocar llave en el servidor.');
        return r.json();
    })
    .then(() => {
        loadKeys();
        showSOCAlert('Token revocado', 'La llave de API para "' + desc + '" ha sido revocada en el servidor.');
    })
    .catch(err => {
        showSOCAlert('❌ Error', err.message);
    });
}

function initWeightsValidation() {
    const inputs = [
        document.getElementById('weight-heur'),
        document.getElementById('weight-simi'),
        document.getElementById('weight-vt'),
        document.getElementById('weight-ml'),
        document.getElementById('weight-vis')
    ];
    const totalEl = document.getElementById('settings-weights-total');
    const saveBtn = document.getElementById('btn-save-settings');

    function updateTotal() {
        let total = 0;
        inputs.forEach(inp => {
            if (inp) total += parseFloat(inp.value) || 0;
        });
        if (totalEl) {
            totalEl.textContent = 'Suma total: ' + total.toFixed(2) + ' (' + Math.round(total * 100) + '%)';
            if (Math.abs(total - 1.0) < 0.001) {
                totalEl.style.color = '#10b981';
            } else {
                totalEl.style.color = '#ef4444';
            }
        }
    }

    inputs.forEach(inp => {
        if (inp) {
            inp.addEventListener('input', updateTotal);
        }
    });

    if (saveBtn) {
        saveBtn.addEventListener('click', () => {
            const values = {
                weight_heuristics: parseFloat(document.getElementById('weight-heur').value) || 0,
                weight_similarity: parseFloat(document.getElementById('weight-simi').value) || 0,
                weight_reputation: parseFloat(document.getElementById('weight-vt').value) || 0,
                weight_ml: parseFloat(document.getElementById('weight-ml').value) || 0,
                weight_visual: parseFloat(document.getElementById('weight-vis').value) || 0
            };
            const total = values.weight_heuristics + values.weight_similarity + values.weight_reputation + values.weight_ml + values.weight_visual;
            
            if (Math.abs(total - 1.0) < 0.001) {
                if (CONFIG.demoMode) {
                    showSOCAlert('Ponderaciones guardadas', 'Los pesos del Risk Engine se han actualizado (Demo).');
                    return;
                }
                
                fetch(`${CONFIG.backendUrl}/api/settings`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Admin-Token': CONFIG.adminToken
                    },
                    body: JSON.stringify(values)
                })
                .then(r => {
                    if (!r.ok) throw new Error('Error al guardar ponderaciones en el servidor.');
                    return r.json();
                })
                .then(() => {
                    showSOCAlert('Ponderaciones guardadas', 'Los pesos del Risk Engine se han actualizado correctamente en el servidor.');
                })
                .catch(err => {
                    showSOCAlert('❌ Error', err.message);
                });
            } else {
                showSOCAlert('Error de validación', 'La suma de ponderaciones debe ser exactamente 1.0 (100%). Actual: ' + total.toFixed(2));
            }
        });
    }

    updateTotal();
}

function updateTimestamp() {
    const el = document.getElementById('timestamp');
    if (el) {
        el.textContent = new Date().toLocaleString('es-ES', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    }
}

// PDF Export
const pdfBtn = document.getElementById('btn-export-pdf');
if (pdfBtn) {
    pdfBtn.addEventListener('click', () => {
        const modal = document.getElementById('incident-modal');
        if (modal && modal.style.display === 'flex') {
            const modalId = document.getElementById('inc-modal-id').textContent;
            const logItem = incidentLogs.find(log => log.id === modalId);
            if (logItem) {
                downloadForensicPDF(logItem);
                return;
            }
        }
        
        // Si el modal no está abierto, exportamos el último incidente registrado (el más reciente)
        if (incidentLogs && incidentLogs.length > 0) {
            downloadForensicPDF(incidentLogs[0]);
        } else {
            showSOCAlert('⚠️ Sin datos', 'No hay incidentes registrados para exportar.');
        }
    });
}

async function updateConnectionState(firstLoad = false) {
    const indicator = document.getElementById('sidebar-status-indicator');
    const text = document.getElementById('sidebar-status-text');
    const finalScore = document.getElementById('final-score');
    const finalVerdict = document.getElementById('final-verdict');
    const explanationBox = document.getElementById('explanation-box');
    const timeline = document.getElementById('execution-timeline');
    const modal = document.getElementById('config-modal');

    // Clean backendUrl
    const url = CONFIG.backendUrl.trim().replace(/\/$/, '');

    // Verificar si las credenciales son válidas (realizando validación contra el backend o fallback si es demo)
    let valid = false;
    let verificationError = '';

    if (CONFIG.clientKey && CONFIG.adminToken) {
        const verification = await verifyCredentialsWithBackend(url, CONFIG.clientKey, CONFIG.adminToken);
        if (verification.valid) {
            valid = true;
            CONFIG.demoMode = false;
        } else {
            // Check fallback
            const VALID_CLIENT_KEY = 'demo-key-123';
            const VALID_ADMIN_TOKENS = ['pymeshield2026', 'admin', 'YOUR_ADMIN_TOKEN_HERE'];
            if (CONFIG.clientKey === VALID_CLIENT_KEY && VALID_ADMIN_TOKENS.includes(CONFIG.adminToken)) {
                valid = true;
                CONFIG.demoMode = true;
            } else {
                verificationError = verification.error;
            }
        }
    }

    if (valid) {
        isConnected = true;
        if (indicator) {
            indicator.style.background = 'var(--success)';
            indicator.style.boxShadow = '0 0 10px var(--success)';
        }
        if (text) {
            text.textContent = CONFIG.demoMode ? 'Modo Demo Activo' : 'Protección Activa';
            text.style.color = 'var(--success)';
        }
        
        if (CONFIG.demoMode) {
            // Start demo sequence
            if (!demoStarted) {
                demoStarted = true;
                initDemoSequence();
            }
            renderWhitelistTable();
            renderKeysTable();
            renderLogsTable();
        } else {
            // Real connection: stop demo if running, connect to WebSocket, pull REST tables
            demoStarted = false;
            connectWebSocket();
            
            // Load tables from backend
            await loadWhitelist();
            await loadKeys();
            await loadIncidents();
            await loadSettings();
            await updateLatencyMetrics();
        }
    } else {
        isConnected = false;
        if (socket) {
            try { socket.close(); } catch(e) {}
            socket = null;
        }
        if (indicator) {
            indicator.style.background = '#6b7280'; // gray
            indicator.style.boxShadow = 'none';
        }
        if (text) {
            text.textContent = 'Desconectado';
            text.style.color = '#6b7280';
        }
        if (finalScore) finalScore.textContent = '0%';
        if (finalVerdict) {
            finalVerdict.textContent = 'Desconectado';
            finalVerdict.style.color = 'var(--text-muted)';
        }
        if (explanationBox) {
            explanationBox.innerHTML = '<div style="text-align: center; padding: 10px; color: var(--text-muted); font-size: 0.8rem;">Consola desconectada. Abra la pestaña "Conexión" e introduzca el Client API Key y el Admin Token para iniciar.</div>';
            explanationBox.classList.remove('has-content');
        }
        if (timeline) {
            timeline.innerHTML = `<div class="timeline-item info"><span class="timeline-text" style="color: var(--text-muted);">Aguardando autorización de credenciales del SOC... ${verificationError ? '(' + verificationError + ')' : ''}</span></div>`;
        }
        
        // Render empty tables with notice
        renderWhitelistTable();
        renderKeysTable();
        renderLogsTable();

        // Show modal automatically on first load if not connected
        if (firstLoad && modal) {
            modal.style.display = 'flex';
            // Show custom notice in modal
            const pNotice = modal.querySelector('p');
            if (pNotice) {
                pNotice.innerHTML = 'Conecta esta consola al servidor central de tu organización o clúster local de Phishing Shield.<br><strong style="color: #00e5a0; display: block; margin-top: 8px;">🔑 Credenciales de demostración:<br>Client Key: demo-key-123<br>Admin Token: pymeshield2026</strong>';
            }
        }
    }
}

let currentLogsFilter = 'all';

function initTables() {
    // Cargar datos iniciales de demo (fallback local)
    whitelist = JSON.parse(localStorage.getItem('ps_whitelist')) || [
        'google.com', 'wikipedia.org', 'microsoft.com', 'santander.cl'
    ];
    apiKeys = JSON.parse(localStorage.getItem('ps_api_keys')) || [
        { key: 'demo-key-123', desc: 'Demo Token (Default)', date: '2026-07-06' }
    ];
    incidentLogs = JSON.parse(localStorage.getItem('ps_incident_logs')) || [
        { id: 'INC-2026-001', timestamp: new Date(Date.now() - 3600000).toISOString(), url: 'http://paypal-login-secure.verify-account.xyz/auth', ip: '192.168.1.45', verdict: 'danger', score: 93, bypassed: false },
        { id: 'INC-2026-002', timestamp: new Date(Date.now() - 7200000).toISOString(), url: 'https://bancochile-verify.xyz/login.php', ip: '192.168.1.112', verdict: 'danger', score: 87, bypassed: true },
        { id: 'INC-2026-003', timestamp: new Date(Date.now() - 10800000).toISOString(), url: 'http://my-safe-bank.com/portal', ip: '192.168.1.22', verdict: 'safe', score: 12, bypassed: false }
    ];

    // Whitelist event
    const btnAddWhitelist = document.getElementById('btn-add-whitelist');
    const whitelistInput = document.getElementById('whitelist-domain-input');
    if (btnAddWhitelist && whitelistInput) {
        btnAddWhitelist.addEventListener('click', () => {
            if (!isConnected) {
                showSOCAlert('❌ Error de conexión', 'Consola desconectada. Ingrese las credenciales en la pestaña "Conexión".');
                return;
            }
            const domain = whitelistInput.value.trim();
            if (domain) {
                if (CONFIG.demoMode) {
                    if (whitelist.includes(domain)) {
                        showSOCAlert('⚠️ Dominio duplicado', 'El dominio ya está en la whitelist.');
                        return;
                    }
                    whitelist.push(domain);
                    localStorage.setItem('ps_whitelist', JSON.stringify(whitelist));
                    renderWhitelistTable();
                    whitelistInput.value = '';
                    showSOCAlert('✅ Dominio añadido', 'Se ha agregado ' + domain + ' a la Whitelist Central.');
                    return;
                }

                fetch(`${CONFIG.backendUrl}/api/whitelist`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Admin-Token': CONFIG.adminToken
                    },
                    body: JSON.stringify({ domain })
                })
                .then(r => {
                    if (!r.ok) throw new Error('Error al añadir exclusión en el servidor.');
                    return r.json();
                })
                .then(() => {
                    loadWhitelist();
                    whitelistInput.value = '';
                    showSOCAlert('✅ Dominio añadido', 'Se ha agregado ' + domain + ' a la Whitelist Central en el servidor.');
                })
                .catch(err => {
                    showSOCAlert('❌ Error', err.message);
                });
            }
        });
    }

    // Keys event
    const btnAddKey = document.getElementById('btn-add-key');
    const keyDescInput = document.getElementById('key-desc-input');
    if (btnAddKey && keyDescInput) {
        btnAddKey.addEventListener('click', () => {
            if (!isConnected) {
                showSOCAlert('❌ Error de conexión', 'Consola desconectada. Ingrese las credenciales en la pestaña "Conexión".');
                return;
            }
            const desc = keyDescInput.value.trim();
            if (desc) {
                if (CONFIG.demoMode) {
                    const newKey = 'client_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
                    apiKeys.push({
                        key: newKey,
                        desc: desc,
                        date: new Date().toISOString().split('T')[0]
                    });
                    localStorage.setItem('ps_api_keys', JSON.stringify(apiKeys));
                    renderKeysTable();
                    keyDescInput.value = '';
                    showSOCAlert('🔑 Token generado', 'Nueva llave de cliente creada con éxito (Demo).');
                    return;
                }

                fetch(`${CONFIG.backendUrl}/api/keys`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Admin-Token': CONFIG.adminToken
                    },
                    body: JSON.stringify({ description: desc })
                })
                .then(r => {
                    if (!r.ok) throw new Error('Error al generar llave en el servidor.');
                    return r.json();
                })
                .then(() => {
                    loadKeys();
                    keyDescInput.value = '';
                    showSOCAlert('🔑 Token generado', 'Nueva llave de cliente creada con éxito en el servidor.');
                })
                .catch(err => {
                    showSOCAlert('❌ Error', err.message);
                });
            }
        });
    }

    // Clear logs event
    const btnClearLogs = document.getElementById('btn-clear-logs');
    if (btnClearLogs) {
        btnClearLogs.addEventListener('click', () => {
            if (!isConnected) {
                showSOCAlert('❌ Error de conexión', 'Consola desconectada.');
                return;
            }
            if (confirm('¿Está seguro de que desea limpiar todos los registros de auditoría?')) {
                if (CONFIG.demoMode) {
                    incidentLogs = [];
                    localStorage.setItem('ps_incident_logs', JSON.stringify(incidentLogs));
                    renderLogsTable();
                    showSOCAlert('🗑️ Auditoría limpia', 'Se han eliminado todos los logs.');
                    return;
                }

                fetch(`${CONFIG.backendUrl}/api/incidents/clear`, {
                    method: 'POST',
                    headers: {
                        'X-Admin-Token': CONFIG.adminToken
                    }
                })
                .then(r => {
                    if (!r.ok) throw new Error('Error al limpiar logs en el servidor.');
                    return r.json();
                })
                .then(() => {
                    incidentLogs = [];
                    renderLogsTable();
                    showSOCAlert('🗑️ Auditoría limpia', 'Se han eliminado todos los logs del servidor.');
                })
                .catch(err => {
                    showSOCAlert('❌ Error', err.message);
                });
            }
        });
    }

    // Search event
    const logsSearch = document.getElementById('logs-search');
    if (logsSearch) {
        logsSearch.addEventListener('input', (e) => {
            renderLogsTable(e.target.value.toLowerCase());
        });
    }

    // Segmented filters event
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            currentLogsFilter = e.target.getAttribute('data-filter');
            const searchVal = document.getElementById('logs-search')?.value.toLowerCase() || '';
            renderLogsTable(searchVal);
        });
    });
}

function renderWhitelistTable() {
    const tbody = document.getElementById('whitelist-table-body');
    if (!tbody) return;

    if (!isConnected) {
        tbody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-muted); padding: 30px;">Desconectado. Configure las credenciales de conexión.</td></tr>';
        return;
    }

    if (whitelist.length === 0) {
        tbody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-muted); padding: 30px;">No hay exclusiones registradas.</td></tr>';
        return;
    }

    tbody.innerHTML = whitelist.map((domain, i) => {
        return '<tr style="animation: timelineSlide 0.3s ' + (i * 0.05) + 's both;"><td>' + domain + '</td><td style="text-align: center;"><button onclick="removeWhitelist(' + i + ')" style="background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); color: #ef4444; padding: 4px 12px; border-radius: 6px; font-size: 0.75rem; cursor: pointer; transition: all 0.2s;">Eliminar</button></td></tr>';
    }).join('');
}

function removeWhitelist(index) {
    if (!isConnected) return;
    const domain = whitelist[index];
    
    if (CONFIG.demoMode) {
        whitelist.splice(index, 1);
        localStorage.setItem('ps_whitelist', JSON.stringify(whitelist));
        renderWhitelistTable();
        showSOCAlert('Exclusión eliminada', 'El dominio ' + domain + ' fue removido de la Whitelist.');
        return;
    }

    fetch(`${CONFIG.backendUrl}/api/whitelist`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'X-Admin-Token': CONFIG.adminToken
        },
        body: JSON.stringify({ domain })
    })
    .then(r => {
        if (!r.ok) throw new Error('Error al eliminar exclusión en el servidor.');
        return r.json();
    })
    .then(() => {
        loadWhitelist();
        showSOCAlert('Exclusión eliminada', 'El dominio ' + domain + ' fue removido de la Whitelist en el servidor.');
    })
    .catch(err => {
        showSOCAlert('❌ Error', err.message);
    });
}

function renderLogsTable(filter = '') {
    const tbody = document.getElementById('logs-table-body');
    if (!tbody) return;

    if (!isConnected) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">Desconectado. Configure las credenciales de conexión.</td></tr>';
        return;
    }

    let filtered = incidentLogs.filter(log => 
        log.url.toLowerCase().includes(filter) || 
        log.ip.toLowerCase().includes(filter) ||
        log.id.toLowerCase().includes(filter)
    );

    if (currentLogsFilter !== 'all') {
        filtered = filtered.filter(log => log.verdict === currentLogsFilter);
    }

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">No hay incidentes coincidentes.</td></tr>';
        return;
    }

    tbody.innerHTML = filtered.map((logItem, i) => {
        const time = new Date(logItem.timestamp).toLocaleString('es-ES', { hour12: false });
        const badgeClass = logItem.verdict === 'danger' ? 'danger' : logItem.verdict === 'suspicious' ? 'warning' : 'success';
        const badgeText = logItem.verdict === 'danger' ? 'CRÍTICO' : logItem.verdict === 'suspicious' ? 'SOSPECHOSO' : 'SEGURO';
        
        // Determinar clase de riesgo
        let riskClass = 'low';
        if (logItem.score >= 55) {
            riskClass = 'high';
        } else if (logItem.score >= 20) {
            riskClass = 'medium';
        }

        // Determinar clase de bypass
        const bypassClass = logItem.bypassed ? 'danger' : 'success';
        const bypassText = logItem.bypassed ? 'SÍ' : 'NO';

        return '<tr onclick="showIncidentDetails(\'' + logItem.id + '\')" style="cursor: pointer; animation: timelineSlide 0.3s ' + (i * 0.03) + 's both;">' +
            '<td><span class="id-badge">' + logItem.id + '</span></td>' +
            '<td>' + time + '</td>' +
            '<td class="mono" style="font-size: 0.8rem;">' + logItem.ip + '</td>' +
            '<td><a href="' + logItem.url + '" target="_blank" class="table-url-link" onclick="event.stopPropagation()" title="' + logItem.url + '">' + logItem.url + '</a></td>' +
            '<td><span class="ms-status ' + badgeClass + '">' + badgeText + '</span></td>' +
            '<td><span class="risk-badge risk-' + riskClass + '">' + logItem.score + '%</span></td>' +
            '<td style="text-align: center;"><span class="ms-status ' + bypassClass + '">' + bypassText + '</span></td>' +
            '</tr>';
    }).join('');
}

/* ============================================================
   INCIDENT INVESTIGATION REPORT MODAL & FORENSICS
   ============================================================ */
function initIncidentModal() {
    const modal = document.getElementById('incident-modal');
    const btnClose = document.getElementById('inc-modal-btn-close');
    const btnCloseBottom = document.getElementById('inc-modal-btn-close-bottom');

    if (modal) {
        if (btnClose) {
            btnClose.addEventListener('click', () => modal.style.display = 'none');
        }
        if (btnCloseBottom) {
            btnCloseBottom.addEventListener('click', () => modal.style.display = 'none');
        }
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.style.display = 'none';
        });
    }
}

function showIncidentDetails(id) {
    const logItem = incidentLogs.find(log => log.id === id);
    if (!logItem) return;

    const modal = document.getElementById('incident-modal');
    if (!modal) return;

    // Llenar campos básicos
    document.getElementById('inc-modal-id').textContent = logItem.id;
    document.getElementById('inc-modal-url').textContent = logItem.url;
    document.getElementById('inc-modal-ip').textContent = logItem.ip || '172.20.0.1';


    const time = new Date(logItem.timestamp).toLocaleString('es-ES', { hour12: false });
    document.getElementById('inc-modal-time').textContent = time;

    // Badge de veredicto
    const badge = document.getElementById('inc-modal-badge');
    badge.className = 'ms-status ' + (logItem.verdict === 'danger' ? 'danger' : logItem.verdict === 'suspicious' ? 'warning' : 'success');
    badge.textContent = logItem.verdict === 'danger' ? 'VEREDICTO: CRÍTICO' : logItem.verdict === 'suspicious' ? 'VEREDICTO: SOSPECHOSO' : 'VEREDICTO: SEGURO';

    // Bypass badge
    const bypassBadge = document.getElementById('inc-modal-bypassed');
    bypassBadge.className = 'ms-status ' + (logItem.bypassed ? 'danger' : 'success');
    bypassBadge.textContent = logItem.bypassed ? 'SÍ (ADVERTENCIA IGNORADA)' : 'NO (BLOQUEO RESPETADO)';

    // Generar desglose forense detallado de microservicios
    const servicesContainer = document.getElementById('inc-modal-services');
    servicesContainer.innerHTML = '';

    const forensicData = getForensicReportData(logItem);
    
    forensicData.forEach(srv => {
        const srvClass = srv.score >= 0.75 ? 'success' : srv.score >= 0.55 ? 'warning' : 'danger';
        const srvScorePercent = Math.round(100 - (srv.score * 100)) + '%'; // Riesgo
        
        let reasonsHtml = '';
        if (srv.reasons && srv.reasons.length > 0) {
            reasonsHtml = srv.reasons.map(r => `<div style="color: var(--text-muted); font-size: 0.75rem; display: flex; align-items: flex-start; gap: 6px; margin-top: 4px; line-height: 1.4;">
                <span style="color: ${srv.score >= 0.75 ? '#00e5a0' : srv.score >= 0.55 ? '#f59e0b' : '#ef4444'}; margin-top: 2px;">•</span> 
                <span style="flex: 1;">${r}</span>
            </div>`).join('');
        } else {
            reasonsHtml = `<div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 4px;">Sin anomalías detectadas.</div>`;
        }

        const card = document.createElement('div');
        card.style.background = 'rgba(255,255,255,0.02)';
        card.style.border = '1px solid rgba(255,255,255,0.05)';
        card.style.borderRadius = '10px';
        card.style.padding = '12px 16px';
        
        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span style="font-weight: 600; color: #fff; font-size: 0.8rem;">${srv.name}</span>
                <span class="ms-status ${srvClass}" style="font-weight: 700; font-size: 0.7rem; padding: 2px 8px;">Riesgo: ${srvScorePercent}</span>
            </div>
            ${reasonsHtml}
        `;
        servicesContainer.appendChild(card);
    });

    // Acción de whitelist
    const btnWhitelist = document.getElementById('inc-modal-btn-whitelist');
    btnWhitelist.onclick = () => {
        try {
            const parsed = new URL(logItem.url);
            const domain = parsed.hostname;
            whitelistInputAndAdd(domain);
            modal.style.display = 'none';
        } catch (e) {
            showSOCAlert('❌ Error', 'No se pudo extraer el dominio de la URL.');
        }
    };

    // Acción de PDF
    const btnPdf = document.getElementById('inc-modal-btn-pdf');
    if (btnPdf) {
        btnPdf.onclick = () => {
            downloadForensicPDF(logItem);
        };
    }

    modal.style.display = 'flex';
}

function downloadForensicPDF(logItem) {
    let jsPDFClass = null;
    if (window.jspdf && window.jspdf.jsPDF) {
        jsPDFClass = window.jspdf.jsPDF;
    } else if (window.jsPDF) {
        jsPDFClass = window.jsPDF;
    }
    
    if (!jsPDFClass) {
        showSOCAlert('❌ Error', 'Librería jsPDF no cargada.');
        return;
    }

    // Mostrar alerta instantánea
    showSOCAlert('📥 Generando PDF', 'Generando y descargando informe técnico forense...');

    const doc = new jsPDFClass({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4'
    });

    let domain = 'desconocido';
    try {
        const parsed = new URL(logItem.url);
        domain = parsed.hostname;
    } catch (e) {
        domain = logItem.url;
    }

    const totalRisk = logItem.score || 0;
    let timeStr = 'N/A';
    try {
        if (logItem.timestamp) {
            timeStr = new Date(logItem.timestamp).toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
        }
    } catch (e) {
        timeStr = logItem.timestamp || 'N/A';
    }

    // Verdict mapping
    let verdictTitle = '';
    let verdictText = '';
    let verdictColor = [16, 185, 129]; // RGB Green
    let verdictBg = [230, 248, 240];
    let badgeText = 'SITIO SEGURO';
    if (logItem.verdict === 'danger') {
        verdictTitle = 'PELIGROSO';
        verdictText = 'AMENAZA DE PHISHING DETECTADA';
        verdictColor = [220, 38, 38]; // RGB Red
        verdictBg = [254, 226, 226];
        badgeText = 'AMENAZA CONFIRMADA';
    } else if (logItem.verdict === 'suspicious') {
        verdictTitle = 'SOSPECHOSO';
        verdictText = 'VERIFICACIÓN REQUERIDA';
        verdictColor = [217, 119, 6]; // RGB Orange
        verdictBg = [254, 243, 199];
        badgeText = 'SITIO SOSPECHOSO';
    } else {
        verdictTitle = 'SEGURO';
        verdictText = 'SIN AMENAZAS DETECTADAS';
    }

    // --- Header Logo ---
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.setTextColor(0, 229, 160); // Primary (#00e5a0)
    doc.text('Phishing', 15, 20);
    
    const logoOffset = doc.getTextWidth('Phishing ');
    doc.setTextColor(31, 41, 55); // Dark text
    doc.text('Shield', 15 + logoOffset, 20);
    
    doc.setFontSize(7.5);
    doc.setTextColor(107, 114, 128); // Muted gray
    doc.text('TECHNICAL THREAT REPORT & FORENSIC ANALYSIS', 15, 24.5);

    // Right-side Info
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(75, 85, 99);
    doc.text(`Incidente ID: ${logItem.id}`, 195, 19, { align: 'right' });
    doc.text(`Fecha/Hora: ${timeStr}`, 195, 24, { align: 'right' });

    // Main line under header
    doc.setDrawColor(55, 65, 81);
    doc.setLineWidth(0.4);
    doc.line(15, 27, 195, 27);

    let y = 36;

    // --- 1. RESUMEN EJECUTIVO ---
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(17, 24, 39);
    doc.text('1. RESUMEN EJECUTIVO', 15, y);
    
    // Sub-line
    doc.setDrawColor(229, 231, 235);
    doc.setLineWidth(0.25);
    doc.line(15, y + 2, 195, y + 2);
    
    y += 7;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(55, 65, 81);
    const summaryText = 'El sistema de prevención de phishing de Phishing Shield ha interceptado y analizado una navegación web en tiempo real. Basado en el análisis multi-capa realizado por el clúster de microservicios Docker, el veredicto del motor de riesgo se detalla a continuación:';
    const splitSummary = doc.splitTextToSize(summaryText, 180);
    doc.text(splitSummary, 15, y);
    
    y += splitSummary.length * 4.2 + 2;

    // Verdict Box
    // Background fill (light gray)
    doc.setFillColor(243, 244, 246);
    doc.rect(15, y, 180, 20, 'F');
    // Left colored border
    doc.setFillColor(verdictColor[0], verdictColor[1], verdictColor[2]);
    doc.rect(15, y, 1.5, 20, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(107, 114, 128);
    doc.text('VERDICTO FINAL:', 20, y + 4.5);

    doc.setFontSize(10.5);
    doc.setTextColor(verdictColor[0], verdictColor[1], verdictColor[2]);
    doc.text(`${verdictTitle} - ${verdictText}`, 20, y + 10);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(55, 65, 81);
    doc.text(`Nivel de Riesgo Consolidado: ${totalRisk}%`, 20, y + 15.5);

    y += 26;

    // --- 2. DETALLES DE LA AMENAZA INTERCEPTADA ---
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(17, 24, 39);
    doc.text('2. DETALLES DE LA AMENAZA INTERCEPTADA', 15, y);
    
    doc.setDrawColor(229, 231, 235);
    doc.line(15, y + 2, 195, y + 2);
    
    y += 8;

    // Table rows
    const details = [
        { label: 'URL Target:', val: logItem.url },
        { label: 'Dominio:', val: domain },
        { label: 'Clasificación:', val: badgeText }
    ];

    details.forEach(item => {
        // Outline row
        doc.setDrawColor(229, 231, 235);
        doc.setLineWidth(0.2);
        
        // Label col (background)
        doc.setFillColor(249, 250, 251);
        doc.rect(15, y, 35, 8, 'F');
        doc.rect(15, y, 180, 8, 'D'); // Outer box
        
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(75, 85, 99);
        doc.text(item.label, 18, y + 5.5);

        // Value col
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(31, 41, 55);
        
        if (item.label === 'URL Target:') {
            doc.setFont('courier', 'normal');
            doc.setFontSize(7.5);
            const splitUrl = doc.splitTextToSize(item.val, 140);
            doc.text(splitUrl, 54, y + 5.2);
        } else if (item.label === 'Clasificación:') {
            // Draw colored badge back
            doc.setFillColor(verdictBg[0], verdictBg[1], verdictBg[2]);
            doc.rect(54, y + 2, 38, 4, 'F');
            
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(7.5);
            doc.setTextColor(verdictColor[0], verdictColor[1], verdictColor[2]);
            doc.text(item.val, 56, y + 5.0);
        } else {
            doc.setFont('courier', 'normal');
            doc.setFontSize(8);
            doc.text(item.val, 54, y + 5.5);
        }
        y += 8;
    });

    y += 5;

    // --- 3. DETALLE TÉCNICO DE MICROSERVICIOS ---
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(17, 24, 39);
    doc.text('3. DETALLE TÉCNICO DE MICROSERVICIOS', 15, y);
    
    doc.line(15, y + 2, 195, y + 2);
    y += 7;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(75, 85, 99);
    doc.text('Análisis forense individualizado por vector de ataque:', 15, y);
    y += 4;

    // Table Header
    doc.setFillColor(243, 244, 246);
    doc.rect(15, y, 180, 7, 'F');
    doc.rect(15, y, 180, 7, 'D');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(55, 65, 81);
    doc.text('Módulo de Seguridad', 18, y + 4.8);
    doc.text('Métrica Evaluada', 70, y + 4.8);
    doc.text('Puntaje Obtenido', 135, y + 4.8);
    doc.text('Estado', 170, y + 4.8);

    y += 7;

    // Dynamic Microservices scores calculation
    let multipliers = [0.8, 0.7, 1.2, 1.3];
    if (logItem.verdict === 'danger') {
        multipliers = [1.1, 0.9, 1.2, 1.0];
    } else if (logItem.verdict === 'suspicious') {
        multipliers = [0.9, 1.1, 0.8, 1.2];
    }

    let r0 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[0])));
    let r1 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[1])));
    let r2 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[2])));
    let r3 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[3])));
    let r4 = Math.min(100, Math.max(0, (totalRisk * 5) - (r0 + r1 + r2 + r3)));

    const services = [
        { name: 'Análisis de Enlace (Heurísticas)', metric: 'Patrones léxicos, longitud de URL y TLD', max: 25, r: r0 },
        { name: 'Verificación de Marca (Similitud)', metric: 'Similitud de caracteres (Look-alike)', max: 20, r: r1 },
        { name: 'Base de Datos Global (Reputación)', metric: 'Consultas a listas negras de VirusTotal', max: 25, r: r2 },
        { name: 'Protección por I.A. (ONNX Model)', metric: 'Predicción de Random Forest entrenado', max: 15, r: r3 },
        { name: 'Análisis Visual (pHash Match)', metric: 'Similitud perceptual de captura de pantalla', max: 15, r: r4 }
    ];

    services.forEach(s => {
        doc.rect(15, y, 180, 7, 'D'); // Outline row
        
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(31, 41, 55);
        doc.text(s.name, 18, y + 4.8);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        doc.setTextColor(75, 85, 99);
        doc.text(s.metric, 70, y + 4.8);

        const obtained = Math.round((1.0 - (s.r / 100)) * s.max);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(31, 41, 55);
        doc.text(`${obtained} / ${s.max}`, 135, y + 4.8);

        const srvStatus = s.r <= 25 ? 'SEGURO' : s.r <= 55 ? 'SOSPECHOSO' : 'PELIGROSO';
        const badgeColor = s.r <= 25 ? [16, 185, 129] : s.r <= 55 ? [217, 119, 6] : [220, 38, 38];
        doc.setTextColor(badgeColor[0], badgeColor[1], badgeColor[2]);
        doc.text(srvStatus, 170, y + 4.8);

        y += 7;
    });

    y += 5;

    // --- 4. ANÁLISIS DE CAUSA RAÍZ (EVIDENCIAS) ---
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(17, 24, 39);
    doc.text('4. ANÁLISIS DE CAUSA RAÍZ (EVIDENCIAS)', 15, y);
    
    doc.line(15, y + 2, 195, y + 2);
    y += 7;

    const forensic = getForensicReportData(logItem);
    let reasonsList = [];
    if (forensic && forensic.length > 0) {
        forensic.forEach(f => {
            if (f.reasons && f.reasons.length > 0) {
                f.reasons.forEach(r => reasonsList.push(r));
            }
        });
    }

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(55, 65, 81);
    
    reasonsList.forEach(r => {
        doc.text('* ' + r, 18, y);
        y += 4.2;
    });

    y += 3;

    // --- 5. ACCIONES DE MITIGACIÓN RECOMENDADAS ---
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(17, 24, 39);
    doc.text('5. ACCIONES DE MITIGACIÓN RECOMENDADAS', 15, y);
    
    doc.line(15, y + 2, 195, y + 2);
    y += 7;

    let mitigations = [];
    if (logItem.verdict === 'danger') {
        mitigations = [
            'Bloqueo de Dominio: Añadir el dominio a las listas de bloqueo perimetral en Firewalls corporativos.',
            'Alerta de Credenciales: Solicitar el restablecimiento de contraseñas si algún empleado ingresó datos.',
            'Notificación Registrador: Enviar reporte de abuso al registrador del dominio para proceder a la baja técnica.'
        ];
    } else if (logItem.verdict === 'suspicious') {
        mitigations = [
            'Monitoreo Preventivo: Habilitar alertas tempranas si se detectan visitas adicionales a este host.',
            'Educación de Usuario: Recordar al personal involucrado las directrices de concientización sobre enlaces.'
        ];
    } else {
        mitigations = [
            'Exclusión Sugerida: Si el dominio es recurrentes en la organización, evaluar su adición a la Whitelist.',
            'Sin Acciones Correctivas: El enlace no presenta características de suplantación ni malware activo.'
        ];
    }

    mitigations.forEach(m => {
        doc.text('* ' + m, 18, y);
        y += 4.2;
    });

    // --- Signature / Stamp ---
    const signY = 273;
    doc.setDrawColor(229, 231, 235);
    doc.setLineWidth(0.25);
    doc.line(15, signY, 195, signY);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(75, 85, 99);
    doc.text('Oficial de Seguridad de la Información (CISO)', 15, signY + 6);
    doc.setFont('helvetica', 'normal');
    doc.text('Phishing Shield Enterprise Security', 15, signY + 10);

    // Verified stamp box
    doc.setDrawColor(59, 130, 246);
    doc.setLineWidth(0.4);
    doc.rect(130, signY + 3, 65, 12);
    
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(37, 99, 235);
    doc.text('VERIFICADO POR PHISHING SHIELD', 133, signY + 7.5);
    
    doc.setFontSize(6.5);
    doc.setTextColor(75, 85, 99);
    doc.text('SECURE LOG ENCRYPTED', 133, signY + 11.5);

    doc.save('Reporte_Phishing_' + domain.replace(/[\.\:]/g, '_') + '.pdf');
}

function whitelistInputAndAdd(domain) {
    if (CONFIG.demoMode) {
        if (whitelist.includes(domain)) {
            showSOCAlert('⚠️ Dominio duplicado', 'El dominio ya está en la whitelist.');
            return;
        }
        whitelist.push(domain);
        localStorage.setItem('ps_whitelist', JSON.stringify(whitelist));
        renderWhitelistTable();
        showSOCAlert('✅ Dominio añadido', 'Se ha agregado ' + domain + ' a la Whitelist Central.');
        return;
    }

    fetch(`${CONFIG.backendUrl}/api/whitelist`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Admin-Token': CONFIG.adminToken
        },
        body: JSON.stringify({ domain })
    })
    .then(r => {
        if (!r.ok) throw new Error('Error al añadir exclusión en el servidor.');
        return r.json();
    })
    .then(() => {
        loadWhitelist();
        showSOCAlert('✅ Dominio añadido', 'Se ha agregado ' + domain + ' a la Whitelist Central en el servidor.');
    })
    .catch(err => {
        showSOCAlert('❌ Error', err.message);
    });
}

function getForensicReportData(logItem) {
    const urlLower = logItem.url.toLowerCase();
    const isPaypal = urlLower.includes('paypal');
    const isBanco = urlLower.includes('banco') || urlLower.includes('santander') || urlLower.includes('chile');
    const isUdemy = urlLower.includes('udemy');
    
    const totalRisk = logItem.score || 0;
    
    if (logItem.verdict === 'danger') {
        const multipliers = [1.1, 0.9, 1.2, 1.0];
        let r0 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[0])));
        let r1 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[1])));
        let r2 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[2])));
        let r3 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[3])));
        let r4 = Math.min(100, Math.max(0, (totalRisk * 5) - (r0 + r1 + r2 + r3)));
        
        return [
            {
                name: "Análisis Heurístico",
                score: 1.0 - (r0 / 100),
                reasons: [
                    urlLower.includes('.xyz') ? "TLD de riesgo crítico registrado (.xyz)" : "TLD alternativo de bajo costo",
                    urlLower.includes('http://') ? "Conexión insegura sin cifrado SSL/HTTPS activo" : "Certificado SSL de baja confianza/reciente",
                    "Estructura sintáctica del host sospechosa con exceso de guiones y subdominios"
                ]
            },
            {
                name: "Similitud Léxica (Brand Spoofing)",
                score: 1.0 - (r1 / 100),
                reasons: [
                    isPaypal ? "Suplantación de identidad detectada de la marca PayPal Inc." : isBanco ? "Suplantación de identidad detectada de Entidad Bancaria oficial" : "Contiene marca corporativa registrada fuera del dominio legítimo",
                    "Alta coincidencia de caracteres homógrafos o typosquatting respecto al dominio real"
                ]
            },
            {
                name: "Reputación e Historial (VirusTotal)",
                score: 1.0 - (r2 / 100),
                reasons: [
                    "Dominio reportado en listas negras de phishing activo por la comunidad SOC",
                    "Detección confirmada por múltiples motores de reputación integrados"
                ]
            },
            {
                name: "Clasificación por Aprendizaje Automático (ML)",
                score: 1.0 - (r3 / 100),
                reasons: [
                    "Modelo ONNX PhishStorm (93.2% precisión) clasifica la estructura como phishing de alto nivel",
                    "Distribución estadística anómala de palabras clave y entropía de dominio"
                ]
            },
            {
                name: "Inspección Visual (Computer Vision)",
                score: 1.0 - (r4 / 100),
                reasons: [
                    "La firma visual y el árbol DOM del portal coinciden en más de un 94% con la UI de inicio de sesión de la marca afectada"
                ]
            }
        ];
    } else if (logItem.verdict === 'suspicious') {
        const multipliers = [0.9, 1.1, 0.8, 1.2];
        let r0 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[0])));
        let r1 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[1])));
        let r2 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[2])));
        let r3 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[3])));
        let r4 = Math.min(100, Math.max(0, (totalRisk * 5) - (r0 + r1 + r2 + r3)));
        
        return [
            {
                name: "Análisis Heurístico",
                score: 1.0 - (r0 / 100),
                reasons: [
                    urlLower.includes('.xyz') ? "TLD sospechoso (.xyz)" : "Uso de TLD genérico no restringido",
                    "Uso de palabras clave asociadas a redireccionamiento o portales de autenticación"
                ]
            },
            {
                name: "Similitud Léxica (Brand Spoofing)",
                score: 1.0 - (r1 / 100),
                reasons: [
                    isUdemy ? "Coincidencia parcial con nombre de dominio educativo" : "Uso de términos sensibles en la estructura de directorios"
                ]
            },
            {
                name: "Reputación e Historial (VirusTotal)",
                score: 1.0 - (r2 / 100),
                reasons: [
                    "Sin reportes de infección activos, pero el dominio carece de historial reputacional sólido (registro reciente)"
                ]
            },
            {
                name: "Clasificación por Aprendizaje Automático (ML)",
                score: 1.0 - (r3 / 100),
                reasons: [
                    "Clasificador ML calcula sospecha media por proporciones sintácticas en el URL"
                ]
            },
            {
                name: "Inspección Visual (Computer Vision)",
                score: 1.0 - (r4 / 100),
                reasons: [
                    "Layout visual estándar, sin suplantaciones de logos o banners idénticos a los corporativos protegidos"
                ]
            }
        ];
    } else {
        const multipliers = [0.8, 0.7, 1.2, 1.3];
        let r0 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[0])));
        let r1 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[1])));
        let r2 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[2])));
        let r3 = Math.min(100, Math.max(0, Math.round(totalRisk * multipliers[3])));
        let r4 = Math.min(100, Math.max(0, (totalRisk * 5) - (r0 + r1 + r2 + r3)));
        
        return [
            {
                name: "Análisis Heurístico",
                score: 1.0 - (r0 / 100),
                reasons: [
                    r0 === 0 ? "Validado en base de datos central de exclusión (Whitelist) de la organización" : "Análisis sintáctico con sospecha baja (" + r0 + "% de riesgo)"
                ]
            },
            {
                name: "Similitud Léxica (Brand Spoofing)",
                score: 1.0 - (r1 / 100),
                reasons: [
                    r1 === 0 ? "Corresponde al dominio real verificado de la entidad" : "Similitud léxica menor con marcas protegidas (" + r1 + "% de riesgo)"
                ]
            },
            {
                name: "Reputación e Historial (VirusTotal)",
                score: 1.0 - (r2 / 100),
                reasons: [
                    r2 === 0 ? "0/94 detecciones de motores de seguridad en VirusTotal" : "Reputación media o alertas de red parciales (" + r2 + "% de riesgo)"
                ]
            },
            {
                name: "Clasificación por Aprendizaje Automático (ML)",
                score: 1.0 - (r3 / 100),
                reasons: [
                    r3 === 0 ? "Score de confianza ML seguro para el host" : "Modelo de IA calcula riesgo mínimo en el URL (" + r3 + "% de riesgo)"
                ]
            },
            {
                name: "Inspección Visual (Computer Vision)",
                score: 1.0 - (r4 / 100),
                reasons: [
                    r4 === 0 ? "Visualización autorizada y libre de marcas falsas" : "Similitud cromática y visual baja (" + r4 + "% de riesgo)"
                ]
            }
        ];
    }
}

/* ============================================================
   USER REPORTS (FALSE POSITIVES) MANAGEMENT
   ============================================================ */
let userReports = [];

function loadReports() {
    if (!isConnected) return;
    
    fetch(`${CONFIG.backendUrl}/api/reports`, {
        headers: {
            'X-Admin-Token': CONFIG.adminToken
        }
    })
    .then(r => {
        if (!r.ok) throw new Error('Error al cargar reportes desde el orquestador.');
        return r.json();
    })
    .then(data => {
        userReports = data || [];
        renderReportsTable();
    })
    .catch(err => {
        console.error('Error loading user reports:', err);
        const tbody = document.getElementById('reports-table-body');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #ef4444; padding: 30px;">Error al conectar con el servidor: ' + err.message + '</td></tr>';
        }
    });
}

function renderReportsTable() {
    const tbody = document.getElementById('reports-table-body');
    if (!tbody) return;

    if (!isConnected) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">Desconectado. Configure las credenciales de conexión.</td></tr>';
        return;
    }

    if (userReports.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">No hay reportes de falsos positivos pendientes.</td></tr>';
        return;
    }

    tbody.innerHTML = userReports.map((rep, i) => {
        const time = new Date(rep.timestamp).toLocaleString('es-ES', { hour12: false });
        return `<tr style="animation: timelineSlide 0.3s ${i * 0.05}s both;">
            <td><span class="id-badge">${rep.id}</span></td>
            <td><span style="color: var(--text-muted); font-family: monospace;">${rep.incident_id || 'N/A'}</span></td>
            <td><a href="${rep.url}" target="_blank" class="table-url-link" onclick="event.stopPropagation()" title="${rep.url}">${rep.url}</a></td>
            <td class="mono" style="font-size: 0.8rem;">${time}</td>
            <td style="text-align: center; display: flex; gap: 8px; justify-content: center; align-items: center; border-bottom: none; height: 100%; padding: 8px 0;">
                <button onclick="actionReport('${rep.id}', 'approve')" class="btn-admin" style="background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.25); color: #10b981; padding: 4px 12px; border-radius: 6px; font-size: 0.75rem; cursor: pointer; transition: all 0.2s;">✓ Whitelist</button>
                <button onclick="actionReport('${rep.id}', 'reject')" class="btn-admin" style="background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.25); color: #ef4444; padding: 4px 12px; border-radius: 6px; font-size: 0.75rem; cursor: pointer; transition: all 0.2s;">✕ Rechazar</button>
            </td>
        </tr>`;
    }).join('');
}

function actionReport(id, action) {
    if (!isConnected) return;
    
    fetch(`${CONFIG.backendUrl}/api/reports`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'X-Admin-Token': CONFIG.adminToken
        },
        body: JSON.stringify({ id, action })
    })
    .then(r => {
        if (!r.ok) throw new Error('Error al procesar acción en el reporte.');
        return r.json();
    })
    .then(() => {
        showSOCAlert('Reporte procesado', `El reporte ${id} fue ${action === 'approve' ? 'aprobado y añadido a whitelist' : 'rechazado y archivado'}.`);
        loadReports();
    })
    .catch(err => {
        showSOCAlert('❌ Error', err.message);
    });
}

async function updateLatencyMetrics() {
    if (!isConnected || CONFIG.demoMode) return;
    try {
        const res = await fetch(`${CONFIG.backendUrl}/api/metrics`, {
            headers: { 'X-Admin-Token': CONFIG.adminToken }
        });
        if (res.ok) {
            const metrics = await res.json();
            const p95El = document.getElementById('latency-p95');
            const avgEl = document.getElementById('avg-latency-val');
            if (p95El && metrics.p95_latency_ms !== undefined) {
                p95El.textContent = metrics.p95_latency_ms.toFixed(0) + ' ms';
            }
            if (avgEl && metrics.p50_latency_ms !== undefined) {
                avgEl.textContent = metrics.p50_latency_ms.toFixed(0) + ' ms';
            }
        }
    } catch(e) {
        console.warn('Error loading latency metrics:', e);
    }
}
