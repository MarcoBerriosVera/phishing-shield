chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "getDOM") {
    sendResponse({ dom: document.documentElement.outerHTML });
    return true;
  }

  if (message.type === "SHIELD_RESULT") {
    const status = message.payload.status || "analyzing";
    if (status === "safe" || status === "analyzing") {
      const existing = document.getElementById("phishing-shield-toast");
      if (existing) existing.remove();
      return;
    }

    showNotification(message.payload);

    if (status === "suspicious" || status === "danger") {
      captureAndAnalyze(message.payload.url || location.href);
    }
  }
});

function showNotification(data) {
  const existing = document.getElementById("phishing-shield-toast");
  if (existing) existing.remove();

  const status = data.status || "analyzing";
  const score = data.score ? `${(data.score * 100).toFixed(0)}%` : null;
  const url = data.url ? data.url.substring(0, 45) + (data.url.length > 45 ? "..." : "") : "";

  const config = {
    analyzing: { color: "#4d9fff", icon: "⟳", badge: "Analizando", title: "Verificando seguridad...", sub: "Analizando con 4 métodos en paralelo" },
    safe:      { color: "#00e5a0", icon: "✓", badge: "Verificado", title: "Sitio seguro", sub: "Sin amenazas detectadas" },
    suspicious:{ color: "#f5a623", icon: "⚠", badge: "Sospechoso", title: "Sitio no verificado", sub: "Procede con precaución" },
    danger:    { color: "#ff4455", icon: "✕", badge: "Bloqueado", title: "Phishing detectado", sub: "Este sitio es peligroso" }
  };

  const c = config[status];

  const toast = document.createElement("div");
  toast.id = "phishing-shield-toast";
  toast.setAttribute("style", `
    position: fixed !important;
    top: 20px !important;
    right: 20px !important;
    z-index: 2147483647 !important;
    width: 300px !important;
    background: #0f1117 !important;
    border: 1px solid ${c.color}44 !important;
    border-radius: 14px !important;
    overflow: hidden !important;
    box-shadow: 0 20px 60px rgba(0,0,0,0.6) !important;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
    animation: psSlideIn 0.3s ease !important;
  `);

  toast.innerHTML = `
    <div style="height:3px;background:linear-gradient(90deg,transparent,${c.color},transparent)"></div>
    <div style="padding:14px 16px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
        <div id="ps-badge" style="
          display:inline-flex;align-items:center;gap:5px;
          padding:3px 10px;border-radius:20px;
          font-size:10px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;
          background:${c.color}20;color:${c.color};border:1px solid ${c.color}44;
        "></div>
        <button id="ps-close" style="
          width:22px;height:22px;border-radius:6px;
          background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.08);
          color:#5a5f72;cursor:pointer;font-size:16px;
          display:flex;align-items:center;justify-content:center;
        ">×</button>
      </div>
      <div id="ps-title" style="font-size:14px;font-weight:600;color:#e8eaf0;margin-bottom:3px"></div>
      <div id="ps-sub" style="font-size:11px;color:#5a5f72"></div>
      <div id="ps-url-container" style="
        margin-top:10px;padding:7px 10px;
        background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.07);border-radius:8px;
        font-size:10px;font-family:'Courier New',monospace;color:#5a5f72;
        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
        display:none;
      ">🔗 <span id="ps-url"></span></div>
      <div id="ps-score-container" style="
        display:none;align-items:center;justify-content:space-between;
        margin-top:10px;padding:8px 10px;border-radius:8px;background:${c.color}15;
      ">
        <span style="font-size:11px;font-weight:500;color:${c.color}">🛡 Phishing Shield</span>
        <span id="ps-score" style="font-size:13px;font-weight:700;font-family:'Courier New',monospace;color:${c.color}"></span>
      </div>
    </div>
  `;

  toast.querySelector("#ps-badge").textContent = `${c.icon} ${c.badge}`;
  toast.querySelector("#ps-title").textContent = c.title;
  toast.querySelector("#ps-sub").textContent = c.sub;

  if (url) {
    const urlContainer = toast.querySelector("#ps-url-container");
    urlContainer.style.display = "block";
    toast.querySelector("#ps-url").textContent = url;
  }

  if (score) {
    const scoreContainer = toast.querySelector("#ps-score-container");
    scoreContainer.style.display = "flex";
    toast.querySelector("#ps-score").textContent = `Score: ${score}`;
  }

  toast.querySelector("#ps-close").addEventListener("click", () => {
    toast.remove();
  });

  document.body.appendChild(toast);

  if (status === "safe") {
    setTimeout(() => toast.remove(), 3000);
  }
}

// Captura visual y envía hash al servidor
async function captureAndAnalyze(url) {
  try {
    // Esperar que la página cargue visualmente
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    // Notificar al background para capturar
    chrome.runtime.sendMessage({
      action: 'captureVisual',
      url: url
    });
  } catch (e) {
    console.log('Error en captura visual:', e);
  }
}

// --- Análisis Dinámico de Comportamiento Client-Side (REQ-ARQ-04) ---
function scanDynamicBehavior() {
  const warnings = [];
  
  // 1. Verificar formularios de contraseña cross-origin (Credential Theft / Harvesting)
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  passwordInputs.forEach(pass => {
    const form = pass.closest('form');
    if (form) {
      const action = form.getAttribute('action') || '';
      if (action.startsWith('http') || action.startsWith('//')) {
        try {
          const actionUrl = new URL(action, window.location.href);
          if (actionUrl.hostname !== window.location.hostname) {
            warnings.push("Formulario de contraseña intenta enviar datos a un servidor externo cruzado (Cross-Origin Credential Theft).");
          }
        } catch {}
      }
    }
  });

  // 2. Detectar inputs de contraseñas ofuscados o invisibles (Overlay capture / Keylogging)
  passwordInputs.forEach(pass => {
    const style = window.getComputedStyle(pass);
    if (style.opacity === '0' || style.display === 'none' || style.visibility === 'hidden') {
      warnings.push("Campo de contraseña invisible u ofuscado detectado en tiempo de ejecución (posible overlay malicioso).");
    }
  });

  // 3. Detectar formularios de autenticación sobre canales inseguros (HTTP)
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    const action = form.getAttribute('action') || '';
    if (action.includes('login') && !action.startsWith('https') && window.location.protocol === 'https:') {
      warnings.push("Formulario de inicio de sesión intenta transmitir credenciales sobre canal inseguro sin HTTPS.");
    }
  });

  return warnings;
}

// El análisis visual se dispara desde el listener de SHIELD_RESULT
// solo cuando el backend marca la página como sospechosa o peligrosa.