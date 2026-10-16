'use strict';

// ==========================================================================
// CONFIGURACIÓN CENTRAL DEL SERVIDOR SAAS
// Cambia esta URL por la de tu servidor en la nube (ej. 'https://api.tu-soc.com')
// ==========================================================================
const DEFAULT_BACKEND_URL = 'http://localhost:8080';

document.addEventListener('DOMContentLoaded', async () => {
  const backendUrlInput = document.getElementById('backendUrl');
  const clientKeyInput = document.getElementById('clientKey');
  const adminTokenInput = document.getElementById('adminToken');
  const btnTest = document.getElementById('btnTest');
  const btnSave = document.getElementById('btnSave');
  const statusPanel = document.getElementById('statusPanel');
  const statusIcon = document.getElementById('statusIcon');
  const statusTitle = document.getElementById('statusTitle');
  const statusDesc = document.getElementById('statusDesc');

  // Cargar valores guardados
  let settings;
  const isExtension = typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local;
  if (isExtension) {
    settings = await chrome.storage.local.get({
      backend_url: DEFAULT_BACKEND_URL,
      client_key: 'demo-key-123',
      admin_token: ''
    });
  } else {
    settings = {
      backend_url: localStorage.getItem('ps_backend_url') || DEFAULT_BACKEND_URL,
      client_key: localStorage.getItem('ps_client_key') || 'demo-key-123',
      admin_token: localStorage.getItem('ps_admin_token') || ''
    };
  }

  backendUrlInput.value = settings.backend_url;
  clientKeyInput.value = settings.client_key || 'demo-key-123';
  if (adminTokenInput) adminTokenInput.value = settings.admin_token || '';

  // Función para mostrar estado
  function showStatus(type, title, message) {
    statusPanel.className = 'status-panel ' + type;
    statusTitle.textContent = title;
    statusDesc.textContent = message;

    if (type === 'success') {
      statusIcon.innerHTML = '<polyline points="20 6 9 17 4 12"/>';
    } else if (type === 'error') {
      statusIcon.innerHTML = '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>';
    }
  }

  // Probar conexión
  btnTest.addEventListener('click', async () => {
    let url = backendUrlInput.value.trim().replace(/\/$/, '');
    const key = clientKeyInput.value.trim();

    if (!url) {
      showStatus('error', 'URL Requerida', 'Por favor ingresa la URL del servidor backend.');
      return;
    }

    showStatus('success', 'Conectando...', 'Estableciendo comunicación con el servidor backend...');
    statusPanel.style.background = 'rgba(59, 130, 246, 0.1)';
    statusPanel.style.borderColor = 'rgba(59, 130, 246, 0.2)';
    statusIcon.innerHTML = '<path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>'; // simple spinner representation or path

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const res = await fetch(`${url}/health`, {
        method: 'GET',
        headers: {
          'X-Client-Key': key
        },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (res.ok) {
        const data = await res.json();
        if (data.status === 'ok') {
          showStatus('success', 'Conexión Exitosa', 'El servidor respondió correctamente y autorizó la API Key.');
        } else {
          showStatus('error', 'Respuesta Inesperada', 'El servidor respondió, pero el estado no es OK.');
        }
      } else if (res.status === 401) {
        showStatus('error', 'No Autorizado (401)', 'La API Key (Token) ingresada es inválida o expiró.');
      } else {
        showStatus('error', `Error HTTP ${res.status}`, `El servidor respondió con código de error ${res.status}.`);
      }
    } catch (err) {
      showStatus('error', 'Error de Conexión', 'No se pudo conectar al servidor. Verifica la URL y que el servicio esté activo.');
    }
  });

  const btnDashboard = document.getElementById('btnDashboard');
  const dashboardBtnContainer = document.getElementById('dashboardBtnContainer');

  // Mostrar el botón del dashboard si ya hay configuraciones cargadas
  if (backendUrlInput.value && clientKeyInput.value && dashboardBtnContainer) {
    dashboardBtnContainer.style.display = 'block';
  }

  if (btnDashboard) {
    btnDashboard.addEventListener('click', () => {
      if (isExtension) {
        const dashboardUrl = chrome.runtime.getURL('dashboard/index.html');
        chrome.tabs.create({ url: dashboardUrl });
      } else {
        // En desarrollo local (como un archivo local), abrimos el dashboard vecino
        window.open('dashboard/index.html', '_blank');
      }
    });
  }

  const btnAutofillDemo = document.getElementById('btnAutofillDemo');
  if (btnAutofillDemo) {
    btnAutofillDemo.addEventListener('click', () => {
      backendUrlInput.value = 'http://localhost:8080';
      clientKeyInput.value = 'demo-key-123';
      if (adminTokenInput) adminTokenInput.value = 'pymeshield2026';
      showStatus('success', 'Demo Autocompletada', 'Valores de demostración cargados. Haz clic en "Guardar" para aplicarlos.');
    });
  }

  // Guardar configuración
  btnSave.addEventListener('click', async () => {
    const url = backendUrlInput.value.trim().replace(/\/$/, '');
    const key = clientKeyInput.value.trim();

    if (!url) {
      showStatus('error', 'URL Requerida', 'Por favor ingresa la URL del servidor backend.');
      return;
    }

    const adminTok = adminTokenInput ? adminTokenInput.value.trim() : '';
    if (isExtension) {
      await chrome.storage.local.set({
        backend_url: url,
        client_key: key,
        admin_token: adminTok
      });
    } else {
      localStorage.setItem('ps_backend_url', url);
      localStorage.setItem('ps_client_key', key);
      localStorage.setItem('ps_admin_token', adminTok);
    }

    showStatus('success', 'Configuración Guardada', 'Los ajustes se aplicaron correctamente.');
    
    if (dashboardBtnContainer) {
      dashboardBtnContainer.style.display = 'block';
    }
  });
});
