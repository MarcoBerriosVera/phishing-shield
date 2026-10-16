# Phishing Shield — Textos para Chrome Web Store

---

## DESCRIPCIÓN CORTA (≤132 caracteres)

```
Protección en tiempo real contra phishing con IA + gestor de contraseñas cifrado. Sin servidores externos. 100% local.
```
✅ 118 caracteres

---

## DESCRIPCIÓN LARGA

```
🛡️ PHISHING SHIELD — Tu escudo contra el phishing

Phishing Shield es una extensión de seguridad que analiza cada sitio web que visitas en tiempo real, usando inteligencia artificial y múltiples capas de detección para protegerte de ataques de phishing antes de que sea demasiado tarde.

🔍 DETECCIÓN MULTICAPA
• Análisis heurístico de URLs sospechosas
• Detección de similitud con dominios legítimos (typosquatting)
• Verificación de reputación del dominio
• Modelo de IA entrenado en patrones de phishing reales
• Bloqueo inmediato con aviso visual al detectar amenazas

🔐 GESTOR DE CONTRASEÑAS INTEGRADO
• Almacenamiento cifrado con AES-256-GCM
• Clave derivada con PBKDF2 (600.000 iteraciones) — nadie más puede acceder
• Verificación de brechas de datos via Have I Been Pwned (k-anonimato: tu contraseña nunca sale de tu dispositivo)
• Generador de contraseñas seguras con análisis de robustez inteligente
• Autocompletado en formularios de inicio de sesión
• Bloqueo automático tras 15 minutos de inactividad
• Autenticación de dos factores (TOTP) opcional

🔒 PRIVACIDAD TOTAL
Todo el análisis se realiza localmente en tu computador. Tus contraseñas NUNCA se envían a ningún servidor. No recopilamos datos de uso, no mostramos publicidad, no vendemos tus datos. Cumple con la Ley 21.719 de Protección de Datos (Chile) y el estándar GDPR.

📊 PANEL DE CONTROL
• Historial de URLs analizadas
• Estadísticas de amenazas bloqueadas
• Estado en tiempo real de cada capa de protección

Desarrollado como proyecto de investigación en ciberseguridad.
```

---

## JUSTIFICACIONES DE PERMISOS

### `storage`
Se usa para guardar el historial de análisis de URLs y el vault cifrado de contraseñas, ambos almacenados únicamente en el dispositivo local del usuario. Ningún dato se envía a servidores externos.

### `alarms`
Se usa para implementar el bloqueo automático del gestor de contraseñas después de 15 minutos de inactividad, protegiendo al usuario si olvida cerrar la sesión.

### `clipboardWrite`
Se usa exclusivamente cuando el usuario hace clic en el botón "Copiar contraseña" dentro del gestor de contraseñas. La extensión nunca accede al portapapeles sin acción explícita del usuario.

### `scripting`
Se usa para inyectar la página de bloqueo cuando se detecta un sitio de phishing, reemplazando el contenido peligroso con un aviso de seguridad. No se usa para ningún otro propósito.

### `webNavigation`
Se usa para interceptar la navegación antes de que la página cargue, permitiendo analizar y bloquear sitios peligrosos de forma proactiva.

### `tabs`
Se usa para leer la URL de la pestaña activa y para abrir la interfaz del gestor de contraseñas en una nueva pestaña.

### `<all_urls>` (host_permissions)
Necesario para que la extensión pueda analizar cualquier sitio web que el usuario visite, sin importar el dominio. Sin este permiso, la protección anti-phishing solo funcionaría en dominios específicos, dejando al usuario desprotegido en sitios desconocidos.

### `https://api.pwnedpasswords.com/*` (host_permissions)
Se usa únicamente para consultar el servicio Have I Been Pwned al verificar si una contraseña ha sido comprometida en brechas de datos. Solo se envían los primeros 5 caracteres del hash SHA-1 (protocolo k-anonimato). La contraseña completa nunca abandona el dispositivo del usuario.

---

## DATOS ADICIONALES DE LA FICHA

- **Categoría:** Seguridad
- **Idioma principal:** Español
- **Sitio web del desarrollador:** [Tu GitHub Pages URL con privacy-policy.html]
- **URL de Política de Privacidad:** [Tu GitHub Pages URL]/privacy-policy.html
- **Correo de soporte:** marcoberriosvera@gmail.com
- **Precio:** Gratuita

---

## NOTAS PARA EL FORMULARIO DE PUBLICACIÓN

1. En "Tipo de uso de datos del usuario" seleccionar:
   - ✅ El elemento de almacenamiento de Chrome (para vault local)
   - ✅ Actividad web (URLs analizadas, permanecen locales)
   - ❌ NO marcar "Información de identificación personal"
   - ❌ NO marcar "Comunicaciones"

2. En "¿Se transfieren los datos a terceros?": NO (excepto HIBP con k-anonimato, que ya está descrito en la política de privacidad)

3. En "¿Se usan los datos con fines que no sean la función principal?": NO

4. En "¿Se venden los datos?": NO
```
