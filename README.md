# 🛡️ Phishing Shield

Sistema de detección de phishing en tiempo real compuesto por una **extensión de Chrome (Manifest V3)** y un **backend de microservicios** en Go y Python, orquestados con Docker Compose. Incluye además un **gestor de contraseñas cifrado** dentro de la extensión.

> Proyecto desarrollado como parte de mi formación como Técnico en Informática mención Ciberseguridad (CFT Estatal).

---

## Arquitectura

```
┌──────────────────────────┐        X-Client-Key         ┌──────────────────────────────┐
│   Extensión Chrome (MV3) │ ──────────────────────────▶ │  Orquestador (Go · :8080)    │
│  · content scripts       │ ◀────────── veredicto ───── │  · chi router + rate limit   │
│  · bloqueo de página     │                             │  · auth cliente / admin      │
│  · vault AES-256-GCM     │                             │  · incidentes, whitelist     │
└──────────────────────────┘                             │  · métricas p95, websocket   │
                                                         └──────┬───────────────────────┘
          Dashboard SOC (X-Admin-Token) ◀───────────────────────┤  consulta en paralelo
                                                                ▼
        ┌──────────────┬───────────────┬────────────────┬──────────────┬───────────────┐
        │ heuristics   │ similarity    │ reputation     │ ml           │ visual        │
        │ Go · :8081   │ Go · :8082    │ Go · :8083     │ Python ·8084 │ Python · :8085│
        │ reglas sobre │ typosquatting │ VirusTotal API │ Random Forest│ hash perceptual│
        │ la URL       │ vs. marcas    │                │ en ONNX      │ de logos/marcas│
        └──────────────┴───────────────┴────────────────┴──────────────┴───────────────┘
```

| Componente | Tecnología | Qué hace |
|---|---|---|
| `extension/` | JavaScript, Chrome MV3 | Intercepta la navegación, consulta al orquestador y bloquea la página si es maliciosa. Incluye vault de contraseñas y verificación contra *Have I Been Pwned* (k-anonimato). |
| `orchestrator/` | Go (chi) | Punto de entrada único. Autenticación por API key de cliente y token de administrador, *rate limiting* por IP (100 req/min), registro de incidentes, whitelist, reportes de falsos positivos y métricas. |
| `services/heuristics` | Go | Reglas sobre la estructura de la URL (IPs, subdominios, palabras clave, etc.). |
| `services/similarity` | Go | Detección de *typosquatting*: distancia de Levenshtein entre el dominio y marcas conocidas. |
| `services/reputation` | Go | Consulta de reputación del dominio vía VirusTotal. |
| `services/ml` | Python (FastAPI, ONNX Runtime) | Modelo Random Forest entrenado con el dataset PhishStorm (`train.py`). **Verifica el hash SHA-256 del modelo antes de cargarlo** para detectar manipulación. |
| `services/visual` | Python (FastAPI, imagehash) | Compara el hash perceptual de la página con logos de marcas conocidas. |
| `services/vault` | Go | Almacenamiento *zero-knowledge* del vault: solo guarda datos cifrados (DEK envuelta con KEK, blob y secreto TOTP en AES-256-GCM); nunca ve contraseñas en claro. No está incluido en el `docker-compose.yml`. |
| `dashboard/` | HTML/JS | Panel tipo SOC: incidentes, whitelist, API keys, reportes y métricas. |

## Decisiones de seguridad

- **Autenticación separada** para clientes (`X-Client-Key`) y administradores (`X-Admin-Token`).
- **Rate limiting** por IP en el orquestador.
- **Integridad del modelo de ML**: el servicio se niega a cargar un `.onnx` cuyo SHA-256 no coincida.
- **Vault local**: AES-256-GCM con clave derivada por PBKDF2-HMAC-SHA256 (600.000 iteraciones, salt aleatorio), `CryptoKey` no extraíble y bloqueo automático a los 15 minutos.
- **Modelo de amenazas** documentado en [`vault_security_analysis.pdf`](vault_security_analysis.pdf) (fuerza bruta, acceso físico, malware, XSS, etc.).
- Secretos solo por variables de entorno; `.env` excluido del repositorio.

## Cómo ejecutarlo

Requisitos: Docker y Docker Compose.

```bash
cd docker
cp .env.example .env      # completa ADMIN_TOKEN y, si quieres, VIRUSTOTAL_API_KEY
docker compose up --build
```

El orquestador queda en `http://localhost:8080` (`GET /health` para comprobarlo).

**Extensión:** abre `chrome://extensions`, activa *Modo desarrollador* → *Cargar descomprimida* → selecciona la carpeta `extension/`.

**Modo demo:** con `DEMO_MODE=true` el orquestador carga datos de ejemplo y no exige API keys de cliente (no usar en producción).

## Reentrenar el modelo

```bash
cd services/ml
pip install -r requirements.txt pandas scikit-learn skl2onnx
python train.py
```

Al regenerar `phishing_model.onnx`, actualiza `EXPECTED_HASH` en `services/ml/main.py`.

## Estructura

```
phishing-shield/
├── extension/        Extensión Chrome (MV3) + vault
├── orchestrator/     API principal en Go
├── services/         Microservicios de detección
├── dashboard/        Panel de administración (SOC)
├── presentation/     Presentación del proyecto
├── docker/           docker-compose.yml y .env.example
├── test-server/      Servidor de pruebas local
└── store/            Política de privacidad y textos para Chrome Web Store
```

## Autor

**Marco Berríos Vera** — Técnico en Informática, mención Ciberseguridad.
