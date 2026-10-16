// Presentation Slide Controller
document.addEventListener('DOMContentLoaded', () => {
    const slides = document.querySelectorAll('.slide');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const slideCounter = document.getElementById('slideCounter');
    const progressBar = document.getElementById('progressBar');
    
    let currentSlideIdx = 0;
    const totalSlides = slides.length;

    // Update UI elements for slide navigation
    function updateSlide() {
        slides.forEach((slide, idx) => {
            if (idx === currentSlideIdx) {
                slide.classList.add('active');
            } else {
                slide.classList.remove('active');
            }
        });

        // Update counter text
        slideCounter.textContent = `${currentSlideIdx + 1} / ${totalSlides}`;

        // Update progress bar width
        const progressPercentage = ((currentSlideIdx + 1) / totalSlides) * 100;
        progressBar.style.width = `${progressPercentage}%`;
    }

    // Navigation triggers
    function nextSlide() {
        if (currentSlideIdx < totalSlides - 1) {
            currentSlideIdx++;
            updateSlide();
        }
    }

    function prevSlide() {
        if (currentSlideIdx > 0) {
            currentSlideIdx--;
            updateSlide();
        }
    }

    // Key event listeners
    document.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowRight' || e.key === ' ' || e.key === 'Enter') {
            nextSlide();
        } else if (e.key === 'ArrowLeft' || e.key === 'Backspace') {
            prevSlide();
        }
    });

    nextBtn.addEventListener('click', nextSlide);
    prevBtn.addEventListener('click', prevSlide);

    // Initial setup
    updateSlide();

    // --- Slide 4: Interactive Architecture Node Handler ---
    const archNodes = document.querySelectorAll('.arch-node');
    const archDescTitle = document.getElementById('archDescTitle');
    const archDescText = document.getElementById('archDescText');
    const archCard = document.getElementById('archDesc');

    const nodeDetails = {
        extension: {
            title: "Agente Cliente (Extensión Manifest V3)",
            text: "Intercepta de forma transparente todas las peticiones DNS y peticiones de navegación mediante listeners activos del navegador. Si detecta una dirección de destino sospechosa, congela preventivamente la carga del DOM y envía la URL cifrada a la API del orquestador. También almacena y procesa localmente el Vault cifrado con AES-256-GCM y PBKDF2."
        },
        orchestrator: {
            title: "Orquestador Central de Red (Go API REST)",
            text: "Implementado en Go, procesa simultáneamente múltiples solicitudes en el endpoint `/analyze`. Utilizando Goroutines y canales concurrentes (sync.WaitGroup), distribuye la solicitud a los 5 motores analíticos asíncronos en milisegundos, reúne sus veredictos parciales y genera un score consolidado con un timeout de seguridad de 8 segundos."
        },
        engines: {
            title: "Motores Analíticos Distribuidos (Docker Compose)",
            text: "Conjunto modular de microservicios aislados en Docker que corren en paralelo: Heurística (análisis sintáctico en Go), Similitud Léxica (distancia Levenshtein en Go), Reputación local (JSON/VirusTotal en Go), Inteligencia Artificial (FastAPI/ONNX en Python) y Análisis Visual cromático (FastAPI en Python)."
        }
    };

    archNodes.forEach(node => {
        node.addEventListener('click', () => {
            // Remove active status from all nodes
            archNodes.forEach(n => n.classList.remove('active'));
            // Set clicked node to active
            node.classList.add('active');

            const key = node.getAttribute('data-node');
            const data = nodeDetails[key];

            // Soft transition effect
            archCard.style.opacity = 0;
            setTimeout(() => {
                archDescTitle.textContent = data.title;
                archDescText.textContent = data.text;
                archCard.style.opacity = 1;
            }, 150);
        });
    });

    // --- Slide 7: Simulated Live Log Generator for SOC Preview ---
    const socLogs = document.getElementById('socLogs');
    const mockDomains = [
        "login-verify-santander.cl", "secure-banco-estado.xyz", "office365-admin-portal.top", 
        "bci-persona-login.net", "actualizacion-tarjeta-credito.cf", "verificacion-clave-unica.gq",
        "soporte-netflix-update.ml", "seguridad-outlook-webmail.top", "netflix-cuenta-soporte.xyz"
    ];
    const mockEngines = [
        "ML ONNX Classifier", "Levenshtein Similitud", "Heuristic Sintáctica", "Reputación VirusTotal"
    ];

    function generateLiveLog() {
        const time = new Date();
        const timeStr = `[${time.toTimeString().split(' ')[0]}]`;
        const randomDomain = mockDomains[Math.floor(Math.random() * mockDomains.length)];
        const randomEngine = mockEngines[Math.floor(Math.random() * mockEngines.length)];
        
        const logLine = document.createElement('div');
        logLine.className = 'log-line';
        logLine.innerHTML = `<span class="log-time">${timeStr}</span> <span class="log-tag red">DANGER</span> Interceptado: ${randomDomain} (${randomEngine} match)`;
        
        socLogs.appendChild(logLine);
        socLogs.scrollTop = socLogs.scrollHeight;

        // Keep maximum logs count around 8
        if (socLogs.children.length > 8) {
            socLogs.removeChild(socLogs.children[0]);
        }
    }

    // Insert a new simulated threat lock every 5 seconds
    setInterval(generateLiveLog, 5000);
});
