package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Phishing Shield - Test</title>
  <style>
    body { font-family: sans-serif; background: #0a0b0f; color: #e8eaf0; padding: 40px; }
    h1 { color: #00e5a0; margin-bottom: 30px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }
    .card { background: #111318; border-radius: 12px; padding: 24px; border: 1px solid rgba(255,255,255,0.07); }
    .card h2 { font-size: 14px; margin-bottom: 8px; }
    .card p { font-size: 12px; color: #5a5f72; margin-bottom: 16px; }
    a { display: block; padding: 10px 16px; border-radius: 8px; text-decoration: none; font-size: 13px; font-weight: 600; text-align: center; }
    .green { background: rgba(0,229,160,0.15); color: #00e5a0; border: 1px solid rgba(0,229,160,0.3); }
    .yellow { background: rgba(245,166,35,0.15); color: #f5a623; border: 1px solid rgba(245,166,35,0.3); }
    .red { background: rgba(255,68,85,0.15); color: #ff4455; border: 1px solid rgba(255,68,85,0.3); }
  </style>
</head>
<body>
  <h1>🛡 Phishing Shield — Página de Pruebas</h1>
  <div class="grid">
    <div class="card">
      <h2>✓ Estado: SEGURO</h2>
      <p>Simula un sitio legítimo. Debería mostrar notificación verde.</p>
      <a class="green" href="/safe">Ir a sitio seguro</a>
    </div>
    <div class="card">
      <h2>⚠ Estado: SOSPECHOSO</h2>
      <p>Simula un sitio sospechoso con palabras clave de phishing.</p>
      <a class="yellow" href="/suspicious">Ir a sitio sospechoso</a>
    </div>
    <div class="card">
      <h2>✕ Estado: BLOQUEADO</h2>
      <p>Simula un sitio de phishing conocido. Debería mostrar rojo.</p>
      <a class="red" href="/danger">Ir a sitio peligroso</a>
    </div>
  </div>
</body>
</html>`)
	})

	http.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<h1>Sitio seguro de prueba</h1>`)
	})

	http.HandleFunc("/suspicious", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<h1>Sitio sospechoso de prueba</h1>`)
	})

	http.HandleFunc("/danger", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<h1>Sitio peligroso de prueba</h1>`)
	})


	fmt.Println("Test server en :9000")
	log.Fatal(http.ListenAndServe(":9000", nil))
}
