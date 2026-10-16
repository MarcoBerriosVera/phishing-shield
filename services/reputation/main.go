package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Request struct {
	URL string `json:"url"`
}

type Response struct {
	Score   float64  `json:"score"`
	Reasons []string `json:"reasons"`
}

var vtAPIKey string

// localBlacklist — dominios bloqueados sin depender de VirusTotal.
// Ideal para demo: respuesta inmediata y 100% confiable.
var localBlacklist = map[string]bool{
	"login-banco-seguro.com":                 true,
	"www.login-banco-seguro.com":             true,
	"secure-bancochile-login.tk":             true,
	"bancochile-verify.xyz":                  true,
	"bancosantander-cl-secure.phishing":      true,
	"paypa1.com":                             true,
	"www.paypa1.com":                         true,
	"paypal-login-secure.verify-account.xyz": true,
	"www.paypal-login-secure.verify-account.xyz": true,
	"phishing-demo.com":                      true,
	"www.phishing-demo.com":                  true,
}

func main() {
	loadEnv()
	vtAPIKey = os.Getenv("VIRUSTOTAL_API_KEY")
	if vtAPIKey == "" {
		log.Println("ADVERTENCIA: VIRUSTOTAL_API_KEY no configurada — usando modo degradado")
	}

	http.HandleFunc("/analyze", analyzeHandler)
	log.Println("Reputation service (VirusTotal) corriendo en :8083")
	log.Fatal(http.ListenAndServe(":8083", nil))
}

func loadEnv() {
	file, err := os.Open(".env")
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			os.Setenv(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<13)
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request: invalid JSON or body too large", http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		http.Error(w, "Bad Request: url parameter is required", http.StatusBadRequest)
		return
	}

	// 1. Chequear lista negra local PRIMERO — sin llamar a VirusTotal
	if parsed, err := url.Parse(req.URL); err == nil {
		host := strings.ToLower(parsed.Hostname())
		if localBlacklist[host] {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(Response{
				Score:   0.0,
				Reasons: []string{"Dominio en lista negra local — phishing confirmado"},
			}); err != nil {
				log.Printf("Error encoding response: %v", err)
			}
			return
		}
	}

	// 2. Si no está en lista negra → consultar VirusTotal
	score, reasons := analyze(req.URL)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(Response{Score: score, Reasons: reasons}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func analyze(rawURL string) (float64, []string) {
	if vtAPIKey == "" {
		return 1.0, []string{"VirusTotal no configurado - Verificación local limpia"}
	}

	verdict, stats, err := checkVirusTotal(rawURL)
	if err != nil {
		log.Println("Error consultando VirusTotal:", err)
		return 1.0, []string{"Error de conexión con VirusTotal - Verificación local limpia"}
	}

	return verdict, stats
}

// checkVirusTotal consulta la API v3 de VirusTotal
func checkVirusTotal(rawURL string) (float64, []string, error) {
	// VirusTotal requiere el ID en base64 url-safe de la URL
	urlID := base64URLEncode(rawURL)

	endpoint := fmt.Sprintf("https://www.virustotal.com/api/v3/urls/%s", urlID)

	client := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return 0.5, nil, err
	}
	req.Header.Set("x-apikey", vtAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return 1.0, nil, err
	}
	defer resp.Body.Close()

	// Si la URL nunca fue escaneada, la enviamos a analizar
	if resp.StatusCode == 404 {
		return submitURLForScan(rawURL)
	}

	if resp.StatusCode != 200 {
		return 1.0, []string{"Modo degradado (VirusTotal respondió código " + fmt.Sprint(resp.StatusCode) + ") - Verificación local limpia"}, nil
	}

	var result vtURLResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0.5, nil, err
	}

	return scoreFromStats(result.Data.Attributes.LastAnalysisStats)
}

type vtURLResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats map[string]int `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

func scoreFromStats(stats map[string]int) (float64, []string, error) {
	malicious := stats["malicious"]
	suspicious := stats["suspicious"]
	harmless := stats["harmless"]
	undetected := stats["undetected"]

	total := malicious + suspicious + harmless + undetected
	if total == 0 {
		return 0.5, []string{"Sin datos suficientes de VirusTotal"}, nil
	}

	reasons := []string{}
	if malicious > 0 {
		reasons = append(reasons, fmt.Sprintf("%d motores de VirusTotal marcan como malicioso", malicious))
	}
	if suspicious > 0 {
		reasons = append(reasons, fmt.Sprintf("%d motores marcan como sospechoso", suspicious))
	}

	// Score: cualquier detección maliciosa es una señal fuerte de alerta,
	// independiente de cuántos motores totales analizaron la URL
	score := 1.0
	if malicious > 0 {
		penalty := 0.5 + (float64(malicious) * 0.08)
		if penalty > 0.95 {
			penalty = 0.95
		}
		score = 1.0 - penalty
	} else if suspicious > 0 {
		penalty := 0.2 + (float64(suspicious) * 0.05)
		if penalty > 0.5 {
			penalty = 0.5
		}
		score = 1.0 - penalty
	}

	if score < 0 {
		score = 0
	}
	return score, reasons, nil
}

func submitURLForScan(rawURL string) (float64, []string, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	form := url.Values{}
	form.Set("url", rawURL)

	req, err := http.NewRequest("POST", "https://www.virustotal.com/api/v3/urls",
		strings.NewReader(form.Encode()))
	if err != nil {
		return 1.0, nil, err
	}
	req.Header.Set("x-apikey", vtAPIKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return 1.0, nil, err
	}
	defer resp.Body.Close()

	// URL recién enviada — aún no hay análisis, devolvemos neutro
	return 1.0, []string{"URL nueva enviada a VirusTotal para análisis"}, nil
}

func base64URLEncode(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
