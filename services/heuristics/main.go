package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type Request struct {
	URL string `json:"url"`
}

type Response struct {
	Score   float64  `json:"score"`
	Reasons []string `json:"reasons"`
}

// trustedDomains — dominios cuyo path/query no activa heurísticas agresivas.
// El dominio en sí sigue evaluándose normalmente.
var trustedDomains = map[string]bool{
	"google.com":       true,
	"www.google.com":   true,
	"google.cl":        true,
	"www.google.cl":    true,
	"bing.com":         true,
	"www.bing.com":     true,
	"duckduckgo.com":   true,
	"yahoo.com":        true,
	"github.com":       true,
	"www.github.com":   true,
	"youtube.com":      true,
	"www.youtube.com":  true,
	"wikipedia.org":    true,
	"www.wikipedia.org": true,
}

func main() {
	http.HandleFunc("/analyze", analyzeHandler)
	log.Println("Heuristics service corriendo en :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
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
	score, reasons := analyze(req.URL)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(Response{Score: score, Reasons: reasons}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func analyze(rawURL string) (float64, []string) {
	reasons := []string{}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0.0, []string{"URL inválida"}
	}

	host := strings.ToLower(parsed.Hostname())

	// ── A) ANÁLISIS DEL DOMINIO RAÍZ (siempre se ejecuta) ────────────
	domainPenalty := 0.0

	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		domainPenalty += 0.20
		reasons = append(reasons, "Demasiados subdominios")
	}

	ipRegex := regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	if ipRegex.MatchString(host) {
		domainPenalty += 0.30
		reasons = append(reasons, "Usa IP en vez de dominio")
	}

	if strings.Count(host, "-") > 2 {
		domainPenalty += 0.10
		reasons = append(reasons, "Exceso de guiones en dominio")
	}

	suspiciousTLDs := []string{".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(host, tld) {
			domainPenalty += 0.25
			reasons = append(reasons, "TLD sospechoso: "+tld)
		}
	}

	if parsed.Scheme == "http" {
		domainPenalty += 0.10
		reasons = append(reasons, "Sin cifrado HTTPS")
	}

	// ── B) ANÁLISIS DE PATH Y QUERY — solo si el dominio NO es de confianza
	queryPenalty := 0.0

	if !trustedDomains[host] {
		// URL total larga (solo cuenta si el dominio tampoco es confiable)
		if len(rawURL) > 75 {
			queryPenalty += 0.15
			reasons = append(reasons, "URL sospechosamente larga")
		}

		suspicious := []string{"login", "verify", "secure", "account", "update", "banking", "confirm", "password"}
		count := 0
		pathAndQuery := strings.ToLower(parsed.Path + "?" + parsed.RawQuery)
		for _, word := range suspicious {
			if strings.Contains(pathAndQuery, word) {
				count++
			}
		}
		if count >= 2 {
			queryPenalty += 0.20
			reasons = append(reasons, "Múltiples palabras sospechosas en ruta/query")
		} else if count == 1 {
			queryPenalty += 0.05 // peso muy bajo para una sola palabra
		}
	}

	// ── C) SCORE FINAL: dominio (70%) + query (30%) ───────────────────
	// Fórmula: penalizaciones de dominio tienen mucho más peso que las de query
	totalPenalty := domainPenalty*0.70 + queryPenalty*0.30
	score := 1.0 - totalPenalty
	if score < 0 {
		score = 0
	}

	return score, reasons
}
