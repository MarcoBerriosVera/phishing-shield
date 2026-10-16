package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Request struct {
	URL string `json:"url"`
}

type Response struct {
	Score   float64  `json:"score"`
	Reasons []string `json:"reasons"`
}

// Marcas conocidas a proteger
var knownBrands = []string{
	"paypal", "google", "facebook", "microsoft", "apple",
	"amazon", "netflix", "instagram", "twitter", "banco",
	"santander", "bci", "scotiabank", "falabella", "mercadolibre",
}

func main() {
	http.HandleFunc("/analyze", analyzeHandler)
	log.Println("Similarity service corriendo en :8082")
	log.Fatal(http.ListenAndServe(":8082", nil))
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
	penalty := 0.0

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0.5, []string{}
	}

	host := strings.ToLower(parsed.Hostname())

	for _, brand := range knownBrands {
		// Coincidencia exacta en dominio = legítimo
		if host == brand+".com" || host == "www."+brand+".com" {
			continue
		}

		// Contiene la marca pero no es el dominio oficial
		if strings.Contains(host, brand) {
			penalty += 0.3
			reasons = append(reasons, "Suplanta a "+brand)
			break
		}

		// Typosquatting — distancia de edición
		domain := extractDomain(host)
		if levenshtein(domain, brand) == 1 {
			penalty += 0.4
			reasons = append(reasons, "Muy similar a "+brand+" (typosquatting)")
			break
		}
	}

	score := 1.0 - penalty
	if score < 0 {
		score = 0
	}

	return score, reasons
}

func extractDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return host
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	dp := make([][]int, la+1)
	for i := range dp {
		dp[i] = make([]int, lb+1)
		dp[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		dp[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1]
			} else {
				dp[i][j] = 1 + min3(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
			}
		}
	}
	return dp[la][lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
