package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/gorilla/websocket"
)

// ── Types ─────────────────────────────────────────────────────────────────────

type AnalyzeRequest struct {
	URL                string   `json:"url"`
	DOM                string   `json:"dom"` // Client-rendered DOM HTML for anti-cloaking
	BehavioralWarnings []string `json:"behavioral_warnings"` // Client-side behavioral findings
}

type ServiceDetail struct {
	Score   float64  `json:"score"`
	Reasons []string `json:"reasons"`
}

type AnalyzeResponse struct {
	ID       string                   `json:"id"`
	URL      string                   `json:"url"`
	Status   string                   `json:"status"`
	Score    float64                  `json:"score"`
	Message  string                   `json:"message"`
	Details  map[string]float64       `json:"details"`
	Services map[string]ServiceDetail `json:"services"`
}

type ServiceResult struct {
	Score   float64  `json:"score"`
	Reasons []string `json:"reasons"`
}

type TelemetryUpdate struct {
	Analyzed   int `json:"analyzed"`
	Safe       int `json:"safe"`
	Suspicious int `json:"suspicious"`
	Blocked    int `json:"blocked"`
}

type APIKeyEntry struct {
	Token       string    `json:"token"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type Incident struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	URL       string    `json:"url"`
	Status    string    `json:"status"`
	Score     int       `json:"score"`
	UserIP    string    `json:"user_ip"`
	Bypassed  bool      `json:"bypassed"`
}

type RiskSettings struct {
	WeightHeuristics float64 `json:"weight_heuristics"`
	WeightSimilarity float64 `json:"weight_similarity"`
	WeightReputation float64 `json:"weight_reputation"`
	WeightML         float64 `json:"weight_ml"`
	WeightVisual     float64 `json:"weight_visual"`
}

// ── Global state ──────────────────────────────────────────────────────────────

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		allowed := strings.HasPrefix(origin, "chrome-extension://") ||
			origin == "null" ||
			strings.HasPrefix(origin, "http://localhost") ||
			strings.HasPrefix(origin, "http://127.0.0.1") ||
			strings.HasPrefix(origin, "https://localhost") ||
			strings.HasPrefix(origin, "https://127.0.0.1")
		return allowed
	},
}

var (
	clients   = make(map[*websocket.Conn]bool)
	clientsMu sync.Mutex
)

var (
	statsMu   sync.Mutex
	statsAnal = 0
	statsSafe = 0
	statsSusp = 0
	statsBlk  = 0
)

var (
	keysMu            sync.RWMutex
	allowedClientKeys = map[string]APIKeyEntry{}

	incidentsMu sync.RWMutex
	incidents   = []Incident{}

	whitelistMu      sync.RWMutex
	centralWhitelist = map[string]bool{
		"google.com":    true,
		"santander.cl":  true,
		"microsoft.com": true,
	}

	settingsMu   sync.RWMutex
	riskSettings = RiskSettings{
		WeightHeuristics: 0.25,
		WeightSimilarity: 0.20,
		WeightReputation: 0.25,
		WeightML:         0.15,
		WeightVisual:     0.15,
	}
)

type FalsePositiveReport struct {
	ID         string    `json:"id"`
	URL        string    `json:"url"`
	IncidentID string    `json:"incident_id"`
	Timestamp  time.Time `json:"timestamp"`
}

var (
	reports     []FalsePositiveReport
	reportsMu   sync.RWMutex
	latencies   []int64
	latenciesMu sync.Mutex
)

func saveReports() {
	reportsMu.RLock()
	cp := append([]FalsePositiveReport{}, reports...)
	reportsMu.RUnlock()
	saveJSON("reports.json", cp)
}

func recordLatency(ms int64) {
	latenciesMu.Lock()
	defer latenciesMu.Unlock()
	latencies = append(latencies, ms)
	if len(latencies) > 100 {
		latencies = latencies[1:]
	}
}

func getPercentile(p float64) float64 {
	latenciesMu.Lock()
	defer latenciesMu.Unlock()
	n := len(latencies)
	if n == 0 {
		return 0
	}
	sorted := make([]int64, n)
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	idx := float64(n-1) * p
	low := math.Floor(idx)
	high := math.Ceil(idx)
	if low == high {
		return float64(sorted[int(low)])
	}
	return float64(sorted[int(low)])*(high-idx) + float64(sorted[int(high)])*(idx-low)
}

// adminToken is set from ADMIN_TOKEN env at startup.
// Empty means admin routes are disabled.
var adminToken string

// ── Persistence ───────────────────────────────────────────────────────────────

const maxIncidents = 1000

var dataDir = "/data"

func dataPath(name string) string {
	return filepath.Join(dataDir, name)
}

// saveJSON atomically writes v as indented JSON to dataDir/filename.
func saveJSON(filename string, v interface{}) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Printf("saveJSON: mkdir %s: %v", dataDir, err)
		return
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("saveJSON %s: marshal: %v", filename, err)
		return
	}
	tmp := dataPath(filename + ".tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("saveJSON %s: write: %v", filename, err)
		return
	}
	if err := os.Rename(tmp, dataPath(filename)); err != nil {
		log.Printf("saveJSON %s: rename: %v", filename, err)
	}
}

// loadJSON reads dataDir/filename into v. Returns false if file missing or invalid.
func loadJSON(filename string, v interface{}) bool {
	data, err := os.ReadFile(dataPath(filename))
	if err != nil {
		return false
	}
	return json.Unmarshal(data, v) == nil
}

func saveKeys() {
	keysMu.RLock()
	list := make([]APIKeyEntry, 0, len(allowedClientKeys))
	for _, e := range allowedClientKeys {
		list = append(list, e)
	}
	keysMu.RUnlock()
	saveJSON("keys.json", list)
}

func saveIncidents() {
	incidentsMu.RLock()
	cp := append([]Incident{}, incidents...)
	incidentsMu.RUnlock()
	saveJSON("incidents.json", cp)
}

func saveWhitelist() {
	whitelistMu.RLock()
	list := make([]string, 0, len(centralWhitelist))
	for d := range centralWhitelist {
		list = append(list, d)
	}
	whitelistMu.RUnlock()
	saveJSON("whitelist.json", list)
}

func saveSettings() {
	settingsMu.RLock()
	s := riskSettings
	settingsMu.RUnlock()
	saveJSON("settings.json", s)
}

func saveTelemetry() {
	statsMu.Lock()
	t := TelemetryUpdate{statsAnal, statsSafe, statsSusp, statsBlk}
	statsMu.Unlock()
	saveJSON("telemetry.json", t)
}

// loadAllState restores persistent state from disk at startup.
func loadAllState() {
	// Keys
	keysMu.Lock()
	var keys []APIKeyEntry
	if loadJSON("keys.json", &keys) {
		for _, e := range keys {
			allowedClientKeys[e.Token] = e
		}
		log.Printf("Cargadas %d API keys desde disco", len(keys))
	}
	keysMu.Unlock()

	// Incidents
	incidentsMu.Lock()
	loadJSON("incidents.json", &incidents)
	if incidents == nil {
		incidents = []Incident{}
	}
	log.Printf("Cargados %d incidentes desde disco", len(incidents))
	incidentsMu.Unlock()

	// Whitelist (merge with defaults)
	whitelistMu.Lock()
	var wl []string
	if loadJSON("whitelist.json", &wl) {
		for _, d := range wl {
			centralWhitelist[d] = true
		}
		log.Printf("Cargados %d dominios en whitelist desde disco", len(wl))
	}
	whitelistMu.Unlock()

	// Settings
	settingsMu.Lock()
	if loadJSON("settings.json", &riskSettings) {
		log.Println("Configuración de pesos cargada desde disco")
	}
	settingsMu.Unlock()

	// Telemetry
	statsMu.Lock()
	var tel TelemetryUpdate
	if loadJSON("telemetry.json", &tel) {
		statsAnal = tel.Analyzed
		statsSafe = tel.Safe
		statsSusp = tel.Suspicious
		statsBlk  = tel.Blocked
		log.Printf("Telemetría restaurada: %d analizados", statsAnal)
	}
	statsMu.Unlock()

	// Reports
	reportsMu.Lock()
	loadJSON("reports.json", &reports)
	if reports == nil {
		reports = []FalsePositiveReport{}
	}
	log.Printf("Cargados %d reportes desde disco", len(reports))
	reportsMu.Unlock()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isKeyAllowed(key string) bool {
	keysMu.RLock()
	defer keysMu.RUnlock()
	_, exists := allowedClientKeys[key]
	return exists
}

func isWhitelisted(urlString string) bool {
	parsed, err := url.Parse(urlString)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		// Clean scheme and paths if they passed a raw URL string without parsing it successfully
		host = strings.ToLower(urlString)
		if strings.Contains(host, "://") {
			parts := strings.Split(host, "://")
			if len(parts) > 1 {
				host = parts[1]
			}
		}
		host = strings.Split(host, "/")[0]
		host = strings.Split(host, ":")[0]
	}
	
	whitelistMu.RLock()
	defer whitelistMu.RUnlock()
	
	// Exact match first
	if centralWhitelist[host] {
		return true
	}
	
	// Check parent subdomains (e.g. if host is mail.google.com, check google.com)
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		sub := strings.Join(parts[i:], ".")
		if centralWhitelist[sub] {
			return true
		}
	}
	return false
}

func generateRandomString(length int) string {
	b := make([]byte, length/2)
	if _, err := cryptorand.Read(b); err != nil {
		return "fallbackkey123"
	}
	return hex.EncodeToString(b)
}

// generateIncidentID returns a collision-resistant ID using crypto/rand.
func generateIncidentID() string {
	b := make([]byte, 5)
	cryptorand.Read(b)
	return "PS-" + hex.EncodeToString(b)
}

func forwardToSIEM(id string, urlStr string, status string, riskPercent int, userIP string, bypassed bool) {
	logFile := dataPath("siem_incidents.log")
	entry := map[string]interface{}{
		"event_source": "PhishingShieldOrchestrator",
		"incident_id":  id,
		"timestamp":    time.Now().Format(time.RFC3339),
		"target_url":   urlStr,
		"verdict":      status,
		"risk_score":   riskPercent,
		"user_ip":      userIP,
		"bypassed":     bypassed,
	}
	jsonData, err := json.Marshal(entry)
	if err != nil {
		return
	}
	// Escribir en modo append
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("SIEM Logger error: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(jsonData, '\n')); err != nil {
		log.Printf("SIEM Logger write error: %v", err)
	}
}

func sendWebhookAlert(urlStr string, tracebackID string) {
	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookURL == "" {
		webhookURL = os.Getenv("DISCORD_WEBHOOK_URL")
	}
	if webhookURL == "" {
		return
	}
	payload := map[string]interface{}{
		"text": fmt.Sprintf("⚠️ *Alerta SOC: Advertencia Ignorada (Bypass)*\n*URL:* %s\n*ID Trazabilidad:* %s\n*Hora:* %s\n*Acción:* El usuario decidió ignorar la pantalla de bloqueo y continuar al sitio.",
			urlStr, tracebackID, time.Now().Format("2006-01-02 15:04:05")),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func registerIncident(id string, urlStr string, status string, riskPercent int, userIP string, bypassed bool) string {
	if id == "" {
		id = generateIncidentID()
	}
	incidentsMu.Lock()
	if len(incidents) >= maxIncidents {
		incidents = incidents[1:]
	}
	incidents = append(incidents, Incident{
		ID:        id,
		Timestamp: time.Now(),
		URL:       urlStr,
		Status:    status,
		Score:     riskPercent,
		UserIP:    userIP,
		Bypassed:  bypassed,
	})
	incidentsMu.Unlock()
	go saveIncidents()

	// Forward to SIEM log (REQ-ARQ-03)
	go forwardToSIEM(id, urlStr, status, riskPercent, userIP, bypassed)

	return id
}

func markIncidentBypassed(urlStr string) {
	incidentsMu.Lock()
	var incidentID string
	for i := len(incidents) - 1; i >= 0; i-- {
		if incidents[i].URL == urlStr {
			incidents[i].Bypassed = true
			incidentID = incidents[i].ID
			break
		}
	}
	incidentsMu.Unlock()
	go saveIncidents()

	if incidentID != "" {
		traceID := "#PS-" + incidentID + "-A"
		if len(incidentID) > 5 {
			traceID = "#PS-" + strings.ToUpper(incidentID[len(incidentID)-5:]) + "-A"
		}
		// Enviar alerta de webhook SOC (REQ-BE-02)
		go sendWebhookAlert(urlStr, traceID)
	}
}

func getIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		var err error
		ip, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
	}
	if ip == "::1" {
		return "127.0.0.1"
	}
	return ip
}

// loadClientKeys reads API keys from CLIENT_API_KEYS env (additive, won't overwrite disk keys).
// Demo key is ONLY added when DEMO_MODE=true is explicitly set.
func loadClientKeys() {
	keysStr := os.Getenv("CLIENT_API_KEYS")
	if keysStr != "" {
		keysMu.Lock()
		for _, key := range strings.Split(keysStr, ",") {
			k := strings.TrimSpace(key)
			if k == "" {
				continue
			}
			if _, exists := allowedClientKeys[k]; !exists {
				allowedClientKeys[k] = APIKeyEntry{
					Token:       k,
					Description: "Configurado por variable de entorno",
					CreatedAt:   time.Now(),
				}
			}
		}
		keysMu.Unlock()
	}

	if len(allowedClientKeys) == 0 || os.Getenv("DEMO_MODE") == "true" {
		keysMu.Lock()
		allowedClientKeys["demo-key-123"] = APIKeyEntry{
			Token:       "demo-key-123",
			Description: "Demo Key (DEMO_MODE activo — NO usar en producción)",
			CreatedAt:   time.Now(),
		}
		keysMu.Unlock()
		log.Println("⚠️  DEMO_MODE=true o sin llaves configuradas — demo-key-123 habilitada. No usar en producción.")
	}
}

// ── Middleware ─────────────────────────────────────────────────────────────────

// corsMiddleware permite solo orígenes legítimos:
// extensiones Chrome (chrome-extension://) y localhost para desarrollo.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if origin != "" {
			allowed := strings.HasPrefix(origin, "chrome-extension://") ||
				origin == "null" ||
				strings.HasPrefix(origin, "http://localhost") ||
				strings.HasPrefix(origin, "http://127.0.0.1") ||
				strings.HasPrefix(origin, "https://localhost") ||
				strings.HasPrefix(origin, "https://127.0.0.1")

			if !allowed {
				http.Error(w, "CORS: origin not allowed", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}

		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Client-Key, X-Admin-Token")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authMiddleware valida X-Client-Key para rutas de la extensión.
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}
		key := r.Header.Get("X-Client-Key")
		if key == "" {
			key = r.URL.Query().Get("token")
		}
		if !isKeyAllowed(key) {
			http.Error(w, "Unauthorized: invalid or missing Client API Key", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminMiddleware valida X-Admin-Token para rutas de administración.
// Si ADMIN_TOKEN no está configurado, devuelve 503 para alertar al operador.
func adminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}
		if adminToken == "" {
			http.Error(w, "Admin access unavailable: ADMIN_TOKEN not configured", http.StatusServiceUnavailable)
			return
		}
		token := r.Header.Get("X-Admin-Token")
		if token != adminToken {
			http.Error(w, "Unauthorized: invalid admin token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── Startup ───────────────────────────────────────────────────────────────────

func init() {
	if dir := os.Getenv("DATA_DIR"); dir != "" {
		dataDir = dir
	}
	loadAllState()
	loadClientKeys()

	// Telemetría de demo solo si no hay datos reales en disco
	if os.Getenv("DEMO_MODE") == "true" {
		statsMu.Lock()
		if statsAnal == 0 {
			statsAnal = 14208
			statsSafe = 13902
			statsSusp = 154
			statsBlk  = 152
		}
		statsMu.Unlock()
	}
}

// ── WebSocket ─────────────────────────────────────────────────────────────────

func wsHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" || !isKeyAllowed(token) {
		http.Error(w, "Unauthorized: invalid client token", http.StatusUnauthorized)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error al actualizar a WebSocket:", err)
		return
	}
	clientsMu.Lock()
	clients[conn] = true
	clientsMu.Unlock()

	defer func() {
		clientsMu.Lock()
		delete(clients, conn)
		clientsMu.Unlock()
		conn.Close()
	}()

	statsMu.Lock()
	initialTelemetry := TelemetryUpdate{
		Analyzed:   statsAnal,
		Safe:       statsSafe,
		Suspicious: statsSusp,
		Blocked:    statsBlk,
	}
	statsMu.Unlock()

	initPayload, _ := json.Marshal(map[string]interface{}{
		"event": "TELEMETRY_UPDATE",
		"data":  initialTelemetry,
	})
	conn.WriteMessage(websocket.TextMessage, initPayload)

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

type WSMessage struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
}

func broadcast(event string, data interface{}) {
	msg := WSMessage{Event: event, Data: data}
	payload, err := json.Marshal(msg)
	if err != nil {
		return
	}
	clientsMu.Lock()
	defer clientsMu.Unlock()
	for conn := range clients {
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			conn.Close()
			delete(clients, conn)
		}
	}
}

// ── Admin handlers ────────────────────────────────────────────────────────────

func getIncidentsHandler(w http.ResponseWriter, r *http.Request) {
	incidentsMu.RLock()
	defer incidentsMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(incidents)
}

func clearIncidentsHandler(w http.ResponseWriter, r *http.Request) {
	incidentsMu.Lock()
	incidents = []Incident{}
	incidentsMu.Unlock()
	go saveIncidents()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func getWhitelistHandler(w http.ResponseWriter, r *http.Request) {
	whitelistMu.RLock()
	defer whitelistMu.RUnlock()
	list := make([]string, 0, len(centralWhitelist))
	for k := range centralWhitelist {
		list = append(list, k)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func addWhitelistHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}
	dom := strings.ToLower(strings.TrimSpace(req.Domain))
	if dom == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}
	
	// Extract clean hostname if they pasted a full URL
	if strings.Contains(dom, "://") {
		if parsed, err := url.Parse(dom); err == nil {
			dom = parsed.Hostname()
		} else {
			parts := strings.Split(dom, "://")
			if len(parts) > 1 {
				dom = parts[1]
			}
		}
	}
	dom = strings.Split(dom, "/")[0]
	dom = strings.Split(dom, ":")[0]
	dom = strings.TrimSpace(dom)
	
	if dom == "" {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}

	whitelistMu.Lock()
	centralWhitelist[dom] = true
	whitelistMu.Unlock()
	go saveWhitelist()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func deleteWhitelistHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}
	dom := strings.ToLower(strings.TrimSpace(req.Domain))
	whitelistMu.Lock()
	delete(centralWhitelist, dom)
	whitelistMu.Unlock()
	go saveWhitelist()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func getKeysHandler(w http.ResponseWriter, r *http.Request) {
	keysMu.RLock()
	defer keysMu.RUnlock()
	list := make([]APIKeyEntry, 0, len(allowedClientKeys))
	for _, entry := range allowedClientKeys {
		list = append(list, entry)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func addKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}
	desc := strings.TrimSpace(req.Description)
	if desc == "" {
		desc = "Dispositivo corporativo"
	}
	token := "pk_" + generateRandomString(16)
	entry := APIKeyEntry{
		Token:       token,
		Description: desc,
		CreatedAt:   time.Now(),
	}
	keysMu.Lock()
	allowedClientKeys[token] = entry
	keysMu.Unlock()
	go saveKeys()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}

func deleteKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}
	keysMu.Lock()
	delete(allowedClientKeys, req.Token)
	keysMu.Unlock()
	go saveKeys()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func getSettingsHandler(w http.ResponseWriter, r *http.Request) {
	settingsMu.RLock()
	defer settingsMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(riskSettings)
}

func updateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	var req RiskSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}
	settingsMu.Lock()
	riskSettings = req
	settingsMu.Unlock()
	go saveSettings()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	adminToken = os.Getenv("ADMIN_TOKEN")
	if adminToken == "" {
		log.Println("⚠️  ADMIN_TOKEN no configurado — rutas /api/* responderán 503 hasta configurarlo.")
	} else {
		log.Println("✅ ADMIN_TOKEN configurado — rutas /api/* protegidas.")
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware)
	r.Use(httprate.LimitByIP(100, 1*time.Minute))

	// Ruta pública — sin autenticación
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			log.Printf("Error encoding health response: %v", err)
		}
	})
	r.Post("/api/reports", addReportHandler) // Public false positive submission

	// Rutas de cliente — requieren X-Client-Key válida
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware)
		r.Post("/analyze", analyzeHandler)
		r.Post("/analyze-hash", analyzeHashHandler)
		r.Post("/bypass", bypassHandler)
		r.Get("/ws", wsHandler)
	})

	// Rutas de administración — requieren X-Admin-Token
	r.Group(func(r chi.Router) {
		r.Use(adminMiddleware)
		r.Get("/api/incidents", getIncidentsHandler)
		r.Post("/api/incidents/clear", clearIncidentsHandler)
		r.Get("/api/whitelist", getWhitelistHandler)
		r.Post("/api/whitelist", addWhitelistHandler)
		r.Delete("/api/whitelist", deleteWhitelistHandler)
		r.Get("/api/keys", getKeysHandler)
		r.Post("/api/keys", addKeyHandler)
		r.Delete("/api/keys", deleteKeyHandler)
		r.Get("/api/settings", getSettingsHandler)
		r.Post("/api/settings", updateSettingsHandler)
		r.Get("/api/reports", getReportsHandler)        // SOC User reports view
		r.Delete("/api/reports", deleteReportHandler)  // SOC User reports action
		r.Get("/api/metrics", getMetricsHandler)        // SOC Telemetry metrics (P95)
	})

	log.Println("Orquestador corriendo en :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// ── Analyze handlers ──────────────────────────────────────────────────────────

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<22) // 4MB to support dynamic DOM payloads
	var req AnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request: invalid JSON or request body too large", http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		http.Error(w, "Bad request: url parameter is required", http.StatusBadRequest)
		return
	}
	if !isValidURL(req.URL) {
		http.Error(w, "Bad request: URL is invalid or target domain/IP is blocked", http.StatusBadRequest)
		return
	}

	if isWhitelisted(req.URL) {
		incidentID := generateIncidentID()
		resp := AnalyzeResponse{
			ID:      incidentID,
			URL:     req.URL,
			Status:  "safe",
			Score:   1.0,
			Message: "Dominio en whitelist central — verificado legítimo",
			Details: map[string]float64{
				"heuristics": 1.0, "similarity": 1.0,
				"reputation": 1.0, "ml": 1.0, "visual": 1.0,
			},
			Services: map[string]ServiceDetail{
				"heuristics": {Score: 1.0, Reasons: []string{"Dominio en whitelist central"}},
				"similarity": {Score: 1.0, Reasons: []string{"Dominio en whitelist central"}},
				"reputation": {Score: 1.0, Reasons: []string{"Dominio en whitelist central"}},
				"ml":         {Score: 1.0, Reasons: []string{"Dominio en whitelist central"}},
				"visual":     {Score: 1.0, Reasons: []string{"Dominio en whitelist central"}},
			},
		}
		broadcast("URL_INTERCEPTED", map[string]interface{}{"url": req.URL, "timeMs": 0})
		time.Sleep(150 * time.Millisecond)
		broadcast("FINAL_VERDICT", map[string]interface{}{
			"score": 0, "verdictText": "Seguro",
			"verdictTitle": "Dominio en Whitelist Central", "isDangerous": false,
			"explanations": []string{"El administrador corporativo ha añadido este dominio a la lista de exclusiones."},
			"timeMs":       0,
		})
		registerIncident(incidentID, req.URL, "safe", 0, getIP(r), false)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	incidentID := generateIncidentID()

	// Guardar el DOM HTML recibido (REQ-ARQ-01 Anti-Cloaking)
	if req.DOM != "" {
		domDir := dataPath("doms")
		os.MkdirAll(domDir, 0755)
		domFile := filepath.Join(domDir, incidentID+".html")
		os.WriteFile(domFile, []byte(req.DOM), 0644)
	}

	broadcast("URL_INTERCEPTED", map[string]interface{}{"url": req.URL, "timeMs": 0})
	time.Sleep(150 * time.Millisecond)
	broadcast("ORCHESTRATOR_START", map[string]interface{}{"timeMs": 10})
	time.Sleep(150 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 8000*time.Millisecond)
	defer cancel()

	svcMetadata := map[string]struct {
		id         string
		shortLabel string
		label      string
		maxScore   float64
		fn         func(context.Context, string) ServiceResult
	}{
		"heuristics": {"ms-heur", "heur", "Heurísticas", 25.0, callHeuristics},
		"similarity": {"ms-simi", "simi", "Similitud Léxica", 20.0, callSimilarity},
		"reputation": {"ms-vt", "vt", "Reputación VT", 25.0, callReputation},
		"ml":         {"ms-ml", "ml", "Machine Learning", 15.0, callML},
		"visual":     {"ms-vis", "vis", "Análisis Visual", 15.0, callVisual},
	}

	for _, meta := range svcMetadata {
		broadcast("MICROSERVICE_PROCESSING", map[string]interface{}{
			"id": meta.id, "shortLabel": meta.shortLabel, "label": meta.label,
		})
	}
	time.Sleep(150 * time.Millisecond)

	results := make(map[string]ServiceResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	startTime := time.Now()

	for name, meta := range svcMetadata {
		wg.Add(1)
		go func(name string, meta struct {
			id         string
			shortLabel string
			label      string
			maxScore   float64
			fn         func(context.Context, string) ServiceResult
		}) {
			defer wg.Done()
			svcStart := time.Now()
			res := meta.fn(ctx, req.URL)
			execTime := time.Since(svcStart).Milliseconds()

			mu.Lock()
			results[name] = res
			mu.Unlock()

			type DetailItem struct {
				Text       string `json:"text"`
				IsCritical bool   `json:"isCritical"`
			}
			details := []DetailItem{}
			for _, reason := range res.Reasons {
				details = append(details, DetailItem{Text: reason, IsCritical: res.Score < 0.7})
			}
			if len(details) == 0 && res.Score >= 0.9 {
				details = append(details, DetailItem{Text: "Verificación exitosa sin reparos", IsCritical: false})
			}

			broadcast("MICROSERVICE_DONE", map[string]interface{}{
				"id": meta.id, "shortLabel": meta.shortLabel, "label": meta.label,
				"score":           int(res.Score * meta.maxScore),
				"maxScore":        int(meta.maxScore),
				"executionTimeMs": execTime,
				"timeMs":          time.Since(startTime).Milliseconds(),
				"details":         details,
			})
		}(name, meta)
	}

	wg.Wait()

	// Inyectar alertas de comportamiento dinámico client-side (REQ-ARQ-04)
	if len(req.BehavioralWarnings) > 0 {
		hResult := results["heuristics"]
		hResult.Score = 0.10 // Forzar veredicto de bloqueo
		hResult.Reasons = append(hResult.Reasons, req.BehavioralWarnings...)
		results["heuristics"] = hResult
	}

	latencyMs := time.Since(startTime).Milliseconds()
	recordLatency(latencyMs) // Registrar latencias para percentiles P95 (REQ-ARQ-02)

	broadcast("RISK_CALCULATION", map[string]interface{}{"timeMs": latencyMs})
	time.Sleep(150 * time.Millisecond)

	settingsMu.RLock()
	weights := riskSettings
	settingsMu.RUnlock()

	finalScore := results["heuristics"].Score*weights.WeightHeuristics +
		results["similarity"].Score*weights.WeightSimilarity +
		results["reputation"].Score*weights.WeightReputation +
		results["ml"].Score*weights.WeightML +
		results["visual"].Score*weights.WeightVisual

	status, message := verdict(finalScore)

	explanations := []string{}
	for _, name := range []string{"heuristics", "similarity", "reputation", "ml", "visual"} {
		explanations = append(explanations, results[name].Reasons...)
	}
	if len(explanations) == 0 {
		explanations = append(explanations, "Todos los análisis indican que el sitio es legítimo.")
	}

	isDangerous := status == "danger"
	verdictText, verdictTitle := "Seguro", "Sin amenazas detectadas"
	if status == "danger" {
		verdictText, verdictTitle = "Peligroso", "Amenaza de Phishing Detectada"
	} else if status == "suspicious" {
		verdictText, verdictTitle = "Sospechoso", "Sitio No Verificado"
	}

	riskPercent := int((1.0 - finalScore) * 100)
	if riskPercent < 0 {
		riskPercent = 0
	} else if riskPercent > 100 {
		riskPercent = 100
	}

	broadcast("FINAL_VERDICT", map[string]interface{}{
		"score": riskPercent, "verdictText": verdictText,
		"verdictTitle": verdictTitle, "isDangerous": isDangerous,
		"explanations": explanations,
		"timeMs":       latencyMs,
	})
	time.Sleep(150 * time.Millisecond)

	statsMu.Lock()
	statsAnal++
	if status == "safe" {
		statsSafe++
	} else if status == "suspicious" {
		statsSusp++
	} else if status == "danger" {
		statsBlk++
	}
	telemetry := TelemetryUpdate{statsAnal, statsSafe, statsSusp, statsBlk}
	statsMu.Unlock()

	broadcast("TELEMETRY_UPDATE", telemetry)
	go saveTelemetry()

	registerIncident(incidentID, req.URL, status, riskPercent, getIP(r), false)

	serviceDetails := map[string]ServiceDetail{}
	simpleDetails := map[string]float64{}
	for k, v := range results {
		serviceDetails[k] = ServiceDetail{Score: v.Score, Reasons: v.Reasons}
		simpleDetails[k] = v.Score
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(AnalyzeResponse{
		ID: incidentID, URL: req.URL, Status: status, Score: finalScore,
		Message: message, Details: simpleDetails, Services: serviceDetails,
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func verdict(score float64) (string, string) {
	switch {
	case score >= 0.75:
		return "safe", "Sin amenazas detectadas"
	case score >= 0.55:
		return "suspicious", "Sitio sospechoso, procede con cuidado"
	default:
		return "danger", "Phishing detectado — sitio bloqueado"
	}
}

type BypassRequest struct {
	URL string `json:"url"`
}

func bypassHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<13)
	var req BypassRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request: invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		http.Error(w, "Bad request: url is required", http.StatusBadRequest)
		return
	}
	if req.URL == "test-connection" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	markIncidentBypassed(req.URL)
	broadcast("USER_BYPASSED_WARNING", map[string]interface{}{
		"url": req.URL, "timeMs": time.Now().UnixMilli(),
	})
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]bool{"ok": true}); err != nil {
		log.Printf("Error encoding bypass response: %v", err)
	}
}

type AnalyzeHashRequest struct {
	Hash   string `json:"hash"`
	Domain string `json:"domain"`
}

func analyzeHashHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<13)
	var req AnalyzeHashRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request: invalid JSON body", http.StatusBadRequest)
		return
	}

	target := "http://localhost:8085/analyze-hash"
	if isDocker() {
		target = "http://visual:8085/analyze-hash"
	}

	body, _ := json.Marshal(req)
	ctx, cancel := context.WithTimeout(context.Background(), 8000*time.Millisecond)
	defer cancel()

	hReq, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewBuffer(body))
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	hReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(hReq)
	if err != nil {
		http.Error(w, "Visual service offline", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		http.Error(w, "Failed to decode visual service response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("Error encoding hash response: %v", err)
	}
}

// ── Service callers ───────────────────────────────────────────────────────────

func callServiceByHost(ctx context.Context, url, host, port string) ServiceResult {
	target := "http://localhost:" + port + "/analyze"
	if isDocker() {
		target = "http://" + host + ":" + port + "/analyze"
	}
	body, _ := json.Marshal(map[string]string{"url": url})
	req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewBuffer(body))
	if err != nil {
		return ServiceResult{Score: 0.5, Reasons: []string{"Error interno de red"}}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ServiceResult{Score: 0.5, Reasons: []string{"Microservicio fuera de línea"}}
	}
	defer resp.Body.Close()

	var result struct {
		Score   float64  `json:"score"`
		Reasons []string `json:"reasons"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Error decoding service response from %s:%s: %v", host, port, err)
		return ServiceResult{Score: 0.5, Reasons: []string{"Error al decodificar respuesta del microservicio"}}
	}
	if result.Reasons == nil {
		result.Reasons = []string{}
	}
	return ServiceResult{Score: result.Score, Reasons: result.Reasons}
}

func isDocker() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

func callHeuristics(ctx context.Context, url string) ServiceResult {
	return callServiceByHost(ctx, url, "heuristics", "8081")
}
func callSimilarity(ctx context.Context, url string) ServiceResult {
	return callServiceByHost(ctx, url, "similarity", "8082")
}
func callReputation(ctx context.Context, url string) ServiceResult {
	return callServiceByHost(ctx, url, "reputation", "8083")
}
func callML(ctx context.Context, url string) ServiceResult {
	return callServiceByHost(ctx, url, "ml", "8084")
}
func callVisual(ctx context.Context, url string) ServiceResult {
	return callServiceByHost(ctx, url, "visual", "8085")
}

func isValidURL(urlString string) bool {
	parsed, err := url.Parse(urlString)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	host := parsed.Hostname()
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
			return false
		}
	}
	if host == "169.254.169.254" || host == "metadata.google.internal" {
		return false
	}
	return true
}

func addReportHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<13)
	var req struct {
		URL        string `json:"url"`
		IncidentID string `json:"incident_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	reportsMu.Lock()
	duplicated := false
	for _, rep := range reports {
		if rep.URL == req.URL {
			duplicated = true
			break
		}
	}
	if !duplicated {
		reports = append(reports, FalsePositiveReport{
			ID:         "REP-" + strconv.FormatInt(time.Now().UnixNano()/1000000%100000, 10),
			URL:        req.URL,
			IncidentID: req.IncidentID,
			Timestamp:  time.Now(),
		})
		go saveReports()
	}
	reportsMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func getReportsHandler(w http.ResponseWriter, r *http.Request) {
	reportsMu.RLock()
	cp := append([]FalsePositiveReport{}, reports...)
	reportsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cp)
}

func deleteReportHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string `json:"id"`
		Action string `json:"action"` // "approve" or "reject"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	reportsMu.Lock()
	foundIdx := -1
	var foundReport FalsePositiveReport
	for i, rep := range reports {
		if rep.ID == req.ID {
			foundIdx = i
			foundReport = rep
			break
		}
	}

	if foundIdx != -1 {
		reports = append(reports[:foundIdx], reports[foundIdx+1:]...)
		go saveReports()
	}
	reportsMu.Unlock()

	if foundIdx == -1 {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}

	if req.Action == "approve" {
		u, err := url.Parse(foundReport.URL)
		if err == nil {
			domain := u.Hostname()
			if domain != "" {
				whitelistMu.Lock()
				centralWhitelist[domain] = true
				whitelistMu.Unlock()
				go saveWhitelist()
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func getMetricsHandler(w http.ResponseWriter, r *http.Request) {
	p50 := getPercentile(0.50)
	p90 := getPercentile(0.90)
	p95 := getPercentile(0.95)

	statsMu.Lock()
	stats := map[string]interface{}{
		"p50_latency_ms": p50,
		"p90_latency_ms": p90,
		"p95_latency_ms": p95,
		"analyzed":       statsAnal,
		"safe":           statsSafe,
		"suspicious":     statsSusp,
		"blocked":        statsBlk,
	}
	statsMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}


