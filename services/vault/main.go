package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ── Vault data structure stored on disk ─────────────────────────────────────
// All sensitive fields are base64-encoded ciphertext — this service is
// zero-knowledge: it never holds plaintext passwords or the master key.
type VaultState struct {
	Initialized bool   `json:"initialized"`
	// PBKDF2 salt (random, 16 bytes, base64)
	Salt        string `json:"salt"`
	// DEK encrypted with KEK (AES-256-GCM). DEK is the actual vault key.
	DekEnc      string `json:"dek_enc"`
	DekIV       string `json:"dek_iv"`
	// TOTP secret encrypted with DEK
	TotpEnabled bool   `json:"totp_enabled"`
	TotpEnc     string `json:"totp_enc"`
	TotpIV      string `json:"totp_iv"`
	// Vault entries blob encrypted with DEK
	BlobEnc     string `json:"blob_enc"`
	BlobIV      string `json:"blob_iv"`
	// Metadata
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// ── File-based storage ───────────────────────────────────────────────────────
type Storage struct {
	mu   sync.RWMutex
	path string
	data VaultState
}

func newStorage(path string) (*Storage, error) {
	s := &Storage{path: path}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *Storage) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &s.data)
}

func (s *Storage) get() VaultState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}

func (s *Storage) set(v VaultState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = v
	return s.save()
}

func (s *Storage) reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = VaultState{}
	return s.save()
}

// Atomic write: temp file → rename
func (s *Storage) save() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// ── Handlers ─────────────────────────────────────────────────────────────────
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := origin == "" ||
			strings.HasPrefix(origin, "chrome-extension://") ||
			strings.HasPrefix(origin, "moz-extension://") ||
			origin == "http://localhost:8086" ||
			strings.HasPrefix(origin, "http://localhost:")

		if allowed && origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode error: %v", err)
	}
}

func makeHandlers(store *Storage) http.Handler {
	mux := http.NewServeMux()

	// GET /vault — return full vault state
	mux.HandleFunc("/vault", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		case http.MethodGet:
			jsonResponse(w, http.StatusOK, store.get())

		// POST /vault — save vault state (create or update)
		case http.MethodPost:
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB max
			var incoming VaultState
			if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
				jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
			if incoming.Salt == "" || incoming.DekEnc == "" {
				jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "salt and dek_enc are required"})
				return
			}
			incoming.Initialized = true
			incoming.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			if !store.get().Initialized {
				incoming.CreatedAt = incoming.UpdatedAt
			} else {
				incoming.CreatedAt = store.get().CreatedAt
			}
			if err := store.set(incoming); err != nil {
				log.Printf("storage error: %v", err)
				jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "storage error"})
				return
			}
			jsonResponse(w, http.StatusOK, map[string]string{"status": "saved"})

		// DELETE /vault — wipe vault
		case http.MethodDelete:
			if err := store.reset(); err != nil {
				jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "reset failed"})
				return
			}
			jsonResponse(w, http.StatusOK, map[string]string{"status": "reset"})

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	// GET /health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]string{"status": "ok", "service": "vault"})
	})

	return corsMiddleware(mux)
}

func main() {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "/data"
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatalf("cannot create data dir: %v", err)
	}

	store, err := newStorage(dataDir + "/vault.json")
	if err != nil {
		log.Fatalf("storage init error: %v", err)
	}

	log.Println("Vault service corriendo en :8086")
	log.Fatal(http.ListenAndServe(":8086", makeHandlers(store)))
}
