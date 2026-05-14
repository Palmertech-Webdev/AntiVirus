package reputation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type Verdict string

const (
	VerdictClean     Verdict = "Clean"
	VerdictMalicious Verdict = "Malicious"
	VerdictUnknown   Verdict = "Unknown"
)

type ReputationResult struct {
	SHA256     string    `json:"sha256"`
	Verdict    Verdict   `json:"verdict"`
	ThreatName string    `json:"threatName,omitempty"`
	Confidence int       `json:"confidence"` // 0-100
	CachedAt   time.Time `json:"cachedAt"`
}

type ReputationLookup struct {
	backendURL string
	cache      map[string]ReputationResult
	mu         sync.RWMutex
	httpClient *http.Client
}

func NewReputationLookup(backendURL string) *ReputationLookup {
	return &ReputationLookup{
		backendURL: backendURL,
		cache:      make(map[string]ReputationResult),
		httpClient: &http.Client{Timeout: 8 * time.Second},
	}
}

// LookupFile hashes a file and checks its reputation.
func (r *ReputationLookup) LookupFile(filePath string) (*ReputationResult, error) {
	hash, err := sha256File(filePath)
	if err != nil {
		return nil, fmt.Errorf("hash file: %w", err)
	}
	return r.LookupHash(hash)
}

// LookupHash checks a SHA-256 hash against the backend reputation service.
func (r *ReputationLookup) LookupHash(hash string) (*ReputationResult, error) {
	// Check local cache first
	r.mu.RLock()
	if cached, ok := r.cache[hash]; ok && time.Since(cached.CachedAt) < 10*time.Minute {
		r.mu.RUnlock()
		return &cached, nil
	}
	r.mu.RUnlock()

	// Query backend
	url := fmt.Sprintf("%s/api/v1/reputation/%s", r.backendURL, hash)
	resp, err := r.httpClient.Get(url)
	if err != nil {
		log.Printf("[ReputationLookup] Backend unreachable, returning Unknown for %s: %v", hash[:16], err)
		result := ReputationResult{SHA256: hash, Verdict: VerdictUnknown, CachedAt: time.Now()}
		return &result, nil
	}
	defer resp.Body.Close()

	var result ReputationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	result.CachedAt = time.Now()

	r.mu.Lock()
	r.cache[hash] = result
	r.mu.Unlock()

	return &result, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
