package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type TrustResult struct {
	Trusted bool
	Reason  string
}

type RuntimeTrustValidator struct {
	expectedSelfHash string // set at build time via ldflags
}

func NewRuntimeTrustValidator(expectedHash string) *RuntimeTrustValidator {
	return &RuntimeTrustValidator{expectedSelfHash: expectedHash}
}

// ValidateSelf verifies the running binary's SHA-256 matches the expected hash.
func (v *RuntimeTrustValidator) ValidateSelf() TrustResult {
	if v.expectedSelfHash == "" {
		return TrustResult{Trusted: true, Reason: "self-hash check skipped (not configured)"}
	}
	selfPath, err := os.Executable()
	if err != nil {
		return TrustResult{Trusted: false, Reason: fmt.Sprintf("cannot resolve self path: %v", err)}
	}
	hash, err := hashFile(selfPath)
	if err != nil {
		return TrustResult{Trusted: false, Reason: fmt.Sprintf("hash failed: %v", err)}
	}
	if hash != v.expectedSelfHash {
		return TrustResult{Trusted: false, Reason: fmt.Sprintf("self-hash mismatch: expected %s, got %s", v.expectedSelfHash[:16], hash[:16])}
	}
	return TrustResult{Trusted: true, Reason: "self-hash verified"}
}

// ValidateFile checks a file's hash against an expected value.
func (v *RuntimeTrustValidator) ValidateFile(path, expectedHash string) TrustResult {
	hash, err := hashFile(path)
	if err != nil {
		return TrustResult{Trusted: false, Reason: fmt.Sprintf("hash failed: %v", err)}
	}
	if hash != expectedHash {
		return TrustResult{Trusted: false, Reason: "hash mismatch"}
	}
	return TrustResult{Trusted: true, Reason: "verified"}
}

func hashFile(path string) (string, error) {
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
