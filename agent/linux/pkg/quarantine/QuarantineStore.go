package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

const quarantineRoot = "/var/lib/fenrir/quarantine"

type QuarantineEntry struct {
	OriginalPath   string    `json:"originalPath"`
	QuarantinePath string    `json:"quarantinePath"`
	SHA256         string    `json:"sha256"`
	Reason         string    `json:"reason"`
	QuarantinedAt  time.Time `json:"quarantinedAt"`
}

type QuarantineStore struct {
	root string
}

func NewQuarantineStore() *QuarantineStore {
	if err := os.MkdirAll(quarantineRoot, 0700); err != nil {
		log.Printf("[QuarantineStore] Could not create quarantine dir: %v", err)
	}
	return &QuarantineStore{root: quarantineRoot}
}

// Quarantine moves a file into the quarantine directory and removes execute permissions.
func (q *QuarantineStore) Quarantine(filePath string, reason string) (*QuarantineEntry, error) {
	hash, err := sha256File(filePath)
	if err != nil {
		return nil, fmt.Errorf("hash file: %w", err)
	}

	destName := fmt.Sprintf("%d_%s.quarantine", time.Now().UnixNano(), hash[:16])
	destPath := filepath.Join(q.root, destName)

	if err := moveFile(filePath, destPath); err != nil {
		return nil, fmt.Errorf("move file: %w", err)
	}

	// Strip all execute permissions from quarantined file
	if err := os.Chmod(destPath, 0400); err != nil {
		log.Printf("[QuarantineStore] chmod warning: %v", err)
	}

	entry := &QuarantineEntry{
		OriginalPath:   filePath,
		QuarantinePath: destPath,
		SHA256:         hash,
		Reason:         reason,
		QuarantinedAt:  time.Now(),
	}

	log.Printf("[QuarantineStore] Quarantined: %s -> %s (reason: %s)", filePath, destPath, reason)
	return entry, nil
}

// Restore moves a quarantined file back to its original path.
func (q *QuarantineStore) Restore(entry *QuarantineEntry) error {
	return moveFile(entry.QuarantinePath, entry.OriginalPath)
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

func moveFile(src, dst string) error {
	// Try atomic rename first (same filesystem)
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// Fall back to copy+delete (cross-filesystem)
	if err := copyFile(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
