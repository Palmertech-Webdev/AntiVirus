package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const evidenceRoot = "/var/lib/fenrir/evidence"

type EvidenceBundle struct {
	BundleId    string    `json:"bundleId"`
	Pid         uint32    `json:"pid"`
	ProcessName string    `json:"processName"`
	CreatedAt   time.Time `json:"createdAt"`
	ProcessTree string    `json:"processTree,omitempty"`
	OpenFiles   string    `json:"openFiles,omitempty"`
	NetConns    string    `json:"netConnections,omitempty"`
}

type EvidenceRecorder struct{}

func NewEvidenceRecorder() *EvidenceRecorder {
	os.MkdirAll(evidenceRoot, 0700)
	return &EvidenceRecorder{}
}

// Collect gathers forensic evidence for a suspicious process.
func (e *EvidenceRecorder) Collect(pid uint32, processName string) (*EvidenceBundle, error) {
	bundleId := fmt.Sprintf("%d_%d", time.Now().UnixNano(), pid)
	bundle := &EvidenceBundle{
		BundleId:    bundleId,
		Pid:         pid,
		ProcessName: processName,
		CreatedAt:   time.Now(),
	}

	pidStr := fmt.Sprintf("%d", pid)

	if out, err := exec.Command("pstree", "-p", pidStr).Output(); err == nil {
		bundle.ProcessTree = string(out)
	}
	if out, err := exec.Command("lsof", "-p", pidStr).Output(); err == nil {
		bundle.OpenFiles = string(out)
	}
	if out, err := exec.Command("ss", "-tp", fmt.Sprintf("( dport %s or sport %s )", pidStr, pidStr)).Output(); err == nil {
		bundle.NetConns = string(out)
	}

	bundlePath := filepath.Join(evidenceRoot, bundleId+".json")
	data, _ := json.MarshalIndent(bundle, "", "  ")
	if err := os.WriteFile(bundlePath, data, 0600); err != nil {
		return bundle, fmt.Errorf("write evidence: %w", err)
	}

	return bundle, nil
}
