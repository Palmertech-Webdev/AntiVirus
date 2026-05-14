package remediation

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/AntiVirus/agent/linux/pkg/quarantine"
)

type RemediationAction string

const (
	ActionKillProcess RemediationAction = "KillProcess"
	ActionQuarantine  RemediationAction = "Quarantine"
	ActionDelete      RemediationAction = "Delete"
	ActionAlert       RemediationAction = "Alert"
)

type RemediationRequest struct {
	Pid      uint32
	FilePath string
	Reason   string
	Actions  []RemediationAction
}

type RemediationResult struct {
	Success bool
	Actions []string
	Errors  []string
}

type RemediationEngine struct {
	quarantine *quarantine.QuarantineStore
}

func NewRemediationEngine(q *quarantine.QuarantineStore) *RemediationEngine {
	return &RemediationEngine{quarantine: q}
}

func (e *RemediationEngine) Remediate(req RemediationRequest) RemediationResult {
	result := RemediationResult{Success: true}

	for _, action := range req.Actions {
		switch action {
		case ActionKillProcess:
			if err := e.killProcess(req.Pid); err != nil {
				msg := fmt.Sprintf("KillProcess PID %d failed: %v", req.Pid, err)
				log.Println("[RemediationEngine]", msg)
				result.Errors = append(result.Errors, msg)
				result.Success = false
			} else {
				result.Actions = append(result.Actions, fmt.Sprintf("Killed PID %d", req.Pid))
			}

		case ActionQuarantine:
			if req.FilePath == "" {
				continue
			}
			entry, err := e.quarantine.Quarantine(req.FilePath, req.Reason)
			if err != nil {
				msg := fmt.Sprintf("Quarantine %s failed: %v", req.FilePath, err)
				log.Println("[RemediationEngine]", msg)
				result.Errors = append(result.Errors, msg)
				result.Success = false
			} else {
				result.Actions = append(result.Actions, fmt.Sprintf("Quarantined %s -> %s", req.FilePath, entry.QuarantinePath))
			}

		case ActionDelete:
			if req.FilePath == "" {
				continue
			}
			if err := os.Remove(req.FilePath); err != nil {
				msg := fmt.Sprintf("Delete %s failed: %v", req.FilePath, err)
				log.Println("[RemediationEngine]", msg)
				result.Errors = append(result.Errors, msg)
				result.Success = false
			} else {
				result.Actions = append(result.Actions, fmt.Sprintf("Deleted %s", req.FilePath))
			}

		case ActionAlert:
			log.Printf("[RemediationEngine][ALERT] %s | File: %s | PID: %d", req.Reason, req.FilePath, req.Pid)
			result.Actions = append(result.Actions, "Alert logged")
		}
	}

	return result
}

func (e *RemediationEngine) killProcess(pid uint32) error {
	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		return err
	}
	log.Printf("[RemediationEngine] Sent SIGKILL to PID %d", pid)
	return nil
}
