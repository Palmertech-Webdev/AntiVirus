package selftest

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

type TestResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

type SelfTestRunner struct {
	backendURL string
}

func NewSelfTestRunner(backendURL string) *SelfTestRunner {
	return &SelfTestRunner{backendURL: backendURL}
}

// RunAll executes all health checks and returns results.
func (s *SelfTestRunner) RunAll() []TestResult {
	tests := []struct {
		name string
		fn   func() (bool, string)
	}{
		{"backend_reachable", s.testBackend},
		{"running_as_root", s.testRoot},
		{"quarantine_dir_writable", s.testQuarantineDir},
		{"evidence_dir_writable", s.testEvidenceDir},
	}

	var results []TestResult
	for _, t := range tests {
		passed, msg := t.fn()
		results = append(results, TestResult{Name: t.name, Passed: passed, Message: msg})
		if passed {
			fmt.Printf("[SelfTest] ✅ %s\n", t.name)
		} else {
			fmt.Printf("[SelfTest] ❌ %s: %s\n", t.name, msg)
		}
	}
	return results
}

func (s *SelfTestRunner) testBackend() (bool, string) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(s.backendURL)
	if err != nil {
		return false, fmt.Sprintf("backend unreachable: %v", err)
	}
	resp.Body.Close()
	return true, ""
}

func (s *SelfTestRunner) testRoot() (bool, string) {
	if os.Getuid() != 0 {
		return false, "agent must run as root for eBPF"
	}
	return true, ""
}

func (s *SelfTestRunner) testQuarantineDir() (bool, string) {
	return testDirWritable("/var/lib/fenrir/quarantine")
}

func (s *SelfTestRunner) testEvidenceDir() (bool, string) {
	return testDirWritable("/var/lib/fenrir/evidence")
}

func testDirWritable(path string) (bool, string) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return false, fmt.Sprintf("cannot create %s: %v", path, err)
	}
	tmp := path + "/.fenrir_write_test"
	if err := os.WriteFile(tmp, []byte("ok"), 0600); err != nil {
		return false, fmt.Sprintf("not writable: %v", err)
	}
	os.Remove(tmp)
	return true, ""
}
