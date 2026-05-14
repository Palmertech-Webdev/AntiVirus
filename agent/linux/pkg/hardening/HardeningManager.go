package hardening

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

type HardeningCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Current string `json:"current,omitempty"`
	Message string `json:"message,omitempty"`
}

type HardeningManager struct{}

func NewHardeningManager() *HardeningManager {
	return &HardeningManager{}
}

// RunChecks evaluates key kernel hardening parameters.
func (h *HardeningManager) RunChecks() []HardeningCheck {
	checks := []struct {
		name     string
		sysctlFn func() HardeningCheck
	}{
		{"kernel.randomize_va_space", h.checkASLR},
		{"kernel.dmesg_restrict", h.checkDmesgRestrict},
		{"kernel.kptr_restrict", h.checkKptrRestrict},
		{"fs.protected_hardlinks", h.checkHardlinks},
		{"fs.protected_symlinks", h.checkSymlinks},
		{"net.ipv4.conf.all.rp_filter", h.checkRPFilter},
	}

	var results []HardeningCheck
	for _, c := range checks {
		result := c.sysctlFn()
		result.Name = c.name
		results = append(results, result)
		if result.Passed {
			log.Printf("[Hardening] ✅ %s = %s", c.name, result.Current)
		} else {
			log.Printf("[Hardening] ❌ %s: %s", c.name, result.Message)
		}
	}
	return results
}

func readSysctl(key string) (string, error) {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (h *HardeningManager) checkASLR() HardeningCheck {
	val, err := readSysctl("kernel.randomize_va_space")
	if err != nil {
		return HardeningCheck{Passed: false, Message: fmt.Sprintf("read failed: %v", err)}
	}
	n, _ := strconv.Atoi(val)
	return HardeningCheck{Passed: n == 2, Current: val, Message: "Expected 2 (full ASLR)"}
}

func (h *HardeningManager) checkDmesgRestrict() HardeningCheck {
	val, err := readSysctl("kernel.dmesg_restrict")
	if err != nil {
		return HardeningCheck{Passed: false, Message: fmt.Sprintf("read failed: %v", err)}
	}
	return HardeningCheck{Passed: val == "1", Current: val, Message: "Expected 1"}
}

func (h *HardeningManager) checkKptrRestrict() HardeningCheck {
	val, err := readSysctl("kernel.kptr_restrict")
	if err != nil {
		return HardeningCheck{Passed: false, Message: fmt.Sprintf("read failed: %v", err)}
	}
	return HardeningCheck{Passed: val == "2", Current: val, Message: "Expected 2"}
}

func (h *HardeningManager) checkHardlinks() HardeningCheck {
	val, err := readSysctl("fs.protected_hardlinks")
	if err != nil {
		return HardeningCheck{Passed: false, Message: fmt.Sprintf("read failed: %v", err)}
	}
	return HardeningCheck{Passed: val == "1", Current: val, Message: "Expected 1"}
}

func (h *HardeningManager) checkSymlinks() HardeningCheck {
	val, err := readSysctl("fs.protected_symlinks")
	if err != nil {
		return HardeningCheck{Passed: false, Message: fmt.Sprintf("read failed: %v", err)}
	}
	return HardeningCheck{Passed: val == "1", Current: val, Message: "Expected 1"}
}

func (h *HardeningManager) checkRPFilter() HardeningCheck {
	val, err := readSysctl("net.ipv4.conf.all.rp_filter")
	if err != nil {
		return HardeningCheck{Passed: false, Message: fmt.Sprintf("read failed: %v", err)}
	}
	return HardeningCheck{Passed: val == "1", Current: val, Message: "Expected 1 (strict)"}
}
