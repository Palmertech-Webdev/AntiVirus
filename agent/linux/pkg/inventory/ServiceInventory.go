package inventory

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

type ServiceRecord struct {
	Name        string `json:"name"`
	LoadState   string `json:"loadState"`
	ActiveState string `json:"activeState"`
	Description string `json:"description"`
}

type ServiceInventory struct {
	lastSnapshot []ServiceRecord
	snapshotAt   time.Time
}

func NewServiceInventory() *ServiceInventory {
	return &ServiceInventory{}
}

// Snapshot queries systemd for all loaded units and returns the current service list.
func (si *ServiceInventory) Snapshot() ([]ServiceRecord, error) {
	out, err := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager").Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl: %w", err)
	}

	var records []ServiceRecord
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		records = append(records, ServiceRecord{
			Name:        fields[0],
			LoadState:   fields[1],
			ActiveState: fields[2],
			Description: strings.Join(fields[4:], " "),
		})
	}

	si.lastSnapshot = records
	si.snapshotAt = time.Now()
	log.Printf("[ServiceInventory] Snapshot: %d services", len(records))
	return records, nil
}

// Delta returns newly appeared and disappeared services since the last snapshot.
func (si *ServiceInventory) Delta() (added, removed []ServiceRecord, err error) {
	previous := si.lastSnapshot
	current, err := si.Snapshot()
	if err != nil {
		return nil, nil, err
	}

	prev := make(map[string]ServiceRecord)
	for _, s := range previous {
		prev[s.Name] = s
	}
	curr := make(map[string]ServiceRecord)
	for _, s := range current {
		curr[s.Name] = s
	}

	for name, svc := range curr {
		if _, exists := prev[name]; !exists {
			added = append(added, svc)
		}
	}
	for name, svc := range prev {
		if _, exists := curr[name]; !exists {
			removed = append(removed, svc)
		}
	}
	return
}
