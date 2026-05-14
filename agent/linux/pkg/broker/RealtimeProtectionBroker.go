package broker

import (
	"fmt"
	"log"
	"time"

	"github.com/AntiVirus/agent/linux/pkg/client"
	"github.com/AntiVirus/agent/linux/pkg/engine"
	"github.com/AntiVirus/agent/linux/pkg/inventory"
	"github.com/AntiVirus/agent/linux/pkg/telemetry"
)

// BehaviorEvent is the internal cross-subsystem event type.
type BehaviorEvent struct {
	EventType   string
	Pid         uint32
	Uid         uint32
	ProcessName string
	CommandLine string
	DestIP      string
	DestPort    uint16
	FilePath    string
}

type RealtimeProtectionBroker struct {
	deviceId  string
	queue     *telemetry.TelemetryQueueStore
	scanner   *engine.ScanEngine
	inventory *inventory.ProcessInventory
	client    *client.ControlPlaneClient
}

func NewRealtimeProtectionBroker(
	deviceId string,
	scanner *engine.ScanEngine,
	inv *inventory.ProcessInventory,
	planeClient *client.ControlPlaneClient,
) *RealtimeProtectionBroker {
	b := &RealtimeProtectionBroker{
		deviceId:  deviceId,
		scanner:   scanner,
		inventory: inv,
		client:    planeClient,
	}

	b.queue = telemetry.NewTelemetryQueueStore(50, b.flushToBackend)
	return b
}

func (b *RealtimeProtectionBroker) ObserveEvent(event BehaviorEvent) {
	switch event.EventType {
	case "ProcessStart":
		b.inventory.AddProcess(inventory.ProcessContext{
			Pid:         event.Pid,
			ProcessName: event.ProcessName,
			CommandLine: event.CommandLine,
			Uid:         event.Uid,
		})

		// YARA scan on new process
		if matched, rules := b.scanner.ScanFile(event.CommandLine); matched {
			log.Printf("[Broker][YARA] Match on process %s: %v", event.ProcessName, rules)
		}
	}

	te := b.buildTelemetryEvent(event)
	b.queue.Enqueue(te)
}

func (b *RealtimeProtectionBroker) buildTelemetryEvent(event BehaviorEvent) telemetry.TelemetryEvent {
	te := telemetry.TelemetryEvent{
		EventId:   fmt.Sprintf("%d", time.Now().UnixNano()),
		DeviceId:  b.deviceId,
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		EventType: event.EventType,
	}

	switch event.EventType {
	case "ProcessStart":
		te.Payload = map[string]interface{}{
			"eventType":   "ProcessStart",
			"processName": event.ProcessName,
			"pid":         event.Pid,
			"commandLine": event.CommandLine,
		}
	case "NetworkConnect":
		te.Payload = map[string]interface{}{
			"eventType":       "NetworkConnect",
			"processName":     event.ProcessName,
			"pid":             event.Pid,
			"destinationIp":   event.DestIP,
			"destinationPort": event.DestPort,
			"protocol":        "tcp4",
		}
	case "FileWrite":
		te.Payload = map[string]interface{}{
			"eventType":   "FileWrite",
			"processName": event.ProcessName,
			"pid":         event.Pid,
			"filePath":    event.FilePath,
		}
	}

	return te
}

func (b *RealtimeProtectionBroker) flushToBackend(events []telemetry.TelemetryEvent) {
	for _, event := range events {
		if err := b.client.SendEvent(event); err != nil {
			log.Printf("[Broker] Failed to send telemetry: %v", err)
		}
	}
}

func (b *RealtimeProtectionBroker) FlushAll() {
	b.queue.Flush()
}
