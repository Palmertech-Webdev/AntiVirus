package telemetry

import (
	"log"
	"sync"
)

type TelemetryEvent struct {
	EventId   string      `json:"eventId"`
	DeviceId  string      `json:"deviceId"`
	Timestamp string      `json:"timestamp"`
	EventType string      `json:"eventType"`
	Payload   interface{} `json:"payload"`
}

type TelemetryQueueStore struct {
	mu      sync.Mutex
	queue   []TelemetryEvent
	maxSize int
	flushFn func(events []TelemetryEvent)
}

func NewTelemetryQueueStore(maxSize int, flushFn func(events []TelemetryEvent)) *TelemetryQueueStore {
	return &TelemetryQueueStore{
		queue:   make([]TelemetryEvent, 0, maxSize),
		maxSize: maxSize,
		flushFn: flushFn,
	}
}

func (q *TelemetryQueueStore) Enqueue(event TelemetryEvent) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.queue = append(q.queue, event)
	log.Printf("[TelemetryQueue] Enqueued %s event. Queue depth: %d", event.EventType, len(q.queue))

	if len(q.queue) >= q.maxSize {
		q.flush()
	}
}

func (q *TelemetryQueueStore) Flush() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.flush()
}

// flush assumes the caller holds the mutex.
func (q *TelemetryQueueStore) flush() {
	if len(q.queue) == 0 {
		return
	}
	batch := make([]TelemetryEvent, len(q.queue))
	copy(batch, q.queue)
	q.queue = q.queue[:0]
	go q.flushFn(batch)
}
