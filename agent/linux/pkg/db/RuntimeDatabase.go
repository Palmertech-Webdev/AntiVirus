package db

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	bucketEvents     = "events"
	bucketState      = "state"
	bucketQuarantine = "quarantine"
)

type RuntimeDatabase struct {
	db *bolt.DB
}

func Open(path string) (*RuntimeDatabase, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range []string{bucketEvents, bucketState, bucketQuarantine} {
			if _, err := tx.CreateBucketIfNotExists([]byte(bucket)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("create buckets: %w", err)
	}

	log.Printf("[RuntimeDatabase] Opened: %s", path)
	return &RuntimeDatabase{db: db}, nil
}

func (r *RuntimeDatabase) Close() {
	if r.db != nil {
		r.db.Close()
	}
}

// SetState persists an arbitrary key/value pair in the state bucket.
func (r *RuntimeDatabase) SetState(key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return r.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketState)).Put([]byte(key), data)
	})
}

// GetState retrieves a value from the state bucket.
func (r *RuntimeDatabase) GetState(key string, dest interface{}) error {
	return r.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(bucketState)).Get([]byte(key))
		if v == nil {
			return fmt.Errorf("key not found: %s", key)
		}
		return json.Unmarshal(v, dest)
	})
}

// RecordEvent appends a telemetry event to the events bucket (keyed by timestamp+nonce).
func (r *RuntimeDatabase) RecordEvent(event interface{}) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%d", time.Now().UnixNano())
	return r.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketEvents)).Put([]byte(key), data)
	})
}

// RecordQuarantineEntry logs a quarantine action.
func (r *RuntimeDatabase) RecordQuarantineEntry(entry interface{}) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%d", time.Now().UnixNano())
	return r.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketQuarantine)).Put([]byte(key), data)
	})
}

// AllQuarantineEntries returns all quarantined file records.
func (r *RuntimeDatabase) AllQuarantineEntries() ([]json.RawMessage, error) {
	var results []json.RawMessage
	err := r.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketQuarantine)).ForEach(func(k, v []byte) error {
			cp := make([]byte, len(v))
			copy(cp, v)
			results = append(results, cp)
			return nil
		})
	})
	return results, err
}
