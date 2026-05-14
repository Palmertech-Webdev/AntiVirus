package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type ControlPlaneClient struct {
	backendURL string
	httpClient *http.Client
}

func NewControlPlaneClient(backendURL string) *ControlPlaneClient {
	return &ControlPlaneClient{
		backendURL: backendURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *ControlPlaneClient) SendEvent(payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	resp, err := c.httpClient.Post(c.backendURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("http post error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backend returned status %d", resp.StatusCode)
	}
	return nil
}

func (c *ControlPlaneClient) SendBatch(events []interface{}) {
	for _, event := range events {
		if err := c.SendEvent(event); err != nil {
			log.Printf("[ControlPlane] Error sending event: %v", err)
		}
	}
}
