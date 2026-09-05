package collectors

import (
	"encoding/json"
	"fmt"
	"time"
)

type CanonicalEvent struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	Timestamp     string `json:"timestamp"`
	IngestedAt    string `json:"ingested_at"`
	Source        string `json:"source"`
	SourceType    string `json:"source_type"`
	EventType     string `json:"event_type"`
	Category      string `json:"category"`
	SchemaVersion string `json:"schema_version"`
	RawEvent      any    `json:"raw_event"`
}

func Normalize(tenantID, source, eventType, category string, raw any) (CanonicalEvent, error) {
	if len(tenantID) < 4 || tenantID[:4] != "ten_" {
		return CanonicalEvent{}, fmt.Errorf("tenant_id must use ten_ prefix")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return CanonicalEvent{
		ID:            fmt.Sprintf("evt_go_%d", time.Now().UTC().UnixNano()),
		TenantID:      tenantID,
		Timestamp:     now,
		IngestedAt:    now,
		Source:        source,
		SourceType:    "collector",
		EventType:     eventType,
		Category:      category,
		SchemaVersion: "1.0.0",
		RawEvent:      raw,
	}, nil
}

func Encode(event CanonicalEvent) ([]byte, error) {
	return json.Marshal(event)
}
