package collectors

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Collector reads cloud or Kubernetes audit records, validates them, and
// publishes CanonicalEvent JSON. It does not perform security reasoning.
type Collector struct {
	TenantID string
	Source   string
	Retries  int
}

type HealthReport struct {
	OK        bool   `json:"ok"`
	Source    string `json:"source"`
	Collected int    `json:"collected"`
	Rejected  int    `json:"rejected"`
	Retries   int    `json:"retries"`
	Message   string `json:"message"`
}

func (c Collector) CollectAudit(raw json.RawMessage) (CanonicalEvent, error) {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return CanonicalEvent{}, fmt.Errorf("invalid audit json: %w", err)
	}
	verb, _ := payload["verb"].(string)
	if verb == "" {
		if api, ok := payload["apiVersion"].(string); ok && api != "" {
			verb = "watch"
		}
	}
	eventType := verb
	if eventType == "" {
		if ev, ok := payload["eventName"].(string); ok {
			eventType = ev
		}
	}
	if eventType == "" {
		eventType = "audit"
	}
	category := "cloud"
	if strings.Contains(strings.ToLower(c.Source), "kube") {
		category = "kubernetes"
	}
	return Normalize(c.TenantID, c.Source, eventType, category, payload)
}

func (c Collector) CollectReader(reader io.Reader) ([]CanonicalEvent, HealthReport, error) {
	decoder := json.NewDecoder(reader)
	var events []CanonicalEvent
	rejected := 0
	retries := 0
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return events, HealthReport{OK: false, Source: c.Source, Message: err.Error()}, err
		}
		event, err := c.CollectAudit(raw)
		if err != nil {
			if retries < c.Retries {
				retries++
				event, err = c.CollectAudit(raw)
			}
			if err != nil {
				rejected++
				continue
			}
		}
		events = append(events, event)
	}
	report := HealthReport{
		OK:        rejected == 0,
		Source:    c.Source,
		Collected: len(events),
		Rejected:  rejected,
		Retries:   retries,
		Message:   "collect-validate-normalize",
	}
	return events, report, nil
}

func PublishJSON(writer io.Writer, events []CanonicalEvent) error {
	encoder := json.NewEncoder(writer)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	return nil
}

func RunFileCollector(path, tenantID, source string) (HealthReport, error) {
	file, err := os.Open(path)
	if err != nil {
		return HealthReport{OK: false, Source: source, Message: err.Error()}, err
	}
	defer file.Close()
	collector := Collector{TenantID: tenantID, Source: source, Retries: 1}
	events, report, err := collector.CollectReader(file)
	if err != nil {
		return report, err
	}
	if err := PublishJSON(os.Stdout, events); err != nil {
		report.OK = false
		report.Message = err.Error()
		return report, err
	}
	report.Message = fmt.Sprintf("published %d events at %s", len(events), time.Now().UTC().Format(time.RFC3339))
	return report, nil
}
