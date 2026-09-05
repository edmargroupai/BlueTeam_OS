package collectors

import (
	"strings"
	"testing"
)

func TestCollectKubernetesAudit(t *testing.T) {
	raw := `{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"create","objectRef":{"resource":"secrets","namespace":"prod"}}`
	collector := Collector{TenantID: "ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Source: "kube-apiserver", Retries: 1}
	event, err := collector.CollectAudit([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if event.Category != "kubernetes" {
		t.Fatalf("category %s", event.Category)
	}
	if event.EventType != "create" {
		t.Fatalf("event type %s", event.EventType)
	}
	if event.SchemaVersion != "1.0.0" {
		t.Fatalf("schema %s", event.SchemaVersion)
	}
}

func TestCollectReaderHealth(t *testing.T) {
	body := `{"verb":"get","objectRef":{"resource":"pods"}}
{"verb":"update","objectRef":{"resource":"deployments"}}
`
	collector := Collector{TenantID: "ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Source: "kube-apiserver", Retries: 1}
	events, report, err := collector.CollectReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || !report.OK {
		t.Fatalf("events=%d report=%+v", len(events), report)
	}
}

func TestRejectsBadTenant(t *testing.T) {
	collector := Collector{TenantID: "nope", Source: "kube-apiserver"}
	_, err := collector.CollectAudit([]byte(`{"verb":"get"}`))
	if err == nil {
		t.Fatal("expected tenant validation error")
	}
}
