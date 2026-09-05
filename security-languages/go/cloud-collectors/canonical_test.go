package collectors

import "testing"

func TestNormalizeRejectsMissingTenant(t *testing.T) {
	_, err := Normalize("bad", "aws", "AssumeRole", "cloud", nil)
	if err == nil {
		t.Fatal("expected tenant validation error")
	}
}

func TestNormalizeEmitsCanonicalVersion(t *testing.T) {
	event, err := Normalize("ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "aws-cloudtrail", "AssumeRole", "cloud", nil)
	if err != nil {
		t.Fatal(err)
	}
	if event.SchemaVersion != "1.0.0" {
		t.Fatalf("schema %s", event.SchemaVersion)
	}
}
