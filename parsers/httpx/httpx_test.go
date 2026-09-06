// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package httpx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

func TestParseJSONLines_Simple(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "simple.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, quality, err := parseJSONLines(raw)
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Errorf("quality = %d; want STRUCTURED", quality)
	}
	if got, want := len(disc.Endpoints), 2; got != want {
		t.Fatalf("endpoints = %d; want %d", got, want)
	}
	if disc.Endpoints[0].Url != "http://scanme.nmap.org" {
		t.Errorf("endpoint[0].url = %q; want http://scanme.nmap.org", disc.Endpoints[0].Url)
	}
	if disc.Endpoints[0].StatusCode == nil || *disc.Endpoints[0].StatusCode != 200 {
		t.Errorf("endpoint[0].status_code = %v; want 200", disc.Endpoints[0].StatusCode)
	}
	if disc.Endpoints[0].Title == nil || *disc.Endpoints[0].Title != "Go ahead and ScanMe!" {
		t.Errorf("endpoint[0].title = %v", disc.Endpoints[0].Title)
	}

	// Technologies: Apache, Ubuntu (endpoint 1) + Apache (endpoint 2) = 3.
	if got := len(disc.Technologies); got != 3 {
		t.Errorf("technologies = %d; want 3", got)
	}
	// Each Endpoint must point at a Service.
	for _, e := range disc.Endpoints {
		if e.ServiceId == "" {
			t.Errorf("endpoint %q has empty service_id", e.Url)
		}
	}
}

func TestParseJSONLines_EmptyInput(t *testing.T) {
	_, quality, err := parseJSONLines(nil)
	if err != nil {
		t.Fatalf("empty input returned error: %v", err)
	}
	if quality != registry.ParseQualityRaw {
		t.Errorf("quality = %d; want RAW (3)", quality)
	}
}

func TestParseJSONLines_MalformedLine(t *testing.T) {
	// Non-JSON lines (no leading '{') are skipped silently — that's
	// deliberate so stray log output doesn't poison the whole scan. A
	// JSON-looking-but-malformed line must surface as PARTIAL + error.
	raw := []byte(`{"url":"http://a","status_code":200}` + "\n{\"url\": truncated")
	_, quality, err := parseJSONLines(raw)
	if err == nil {
		t.Fatal("expected error on JSON-but-malformed line")
	}
	if quality != registry.ParseQualityPartial {
		t.Errorf("quality = %d; want PARTIAL (2)", quality)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if _, ok := registry.Lookup(toolName); !ok {
		t.Fatalf("registry.Lookup(%q) = false", toolName)
	}
}
