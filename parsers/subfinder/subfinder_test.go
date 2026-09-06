// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package subfinder

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

func TestParseJSONLines(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "simple.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, quality, err := parseJSONLines(raw, "example.com")
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Errorf("quality = %d; want STRUCTURED", quality)
	}
	if got := len(disc.Domains); got != 1 {
		t.Fatalf("domains = %d; want 1 root", got)
	}
	if got := len(disc.Subdomains); got != 3 {
		t.Fatalf("subdomains = %d; want 3", got)
	}
	for _, s := range disc.Subdomains {
		if s.DomainId == "" {
			t.Errorf("subdomain %q has empty domain_id", s.Name)
		}
	}
}

func TestRegistryIntegration(t *testing.T) {
	if _, ok := registry.Lookup(toolName); !ok {
		t.Fatalf("registry.Lookup(%q) = false", toolName)
	}
}
