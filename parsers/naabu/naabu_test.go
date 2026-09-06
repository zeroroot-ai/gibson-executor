// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package naabu

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
	disc, quality, err := parseJSONLines(raw)
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Errorf("quality = %d; want STRUCTURED", quality)
	}
	// Same IP across 3 ports → 1 host, 3 ports.
	if got := len(disc.Hosts); got != 1 {
		t.Fatalf("hosts = %d; want 1 (dedup by IP)", got)
	}
	if got := len(disc.Ports); got != 3 {
		t.Fatalf("ports = %d; want 3", got)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if _, ok := registry.Lookup(toolName); !ok {
		t.Fatalf("registry.Lookup(%q) = false", toolName)
	}
}
