// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package masscan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

func TestParseJSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "simple.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, quality, err := parseJSON(raw)
	if err != nil {
		t.Fatalf("parseJSON: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Errorf("quality = %d; want STRUCTURED", quality)
	}
	// 2 distinct IPs → 2 hosts.
	if got := len(disc.Hosts); got != 2 {
		t.Fatalf("hosts = %d; want 2", got)
	}
	// 3 total port entries.
	if got := len(disc.Ports); got != 3 {
		t.Fatalf("ports = %d; want 3", got)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if _, ok := registry.Lookup(toolName); !ok {
		t.Fatalf("registry.Lookup(%q) = false", toolName)
	}
}
