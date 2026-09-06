// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package nuclei

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

func TestParseJSONLines_TwoFindings(t *testing.T) {
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
	if got, want := len(disc.Findings), 2; got != want {
		t.Fatalf("findings = %d; want %d", got, want)
	}

	crit := disc.Findings[0]
	if crit.Title != "Apache HTTPD RCE via mod_whatever" {
		t.Errorf("finding[0].title = %q", crit.Title)
	}
	if crit.Severity != "critical" {
		t.Errorf("finding[0].severity = %q; want critical", crit.Severity)
	}
	if crit.CvssScore == nil || *crit.CvssScore != 9.8 {
		t.Errorf("finding[0].cvss_score = %v; want 9.8", crit.CvssScore)
	}
	if crit.CveIds == nil || *crit.CveIds != "CVE-2023-12345" {
		t.Errorf("finding[0].cve_ids = %v", crit.CveIds)
	}

	info := disc.Findings[1]
	if info.Severity != "info" {
		t.Errorf("finding[1].severity = %q; want info", info.Severity)
	}
}

func TestParseJSONLines_EmptyCleanRun(t *testing.T) {
	// A silent success from nuclei is meaningful: "scanned, no findings" is
	// still a structured result. Confirm quality reports STRUCTURED, not RAW.
	_, quality, err := parseJSONLines(nil)
	if err != nil {
		t.Fatalf("error on empty input: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Errorf("quality = %d; want STRUCTURED (clean run, zero findings)", quality)
	}
}

func TestNormaliseSeverity(t *testing.T) {
	tests := map[string]string{
		"Critical":       "critical",
		"HIGH":           "high",
		"medium":         "medium",
		"low":            "low",
		"Info":           "info",
		"informational":  "info",
		"unknown":        "info",
		"":               "info",
		"unexpected-val": "unexpected-val",
	}
	for in, want := range tests {
		if got := normaliseSeverity(in); got != want {
			t.Errorf("normaliseSeverity(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestRegistryIntegration(t *testing.T) {
	if _, ok := registry.Lookup(toolName); !ok {
		t.Fatalf("registry.Lookup(%q) = false", toolName)
	}
}
