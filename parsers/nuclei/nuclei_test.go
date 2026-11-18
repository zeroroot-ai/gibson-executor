// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package nuclei

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
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
	if got, want := len(disc.Findings), 3; got != want {
		t.Fatalf("findings = %d; want %d", got, want)
	}

	crit := disc.Findings[0]
	if crit.Title != "Apache HTTPD RCE via mod_whatever" {
		t.Errorf("finding[0].title = %q", crit.Title)
	}
	if crit.Severity != "critical" {
		t.Errorf("finding[0].severity = %q; want critical", crit.Severity)
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

// TestParseJSONLines_HostIsTheFindingsParent covers nucleiEvent.Host, which was
// also decoded and dropped: a finding named a template and a matched URL but
// never said which host it was about in a field the graph can traverse.
func TestParseJSONLines_HostIsTheFindingsParent(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "simple.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, _, err := parseJSONLines(raw)
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	for i, f := range disc.Findings {
		if f.GetParentId() != "http://scanme.nmap.org" {
			t.Errorf("finding[%d].parent_id = %q; want the nuclei host", i, f.GetParentId())
		}
	}
}

// TestDescribe_MemoryHeadroom locks the sandbox memory the daemon gives nuclei.
// 1Gi OOM-killed nuclei in the Firecracker guest on staging (gibson#1356), so
// the hint must not fall back below 2Gi.
func TestDescribe_MemoryHeadroom(t *testing.T) {
	got := (&parser{}).Describe().Resources.Memory
	if got != "2Gi" {
		t.Fatalf("nuclei sandbox memory hint = %q, want 2Gi (gibson#1356)", got)
	}
}

// TestExecute_RaisesAddressSpaceCeiling proves nuclei lifts RLIMIT_AS above the
// 2 GiB default, like trivy, so its Go arena reservation does not fail at
// startup. The override is a max, so it only ever raises the ceiling.
func TestExecute_RaisesAddressSpaceCeiling(t *testing.T) {
	if nucleiAddressSpaceBytes <= sandbox.DefaultConfig().MemoryBytes {
		t.Fatalf("nucleiAddressSpaceBytes %d must exceed the default RLIMIT_AS %d", nucleiAddressSpaceBytes, sandbox.DefaultConfig().MemoryBytes)
	}
}
