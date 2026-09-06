// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package nuclei

import (
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// TestPolicy_ConstrainsTemplatesFlag asserts that -t / --templates can
// only name a template relative to the runner's pinned template
// directory. The flag used to be absent from the allowlist, which read as
// a denial but was not one: the parser piped req.Options["templates"]
// into -t with no validator at all. It is listed now, so both the args
// path and the options path meet the same validator.
func TestPolicy_ConstrainsTemplatesFlag(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)

	for _, bad := range []string{"/tmp/malicious", "../../etc/passwd", "~/evil", "cves;id"} {
		if _, _, err := policy.ApplyArgs([]string{"-t", bad}, p); err == nil {
			t.Errorf("policy accepted -t %q", bad)
		}
	}

	out, dropped, err := policy.ApplyArgs([]string{"-t", "cves/2023", "-severity", "high"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("expected nothing dropped, got %+v", dropped)
	}
	want := []string{"-t", "cves/2023", "-severity", "high"}
	if len(out) != len(want) {
		t.Fatalf("out = %v; want %v", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("out = %v; want %v", out, want)
		}
	}
}

// TestPolicy_RejectsUnknownSeverity asserts the severity filter is an
// enum, not a free string.
func TestPolicy_RejectsUnknownSeverity(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	if _, _, err := policy.ApplyArgs([]string{"-severity", "catastrophic"}, p); err == nil {
		t.Fatal("policy accepted an unknown severity")
	}
}

// TestPolicy_DropsOutputFlag asserts -output is rejected.
func TestPolicy_DropsOutputFlag(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	_, dropped, err := policy.ApplyArgs([]string{"-output", "/etc/passwd"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Flag != "-output" {
		t.Fatalf("expected -output dropped, got %+v", dropped)
	}
}
