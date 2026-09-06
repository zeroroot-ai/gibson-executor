// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package masscan

import (
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// TestPolicy_DropsOutputFile asserts the canonical injection
// `-oN /etc/passwd` is rejected. The runner pins -oJ - so any -o* flag is
// a guaranteed misuse signal.
func TestPolicy_DropsOutputFile(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	_, dropped, err := policy.ApplyArgs([]string{"-oN", "/etc/passwd"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Flag != "-oN" {
		t.Fatalf("expected -oN dropped, got %+v", dropped)
	}
}

func TestPolicy_AllowsRateAndBanners(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	out, dropped, err := policy.ApplyArgs([]string{"--rate", "10000", "--banners"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("expected 0 dropped, got %v", dropped)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 args, got %v", out)
	}
}
