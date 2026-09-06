// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package naabu

import (
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

func TestPolicy_DropsOutputFlag(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	_, dropped, err := policy.ApplyArgs([]string{"-output", "/etc/passwd", "-rate", "100"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Flag != "-output" {
		t.Fatalf("expected -output dropped, got %+v", dropped)
	}
}

func TestPolicy_AllowsRateAndPorts(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	out, dropped, err := policy.ApplyArgs([]string{"-rate", "1000", "-p", "80,443"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("expected 0 dropped, got %v", dropped)
	}
	if len(out) != 4 {
		t.Fatalf("expected 4 args, got %v", out)
	}
}
