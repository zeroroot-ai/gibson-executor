// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dnsx

import (
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

func TestPolicy_DropsOutputFlag(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	_, dropped, err := policy.ApplyArgs([]string{"-o", "/etc/passwd"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Flag != "-o" {
		t.Fatalf("expected -o dropped, got %+v", dropped)
	}
}

func TestPolicy_AllowsRecordSelectors(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	out, _, err := policy.ApplyArgs([]string{"-cname", "-mx", "-txt"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 args, got %v", out)
	}
}

// TestPolicy_ResolverAcceptsIPLiterals pins that -r takes a comma-separated
// list of resolver addresses, with or without a port.
func TestPolicy_ResolverAcceptsIPLiterals(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	for _, v := range []string{"127.0.0.11", "127.0.0.11:53", "1.1.1.1,8.8.8.8:53", "[::1]:5353", "::1"} {
		out, _, err := policy.ApplyArgs([]string{"-r", v}, p)
		if err != nil {
			t.Fatalf("-r %q rejected: %v", v, err)
		}
		if len(out) != 2 || out[1] != v {
			t.Fatalf("-r %q: argv = %v", v, out)
		}
	}
}

// TestPolicy_ResolverRejectsHostnamesAndJunk pins that a resolver named by
// hostname, an empty entry, or a bad port never reaches dnsx.
func TestPolicy_ResolverRejectsHostnamesAndJunk(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	for _, v := range []string{"", "dns.google", "dns.google:53", "1.1.1.1,", "1.1.1.1:0", "1.1.1.1:70000", "1.1.1.1;id"} {
		if _, _, err := policy.ApplyArgs([]string{"-r", v}, p); err == nil {
			t.Fatalf("-r %q was accepted", v)
		}
	}
}
