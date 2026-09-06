// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package nmap

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// TestPolicy_DropsOutputFile_ON asserts that the canonical injection
// `-oN /etc/passwd` is rejected: the runner already pins -oX -, so allowing
// caller-supplied output flags is an arbitrary-file-write hole.
func TestPolicy_DropsOutputFile_ON(t *testing.T) {
	p, ok := registry.LookupOpenArgsPolicy(toolName)
	if !ok {
		t.Fatal("nmap open policy not registered")
	}

	out, dropped, err := policy.ApplyOpen([]string{"-oN", "/etc/passwd", "-sV"}, p)
	if err != nil {
		t.Fatalf("unexpected validator error: %v", err)
	}

	// -sV is allowed; -oN must be dropped.
	if len(dropped) != 1 || dropped[0].Flag != "-oN" {
		t.Fatalf("expected -oN dropped, got %+v", dropped)
	}
	if dropped[0].Value != "/etc/passwd" {
		t.Fatalf("expected -oN value /etc/passwd, got %q", dropped[0].Value)
	}
	if !strings.Contains(dropped[0].Reason, "writes a caller-named file") {
		t.Errorf("reason = %q; want the capability class that refused it", dropped[0].Reason)
	}
	// Filtered argv must contain -sV but not -oN.
	if len(out) != 1 || out[0] != "-sV" {
		t.Fatalf("expected only [-sV] after filter, got %v", out)
	}
}

// TestPolicy_AllowsSafeFlags asserts the documented happy path.
func TestPolicy_AllowsSafeFlags(t *testing.T) {
	p, _ := registry.LookupOpenArgsPolicy(toolName)
	out, dropped, err := policy.ApplyOpen(
		[]string{"-sV", "-Pn", "-T4", "--top-ports", "100"},
		p,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("expected nothing dropped, got %v", dropped)
	}
	if len(out) != 5 {
		t.Fatalf("expected 5 allowed, got %d (%v)", len(out), out)
	}
}

// TestPolicy_AllowsUnenumeratedFlags is the point of the inversion: a flag
// nobody transcribed still works. --stats-every is the progress printer that
// makes a long scan watchable on the console; the old allowlist did not name
// it, and it is not even in `nmap -h`, so a correct mission failed for a
// reason no author could see.
func TestPolicy_AllowsUnenumeratedFlags(t *testing.T) {
	p, _ := registry.LookupOpenArgsPolicy(toolName)
	out, dropped, err := policy.ApplyOpen(
		[]string{"-vv", "--stats-every", "3s", "--version-all", "--traceroute"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("expected nothing dropped, got %v", dropped)
	}
	joined := strings.Join(out, " ")
	for _, want := range []string{"--stats-every 3s", "--version-all", "--traceroute", "-vv"} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv %q is missing %q", joined, want)
		}
	}
}

// TestPolicy_DeniesEveryCapabilityClass asserts one representative flag per
// class still cannot reach the argv. These are the reasons the policy exists;
// everything else is allowed.
func TestPolicy_DeniesEveryCapabilityClass(t *testing.T) {
	p, _ := registry.LookupOpenArgsPolicy(toolName)
	for _, tc := range []struct {
		flag, class string
	}{
		{"-oN", "writes a caller-named file"},
		{"-iL", "reads a caller-named file"},
		{"--script", "executes caller-supplied scripts or plugins"},
		{"-iR", "involves a machine other than the declared target"},
		{"--send-eth", "forges packets or alters privilege"},
	} {
		out, dropped, err := policy.ApplyOpen([]string{tc.flag, "value"}, p)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.flag, err)
		}
		if len(dropped) != 1 || dropped[0].Flag != tc.flag {
			t.Fatalf("%s: expected it dropped, got out=%v dropped=%v", tc.flag, out, dropped)
		}
		if dropped[0].Reason != tc.class {
			t.Errorf("%s: reason = %q; want %q", tc.flag, dropped[0].Reason, tc.class)
		}
		if len(out) != 0 {
			t.Errorf("%s: argv should be empty, got %v", tc.flag, out)
		}
	}
}

// TestPolicy_ValuedFlagsKeepTheirValidator asserts "allow everything" did not
// loosen the value checks: -p still cannot carry a path.
func TestPolicy_ValuedFlagsKeepTheirValidator(t *testing.T) {
	p, _ := registry.LookupOpenArgsPolicy(toolName)
	if _, _, err := policy.ApplyOpen([]string{"-p", "/etc/passwd"}, p); err == nil {
		t.Fatal("-p accepted a path; PortSpec must reject it")
	}
	if _, _, err := policy.ApplyOpen([]string{"-p", "1-65535"}, p); err != nil {
		t.Fatalf("-p rejected a valid port range: %v", err)
	}
}
