// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package nuclei

import (
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// TestBuildArgs_TargetRejections pins that a target which is not a scan
// subject never reaches the tool. Every entry here would otherwise be read
// as a flag, as several targets, or as a token the tool re-splits.
func TestBuildArgs_TargetRejections(t *testing.T) {
	for _, target := range []string{
		"-oN",                                   // reads as a flag
		"--config",                              // reads as a long flag
		"-",                                     // bare dash
		"https://example.com\nevil.example.com", // second target on a new line
		"https://example.com\x00",               // NUL byte
		"https://example.com evil.example.com",  // space splits the token
		"https://example.com;id",                // shell metacharacter
		"",                                      // absent
	} {
		if args, err := buildArgs(registry.ExecuteRequest{Target: target}); err == nil {
			t.Errorf("buildArgs accepted target %q, produced %v", target, args)
		}
	}
}

// TestBuildArgs_AcceptsValidTarget keeps the rejections above honest: a
// well-formed target still builds an argv.
func TestBuildArgs_AcceptsValidTarget(t *testing.T) {
	args, err := buildArgs(registry.ExecuteRequest{Target: "https://example.com"})
	if err != nil {
		t.Fatalf("buildArgs rejected a valid target: %v", err)
	}
	if len(args) == 0 {
		t.Fatal("buildArgs produced an empty argv")
	}
}

// TestBuildArgs_DisablesUpdateCheck pins that every nuclei invocation carries
// -disable-update-check (gibson-executor#395). The runtime sandbox has no
// egress except to the target, so without this flag nuclei tries to update its
// binary and templates on startup, fails, and aborts before it loads the
// bundled template set. The base shape -jsonl -silent -target stays intact.
func TestBuildArgs_DisablesUpdateCheck(t *testing.T) {
	args, err := buildArgs(registry.ExecuteRequest{Target: "https://example.com"})
	if err != nil {
		t.Fatalf("buildArgs rejected a valid target: %v", err)
	}
	has := func(flag string) bool {
		for _, a := range args {
			if a == flag {
				return true
			}
		}
		return false
	}
	for _, flag := range []string{"-disable-update-check", "-jsonl", "-silent", "-target"} {
		if !has(flag) {
			t.Errorf("buildArgs argv %v is missing %q", args, flag)
		}
	}
}

// TestBuildArgs_OptionCannotIntroduceAFlag pins that an option value is
// held to the same standard as a req.Args value: it can never itself be a
// flag, and it must satisfy the validator registered for that flag.
func TestBuildArgs_OptionCannotIntroduceAFlag(t *testing.T) {
	for _, value := range []string{"-oN", "--script", "/etc/passwd", "/tmp/evil.yaml", "../../etc/passwd", "cves/2023;id"} {
		req := registry.ExecuteRequest{
			Target:  "https://example.com",
			Options: map[string]string{"templates": value},
		}
		if args, err := buildArgs(req); err == nil {
			t.Errorf("buildArgs accepted templates=%q, produced %v", value, args)
		}
	}
}

// TestBuildArgs_AcceptsValidOption keeps the rejections above honest.
func TestBuildArgs_AcceptsValidOption(t *testing.T) {
	req := registry.ExecuteRequest{
		Target:  "https://example.com",
		Options: map[string]string{"templates": "cves/2023"},
	}
	if _, err := buildArgs(req); err != nil {
		t.Fatalf("buildArgs rejected a valid templates option: %v", err)
	}
}
