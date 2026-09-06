// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package masscan

import (
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// TestBuildArgs_TargetRejections pins that a target which is not a scan
// subject never reaches the tool. Every entry here would otherwise be read
// as a flag, as several targets, or as a token the tool re-splits.
func TestBuildArgs_TargetRejections(t *testing.T) {
	for _, target := range []string{
		"-oN",                           // reads as a flag
		"--config",                      // reads as a long flag
		"-",                             // bare dash
		"10.0.0.0/24\nevil.example.com", // second target on a new line
		"10.0.0.0/24\x00",               // NUL byte
		"10.0.0.0/24 evil.example.com",  // space splits the token
		"10.0.0.0/24;id",                // shell metacharacter
		"",                              // absent
	} {
		if args, err := buildArgs(registry.ExecuteRequest{Target: target}); err == nil {
			t.Errorf("buildArgs accepted target %q, produced %v", target, args)
		}
	}
}

// TestBuildArgs_AcceptsValidTarget keeps the rejections above honest: a
// well-formed target still builds an argv.
func TestBuildArgs_AcceptsValidTarget(t *testing.T) {
	args, err := buildArgs(registry.ExecuteRequest{Target: "10.0.0.0/24"})
	if err != nil {
		t.Fatalf("buildArgs rejected a valid target: %v", err)
	}
	if len(args) == 0 {
		t.Fatal("buildArgs produced an empty argv")
	}
}

// TestBuildArgs_OptionCannotIntroduceAFlag pins that an option value is
// held to the same standard as a req.Args value: it can never itself be a
// flag, and it must satisfy the validator registered for that flag.
func TestBuildArgs_OptionCannotIntroduceAFlag(t *testing.T) {
	for _, value := range []string{"-oN", "--script", "/etc/passwd", "80;id"} {
		req := registry.ExecuteRequest{
			Target:  "10.0.0.0/24",
			Options: map[string]string{"ports": value},
		}
		if args, err := buildArgs(req); err == nil {
			t.Errorf("buildArgs accepted ports=%q, produced %v", value, args)
		}
	}
}

// TestBuildArgs_AcceptsValidOption keeps the rejections above honest.
func TestBuildArgs_AcceptsValidOption(t *testing.T) {
	req := registry.ExecuteRequest{
		Target:  "10.0.0.0/24",
		Options: map[string]string{"ports": "80,443"},
	}
	if _, err := buildArgs(req); err != nil {
		t.Fatalf("buildArgs rejected a valid ports option: %v", err)
	}
}
