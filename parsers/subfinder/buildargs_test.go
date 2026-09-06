// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package subfinder

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
		"example.com\nevil.example.com", // second target on a new line
		"example.com\x00",               // NUL byte
		"example.com evil.example.com",  // space splits the token
		"example.com;id",                // shell metacharacter
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
	args, err := buildArgs(registry.ExecuteRequest{Target: "example.com"})
	if err != nil {
		t.Fatalf("buildArgs rejected a valid target: %v", err)
	}
	if len(args) == 0 {
		t.Fatal("buildArgs produced an empty argv")
	}
}
