// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package trivyk8s

import (
	"slices"
	"testing"
)

// The flags trivy v0.76.0 does not define for the k8s command. trivy exits
// FATAL on an unknown flag, so one of these in the argv fails the whole run.
// This is the exact defect fixed here: the old argv passed --all-namespaces.
var rejectedFlags = []string{"--all-namespaces", "--namespace"}

func TestBuildArgs_WholeClusterAddsNoScopeFlag(t *testing.T) {
	args := buildArgs(config{cluster: "goat"})

	for _, bad := range rejectedFlags {
		if slices.Contains(args, bad) {
			t.Fatalf("whole-cluster argv must not carry %q (trivy v0.76.0 rejects it); got %v", bad, args)
		}
	}
	// No scope flag at all is the whole-cluster default.
	if slices.Contains(args, "--include-namespaces") {
		t.Fatalf("whole-cluster argv must carry no --include-namespaces; got %v", args)
	}
}

func TestBuildArgs_SingleNamespaceUsesIncludeNamespaces(t *testing.T) {
	args := buildArgs(config{cluster: "goat", namespace: "kube-system"})

	for _, bad := range rejectedFlags {
		if slices.Contains(args, bad) {
			t.Fatalf("single-namespace argv must not carry %q (trivy v0.76.0 rejects it); got %v", bad, args)
		}
	}
	if i := slices.Index(args, "--include-namespaces"); i < 0 || i+1 >= len(args) || args[i+1] != "kube-system" {
		t.Fatalf("single-namespace argv must carry --include-namespaces kube-system; got %v", args)
	}
}

func TestBuildArgs_AlwaysAsksForJSONAndMisconfig(t *testing.T) {
	args := buildArgs(config{cluster: "goat"})

	if len(args) == 0 || args[0] != "k8s" {
		t.Fatalf("argv must start with the k8s subcommand; got %v", args)
	}
	want := map[string]string{"--format": "json", "--scanners": scanners}
	for flag, val := range want {
		i := slices.Index(args, flag)
		if i < 0 || i+1 >= len(args) || args[i+1] != val {
			t.Fatalf("argv must carry %s %s; got %v", flag, val, args)
		}
	}
}
