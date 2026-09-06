// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package trivy

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// TestTarget_AcceptsImageReferences pins the reference forms a caller may
// scan, including the digest form the fixing loop pins images by.
func TestTarget_AcceptsImageReferences(t *testing.T) {
	for _, ref := range []string{
		"alpine",
		"alpine:3.20",
		"ghcr.io/zeroroot-ai/example-portal:1.4.0",
		"registry.gitlab.com/examplebank/customer-portal:sha-abc123",
		"localhost:5000/team/app:dev",
		"alpine@sha256:" + strings.Repeat("a", 64),
		"ghcr.io/org/app:1.0@sha256:" + strings.Repeat("b", 64),
	} {
		if err := registry.ValidateTarget(toolName, ref); err != nil {
			t.Errorf("%q rejected: %v", ref, err)
		}
	}
}

// TestTarget_RejectsWhatIsNotAnImage pins that a host, a URL, a flag or a
// malformed digest never reaches trivy as a scan subject.
func TestTarget_RejectsWhatIsNotAnImage(t *testing.T) {
	for _, ref := range []string{
		"",
		"-v",
		"https://example.com/app",
		"Alpine:3.20",
		"alpine@sha256:tooshort",
		"alpine@md5:" + strings.Repeat("a", 32),
		"alpine@" + strings.Repeat("a", 64),
		"ghcr.io//app:1.0",
		"alpine:",
		"localhost:0/app",
		"localhost:99999/app",
		"alpine:tag with space",
	} {
		if err := registry.ValidateTarget(toolName, ref); err == nil {
			t.Errorf("%q was accepted as an image reference", ref)
		}
	}
}

// TestArgs_OutputControlIsDenied is the load-bearing one: the runner parses
// trivy's JSON on stdout, so a caller who could change the format could make
// every scan report nothing.
//
// A flag outside the allowlist is STRIPPED, not rejected — ApplyPolicy logs
// it and returns the surviving argv with no error. The assertion is
// therefore that the flag does not survive, which is the property that
// actually matters; asserting an error here would pass only by accident of
// a different policy.
func TestArgs_OutputControlIsDenied(t *testing.T) {
	for _, args := range [][]string{
		{"-f", "table"},
		{"--format", "table"},
		{"-o", "/tmp/out.json"},
		{"--output", "/tmp/out.json"},
		{"--template", "@/tmp/tpl"},
		{"--exit-code", "1"},
		{"--input", "/tmp/image.tar"},
	} {
		out, err := registry.ApplyPolicy(toolName, args, nil)
		if err != nil {
			continue // rejected outright is also fine
		}
		if len(out) != 0 {
			t.Errorf("%v survived the allowlist as %v", args, out)
		}
	}
}

// TestBuildArgs_DeniedFlagsNeverReachTheArgv is the same property at the
// level the tool actually sees: whatever a caller puts in req.Args, the
// format stays JSON and no output path appears.
func TestBuildArgs_DeniedFlagsNeverReachTheArgv(t *testing.T) {
	args, err := buildArgs(registry.ExecuteRequest{
		Target: "ghcr.io/org/app:1.0",
		Args:   []string{"-f", "table", "-o", "/tmp/out.json", "--exit-code", "1"},
	})
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, denied := range []string{"table", "/tmp/out.json", "--exit-code"} {
		if strings.Contains(joined, denied) {
			t.Errorf("denied token %q reached the argv: %v", denied, args)
		}
	}
	if strings.Count(joined, "-f json") != 1 {
		t.Errorf("output format is not exactly `-f json`: %v", args)
	}
}

// TestArgs_AllowsReportNarrowing pins the flags a caller legitimately needs.
func TestArgs_AllowsReportNarrowing(t *testing.T) {
	for _, args := range [][]string{
		{"--severity", "HIGH,CRITICAL"},
		{"--scanners", "vuln"},
		{"--pkg-types", "os"},
		{"--ignore-unfixed"},
		{"--skip-db-update"},
	} {
		if _, err := registry.ApplyPolicy(toolName, args, nil); err != nil {
			t.Errorf("%v rejected: %v", args, err)
		}
	}
	if _, err := registry.ApplyPolicy(toolName, []string{"--severity", "SEVERE"}, nil); err == nil {
		t.Error("--severity SEVERE was accepted; it is not a trivy severity")
	}
}

// TestBuildArgs_FixesFormatAndPutsTheReferenceLast pins the argv shape.
func TestBuildArgs_FixesFormatAndPutsTheReferenceLast(t *testing.T) {
	args, err := buildArgs(registry.ExecuteRequest{
		Target:  "ghcr.io/org/app:1.0",
		Options: map[string]string{"severity": "HIGH,CRITICAL", "ignore_unfixed": "true"},
	})
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.HasPrefix(joined, "image --quiet -f json") {
		t.Errorf("argv does not fix the output format: %v", args)
	}
	if args[len(args)-1] != "ghcr.io/org/app:1.0" {
		t.Errorf("image reference is not last: %v", args)
	}
	if !strings.Contains(joined, "--severity HIGH,CRITICAL") {
		t.Errorf("severity option missing: %v", args)
	}
	if !strings.Contains(joined, "--ignore-unfixed") {
		t.Errorf("ignore_unfixed option missing: %v", args)
	}
}

// TestBuildArgs_RejectsABadTargetBeforeExec pins that validation happens in
// buildArgs, so nothing malformed reaches the process at all.
func TestBuildArgs_RejectsABadTargetBeforeExec(t *testing.T) {
	if _, err := buildArgs(registry.ExecuteRequest{Target: "https://example.com"}); err == nil {
		t.Error("a URL was accepted as an image reference")
	}
}

// TestDescribe_AdvertisesTheContract pins the catalog entry the daemon reads.
func TestDescribe_AdvertisesTheContract(t *testing.T) {
	entry := (&parser{}).Describe()
	if entry.Name != toolName {
		t.Errorf("name = %q", entry.Name)
	}
	if entry.OutputProtoType != "gibson.graphrag.v1.DiscoveryResult" {
		t.Errorf("output proto = %q", entry.OutputProtoType)
	}
	if entry.DefaultTimeoutSeconds <= 0 {
		t.Error("no default timeout declared")
	}
}
