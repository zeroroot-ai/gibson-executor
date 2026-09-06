// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package nmap

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// TestBuildArgs_TargetRejections pins that a target which is not a scan
// subject never reaches the argv. Each of these would otherwise be read by
// nmap as a flag or as several targets.
func TestBuildArgs_TargetRejections(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"leading dash reads as a flag", "-oN"},
		{"long flag", "--script=http-vuln"},
		{"bare dash", "-"},
		{"embedded newline", "10.0.0.1\n10.0.0.2"},
		{"embedded NUL", "10.0.0.1\x00"},
		{"embedded space", "10.0.0.1 10.0.0.2"},
		{"shell metacharacter", "example.com;id"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, err := buildArgs(registry.ExecuteRequest{Target: tc.target})
			if err == nil {
				t.Fatalf("buildArgs accepted target %q, produced %v", tc.target, args)
			}
		})
	}
}

// TestBuildArgs_EmitsDoubleDashBeforeTarget pins the end-of-options
// terminator. nmap's getopt_long stops interpreting flags at "--", so the
// target can never be re-read as one.
func TestBuildArgs_EmitsDoubleDashBeforeTarget(t *testing.T) {
	args, err := buildArgs(registry.ExecuteRequest{Target: "scanme.nmap.org"})
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	if len(args) < 2 {
		t.Fatalf("argv too short: %v", args)
	}
	if got := args[len(args)-1]; got != "scanme.nmap.org" {
		t.Fatalf("target is not last; argv = %v", args)
	}
	if got := args[len(args)-2]; got != "--" {
		t.Fatalf("expected %q immediately before the target; argv = %v", "--", args)
	}
}

// TestBuildArgs_OptionsCannotIntroduceAFlag pins that an option value is
// held to the same standard as a req.Args value: it can never be a flag,
// and it must satisfy the validator registered for that flag.
func TestBuildArgs_OptionsCannotIntroduceAFlag(t *testing.T) {
	cases := []struct {
		name  string
		ports string
	}{
		{"value is a flag", "-oN"},
		{"value is a long flag", "--script"},
		{"value is a path", "/etc/passwd"},
		{"value carries a newline", "80\n-oN"},
		{"value carries a shell metacharacter", "80;id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, err := buildArgs(registry.ExecuteRequest{
				Target:  "10.0.0.1",
				Options: map[string]string{"ports": tc.ports},
			})
			if err == nil {
				t.Fatalf("buildArgs accepted ports=%q, produced %v", tc.ports, args)
			}
		})
	}
}

// TestBuildArgs_HappyPath asserts the argv a legitimate request produces,
// so a future change to ordering or terminators is a visible diff.
func TestBuildArgs_HappyPath(t *testing.T) {
	args, err := buildArgs(registry.ExecuteRequest{
		Target:  "192.168.1.0/24",
		Options: map[string]string{"ports": "22,80,443"},
		Args:    []string{"-sV", "-T4"},
	})
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	want := []string{"-oX", "-", "-p", "22,80,443", "-sV", "-T4", "--", "192.168.1.0/24"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("argv = %v; want %v", args, want)
	}
}

// TestBuildArgs_DeniedArgsFlagIsDropped pins that the allowlist still does
// its original job: an output-file flag never reaches the argv.
func TestBuildArgs_DeniedArgsFlagIsDropped(t *testing.T) {
	args, err := buildArgs(registry.ExecuteRequest{
		Target: "10.0.0.1",
		Args:   []string{"-oN", "/etc/passwd", "-sV"},
	})
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	for _, a := range args {
		if a == "-oN" || a == "/etc/passwd" {
			t.Fatalf("denied flag survived into argv: %v", args)
		}
	}
}
