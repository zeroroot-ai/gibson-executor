// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Per-tool args allowlist for nuclei.
//
// Coverage rationale:
//   - Severity, tag, type filters: documented and safe.
//   - Template selection (`-t`/`--templates`) is ALLOWED behind the
//     templateRef validator. It used to be absent from this map, which
//     read as a denial — but nuclei.go piped req.Options["templates"]
//     straight into `-t`, so the flag reached the argv anyway with no
//     validator at all. Listing it here with a validator is what actually
//     constrains it: a relative template reference, no traversal, no
//     absolute path, so a caller cannot point nuclei at templates outside
//     the runner's pinned template directory.
//   - Output flags (`-o`, `-output`, `-store-resp`, `-store-resp-dir`)
//     are DENIED — the runner consumes JSONL on stdout and never writes
//     to disk on the caller's behalf.
package nuclei

import (
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// severityLevels is nuclei's documented severity vocabulary. The flag
// takes a comma-separated subset.
var severityLevels = []string{"unknown", "info", "low", "medium", "high", "critical"}

var argsPolicy = policy.ArgsPolicy{
	// Template selection — see the package comment above.
	"-t":          templateRef,
	"-templates":  templateRef,
	"--templates": templateRef,

	// Filtering by severity / tags / template type.
	"-severity": policy.AllowCSVEnum(severityLevels...),
	"-s":        policy.AllowCSVEnum(severityLevels...),
	"-tags":     policy.AllowAny,
	"-itags":    policy.AllowAny,
	"-etags":    policy.AllowAny,
	"-type":     policy.AllowAny,
	"-author":   policy.AllowAny,

	// Throughput controls.
	"-rate-limit":  policy.AllowAny,
	"-bulk-size":   policy.AllowAny,
	"-concurrency": policy.AllowAny,
	"-c":           policy.AllowAny,
	"-timeout":     policy.AllowAny,
	"-retries":     policy.AllowAny,

	// Boolean diagnostics that don't affect security posture.
	"-stats":                nil,
	"-silent":               nil,
	"-no-color":             nil,
	"-disable-update-check": nil,
	"-include-rr":           nil,
}

// templateRef validates a nuclei template reference: a relative template
// ID or path such as "cves/2023" or "http/exposures/configs/git-config.yaml".
// Absolute paths and traversal are rejected so the reference can only ever
// resolve inside the runner's pinned template directory.
func templateRef(value string) error {
	if value == "" {
		return fmt.Errorf("template reference must be non-empty")
	}
	if len(value) > 512 {
		return fmt.Errorf("template reference is %d bytes; limit is 512", len(value))
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~") {
		return fmt.Errorf("template reference %q is absolute; use a reference relative to the pinned template directory", value)
	}
	if strings.Contains(value, "..") {
		return fmt.Errorf("template reference %q contains a '..' traversal", value)
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/', r == '.', r == '-', r == '_', r == ',':
		default:
			return fmt.Errorf("template reference %q contains a disallowed character", value)
		}
	}
	return nil
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
	// nuclei scans an absolute http(s) URL, a hostname, or an address.
	registry.RegisterTargetPolicy(toolName, policy.TargetWeb)
}
