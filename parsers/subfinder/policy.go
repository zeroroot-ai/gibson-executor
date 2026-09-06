// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Per-tool args allowlist for subfinder.
//
// Coverage rationale:
//   - Source-control flags safe.
//   - Output flags (`-o`) DENIED — runner consumes JSON on stdout.
//   - Resolver-list (`-r`, `-rl`) DENIED — see dnsx policy rationale.
package subfinder

import (
	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

var argsPolicy = policy.ArgsPolicy{
	"-sources":         policy.AllowAny,
	"-s":               policy.AllowAny,
	"-exclude-sources": policy.AllowAny,
	"-es":              policy.AllowAny,
	"-all":             nil,
	"-recursive":       nil,
	"-active":          nil,
	"-timeout":         policy.AllowAny,
	"-rate-limit":      policy.AllowAny,
	"-rl":              policy.AllowAny,
	"-t":               policy.AllowAny,
	"-silent":          nil,
	"-stats":           nil,
	"-no-color":        nil,
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
	// subfinder enumerates a root domain — a hostname and nothing else.
	registry.RegisterTargetPolicy(toolName, policy.TargetHostname)
}
