// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Per-tool args allowlist for naabu.
//
// Coverage rationale:
//   - Port spec / scan-mode flags safe and documented.
//   - Output flags (`-o`, `-output`, `-csv`, `-json` already pinned) are
//     DENIED. The runner consumes JSON on stdout via -json -silent.
package naabu

import (
	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

var argsPolicy = policy.ArgsPolicy{
	// Port specification.
	"-p":             policy.PortSpec,
	"-top-ports":     policy.Numeric,
	"-exclude-ports": policy.PortSpec,

	// Scan-mode flags.
	"-scan-type": policy.AllowEnum("s", "c", "syn", "connect"),
	"-s":         policy.AllowEnum("s", "c", "syn", "connect"),
	"-Pn":        nil,
	"-sn":        nil,

	// Throughput.
	"-rate":    policy.Numeric,
	"-c":       policy.Numeric,
	"-timeout": policy.Numeric,
	"-retries": policy.Numeric,

	// Boolean diagnostics.
	"-stats":  nil,
	"-silent": nil,
	"-verify": nil,
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
	// naabu scans an address, a prefix, or a resolvable name.
	registry.RegisterTargetPolicy(toolName, policy.TargetNetwork)
}
