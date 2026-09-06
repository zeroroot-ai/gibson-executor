// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Per-tool args allowlist for masscan.
//
// Coverage rationale:
//   - Output flags (`-oN`, `-oX`, `-oJ`, `-oG`, `--output-filename`) DENIED.
//     The runner pins `-oJ -` so JSON reaches stdout; allowing caller-
//     supplied output paths is the canonical example of arbitrary file
//     write via tool injection.
//   - Throughput / scope flags safe.
package masscan

import (
	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

var argsPolicy = policy.ArgsPolicy{
	"-p":          policy.PortSpec,
	"--ports":     policy.PortSpec,
	"--rate":      policy.Numeric,
	"--top-ports": policy.Numeric,
	"--exclude":   policy.AllowAny,
	"--banners":   nil,
	"--ping":      nil,
	"-v":          nil,
	"-vv":         nil,
	"--retries":   policy.Numeric,
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
	// masscan sweeps address space, so an IP or a CIDR prefix only.
	// Hostnames are excluded deliberately: masscan has no `--`
	// end-of-options terminator, which makes the positional target the
	// one slot with no second line of defence, so it gets the narrowest
	// syntax the tool can work with.
	registry.RegisterTargetPolicy(toolName, policy.TargetIP|policy.TargetCIDR)
}
