// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Target and args policy for trivy-k8s.
//
// Args: none. This tool exposes no trivy flag. The subcommand, the output
// format, the scanner set, the timeout and the namespace scope are all fixed
// in Execute, and readInput rejects any req.Args with an error instead of
// dropping them. So there is no flag policy to register: the open-policy rule
// in docs/tool-args-policy.md has nothing to apply to.
//
// Target: the cluster NAME, as a DNS-style label. It is used as a key in the
// result and is never placed on an argv. The central gate in the runner
// requires every tool to have a non-empty target that passes a registered
// syntax, so this registers the hostname syntax, as parsers/kubebench does:
// the two tools take the same kind of target and must agree.
//
// The one caller value that DOES reach an argv is the optional namespace, and
// readInput validates it against RFC 1123 rather than quoting it.

package trivyk8s

import (
	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

func init() {
	registry.RegisterTargetPolicy(toolName, policy.TargetHostname)
}
