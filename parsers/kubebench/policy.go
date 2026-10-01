// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Target and args policy for kube-bench.
//
// Args: none. This tool exposes no kube-bench flag. The target (policies),
// the output format (JSON), the config directory and the version are all fixed
// in Execute, and readInput rejects any req.Args with an error instead of
// dropping them. So there is no flag policy to register: the open-policy
// rule in docs/tool-args-policy.md has nothing to apply to.
//
// Target: the cluster NAME, as a DNS-style label. It is used as a key in the
// result and is never placed on an argv. The central gate in the runner
// requires every tool to have a non-empty target that passes a registered
// syntax, so this registers the hostname syntax, which accepts a label such
// as "prod-eu" and rejects anything that starts with "-", holds whitespace or
// holds a newline.

package kubebench

import (
	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

func init() {
	registry.RegisterTargetPolicy(toolName, policy.TargetHostname)
}
