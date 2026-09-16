// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build !linux && !darwin

package sandbox

import "os/exec"

// applyMemoryLimit is a no-op on platforms without setrlimit(2)/execve(2)
// semantics.  Process-group isolation (Setpgid) and the output caps still
// apply; only the RLIMIT_AS enforcement is absent.  The runner image is Linux,
// so these builds exist for developer tooling, not for production.
func applyMemoryLimit(_ *exec.Cmd, _ uint64) error { return nil }

// applySelfMemoryLimit is a no-op for the same reason.
func applySelfMemoryLimit(_ uint64) error { return nil }

// RunPreExec is a no-op: applyMemoryLimit never plants the sentinel argv on
// these platforms, so there is never a re-exec'd copy to detect.
func RunPreExec() {}
