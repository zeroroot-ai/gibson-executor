// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build !linux && !darwin

// Copyright (c) 2026 ZeroRoot
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
