// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build linux

package skillscript

import (
	"fmt"
	"syscall"
)

// prSetDumpable is PR_SET_DUMPABLE of prctl(2).
const prSetDumpable = 4

// setNonDumpable clears the dumpable flag of this process. The files of
// /proc/<pid> of a non-dumpable process belong to root, so a process of the
// same uid, such as the script, cannot read the environment of the runner or
// open its file descriptors. The execve of the script sets the flag again for
// the script, so the script itself stays as it was.
func setNonDumpable() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno != 0 {
		return fmt.Errorf("prctl PR_SET_DUMPABLE: %w", errno)
	}
	return nil
}
