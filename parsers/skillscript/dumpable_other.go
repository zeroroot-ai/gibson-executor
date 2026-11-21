// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build !linux

package skillscript

import "errors"

// setNonDumpable fails on a system that has no /proc to protect. The tool runs
// in a Linux machine, so the failure stops a run anywhere else.
func setNonDumpable() error {
	return errors.New("skill-script runs only on Linux")
}
