// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build linux || darwin

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

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

// preExecSentinel is the first argument of a re-exec'd copy of this binary
// running in "set RLIMIT_AS, then exec the tool" mode.  It is checked
// positionally as os.Args[1] and never parsed as a flag, so no tool argument
// can be mistaken for it.
const preExecSentinel = "--gibson-sandbox-rlimit-exec"

// preExecArgc is the number of leading argv entries the pre-exec mode
// consumes: the binary itself, the sentinel, the limit, the "--" separator,
// and the resolved path of the tool.  Everything after that is the tool's own
// argv, starting with its argv[0].
const preExecArgc = 5

// exitPreExecFailed follows the shell convention for "the command could not be
// executed".  A tool that never started is reported to the parser as a
// non-zero exit rather than as silence.
const exitPreExecFailed = 127

// applyMemoryLimit rewrites cmd so the process the runner waits on is the tool
// itself, running with RLIMIT_AS already set.
//
// The runner re-execs itself with a sentinel argv; that copy calls setrlimit(2)
// and then execve(2)s the real tool.  execve replaces the process image without
// forking, so the PID exec.Cmd is waiting on, the process group Setpgid put it
// in, and the pipes attached to it all survive into the tool.
//
// The predecessor of this function wrapped the tool in
// `sh -c "ulimit -v N; exec <quoted argv>"`.  That worked, but it flattened a
// argv into a string for a shell to re-parse — an entirely avoidable parsing
// surface in a component whose inputs are attacker-influenced.  Here the tool's
// argv is carried as an argv from end to end and never becomes a string.
func applyMemoryLimit(cmd *exec.Cmd, limitBytes uint64) error {
	if cmd.Err != nil {
		// exec.Command could not resolve the binary.  Leave the command alone
		// so the caller sees the original lookup error rather than a confusing
		// failure from the pre-exec helper.
		return nil
	}
	if limitBytes == 0 {
		return fmt.Errorf("sandbox: refusing to run %q with an RLIMIT_AS of zero", cmd.Path)
	}
	if cmd.Path == "" {
		return fmt.Errorf("sandbox: cmd.Path is empty; cannot arrange RLIMIT_AS")
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("sandbox: locate own executable to arrange RLIMIT_AS: %w", err)
	}

	argv := cmd.Args
	if len(argv) == 0 {
		argv = []string{cmd.Path}
	}

	wrapped := make([]string, 0, preExecArgc+len(argv))
	wrapped = append(wrapped,
		self,
		preExecSentinel,
		strconv.FormatUint(limitBytes, 10),
		"--",
		cmd.Path,
	)
	wrapped = append(wrapped, argv...)

	cmd.Path = self
	cmd.Args = wrapped
	return nil
}

// RunPreExec detects the sentinel argv planted by applyMemoryLimit, applies
// RLIMIT_AS, and execs the real tool.  In that mode it never returns.  In every
// other invocation it returns immediately and the caller proceeds as normal.
//
// Every main() that may reach Apply must call this as its first statement,
// before any flag parsing: a re-exec'd copy of the binary is this binary, and
// it must not fall through into the runner's ordinary behaviour.  Test binaries
// that exercise Apply must call it from TestMain for the same reason.
func RunPreExec() {
	if len(os.Args) < 2 || os.Args[1] != preExecSentinel {
		return
	}
	if len(os.Args) < preExecArgc+1 || os.Args[3] != "--" {
		fmt.Fprintln(os.Stderr, "sandbox: malformed pre-exec invocation")
		os.Exit(exitPreExecFailed)
	}

	limitBytes, err := strconv.ParseUint(os.Args[2], 10, 64)
	if err != nil || limitBytes == 0 {
		fmt.Fprintf(os.Stderr, "sandbox: unusable pre-exec RLIMIT_AS %q\n", os.Args[2])
		os.Exit(exitPreExecFailed)
	}

	path := os.Args[preExecArgc-1]
	argv := os.Args[preExecArgc:]

	// Marshal everything execve(2) needs BEFORE lowering RLIMIT_AS, and stage
	// the failure message too (#356).
	//
	// syscall.Exec is not allocation-free: it calls SlicePtrFromStrings on the
	// argv and the environment to build the C string vectors. Those are Go heap
	// allocations, and when one of them needs a fresh span the runtime mmaps —
	// under the RLIMIT_AS we just installed. If that mmap is refused the Go
	// runtime does not return an error, it throws:
	//
	//	fatal error: runtime: out of memory
	//	runtime.sysMapOS ... syscall.SlicePtrFromStrings ... syscall.Exec
	//
	// and the process dies with status 2 before the tool ever starts. The
	// caller sees an exit code that looks like it came from the tool. Whether
	// it happens depends on whether the allocator can serve those slices from
	// an existing span, so it reproduces as a low-rate flake at any limit
	// value rather than as a clean threshold — measured at 1/20 runs for a
	// 987 MiB limit and 0/20 for both larger and smaller ones.
	//
	// Doing the marshalling first and then issuing execve as a raw syscall
	// leaves no Go allocation between setrlimit(2) and execve(2), so there is
	// no window in which the runtime can need memory it is no longer allowed
	// to have.
	argv0p, err := syscall.BytePtrFromString(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: exec path %s: %v\n", path, err)
		os.Exit(exitPreExecFailed)
	}
	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: exec argv for %s: %v\n", path, err)
		os.Exit(exitPreExecFailed)
	}
	envvp, err := syscall.SlicePtrFromStrings(os.Environ())
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: exec environ for %s: %v\n", path, err)
		os.Exit(exitPreExecFailed)
	}
	// Pre-rendered, with spare capacity for the errno digits, so the failure
	// path below writes bytes that already exist instead of formatting a new
	// string under the tightened limit. strconv.AppendInt into spare capacity
	// does not allocate.
	execFailMsg := make([]byte, 0, len(path)+64)
	execFailMsg = append(execFailMsg, "sandbox: execve "...)
	execFailMsg = append(execFailMsg, path...)
	execFailMsg = append(execFailMsg, ": errno "...)

	if err := setChildMemoryLimit(limitBytes); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: set RLIMIT_AS: %v\n", err)
		os.Exit(exitPreExecFailed)
	}

	// No Go allocation past this point. execve only returns on failure.
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_EXECVE,
		uintptr(unsafe.Pointer(argv0p)),
		uintptr(unsafe.Pointer(&argvp[0])),
		uintptr(unsafe.Pointer(&envvp[0])),
	)
	execFailMsg = strconv.AppendInt(execFailMsg, int64(errno), 10)
	execFailMsg = append(execFailMsg, '\n')
	_, _ = syscall.Write(stderrFD, execFailMsg)
	os.Exit(exitPreExecFailed)
}

// stderrFD is the conventional stderr descriptor. Used directly on the
// post-setrlimit path, where os.Stderr's methods are avoided in favour of a
// bare write(2).
const stderrFD = 2

// setChildMemoryLimit pins both the soft and the hard RLIMIT_AS so the tool
// cannot raise its own ceiling back up.
func setChildMemoryLimit(limitBytes uint64) error {
	lim := syscall.Rlimit{Cur: limitBytes, Max: limitBytes}
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &lim); err != nil {
		return fmt.Errorf("setrlimit RLIMIT_AS=%d: %w", limitBytes, err)
	}
	return nil
}

// applySelfMemoryLimit lowers this process's RLIMIT_AS soft limit.  The hard
// limit is left as inherited, both so that an already-constrained environment
// keeps its constraint and so that the pre-exec helper (which inherits this
// limit) can still set the per-tool ceiling.
func applySelfMemoryLimit(limitBytes uint64) error {
	if limitBytes == 0 {
		return fmt.Errorf("sandbox: refusing to set the runner's RLIMIT_AS to zero")
	}
	var cur syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_AS, &cur); err != nil {
		return fmt.Errorf("getrlimit RLIMIT_AS: %w", err)
	}
	// Never try to raise past the inherited hard limit; setrlimit would fail
	// and we would lose the tightening we can actually apply.
	if cur.Max > 0 && limitBytes > cur.Max {
		limitBytes = cur.Max
	}
	next := syscall.Rlimit{Cur: limitBytes, Max: cur.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &next); err != nil {
		return fmt.Errorf("setrlimit RLIMIT_AS=%d: %w", limitBytes, err)
	}
	return nil
}
