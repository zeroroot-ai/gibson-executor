// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package sandbox applies OS-level resource limits to the tool runner and to
// the child processes it launches.  It provides four independent controls:
//
//  1. Process-group isolation (Setpgid): the child runs in its own process
//     group so that a SIGTERM or SIGKILL targeted at -pgid reaches every
//     forked grandchild the tool may have spawned.
//
//  2. Per-tool virtual-memory ceiling (RLIMIT_AS): a hard per-child OS memory
//     limit that the kernel enforces regardless of what the child process
//     does.  Apply rewrites the command so that the runner re-execs itself in
//     a tiny pre-exec mode (see RunPreExec) which calls setrlimit(2) and then
//     execve(2)s the real tool.  The limit is therefore in force at the moment
//     the kernel loads the tool's image, and the tool keeps the PID the runner
//     is waiting on.  No shell is involved: the tool's argv is passed as an
//     argv, never as a string a shell has to re-parse.
//
//  3. Runner virtual-memory ceiling (RLIMIT_AS on this process): ApplySelf
//     bounds the runner itself.  The runner is the process that buffers tool
//     output, so it needs its own ceiling; limiting only the children misses
//     the process that actually holds the memory.
//
//  4. Output cap (CappedBuffer / LimitReader): stdout and stderr are bounded
//     at OutputCapBytes per stream.  CappedBuffer keeps accepting writes past
//     the cap but discards the overflow, so the tool never blocks on a full
//     pipe; Err() reports afterwards whether the cap was hit.
//
// All limits have environment-variable overrides so operators can tune them
// via Helm values without rebuilding the image:
//
//	TOOL_RUNNER_OUTPUT_CAP_BYTES   default 100 MiB  (per stream, per tool call)
//	TOOL_RUNNER_MEMORY_BYTES       default   2 GiB  (RLIMIT_AS per tool child)
//	TOOL_RUNNER_SELF_MEMORY_BYTES  default   3 GiB  (RLIMIT_AS for the runner)
//
// # Why the memory numbers look large
//
// RLIMIT_AS caps *virtual* address space, not resident memory, and a Go
// runtime reserves a lot of address space before main() runs.  A trivial Go
// binary fails to start under an RLIMIT_AS of 512 MiB ("failed to reserve page
// summary memory") and needs roughly a gigabyte just to reach main.  Several
// tools shipped in this image (httpx, nuclei) are Go binaries, and so is the
// runner.  A ceiling that reads as "generous" for a C program is simply an
// unbootable one here, so the defaults and the floors below are sized from
// measurement rather than from intuition.
package sandbox

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

const (
	// EnvOutputCapBytes is the env-var name for the output-cap override.
	EnvOutputCapBytes = "TOOL_RUNNER_OUTPUT_CAP_BYTES"
	// EnvMemoryBytes is the env-var name for the per-tool memory-limit override.
	EnvMemoryBytes = "TOOL_RUNNER_MEMORY_BYTES"
	// EnvSelfMemoryBytes is the env-var name for the runner's own memory limit.
	EnvSelfMemoryBytes = "TOOL_RUNNER_SELF_MEMORY_BYTES"

	defaultOutputCapBytes = 100 * 1024 * 1024  // 100 MiB per stream
	defaultMemoryBytes    = 2048 * 1024 * 1024 // 2 GiB per tool child
	defaultSelfMemoryUnit = 3072 * 1024 * 1024 // 3 GiB for the runner itself

	// MinToolMemoryBytes is the floor DefaultConfig clamps
	// TOOL_RUNNER_MEMORY_BYTES up to.  Measured: a Go binary cannot reach
	// main() under an RLIMIT_AS of 512 MiB, and this image ships Go tools.
	// An operator who sets a smaller value has not made the sandbox tighter,
	// they have made every Go tool fail to start, so the floor is enforced
	// rather than obeyed.
	MinToolMemoryBytes = 1024 * 1024 * 1024 // 1 GiB

	// goRuntimeReserveBytes is the measured address-space reservation a Go
	// process makes before it has buffered anything.  It is the fixed term of
	// the runner's own floor.
	goRuntimeReserveBytes = 1536 * 1024 * 1024 // 1.5 GiB
)

// ErrOutputCapExceeded is returned by a LimitReader when the byte cap is hit.
var ErrOutputCapExceeded = errors.New("sandbox: output cap exceeded")

// Config holds the resource limits applied to the runner and to each child.
type Config struct {
	// OutputCapBytes is the maximum number of bytes retained from a single
	// stdout or stderr stream.  Note that this is a *per-stream* cap: a tool
	// call that fills both streams retains 2x this value in the runner, which
	// is why SelfMemoryBytes is derived from it.  Default: 100 MiB.
	OutputCapBytes int64

	// MemoryBytes is the RLIMIT_AS hard limit (virtual address space) applied
	// to each tool child at fork time.  Default: 2 GiB.
	MemoryBytes uint64

	// SelfMemoryBytes is the RLIMIT_AS soft limit applied to the runner
	// process itself by ApplySelf.  Default: 3 GiB.
	SelfMemoryBytes uint64
}

// DefaultConfig returns a Config populated from environment variables if
// present, falling back to the compiled-in defaults, with both memory limits
// clamped up to a floor that keeps the runner and its Go tools bootable.
//
// The clamp is deliberately applied here and not in Apply: DefaultConfig is
// the operator-facing path, where an under-sized value is a misconfiguration.
// A Config built in code is honoured verbatim so tests can drive the mechanism
// with a deliberately tiny ceiling.
func DefaultConfig() Config {
	cfg := Config{
		OutputCapBytes:  defaultOutputCapBytes,
		MemoryBytes:     defaultMemoryBytes,
		SelfMemoryBytes: defaultSelfMemoryUnit,
	}
	if v := os.Getenv(EnvOutputCapBytes); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cfg.OutputCapBytes = n
		}
	}
	if v := os.Getenv(EnvMemoryBytes); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			cfg.MemoryBytes = n
		}
	}
	if v := os.Getenv(EnvSelfMemoryBytes); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			cfg.SelfMemoryBytes = n
		}
	}

	if cfg.MemoryBytes < MinToolMemoryBytes {
		cfg.MemoryBytes = MinToolMemoryBytes
	}
	if floor := SelfMemoryFloor(cfg.OutputCapBytes); cfg.SelfMemoryBytes < floor {
		cfg.SelfMemoryBytes = floor
	}
	return cfg
}

// SelfMemoryFloor returns the smallest RLIMIT_AS under which the runner can
// still buffer a full tool call.  A call can fill both stdout and stderr to
// outputCap, and bytes.Buffer grows by doubling, so the transient requirement
// is several times the cap on top of the Go runtime's own reservation.
//
// Exported so that raising TOOL_RUNNER_OUTPUT_CAP_BYTES cannot silently
// produce a runner whose own ceiling is below what its output cap permits.
func SelfMemoryFloor(outputCapBytes int64) uint64 {
	if outputCapBytes < 0 {
		outputCapBytes = 0
	}
	return goRuntimeReserveBytes + 4*uint64(outputCapBytes)
}

// Apply configures cmd with process-group isolation (Setpgid) and an
// RLIMIT_AS virtual-memory ceiling that is in force before the tool's image is
// loaded.  It must be called before cmd.Start() or cmd.Run(), and after the
// caller has finished setting cmd.Path/cmd.Args, because it rewrites both.
//
// A non-nil error means the ceiling could not be arranged.  Callers must treat
// that as a hard failure and not run the tool: an unbounded tool child is the
// condition this package exists to prevent.
func Apply(cmd *exec.Cmd, cfg Config) error {
	// 1. Process-group isolation: the child (and all its descendants) run in
	//    their own process group.  When the context deadline fires, exec.Cmd
	//    sends SIGKILL to -pgid, reaching grandchildren too.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true

	// 2. RLIMIT_AS, set between fork and exec by the pre-exec helper.
	return applyMemoryLimit(cmd, cfg.MemoryBytes)
}

// ApplySelf bounds the runner process's own address space.  The runner is what
// buffers tool output, so a ceiling on the children alone leaves the largest
// allocator in the pipeline unbounded.
//
// The limit is applied to the soft limit only; the inherited hard limit is
// left untouched (and is respected as an upper bound) so that a constrained
// environment stays constrained and the per-tool limit set later by the
// pre-exec helper is still reachable.
//
// A non-nil error is informational, not fatal: the primary bound on runner
// memory is CappedBuffer, which is unconditional.  This is defence in depth,
// and a platform that refuses setrlimit(2) (a restrictive seccomp profile,
// say) should not stop the runner from running at all.
func ApplySelf(cfg Config) error {
	return applySelfMemoryLimit(cfg.SelfMemoryBytes)
}

// LimitReader wraps r so that at most limit bytes may be read in total.
// When the cap is exceeded the next Read returns (0, ErrOutputCapExceeded).
// Partial reads that exhaust the remaining quota return the bytes up to the
// cap and then ErrOutputCapExceeded on the following call.
func LimitReader(r io.Reader, limit int64) io.Reader {
	return &limitedReader{r: r, n: limit}
}

type limitedReader struct {
	r io.Reader
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, ErrOutputCapExceeded
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// CappedBuffer is a drop-in replacement for bytes.Buffer that is safe to use
// as cmd.Stdout / cmd.Stderr.  It accepts writes up to Cap bytes; the first
// write that would exceed the cap is truncated and the overflow is silently
// discarded.  After the command finishes, callers should call Err() to check
// whether the cap was hit.
//
//	var stdout sandbox.CappedBuffer
//	stdout.Init(cfg.OutputCapBytes)
//	cmd.Stdout = &stdout
//	cmd.Run()
//	if err := stdout.Err(); errors.Is(err, sandbox.ErrOutputCapExceeded) { ... }
//
// Discarding rather than erroring keeps the tool from dying on EPIPE mid-scan,
// but it also means a tool that floods its output is never stopped by the cap.
// The per-call timeout is what bounds that case, which is why the runner
// always applies one.
type CappedBuffer struct {
	buf bytes.Buffer
	cap int64
	rem int64
	hit bool
}

// Init sets the byte cap.  Must be called before the first write.
func (c *CappedBuffer) Init(cap int64) {
	c.cap = cap
	c.rem = cap
}

// Write implements io.Writer.  Bytes beyond the cap are silently dropped and
// the overflow flag is set.
func (c *CappedBuffer) Write(p []byte) (int, error) {
	if c.rem <= 0 {
		c.hit = true
		// Report success so the subprocess's write does not fail (we want the
		// process to keep running; we just stop buffering).
		return len(p), nil
	}
	accept := int64(len(p))
	if accept > c.rem {
		accept = c.rem
		c.hit = true
	}
	n, err := c.buf.Write(p[:accept])
	c.rem -= int64(n)
	// Always report the full len(p) consumed so the caller (cmd's internal
	// I/O copier) does not think the write failed.
	return len(p), err
}

// Bytes returns the buffered bytes (up to Cap).
func (c *CappedBuffer) Bytes() []byte { return c.buf.Bytes() }

// Err returns ErrOutputCapExceeded if the cap was hit, otherwise nil.
func (c *CappedBuffer) Err() error {
	if c.hit {
		return ErrOutputCapExceeded
	}
	return nil
}
