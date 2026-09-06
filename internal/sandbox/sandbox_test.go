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

package sandbox_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

// envSelfLimitHelper puts TestMain into a mode that applies ApplySelf to this
// process and prints the resulting RLIMIT_AS. Used by TestApplySelf, which
// cannot run in-process: changing the test binary's own rlimit would leak into
// every other test.
const envSelfLimitHelper = "GIBSON_SANDBOX_TEST_SELF_LIMIT_BYTES"

// TestMain lets the test binary stand in for the runner binary.
//
// sandbox.Apply arranges the per-tool RLIMIT_AS by re-exec-ing the *current*
// executable in pre-exec mode; under `go test` the current executable is this
// test binary. Calling RunPreExec first is therefore not test scaffolding
// around the mechanism — it is the mechanism, exercised exactly as the runner
// exercises it. Without this the memory-limit tests would silently re-run the
// whole test suite in a subprocess instead of exec-ing the tool.
func TestMain(m *testing.M) {
	sandbox.RunPreExec()

	if v := os.Getenv(envSelfLimitHelper); v != "" {
		os.Exit(runSelfLimitHelper(v))
	}

	os.Exit(m.Run())
}

// runSelfLimitHelper applies ApplySelf with the requested ceiling and prints
// the soft and hard RLIMIT_AS the kernel ended up with.
func runSelfLimitHelper(v string) int {
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad %s: %v\n", envSelfLimitHelper, err)
		return 2
	}
	cfg := sandbox.Config{OutputCapBytes: 1024, MemoryBytes: n, SelfMemoryBytes: n}
	if err := sandbox.ApplySelf(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ApplySelf: %v\n", err)
		return 3
	}
	var got syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_AS, &got); err != nil {
		fmt.Fprintf(os.Stderr, "getrlimit: %v\n", err)
		return 4
	}
	fmt.Printf("cur=%d hard=%d\n", got.Cur, got.Max)
	return 0
}

// TestLimitReader_UnderCap verifies that reads below the cap succeed normally.
func TestLimitReader_UnderCap(t *testing.T) {
	t.Parallel()
	src := bytes.NewReader([]byte("hello"))
	lr := sandbox.LimitReader(src, 100)
	got, err := io.ReadAll(lr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

// TestLimitReader_ExactCap verifies that reading exactly cap bytes returns the
// data correctly; a subsequent Read returns ErrOutputCapExceeded because the
// cap is exhausted.  When using io.ReadAll, it will call Read one extra time
// after the cap is hit and receive ErrOutputCapExceeded — the data accumulated
// so far is still available via the partial read.
func TestLimitReader_ExactCap(t *testing.T) {
	t.Parallel()
	data := []byte("abcde")
	src := bytes.NewReader(data)
	lr := sandbox.LimitReader(src, int64(len(data)))

	// Read manually to control buffer size and avoid the extra-call behaviour
	// of io.ReadAll.
	buf := make([]byte, 10)
	n, err := lr.Read(buf)
	if err != nil {
		t.Fatalf("first Read returned unexpected error: %v (n=%d)", err, n)
	}
	if string(buf[:n]) != "abcde" {
		t.Fatalf("first Read: got %q, want %q", buf[:n], "abcde")
	}

	// Cap is now exactly zero; next Read must return ErrOutputCapExceeded.
	n2, err2 := lr.Read(buf)
	if !errors.Is(err2, sandbox.ErrOutputCapExceeded) {
		t.Fatalf("expected ErrOutputCapExceeded after cap, got err=%v n=%d", err2, n2)
	}
}

// TestLimitReader_OverCap verifies that a LimitReader raises
// ErrOutputCapExceeded when more than cap bytes are read from a byte source.
// We use a simple in-process reader rather than a subprocess to avoid
// pipe-drain deadlocks.
func TestLimitReader_OverCap(t *testing.T) {
	t.Parallel()

	const capBytes = 512
	// Produce 1024 bytes — twice the cap.
	data := make([]byte, 1024)
	src := bytes.NewReader(data)
	lr := sandbox.LimitReader(src, capBytes)

	buf := make([]byte, 128)
	var totalRead int
	var hitCap bool
	for {
		n, err := lr.Read(buf)
		totalRead += n
		if errors.Is(err, sandbox.ErrOutputCapExceeded) {
			hitCap = true
			break
		}
		if err != nil {
			t.Fatalf("unexpected error after %d bytes: %v", totalRead, err)
		}
	}

	if !hitCap {
		t.Fatalf("expected ErrOutputCapExceeded after %d bytes, never got it", totalRead)
	}
	if totalRead > capBytes {
		t.Fatalf("read %d bytes past cap of %d", totalRead, capBytes)
	}
}

// TestCappedBuffer_UnderCap verifies that writes below cap succeed.
func TestCappedBuffer_UnderCap(t *testing.T) {
	t.Parallel()
	var cb sandbox.CappedBuffer
	cb.Init(100)
	n, err := cb.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("wrote %d bytes, want 5", n)
	}
	if cb.Err() != nil {
		t.Fatalf("Err() should be nil, got %v", cb.Err())
	}
	if string(cb.Bytes()) != "hello" {
		t.Fatalf("got %q, want %q", cb.Bytes(), "hello")
	}
}

// TestCappedBuffer_OverCap verifies that writes past cap silently drop overflow
// and set Err() to ErrOutputCapExceeded.
func TestCappedBuffer_OverCap(t *testing.T) {
	t.Parallel()
	const cap = 10
	var cb sandbox.CappedBuffer
	cb.Init(cap)

	// Write 20 bytes — 10 accepted, 10 dropped.
	payload := []byte("abcdefghijklmnopqrst") // 20 bytes
	n, err := cb.Write(payload)
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned n=%d, want %d", n, len(payload))
	}
	if !errors.Is(cb.Err(), sandbox.ErrOutputCapExceeded) {
		t.Fatalf("Err() should be ErrOutputCapExceeded, got %v", cb.Err())
	}
	got := string(cb.Bytes())
	if got != "abcdefghij" {
		t.Fatalf("buffered %q, want %q", got, "abcdefghij")
	}
}

// TestCappedBuffer_SubprocessOverCap runs dd to write more than cap bytes and
// verifies CappedBuffer reports ErrOutputCapExceeded after the command.
func TestCappedBuffer_SubprocessOverCap(t *testing.T) {
	t.Parallel()

	// dd produces bs*count = 1024 bytes; cap is 512.
	cmd := exec.Command("dd", "if=/dev/zero", "bs=64", "count=16")
	const cap = 512
	var cb sandbox.CappedBuffer
	cb.Init(cap)
	cmd.Stdout = &cb
	if err := cmd.Run(); err != nil {
		t.Skipf("dd not available: %v", err)
	}
	if !errors.Is(cb.Err(), sandbox.ErrOutputCapExceeded) {
		t.Fatalf("expected ErrOutputCapExceeded, got %v (len=%d)", cb.Err(), len(cb.Bytes()))
	}
}

// TestApply_Setpgid verifies that Apply sets SysProcAttr.Setpgid on the cmd.
func TestApply_Setpgid(t *testing.T) {
	t.Parallel()
	cmd := exec.Command("true")
	cfg := sandbox.DefaultConfig()
	if err := sandbox.Apply(cmd, cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr is nil after Apply")
	}
	if !cmd.SysProcAttr.Setpgid {
		t.Fatal("SysProcAttr.Setpgid is false after Apply")
	}
}

// TestApply_Setpgid_ProcessGroup verifies that a started process actually
// runs in its own process group (pgid == pid).
func TestApply_Setpgid_ProcessGroup(t *testing.T) {
	t.Parallel()
	cmd := exec.Command("true")
	cfg := sandbox.DefaultConfig()
	if err := sandbox.Apply(cmd, cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	pid := cmd.Process.Pid
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		// Process may have exited already; skip the pgid check in that case.
		_ = cmd.Wait()
		t.Skipf("process exited before pgid check: %v", err)
	}
	_ = cmd.Wait()

	if pgid == syscall.Getpid() {
		t.Fatalf("child pgid %d equals parent pid %d; Setpgid had no effect", pgid, syscall.Getpid())
	}
}

// TestApply_MemoryLimit verifies that a subprocess trying to allocate more
// than the configured MemoryBytes limit is killed or exits non-zero.
// We set an artificially low limit (16 MiB) and ask Python to allocate 64 MiB.
// If Python is not installed the test is skipped.
func TestApply_MemoryLimit(t *testing.T) {
	t.Parallel()

	// Verify Python is available.
	pyPath, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available; skipping memory-limit test")
	}

	// 16 MiB limit; try to allocate 64 MiB. The Config is built by hand rather
	// than from DefaultConfig because DefaultConfig clamps the tool limit up to
	// MinToolMemoryBytes, which would make this test unable to prove anything.
	cfg := sandbox.Config{
		OutputCapBytes: sandbox.DefaultConfig().OutputCapBytes,
		MemoryBytes:    16 * 1024 * 1024,
	}
	// Allocate 64 MiB in Python; the process should be killed or fail.
	cmd := exec.Command(pyPath, "-c", "x = bytearray(64*1024*1024)")
	if err := sandbox.Apply(cmd, cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	err = cmd.Run()
	if err == nil {
		t.Fatal("expected process to fail with memory limit, but it succeeded")
	}
	// Any non-zero exit or signal is acceptable — the important thing is the
	// process did not succeed in allocating past the limit.
}

// TestDefaultConfig_EnvOverride verifies that DefaultConfig reads the
// environment variables for both limits.
func TestDefaultConfig_EnvOverride(t *testing.T) {
	// Both memory values are above their floors so this test observes the
	// override, not the clamp; the clamps have their own tests.
	const wantMemory = 4 * 1024 * 1024 * 1024
	const wantSelf = 5 * 1024 * 1024 * 1024
	t.Setenv(sandbox.EnvOutputCapBytes, "1024")
	t.Setenv(sandbox.EnvMemoryBytes, strconv.Itoa(wantMemory))
	t.Setenv(sandbox.EnvSelfMemoryBytes, strconv.Itoa(wantSelf))

	cfg := sandbox.DefaultConfig()
	if cfg.OutputCapBytes != 1024 {
		t.Fatalf("OutputCapBytes: got %d, want 1024", cfg.OutputCapBytes)
	}
	if cfg.MemoryBytes != wantMemory {
		t.Fatalf("MemoryBytes: got %d, want %d", cfg.MemoryBytes, uint64(wantMemory))
	}
	if cfg.SelfMemoryBytes != wantSelf {
		t.Fatalf("SelfMemoryBytes: got %d, want %d", cfg.SelfMemoryBytes, uint64(wantSelf))
	}
}

// TestDefaultConfig_Defaults verifies the compiled-in defaults are correct.
func TestDefaultConfig_Defaults(t *testing.T) {
	t.Setenv(sandbox.EnvOutputCapBytes, "")
	t.Setenv(sandbox.EnvMemoryBytes, "")

	t.Setenv(sandbox.EnvSelfMemoryBytes, "")

	cfg := sandbox.DefaultConfig()
	const wantOutputCap = 100 * 1024 * 1024
	const wantMemory = 2048 * 1024 * 1024
	const wantSelf = 3072 * 1024 * 1024
	if cfg.OutputCapBytes != wantOutputCap {
		t.Fatalf("OutputCapBytes: got %d, want %d", cfg.OutputCapBytes, wantOutputCap)
	}
	if cfg.MemoryBytes != wantMemory {
		t.Fatalf("MemoryBytes: got %d, want %d", cfg.MemoryBytes, uint64(wantMemory))
	}
	if cfg.SelfMemoryBytes != wantSelf {
		t.Fatalf("SelfMemoryBytes: got %d, want %d", cfg.SelfMemoryBytes, uint64(wantSelf))
	}
}

// ---------------------------------------------------------------------------
// The exec path: no shell, and the limit lands on the process the runner
// actually waits on.
// ---------------------------------------------------------------------------

// TestApply_NoShellInExecPath asserts that nothing sandbox.Apply produces asks
// a shell to re-parse the tool's argv.
//
// The predecessor implementation flattened the argv into a single string for
// `sh -c` to split again. Tool arguments are attacker-influenced, so a
// re-parsing step in that path is a liability regardless of how carefully the
// quoting is done. This test pins the property that there is no such step:
// nothing named sh is executed, no `-c` string is constructed, and each
// original argv element survives as its own argv element.
func TestApply_NoShellInExecPath(t *testing.T) {
	t.Parallel()

	original := []string{"nmap", "-oX", "-", "--", "scan me; rm -rf /"}
	cmd := exec.Command("true")
	cmd.Args = original
	if err := sandbox.Apply(cmd, sandbox.DefaultConfig()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if base := filepath.Base(cmd.Path); base == "sh" || base == "bash" || base == "dash" {
		t.Fatalf("Apply exec's a shell (%s); the tool argv must not be re-parsed", cmd.Path)
	}
	for _, a := range cmd.Args {
		if a == "-c" {
			t.Fatalf("Apply built a shell -c invocation: %v", cmd.Args)
		}
		if strings.Contains(a, "ulimit") {
			t.Fatalf("Apply built a ulimit shell script: %v", cmd.Args)
		}
	}

	// Every original argv element must appear verbatim as its own element,
	// never spliced into a single string.
	tail := cmd.Args[len(cmd.Args)-len(original):]
	for i := range original {
		if tail[i] != original[i] {
			t.Fatalf("argv element %d = %q; want %q (argv must pass through intact)", i, tail[i], original[i])
		}
	}
}

// TestApply_LimitAppliesToTheSpawnedProcess is the core assertion of the fix:
// the RLIMIT_AS must be in force in the process that the runner waits on and
// whose pipes it reads — not in some intermediary that has already gone away.
//
// It runs `cat /proc/self/limits`, so the value read back is the limit the
// kernel recorded for the tool's own process image after execve.
func TestApply_LimitAppliesToTheSpawnedProcess(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("/proc/self/limits is Linux-only")
	}
	catPath, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("cat not available")
	}

	const want = 1234 * 1024 * 1024
	cfg := sandbox.Config{OutputCapBytes: 1 << 20, MemoryBytes: want}

	cmd := exec.Command(catPath, "/proc/self/limits")
	if err := sandbox.Apply(cmd, cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var out, errOut sandbox.CappedBuffer
	out.Init(cfg.OutputCapBytes)
	errOut.Init(cfg.OutputCapBytes)
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v\nstdout: %s\nstderr: %s", err, out.Bytes(), errOut.Bytes())
	}

	var line string
	for _, l := range strings.Split(string(out.Bytes()), "\n") {
		if strings.HasPrefix(l, "Max address space") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("no 'Max address space' row in /proc/self/limits:\n%s", out.Bytes())
	}
	if !strings.Contains(line, strconv.Itoa(want)) {
		t.Fatalf("tool process ran with %q; want a soft and hard RLIMIT_AS of %d", line, want)
	}
}

// TestApply_ChildCannotRaiseItsOwnLimit verifies the hard limit is pinned too:
// a tool that calls setrlimit(2) must not be able to lift its own ceiling.
func TestApply_ChildCannotRaiseItsOwnLimit(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("/proc/self/limits is Linux-only")
	}
	catPath, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("cat not available")
	}

	const want = 987 * 1024 * 1024
	cmd := exec.Command(catPath, "/proc/self/limits")
	if err := sandbox.Apply(cmd, sandbox.Config{OutputCapBytes: 1 << 20, MemoryBytes: want}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var out, errOut sandbox.CappedBuffer
	out.Init(1 << 20)
	errOut.Init(1 << 20)
	cmd.Stdout = &out
	// Capture stderr (#356). Without it every failure of this test reduced to
	// a bare "exit status 2" with the reason discarded — which is precisely
	// what made the pre-exec RLIMIT_AS bug expensive to diagnose.
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v\nstdout: %s\nstderr: %s", err, out.Bytes(), errOut.Bytes())
	}

	for _, l := range strings.Split(string(out.Bytes()), "\n") {
		if !strings.HasPrefix(l, "Max address space") {
			continue
		}
		// Columns: name, soft, hard, units. Both limits must be pinned; a
		// soft-only limit is one setrlimit call away from being no limit.
		if strings.Count(l, strconv.Itoa(want)) != 2 {
			t.Fatalf("soft and hard RLIMIT_AS not both pinned to %d: %q", want, l)
		}
		return
	}
	t.Fatalf("no 'Max address space' row:\n%s", out.Bytes())
}

// TestApply_UnresolvedBinaryKeepsOriginalError verifies that a command whose
// binary could not be found is left alone, so the caller sees the lookup
// failure rather than a confusing error from the pre-exec helper.
func TestApply_UnresolvedBinaryKeepsOriginalError(t *testing.T) {
	t.Parallel()
	cmd := exec.Command("this-binary-does-not-exist-a1b2c3")
	if cmd.Err == nil {
		t.Skip("lookup unexpectedly succeeded")
	}
	if err := sandbox.Apply(cmd, sandbox.DefaultConfig()); err != nil {
		t.Fatalf("Apply should not mask the lookup error, got: %v", err)
	}
	if err := cmd.Run(); err == nil {
		t.Fatal("expected the original lookup error from Run")
	}
}

// ---------------------------------------------------------------------------
// The runner's own ceiling.
// ---------------------------------------------------------------------------

// TestApplySelf_BoundsTheRunnerProcess verifies ApplySelf lowers this process's
// RLIMIT_AS. The runner is what buffers tool output, so a ceiling on the tool
// children alone leaves the largest allocator in the pipeline unbounded.
//
// It runs in a subprocess because an rlimit change is process-wide and would
// otherwise leak into every other test in this binary.
func TestApplySelf_BoundsTheRunnerProcess(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("setrlimit is unix-only")
	}

	const want = 3 * 1024 * 1024 * 1024
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d", envSelfLimitHelper, want))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("self-limit helper: %v (output %q)", err, out)
	}
	if !strings.Contains(string(out), fmt.Sprintf("cur=%d", want)) {
		t.Fatalf("runner RLIMIT_AS not applied; helper reported %q", strings.TrimSpace(string(out)))
	}
}

// TestApplySelf_LeavesTheHardLimitAlone verifies the hard limit is untouched.
// Pinning it would be self-defeating: the pre-exec helper inherits this limit
// and must still be able to set the per-tool ceiling, and an environment that
// already constrains the runner should keep its own bound.
func TestApplySelf_LeavesTheHardLimitAlone(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("setrlimit is unix-only")
	}

	var before syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_AS, &before); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d", envSelfLimitHelper, 3*1024*1024*1024))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("self-limit helper: %v (output %q)", err, out)
	}
	if !strings.Contains(string(out), fmt.Sprintf("hard=%d", before.Max)) {
		t.Fatalf("hard limit changed; helper reported %q, inherited hard=%d",
			strings.TrimSpace(string(out)), before.Max)
	}
}

// ---------------------------------------------------------------------------
// Config floors.
// ---------------------------------------------------------------------------

// TestDefaultConfig_ClampsToolMemoryToFloor verifies that an operator cannot
// configure a tool ceiling so low that no Go-based tool in this image can
// reach main(). Measured: a trivial Go binary dies under an RLIMIT_AS of
// 512 MiB, and httpx and nuclei are Go binaries. Below the floor the value
// stops being a tighter sandbox and becomes an outage.
func TestDefaultConfig_ClampsToolMemoryToFloor(t *testing.T) {
	t.Setenv(sandbox.EnvMemoryBytes, "16777216") // 16 MiB
	cfg := sandbox.DefaultConfig()
	if cfg.MemoryBytes != sandbox.MinToolMemoryBytes {
		t.Fatalf("MemoryBytes = %d; want the %d floor", cfg.MemoryBytes, uint64(sandbox.MinToolMemoryBytes))
	}
}

// TestDefaultConfig_SelfLimitCoversTheOutputCap verifies that raising the
// output cap cannot leave the runner with a ceiling below what its own
// buffering is allowed to consume.
func TestDefaultConfig_SelfLimitCoversTheOutputCap(t *testing.T) {
	// 1 GiB per stream — far above the 3 GiB default self limit once the
	// per-stream doubling headroom is accounted for.
	t.Setenv(sandbox.EnvOutputCapBytes, strconv.Itoa(1024*1024*1024))
	cfg := sandbox.DefaultConfig()
	floor := sandbox.SelfMemoryFloor(cfg.OutputCapBytes)
	if cfg.SelfMemoryBytes < floor {
		t.Fatalf("SelfMemoryBytes = %d; below the %d floor implied by a %d output cap",
			cfg.SelfMemoryBytes, floor, cfg.OutputCapBytes)
	}
}

// TestSelfMemoryFloor_GrowsWithTheCap pins the relationship rather than the
// constants: the floor must respond to the output cap, since the cap is what
// the runner is allowed to buffer.
func TestSelfMemoryFloor_GrowsWithTheCap(t *testing.T) {
	t.Parallel()
	small := sandbox.SelfMemoryFloor(100 * 1024 * 1024)
	large := sandbox.SelfMemoryFloor(1024 * 1024 * 1024)
	if large <= small {
		t.Fatalf("floor did not grow with the output cap: %d -> %d", small, large)
	}
	if small <= 2*100*1024*1024 {
		t.Fatalf("floor %d does not even cover both streams at the cap", small)
	}
}

// TestApply_PreExecSurvivesTightLimitRepeatedly is the regression test for
// #356: the pre-exec helper must not allocate on the Go heap between
// setrlimit(2) and execve(2).
//
// It used to. syscall.Exec builds its C string vectors with
// SlicePtrFromStrings, and when one of those allocations needed a fresh span
// the runtime mmap'd under the RLIMIT_AS just installed, got refused, and
// threw "fatal error: runtime: out of memory" — killing the launcher with
// status 2 before the tool ever started, so the caller saw an exit code that
// looked like the tool's own.
//
// Whether the allocator needed a new span was luck, so the bug surfaced as a
// low-rate flake rather than a clean failure: measured at 1/20 runs for a
// 987 MiB limit and 0/20 for both larger and smaller ones. A single launch
// therefore proves nothing; this repeats enough times to make the old
// behaviour reliably visible, and asserts on the exact signature so a
// regression cannot be mistaken for an unrelated failure.
func TestApply_PreExecSurvivesTightLimitRepeatedly(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("/proc/self/limits is Linux-only")
	}
	catPath, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("cat not available")
	}

	// Limits spanning the range where the old code failed, including the
	// 987 MiB value from the original flake.
	for _, mib := range []int{987, 512, 128} {
		limit := uint64(mib) * 1024 * 1024
		for i := range 25 {
			cmd := exec.Command(catPath, "/proc/self/limits")
			if err := sandbox.Apply(cmd, sandbox.Config{
				OutputCapBytes: 1 << 20,
				MemoryBytes:    limit,
			}); err != nil {
				t.Fatalf("Apply (limit %d MiB): %v", mib, err)
			}
			var out, errOut sandbox.CappedBuffer
			out.Init(1 << 20)
			errOut.Init(1 << 20)
			cmd.Stdout = &out
			cmd.Stderr = &errOut

			if err := cmd.Run(); err != nil {
				stderr := string(errOut.Bytes())
				if strings.Contains(stderr, "out of memory") {
					t.Fatalf("iteration %d at %d MiB: the launcher OOM'd applying "+
						"its own limit — an allocation crept back in between "+
						"setrlimit and execve.\nerr: %v\nstderr: %s", i, mib, err, stderr)
				}
				t.Fatalf("iteration %d at %d MiB: %v\nstdout: %s\nstderr: %s",
					i, mib, err, out.Bytes(), stderr)
			}

			// The tool really ran, and really got the limit.
			if !strings.Contains(string(out.Bytes()), "Max address space") {
				t.Fatalf("iteration %d at %d MiB: no limits output; got %q",
					i, mib, out.Bytes())
			}
			if !strings.Contains(string(out.Bytes()), strconv.FormatUint(limit, 10)) {
				t.Fatalf("iteration %d at %d MiB: RLIMIT_AS not applied; got %q",
					i, mib, out.Bytes())
			}
		}
	}
}
