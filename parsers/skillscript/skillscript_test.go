// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package skillscript

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

// TestMain lets the test binary serve as the re-exec target of the sandbox,
// as the runner binary does in main.
func TestMain(m *testing.M) {
	sandbox.RunPreExec()
	os.Exit(m.Run())
}

// dirMode is the mode of the directories of a placed tree. It is a variable
// because a runner that the test starts as another user must enter them.
var dirMode os.FileMode = 0o755

// place writes the files below a temporary root and returns the root.
func place(t *testing.T, files map[string]struct {
	body string
	mode os.FileMode
}) string {
	t.Helper()
	return placeIn(t, t.TempDir(), files)
}

// placeIn writes the files below root, with the given modes, and returns root.
func placeIn(t *testing.T, root string, files map[string]struct {
	body string
	mode os.FileMode
}) string {
	t.Helper()
	for rel, f := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), dirMode); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f.body), f.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, f.mode); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

type file = struct {
	body string
	mode os.FileMode
}

func run(t *testing.T, root, target string, args ...string) (*registry.ExecuteResponse, result, error) {
	t.Helper()
	p := &parser{root: root}
	resp, err := p.Execute(t.Context(), registry.ExecuteRequest{Target: target, Args: args})
	var out result
	if err == nil {
		if jerr := json.Unmarshal([]byte(resp.OutputJSON), &out); jerr != nil {
			t.Fatalf("output_json %q: %v", resp.OutputJSON, jerr)
		}
	}
	return resp, out, err
}

func TestExecute_RunsAPlacedScriptWithItsArguments(t *testing.T) {
	root := place(t, map[string]file{
		"skill/scripts/run.sh": {"#!/bin/sh\necho \"hello $1\"\necho err >&2\nexit 0\n", 0o555},
	})
	resp, out, err := run(t, root, "skill/scripts/run.sh", "world")
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode != 0 || out.Stdout != "hello world\n" || out.Stderr != "err\n" {
		t.Fatalf("result = %+v", out)
	}
	if resp.ParseQuality != registry.ParseQualityRaw {
		t.Fatalf("quality = %v", resp.ParseQuality)
	}
}

func TestExecute_ANonZeroExitIsAResult(t *testing.T) {
	root := place(t, map[string]file{"skill/fail.sh": {"#!/bin/sh\necho no\nexit 7\n", 0o555}})
	_, out, err := run(t, root, "skill/fail.sh")
	if err != nil || out.ExitCode != 7 || out.Stdout != "no\n" {
		t.Fatalf("result = %+v, err = %v", out, err)
	}
}

func TestExecute_TheScriptSeesNoEnvironmentOfTheRunner(t *testing.T) {
	t.Setenv("GIBSON_SECRET_TOKEN", "hunter2")
	t.Setenv("GIBSON_TOOL_INPUT_B64", "input")
	root := place(t, map[string]file{"skill/env.sh": {"#!/bin/sh\nenv\n", 0o555}})
	_, out, err := run(t, root, "skill/env.sh")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.Stdout, "hunter2") || strings.Contains(out.Stdout, "GIBSON_") {
		t.Fatalf("the script saw the environment of the runner:\n%s", out.Stdout)
	}
}

func TestExecute_RefusesWhatIsNotAnExecutableRegularFileInTheRoot(t *testing.T) {
	outside := place(t, map[string]file{"evil.sh": {"#!/bin/sh\necho owned\n", 0o700}})
	root := place(t, map[string]file{
		"skill/plain.txt": {"data", 0o444},
		"skill/ok.sh":     {"#!/bin/sh\ntrue\n", 0o555},
	})
	if err := os.Symlink(outside, filepath.Join(root, "skill", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "evil.sh"), filepath.Join(root, "skill", "evil.sh")); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"no execute bit":       "skill/plain.txt",
		"a directory":          "skill/scripts",
		"a missing file":       "skill/missing.sh",
		"a link out of root":   "skill/evil.sh",
		"a link as directory":  "skill/link/evil.sh",
		"an escape":            "skill/../../etc/passwd",
		"an absolute path":     "/bin/sh",
		"a bare skill name":    "skill",
		"a flag as the target": "-c",
	}
	for name, target := range cases {
		if _, _, err := run(t, root, target); err == nil {
			t.Errorf("%s: %q ran", name, target)
		}
	}
	if _, _, err := run(t, root, "skill/ok.sh"); err != nil {
		t.Fatalf("a plain script failed: %v", err)
	}
}

func TestExecute_RefusesBadArguments(t *testing.T) {
	root := place(t, map[string]file{"skill/ok.sh": {"#!/bin/sh\ntrue\n", 0o555}})
	if _, _, err := run(t, root, "skill/ok.sh", "a\x00b"); err == nil {
		t.Error("a NUL byte in an argument ran")
	}
	if _, _, err := run(t, root, "skill/ok.sh", strings.Repeat("x", maxArgsBytes+1)); err == nil {
		t.Error("arguments above the bound ran")
	}
}

func TestExecute_TheDeadlineStopsTheWholeProcessGroup(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	root := place(t, map[string]file{"skill/slow.sh": {"#!/bin/sh\n(sleep 1; touch " + marker + ") &\nsleep 30\n", 0o555}})
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	p := &parser{root: root}
	if _, err := p.Execute(ctx, registry.ExecuteRequest{Target: "skill/slow.sh"}); err == nil {
		t.Fatal("the deadline gave no error")
	}
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a child of the script survived the deadline")
	}
}

// alive reports whether the process runs. A zombie is dead.
func alive(pid string) bool {
	raw, err := os.ReadFile(filepath.Clean("/proc/" + pid + "/stat"))
	if err != nil {
		return false
	}
	i := bytes.LastIndexByte(raw, ')')
	return i >= 0 && i+2 < len(raw) && raw[i+2] != 'Z'
}

func TestExecute_ABackgroundChildDoesNotOutliveTheCall(t *testing.T) {
	root := place(t, map[string]file{"skill/bg.sh": {"#!/bin/sh\nsleep 60 >/dev/null 2>&1 </dev/null &\necho $!\n", 0o555}})
	_, out, err := run(t, root, "skill/bg.sh")
	if err != nil {
		t.Fatal(err)
	}
	pid := strings.TrimSpace(out.Stdout)
	deadline := time.Now().Add(3 * time.Second)
	for alive(pid) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if alive(pid) {
		if n, cerr := strconv.Atoi(pid); cerr == nil {
			_ = syscall.Kill(n, syscall.SIGKILL)
		}
		t.Fatalf("the background child %s still runs after the call", pid)
	}
}

func TestExecute_CutsOutputAtTheCapAndSaysSo(t *testing.T) {
	root := place(t, map[string]file{
		"skill/big.sh": {"#!/bin/sh\nhead -c 3000000 /dev/zero | tr '\\0' 'a'\n", 0o555},
		// An "é" is two bytes. The cut falls inside one when the output is made of them.
		"skill/utf.sh": {"#!/bin/sh\nhead -c 3000000 /dev/zero | tr '\\0' 'e' | sed 's/e/\xc3\xa9/g'\n", 0o555},
		"skill/bin.sh": {"#!/bin/sh\nprintf '\\377\\376ok'\n", 0o555},
	})
	_, big, err := run(t, root, "skill/big.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !big.StdoutTruncated || len(big.Stdout) != maxStreamBytes || big.StdoutEncoding != "utf-8" || big.StderrTruncated {
		t.Fatalf("big: truncated=%t len=%d enc=%s", big.StdoutTruncated, len(big.Stdout), big.StdoutEncoding)
	}
	_, utf, err := run(t, root, "skill/utf.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !utf.StdoutTruncated || utf.StdoutEncoding != "utf-8" || !utf8.ValidString(utf.Stdout) {
		t.Fatalf("utf: truncated=%t enc=%s valid=%t", utf.StdoutTruncated, utf.StdoutEncoding, utf8.ValidString(utf.Stdout))
	}
	_, bin, err := run(t, root, "skill/bin.sh")
	if err != nil {
		t.Fatal(err)
	}
	raw, derr := base64.StdEncoding.DecodeString(bin.Stdout)
	if bin.StdoutEncoding != "base64" || derr != nil || !bytes.Equal(raw, []byte{0xff, 0xfe, 'o', 'k'}) || bin.StdoutTruncated {
		t.Fatalf("bin: enc=%s out=%q err=%v", bin.StdoutEncoding, bin.Stdout, derr)
	}
}

// helperEnv selects the helper mode of TestMain-less re-exec: the test binary
// starts itself with the secret in its initial environment, as the daemon
// starts the runner, and runs a script that attacks its parent.
const (
	helperEnv  = "SKILLSCRIPT_TEST_HELPER"
	rootEnvVar = "SKILLSCRIPT_TEST_ROOT"
)

// TestHelperProcess is the runner in the attack test. It is not a test when
// helperEnv is unset.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		return
	}
	if mode == "unprotected" {
		protectRunner = func() error { return nil }
	}
	p := &parser{root: os.Getenv(rootEnvVar)}
	resp, err := p.Execute(context.Background(), registry.ExecuteRequest{Target: "skill/attack.sh"})
	if err != nil {
		t.Fatal(err)
	}
	// The result goes out on file descriptor 3, which the parent gave.
	result := os.NewFile(3, "result")
	if _, werr := result.WriteString(resp.OutputJSON); werr != nil {
		t.Fatal(werr)
	}
	_ = result.Close()
}

// nobody is the uid and gid that the helper runner takes when the test runs
// as root. Root passes the /proc checks whatever the dumpable flag says, so
// the control run needs a runner that is not root.
const nobody = 65534

// openMode is the mode of a file that the helper runner, which can be another
// user, must write.
var openMode os.FileMode = 0o666

// copyFile copies the test binary to dst, readable and executable by any user.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(filepath.Clean(src))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(filepath.Clean(dst))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Chmod(dirMode); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// blockingDir returns the first directory on the path of dir, from the top,
// that other users cannot search, or "" when every directory allows it. It
// only reads the modes and changes nothing.
func blockingDir(dir string) string {
	var chain []string
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		chain = append(chain, d)
		if d == filepath.Dir(d) {
			break
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		fi, err := os.Stat(chain[i])
		if err != nil || fi.Mode().Perm()&0o001 == 0 {
			return chain[i]
		}
	}
	return ""
}

// attack runs the helper runner in a mode and returns what the script read
// from the environment of its parent, and what the script wrote to the
// standard output of its parent. Everything the runner touches is in one
// directory that any user can enter, and a runner that would be root runs as
// nobody, so the control run never depends on who runs the test.
func attack(t *testing.T, mode string) (read, channel string) {
	t.Helper()
	// One directory that any user can enter. MkdirTemp makes it in the
	// temporary directory, which any user can enter, so no parent changes.
	shared, err := os.MkdirTemp("", "skillscript-attack")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shared) })
	if err := os.Chmod(shared, dirMode); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		// The helper runs as nobody. Say so plainly when it cannot enter.
		if blocked := blockingDir(shared); blocked != "" {
			t.Fatalf("uid %d cannot enter %s because %s has no search permission for others, so the control run cannot start; set TMPDIR to a directory that every user can enter", nobody, shared, blocked)
		}
	}
	root := placeIn(t, filepath.Join(shared, "files"), map[string]file{"skill/attack.sh": {
		"#!/bin/sh\ntr '\\0' '\\n' < /proc/$PPID/environ 2>&1\nprintf 'FORGED-LINE FORGED-LINE FORGED-LINE\\n' >> /proc/$PPID/fd/1 2>/dev/null\nexit 0\n", 0o555}})
	if err := os.Chmod(filepath.Join(shared, "files"), dirMode); err != nil {
		t.Fatal(err)
	}
	capture, result := filepath.Join(shared, "stdout"), filepath.Join(shared, "result")
	outFile, err := os.Create(filepath.Clean(capture))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outFile.Close() }()
	resultFile, err := os.Create(filepath.Clean(result))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resultFile.Close() }()
	for _, f := range []*os.File{outFile, resultFile} {
		if err := f.Chmod(openMode); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner := filepath.Join(shared, "runner")
	copyFile(t, self, runner)
	env := append(os.Environ(), helperEnv+"="+mode, rootEnvVar+"="+root,
		"GIBSON_SECRET_TOKEN=hunter2", "GIBSON_TOOL_INPUT_B64=call-input")
	attr := &os.ProcAttr{Env: env, Files: []*os.File{nil, outFile, os.Stderr, resultFile}}
	if os.Geteuid() == 0 {
		attr.Sys = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobody, Gid: nobody}}
	}
	proc, err := os.StartProcess(runner, []string{runner, "-test.run=^TestHelperProcess$"}, attr)
	if err != nil {
		t.Fatalf("start the helper runner: %v", err)
	}
	if state, werr := proc.Wait(); werr != nil || !state.Success() {
		t.Fatalf("helper runner: %v %v", state, werr)
	}
	raw, err := os.ReadFile(filepath.Clean(result))
	if err != nil {
		t.Fatal(err)
	}
	var res struct{ Stdout string }
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	captured, err := os.ReadFile(filepath.Clean(capture))
	if err != nil {
		t.Fatal(err)
	}
	return res.Stdout, string(captured)
}

// TestExecute_TheScriptCannotReachTheRunnerThroughProc proves the fix of the
// review: with the runner non-dumpable, a script cannot read the initial
// environment of its parent and cannot write to its output channel. The
// control run without the protection proves that the test sees the attack.
func TestExecute_TheScriptCannotReachTheRunnerThroughProc(t *testing.T) {
	read, channel := attack(t, "protected")
	if strings.Contains(read, "hunter2") || strings.Contains(read, "GIBSON_TOOL_INPUT_B64") {
		t.Error("the script read the environment of the runner")
	}
	if strings.Contains(channel, "FORGED") {
		t.Error("the script wrote to the output channel of the runner")
	}
	read, channel = attack(t, "unprotected")
	if !strings.Contains(read, "hunter2") || !strings.Contains(channel, "FORGED") {
		t.Errorf("the control run did not show the attack: read the secret=%t, forged the channel=%t",
			strings.Contains(read, "hunter2"), strings.Contains(channel, "FORGED"))
	}
}

func TestExecute_MissingSkillFilesAreAnError(t *testing.T) {
	p := &parser{root: filepath.Join(t.TempDir(), "none")}
	if _, err := p.Execute(t.Context(), registry.ExecuteRequest{Target: "skill/a.sh"}); err == nil {
		t.Fatal("ran with no skill files")
	}
}

func TestDescribe(t *testing.T) {
	d := (&parser{}).Describe()
	if d.Name != "skill-script" || d.OutputProtoType == "" || d.DefaultTimeoutSeconds <= 0 {
		t.Fatalf("catalog entry = %+v", d)
	}
}
