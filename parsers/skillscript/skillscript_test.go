// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package skillscript

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

// TestMain lets the test binary serve as the re-exec target of the sandbox,
// as the runner binary does in main.
func TestMain(m *testing.M) {
	sandbox.RunPreExec()
	os.Exit(m.Run())
}

// place writes a file below a temporary root with mode and returns the root.
func place(t *testing.T, files map[string]struct {
	body string
	mode os.FileMode
}) string {
	t.Helper()
	root := t.TempDir()
	for rel, f := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
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

func TestExecute_TheDeadlineStopsTheScript(t *testing.T) {
	root := place(t, map[string]file{"skill/slow.sh": {"#!/bin/sh\nsleep 30\n", 0o555}})
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	p := &parser{root: root}
	start := time.Now()
	_, err := p.Execute(ctx, registry.ExecuteRequest{Target: "skill/slow.sh"})
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("err = %v after %s, want an error soon", err, time.Since(start))
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
