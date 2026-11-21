// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package skillscript implements the skill-script tool: it runs a script of a
// loaded Agent Skill that the sandbox launch placed in the machine.
//
// The daemon launches this image with the files of the Agent Skill. Setec
// copies them, read-only, below /setec/files before the runner starts, so the
// script is there from the first instruction. The tool runs the script as the
// agent's own tool call: the same sandbox, the same egress limit, the same
// record of the call as any other tool. It adds no network path and no
// privilege.
//
// The script is the one place where this tool differs from the other
// parsers: it is arbitrary code of the tenant. The boundary is the sandbox,
// not an argument filter. What this tool does is keep the run small and
// predictable:
//
//   - the target is a clean relative path, checked once by the runner and
//     again here, and it must resolve inside /setec/files;
//   - the file must be a regular file with an execute bit, found without a
//     symbolic link on the way out of the directory;
//   - the script runs from an argv, never from a shell string, with a clean
//     environment: the runner's own environment holds the call input and any
//     secret that the daemon gave the tool, and the script gets none of it;
//   - the output is capped, and the call has the deadline of the runner.
package skillscript

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

const (
	toolName       = "skill-script"
	toolVersion    = "0.1.0"
	defaultTimeout = 300 // seconds

	// filesRoot is where the sandbox launch places the files of a skill.
	filesRoot = "/setec/files"

	// maxArgsBytes bounds the argv of the script. It is a size bound only.
	maxArgsBytes = 64 << 10
)

func init() {
	registry.Register(&parser{root: filesRoot})
	registry.RegisterTargetPolicy(toolName, policy.TargetSkillScript)
}

type parser struct {
	// root is the directory that holds the placed files. It is a field so a
	// test can use a temporary directory.
	root string
}

// Describe returns the catalog entry rendered by --list-tools.
func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:        toolName,
		Version:     toolVersion,
		Description: "Runs a script of a loaded Agent Skill that was placed in the sandbox. Returns the exit code, stdout and stderr of the script.",
		Tags:        []string{"agent-skill", "script"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{"type": "string", "description": `Path of the script as "<skill>/<path>", for example "pdf-tools/scripts/extract.sh".`},
				"args":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Arguments of the script."},
			},
			"required": []any{"target"},
		},
		OutputProtoType:       "google.protobuf.Struct",
		DefaultParseQuality:   registry.ParseQualityRaw,
		Resources:             registry.ResourceHint{VCPU: 1, Memory: "512Mi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

// result is the output_json of a call.
type result struct {
	ExitCode int32  `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// Execute runs the script. A script that exits with a non-zero code is a
// result, not an error: the exit code is part of the answer. A script that
// cannot start, a script that the deadline stops, and output above the cap
// are errors.
func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	failed := &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed}
	if err := registry.ValidateTarget(toolName, req.Target); err != nil {
		return failed, fmt.Errorf("skill-script target: %w", err)
	}
	if err := checkArgs(req.Args); err != nil {
		return failed, err
	}
	script, err := p.resolve(req.Target)
	if err != nil {
		return failed, err
	}

	sbCfg := sandbox.DefaultConfig()
	var stdout, stderr sandbox.CappedBuffer
	stdout.Init(sbCfg.OutputCapBytes)
	stderr.Init(sbCfg.OutputCapBytes)
	cmd := exec.CommandContext(ctx, script, req.Args...)
	cmd.Dir = filepath.Dir(script)
	cmd.Env = cleanEnv()
	if err := sandbox.Apply(cmd, sbCfg); err != nil {
		return failed, fmt.Errorf("skill-script sandbox: %w", err)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// A script starts children. The deadline stops the whole process group, not
	// only the script, and the call does not wait for a child that holds a pipe.
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ParseQuality: registry.ParseQualityRaw}
	if cmd.ProcessState != nil {
		if code := cmd.ProcessState.ExitCode(); code >= math.MinInt32 && code <= math.MaxInt32 {
			resp.ExitCode = int32(code)
		}
	}
	if err := stdout.Err(); err != nil {
		return resp, fmt.Errorf("skill-script stdout: %w", err)
	}
	if err := stderr.Err(); err != nil {
		return resp, fmt.Errorf("skill-script stderr: %w", err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return resp, fmt.Errorf("skill-script stopped: %w", ctxErr)
	}
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		return resp, fmt.Errorf("skill-script exec: %w", runErr)
	}
	out, err := json.Marshal(result{ExitCode: resp.ExitCode, Stdout: string(resp.Stdout), Stderr: string(resp.Stderr)})
	if err != nil {
		return resp, fmt.Errorf("skill-script output: %w", err)
	}
	resp.OutputJSON = string(out)
	return resp, nil
}

// resolve returns the absolute path of the script below the root. The path
// must stay inside the root after symbolic links, and must name a regular
// file with an execute bit.
func (p *parser) resolve(rel string) (string, error) {
	root, err := filepath.EvalSymlinks(p.root)
	if err != nil {
		return "", fmt.Errorf("skill-script: the skill files are not in the sandbox: %w", err)
	}
	abs, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return "", fmt.Errorf("skill-script: %q is not a file of a loaded skill: %w", rel, err)
	}
	if !strings.HasPrefix(abs, root+string(filepath.Separator)) {
		return "", fmt.Errorf("skill-script: %q leaves the skill files", rel)
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("skill-script: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("skill-script: %q is not a regular file", rel)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("skill-script: %q has no execute bit; the skill must set the mode of the script", rel)
	}
	return abs, nil
}

// checkArgs applies the size bound of the argv and refuses a NUL byte.
func checkArgs(args []string) error {
	total := 0
	for _, a := range args {
		if strings.ContainsRune(a, 0) {
			return errors.New("skill-script args: an argument holds a NUL byte")
		}
		total += len(a) + 1
	}
	if total > maxArgsBytes {
		return fmt.Errorf("skill-script args: %d bytes, above %d", total, maxArgsBytes)
	}
	return nil
}

// cleanEnv is the environment of the script: a fixed PATH and nothing of the
// environment of the runner.
func cleanEnv() []string {
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "LANG=C.UTF-8"}
}
