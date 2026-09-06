// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package dnsx wraps ProjectDiscovery's dnsx DNS toolkit.
// Emits Host + Subdomain nodes for each resolved record.
package dnsx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

const (
	toolName       = "dnsx"
	toolVersion    = "0.1.0"
	defaultTimeout = 300
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:                  toolName,
		Version:               toolVersion,
		Description:           "DNS resolver + record enumerator (ProjectDiscovery dnsx). Emits Host nodes for resolved A/AAAA records.",
		Tags:                  []string{"recon", "dns"},
		InputSchema:           map[string]any{"type": "object", "properties": map[string]any{"target": map[string]any{"type": "string"}}, "required": []any{"target"}},
		OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
		DefaultParseQuality:   registry.ParseQualityStructured,
		Resources:             registry.ResourceHint{VCPU: 1, Memory: "256Mi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

func (p *parser) OutputMessage() proto.Message { return nil }

type dnsxRecord struct {
	Host string   `json:"host"`
	A    []string `json:"a"`
	AAAA []string `json:"aaaa"`
}

// buildArgs composes the dnsx argv. dnsx reads its subject list from
// `-l /dev/stdin`, one target per line, so the target never touches the
// argv — but a newline inside it turns one line into several. Target
// validation rejects control characters, which is what makes the stdin
// write in Execute a single-target write.
func buildArgs(req registry.ExecuteRequest) ([]string, error) {
	if err := registry.ValidateTarget(toolName, req.Target); err != nil {
		return nil, fmt.Errorf("dnsx target: %w", err)
	}
	args := []string{"-json", "-silent", "-l", "/dev/stdin", "-a", "-aaaa"}
	filtered, err := registry.ApplyPolicy(toolName, req.Args, nil)
	if err != nil {
		return nil, err
	}
	return append(args, filtered...), nil
}

func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	args, argErr := buildArgs(req)
	if argErr != nil {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed}, argErr
	}
	sbCfg := sandbox.DefaultConfig()
	var stdout, stderr sandbox.CappedBuffer
	stdout.Init(sbCfg.OutputCapBytes)
	stderr.Init(sbCfg.OutputCapBytes)
	cmd := exec.CommandContext(ctx, "dnsx", args...)
	if err := sandbox.Apply(cmd, sbCfg); err != nil {
		// No resource ceiling means no run: an unbounded tool child is the
		// condition the sandbox exists to prevent, so fail closed.
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("dnsx sandbox: %w", err)
	}
	cmd.Stdin = bytes.NewReader([]byte(req.Target + "\n"))
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		resp.ExitCode = int32(cmd.ProcessState.ExitCode())
	}
	if err := stdout.Err(); err != nil {
		return resp, fmt.Errorf("dnsx stdout: %w", err)
	}
	disc, quality, parseErr := parseJSONLines(stdout.Bytes())
	resp.Discovery = disc
	resp.ParseQuality = quality
	if runErr != nil && len(stdout.Bytes()) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("dnsx exec: %w", runErr)
	}
	return resp, parseErr
}

func parseJSONLines(raw []byte) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	lines := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r dnsxRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", lines+1, err)
		}
		lines++
		for _, ip := range r.A {
			hostID := fmt.Sprintf("host:%s", ip)
			hn := r.Host
			disc.Hosts = append(disc.Hosts, &graphragpb.Host{
				Id:       &hostID,
				Ip:       ip,
				Hostname: &hn,
			})
		}
		for _, ip := range r.AAAA {
			hostID := fmt.Sprintf("host:%s", ip)
			hn := r.Host
			disc.Hosts = append(disc.Hosts, &graphragpb.Host{
				Id:       &hostID,
				Ip:       ip,
				Hostname: &hn,
			})
		}
	}
	if err := sc.Err(); err != nil {
		return disc, registry.ParseQualityPartial, err
	}
	return disc, registry.ParseQualityStructured, nil
}
