// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package naabu wraps ProjectDiscovery's naabu port scanner.
// Emits Host + Port nodes for each discovered open port.
package naabu

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
	toolName       = "naabu"
	toolVersion    = "0.1.0"
	defaultTimeout = 300
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:                  toolName,
		Version:               toolVersion,
		Description:           "Fast port scanner (ProjectDiscovery naabu). Emits Host/Port nodes for each open port.",
		Tags:                  []string{"recon", "network"},
		InputSchema:           map[string]any{"type": "object", "properties": map[string]any{"target": map[string]any{"type": "string"}, "ports": map[string]any{"type": "string"}}, "required": []any{"target"}},
		OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
		DefaultParseQuality:   registry.ParseQualityStructured,
		Resources:             registry.ResourceHint{VCPU: 2, Memory: "512Mi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

func (p *parser) OutputMessage() proto.Message { return nil }

type naabuRecord struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// buildArgs composes the naabu argv. The target rides as the value of
// `-host` rather than as a positional, but that is not on its own a
// control: goflags takes the token after `-host` verbatim, so a target of
// "-p" would simply become the literal host string and a newline would
// split naabu's host list. Validation is what makes the slot safe.
// req.Options["ports"] is routed through the same allowlist entry a
// caller-supplied `-p` would hit.
func buildArgs(req registry.ExecuteRequest) ([]string, error) {
	if err := registry.ValidateTarget(toolName, req.Target); err != nil {
		return nil, fmt.Errorf("naabu target: %w", err)
	}

	args := []string{"-json", "-silent", "-host", req.Target}
	if ports := req.Options["ports"]; ports != "" {
		pair, err := registry.ApplyOption(toolName, "-p", ports, nil)
		if err != nil {
			return nil, fmt.Errorf("naabu ports option: %w", err)
		}
		args = append(args, pair...)
	}

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
	cmd := exec.CommandContext(ctx, "naabu", args...)
	if err := sandbox.Apply(cmd, sbCfg); err != nil {
		// No resource ceiling means no run: an unbounded tool child is the
		// condition the sandbox exists to prevent, so fail closed.
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("naabu sandbox: %w", err)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		resp.ExitCode = int32(cmd.ProcessState.ExitCode())
	}
	if err := stdout.Err(); err != nil {
		return resp, fmt.Errorf("naabu stdout: %w", err)
	}
	disc, quality, parseErr := parseJSONLines(stdout.Bytes())
	resp.Discovery = disc
	resp.ParseQuality = quality
	if runErr != nil && len(stdout.Bytes()) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("naabu exec: %w", runErr)
	}
	return resp, parseErr
}

func parseJSONLines(raw []byte) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	hostsByIP := map[string]string{} // ip → host_id

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	lines := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r naabuRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", lines+1, err)
		}
		lines++
		hostID, seen := hostsByIP[r.IP]
		if !seen {
			hostID = fmt.Sprintf("host:%s", r.IP)
			hostsByIP[r.IP] = hostID
			hn := r.Host
			h := &graphragpb.Host{Id: &hostID, Ip: r.IP}
			if r.Host != "" {
				h.Hostname = &hn
			}
			disc.Hosts = append(disc.Hosts, h)
		}
		portID := fmt.Sprintf("%s:port:tcp/%d", hostID, r.Port)
		disc.Ports = append(disc.Ports, &graphragpb.Port{
			Id:       &portID,
			HostId:   hostID,
			Number:   int32(r.Port),
			Protocol: "tcp",
		})
	}
	if err := sc.Err(); err != nil {
		return disc, registry.ParseQualityPartial, err
	}
	return disc, registry.ParseQualityStructured, nil
}
