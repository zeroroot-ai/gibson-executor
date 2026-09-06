// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package masscan wraps the masscan high-speed port scanner. Masscan emits
// line-delimited JSON of the form `{"ip":..., "ports":[{"port":..., "proto":"tcp"}]}`.
// Emits Host + Port nodes.
package masscan

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
	toolName       = "masscan"
	toolVersion    = "0.1.0"
	defaultTimeout = 600
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:                  toolName,
		Version:               toolVersion,
		Description:           "High-throughput port scanner (masscan). Emits Host/Port nodes for open ports across large CIDR ranges.",
		Tags:                  []string{"recon", "network", "scan"},
		InputSchema:           map[string]any{"type": "object", "properties": map[string]any{"target": map[string]any{"type": "string"}, "ports": map[string]any{"type": "string"}, "rate": map[string]any{"type": "string"}}, "required": []any{"target", "ports"}},
		OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
		DefaultParseQuality:   registry.ParseQualityStructured,
		Resources:             registry.ResourceHint{VCPU: 4, Memory: "2Gi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

func (p *parser) OutputMessage() proto.Message { return nil }

type masscanPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type masscanRecord struct {
	IP    string        `json:"ip"`
	Ports []masscanPort `json:"ports"`
}

// buildArgs composes the masscan argv. req.Options["ports"] and
// req.Options["rate"] are routed through the tool's own args allowlist so
// they cannot reach the argv on softer terms than `-p` / `--rate` in
// req.Args would, and req.Target is validated as an IP or CIDR before it
// is spliced in.
//
// masscan parses its argv with a hand-rolled loop rather than getopt, and
// its documentation names no `--` end-of-options terminator, so no
// terminator is emitted here: target validation is the whole control for
// the positional. That is why the accepted target kinds for masscan are
// the narrowest of any parser — an address or a prefix, never a name.
func buildArgs(req registry.ExecuteRequest) ([]string, error) {
	if err := registry.ValidateTarget(toolName, req.Target); err != nil {
		return nil, fmt.Errorf("masscan target: %w", err)
	}

	ports := req.Options["ports"]
	if ports == "" {
		ports = "1-65535"
	}
	rate := req.Options["rate"]
	if rate == "" {
		rate = "1000"
	}

	ratePair, err := registry.ApplyOption(toolName, "--rate", rate, nil)
	if err != nil {
		return nil, fmt.Errorf("masscan rate option: %w", err)
	}
	portPair, err := registry.ApplyOption(toolName, "-p", ports, nil)
	if err != nil {
		return nil, fmt.Errorf("masscan ports option: %w", err)
	}

	filtered, err := registry.ApplyPolicy(toolName, req.Args, nil)
	if err != nil {
		return nil, err
	}

	args := make([]string, 0, len(ratePair)+len(portPair)+len(filtered)+3)
	args = append(args, ratePair...)
	args = append(args, portPair...)
	args = append(args, "-oJ", "-", req.Target)
	args = append(args, filtered...)
	return args, nil
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
	cmd := exec.CommandContext(ctx, "masscan", args...)
	if err := sandbox.Apply(cmd, sbCfg); err != nil {
		// No resource ceiling means no run: an unbounded tool child is the
		// condition the sandbox exists to prevent, so fail closed.
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("masscan sandbox: %w", err)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		resp.ExitCode = int32(cmd.ProcessState.ExitCode())
	}
	if err := stdout.Err(); err != nil {
		return resp, fmt.Errorf("masscan stdout: %w", err)
	}
	disc, quality, parseErr := parseJSON(stdout.Bytes())
	resp.Discovery = disc
	resp.ParseQuality = quality
	if runErr != nil && len(stdout.Bytes()) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("masscan exec: %w", runErr)
	}
	return resp, parseErr
}

// parseJSON handles masscan's -oJ output — it emits a JSON array prefixed
// with comma-separated objects (non-strict). We handle both valid arrays
// and the streaming-friendly line-delimited form.
func parseJSON(raw []byte) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	seenHosts := map[string]string{}

	// Strip the array brackets if present, process each JSON object
	// independently. This tolerates masscan's non-standard trailing comma.
	body := bytes.TrimSpace(raw)
	body = bytes.TrimPrefix(body, []byte("["))
	body = bytes.TrimSuffix(body, []byte("]"))

	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	lines := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		line = bytes.TrimSuffix(line, []byte(","))
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r masscanRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", lines+1, err)
		}
		lines++
		hostID, seen := seenHosts[r.IP]
		if !seen {
			hostID = fmt.Sprintf("host:%s", r.IP)
			seenHosts[r.IP] = hostID
			disc.Hosts = append(disc.Hosts, &graphragpb.Host{Id: &hostID, Ip: r.IP})
		}
		for _, p := range r.Ports {
			proto := p.Proto
			if proto == "" {
				proto = "tcp"
			}
			portID := fmt.Sprintf("%s:port:%s/%d", hostID, proto, p.Port)
			port := &graphragpb.Port{
				Id: &portID, HostId: hostID, Number: int32(p.Port), Protocol: proto,
			}
			if p.Status != "" {
				s := p.Status
				port.State = &s
			}
			if p.Reason != "" {
				reason := p.Reason
				port.Reason = &reason
			}
			disc.Ports = append(disc.Ports, port)
		}
	}
	if err := sc.Err(); err != nil {
		return disc, registry.ParseQualityPartial, err
	}
	return disc, registry.ParseQualityStructured, nil
}
