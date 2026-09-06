// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package nmap implements a Gibson tool-runner parser that wraps the nmap
// CLI. It executes `nmap -oX - <args>`, parses the XML output via the
// Ullaakut/nmap library, and maps the result to taxonomy-aligned
// gibson.graphrag.v1.Host / Port / Service nodes inside a DiscoveryResult.
//
// A parser panic or nmap-exec failure is surfaced as ParseQuality=FAILED
// with the stdout/stderr preserved; the daemon still logs the tool call as
// a successful execution and the operator can diagnose from the raw output.
package nmap

import (
	"context"
	"fmt"
	"os/exec"

	nmaplib "github.com/Ullaakut/nmap/v3"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

const (
	toolName       = "nmap"
	toolVersion    = "0.1.0"
	defaultTimeout = 300 // seconds
)

// init registers the parser at process start. Blank-importing this package
// from cmd/gibson-runner/main.go is sufficient to pull it in.
func init() {
	registry.Register(&parser{})
}

// parser is the nmap parser.
type parser struct{}

// Describe returns the catalog entry rendered by --list-tools.
func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:        toolName,
		Version:     toolVersion,
		Description: "TCP/UDP port scanner with service + OS detection. Returns typed Host/Port/Service nodes for the knowledge graph.",
		Tags:        []string{"recon", "network", "discovery"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{"type": "string", "description": "IPv4/IPv6 address, CIDR, or hostname."},
				"ports":  map[string]any{"type": "string", "description": `Port spec — e.g. "22,80,443" or "1-1024". Default: top-1000.`},
				"args":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Extra CLI flags, e.g. [\"-sV\", \"-O\"]."},
			},
			"required": []any{"target"},
		},
		OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
		DefaultParseQuality:   registry.ParseQualityStructured,
		Resources:             registry.ResourceHint{VCPU: 2, Memory: "512Mi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

// OutputMessage returns nil — v0.1 parsers fill registry.ExecuteResponse
// directly rather than a tool-specific proto.
func (p *parser) OutputMessage() proto.Message { return nil }

// buildArgs composes the nmap argv from the request. Always prepends -oX -
// for XML-on-stdout so parseXML can consume it.
//
// Three controls, in order, because req.Target, req.Options and req.Args
// are three separate writes into the same argv:
//
//   - req.Target is validated against the tool's registered target kinds
//     (IP, CIDR or hostname). Without that, a target of "-oN" is a flag,
//     not a scan subject, and the allowlist below is decoration.
//   - req.Options["ports"] goes through the same allowlist entry and
//     validator as a caller-supplied `-p` in req.Args.
//   - req.Args is filtered by the per-tool allowlist.
//
// The target is placed last, behind a `--` end-of-options terminator.
// nmap parses its argv with getopt_long, which stops interpreting flags
// at `--` and treats everything after it as targets, so the positional
// can no longer be re-read as a flag even if validation is ever loosened.
func buildArgs(req registry.ExecuteRequest) ([]string, error) {
	if err := registry.ValidateTarget(toolName, req.Target); err != nil {
		return nil, fmt.Errorf("nmap target: %w", err)
	}

	args := []string{"-oX", "-"}
	if ports := req.Options["ports"]; ports != "" {
		pair, err := registry.ApplyOption(toolName, "-p", ports, nil)
		if err != nil {
			return nil, fmt.Errorf("nmap ports option: %w", err)
		}
		args = append(args, pair...)
	}

	filtered, err := registry.ApplyPolicy(toolName, req.Args, nil)
	if err != nil {
		return nil, err
	}
	args = append(args, filtered...)
	args = append(args, "--", req.Target)
	return args, nil
}

// Execute runs nmap and returns the parsed DiscoveryResult. When nmap is not
// installed or the invocation fails, ParseQuality=FAILED and the error is
// preserved; the registry contract requires Execute to return a non-nil
// response even on failure so the daemon sees stdout/stderr for diagnostics.
func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	args, policyErr := buildArgs(req)
	if policyErr != nil {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("nmap args policy: %w", policyErr)
	}

	sbCfg := sandbox.DefaultConfig()
	var stdout, stderr sandbox.CappedBuffer
	stdout.Init(sbCfg.OutputCapBytes)
	stderr.Init(sbCfg.OutputCapBytes)
	cmd := exec.CommandContext(ctx, "nmap", args...)
	if err := sandbox.Apply(cmd, sbCfg); err != nil {
		// No resource ceiling means no run: an unbounded tool child is the
		// condition the sandbox exists to prevent, so fail closed.
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("nmap sandbox: %w", err)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}
	if cmd.ProcessState != nil {
		resp.ExitCode = int32(cmd.ProcessState.ExitCode())
	}

	if err := stdout.Err(); err != nil {
		return resp, fmt.Errorf("nmap stdout: %w", err)
	}
	if runErr != nil && len(stdout.Bytes()) == 0 {
		// nmap didn't even produce XML — hard failure.
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("nmap exec: %w", runErr)
	}

	disc, quality, parseErr := parseXML(stdout.Bytes())
	resp.Discovery = disc
	resp.ParseQuality = quality
	if parseErr != nil {
		// Preserve stdout/stderr; caller still gets useful context. Exec may
		// have succeeded but the parser couldn't make sense of the output.
		return resp, fmt.Errorf("nmap parse: %w", parseErr)
	}
	return resp, nil
}

// parseXML converts an nmap XML document to a DiscoveryResult. Broken out
// from Execute so golden tests can drive recorded fixtures without requiring
// nmap to be installed on the CI runner.
func parseXML(xml []byte) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	var run nmaplib.Run
	if err := nmaplib.Parse(xml, &run); err != nil {
		return nil, registry.ParseQualityFailed, err
	}

	disc := &graphragpb.DiscoveryResult{}
	for i := range run.Hosts {
		h := &run.Hosts[i]
		hostNode := hostToProto(h)
		disc.Hosts = append(disc.Hosts, hostNode)

		hostID := ""
		if hostNode.Id != nil {
			hostID = *hostNode.Id
		}

		for j := range h.Ports {
			port := &h.Ports[j]
			portNode := portToProto(port, hostID)
			disc.Ports = append(disc.Ports, portNode)

			if port.Service.Name != "" {
				portID := ""
				if portNode.Id != nil {
					portID = *portNode.Id
				}
				disc.Services = append(disc.Services, serviceToProto(&port.Service, portID))
			}
		}
	}
	return disc, registry.ParseQualityStructured, nil
}

func hostToProto(h *nmaplib.Host) *graphragpb.Host {
	out := &graphragpb.Host{}
	id := stableHostID(h)
	out.Id = &id
	if len(h.Addresses) > 0 {
		out.Ip = h.Addresses[0].Addr
		for _, a := range h.Addresses {
			if a.AddrType == "mac" && out.MacAddress == nil {
				mac := a.Addr
				out.MacAddress = &mac
			}
		}
	}
	if len(h.Hostnames) > 0 {
		hn := h.Hostnames[0].Name
		out.Hostname = &hn
	}
	if s := h.Status.State; s != "" {
		out.State = &s
	}
	if len(h.OS.Matches) > 0 {
		osName := h.OS.Matches[0].Name
		out.Os = &osName
	}
	return out
}

func portToProto(p *nmaplib.Port, hostID string) *graphragpb.Port {
	id := stablePortID(hostID, int32(p.ID), p.Protocol)
	out := &graphragpb.Port{
		Id:       &id,
		HostId:   hostID,
		Number:   int32(p.ID),
		Protocol: p.Protocol,
	}
	if s := p.State.State; s != "" {
		out.State = &s
	}
	if r := p.State.Reason; r != "" {
		out.Reason = &r
	}
	return out
}

func serviceToProto(s *nmaplib.Service, portID string) *graphragpb.Service {
	id := stableServiceID(portID, s.Name)
	out := &graphragpb.Service{
		Id:     &id,
		PortId: portID,
		Name:   s.Name,
	}
	if s.Product != "" {
		p := s.Product
		out.Product = &p
	}
	if s.Version != "" {
		v := s.Version
		out.Version = &v
	}
	if s.ExtraInfo != "" {
		ei := s.ExtraInfo
		out.ExtraInfo = &ei
	}
	return out
}

// stableHostID produces a deterministic ID for a host given its addresses.
// The knowledge-graph merge logic deduplicates by identifying properties,
// so the ID only needs to be unique within a single tool response — a
// stable string from the primary address is plenty and makes test goldens
// diffable.
func stableHostID(h *nmaplib.Host) string {
	if len(h.Addresses) > 0 {
		return "host:" + h.Addresses[0].Addr
	}
	return "host:unknown"
}

func stablePortID(hostID string, number int32, protocol string) string {
	return fmt.Sprintf("%s:port:%s/%d", hostID, protocol, number)
}

func stableServiceID(portID, name string) string {
	return portID + ":service:" + name
}
