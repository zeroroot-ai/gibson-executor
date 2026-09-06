// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package nuclei implements a Gibson tool-runner parser wrapping
// ProjectDiscovery's nuclei template-based vulnerability scanner. It runs
// `nuclei -jsonl` (one JSON object per finding) and maps each line to a
// taxonomy-aligned Finding node inside a DiscoveryResult.
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

const (
	toolName       = "nuclei"
	toolVersion    = "0.1.0"
	defaultTimeout = 600
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:        toolName,
		Version:     toolVersion,
		Description: "Template-based vulnerability scanner (ProjectDiscovery nuclei). Emits typed Finding nodes with severity + CVSS + MITRE classification when templates supply it.",
		Tags:        []string{"scan", "vulnerability", "web"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target":    map[string]any{"type": "string", "description": "URL or host to scan."},
				"templates": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Template IDs or paths (e.g. cves/2023 or a specific template path). Default: nuclei's built-in default template set."},
				"severity":  map[string]any{"type": "string", "description": `Comma-separated severity filter, e.g. "critical,high".`},
				"args":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Extra nuclei flags."},
			},
			"required": []any{"target"},
		},
		OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
		DefaultParseQuality:   registry.ParseQualityStructured,
		Resources:             registry.ResourceHint{VCPU: 2, Memory: "1Gi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

func (p *parser) OutputMessage() proto.Message { return nil }

// nucleiEvent is the subset of nuclei's -jsonl output we consume. nuclei
// emits many fields; we decode what feeds a Finding and preserve raw output
// in stdout for operators.
type nucleiEvent struct {
	TemplateID       string     `json:"template-id"`
	Info             nucleiInfo `json:"info"`
	Host             string     `json:"host"`
	MatchedAt        string     `json:"matched-at"`
	Type             string     `json:"type"`
	CurlCommand      string     `json:"curl-command"`
	ExtractedResults []string   `json:"extracted-results"`
}

type nucleiInfo struct {
	Name           string               `json:"name"`
	Description    string               `json:"description"`
	Severity       string               `json:"severity"`
	Remediation    string               `json:"remediation"`
	Classification nucleiClassification `json:"classification"`
	Tags           []string             `json:"tags"`
}

type nucleiClassification struct {
	CveID       []string `json:"cve-id"`
	CweID       []string `json:"cwe-id"`
	CvssScore   float64  `json:"cvss-score"`
	CvssMetrics string   `json:"cvss-metrics"`
}

// buildArgs composes the nuclei argv.
//
// `-t` is the flag that matters here. The args allowlist denied it, but
// the option path appended `-t <req.Options["templates"]>` directly, so
// the denial only ever applied to req.Args — the same flag arrived
// unchecked through the other door. Both doors now lead through the same
// allowlist entry and the same templateRef validator.
func buildArgs(req registry.ExecuteRequest) ([]string, error) {
	if err := registry.ValidateTarget(toolName, req.Target); err != nil {
		return nil, fmt.Errorf("nuclei target: %w", err)
	}

	args := []string{"-jsonl", "-silent", "-target", req.Target}
	if sev := req.Options["severity"]; sev != "" {
		pair, err := registry.ApplyOption(toolName, "-severity", sev, nil)
		if err != nil {
			return nil, fmt.Errorf("nuclei severity option: %w", err)
		}
		args = append(args, pair...)
	}
	if tpl := req.Options["templates"]; tpl != "" {
		pair, err := registry.ApplyOption(toolName, "-t", tpl, nil)
		if err != nil {
			return nil, fmt.Errorf("nuclei templates option: %w", err)
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
	cmd := exec.CommandContext(ctx, "nuclei", args...)
	if err := sandbox.Apply(cmd, sbCfg); err != nil {
		// No resource ceiling means no run: an unbounded tool child is the
		// condition the sandbox exists to prevent, so fail closed.
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("nuclei sandbox: %w", err)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}
	if err := stdout.Err(); err != nil {
		return resp, fmt.Errorf("nuclei stdout: %w", err)
	}
	if cmd.ProcessState != nil {
		resp.ExitCode = int32(cmd.ProcessState.ExitCode())
	}

	disc, quality, parseErr := parseJSONLines(stdout.Bytes())
	resp.Discovery = disc
	resp.ParseQuality = quality
	if runErr != nil && len(stdout.Bytes()) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("nuclei exec: %w", runErr)
	}
	if parseErr != nil {
		return resp, fmt.Errorf("nuclei parse: %w", parseErr)
	}
	return resp, nil
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
		var ev nucleiEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", lines+1, err)
		}
		lines++
		if f := toFinding(ev); f != nil {
			disc.Findings = append(disc.Findings, f)
		}
	}
	if err := sc.Err(); err != nil {
		return disc, registry.ParseQualityPartial, err
	}
	if lines == 0 {
		// A clean nuclei run with zero findings is a valid, meaningful result —
		// there genuinely were no matches. Return STRUCTURED with an empty
		// Findings slice so the graph records "scanned, nothing found" rather
		// than "parse quality unknown."
		return disc, registry.ParseQualityStructured, nil
	}
	return disc, registry.ParseQualityStructured, nil
}

func toFinding(ev nucleiEvent) *graphragpb.Finding {
	title := ev.Info.Name
	if title == "" {
		title = ev.TemplateID
	}
	if title == "" {
		return nil
	}
	f := &graphragpb.Finding{
		Title:    title,
		Severity: normaliseSeverity(ev.Info.Severity),
	}
	findingID := fmt.Sprintf("finding:%s:%s", ev.TemplateID, ev.MatchedAt)
	f.Id = &findingID
	if ev.Info.Description != "" {
		d := ev.Info.Description
		f.Description = &d
	}
	if ev.Info.Remediation != "" {
		r := ev.Info.Remediation
		f.Remediation = &r
	}
	if ev.Info.Classification.CvssScore > 0 {
		cs := ev.Info.Classification.CvssScore
		f.CvssScore = &cs
	}
	if len(ev.Info.Classification.CveID) > 0 {
		cve := strings.Join(ev.Info.Classification.CveID, ",")
		f.CveIds = &cve
	}
	if len(ev.Info.Tags) > 0 {
		cat := strings.Join(ev.Info.Tags, ",")
		f.Category = &cat
	}
	return f
}

// normaliseSeverity maps nuclei's severity strings to the canonical set
// used in Gibson findings: "critical", "high", "medium", "low", "info".
func normaliseSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	case "unknown", "":
		return "info"
	default:
		return strings.ToLower(s)
	}
}
