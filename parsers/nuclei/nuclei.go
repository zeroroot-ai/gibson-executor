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

// nucleiEvent is the subset of nuclei's -jsonl output we consume.
//
// Every field here has to reach the emitted DiscoveryResult. Six of them were
// decoded and dropped (gibson-executor#89): a finding lost its reproduction
// command, its extracted proof, its CWE, its CVSS vector, the protocol that
// matched and the host it matched on. Host becomes the Finding's parent; the
// rest become Evidence nodes, which is how kubebench and trivy-k8s already
// carry per-finding proof.
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
		appendFinding(disc, ev)
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

// appendFinding maps one nuclei event to a Finding plus its Evidence nodes.
//
// It appends rather than returning a Finding because the proof travels beside
// the finding, not inside it: graphrag's Finding has eleven fields and none of
// them holds a reproduction command, an extracted value, a CWE or a CVSS
// vector. DiscoveryResult.Evidence does, keyed by finding id.
func appendFinding(disc *graphragpb.DiscoveryResult, ev nucleiEvent) {
	title := ev.Info.Name
	if title == "" {
		title = ev.TemplateID
	}
	if title == "" {
		return
	}
	findingID := fmt.Sprintf("finding:%s:%s", ev.TemplateID, ev.MatchedAt)
	f := &graphragpb.Finding{
		Id:       proto.String(findingID),
		Title:    title,
		Severity: normaliseSeverity(ev.Info.Severity),
	}
	if ev.Info.Description != "" {
		f.Description = proto.String(ev.Info.Description)
	}
	if ev.Info.Remediation != "" {
		f.Remediation = proto.String(ev.Info.Remediation)
	}
	if len(ev.Info.Classification.CveID) > 0 {
		f.CveIds = proto.String(strings.Join(ev.Info.Classification.CveID, ","))
	}
	if len(ev.Info.Tags) > 0 {
		f.Category = proto.String(strings.Join(ev.Info.Tags, ","))
	}
	// The host nuclei matched on is the finding's parent.
	if ev.Host != "" {
		f.ParentId = proto.String(ev.Host)
	}
	disc.Findings = append(disc.Findings, f)
	appendEvidence(disc, findingID, ev)
}

// Evidence type slugs. One per kind of proof, so a graph query can ask for
// reproduction commands without parsing a blob. The naming follows the
// convention kubebench and trivy-k8s already set: <tool>-<kind>.
const (
	evidenceReproduction = "nuclei-reproduction"
	evidenceExtracted    = "nuclei-extracted-result"
	evidenceCWE          = "nuclei-cwe"
	evidenceCVSSVector   = "nuclei-cvss-vector"
	evidenceProtocol     = "nuclei-protocol"
)

// appendEvidence records the proof nuclei supplied for one finding. Each node
// is emitted only when nuclei actually gave the value, so a template that
// carries no classification produces no empty nodes.
//
// MatchedAt is the URL on every node that has one: an operator reading the
// proof needs to know where it came from, and the finding id alone encodes it
// only by convention.
func appendEvidence(disc *graphragpb.DiscoveryResult, findingID string, ev nucleiEvent) {
	add := func(kind, content string, withURL bool) {
		if content == "" {
			return
		}
		e := &graphragpb.Evidence{
			Id:        proto.String(findingID + ":" + kind),
			FindingId: findingID,
			Type:      kind,
			Content:   proto.String(content),
		}
		if withURL && ev.MatchedAt != "" {
			e.Url = proto.String(ev.MatchedAt)
		}
		disc.Evidence = append(disc.Evidence, e)
	}

	// The curl command nuclei prints is the whole reproduction: without it a
	// reader has a claim and no way to check it.
	add(evidenceReproduction, strings.TrimSpace(ev.CurlCommand), true)
	// Extracted results are the matched values themselves: the version
	// banner, the leaked path, the response fragment that matched. One per
	// line, in nuclei's order.
	add(evidenceExtracted, strings.Join(ev.ExtractedResults, "\n"), true)
	add(evidenceCWE, strings.Join(ev.Info.Classification.CweID, ","), false)
	add(evidenceCVSSVector, strings.TrimSpace(ev.Info.Classification.CvssMetrics), false)
	// The protocol the template matched over (http, dns, tcp, ssl...). It is
	// not a tag, so it does not belong in Category beside info.tags.
	add(evidenceProtocol, strings.TrimSpace(ev.Type), true)
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
