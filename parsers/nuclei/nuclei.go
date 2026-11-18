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
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/extraction"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

const (
	toolName       = "nuclei"
	toolVersion    = "0.1.0"
	defaultTimeout = 600

	// nuclei is a Go binary that loads its whole template set and reserves a
	// large sparse arena before it maps anything. RLIMIT_AS caps ADDRESS SPACE,
	// not resident memory, so the 2 GiB DefaultConfig ceiling leaves no room for
	// the arena and nuclei dies at startup with a runtime-fatal "cannot allocate
	// memory" (gibson#1356) — the same wall trivy hit. 8 GiB of address space
	// costs no resident memory; the scan's real footprint is a few hundred MiB.
	nucleiAddressSpaceBytes = 8192 * 1024 * 1024
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
		Resources:             registry.ResourceHint{VCPU: 2, Memory: "2Gi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

// nucleiEvent is the subset of nuclei's -jsonl output we consume.
//
// Every field here has to reach the emitted DiscoveryResult. Six of them were
// decoded and dropped (gibson-executor#89). Host becomes the Finding's parent.
// The other fields become evidence items.
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

	// -disable-update-check stops nuclei from reaching the network to check
	// for a binary or template update on startup. The runtime sandbox has no
	// egress except to the target, so any update attempt fails and the whole
	// run aborts before it loads the bundled templates (gibson-executor#395).
	// With the check off, nuclei loads the pinned set the image ships at
	// NUCLEI_TEMPLATES_DIR and runs fully offline.
	args := []string{"-jsonl", "-silent", "-disable-update-check", "-target", req.Target}
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
	if sbCfg.MemoryBytes < nucleiAddressSpaceBytes {
		sbCfg.MemoryBytes = nucleiAddressSpaceBytes
	}
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
		if err := appendFinding(disc, ev); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", lines, err)
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

// appendFinding maps one nuclei event to a Finding and its evidence items.
//
// The proof travels beside the finding, not inside it. The graphrag Finding
// has no field for a reproduction command, an extracted value, a CWE or a CVSS
// vector. DiscoveryResult.finding_evidence does, keyed by the finding ID. The
// ID comes from the template and the matched URL, so it is the same for the
// same tool output.
func appendFinding(disc *graphragpb.DiscoveryResult, ev nucleiEvent) error {
	title := ev.Info.Name
	if title == "" {
		title = ev.TemplateID
	}
	if title == "" {
		return nil
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
	return appendEvidence(disc, findingID, ev)
}

// Evidence kind slugs. They go in the metadata key "kind", one for each kind
// of proof, so a graph query can ask for reproduction commands without parsing
// a blob. The naming follows the convention of kubebench and trivy-k8s:
// <tool>-<kind>.
const (
	evidenceReproduction = "nuclei-reproduction"
	evidenceExtracted    = "nuclei-extracted-result"
	evidenceCWE          = "nuclei-cwe"
	evidenceCVSSVector   = "nuclei-cvss-vector"
	evidenceProtocol     = "nuclei-protocol"
)

// appendEvidence records the proof that nuclei supplied for one finding. It
// adds an item only when nuclei gave the value, so a template with no
// classification produces no empty item. The parser sets no tier and no tool
// call ID. The daemon sets both.
//
// MatchedAt is the "url" metadata on each item that has one. A reader of the
// proof needs to know where it came from.
func appendEvidence(disc *graphragpb.DiscoveryResult, findingID string, ev nucleiEvent) error {
	var first error
	add := func(kind string, typ typespb.EvidenceType, title, content string, withURL bool) {
		if content == "" || first != nil {
			return
		}
		md := map[string]string{"kind": kind, "template_id": ev.TemplateID}
		if withURL && ev.MatchedAt != "" {
			md["url"] = ev.MatchedAt
		}
		if err := extraction.AddEvidence(disc, findingID, extraction.Evidence{
			Type: typ, Title: title, Content: content, Metadata: md,
		}); err != nil {
			first = fmt.Errorf("nuclei: %w", err)
		}
	}

	// The curl command that nuclei prints is the whole reproduction. Without
	// it a reader has a claim and no way to check it.
	add(evidenceReproduction, typespb.EvidenceType_EVIDENCE_TYPE_REQUEST,
		"nuclei reproduction command", strings.TrimSpace(ev.CurlCommand), true)
	// Extracted results are the matched values: the version banner, the leaked
	// path, the response fragment that matched. One for each line, in the
	// order of nuclei.
	add(evidenceExtracted, typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE,
		"nuclei extracted results", strings.Join(ev.ExtractedResults, "\n"), true)
	add(evidenceCWE, typespb.EvidenceType_EVIDENCE_TYPE_OTHER,
		"nuclei CWE", strings.Join(ev.Info.Classification.CweID, ","), false)
	add(evidenceCVSSVector, typespb.EvidenceType_EVIDENCE_TYPE_OTHER,
		"nuclei CVSS vector", strings.TrimSpace(ev.Info.Classification.CvssMetrics), false)
	// The protocol that the template matched over (http, dns, tcp, ssl). It is
	// not a tag, so it does not belong in Category beside info.tags.
	add(evidenceProtocol, typespb.EvidenceType_EVIDENCE_TYPE_OTHER,
		"nuclei protocol", strings.TrimSpace(ev.Type), true)
	return first
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
