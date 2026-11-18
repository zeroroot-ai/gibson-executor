// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package nuclei

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

func TestParseJSONLines_TwoFindings(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "simple.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, quality, err := parseJSONLines(raw)
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Errorf("quality = %d; want STRUCTURED", quality)
	}
	if got, want := len(disc.Findings), 3; got != want {
		t.Fatalf("findings = %d; want %d", got, want)
	}

	crit := disc.Findings[0]
	if crit.Title != "Apache HTTPD RCE via mod_whatever" {
		t.Errorf("finding[0].title = %q", crit.Title)
	}
	if crit.Severity != "critical" {
		t.Errorf("finding[0].severity = %q; want critical", crit.Severity)
	}
	if crit.CveIds == nil || *crit.CveIds != "CVE-2023-12345" {
		t.Errorf("finding[0].cve_ids = %v", crit.CveIds)
	}

	info := disc.Findings[1]
	if info.Severity != "info" {
		t.Errorf("finding[1].severity = %q; want info", info.Severity)
	}
}

func TestParseJSONLines_EmptyCleanRun(t *testing.T) {
	// A silent success from nuclei is meaningful: "scanned, no findings" is
	// still a structured result. Confirm quality reports STRUCTURED, not RAW.
	_, quality, err := parseJSONLines(nil)
	if err != nil {
		t.Fatalf("error on empty input: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Errorf("quality = %d; want STRUCTURED (clean run, zero findings)", quality)
	}
}

func TestNormaliseSeverity(t *testing.T) {
	tests := map[string]string{
		"Critical":       "critical",
		"HIGH":           "high",
		"medium":         "medium",
		"low":            "low",
		"Info":           "info",
		"informational":  "info",
		"unknown":        "info",
		"":               "info",
		"unexpected-val": "unexpected-val",
	}
	for in, want := range tests {
		if got := normaliseSeverity(in); got != want {
			t.Errorf("normaliseSeverity(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestRegistryIntegration(t *testing.T) {
	if _, ok := registry.Lookup(toolName); !ok {
		t.Fatalf("registry.Lookup(%q) = false", toolName)
	}
}

// TestParseJSONLines_HostIsTheFindingsParent covers nucleiEvent.Host, which was
// also decoded and dropped: a finding named a template and a matched URL but
// never said which host it was about in a field the graph can traverse.
func TestParseJSONLines_HostIsTheFindingsParent(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "simple.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, _, err := parseJSONLines(raw)
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	for i, f := range disc.Findings {
		if f.GetParentId() != "http://scanme.nmap.org" {
			t.Errorf("finding[%d].parent_id = %q; want the nuclei host", i, f.GetParentId())
		}
	}
}

// TestDescribe_MemoryHeadroom locks the sandbox memory the daemon gives nuclei.
// 1Gi OOM-killed nuclei in the Firecracker guest on staging (gibson#1356), so
// the hint must not fall back below 2Gi.
func TestDescribe_MemoryHeadroom(t *testing.T) {
	got := (&parser{}).Describe().Resources.Memory
	if got != "2Gi" {
		t.Fatalf("nuclei sandbox memory hint = %q, want 2Gi (gibson#1356)", got)
	}
}

// TestExecute_RaisesAddressSpaceCeiling proves nuclei lifts RLIMIT_AS above the
// 2 GiB default, like trivy, so its Go arena reservation does not fail at
// startup. The override is a max, so it only ever raises the ceiling.
func TestExecute_RaisesAddressSpaceCeiling(t *testing.T) {
	if nucleiAddressSpaceBytes <= sandbox.DefaultConfig().MemoryBytes {
		t.Fatalf("nucleiAddressSpaceBytes %d must exceed the default RLIMIT_AS %d", nucleiAddressSpaceBytes, sandbox.DefaultConfig().MemoryBytes)
	}
}

// evidenceByKind indexes the evidence items of one finding by the metadata key
// "kind".
func evidenceByKind(disc *graphragpb.DiscoveryResult, findingID string) map[string]*typespb.Evidence {
	out := map[string]*typespb.Evidence{}
	for _, fe := range disc.GetFindingEvidence() {
		if fe.GetFindingId() == findingID {
			out[fe.GetEvidence().GetMetadata()["kind"]] = fe.GetEvidence()
		}
	}
	return out
}

// TestParseJSONLines_EvidenceCarriesTheProof is gibson-executor#89.
//
// The curl command, the extracted results, the CWE ids and the CVSS vector of
// nuclei have no field on the graphrag Finding. They travel as evidence items
// of the finding. The parser sets no tier and no tool call ID.
func TestParseJSONLines_EvidenceCarriesTheProof(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "simple.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, _, err := parseJSONLines(raw)
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}

	leak := disc.Findings[2]
	if leak.Title != "Server version disclosed in response headers" {
		t.Fatalf("finding[2].title = %q", leak.Title)
	}
	ev := evidenceByKind(disc, leak.GetId())

	repro, ok := ev[evidenceReproduction]
	if !ok {
		t.Fatalf("no %s evidence; the finding cannot be reproduced", evidenceReproduction)
	}
	if !strings.Contains(repro.GetContent(), "curl -X 'GET'") {
		t.Errorf("reproduction content = %q; want the curl command", repro.GetContent())
	}
	if repro.GetType() != typespb.EvidenceType_EVIDENCE_TYPE_REQUEST {
		t.Errorf("reproduction type = %v; want REQUEST", repro.GetType())
	}
	if got := repro.GetMetadata()["url"]; got != "http://scanme.nmap.org/static/app.js" {
		t.Errorf("reproduction url = %q; want matched-at", got)
	}

	extracted, ok := ev[evidenceExtracted]
	if !ok {
		t.Fatalf("no %s evidence; the matched values are the proof", evidenceExtracted)
	}
	for _, want := range []string{"Apache/2.4.49 (Unix)", "X-Powered-By: PHP/5.6.40"} {
		if !strings.Contains(extracted.GetContent(), want) {
			t.Errorf("extracted content %q does not carry %q", extracted.GetContent(), want)
		}
	}
	if extracted.GetType() != typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE {
		t.Errorf("extracted type = %v; want RESPONSE", extracted.GetType())
	}

	if got := ev[evidenceCWE].GetContent(); got != "CWE-200,CWE-497" {
		t.Errorf("cwe evidence = %q; want both ids in the order of nuclei", got)
	}
	if got := ev[evidenceCVSSVector].GetContent(); got != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" {
		t.Errorf("cvss vector evidence = %q", got)
	}
	if got := ev[evidenceProtocol].GetContent(); got != "http" {
		t.Errorf("protocol evidence = %q; want http", got)
	}

	// The parser never sets the tier or the tool call ID. The daemon does.
	// Every item must name a finding that is in the result.
	ids := map[string]bool{}
	for _, f := range disc.Findings {
		ids[f.GetId()] = true
	}
	for _, fe := range disc.GetFindingEvidence() {
		e := fe.GetEvidence()
		if e.GetTier() != typespb.EvidenceTier_EVIDENCE_TIER_UNSPECIFIED || e.GetToolCallId() != "" {
			t.Errorf("evidence %q has a tier or a tool call id that the parser set", e.GetTitle())
		}
		if !ids[fe.GetFindingId()] {
			t.Errorf("evidence %q points at finding %q, which is not in the result", e.GetTitle(), fe.GetFindingId())
		}
	}
}

// TestParseJSONLines_FindingIDIsStable pins that the finding ID, which the
// evidence uses as its key, is the same for the same tool output.
func TestParseJSONLines_FindingIDIsStable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "simple.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	a, _, err := parseJSONLines(raw)
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	b, _, err := parseJSONLines(raw)
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	if len(a.Findings) == 0 || len(a.Findings) != len(b.Findings) {
		t.Fatalf("findings: %d and %d", len(a.Findings), len(b.Findings))
	}
	for i := range a.Findings {
		if a.Findings[i].GetId() == "" || a.Findings[i].GetId() != b.Findings[i].GetId() {
			t.Errorf("finding[%d] id %q and %q differ or are empty", i, a.Findings[i].GetId(), b.Findings[i].GetId())
		}
	}
}

// TestParseJSONLines_NoEvidenceWhenNucleiGaveNone keeps the mapping honest in
// the other direction. The exposed-panel fixture line carries no curl command,
// no extracted results and no classification, so it must produce no evidence
// but the protocol. An empty item would assert proof that does not exist.
func TestParseJSONLines_NoEvidenceWhenNucleiGaveNone(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "simple.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, _, err := parseJSONLines(raw)
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	ev := evidenceByKind(disc, disc.Findings[1].GetId())
	for _, kind := range []string{evidenceReproduction, evidenceExtracted, evidenceCWE, evidenceCVSSVector} {
		if _, ok := ev[kind]; ok {
			t.Errorf("%s evidence emitted for a finding nuclei gave none for", kind)
		}
	}
	if _, ok := ev[evidenceProtocol]; !ok {
		t.Errorf("protocol evidence missing; nuclei did report type=http for this line")
	}
}
