// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package nuclei

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
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

// evidenceByType indexes a DiscoveryResult's Evidence for one finding.
func evidenceByType(disc *graphragpb.DiscoveryResult, findingID string) map[string]*graphragpb.Evidence {
	out := map[string]*graphragpb.Evidence{}
	for _, e := range disc.Evidence {
		if e.GetFindingId() == findingID {
			out[e.GetType()] = e
		}
	}
	return out
}

// TestParseJSONLines_EvidenceCarriesTheProof is gibson-executor#89.
//
// nuclei's curl-command, extracted-results, cwe-id and cvss-metrics were
// decoded into nucleiEvent and never read, so a finding arrived with no way to
// reproduce it, no extracted value, no CWE and no CVSS vector. graphrag's
// Finding has no field for any of them; DiscoveryResult.Evidence does.
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
	ev := evidenceByType(disc, leak.GetId())

	repro, ok := ev[evidenceReproduction]
	if !ok {
		t.Fatalf("no %s evidence; the finding cannot be reproduced", evidenceReproduction)
	}
	if !strings.Contains(repro.GetContent(), "curl -X 'GET'") {
		t.Errorf("reproduction content = %q; want the curl command", repro.GetContent())
	}
	if repro.GetUrl() != "http://scanme.nmap.org/static/app.js" {
		t.Errorf("reproduction url = %q; want matched-at", repro.GetUrl())
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

	if got := ev[evidenceCWE].GetContent(); got != "CWE-200,CWE-497" {
		t.Errorf("cwe evidence = %q; want both ids in nuclei's order", got)
	}
	if got := ev[evidenceCVSSVector].GetContent(); got != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" {
		t.Errorf("cvss vector evidence = %q", got)
	}
	if got := ev[evidenceProtocol].GetContent(); got != "http" {
		t.Errorf("protocol evidence = %q; want http", got)
	}

	// Every Evidence node must name a Finding that is actually in the result.
	// An orphan is worse than a missing one: it reads as proof of something
	// nobody emitted.
	ids := map[string]bool{}
	for _, f := range disc.Findings {
		ids[f.GetId()] = true
	}
	for _, e := range disc.Evidence {
		if !ids[e.GetFindingId()] {
			t.Errorf("evidence %q points at finding %q, which is not in the result", e.GetType(), e.GetFindingId())
		}
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

// TestParseJSONLines_NoEvidenceWhenNucleiGaveNone keeps the mapping honest in
// the other direction. The exposed-panel fixture line carries no curl command,
// no extracted results and no classification, so it must produce no Evidence
// but the protocol — an empty node would assert proof that does not exist.
func TestParseJSONLines_NoEvidenceWhenNucleiGaveNone(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "simple.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, _, err := parseJSONLines(raw)
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	panel := disc.Findings[1]
	ev := evidenceByType(disc, panel.GetId())
	for _, kind := range []string{evidenceReproduction, evidenceExtracted, evidenceCWE, evidenceCVSSVector} {
		if _, ok := ev[kind]; ok {
			t.Errorf("%s evidence emitted for a finding nuclei gave none for", kind)
		}
	}
	if _, ok := ev[evidenceProtocol]; !ok {
		t.Errorf("protocol evidence missing; nuclei did report type=http for this line")
	}
}
