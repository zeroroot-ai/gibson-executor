// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package httpx

import (
	"os"
	"strings"
	"testing"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

func loadHeaderGolden(t *testing.T) *graphragpb.DiscoveryResult {
	t.Helper()
	raw, err := os.ReadFile("testdata/headers.jsonl")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, quality, err := parseJSONLines(raw)
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Fatalf("quality = %v, want structured", quality)
	}
	return disc
}

// headerKinds returns the finding kinds recorded against one target.
func headerKinds(disc *graphragpb.DiscoveryResult, target string) map[string]*graphragpb.Finding {
	out := map[string]*graphragpb.Finding{}
	prefix := "finding:header:" + target + ":"
	for _, f := range disc.Findings {
		if id := f.GetId(); strings.HasPrefix(id, prefix) {
			out[strings.TrimPrefix(id, prefix)] = f
		}
	}
	return out
}

func kindNames(m map[string]*graphragpb.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestHeaders_BareServiceReportsEveryMissingHeader is the base case.
func TestHeaders_BareServiceReportsEveryMissingHeader(t *testing.T) {
	got := headerKinds(loadHeaderGolden(t), "https://bare.example.com")
	for _, want := range []string{
		"missing-hsts", "missing-csp", "missing-nosniff",
		"missing-frame-options", "missing-referrer-policy",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("no %s finding; got %v", want, kindNames(got))
		}
	}
	if sev := got["missing-hsts"].GetSeverity(); sev != "medium" {
		t.Errorf("HSTS severity = %q, want medium", sev)
	}
	if sev := got["missing-referrer-policy"].GetSeverity(); sev != "low" {
		t.Errorf("Referrer-Policy severity = %q, want low", sev)
	}
}

// TestHeaders_HardenedServiceIsSilent is the discipline that keeps the
// check worth reading.
func TestHeaders_HardenedServiceIsSilent(t *testing.T) {
	if got := headerKinds(loadHeaderGolden(t), "https://hardened.example.com"); len(got) != 0 {
		t.Errorf("a correctly configured service produced findings: %v", kindNames(got))
	}
}

// TestHeaders_HSTSIsNotReportedOverPlaintext pins that a header which only
// means something over TLS is not demanded of an http:// endpoint.
func TestHeaders_HSTSIsNotReportedOverPlaintext(t *testing.T) {
	got := headerKinds(loadHeaderGolden(t), "http://plain.example.com")
	if _, reported := got["missing-hsts"]; reported {
		t.Error("HSTS reported missing on an http:// endpoint, where it does nothing")
	}
	// The one thing genuinely absent there is X-Frame-Options... which the
	// CSP covers, so this endpoint should be silent too.
	if len(got) != 0 {
		t.Errorf("expected silence, got %v", kindNames(got))
	}
}

// TestHeaders_CSPFrameAncestorsSupersedesXFrameOptions pins that the modern
// mechanism satisfies the old one. Reporting both would be a finding nobody
// should act on.
func TestHeaders_CSPFrameAncestorsSupersedesXFrameOptions(t *testing.T) {
	disc := loadHeaderGolden(t)
	for _, target := range []string{
		"http://plain.example.com",
		"https://sniffable.example.com",
	} {
		if _, reported := headerKinds(disc, target)["missing-frame-options"]; reported {
			t.Errorf("%s: X-Frame-Options reported missing despite a CSP frame-ancestors directive", target)
		}
	}
}

// TestHeaders_PresentButWrongValueIsReported pins that a header set to the
// wrong thing is not treated as satisfied.
func TestHeaders_PresentButWrongValueIsReported(t *testing.T) {
	got := headerKinds(loadHeaderGolden(t), "https://sniffable.example.com")
	f, ok := got["missing-nosniff"]
	if !ok {
		t.Fatalf("X-Content-Type-Options: text/html was accepted; got %v", kindNames(got))
	}
	if !strings.Contains(f.GetTitle(), "does not say nosniff") {
		t.Errorf("title does not name the wrong value: %q", f.GetTitle())
	}
	// That is the ONLY thing wrong with this endpoint.
	if len(got) != 1 {
		t.Errorf("expected exactly one finding, got %v", kindNames(got))
	}
}

// TestHeaders_FailedProbeProducesNothing pins that an unreachable host is
// the absence of an observation, not a weakness.
func TestHeaders_FailedProbeProducesNothing(t *testing.T) {
	if got := headerKinds(loadHeaderGolden(t), "https://down.example.com"); len(got) != 0 {
		t.Errorf("a failed probe produced findings: %v", kindNames(got))
	}
}

// TestHeaders_NoRecordedHeadersProducesNothing is the one that stops a
// false-positive storm: "we did not look" must never render as "every
// header is missing".
func TestHeaders_NoRecordedHeadersProducesNothing(t *testing.T) {
	if got := headerKinds(loadHeaderGolden(t), "https://noheaders.example.com"); len(got) != 0 {
		t.Errorf("a response with no recorded headers produced findings: %v", kindNames(got))
	}
}

// TestHeaders_FindingIDsAreDeterministic pins that a re-probe updates the
// same findings rather than appending duplicates.
func TestHeaders_FindingIDsAreDeterministic(t *testing.T) {
	first, second := loadHeaderGolden(t), loadHeaderGolden(t)
	if len(first.Findings) != len(second.Findings) {
		t.Fatalf("counts differ: %d vs %d", len(first.Findings), len(second.Findings))
	}
	for i := range first.Findings {
		if first.Findings[i].GetId() != second.Findings[i].GetId() {
			t.Fatalf("id %d differs: %q vs %q", i, first.Findings[i].GetId(), second.Findings[i].GetId())
		}
	}
}

// TestBuildArgs_AlwaysRequestsResponseHeaders pins that the check cannot be
// silently switched off: without -irh httpx reports no headers, and every
// endpoint would then look clean.
func TestBuildArgs_AlwaysRequestsResponseHeaders(t *testing.T) {
	args, err := buildArgs(registry.ExecuteRequest{Target: "https://example.com"})
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	found := false
	for _, a := range args {
		if a == "-irh" {
			found = true
		}
	}
	if !found {
		t.Errorf("-irh missing from argv: %v", args)
	}
}
