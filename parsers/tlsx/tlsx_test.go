// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tlsx

import (
	"os"
	"strings"
	"testing"
	"time"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// fixedNow keeps expiry grading deterministic: the fixture's dates are read
// against this instant, never against the wall clock.
var fixedNow = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

func loadGolden(t *testing.T) *graphragpb.DiscoveryResult {
	t.Helper()
	raw, err := os.ReadFile("testdata/probe.jsonl")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, quality, err := parseJSONLines(raw, fixedNow)
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Fatalf("quality = %v, want structured", quality)
	}
	return disc
}

func findingsFor(disc *graphragpb.DiscoveryResult, endpoint string) map[string]*graphragpb.Finding {
	out := map[string]*graphragpb.Finding{}
	for _, f := range disc.Findings {
		if f.GetParentId() != endpoint {
			continue
		}
		// The id tail after "finding:tls:<endpoint>:" is the kind.
		prefix := "finding:tls:" + endpoint + ":"
		out[strings.TrimPrefix(f.GetId(), prefix)] = f
	}
	return out
}

// TestParse_ExpiredCertificateIsCritical pins the clearest case.
func TestParse_ExpiredCertificateIsCritical(t *testing.T) {
	got := findingsFor(loadGolden(t), "expired.example.com:443")
	f, ok := got["cert-expired"]
	if !ok {
		t.Fatalf("no cert-expired finding; got %v", keys(got))
	}
	if f.GetSeverity() != "critical" {
		t.Errorf("severity = %q, want critical", f.GetSeverity())
	}
	// An expired certificate must not also be reported as "expiring soon";
	// one certificate, one expiry statement.
	if _, dup := got["cert-expiring"]; dup {
		t.Error("an expired certificate also produced an expiring finding")
	}
}

// TestParse_SupportedWeakVersionIsFoundEvenWhenNegotiationIsModern is the
// finding the whole enumeration exists for: the attacker picks the version.
func TestParse_SupportedWeakVersionIsFoundEvenWhenNegotiationIsModern(t *testing.T) {
	got := findingsFor(loadGolden(t), "legacy.example.com:443")
	f, ok := got["weak-protocol-tls10"]
	if !ok {
		t.Fatalf("TLS 1.0 in version_enum produced no finding; got %v", keys(got))
	}
	if f.GetSeverity() != "high" {
		t.Errorf("severity = %q, want high", f.GetSeverity())
	}
	// tls12 and tls13 are acceptable and must not be reported.
	for _, k := range keys(got) {
		if strings.HasPrefix(k, "weak-protocol-tls12") || strings.HasPrefix(k, "weak-protocol-tls13") {
			t.Errorf("acceptable version reported as weak: %s", k)
		}
	}
}

// TestParse_SelfSignedAndWeakCipher pins that several problems on one
// service each get their own finding.
func TestParse_SelfSignedAndWeakCipher(t *testing.T) {
	got := findingsFor(loadGolden(t), "selfsigned.example.com:8443")
	if f, ok := got["cert-self-signed"]; !ok {
		t.Errorf("no self-signed finding; got %v", keys(got))
	} else if f.GetSeverity() != "high" {
		t.Errorf("self-signed severity = %q, want high", f.GetSeverity())
	}
	if f, ok := got["weak-cipher"]; !ok {
		t.Errorf("RC4 cipher produced no finding; got %v", keys(got))
	} else if f.GetSeverity() != "high" {
		t.Errorf("RC4 severity = %q, want high", f.GetSeverity())
	}
	// A self-signed certificate is already reported as self-signed; saying
	// "untrusted" as well is the same fact twice.
	if _, dup := got["cert-untrusted"]; dup {
		t.Error("a self-signed certificate also produced an untrusted finding")
	}
}

// TestParse_HealthyServiceProducesNothing is what stops the tool crying
// wolf: a correctly configured service must be silent.
func TestParse_HealthyServiceProducesNothing(t *testing.T) {
	if got := findingsFor(loadGolden(t), "healthy.example.com:443"); len(got) != 0 {
		t.Errorf("a healthy service produced findings: %v", keys(got))
	}
}

// TestParse_FailedProbeIsNotAFinding pins that an unreachable host is the
// absence of an observation, not a weakness.
func TestParse_FailedProbeIsNotAFinding(t *testing.T) {
	if got := findingsFor(loadGolden(t), "unreachable.example.com:443"); len(got) != 0 {
		t.Errorf("a failed probe produced findings: %v", keys(got))
	}
}

// TestParse_ExpiryIsGradedByRemainingDays pins the grading, against a fixed
// clock so the test cannot rot.
func TestParse_ExpiryIsGradedByRemainingDays(t *testing.T) {
	for _, tc := range []struct {
		name     string
		notAfter time.Time
		wantKind string
		wantSev  string
	}{
		{"three days out is high", fixedNow.AddDate(0, 0, 3), "cert-expiring", "high"},
		{"twenty days out is medium", fixedNow.AddDate(0, 0, 20), "cert-expiring", "medium"},
		{"a year out is silent", fixedNow.AddDate(1, 0, 0), "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disc := &graphragpb.DiscoveryResult{}
			certificateFindings(disc, &response{
				Host: "h", Port: "443", NotAfter: tc.notAfter, SubjectCN: "h",
			}, fixedNow)
			if tc.wantKind == "" {
				if len(disc.Findings) != 0 {
					t.Fatalf("expected no finding, got %d", len(disc.Findings))
				}
				return
			}
			if len(disc.Findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(disc.Findings))
			}
			if got := disc.Findings[0].GetSeverity(); got != tc.wantSev {
				t.Errorf("severity = %q, want %q", got, tc.wantSev)
			}
		})
	}
}

// TestParse_FindingIDsAreDeterministic pins that a re-probe updates rather
// than duplicates.
func TestParse_FindingIDsAreDeterministic(t *testing.T) {
	first, second := loadGolden(t), loadGolden(t)
	if len(first.Findings) != len(second.Findings) {
		t.Fatalf("counts differ: %d vs %d", len(first.Findings), len(second.Findings))
	}
	for i := range first.Findings {
		if first.Findings[i].GetId() != second.Findings[i].GetId() {
			t.Fatalf("id %d differs: %q vs %q", i, first.Findings[i].GetId(), second.Findings[i].GetId())
		}
	}
}

func keys(m map[string]*graphragpb.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
