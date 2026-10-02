// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tlsx

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// Skipping a failed probe was already right: an unreachable host is the absence
// of an observation, not a TLS weakness. What was missing is that
// `response.Error` was decoded and never used, so a run where EVERY probe
// failed returned STRUCTURED with zero findings — byte-identical to "every host
// was reached and its TLS is fine" (gibson-executor#89).

func TestParse_AllProbesFailedIsNotACleanResult(t *testing.T) {
	raw := `{"host":"a.example","port":"443","probe_status":false,"error":"connection refused"}
{"host":"b.example","port":"443","probe_status":false,"error":"i/o timeout"}`

	disc, quality, targetErrs, err := parseJSONLines([]byte(raw), fixedNow)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(disc.Findings) != 0 {
		t.Errorf("a failed probe produced %d finding(s)", len(disc.Findings))
	}
	if quality == registry.ParseQualityStructured {
		t.Fatal("quality = STRUCTURED for a run where no probe completed; that reads as 'TLS is fine'")
	}
	if quality != registry.ParseQualityPartial {
		t.Errorf("quality = %v, want PARTIAL", quality)
	}
	if len(targetErrs) != 2 {
		t.Fatalf("per-target errors = %v, want two", targetErrs)
	}
	joined := strings.Join(targetErrs, " ")
	for _, want := range []string{"a.example:443", "connection refused", "b.example:443", "i/o timeout"} {
		if !strings.Contains(joined, want) {
			t.Errorf("per-target errors do not mention %q: %v", want, targetErrs)
		}
	}
}

// tlsx does not always fill `error`. The report must key on probe_status, and
// must not print an empty reason.
func TestParse_FailedProbeWithNoErrorTextStillReports(t *testing.T) {
	_, quality, targetErrs, err := parseJSONLines([]byte(`{"host":"q.example","port":"443","probe_status":false}`), fixedNow)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if quality != registry.ParseQualityPartial {
		t.Errorf("quality = %v, want PARTIAL", quality)
	}
	if len(targetErrs) != 1 {
		t.Fatalf("per-target errors = %v, want one", targetErrs)
	}
	if !strings.Contains(targetErrs[0], "q.example:443") || !strings.Contains(targetErrs[0], "no reason") {
		t.Errorf("report = %q, want the target and that tlsx gave no reason", targetErrs[0])
	}
}

// All probes completed: STRUCTURED, no gaps reported.
func TestParse_AllProbesCompletedIsStructured(t *testing.T) {
	raw := `{"host":"ok.example","ip":"10.0.0.1","port":"443","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_256_GCM_SHA384","not_after":"2030-01-01T00:00:00Z","subject_cn":"ok.example","issuer_cn":"Example CA"}`
	_, quality, targetErrs, err := parseJSONLines([]byte(raw), fixedNow)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Errorf("quality = %v, want STRUCTURED", quality)
	}
	if len(targetErrs) != 0 {
		t.Errorf("a clean run reported gaps: %v", targetErrs)
	}
}
