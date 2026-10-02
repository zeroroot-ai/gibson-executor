// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zero Root AI

package httpx

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// A probe httpx could not complete carries `"failed": true` and an `error`
// string. The parser decoded both and used neither, so appendProbe built a
// Service, an Endpoint and any Technology lines for a target that never
// answered. The graph then held a service that does not exist, and the reason
// httpx gave was thrown away (gibson-executor#89).

const failedLine = `{"url":"https://down.example","host":"down.example","scheme":"https","failed":true,"error":"dial tcp 10.0.0.1:443: connect: connection refused"}`

const liveLine = `{"url":"https://up.example","host":"up.example","scheme":"https","status_code":200,"webserver":"nginx","method":"GET","tech":["nginx"],"header":{"server":"nginx"}}`

func TestParse_FailedProbeProducesNoNodes(t *testing.T) {
	disc, quality, errs, err := parseJSONLines([]byte(failedLine + "\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n := len(disc.Services); n != 0 {
		t.Errorf("failed probe produced %d Service(s); a host that never answered has no service", n)
	}
	if n := len(disc.Endpoints); n != 0 {
		t.Errorf("failed probe produced %d Endpoint(s)", n)
	}
	if n := len(disc.Technologies); n != 0 {
		t.Errorf("failed probe produced %d Technology node(s)", n)
	}
	if quality != registry.ParseQualityPartial {
		t.Errorf("quality = %v, want PARTIAL: nothing was observed", quality)
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "connection refused") {
		t.Errorf("per-target errors = %v, want the reason httpx gave", errs)
	}
	if !strings.Contains(strings.Join(errs, " "), "down.example") {
		t.Errorf("per-target errors do not name the target: %v", errs)
	}
}

func TestParse_LiveProbeStillProducesNodes(t *testing.T) {
	disc, quality, errs, err := parseJSONLines([]byte(liveLine + "\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(disc.Services) != 1 || len(disc.Endpoints) != 1 || len(disc.Technologies) != 1 {
		t.Fatalf("live probe produced %d services, %d endpoints, %d technologies; want 1/1/1",
			len(disc.Services), len(disc.Endpoints), len(disc.Technologies))
	}
	if quality != registry.ParseQualityStructured {
		t.Errorf("quality = %v, want STRUCTURED", quality)
	}
	if len(errs) != 0 {
		t.Errorf("a clean run reported per-target errors: %v", errs)
	}
}

// A mixed run is PARTIAL: some targets were observed and some were not, and a
// caller that reads STRUCTURED would treat the gap as "nothing to report".
func TestParse_MixedRunIsPartial(t *testing.T) {
	disc, quality, errs, err := parseJSONLines([]byte(liveLine + "\n" + failedLine + "\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(disc.Services) != 1 {
		t.Errorf("services = %d, want only the live one", len(disc.Services))
	}
	if quality != registry.ParseQualityPartial {
		t.Errorf("quality = %v, want PARTIAL", quality)
	}
	if len(errs) != 1 {
		t.Errorf("per-target errors = %v, want one", errs)
	}
}

// httpx reports a failure with `failed:true` and usually an `error` string, but
// the error can be absent. The guard must key on the failure, not on the text.
func TestParse_FailedWithNoErrorTextStillSkips(t *testing.T) {
	disc, quality, errs, err := parseJSONLines([]byte(`{"url":"https://x.example","host":"x.example","failed":true}` + "\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(disc.Services) != 0 || len(disc.Endpoints) != 0 {
		t.Errorf("a failure with no error text still produced nodes")
	}
	if quality != registry.ParseQualityPartial {
		t.Errorf("quality = %v, want PARTIAL", quality)
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "x.example") {
		t.Errorf("per-target errors = %v, want one naming the target", errs)
	}
}
