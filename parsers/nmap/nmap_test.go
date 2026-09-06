// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package nmap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// TestParseXML_SimpleScan feeds a recorded nmap -sV -oX - output through the
// parser and asserts the resulting DiscoveryResult matches expectations.
// This guards against upstream nmap output-format drift: if nmap changes
// its XML schema, this test catches it before the image publishes.
func TestParseXML_SimpleScan(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "simple-scan.xml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	disc, quality, err := parseXML(raw)
	if err != nil {
		t.Fatalf("parseXML: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Errorf("parse quality = %d; want STRUCTURED (1)", quality)
	}
	if got, want := len(disc.Hosts), 1; got != want {
		t.Fatalf("hosts = %d; want %d", got, want)
	}
	if got, want := disc.Hosts[0].Ip, "45.33.32.156"; got != want {
		t.Errorf("host ip = %q; want %q", got, want)
	}
	if disc.Hosts[0].Hostname == nil || *disc.Hosts[0].Hostname != "scanme.nmap.org" {
		t.Errorf("host hostname = %v; want scanme.nmap.org", disc.Hosts[0].Hostname)
	}
	if disc.Hosts[0].State == nil || *disc.Hosts[0].State != "up" {
		t.Errorf("host state = %v; want up", disc.Hosts[0].State)
	}

	// Three ports (22, 80, 443).
	if got, want := len(disc.Ports), 3; got != want {
		t.Fatalf("ports = %d; want %d", got, want)
	}
	portNumbers := map[int32]bool{}
	for _, p := range disc.Ports {
		portNumbers[p.Number] = true
		if p.Protocol != "tcp" {
			t.Errorf("port %d protocol = %q; want tcp", p.Number, p.Protocol)
		}
		if p.HostId == "" {
			t.Errorf("port %d has empty host_id", p.Number)
		}
	}
	for _, want := range []int32{22, 80, 443} {
		if !portNumbers[want] {
			t.Errorf("missing port %d in result", want)
		}
	}

	// Services: ssh, http, https (https even though port is closed — the
	// XML carries a table-guess service name).
	if got := len(disc.Services); got < 2 {
		t.Fatalf("services = %d; want >=2 (ssh + http populated with product/version)", got)
	}
	sshFound, httpFound := false, false
	for _, s := range disc.Services {
		switch s.Name {
		case "ssh":
			sshFound = true
			if s.Product == nil || *s.Product != "OpenSSH" {
				t.Errorf("ssh product = %v; want OpenSSH", s.Product)
			}
		case "http":
			httpFound = true
			if s.Product == nil || *s.Product != "Apache httpd" {
				t.Errorf("http product = %v; want Apache httpd", s.Product)
			}
		}
	}
	if !sshFound {
		t.Error("ssh service not found")
	}
	if !httpFound {
		t.Error("http service not found")
	}
}

// TestParseXML_Malformed surfaces ParseQualityFailed with a non-nil error on
// garbage input so operators see clear diagnostics rather than silent zeros.
func TestParseXML_Malformed(t *testing.T) {
	_, quality, err := parseXML([]byte("this is not xml"))
	if err == nil {
		t.Fatal("expected parse error; got nil")
	}
	if quality != registry.ParseQualityFailed {
		t.Errorf("parse quality = %d; want FAILED (4)", quality)
	}
}

// TestDescribe_StableCatalog freezes the catalog entry so the runner's
// --list-tools output doesn't drift across refactors without a conscious
// update. Downstream consumers (dashboard, orchestrator LLM) depend on
// stable names/tags/schemas.
func TestDescribe_StableCatalog(t *testing.T) {
	entry := (&parser{}).Describe()
	if entry.Name != toolName {
		t.Errorf("name = %q; want %q", entry.Name, toolName)
	}
	if entry.OutputProtoType != "gibson.graphrag.v1.DiscoveryResult" {
		t.Errorf("output_proto_type = %q; want gibson.graphrag.v1.DiscoveryResult", entry.OutputProtoType)
	}
	if entry.DefaultParseQuality != registry.ParseQualityStructured {
		t.Errorf("default_parse_quality = %d; want STRUCTURED", entry.DefaultParseQuality)
	}
	// Encode → decode round-trip ensures the JSON shape is stable.
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got registry.CatalogEntry
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Name != entry.Name {
		t.Errorf("round-trip drift: name = %q; want %q", got.Name, entry.Name)
	}
}

// TestRegistryIntegration asserts the init() registration actually inserted
// the parser into the central map, so --list-tools will enumerate it.
func TestRegistryIntegration(t *testing.T) {
	p, ok := registry.Lookup(toolName)
	if !ok {
		t.Fatalf("registry.Lookup(%q) = false; want true", toolName)
	}
	if _, ok := p.(*parser); !ok {
		t.Errorf("looked-up parser type = %T; want *nmap.parser", p)
	}
}
