// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package trivy

import (
	"os"
	"testing"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

func loadGolden(t *testing.T) *graphragpb.DiscoveryResult {
	t.Helper()
	raw, err := os.ReadFile("testdata/report.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, quality, err := parseReport(raw)
	if err != nil {
		t.Fatalf("parseReport: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Fatalf("quality = %v, want structured", quality)
	}
	return disc
}

func nodesOfType(disc *graphragpb.DiscoveryResult, nodeType string) []*graphragpb.CustomNode {
	var out []*graphragpb.CustomNode
	for _, n := range disc.CustomNodes {
		if n.GetNodeType() == nodeType {
			out = append(out, n)
		}
	}
	return out
}

// TestParse_EmitsOneImageKeyedByRepoDigest pins that the image identity is
// the repository digest, never the tag: a re-scan of the same bytes must
// land on the same node.
func TestParse_EmitsOneImageKeyedByRepoDigest(t *testing.T) {
	disc := loadGolden(t)
	images := nodesOfType(disc, nodeImage)
	if len(images) != 1 {
		t.Fatalf("got %d Image nodes, want 1", len(images))
	}
	const wantDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	if got := images[0].GetIdProperties()["digest"]; got != wantDigest {
		t.Errorf("image digest = %q, want the repo digest %q", got, wantDigest)
	}
	if got := images[0].GetProperties()["os_family"]; got != "debian" {
		t.Errorf("os_family = %q, want debian", got)
	}
}

// TestParse_PackagesAreDedupedAcrossOccurrences pins that a package with two
// vulnerabilities is one Package node, and that ecosystems stay distinct.
func TestParse_PackagesAreDedupedAcrossOccurrences(t *testing.T) {
	disc := loadGolden(t)
	pkgs := nodesOfType(disc, nodePackage)
	if len(pkgs) != 2 {
		t.Fatalf("got %d Package nodes, want 2 (zlib1g once despite two CVEs, plus lodash)", len(pkgs))
	}
	byID := map[string]*graphragpb.CustomNode{}
	for _, p := range pkgs {
		byID[p.GetIdProperties()["id"]] = p
	}
	zlib, ok := byID["pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1"]
	if !ok {
		t.Fatalf("no zlib1g package node; got %v", byID)
	}
	if zlib.GetRelationshipType() != "CONTAINS" || zlib.GetParentType() != nodeImage {
		t.Errorf("zlib1g parent edge = %s %s, want Image CONTAINS", zlib.GetParentType(), zlib.GetRelationshipType())
	}
	if _, ok := byID["pkg:npm/lodash@4.17.20"]; !ok {
		t.Errorf("no lodash package node; got %v", byID)
	}
}

// TestParse_VulnerabilityIsIdentityFindingIsOccurrence is the shape the whole
// parser exists to produce: the CVE carries no status, and each occurrence is
// its own Finding joined to it by an edge.
func TestParse_VulnerabilityIsIdentityFindingIsOccurrence(t *testing.T) {
	disc := loadGolden(t)

	vulns := nodesOfType(disc, nodeVulnerability)
	if len(vulns) != 3 {
		t.Fatalf("got %d Vulnerability nodes, want 3", len(vulns))
	}
	for _, v := range vulns {
		if _, has := v.GetProperties()["status"]; has {
			t.Errorf("Vulnerability %s carries a status; status belongs on the Finding",
				v.GetIdProperties()["id"])
		}
	}

	if len(disc.Findings) != 3 {
		t.Fatalf("got %d Findings, want 3", len(disc.Findings))
	}
	if len(disc.ExplicitRelationships) != 3 {
		t.Fatalf("got %d relationships, want 3 INSTANCE_OF edges", len(disc.ExplicitRelationships))
	}
	for _, rel := range disc.ExplicitRelationships {
		if rel.GetRelationshipType() != "INSTANCE_OF" {
			t.Errorf("relationship type = %q, want INSTANCE_OF", rel.GetRelationshipType())
		}
	}
}

// TestParse_FindingCarriesFixAndScore pins the fields the fixing agent reads.
func TestParse_FindingCarriesFixAndScore(t *testing.T) {
	disc := loadGolden(t)
	byCVE := map[string]*graphragpb.Finding{}
	for _, f := range disc.Findings {
		byCVE[f.GetCveIds()] = f
	}

	fixed, ok := byCVE["CVE-2024-0001"]
	if !ok {
		t.Fatal("no Finding for CVE-2024-0001")
	}
	if got := fixed.GetRemediation(); got != "Upgrade zlib1g to 1:1.2.13.dfsg-1+deb12u1" {
		t.Errorf("remediation = %q", got)
	}
	if got := fixed.GetCvssScore(); got != 7.5 {
		t.Errorf("cvss = %v, want the NVD score 7.5 in preference to redhat's 6.1", got)
	}
	if got := fixed.GetSeverity(); got != "high" {
		t.Errorf("severity = %q, want lowercase high", got)
	}
	if got := fixed.GetParentType(); got != nodePackage {
		t.Errorf("parent type = %q, want Package", got)
	}

	// No fixed version means no remediation text — an empty "upgrade to"
	// instruction would be worse than none.
	unfixed, ok := byCVE["CVE-2024-0002"]
	if !ok {
		t.Fatal("no Finding for CVE-2024-0002")
	}
	if unfixed.Remediation != nil {
		t.Errorf("remediation = %q for a vulnerability with no fix", unfixed.GetRemediation())
	}
	// Only redhat scores this one; the parser must still find a score.
	if got := unfixed.GetCvssScore(); got != 5.3 {
		t.Errorf("cvss = %v, want the only available score 5.3", got)
	}
}

// TestParse_FindingIDsAreDeterministic pins that two parses of one report
// agree, so a re-scan updates a Finding instead of duplicating it.
func TestParse_FindingIDsAreDeterministic(t *testing.T) {
	first := loadGolden(t)
	second := loadGolden(t)
	if len(first.Findings) != len(second.Findings) {
		t.Fatalf("finding counts differ: %d vs %d", len(first.Findings), len(second.Findings))
	}
	for i := range first.Findings {
		if first.Findings[i].GetId() != second.Findings[i].GetId() {
			t.Fatalf("finding %d id differs between parses: %q vs %q",
				i, first.Findings[i].GetId(), second.Findings[i].GetId())
		}
	}
	want := "finding:sha256:2222222222222222222222222222222222222222222222222222222222222222:" +
		"pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1:CVE-2024-0001"
	if got := first.Findings[0].GetId(); got != want {
		t.Errorf("finding id = %q, want %q", got, want)
	}
}

// TestParse_SkipsRowsThatIdentifyNoOccurrence pins that a row naming no CVE
// is dropped rather than emitted as an unjoinable node. The fixture carries
// one such row.
func TestParse_SkipsRowsThatIdentifyNoOccurrence(t *testing.T) {
	disc := loadGolden(t)
	for _, f := range disc.Findings {
		if f.GetCveIds() == "" {
			t.Errorf("emitted a Finding with no vulnerability id: %q", f.GetTitle())
		}
	}
	for _, p := range nodesOfType(disc, nodePackage) {
		if p.GetProperties()["name"] == "ghost" {
			t.Error("emitted a Package for a row that identified no vulnerability")
		}
	}
}

// TestParse_RejectsNonJSON pins that a format change is a hard parse failure
// rather than a silent empty result — a scanner that reports nothing must
// never look like a clean image.
func TestParse_RejectsNonJSON(t *testing.T) {
	if _, quality, err := parseReport([]byte("not json")); err == nil {
		t.Error("expected an error for non-JSON output")
	} else if quality != registry.ParseQualityFailed {
		t.Errorf("quality = %v, want failed", quality)
	}
	if _, _, err := parseReport([]byte("   ")); err == nil {
		t.Error("expected an error for empty output")
	}
}
