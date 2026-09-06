// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package trivy wraps Aqua Security's image scanner. It answers "what is
// installed in this image, and which of it is vulnerable", which is the one
// question the other parsers here cannot: they all look at a running
// service from the outside, and this one looks at the artefact.
//
// It emits four node shapes and the edges between them:
//
//	Image          the artefact, keyed by digest
//	Package        one dependency at one version inside that Image
//	Vulnerability  the identity of a weakness (a CVE or GHSA id), no status
//	Finding        one occurrence of a Vulnerability in one Package
//
// Vulnerability and Finding are deliberately separate. A CVE that affects
// four applications is ONE Vulnerability node with four Findings hanging
// off it — that is what makes "show me everything affected by this CVE" a
// single hop rather than a property scan, and it is why status lives on the
// Finding and never on the Vulnerability.
//
// Image, Package and Vulnerability travel as CustomNodes: they are outside
// the DiscoveryResult's typed set, and the open-world escape hatch is the
// documented way to emit a shape the taxonomy has not promoted yet. No
// proto change is needed for this parser, and none should be made for it.
package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"sort"
	"strings"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

const (
	toolName    = "trivy"
	toolVersion = "0.1.0"
	// Image scans pull a layer set and, on a cold cache, the vulnerability
	// database. Ten minutes is generous for a large image on a slow link
	// and still bounded.
	defaultTimeout = 600

	// trivy memory-maps its vulnerability database (bolt), and RLIMIT_AS
	// caps ADDRESS SPACE, not resident memory. A Go process already
	// reserves a large sparse arena before it maps anything, so the 2 GiB
	// default leaves no room for the mapping and trivy dies at startup with
	// "DB error: failed to open db: cannot allocate memory" — which is what
	// the first CI run of this parser did. 8 GiB of address space costs no
	// resident memory; the scan's actual footprint is a few hundred MiB.
	trivyAddressSpaceBytes = 8192 * 1024 * 1024

	nodeImage         = "Image"
	nodePackage       = "Package"
	nodeVulnerability = "Vulnerability"
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:        toolName,
		Version:     toolVersion,
		Description: "Container image vulnerability scan (Aqua Trivy). Emits Image/Package/Vulnerability nodes and one Finding per affected package.",
		Tags:        []string{"sca", "vulnerability", "container", "supply-chain"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{
					"type":        "string",
					"description": "Image reference to scan, e.g. ghcr.io/org/app:1.2.3 or app@sha256:<hex>.",
				},
				"severity": map[string]any{
					"type":        "string",
					"description": "Comma-separated severities to report: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL.",
				},
				"ignore_unfixed": map[string]any{
					"type":        "string",
					"description": "\"true\" to report only vulnerabilities that have a fixed version.",
				},
				"args": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
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

// report is the subset of `trivy image -f json` this parser reads.
type report struct {
	ArtifactName string `json:"ArtifactName"`
	Metadata     struct {
		OS struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
		ImageID     string   `json:"ImageID"`
		RepoDigests []string `json:"RepoDigests"`
		RepoTags    []string `json:"RepoTags"`
	} `json:"Metadata"`
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Status           string `json:"Status"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
			PrimaryURL       string `json:"PrimaryURL"`
			PkgIdentifier    struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
			CVSS map[string]struct {
				V3Score float64 `json:"V3Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// buildArgs composes the trivy argv.
//
// `-f json` and `--quiet` are fixed: the runner parses stdout, so a caller
// must not be able to change the output format or interleave a progress
// bar with it. Everything else routes through the shared allowlist.
func buildArgs(req registry.ExecuteRequest) ([]string, error) {
	if err := registry.ValidateTarget(toolName, req.Target); err != nil {
		return nil, fmt.Errorf("trivy target: %w", err)
	}

	args := []string{"image", "--quiet", "-f", "json"}
	if sev := req.Options["severity"]; sev != "" {
		pair, err := registry.ApplyOption(toolName, "--severity", sev, nil)
		if err != nil {
			return nil, fmt.Errorf("trivy severity option: %w", err)
		}
		args = append(args, pair...)
	}
	if req.Options["ignore_unfixed"] == "true" {
		args = append(args, "--ignore-unfixed")
	}

	filtered, err := registry.ApplyPolicy(toolName, req.Args, nil)
	if err != nil {
		return nil, fmt.Errorf("trivy args: %w", err)
	}
	args = append(args, filtered...)

	// The image reference goes last, after every flag, so a reference that
	// somehow reached here still cannot be read as one.
	return append(args, req.Target), nil
}

func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	args, argErr := buildArgs(req)
	if argErr != nil {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed}, argErr
	}

	sbCfg := sandbox.DefaultConfig()
	if sbCfg.MemoryBytes < trivyAddressSpaceBytes {
		sbCfg.MemoryBytes = trivyAddressSpaceBytes
	}
	var stdout, stderr sandbox.CappedBuffer
	stdout.Init(sbCfg.OutputCapBytes)
	stderr.Init(sbCfg.OutputCapBytes)
	// The program is a literal, never chosen at runtime, and every element
	// of args comes from buildArgs: the target is validated as an image
	// reference by ValidateTarget, options go through registry.ApplyOption,
	// and req.Args is filtered by the per-tool allowlist. That filtering is
	// this repo's control for exactly the risk G204 names, so a caller
	// cannot reach a flag the policy denies. Every parser here has the same
	// shape; gosec reports it only on the lines a PR adds.
	//
	//nolint:gosec // G204: argv is policed by buildArgs + the args allowlist.
	cmd := exec.CommandContext(ctx, "trivy", args...)
	if err := sandbox.Apply(cmd, sbCfg); err != nil {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("trivy sandbox: %w", err)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		// A wait status is -1 (killed before exiting) or 0..255, so the
		// guard never fires; it is here because the compiler cannot know
		// that and a silently wrapped exit code would be a lie.
		if ec := cmd.ProcessState.ExitCode(); ec >= math.MinInt32 && ec <= math.MaxInt32 {
			resp.ExitCode = int32(ec)
		}
	}
	if err := stdout.Err(); err != nil {
		return resp, fmt.Errorf("trivy stdout: %w", err)
	}
	if runErr != nil && len(stdout.Bytes()) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("trivy exec: %w", runErr)
	}

	disc, quality, parseErr := parseReport(stdout.Bytes())
	resp.Discovery = disc
	resp.ParseQuality = quality
	return resp, parseErr
}

// imageDigest picks the stable identity for the scanned image: a repository
// digest when the registry gave one, else the image ID. A tag is never the
// identity — the same tag is a different artefact tomorrow, and the whole
// point of keying on a digest is that a re-scan of the same bytes converges
// on the same node instead of forking a new one.
func imageDigest(r *report) string {
	for _, rd := range r.Metadata.RepoDigests {
		if _, digest, ok := strings.Cut(rd, "@"); ok && digest != "" {
			return digest
		}
	}
	if r.Metadata.ImageID != "" {
		return r.Metadata.ImageID
	}
	return r.ArtifactName
}

// packageID prefers the package URL, which already encodes ecosystem, name
// and version in one canonical string. Without one, the ecosystem is folded
// in by hand so that `busybox` from an apk image and `busybox` from a Debian
// image stay two packages rather than colliding into one.
func packageID(purl, ecosystem, name, version string) string {
	if purl != "" {
		return purl
	}
	return fmt.Sprintf("pkg:%s/%s@%s", ecosystem, name, version)
}

func cvssScore(scores map[string]struct {
	V3Score float64 `json:"V3Score"`
}) (float64, bool) {
	// Prefer NVD, then any other source, deterministically by name so two
	// runs over the same report never disagree.
	if s, ok := scores["nvd"]; ok && s.V3Score > 0 {
		return s.V3Score, true
	}
	keys := make([]string, 0, len(scores))
	for k := range scores {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if scores[k].V3Score > 0 {
			return scores[k].V3Score, true
		}
	}
	return 0, false
}

func parseReport(raw []byte) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return disc, registry.ParseQualityPartial, errors.New("trivy produced no output")
	}

	var r report
	if err := json.Unmarshal([]byte(trimmed), &r); err != nil {
		return disc, registry.ParseQualityFailed, fmt.Errorf("unmarshal trivy report: %w", err)
	}

	digest := imageDigest(&r)
	imageProps := map[string]string{"name": r.ArtifactName}
	if r.Metadata.OS.Family != "" {
		imageProps["os_family"] = r.Metadata.OS.Family
	}
	if r.Metadata.OS.Name != "" {
		imageProps["os_name"] = r.Metadata.OS.Name
	}
	if len(r.Metadata.RepoTags) > 0 {
		imageProps["tags"] = strings.Join(r.Metadata.RepoTags, ",")
	}
	disc.CustomNodes = append(disc.CustomNodes, &graphragpb.CustomNode{
		NodeType:     nodeImage,
		IdProperties: map[string]string{"digest": digest},
		Properties:   imageProps,
	})

	// A package and a CVE each appear once per occurrence in the report;
	// both are emitted once per identity here, because the node is the
	// identity and the Finding is the occurrence.
	seenPkg := map[string]bool{}
	seenVuln := map[string]bool{}

	for _, res := range r.Results {
		ecosystem := res.Type
		if ecosystem == "" {
			ecosystem = "unknown"
		}
		for _, v := range res.Vulnerabilities {
			if v.VulnerabilityID == "" || v.PkgName == "" {
				// A row naming neither a package nor a weakness identifies
				// no occurrence; keeping it would create an unjoinable node.
				continue
			}
			pkgID := packageID(v.PkgIdentifier.PURL, ecosystem, v.PkgName, v.InstalledVersion)

			if !seenPkg[pkgID] {
				seenPkg[pkgID] = true
				disc.CustomNodes = append(disc.CustomNodes, &graphragpb.CustomNode{
					NodeType:     nodePackage,
					IdProperties: map[string]string{"id": pkgID},
					Properties: map[string]string{
						"name":      v.PkgName,
						"version":   v.InstalledVersion,
						"ecosystem": ecosystem,
					},
					ParentType:       proto.String(nodeImage),
					ParentId:         map[string]string{"digest": digest},
					RelationshipType: proto.String("CONTAINS"),
				})
			}

			severity := strings.ToLower(v.Severity)
			if !seenVuln[v.VulnerabilityID] {
				seenVuln[v.VulnerabilityID] = true
				vulnProps := map[string]string{"severity": severity}
				if v.Title != "" {
					vulnProps["title"] = v.Title
				}
				if v.PrimaryURL != "" {
					vulnProps["url"] = v.PrimaryURL
				}
				if score, ok := cvssScore(v.CVSS); ok {
					vulnProps["cvss_score"] = fmt.Sprintf("%.1f", score)
				}
				disc.CustomNodes = append(disc.CustomNodes, &graphragpb.CustomNode{
					NodeType:     nodeVulnerability,
					IdProperties: map[string]string{"id": v.VulnerabilityID},
					Properties:   vulnProps,
				})
			}

			// One Finding per (image, package, vulnerability). The id is
			// derived rather than random so a re-scan updates the same
			// Finding instead of appending a duplicate.
			findingID := fmt.Sprintf("finding:%s:%s:%s", digest, pkgID, v.VulnerabilityID)
			title := v.Title
			if title == "" {
				title = fmt.Sprintf("%s in %s %s", v.VulnerabilityID, v.PkgName, v.InstalledVersion)
			}
			finding := &graphragpb.Finding{
				Id:         proto.String(findingID),
				Title:      title,
				Severity:   severity,
				CveIds:     proto.String(v.VulnerabilityID),
				Category:   proto.String("vulnerable-dependency"),
				ParentType: proto.String(nodePackage),
				ParentId:   proto.String(pkgID),
			}
			if v.Description != "" {
				finding.Description = proto.String(v.Description)
			}
			if score, ok := cvssScore(v.CVSS); ok {
				finding.CvssScore = proto.Float64(score)
			}
			if v.FixedVersion != "" {
				finding.Remediation = proto.String(fmt.Sprintf("Upgrade %s to %s", v.PkgName, v.FixedVersion))
			}
			disc.Findings = append(disc.Findings, finding)

			// The edge that makes one CVE across many images a single hop.
			disc.ExplicitRelationships = append(disc.ExplicitRelationships,
				&graphragpb.ExplicitRelationship{
					FromType:         "finding",
					FromId:           map[string]string{"id": findingID},
					ToType:           strings.ToLower(nodeVulnerability),
					ToId:             map[string]string{"id": v.VulnerabilityID},
					RelationshipType: "INSTANCE_OF",
				})
		}
	}

	return disc, registry.ParseQualityStructured, nil
}
