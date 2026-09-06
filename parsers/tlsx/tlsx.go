// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package tlsx wraps ProjectDiscovery's TLS prober. It reports what a
// service's TLS actually is — negotiated version, cipher, and the state of
// the presented certificate — as Findings.
//
// The judgement lives here, not in the tool. tlsx reports facts ("this is
// TLS 1.0", "self_signed: true"); which of those facts is a problem, and
// how bad, is this parser's decision, recorded in one table so it can be
// argued with rather than rediscovered by reading code.
//
// Certificate expiry is graded by remaining days rather than treated as a
// boolean. "Expired" is an outage that already happened; "expires in six
// days" is the one worth waking someone for, and both must be separable
// from a certificate with a year left.
package tlsx

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os/exec"
	"strings"
	"time"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

const (
	toolName       = "tlsx"
	toolVersion    = "0.1.0"
	defaultTimeout = 120

	// expirySoonDays is when a certificate stops being healthy and starts
	// being a deadline. Thirty days is the usual renewal window, so a
	// certificate inside it has already missed one.
	expirySoonDays = 30
	// expiryUrgentDays is when it becomes an incident in waiting.
	expiryUrgentDays = 7
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:        toolName,
		Version:     toolVersion,
		Description: "TLS configuration and certificate probe (ProjectDiscovery tlsx). Emits a Finding per weak protocol, weak cipher, or certificate problem.",
		Tags:        []string{"tls", "certificate", "misconfiguration"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{
					"type":        "string",
					"description": "Host, address or URL to probe.",
				},
				"port": map[string]any{
					"type":        "string",
					"description": "Port to probe. Defaults to 443.",
				},
				"args": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
			"required": []any{"target"},
		},
		OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
		DefaultParseQuality:   registry.ParseQualityStructured,
		Resources:             registry.ResourceHint{VCPU: 1, Memory: "256Mi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

func (p *parser) OutputMessage() proto.Message { return nil }

// response is the subset of tlsx's JSON line this parser reads. Field names
// are taken from tlsx's own clients.Response, whose CertificateResponse is
// inlined — so the certificate fields sit at the top level here too.
type response struct {
	Host        string `json:"host"`
	IP          string `json:"ip"`
	Port        string `json:"port"`
	ProbeStatus bool   `json:"probe_status"`
	Error       string `json:"error"`
	Version     string `json:"tls_version"`
	Cipher      string `json:"cipher"`
	ServerName  string `json:"sni"`

	// Inlined CertificateResponse.
	Expired    bool      `json:"expired"`
	SelfSigned bool      `json:"self_signed"`
	MisMatched bool      `json:"mismatched"`
	Revoked    bool      `json:"revoked"`
	Untrusted  bool      `json:"untrusted"`
	NotAfter   time.Time `json:"not_after"`
	SubjectCN  string    `json:"subject_cn"`
	IssuerCN   string    `json:"issuer_cn"`

	VersionEnum []string `json:"version_enum"`
}

// weakVersions are the protocol versions no service should still negotiate.
// tlsx reports them in its own lowercase spelling.
var weakVersions = map[string]string{
	"ssl30": "critical",
	"sslv3": "critical",
	"tls10": "high",
	"tls11": "high",
}

// weakCipherMarkers are substrings that make a cipher suite unacceptable.
// Matching on markers rather than an exhaustive suite list means a suite
// nobody has enumerated yet is still caught by the property that makes it
// weak.
var weakCipherMarkers = []struct {
	marker   string
	severity string
	why      string
}{
	{"_NULL_", "critical", "no encryption"},
	{"_anon_", "critical", "no authentication, so the connection is trivially intercepted"},
	{"EXPORT", "critical", "deliberately weakened key length"},
	{"_RC4_", "high", "RC4 is broken"},
	{"_DES_", "high", "DES/3DES is broken"},
	{"_MD5", "high", "MD5 integrity is broken"},
	{"_CBC_", "low", "CBC suites are vulnerable to padding-oracle classes and are deprecated"},
}

func buildArgs(req registry.ExecuteRequest) ([]string, error) {
	if err := registry.ValidateTarget(toolName, req.Target); err != nil {
		return nil, fmt.Errorf("tlsx target: %w", err)
	}

	args := []string{"-json", "-silent", "-u", req.Target}
	if port := req.Options["port"]; port != "" {
		pair, err := registry.ApplyOption(toolName, "-p", port, nil)
		if err != nil {
			return nil, fmt.Errorf("tlsx port option: %w", err)
		}
		args = append(args, pair...)
	}

	filtered, err := registry.ApplyPolicy(toolName, req.Args, nil)
	if err != nil {
		return nil, fmt.Errorf("tlsx args: %w", err)
	}
	return append(args, filtered...), nil
}

func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	args, argErr := buildArgs(req)
	if argErr != nil {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed}, argErr
	}

	sbCfg := sandbox.DefaultConfig()
	var stdout, stderr sandbox.CappedBuffer
	stdout.Init(sbCfg.OutputCapBytes)
	stderr.Init(sbCfg.OutputCapBytes)
	// The program is a literal and every argv element comes from buildArgs:
	// the target is validated and req.Args is filtered by the per-tool
	// allowlist, which is this repo's control for the risk G204 names.
	//
	//nolint:gosec // G204: argv is policed by buildArgs + the args allowlist.
	cmd := exec.CommandContext(ctx, "tlsx", args...)
	if err := sandbox.Apply(cmd, sbCfg); err != nil {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("tlsx sandbox: %w", err)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		if ec := cmd.ProcessState.ExitCode(); ec >= math.MinInt32 && ec <= math.MaxInt32 {
			resp.ExitCode = int32(ec)
		}
	}
	if err := stdout.Err(); err != nil {
		return resp, fmt.Errorf("tlsx stdout: %w", err)
	}
	if runErr != nil && len(stdout.Bytes()) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("tlsx exec: %w", runErr)
	}

	disc, quality, parseErr := parseJSONLines(stdout.Bytes(), time.Now())
	resp.Discovery = disc
	resp.ParseQuality = quality
	return resp, parseErr
}

// endpoint names the probed service in a finding id and title.
func (r *response) endpoint() string {
	host := r.Host
	if host == "" {
		host = r.IP
	}
	if r.Port == "" {
		return host
	}
	return host + ":" + r.Port
}

// addFinding appends one finding, keyed deterministically so a re-probe of
// the same service updates rather than duplicates.
func addFinding(disc *graphragpb.DiscoveryResult, ep, kind, severity, title, description string) {
	id := fmt.Sprintf("finding:tls:%s:%s", ep, kind)
	f := &graphragpb.Finding{
		Id:          proto.String(id),
		Title:       title,
		Severity:    severity,
		Description: proto.String(description),
		Category:    proto.String("tls-configuration"),
		ParentType:  proto.String("service"),
		ParentId:    proto.String(ep),
	}
	disc.Findings = append(disc.Findings, f)
}

// certificateFindings grades the certificate state. Expiry is graded by
// remaining days: expired is an outage that already happened, and a
// certificate a week out is the one worth acting on today.
func certificateFindings(disc *graphragpb.DiscoveryResult, r *response, now time.Time) {
	ep := r.endpoint()
	switch {
	case r.Expired:
		addFinding(disc, ep, "cert-expired", "critical",
			"TLS certificate has expired",
			fmt.Sprintf("The certificate for %q expired on %s. Clients reject the connection.",
				r.SubjectCN, r.NotAfter.Format(time.RFC3339)))
	case !r.NotAfter.IsZero():
		days := int(r.NotAfter.Sub(now).Hours() / 24)
		switch {
		case days <= expiryUrgentDays:
			addFinding(disc, ep, "cert-expiring", "high",
				fmt.Sprintf("TLS certificate expires in %d day(s)", days),
				fmt.Sprintf("The certificate for %q expires on %s.",
					r.SubjectCN, r.NotAfter.Format(time.RFC3339)))
		case days <= expirySoonDays:
			addFinding(disc, ep, "cert-expiring", "medium",
				fmt.Sprintf("TLS certificate expires in %d days", days),
				fmt.Sprintf("The certificate for %q expires on %s, inside the usual renewal window.",
					r.SubjectCN, r.NotAfter.Format(time.RFC3339)))
		}
	}

	if r.SelfSigned {
		addFinding(disc, ep, "cert-self-signed", "high",
			"TLS certificate is self-signed",
			fmt.Sprintf("The certificate for %q is self-signed, so it proves no identity to a client that does not already trust it.", r.SubjectCN))
	}
	if r.MisMatched {
		addFinding(disc, ep, "cert-mismatched", "high",
			"TLS certificate does not match the host",
			fmt.Sprintf("The certificate presented by %s names %q, which does not cover the requested host.", ep, r.SubjectCN))
	}
	if r.Revoked {
		addFinding(disc, ep, "cert-revoked", "critical",
			"TLS certificate has been revoked",
			fmt.Sprintf("The certificate for %q is revoked; its private key must be treated as compromised.", r.SubjectCN))
	}
	if r.Untrusted && !r.SelfSigned {
		addFinding(disc, ep, "cert-untrusted", "medium",
			"TLS certificate does not chain to a trusted root",
			fmt.Sprintf("The certificate for %q, issued by %q, does not chain to a trusted root.", r.SubjectCN, r.IssuerCN))
	}
}

// protocolFindings grades the negotiated version, and every other version
// the service was found to support when the caller asked tlsx to enumerate.
// A service that negotiates TLS 1.3 but still accepts TLS 1.0 is a finding:
// the attacker picks the version, not the server's preference order.
func protocolFindings(disc *graphragpb.DiscoveryResult, r *response) {
	ep := r.endpoint()
	seen := map[string]bool{}
	versions := append([]string{r.Version}, r.VersionEnum...)
	for _, v := range versions {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		severity, weak := weakVersions[v]
		if !weak {
			continue
		}
		addFinding(disc, ep, "weak-protocol-"+v, severity,
			"Service accepts "+strings.ToUpper(v),
			fmt.Sprintf("%s accepts %s. A client that offers only the weak version gets it, so supporting it alongside a modern version does not mitigate it.",
				ep, strings.ToUpper(v)))
	}
}

// cipherFindings grades the negotiated cipher suite.
func cipherFindings(disc *graphragpb.DiscoveryResult, r *response) {
	if r.Cipher == "" {
		return
	}
	ep := r.endpoint()
	upper := strings.ToUpper(r.Cipher)
	for _, m := range weakCipherMarkers {
		if !strings.Contains(upper, strings.ToUpper(m.marker)) {
			continue
		}
		addFinding(disc, ep, "weak-cipher", m.severity,
			"Service negotiates the weak cipher "+r.Cipher,
			fmt.Sprintf("%s negotiated %s: %s.", ep, r.Cipher, m.why))
		// One finding per service for the cipher: the strongest marker
		// that matched is the one worth reporting, and the table is
		// ordered by severity.
		return
	}
}

func parseJSONLines(raw []byte, now time.Time) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	lines := strings.Split(string(raw), "\n")
	parsed := 0
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var r response
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", i+1, err)
		}
		parsed++
		// A failed probe is not a finding about the service's TLS; it is
		// the absence of an observation. Reporting it as a weakness would
		// turn every unreachable host into a vulnerability.
		if !r.ProbeStatus {
			continue
		}
		certificateFindings(disc, &r, now)
		protocolFindings(disc, &r)
		cipherFindings(disc, &r)
	}
	if parsed == 0 {
		return disc, registry.ParseQualityPartial, nil
	}
	return disc, registry.ParseQualityStructured, nil
}
