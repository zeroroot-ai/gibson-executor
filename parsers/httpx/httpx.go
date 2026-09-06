// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package httpx implements a Gibson tool-runner parser wrapping
// ProjectDiscovery's httpx HTTP probe + fingerprinter. It runs
// `httpx -json` and decodes the JSON-lines output into Endpoint + Service +
// Technology taxonomy nodes inside a DiscoveryResult.
package httpx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

const (
	toolName       = "httpx"
	toolVersion    = "0.1.0"
	defaultTimeout = 180
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:        toolName,
		Version:     toolVersion,
		Description: "HTTP probe + fingerprinter (ProjectDiscovery httpx). Emits typed Endpoint/Service/Technology nodes.",
		Tags:        []string{"recon", "web", "fingerprint"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{"type": "string", "description": "URL, host, or IP. httpx accepts the same inputs via stdin; single value here is probed once."},
				"paths":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": `Paths to probe beneath the target (e.g. ["/", "/api"]).`},
				"args":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Extra httpx flags."},
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

// httpxResult is the subset of httpx's -json output we consume. httpx emits
// many more fields; we decode only what feeds taxonomy nodes and preserve
// the rest in stdout for operators who want to inspect raw output.
type httpxResult struct {
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	StatusCode    int      `json:"status_code"`
	ContentType   string   `json:"content_type"`
	ContentLength int64    `json:"content_length"`
	Title         string   `json:"title"`
	WebServer     string   `json:"webserver"`
	Tech          []string `json:"tech"`
	Scheme        string   `json:"scheme"`
	Method        string   `json:"method"`

	// Response headers, present because buildArgs always passes -irh.
	// httpx normalises each key to lowercase with "-" replaced by "_"
	// (runner.normalizeHeaders) and joins repeated values with ", ".
	Headers map[string]any `json:"header"`
	// Failed marks a probe that never got a response.
	Failed bool   `json:"failed"`
	Error  string `json:"error"`
}

// buildArgs composes the httpx argv. req.Options["paths"] previously
// reached `-path` unvalidated even though the allowlist already carried a
// validator for that exact flag — the option path simply did not consult
// it. It is routed through the allowlist now.
func buildArgs(req registry.ExecuteRequest) ([]string, error) {
	if err := registry.ValidateTarget(toolName, req.Target); err != nil {
		return nil, fmt.Errorf("httpx target: %w", err)
	}

	// -irh is fixed, not optional. The security-header findings below are
	// only possible when httpx reports the response headers, and an option
	// to turn them off would be a switch that silently removes a check
	// rather than reporting a clean result.
	args := []string{"-json", "-silent", "-irh", "-target", req.Target}
	if paths := req.Options["paths"]; paths != "" {
		pair, err := registry.ApplyOption(toolName, "-path", paths, nil)
		if err != nil {
			return nil, fmt.Errorf("httpx paths option: %w", err)
		}
		args = append(args, pair...)
	}

	filtered, err := registry.ApplyPolicy(toolName, req.Args, nil)
	if err != nil {
		return nil, err
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
	cmd := exec.CommandContext(ctx, "httpx", args...)
	if err := sandbox.Apply(cmd, sbCfg); err != nil {
		// No resource ceiling means no run: an unbounded tool child is the
		// condition the sandbox exists to prevent, so fail closed.
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("httpx sandbox: %w", err)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}
	if cmd.ProcessState != nil {
		resp.ExitCode = int32(cmd.ProcessState.ExitCode())
	}

	if err := stdout.Err(); err != nil {
		return resp, fmt.Errorf("httpx stdout: %w", err)
	}
	disc, quality, parseErr := parseJSONLines(stdout.Bytes())
	resp.Discovery = disc
	resp.ParseQuality = quality
	if runErr != nil && len(stdout.Bytes()) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("httpx exec: %w", runErr)
	}
	if parseErr != nil {
		return resp, fmt.Errorf("httpx parse: %w", parseErr)
	}
	return resp, nil
}

// parseJSONLines converts httpx's -json output to a DiscoveryResult. Each
// line is one probe result. Empty input → empty DiscoveryResult + quality
// RAW (nothing to structure).
func parseJSONLines(raw []byte) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	lines := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r httpxResult
		if err := json.Unmarshal(line, &r); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", lines+1, err)
		}
		lines++
		appendProbe(disc, r)
		securityHeaderFindings(disc, r)
	}
	if err := sc.Err(); err != nil {
		return disc, registry.ParseQualityPartial, err
	}
	if lines == 0 {
		return disc, registry.ParseQualityRaw, nil
	}
	return disc, registry.ParseQualityStructured, nil
}

func appendProbe(disc *graphragpb.DiscoveryResult, r httpxResult) {
	// Service — synthetic "http" or scheme if present.
	serviceID := fmt.Sprintf("service:%s", r.URL)
	serviceName := "http"
	if strings.ToLower(r.Scheme) == "https" {
		serviceName = "https"
	}
	svc := &graphragpb.Service{
		Id:   &serviceID,
		Name: serviceName,
	}
	if r.WebServer != "" {
		ws := r.WebServer
		svc.Product = &ws
	}
	disc.Services = append(disc.Services, svc)

	// Endpoint.
	ep := &graphragpb.Endpoint{
		ServiceId: serviceID,
		Url:       r.URL,
	}
	epID := fmt.Sprintf("endpoint:%s", r.URL)
	ep.Id = &epID
	if r.Method != "" {
		m := r.Method
		ep.Method = &m
	}
	if r.StatusCode != 0 {
		sc := int32(r.StatusCode)
		ep.StatusCode = &sc
	}
	if r.ContentType != "" {
		ct := r.ContentType
		ep.ContentType = &ct
	}
	if r.ContentLength > 0 {
		cl := r.ContentLength
		ep.ContentLength = &cl
	}
	if r.Title != "" {
		t := r.Title
		ep.Title = &t
	}
	disc.Endpoints = append(disc.Endpoints, ep)

	// Technology fingerprints.
	for _, t := range r.Tech {
		if t == "" {
			continue
		}
		parent := epID
		parentType := "endpoint"
		techID := fmt.Sprintf("tech:%s:%s", r.URL, t)
		disc.Technologies = append(disc.Technologies, &graphragpb.Technology{
			Id:         &techID,
			Name:       t,
			ParentId:   &parent,
			ParentType: &parentType,
		})
	}
}

// --- security-response-header findings -----------------------------------
//
// httpx already fetches the response, so the header posture of a service is
// a fact it has in hand. This is the second half of #400; the first (TLS)
// lives in parsers/tlsx against a different binary.
//
// It lives in the httpx parser rather than in a tool of its own because a
// second parser would have to exec the same httpx binary and would
// duplicate its argv construction, allowlist and execution path — a second
// codepath for one concern (ADR-0027). One binary, one parser.

// securityHeader is one row of the judgement. The tool reports headers;
// which absent header is a problem, and how bad, is a decision, and it is
// gathered here so it can be argued with rather than being rediscovered by
// reading code.
//
// Key names are httpx's normalised form: lowercase, "-" replaced by "_".
type securityHeader struct {
	key        string
	kind       string
	severity   string
	title      string
	why        string
	httpsOnly  bool
	wantValue  string // when set, the header must contain this (lowercased)
	valueTitle string // title used when the header is present but wrong
}

// securityHeaders is the table. Severities are deliberately modest: a
// missing header is a weakened defence, not a breach, and grading them
// higher than the certificate and protocol findings in parsers/tlsx would
// bury those.
var securityHeaders = []securityHeader{
	{
		key: "strict_transport_security", kind: "missing-hsts", severity: "medium",
		title:     "HSTS is not set",
		why:       "Without Strict-Transport-Security a browser will still try the site over plaintext, so a first request can be intercepted and downgraded.",
		httpsOnly: true,
	},
	{
		key: "content_security_policy", kind: "missing-csp", severity: "medium",
		title: "Content-Security-Policy is not set",
		why:   "Without a policy the browser executes any script the page references, so an injected script runs with the page's full authority.",
	},
	{
		key: "x_content_type_options", kind: "missing-nosniff", severity: "low",
		title:      "X-Content-Type-Options is not set to nosniff",
		why:        "Without nosniff a browser may re-interpret a response as a type the server never intended, which turns an upload into a script.",
		wantValue:  "nosniff",
		valueTitle: "X-Content-Type-Options does not say nosniff",
	},
	{
		key: "x_frame_options", kind: "missing-frame-options", severity: "low",
		title: "X-Frame-Options is not set",
		why:   "Without it, or a CSP frame-ancestors directive, the page can be framed by another origin and clicks on it redressed.",
	},
	{
		key: "referrer_policy", kind: "missing-referrer-policy", severity: "low",
		title: "Referrer-Policy is not set",
		why:   "Without it the full URL, including anything sensitive in the path or query, is sent to third-party origins the page links to.",
	},
}

// headerValue returns the header's value as a lowercase string. httpx joins
// repeated values with ", " and may hand back a non-string for an odd
// header, so anything that is not a string is treated as present-but-opaque.
func headerValue(headers map[string]any, key string) (string, bool) {
	v, ok := headers[key]
	if !ok {
		return "", false
	}
	s, isString := v.(string)
	if !isString {
		return "", true
	}
	return strings.ToLower(strings.TrimSpace(s)), true
}

// securityHeaderFindings grades one probe's response headers.
//
// Silence is the point. Three cases produce nothing at all:
//   - a probe that failed, because an unreachable host is the absence of an
//     observation rather than a weakness;
//   - a response with no headers recorded, because "we did not look" must
//     never render as "every header is missing";
//   - a correctly configured service.
func securityHeaderFindings(disc *graphragpb.DiscoveryResult, r httpxResult) {
	if r.Failed || r.StatusCode == 0 || len(r.Headers) == 0 {
		return
	}
	isHTTPS := strings.EqualFold(r.Scheme, "https")
	target := r.URL
	if target == "" {
		target = r.Host
	}

	// A CSP that names frame-ancestors is the modern replacement for
	// X-Frame-Options, so reporting the old header as missing when the new
	// mechanism is present would be a finding nobody should act on.
	csp, hasCSP := headerValue(r.Headers, "content_security_policy")
	framedByCSP := hasCSP && strings.Contains(csp, "frame-ancestors")

	for _, h := range securityHeaders {
		if h.httpsOnly && !isHTTPS {
			continue
		}
		if h.kind == "missing-frame-options" && framedByCSP {
			continue
		}
		value, present := headerValue(r.Headers, h.key)
		switch {
		case !present:
			addHeaderFinding(disc, target, h.kind, h.severity, h.title, h.why)
		case h.wantValue != "" && !strings.Contains(value, h.wantValue):
			addHeaderFinding(disc, target, h.kind, h.severity, h.valueTitle, h.why)
		}
	}
}

func addHeaderFinding(disc *graphragpb.DiscoveryResult, target, kind, severity, title, why string) {
	id := fmt.Sprintf("finding:header:%s:%s", target, kind)
	disc.Findings = append(disc.Findings, &graphragpb.Finding{
		Id:          proto.String(id),
		Title:       title,
		Severity:    severity,
		Description: proto.String(fmt.Sprintf("%s %s", target, why)),
		Category:    proto.String("security-header"),
		ParentType:  proto.String("endpoint"),
		ParentId:    proto.String(target),
	})
}
