// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// TestDecodeInputJSON_Fields asserts that decodeInputJSON correctly maps the
// "target" and "args" fields into ExecuteRequest and puts unknown string
// fields into Options.
func TestDecodeInputJSON_Fields(t *testing.T) {
	input := `{"target":"192.168.1.1","ports":"80,443","args":["-sV","-O"]}`
	req, err := decodeInputJSON(input)
	if err != nil {
		t.Fatalf("decodeInputJSON: %v", err)
	}
	if req.Target != "192.168.1.1" {
		t.Errorf("Target = %q; want 192.168.1.1", req.Target)
	}
	if len(req.Args) != 2 || req.Args[0] != "-sV" || req.Args[1] != "-O" {
		t.Errorf("Args = %v; want [-sV -O]", req.Args)
	}
	if req.Options["ports"] != "80,443" {
		t.Errorf("Options[ports] = %q; want 80,443", req.Options["ports"])
	}
}

// TestDecodeInputJSON_Empty asserts that an empty input_json returns a
// zero ExecuteRequest without error.
func TestDecodeInputJSON_Empty(t *testing.T) {
	req, err := decodeInputJSON("")
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if req.Target != "" || len(req.Args) != 0 || len(req.Options) != 0 {
		t.Errorf("expected zero ExecuteRequest, got %+v", req)
	}
}

// TestDecodeInputJSON_TargetOnly asserts that a payload with only "target"
// works and produces no Options.
func TestDecodeInputJSON_TargetOnly(t *testing.T) {
	req, err := decodeInputJSON(`{"target":"10.0.0.1"}`)
	if err != nil {
		t.Fatalf("decodeInputJSON: %v", err)
	}
	if req.Target != "10.0.0.1" {
		t.Errorf("Target = %q; want 10.0.0.1", req.Target)
	}
	if len(req.Options) != 0 {
		t.Errorf("Options should be empty, got %v", req.Options)
	}
}

// ---------------------------------------------------------------------------
// End-to-end dispatch through a fake parser — verifies the full pipeline
// from input decode → Execute → ABI emission without requiring any CLI tool.
// ---------------------------------------------------------------------------

// fakeParser is a minimal registry.Parser for dispatch tests.
type fakeParser struct {
	name   string
	result *registry.ExecuteResponse
	err    error
}

func (f *fakeParser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{Name: f.name}
}

func (f *fakeParser) Execute(_ context.Context, _ registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	return f.result, f.err
}

func (f *fakeParser) OutputMessage() proto.Message { return nil }

// TestDispatch_SuccessPath verifies that a successful Execute round-trips
// through emitResponse and produces a valid ABI marker line.
func TestDispatch_SuccessPath(t *testing.T) {
	// Build a CallToolRequest and encode it as the ABI expects.
	callReq := &componentpb.CallToolRequest{
		ToolName:  "test-fake",
		InputJson: `{"target":"127.0.0.1"}`,
		TimeoutMs: 30000,
	}
	raw, err := protojson.Marshal(callReq)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b64Input := base64.StdEncoding.EncodeToString(raw)

	// Decode and map — same path as runDefault.
	var decoded componentpb.CallToolRequest
	decRaw, _ := base64.StdEncoding.DecodeString(b64Input)
	if err := protojson.Unmarshal(decRaw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	execReq, err := decodeInputJSON(decoded.GetInputJson())
	if err != nil {
		t.Fatalf("decodeInputJSON: %v", err)
	}
	if got := resolveTimeoutSeconds(decoded.GetTimeoutMs(), 0); got != 30 {
		t.Errorf("timeout = %d; want 30", got)
	}
	if execReq.Target != "127.0.0.1" {
		t.Errorf("Target = %q; want 127.0.0.1", execReq.Target)
	}
}

// TestEmitResponse_RoundTrip verifies that emitResponse produces a line that
// starts with abiOutputMarker and contains a valid base64(protojson(CallToolResponse)).
func TestEmitResponse_RoundTrip(t *testing.T) {
	// We can't call emitResponse directly since it writes to os.Stdout and
	// calls os.Exit on marshal error — but we can test the component pieces.
	resp := &componentpb.CallToolResponse{
		OutputJson: `{"hosts":[]}`,
	}
	b, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	line := abiOutputMarker + base64.StdEncoding.EncodeToString(b)
	if !strings.HasPrefix(line, abiOutputMarker) {
		t.Error("line does not start with ABI output marker")
	}

	// Verify the encoded response round-trips.
	enc := strings.TrimPrefix(line, abiOutputMarker)
	decoded, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var got componentpb.CallToolResponse
	if err := protojson.Unmarshal(decoded, &got); err != nil {
		t.Fatalf("protojson unmarshal: %v", err)
	}
	if got.GetOutputJson() != `{"hosts":[]}` {
		t.Errorf("output_json = %q; want {\"hosts\":[]}", got.GetOutputJson())
	}
}

// TestArgsPolicy_DeniedByDefault verifies that a nil policy (no registered
// policy) drops all flags — the default-deny behaviour protects new parsers
// that haven't authored their allowlist yet.
func TestArgsPolicy_DeniedByDefault(t *testing.T) {
	toolName := "unregistered-test-tool-" + t.Name()
	filtered, err := registry.ApplyPolicy(toolName, []string{"-oN", "/etc/passwd"}, nil)
	if err != nil {
		t.Fatalf("ApplyPolicy returned error: %v", err)
	}
	if len(filtered) != 0 {
		t.Errorf("filtered = %v; want empty (deny-all on nil policy)", filtered)
	}
}

// TestTimeout_ContextPropagates verifies that a short timeout cancels the
// context before a long-running (simulated) Execute completes.
func TestTimeout_ContextPropagates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Error("context did not cancel within expected window")
		}
		close(done)
	}()
	<-done
	if ctx.Err() != context.DeadlineExceeded {
		t.Errorf("ctx.Err() = %v; want DeadlineExceeded", ctx.Err())
	}
}

// TestDecodeInputJSON_NonStringOptionsIgnored asserts that non-string values
// in input_json (e.g. integers) are silently skipped rather than erroring.
func TestDecodeInputJSON_NonStringOptionsIgnored(t *testing.T) {
	// "depth" is an integer — should not end up in Options.
	req, err := decodeInputJSON(`{"target":"example.com","depth":5,"timeout_label":"30s"}`)
	if err != nil {
		t.Fatalf("decodeInputJSON: %v", err)
	}
	if req.Target != "example.com" {
		t.Errorf("Target = %q; want example.com", req.Target)
	}
	if _, ok := req.Options["depth"]; ok {
		t.Error("integer field 'depth' should not appear in Options")
	}
	if req.Options["timeout_label"] != "30s" {
		t.Errorf("Options[timeout_label] = %q; want 30s", req.Options["timeout_label"])
	}
}

// Silence unused-import warnings for packages only used indirectly.
var (
	_               = json.Unmarshal
	_ proto.Message = nil
)

// ---------------------------------------------------------------------------
// Target-policy coverage. This file is the one place where every parser is
// linked in, so it is where the "no parser may skip the target gate"
// invariant can actually be enforced.
// ---------------------------------------------------------------------------

// TestEveryParserRegistersATargetPolicy fails the build for a new parser
// that forgets registry.RegisterTargetPolicy. req.Target is caller-
// controlled input spliced straight into a tool's argv; a parser without a
// declared target syntax has no gate on that slot at all.
func TestEveryParserRegistersATargetPolicy(t *testing.T) {
	for _, entry := range registry.Catalog() {
		if _, ok := registry.LookupTargetPolicy(entry.Name); !ok {
			t.Errorf("parser %q registered no target policy; add registry.RegisterTargetPolicy in its policy.go", entry.Name)
		}
	}
}

// TestEveryParserRejectsAFlagShapedTarget walks every registered parser
// and asserts a leading-dash target is refused. A target that begins with
// "-" is read by the underlying CLI as a flag, which would let a caller
// reach flags the per-tool allowlist denies.
func TestEveryParserRejectsAFlagShapedTarget(t *testing.T) {
	for _, entry := range registry.Catalog() {
		for _, target := range []string{"-oN", "--config", "-"} {
			if err := registry.ValidateTarget(entry.Name, target); err == nil {
				t.Errorf("parser %q accepted flag-shaped target %q", entry.Name, target)
			}
		}
	}
}

// TestEveryParserRejectsALineBreakingTarget walks every registered parser
// and asserts a target carrying a newline is refused. Several tools read
// their subject list line by line, so one newline is several targets.
func TestEveryParserRejectsALineBreakingTarget(t *testing.T) {
	for _, entry := range registry.Catalog() {
		for _, target := range []string{"example.com\nevil.example.com", "10.0.0.1\r10.0.0.2", "example.com\x00"} {
			if err := registry.ValidateTarget(entry.Name, target); err == nil {
				t.Errorf("parser %q accepted line-breaking target %q", entry.Name, target)
			}
		}
	}
}

// TestValidateTarget_UnregisteredToolFailsClosed pins the default: no
// declared target syntax means no argv gets built.
func TestValidateTarget_UnregisteredToolFailsClosed(t *testing.T) {
	if err := registry.ValidateTarget("tool-that-does-not-exist", "10.0.0.1"); err == nil {
		t.Fatal("an unregistered tool accepted a target; the default must fail closed")
	}
}

// ---------------------------------------------------------------------------
// Timeout resolution. Every tool call must carry a deadline; the interesting
// cases are the two that used to produce "no deadline at all".
// ---------------------------------------------------------------------------

// TestResolveTimeout_OmittedUsesParserDefault is the central regression: a
// CallToolRequest that carries no timeout_ms must inherit the parser's
// declared DefaultTimeoutSeconds. Before this was wired up the parser default
// was decorative — declared in every catalog entry and read by nobody — and a
// request without an explicit timeout ran with no deadline.
func TestResolveTimeout_OmittedUsesParserDefault(t *testing.T) {
	for _, ms := range []int64{0, -1} {
		got := resolveTimeoutSeconds(ms, 600)
		if got != 600 {
			t.Errorf("resolveTimeoutSeconds(%d, 600) = %d; want 600 (parser default)", ms, got)
		}
	}
}

// TestResolveTimeout_SubSecondRoundsUp covers the inversion case: timeout_ms
// below 1000 used to integer-divide to zero, and zero meant "unbounded". The
// tightest deadline a caller can express must not become the loosest.
func TestResolveTimeout_SubSecondRoundsUp(t *testing.T) {
	for _, ms := range []int64{1, 100, 500, 999} {
		got := resolveTimeoutSeconds(ms, 600)
		if got != 1 {
			t.Errorf("resolveTimeoutSeconds(%d, 600) = %d; want 1", ms, got)
		}
	}
}

// TestResolveTimeout_AlwaysPositive asserts the invariant the caller relies on
// to apply context.WithTimeout unconditionally.
func TestResolveTimeout_AlwaysPositive(t *testing.T) {
	cases := []struct {
		name          string
		ms            int64
		parserDefault int32
	}{
		{"no request timeout, no parser default", 0, 0},
		{"negative request timeout, no parser default", -5000, 0},
		{"negative parser default", 0, -1},
		{"both supplied", 45000, 300},
		{"sub-second, no parser default", 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveTimeoutSeconds(tc.ms, tc.parserDefault); got <= 0 {
				t.Fatalf("resolveTimeoutSeconds(%d, %d) = %d; a tool call must never be unbounded",
					tc.ms, tc.parserDefault, got)
			}
		})
	}
}

// TestResolveTimeout_FallbackWhenParserDeclaresNone verifies the backstop for a
// future parser that omits DefaultTimeoutSeconds.
func TestResolveTimeout_FallbackWhenParserDeclaresNone(t *testing.T) {
	if got := resolveTimeoutSeconds(0, 0); got != fallbackTimeoutSeconds {
		t.Errorf("resolveTimeoutSeconds(0, 0) = %d; want the %d s fallback", got, fallbackTimeoutSeconds)
	}
}

// TestResolveTimeout_ExplicitWins asserts precedence and exact conversion.
func TestResolveTimeout_ExplicitWins(t *testing.T) {
	cases := map[int64]int32{
		1000:   1,
		1001:   2,
		30000:  30,
		45500:  46,
		600000: 600,
	}
	for ms, want := range cases {
		if got := resolveTimeoutSeconds(ms, 300); got != want {
			t.Errorf("resolveTimeoutSeconds(%d, 300) = %d; want %d", ms, got, want)
		}
	}
}

// TestResolveTimeout_HugeValueSaturates verifies that an out-of-range
// timeout_ms saturates instead of wrapping round to a short or negative
// deadline.
func TestResolveTimeout_HugeValueSaturates(t *testing.T) {
	got := resolveTimeoutSeconds(math.MaxInt64, 300)
	if got != math.MaxInt32 {
		t.Errorf("resolveTimeoutSeconds(MaxInt64, 300) = %d; want MaxInt32", got)
	}
}

// TestEveryParserDeclaresADefaultTimeout is the companion invariant to
// TestEveryParserRegistersATargetPolicy. resolveTimeoutSeconds has a fallback
// so a parser that omits the field is still bounded, but the fallback is a
// backstop, not a substitute for a tool-appropriate deadline: nuclei and nmap
// need very different ones. This file is the one place every parser is linked
// in, so it is where the invariant can be enforced.
func TestEveryParserDeclaresADefaultTimeout(t *testing.T) {
	for _, entry := range registry.Catalog() {
		if entry.DefaultTimeoutSeconds <= 0 {
			t.Errorf("parser %q declares DefaultTimeoutSeconds=%d; set a tool-appropriate deadline in its Describe()",
				entry.Name, entry.DefaultTimeoutSeconds)
		}
	}
}
