// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command gibson-runner is the entry point executed inside a Setec microVM to
// dispatch a single Gibson tool call, or (with --list-tools) emit the JSON
// catalog of every parser compiled into this binary.
//
// Three modes:
//
//	gibson-runner --list-tools
//	    Print a JSON array of CatalogEntry objects to stdout, exit 0.
//	    The Gibson daemon's catalog refresher ingests this to populate
//	    ComponentRegistry entries — adding a tool never requires a daemon
//	    restart or Helm change.
//
//	gibson-runner --serve
//	    Run as a long-lived deployment service. Initialises OTel observability
//	    and starts an HTTP health server (default :8081) exposing /readyz and
//	    /healthz. Blocks until SIGTERM/SIGINT.
//	    Use this mode in Kubernetes deployments.
//
//	gibson-runner
//	    Default. Reads GIBSON_TOOL_NAME from env, looks up its registered
//	    parser, reads GIBSON_TOOL_INPUT_B64 for the typed request, executes,
//	    and emits the response via the standard tool-runner ABI marker on
//	    stdout. Exit codes: 0 success, 1 input parse error, 2 execute error,
//	    3 output marshal error, 4 tool not registered.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zeroroot-ai/gibson-executor/internal/observability"
	"github.com/zeroroot-ai/gibson-executor/internal/probes"
	"github.com/zeroroot-ai/gibson-executor/internal/readiness"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"

	// Blank-import every parser package so its init() registers with the
	// central parser registry. The list grows as parsers land.
	//
	// amass is deliberately absent: no shippable amass version accepts the
	// argv the parser built (v3 has the flag but the worst CVEs, v4 dropped
	// JSON output entirely, v5 removed the embedded engine this one-shot
	// exec model needs). See #370 for the follow-up that would restore it
	// against v4's -o/-oA text output.
	_ "github.com/zeroroot-ai/gibson-executor/parsers/dnsx"
	_ "github.com/zeroroot-ai/gibson-executor/parsers/httpx"
	_ "github.com/zeroroot-ai/gibson-executor/parsers/masscan"
	_ "github.com/zeroroot-ai/gibson-executor/parsers/naabu"
	_ "github.com/zeroroot-ai/gibson-executor/parsers/nmap"
	_ "github.com/zeroroot-ai/gibson-executor/parsers/nuclei"
	_ "github.com/zeroroot-ai/gibson-executor/parsers/subfinder"
	_ "github.com/zeroroot-ai/gibson-executor/parsers/tlsx"
	_ "github.com/zeroroot-ai/gibson-executor/parsers/trivy"
)

const (
	envToolName = "GIBSON_TOOL_NAME"
	envInputB64 = "GIBSON_TOOL_INPUT_B64"

	// envHealthAddr is the listen address for the health HTTP server in --serve
	// mode. Defaults to ":8081" (non-privileged port; configurable so tests
	// can bind to :0).
	envHealthAddr = "RUNNER_HEALTH_ADDR"

	// serviceName is the OTel service.name attribute for this binary.
	serviceName = "gibson-executor"

	exitOK                = 0
	exitInputParse        = 1
	exitExecuteError      = 2
	exitOutputMarshal     = 3
	exitToolNotRegistered = 4
)

func main() {
	// FIRST, before flags: this process may be a re-exec'd copy of ourselves
	// whose only job is to set the tool's RLIMIT_AS and execve the real
	// binary. In that mode RunPreExec never returns.
	sandbox.RunPreExec()

	// Bound the runner's own address space. The runner is what buffers tool
	// output, so limiting only the tool children would leave the biggest
	// allocator in the pipeline unbounded. Best-effort: CappedBuffer is the
	// unconditional bound, this is defence in depth, and a platform that
	// refuses setrlimit(2) should not stop the runner from starting.
	sbCfg := sandbox.DefaultConfig()
	if err := sandbox.ApplySelf(sbCfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: runner memory limit not applied: %v\n", err)
	}

	listTools := flag.Bool("list-tools", false, "Emit the JSON catalog of every parser compiled into this binary and exit.")
	verifyTools := flag.Bool("verify-tools", false, "Check that every catalogued tool resolves to an executable on PATH; exit non-zero if any is missing.")
	serve := flag.Bool("serve", false, "Run as a long-lived service, starting the health HTTP server. Use in Kubernetes deployments.")
	flag.Parse()

	if *listTools {
		runListTools()
		return
	}
	if *verifyTools {
		runVerifyTools()
		return
	}
	if *serve {
		runServe()
		return
	}
	runDefault()
}

func runListTools() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(registry.Catalog()); err != nil {
		fmt.Fprintf(os.Stderr, "encode catalog: %v\n", err)
		os.Exit(1)
	}
}

// runVerifyTools reports whether this image can actually run what its catalog
// advertises (#352).
//
// The catalog is the daemon's source of truth for what this image can do, and
// it is derived from the parsers compiled into the binary — not from what is
// installed. Nothing previously connected the two, so five parsers shipped for
// four months against an image that had none of their binaries. A mission
// dispatched to one of them failed with `exec: "<tool>": executable file not
// found in $PATH`, surfaced to the caller as a failed tool run rather than as
// "not supported here".
//
// Run this against a built image to get the answer directly rather than by
// reading a Dockerfile.
func runVerifyTools() {
	names := cataloguedToolNames()
	var missing []string
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			missing = append(missing, name)
			fmt.Fprintf(os.Stderr, "MISSING %s\n", name)
			continue
		}
		fmt.Printf("ok      %s\n", name)
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr,
			"\n%d of %d catalogued tools are not installed in this image: %s\n"+
				"The catalog advertises capability this image cannot deliver.\n",
			len(missing), len(names), strings.Join(missing, ", "))
		os.Exit(1)
	}
}

// cataloguedToolNames returns the tool name of every registered parser.
//
// It lives here, beside the other registry callers, rather than in the
// drift-guard test: cmd/ is subject to a depguard rule that forbids new
// imports of internal/registry, and main.go's import predates it. Routing the
// test through this helper keeps the guard working without either widening the
// depguard allowlist or suppressing it.
func cataloguedToolNames() []string {
	entries := registry.Catalog()
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name)
	}
	return out
}

// runServe starts OTel observability, wires the readiness aggregator with a
// daemon-reachability probe, and blocks on the health HTTP server until
// SIGTERM or SIGINT.
//
// Trace context propagation: observability.Init registers the global OTel
// W3C TraceContext + Baggage propagators. When the daemon stamps outgoing tool
// invocations with a traceparent header, gRPC interceptors and context-aware
// libraries transparently propagate the mission trace ID into every child span
// started inside this process — giving end-to-end visibility from the
// mission's LLM-decision span through to the tool-execution span.
func runServe() {
	// Initialise OTel. The call is idempotent; OTEL_EXPORTER_OTLP_ENDPOINT
	// controls whether traces are exported (no-op when unset so local runs
	// stay quiet without a collector).
	otelProvider, err := observability.Init(context.Background(), serviceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "observability init: %v\n", err)
		os.Exit(1)
	}

	logger := otelProvider.Logger
	logger.Info("gibson-executor starting", "mode", "serve")

	// Readiness aggregator — daemon-callback reachability probe.
	agg := readiness.NewAggregator()
	agg.Register(probes.NewDaemonProbe(0))

	// Health HTTP server.
	addr := healthAddr()
	mux := http.NewServeMux()
	mux.Handle("/readyz", agg.ReadyHandler())
	mux.Handle("/healthz", agg.LivenessHandler())

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Serve in the background; block until signal.
	go func() {
		logger.Info("health server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("health server error", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	logger.Info("shutting down")

	// Graceful HTTP shutdown.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		logger.Warn("health server shutdown error", "error", err)
	}

	// Flush buffered OTel spans and metrics.
	flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer flushCancel()
	if err := otelProvider.Shutdown(flushCtx); err != nil {
		logger.Warn("otel shutdown error", "error", err)
	}

	logger.Info("shutdown complete")
}

// abiOutputMarker and abiErrorMarker are the ABI sentinel prefixes the daemon
// parses from the last stdout line to extract the b64-encoded response or error.
const (
	abiOutputMarker = "===GIBSON_TOOL_OUTPUT==="
	abiErrorMarker  = "===GIBSON_TOOL_ERROR==="
)

func runDefault() {
	toolName := strings.TrimSpace(os.Getenv(envToolName))
	if toolName == "" {
		fmt.Fprintf(os.Stderr, "%s not set\n", envToolName)
		os.Exit(exitInputParse)
	}
	parser, ok := registry.Lookup(toolName)
	if !ok {
		emitError(fmt.Sprintf("tool %q not registered in this runner image", toolName))
		os.Exit(exitToolNotRegistered)
	}

	// Decode the request envelope from GIBSON_TOOL_INPUT_B64.
	inputB64 := strings.TrimSpace(os.Getenv(envInputB64))
	if inputB64 == "" {
		fmt.Fprintf(os.Stderr, "%s not set\n", envInputB64)
		os.Exit(exitInputParse)
	}
	raw, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "base64 decode %s: %v\n", envInputB64, err)
		os.Exit(exitInputParse)
	}
	var callReq componentpb.CallToolRequest
	if err := protojson.Unmarshal(raw, &callReq); err != nil {
		fmt.Fprintf(os.Stderr, "protojson unmarshal CallToolRequest: %v\n", err)
		os.Exit(exitInputParse)
	}

	// Map CallToolRequest.input_json into the internal ExecuteRequest.
	execReq, err := decodeInputJSON(callReq.GetInputJson())
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode input_json: %v\n", err)
		os.Exit(exitInputParse)
	}
	execReq.Timeout = resolveTimeoutSeconds(callReq.GetTimeoutMs(), parser.Describe().DefaultTimeoutSeconds)

	// Validate the target once, centrally, before any parser sees it.
	// Every parser also validates in its own buildArgs — this gate is the
	// backstop that keeps a future parser which forgets the call from
	// becoming reachable with a hostile target.
	if err := registry.ValidateTarget(toolName, execReq.Target); err != nil {
		emitResponse(&componentpb.CallToolResponse{
			Error: &componentpb.ComponentError{
				Code:      "INVALID_TARGET",
				Message:   err.Error(),
				Retryable: false,
			},
		})
		os.Exit(exitExecuteError)
	}

	// Root context: honour SIGTERM/SIGINT so the process exits cleanly when
	// the microVM supervisor terminates it.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Per-call timeout on top of the signal context. resolveTimeoutSeconds
	// always returns a positive value, so this is unconditional: there is no
	// input that produces a tool run with no deadline.
	ctx, timeoutCancel := context.WithTimeout(ctx, time.Duration(execReq.Timeout)*time.Second)
	defer timeoutCancel()

	resp, execErr := parser.Execute(ctx, execReq)
	if execErr != nil {
		// The error is surfaced via CallToolResponse.error so the daemon can
		// log it as a structured outcome.
		//
		// The tool's own stderr is appended to the message. CallToolResponse
		// carries no stdout/stderr field, and ComponentError carries only a
		// string, so without this the caller receives `exit status 1` and the
		// reason dies inside the sandbox — the tool said why it failed and
		// nobody ever sees it. That is the difference between a diagnosable
		// failure and a mystery, for every tool here.
		code := "EXECUTE_ERROR"
		if resp != nil && resp.ParseQuality == registry.ParseQualityFailed {
			code = "PARSE_FAILED"
		}
		emitResponse(&componentpb.CallToolResponse{
			Error: &componentpb.ComponentError{
				Code:      code,
				Message:   withStderrTail(execErr.Error(), resp),
				Retryable: false,
			},
		})
		os.Exit(exitExecuteError)
	}

	// Marshal the DiscoveryResult as protojson into output_json. When there
	// is no discovery (e.g. the tool produced raw output only), emit an empty
	// DiscoveryResult so the daemon's JSON parser always gets a valid object.
	disc := resp.Discovery
	if disc == nil {
		disc = &graphragpb.DiscoveryResult{}
	}
	outputJSON, err := protojson.MarshalOptions{
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}.Marshal(disc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal DiscoveryResult: %v\n", err)
		os.Exit(exitOutputMarshal)
	}
	emitResponse(&componentpb.CallToolResponse{
		OutputJson: string(outputJSON),
	})
}

// fallbackTimeoutSeconds bounds a tool whose parser declares no
// DefaultTimeoutSeconds. Every parser in this binary declares one, so this is
// the backstop for a future parser that forgets: "the author omitted it" must
// degrade to a conservative deadline, never to no deadline at all.
const fallbackTimeoutSeconds int32 = 300

// resolveTimeoutSeconds decides the deadline for a single tool call.
//
// Precedence: an explicit CallToolRequest.timeout_ms wins; otherwise the
// parser's declared DefaultTimeoutSeconds; otherwise fallbackTimeoutSeconds.
// The result is always positive — a tool call never runs unbounded.
//
// Sub-second requests round *up* to one second. Truncating them to zero would
// turn the tightest deadline a caller can ask for into no deadline at all,
// which is the exact inversion of the request.
func resolveTimeoutSeconds(timeoutMs int64, parserDefaultSeconds int32) int32 {
	if timeoutMs > 0 {
		// Saturate before rounding, not after: a caller-supplied timeout_ms
		// near MaxInt64 would overflow the "+ 999" and wrap round to a short
		// (or negative) deadline.
		if timeoutMs > int64(math.MaxInt32)*1000 {
			return math.MaxInt32
		}
		return int32((timeoutMs + 999) / 1000)
	}
	if parserDefaultSeconds > 0 {
		return parserDefaultSeconds
	}
	return fallbackTimeoutSeconds
}

// decodeInputJSON unmarshals the tool-specific JSON payload (input_json from
// CallToolRequest) into an ExecuteRequest. The schema is tool-defined but all
// tools share a common subset: "target" (string), "args" ([]string), and
// arbitrary string k/v pairs that land in Options.
func decodeInputJSON(inputJSON string) (registry.ExecuteRequest, error) {
	var req registry.ExecuteRequest
	if inputJSON == "" {
		return req, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(inputJSON), &m); err != nil {
		return req, fmt.Errorf("unmarshal input_json: %w", err)
	}

	if raw, ok := m["target"]; ok {
		if err := json.Unmarshal(raw, &req.Target); err != nil {
			return req, fmt.Errorf("input_json.target: %w", err)
		}
		delete(m, "target")
	}

	if raw, ok := m["args"]; ok {
		if err := json.Unmarshal(raw, &req.Args); err != nil {
			return req, fmt.Errorf("input_json.args: %w", err)
		}
		delete(m, "args")
	}

	// Remaining fields become Options (string values only; non-strings are
	// skipped — parsers that need structured types handle them directly).
	if len(m) > 0 {
		req.Options = make(map[string]string, len(m))
	}
	for k, raw := range m {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			req.Options[k] = s
		}
	}
	return req, nil
}

// emitResponse marshals resp as protojson, base64-encodes it, and prints
// the ABI output marker line to stdout.
func emitResponse(resp *componentpb.CallToolResponse) {
	b, err := protojson.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal CallToolResponse: %v\n", err)
		os.Exit(exitOutputMarshal)
	}
	fmt.Printf("%s%s\n", abiOutputMarker, base64.StdEncoding.EncodeToString(b))
}

// emitError writes the ABI error marker and message to stdout. The caller is
// responsible for calling os.Exit with the appropriate code.
func emitError(msg string) {
	fmt.Printf("%s%s\n", abiErrorMarker, msg)
}

// healthAddr returns the listen address for the health HTTP server.
// It honours RUNNER_HEALTH_ADDR, defaulting to ":8081".
func healthAddr() string {
	if addr := os.Getenv(envHealthAddr); addr != "" {
		return addr
	}
	return ":8081"
}

// stderrTailBytes bounds how much of a failing tool's stderr is folded into
// the error message. Enough for a usage error or a stack of warnings ending
// in the real cause; far short of letting a chatty tool's output become the
// error itself.
const stderrTailBytes = 2000

// withStderrTail appends the tail of the tool's stderr to msg.
//
// A tool that fails says why on stderr; the runner's own error is usually
// just "exit status 1". Only the tail is kept, because the cause is at the
// end and the head is progress noise.
func withStderrTail(msg string, resp *registry.ExecuteResponse) string {
	if resp == nil || len(resp.Stderr) == 0 {
		return msg
	}
	tail := resp.Stderr
	if len(tail) > stderrTailBytes {
		tail = tail[len(tail)-stderrTailBytes:]
	}
	trimmed := strings.TrimSpace(string(tail))
	if trimmed == "" {
		return msg
	}
	return fmt.Sprintf("%s: %s", msg, trimmed)
}
