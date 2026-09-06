// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package registry is the central map of parsers registered in the runner
// binary. Each parser file under parsers/ registers itself here via init(),
// so adding a parser is a single-file change: create parsers/<tool>/<tool>.go
// and call registry.Register(&myParser{}) in its init().
package registry

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson-executor/internal/policy"
)

// ExecuteRequest is the typed input every parser receives. Callers build it
// from the decoded env-in proto before dispatching to Parser.Run.
type ExecuteRequest struct {
	Target  string
	Args    []string
	Options map[string]string
	Timeout int32
}

// ExecuteResponse is the canonical runner output. Field-100-equivalent
// DiscoveryResult carries the taxonomy-aligned nodes; Stdout and Stderr
// preserve raw CLI output for diagnostics. ParseQuality tags richness so
// graph queries can filter.
type ExecuteResponse struct {
	ExitCode     int32
	Stdout       []byte
	Stderr       []byte
	ParseQuality ParseQuality
	Discovery    *graphragpb.DiscoveryResult
}

// ParseQuality mirrors gibson.component.v1.ParseQuality.
type ParseQuality int32

const (
	ParseQualityUnspecified ParseQuality = 0
	ParseQualityStructured  ParseQuality = 1
	ParseQualityPartial     ParseQuality = 2
	ParseQualityRaw         ParseQuality = 3
	ParseQualityFailed      ParseQuality = 4
)

// CatalogEntry is the self-description a parser emits via Parser.Describe;
// the runner's --list-tools command collects these and prints them as a JSON
// array that the Gibson daemon's catalog refresher ingests.
type CatalogEntry struct {
	Name                  string         `json:"name"`
	Version               string         `json:"version"`
	Description           string         `json:"description"`
	Tags                  []string       `json:"tags"`
	InputSchema           map[string]any `json:"input_schema"`
	OutputProtoType       string         `json:"output_proto_type"`
	DefaultParseQuality   ParseQuality   `json:"default_parse_quality"`
	Resources             ResourceHint   `json:"resources"`
	DefaultTimeoutSeconds int32          `json:"default_timeout_seconds"`
}

// ResourceHint is a per-tool suggested sandbox size. Operators can override
// in daemon config; the runner's hint is authoritative for first-class fit.
type ResourceHint struct {
	VCPU   int32  `json:"vcpu"`
	Memory string `json:"memory"`
}

// Parser is the contract every tool parser implements.
type Parser interface {
	// Describe returns the catalog entry for this parser — rendered in
	// --list-tools output and consumed by the Gibson daemon's refresher.
	Describe() CatalogEntry

	// Execute runs the underlying CLI with args built from the request and
	// parses the output into a DiscoveryResult. Implementations must populate
	// response.ParseQuality even on failure.
	Execute(ctx context.Context, req ExecuteRequest) (*ExecuteResponse, error)

	// OutputMessage returns a fresh empty proto.Message matching
	// CatalogEntry.OutputProtoType. The runner uses this to decide whether
	// a response-shaped wrapping is expected (v0.2+; today all parsers return
	// the canonical ExecuteResponse so this returns nil).
	OutputMessage() proto.Message
}

var (
	mu             sync.RWMutex
	parsers        = map[string]Parser{}
	registry       []Parser
	policies       = map[string]policy.ArgsPolicy{}
	openPolicies   = map[string]policy.OpenPolicy{}
	targetPolicies = map[string]policy.TargetKind{}
)

// Register records a parser in the global table. Panics if the name is
// already taken — parsers collide only on author error, never at runtime.
func Register(p Parser) {
	mu.Lock()
	defer mu.Unlock()
	name := p.Describe().Name
	if name == "" {
		panic("registry: parser Describe().Name is empty")
	}
	if _, dup := parsers[name]; dup {
		panic(fmt.Sprintf("registry: duplicate parser %q", name))
	}
	parsers[name] = p
	registry = append(registry, p)
}

// RegisterArgsPolicy associates a per-tool args allowlist with a tool name.
// Parsers should call this from init() right after Register() so the
// allowlist is in place before any Execute() reaches ApplyPolicy.
//
// Tools with no registered policy default-deny every flag — see
// policy.ApplyArgs's nil-policy semantics. That is intentional: failing
// closed prevents an oversight in a new tool's onboarding from opening
// a flag-injection hole.
// RegisterOpenArgsPolicy registers a tool under the inverted posture: every
// flag is allowed except those its OpenPolicy denies by capability class.
// A tool has either an allowlist or an open policy, never both — registering
// one clears the other so the effective posture is never ambiguous.
func RegisterOpenArgsPolicy(toolName string, o policy.OpenPolicy) {
	mu.Lock()
	defer mu.Unlock()
	if toolName == "" {
		panic("registry: RegisterOpenArgsPolicy with empty tool name")
	}
	openPolicies[toolName] = o
	delete(policies, toolName)
}

// LookupOpenArgsPolicy returns the registered open policy for a tool.
func LookupOpenArgsPolicy(toolName string) (policy.OpenPolicy, bool) {
	mu.RLock()
	defer mu.RUnlock()
	o, ok := openPolicies[toolName]
	return o, ok
}

func RegisterArgsPolicy(toolName string, p policy.ArgsPolicy) {
	mu.Lock()
	defer mu.Unlock()
	if toolName == "" {
		panic("registry: RegisterArgsPolicy with empty tool name")
	}
	policies[toolName] = p
	delete(openPolicies, toolName)
}

// LookupArgsPolicy returns the registered policy for a tool. Second
// return is false when no policy was registered (deny-all default).
func LookupArgsPolicy(toolName string) (policy.ArgsPolicy, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := policies[toolName]
	return p, ok
}

// ApplyPolicy is the canonical entry point parsers call before appending
// req.Args to their argv. It looks up the registered policy, runs
// policy.ApplyArgs, logs any dropped flags via the supplied logger
// (or slog.Default() when nil), and returns the filtered args plus the
// validator error (when any).
//
// Callers MUST surface a non-nil error as a structured InvalidArgument
// failure to the daemon — not silently treat it as "drop". A validator
// rejection means the caller deliberately tried something that pattern-
// matches the policy but failed the value check; that is the strongest
// adversarial signal in the surface and it deserves a hard error.
func ApplyPolicy(toolName string, args []string, log *slog.Logger) ([]string, error) {
	if log == nil {
		log = slog.Default()
	}
	var (
		out     []string
		dropped []policy.DroppedFlag
		err     error
	)
	if o, open := LookupOpenArgsPolicy(toolName); open {
		out, dropped, err = policy.ApplyOpen(args, o)
	} else {
		p, _ := LookupArgsPolicy(toolName)
		out, dropped, err = policy.ApplyArgs(args, p)
	}
	for _, d := range dropped {
		log.Warn("tool.flag.denied",
			"tool", toolName,
			"flag", d.Flag,
			"value", d.Value,
			"reason", d.Reason,
		)
	}
	if err != nil {
		log.Warn("tool.flag.value_rejected",
			"tool", toolName,
			"error", err.Error(),
		)
		return nil, err
	}
	return out, nil
}

// RegisterTargetPolicy declares which target syntaxes a tool accepts.
// Parsers call this from init() alongside RegisterArgsPolicy.
//
// A tool that registers nothing fails closed: ValidateTarget refuses to
// build an argv for it. req.Target is caller-controlled input spliced
// directly into the tool's argv, so "the author forgot" must never
// degrade into "anything goes".
func RegisterTargetPolicy(toolName string, kinds policy.TargetKind) {
	mu.Lock()
	defer mu.Unlock()
	if toolName == "" {
		panic("registry: RegisterTargetPolicy with empty tool name")
	}
	if kinds == 0 {
		panic(fmt.Sprintf("registry: RegisterTargetPolicy(%q) with no permitted target kind", toolName))
	}
	targetPolicies[toolName] = kinds
}

// LookupTargetPolicy returns the registered target kinds for a tool.
// Second return is false when the tool registered none.
func LookupTargetPolicy(toolName string) (policy.TargetKind, bool) {
	mu.RLock()
	defer mu.RUnlock()
	k, ok := targetPolicies[toolName]
	return k, ok
}

// ValidateTarget is the canonical gate every parser runs before splicing
// req.Target into an argv or into a tool's stdin. It is also run once
// centrally by the runner before dispatch, so a parser that forgets the
// call still cannot be reached with a hostile target.
//
// Callers MUST surface a non-nil error as an InvalidArgument failure. A
// rejected target is not a formatting nit: the shapes this rejects
// (a leading dash, an embedded newline, anything that is not an address
// or a name) exist only to make the tool reinterpret the scan subject as
// something else.
func ValidateTarget(toolName, target string) error {
	kinds, ok := LookupTargetPolicy(toolName)
	if !ok {
		return fmt.Errorf(
			"tool %q registered no target policy; refusing to build an argv", toolName)
	}
	if err := policy.ValidateTarget(target, kinds); err != nil {
		return fmt.Errorf("target rejected: %w", err)
	}
	return nil
}

// ApplyOption is the canonical entry point parsers call for every
// req.Options entry that becomes a CLI flag. It routes the option through
// the tool's registered args allowlist so an option value can never reach
// the argv on softer terms than the equivalent req.Args flag would.
//
// Returns the (flag, value) pair to append, or an error the caller must
// surface as InvalidArgument.
func ApplyOption(toolName, flag, value string, log *slog.Logger) ([]string, error) {
	if log == nil {
		log = slog.Default()
	}
	// Options stay strict under BOTH postures: the flag must carry a
	// validator, so an option can never reach the argv on softer terms than
	// the equivalent req.Args flag. An open policy supplies its Validators
	// here, which is why "allow everything" does not loosen the option door.
	p, _ := LookupArgsPolicy(toolName)
	if o, open := LookupOpenArgsPolicy(toolName); open {
		p = o.Validators
	}
	pair, err := policy.ApplyOption(p, flag, value)
	if err != nil {
		log.Warn("tool.option.rejected",
			"tool", toolName,
			"flag", flag,
			"error", err.Error(),
		)
		return nil, err
	}
	return pair, nil
}

// Lookup returns the parser for a tool name. Second return is false if the
// parser is not registered; callers surface TOOL_NOT_REGISTERED.
func Lookup(name string) (Parser, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := parsers[name]
	return p, ok
}

// Catalog returns every registered parser's CatalogEntry, sorted by name so
// --list-tools output is stable and easy to diff across releases.
func Catalog() []CatalogEntry {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]CatalogEntry, 0, len(registry))
	for _, p := range registry {
		out = append(out, p.Describe())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
