// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Per-tool args allowlist for tlsx.
//
// Coverage rationale:
//   - Port and SNI selection choose what is probed. Safe.
//   - The enumeration flags (`-ve`, `-ce`) make tlsx test every version and
//     cipher the service accepts rather than only what it negotiates. They
//     are what turns "this connection used TLS 1.3" into "this service also
//     still accepts TLS 1.0", which is the question worth asking, so they
//     are allowed even though they cost extra connections.
//   - Scan-mode selection (`-tls-version`, `-cipher`) is allowed: both
//     narrow the probe.
//   - Output flags (`-o`, `-output`, `-json`, `-silent`) are DENIED. The
//     runner parses tlsx's JSON lines on stdout; `-json` and `-silent` are
//     fixed in buildArgs, and a caller who could redirect or reformat the
//     output could make every probe report a clean service.
//   - `-cert`, `-so` and the certificate-dump flags are DENIED: they change
//     the record shape this parser reads.

package tlsx

import (
	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// tlsVersions is tlsx's documented version vocabulary, in its own spelling.
var tlsVersions = []string{"ssl30", "tls10", "tls11", "tls12", "tls13"}

var argsPolicy = policy.ArgsPolicy{
	// What to probe.
	"-p":    policy.PortSpec,
	"-port": policy.PortSpec,
	"-sni":  policy.AllowAny,

	// How thoroughly. See the note above: without these, tlsx reports only
	// the negotiated parameters and a service that still accepts a broken
	// version looks clean.
	"-ve":           nil,
	"-version-enum": nil,
	"-ce":           nil,
	"-cipher-enum":  nil,

	// Narrowing the probe.
	"-tls-version": policy.AllowCSVEnum(tlsVersions...),
	"-min-version": policy.AllowEnum(tlsVersions...),
	"-max-version": policy.AllowEnum(tlsVersions...),

	// Throughput and diagnostics that do not change what is reported.
	"-c":       policy.Numeric,
	"-timeout": policy.Numeric,
	"-retries": policy.Numeric,
	"-delay":   policy.AllowAny,
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
	// tlsx probes a host, an address or a URL.
	registry.RegisterTargetPolicy(toolName, policy.TargetWeb)
}
