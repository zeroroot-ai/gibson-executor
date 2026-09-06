// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build tools

// Package recon pins the third-party scanning tools the executor image ships,
// and the security floors those tools build against.
//
// Nothing here is compiled into anything. The blank imports exist so that
// `go mod tidy` keeps the requirements in go.mod: without them it would drop
// every one of them as unused, and the module would stop doing its job
// silently.
//
// See README.md for why this module exists at all — the short version is that
// `go install pkg@version` resolves from the tool's own go.mod and ignores
// ours, so it cannot be given a floor.
package recon

// The tools themselves. Version pins track the matching parser's expected CLI
// flags, not "latest" — read parsers/<tool>/ before bumping one.
import (
	_ "github.com/projectdiscovery/dnsx/cmd/dnsx"
	_ "github.com/projectdiscovery/httpx/cmd/httpx"
	_ "github.com/projectdiscovery/naabu/v2/cmd/naabu"
	_ "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
	_ "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
	_ "github.com/projectdiscovery/tlsx/cmd/tlsx"
)

// The security floors.
//
// These are imported for one reason: to make them DIRECT requirements in
// go.mod rather than `// indirect` ones. An indirect line reads like resolver
// noise and invites deletion; a direct line with this comment above it does
// not. Minimal version selection takes the maximum of every requirement in the
// build, so these raise what the tools above would otherwise drag in.
//
// Raise them freely. Never lower one to make a build pass — the Dockerfile
// re-checks the floors against the linked binaries and will fail the build
// rather than let a regression reach a published image.
import (
	_ "golang.org/x/crypto/ssh"    // floor: v0.52.0 — naabu shipped v0.46.0 (SSH authorization bypass, knownhosts revocation bypass)
	_ "golang.org/x/net/html"      // floor: v0.56.0 — naabu shipped v0.48.0, subfinder/dnsx v0.55.0
	_ "golang.org/x/text/language" // floor: v0.39.0 — naabu shipped v0.32.0, subfinder/dnsx v0.37.0
)
