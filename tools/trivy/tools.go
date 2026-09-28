// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build tools

// Package trivy pins the trivy scanner the executor image ships, and the
// security floor it builds against.
//
// Nothing here is compiled into anything. The blank imports exist so that
// `go mod tidy` keeps the requirements in go.mod.
//
// This is a separate module from tools/recon on purpose. trivy links a
// container runtime, several package-manager parsers and cloud SDKs. In one
// module with the scanners, every bump of either side could move the other's
// dependencies. Two modules keep the two resolutions apart. See README.md.
package trivy

import (
	// The tool. cmd/trivy is a main package and cannot be imported, so the
	// import names the package that main calls into.
	_ "github.com/aquasecurity/trivy/pkg/commands"

	// The security floor. Imported so it is a DIRECT requirement in go.mod and
	// reads as a decision, not as resolver noise. The upstream release
	// archives ship grpc v1.82.1, which carries two fixable HIGH findings and
	// blocked every image publish from 2026-09-16 (gibson-executor#69).
	_ "google.golang.org/grpc"
)
