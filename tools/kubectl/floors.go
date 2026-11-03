// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build tools

// The security floors for the kubectl build.
//
// These blank imports do not reach the binary: the build tag keeps them out of
// a normal `go build`. They exist so that `go mod tidy` keeps x/net and x/text
// as DIRECT requirements in go.mod, where they read as a decision rather than
// resolver noise. Minimal version selection takes the maximum of every
// requirement in the build, so these raise what kubectl would otherwise link.
//
// Raise them freely. Never lower one to make a build pass — the Dockerfile
// re-checks the floors against the linked binary and fails the build rather
// than let a regression reach a published image.
package main

import (
	_ "golang.org/x/net/html"      // floor: v0.61.0 — CVE-2026-78669; kubectl v1.37.2 links v0.57.0
	_ "golang.org/x/text/language" // floor: v0.43.0 — CVE-2026-56851; kubectl v1.37.2 links v0.40.0
)
