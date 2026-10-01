// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build tools

// Package kubebench pins the kube-bench the executor image ships.
//
// Nothing here is compiled into anything. The blank import exists so that
// `go mod tidy` keeps the requirement in go.mod. The root package of
// kube-bench is a main package and cannot be imported, so the import names
// the package its main calls into.
//
// It is a separate module from tools/recon and tools/trivy on purpose.
// kube-bench links the Kubernetes client, the AWS SDK and a database driver.
// In one module with the scanners, a bump of either side could move the
// other's dependencies. See README.md.
package kubebench

import (
	_ "github.com/aquasecurity/kube-bench/cmd"
)
