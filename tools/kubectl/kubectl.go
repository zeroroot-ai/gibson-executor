// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command kubectl builds the upstream kubectl from source, out of this module,
// instead of downloading the published release binary. The build picks up the
// security floors in go.mod through minimal version selection, and the pinned
// Go toolchain gives a current stdlib. See README.md for why this binary is
// built here now.
//
// The entry point mirrors the upstream cmd/kubectl: it constructs the default
// kubectl command from the k8s.io/kubectl staging module and runs it. That
// module carries no main-module-only replace directives, so it builds as an
// ordinary dependency.
package main

import (
	"os"

	"k8s.io/component-base/cli"
	"k8s.io/component-base/logs"
	"k8s.io/kubectl/pkg/cmd"
	"k8s.io/kubectl/pkg/cmd/util"

	// Client auth plugins, the same set the upstream entry point loads.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func main() {
	// Parse the verbosity flag before command construction, so klog works
	// while kubectl handles plugins and the .kuberc file. This matches the
	// upstream entry point.
	logs.GlogSetter(cmd.GetLogVerbosity(os.Args)) //nolint:errcheck
	command := cmd.NewDefaultKubectlCommand()
	if err := cli.RunNoErrOutput(command); err != nil {
		util.CheckErr(err)
	}
}
