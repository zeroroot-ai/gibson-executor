// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Per-tool args allowlist for trivy.
//
// Coverage rationale:
//   - Severity, package-type and scanner selection narrow the scan. Safe.
//   - `--ignore-unfixed` and the DB-freshness flags change what is
//     reported, not what is reached. Safe.
//   - Output control (`-f`, `--format`, `-o`, `--output`, `--template`) is
//     DENIED. The runner parses trivy's JSON on stdout; a caller who can
//     change the format can make every scan parse to nothing, which is a
//     scanner that silently reports no vulnerabilities. `-f json` is fixed
//     in buildArgs and is not reachable from req.Args.
//   - Filesystem and repository scanning (`--input`, and the `fs`/`repo`
//     subcommands) are DENIED. This parser's contract is an image
//     reference validated as one; a path argument would be a different
//     tool with a different target policy.
//   - `--exit-code` is DENIED: a non-zero exit on findings would be read
//     by Execute as a failed run, turning "we found vulnerabilities" into
//     "the tool broke".

package trivy

import (
	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// severityLevels is trivy's documented severity vocabulary. The flag takes
// a comma-separated subset, uppercase.
var severityLevels = []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// scannerKinds are the analysers trivy can run. `license` is included
// because it changes only which results appear, not what is touched.
var scannerKinds = []string{"vuln", "misconfig", "secret", "license"}

// pkgTypes narrows os-vs-application packages.
var pkgTypes = []string{"os", "library"}

var argsPolicy = policy.ArgsPolicy{
	// What to report.
	"--severity":           policy.AllowCSVEnum(severityLevels...),
	"--scanners":           policy.AllowCSVEnum(scannerKinds...),
	"--pkg-types":          policy.AllowCSVEnum(pkgTypes...),
	"--ignore-unfixed":     nil,
	"--detection-priority": policy.AllowEnum("precise", "comprehensive"),

	// Database freshness. A scanner running against a stale database
	// under-reports silently, so both directions are explicit rather than
	// implied by a default nobody stated.
	"--skip-db-update":      nil,
	"--skip-java-db-update": nil,
	"--download-db-only":    nil,

	// Database source. trivy fetches its vulnerability database from
	// ghcr.io/aquasecurity/trivy-db (and the Java index from trivy-java-db)
	// as OCI artefacts. An air-gapped estate mirrors those artefacts and
	// names the mirror here. The value is an image reference and nothing
	// else: never a URL, a path or a host.
	"--db-repository":      policy.ImageRef,
	"--java-db-repository": policy.ImageRef,

	// Throughput and diagnostics that do not change what is reached.
	"--timeout":     policy.AllowAny,
	"--parallel":    policy.Numeric,
	"--quiet":       nil,
	"--no-progress": nil,
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
	// trivy scans an artefact named by an image reference — never a host,
	// a URL or a network range. The reference is resolved against a
	// registry by trivy itself; nothing here dials it.
	registry.RegisterTargetPolicy(toolName, policy.TargetImageRef)
}
