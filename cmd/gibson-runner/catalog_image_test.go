// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// nonToolPackages are things the Dockerfile installs that are deliberately not
// parser tools, so they are expected to have no catalog entry.
var nonToolPackages = map[string]bool{
	"ca-certificates": true,
}

// TestCatalogAndImageAgree is the anti-drift guard for #352, in both
// directions.
//
// The catalog is generated from the parsers compiled into the binary. The
// image is built from a Dockerfile. Nothing connected the two, so when the
// recon pack landed (4599c2b: subfinder, amass, dnsx, naabu, masscan — 840
// lines of parser, test and testdata) it did not touch the Dockerfile, and the
// catalog over-advertised by five tools for four months. Any mission selecting
// one of them failed at dispatch with
//
//	exec: "<tool>": executable file not found in $PATH
//
// surfaced to the caller as a failed tool run rather than as "not supported
// here".
//
// CLAUDE.md's "Adding a parser" checklist already ended with "add the
// apt/go/pip install step to Dockerfile". A checklist step that nothing
// enforces is a step that gets skipped. This is the enforcement.
//
// Both directions matter and they fail differently:
//
//   - catalogued but not installed — the tool is advertised and cannot run.
//     A guaranteed runtime failure, and the one that actually happened.
//   - installed but not catalogued — dead weight in the image. No runtime
//     failure, but it is attack surface and CVE surface nothing can use, which
//     is exactly what `curl` and `jq` turned out to be (#349).
//
// Deliberately a source-level check rather than an image check: it runs on
// every PR in go-ci, where building the image (six Go tools compile from
// source) is far too slow. `gibson-runner --verify-tools` is the complementary
// runtime check — run that inside a built image for the ground truth. This one
// only guarantees the Dockerfile was not forgotten.
func TestCatalogAndImageAgree(t *testing.T) {
	t.Parallel()

	installed := toolsInstalledByDockerfile(t)

	catalogued := map[string]bool{}
	for _, name := range cataloguedToolNames() {
		catalogued[name] = true
	}
	if len(catalogued) == 0 {
		t.Fatal("catalog is empty; the parser blank imports in main.go are not registering")
	}

	for _, name := range sortedKeys(catalogued) {
		if !installed[name] {
			t.Errorf("parser %q is in the catalog but the Dockerfile installs no such binary.\n"+
				"The daemon will advertise it, a mission will dispatch it, and the run will fail with\n"+
				"  exec: %q: executable file not found in $PATH\n"+
				"Add the apt/go-install line to Dockerfile, or remove the parser.",
				name, name)
		}
	}

	for _, name := range sortedKeys(installed) {
		if nonToolPackages[name] {
			continue
		}
		if !catalogued[name] {
			t.Errorf("Dockerfile installs %q but no parser registers it.\n"+
				"Nothing in the image can exec it, so it is attack surface and CVE "+
				"surface with no caller. Either add the parser or drop the install line.\n"+
				"If it is a deliberate non-tool dependency, add it to nonToolPackages "+
				"in this file with a reason.",
				name)
		}
	}
}

var (
	// The apt block: everything between `apt-get install` and the line ending
	// the RUN. Package names are the indented continuation lines.
	aptInstallRe = regexp.MustCompile(`(?s)apt-get install -y --no-install-recommends(.*?)&& rm -rf`)
	aptPkgRe     = regexp.MustCompile(`(?m)^\s+([a-z0-9][a-z0-9.+-]*)\s*\\?\s*$`)
	// Go tools reach the runtime image only via an explicit COPY of the
	// binary built in stage 1, which names the binary unambiguously.
	copyToolRe = regexp.MustCompile(`(?m)^COPY --from=build /out/(\S+) /usr/local/bin/(\S+)\s*$`)
)

// toolsInstalledByDockerfile returns the set of executables the Dockerfile
// puts into the runtime image, read from its apt install list and its
// COPY --from=build lines.
//
// Comments are stripped first, and that is the whole point. The Dockerfile
// documents at length the tools it deliberately does NOT install and why, and
// it names parsers in prose. A search over the raw file matches that prose, so
// the guard would report success because of a comment explaining the very gap
// it exists to catch.
func toolsInstalledByDockerfile(t *testing.T) map[string]bool {
	t.Helper()

	path := filepath.Join("..", "..", "Dockerfile")
	// #nosec G304 -- fixed repo-relative path to the Dockerfile checked in
	// beside this test. No caller input reaches it; the only "variable" is a
	// filepath.Join of three constants, which gosec cannot see through.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var b strings.Builder
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	body := b.String()

	out := map[string]bool{}

	apt := aptInstallRe.FindStringSubmatch(body)
	if apt == nil {
		t.Fatalf("no `apt-get install -y --no-install-recommends ... && rm -rf` block found in %s; "+
			"this guard cannot see what the image installs and would pass vacuously", path)
	}
	for _, m := range aptPkgRe.FindAllStringSubmatch(apt[1], -1) {
		out[m[1]] = true
	}

	copies := copyToolRe.FindAllStringSubmatch(body, -1)
	if len(copies) == 0 {
		t.Fatalf("no `COPY --from=build /out/<tool> /usr/local/bin/<tool>` lines found in %s; "+
			"this guard cannot see the Go tools and would pass vacuously", path)
	}
	for _, m := range copies {
		// The runner binary is the agent itself, not a tool it execs.
		if m[2] == "gibson-runner" {
			continue
		}
		out[m[2]] = true
	}

	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
