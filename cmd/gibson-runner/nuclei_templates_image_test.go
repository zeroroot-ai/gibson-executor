// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDockerfileBundlesNucleiTemplates is the anti-drift guard for
// gibson-executor#395.
//
// nuclei ships no templates in its binary. The runtime sandbox has no network
// egress except to the dispatched target, so a nuclei with no local template
// set cannot download one and aborts every scan with "no templates provided
// for scan" — zero findings, silently. The fix bundles a pinned template set
// into the image and points nuclei at it. Nothing but this guard keeps the
// three parts of that fix in the Dockerfile, so a later edit that drops any one
// of them would re-open the bug with no test to catch it until a mission folds
// to nothing on staging again.
//
// Like TestCatalogAndImageAgree, this is a source-level check: it reads the
// Dockerfile rather than a built image, because building the image (every Go
// tool compiles from source, plus an 84 MB template clone) is far too slow for
// go-ci. scripts/tool-smoke.sh is the complementary runtime proof — its nuclei
// case runs a template from the bundled set, so dropping the COPY fails it.
func TestDockerfileBundlesNucleiTemplates(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "Dockerfile")
	// #nosec G304 -- fixed repo-relative path to the Dockerfile checked in
	// beside this test, same as catalog_image_test.go. No caller input reaches
	// it.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	if missing := nucleiTemplatesRequirementsMissing(string(raw)); len(missing) > 0 {
		t.Errorf("Dockerfile no longer bundles the nuclei template set (gibson-executor#395):\n  - %s\n"+
			"Without all of these, nuclei has no templates in the egress-restricted sandbox and every\n"+
			"scan folds to zero findings with \"no templates provided for scan\".",
			strings.Join(missing, "\n  - "))
	}
}

// TestNucleiTemplatesGuardCanFail is the failing fixture for the guard above
// (CLAUDE.md: "every new guard ships with a failing fixture"). It feeds the
// matcher a Dockerfile body with each requirement removed and asserts the guard
// reports it. A guard that cannot fail is worse than none.
func TestNucleiTemplatesGuardCanFail(t *testing.T) {
	t.Parallel()

	// A body that bundles nothing: no clone, no COPY, no env.
	empty := "FROM scratch\nUSER runner:runner\nWORKDIR /home/runner\n"
	missing := nucleiTemplatesRequirementsMissing(empty)
	if len(missing) != 4 {
		t.Fatalf("guard reported %d missing requirements for an empty Dockerfile, want 4: %v", len(missing), missing)
	}

	// Comments must not satisfy the guard: a Dockerfile that only talks about
	// the template set in prose still bundles nothing.
	commentOnly := "# COPY --from=build /out/nuclei-templates /home/runner/nuclei-templates\n" +
		"# ENV NUCLEI_TEMPLATES_DIR=/home/runner/nuclei-templates\n" +
		"# git clone nuclei-templates.git /out/nuclei-templates\n" +
		"# ARG NUCLEI_TEMPLATES_COMMIT=0000000000000000000000000000000000000000\n"
	if m := nucleiTemplatesRequirementsMissing(commentOnly); len(m) != 4 {
		t.Errorf("guard was satisfied by comments alone; it must match real instructions, got missing=%v", m)
	}
}

var (
	// (?s) so the match can cross the `\`-continued line between `git clone`
	// and the repo URL; non-greedy so it cannot run past the one clone.
	nucleiCloneRe  = regexp.MustCompile(`(?s)git clone\b.*?nuclei-templates\.git\s+/out/nuclei-templates`)
	nucleiCommitRe = regexp.MustCompile(`(?m)^\s*ARG\s+NUCLEI_TEMPLATES_COMMIT=[0-9a-f]{40}\s*$`)
	nucleiCopyRe   = regexp.MustCompile(`COPY --from=build[^\n]*\s/out/nuclei-templates\s+/home/runner/nuclei-templates`)
	nucleiEnvRe    = regexp.MustCompile(`NUCLEI_TEMPLATES_DIR=/home/runner/nuclei-templates`)
)

// nucleiTemplatesRequirementsMissing returns a message for each part of the
// #395 fix that is absent from the Dockerfile. Comment lines are stripped
// first: the Dockerfile documents the template set at length in prose, and the
// guard must match the real instructions, not the comment describing them —
// the same reasoning as toolsInstalledByDockerfile in catalog_image_test.go.
func nucleiTemplatesRequirementsMissing(dockerfile string) []string {
	var b strings.Builder
	for line := range strings.SplitSeq(dockerfile, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	body := b.String()

	var missing []string
	if !nucleiCloneRe.MatchString(body) {
		missing = append(missing, "the build stage no longer clones nuclei-templates into /out/nuclei-templates")
	}
	if !nucleiCommitRe.MatchString(body) {
		missing = append(missing, "no `ARG NUCLEI_TEMPLATES_COMMIT=<40-hex>` pin, so the cloned tag is not verified against a commit")
	}
	if !nucleiCopyRe.MatchString(body) {
		missing = append(missing, "the runtime stage no longer COPYs /out/nuclei-templates to /home/runner/nuclei-templates")
	}
	if !nucleiEnvRe.MatchString(body) {
		missing = append(missing, "NUCLEI_TEMPLATES_DIR no longer points nuclei at /home/runner/nuclei-templates")
	}
	return missing
}
