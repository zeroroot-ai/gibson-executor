// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package trivyk8s

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

// TestMain lets the test binary stand in for the runner: sandbox.Apply
// re-execs the current binary to set RLIMIT_AS, and RunPreExec answers it.
func TestMain(m *testing.M) {
	sandbox.RunPreExec()
	os.Exit(m.Run())
}

// The misconfiguration rows in testdata/k8s-report.json are real trivy 0.75.0
// output. testdata/PROVENANCE.md records the command, the image digest, the
// date, and exactly which part of the file is the assembled cluster wrapper
// and why.
const (
	goldenPath    = "testdata/k8s-report.json"
	goldenCluster = "goat"
	goldenAudit   = "goat/misconfig"

	apiRef    = "goat/Deployment/goat-api"
	workerRef = "goat/Deployment/goat-worker"
	cleanRef  = "goat/ConfigMap/goat-config"
	unreadRef = "kube-system/Role/extension-apiserver-authentication-reader"
)

func loadGolden(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return raw
}

func parseGolden(t *testing.T) (*graphragpb.DiscoveryResult, registry.ParseQuality) {
	t.Helper()
	disc, q, err := parseReport(loadGolden(t), goldenCluster)
	if err != nil {
		t.Fatalf("parseReport: %v", err)
	}
	return disc, q
}

func nodesByType(disc *graphragpb.DiscoveryResult, nodeType string) []*graphragpb.CustomNode {
	var out []*graphragpb.CustomNode
	for _, n := range disc.GetCustomNodes() {
		if n.GetNodeType() == nodeType {
			out = append(out, n)
		}
	}
	return out
}

func auditNode(t *testing.T, disc *graphragpb.DiscoveryResult) *graphragpb.CustomNode {
	t.Helper()
	got := nodesByType(disc, nodeAudit)
	if len(got) != 1 {
		t.Fatalf("want exactly one %s node, got %d", nodeAudit, len(got))
	}
	return got[0]
}

// TestSeverityComesFromTrivy is the point of this tool. kube-bench reports no
// severity, so its parser assigns two tiers of its own. trivy does report one,
// and this parser must pass it through untouched.
func TestSeverityComesFromTrivy(t *testing.T) {
	disc, _ := parseGolden(t)

	// Read the expected severity for each check straight out of the fixture,
	// so the assertion cannot drift from the recording.
	want := map[string]string{}
	var raw struct {
		Resources []struct {
			Results []struct {
				Misconfigurations []struct {
					ID       string `json:"ID"`
					Status   string `json:"Status"`
					Severity string `json:"Severity"`
				} `json:"Misconfigurations"`
			} `json:"Results"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(loadGolden(t), &raw); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	for _, res := range raw.Resources {
		for _, grp := range res.Results {
			for _, m := range grp.Misconfigurations {
				if m.Status == "FAIL" {
					want[m.ID] = strings.ToLower(m.Severity)
				}
			}
		}
	}
	if len(want) == 0 {
		t.Fatal("the fixture holds no FAIL row, so this test would measure nothing")
	}

	for _, f := range disc.GetFindings() {
		id := strings.SplitN(f.GetTitle(), ":", 2)[0]
		w, ok := want[id]
		if !ok {
			t.Errorf("finding %s is not in the fixture", id)
			continue
		}
		if f.GetSeverity() != w {
			t.Errorf("check %s severity = %q, trivy said %q", id, f.GetSeverity(), w)
		}
	}
}

// TestHighSeverityFindingNamesARealWorkload is this issue's headline
// criterion, as far as a fixture can carry it: the finding must be high or
// above and must say which workload it is about.
func TestHighSeverityFindingNamesARealWorkload(t *testing.T) {
	disc, _ := parseGolden(t)

	var high []*graphragpb.Finding
	for _, f := range disc.GetFindings() {
		if f.GetSeverity() == "high" || f.GetSeverity() == "critical" {
			high = append(high, f)
		}
	}
	if len(high) == 0 {
		t.Fatal("no high or critical finding: this tool exists because kube-bench produces none")
	}
	for _, f := range high {
		if f.GetParentId() != apiRef {
			continue
		}
		if !strings.Contains(f.GetDescription(), apiRef) {
			t.Errorf("finding %s does not name the workload in its description: %q", f.GetTitle(), f.GetDescription())
		}
		if f.GetParentType() != nodeWorkload {
			t.Errorf("finding %s parent type = %q, want %q", f.GetTitle(), f.GetParentType(), nodeWorkload)
		}
	}
	t.Logf("%d high or critical findings", len(high))
}

// TestNoFindingForAPassingCheck holds the third acceptance criterion. The
// fixture carries one PASS row, and it must produce no finding and still be
// counted.
func TestNoFindingForAPassingCheck(t *testing.T) {
	disc, _ := parseGolden(t)

	for _, f := range disc.GetFindings() {
		if strings.HasPrefix(f.GetTitle(), "KSV-0030:") {
			t.Errorf("the PASS row produced a finding: %s", f.GetTitle())
		}
	}
	if got := auditNode(t, disc).GetProperties()["checks_passed"]; got != "1" {
		t.Errorf("checks_passed = %q, want 1", got)
	}
}

// TestAnUnreadableResourceIsNotClean is the fourth criterion. A resource the
// credential could not read must be named, must not be counted as audited,
// and must make the run partial.
func TestAnUnreadableResourceIsNotClean(t *testing.T) {
	disc, quality := parseGolden(t)

	if quality != registry.ParseQualityPartial {
		t.Errorf("quality = %v, want partial: one resource was unreadable", quality)
	}
	props := auditNode(t, disc).GetProperties()
	if props["resources_unread"] != "1" {
		t.Errorf("resources_unread = %q, want 1", props["resources_unread"])
	}
	if props["complete"] != "false" {
		t.Errorf("complete = %q, want false", props["complete"])
	}
	if !strings.Contains(props["not_audited"], unreadRef) {
		t.Errorf("not_audited does not name the resource: %q", props["not_audited"])
	}
	if !strings.Contains(props["not_audited"], "is forbidden") {
		t.Errorf("not_audited drops the reason the API gave: %q", props["not_audited"])
	}
	// The unreadable resource must not appear as an audited workload.
	for _, n := range nodesByType(disc, nodeWorkload) {
		if n.GetIdProperties()["id"] == unreadRef {
			t.Errorf("the unreadable resource was emitted as an audited %s", nodeWorkload)
		}
	}
}

// TestACleanWorkloadIsStillAudited separates "no problem" from "never looked",
// which is the whole reason the Workload node exists.
func TestACleanWorkloadIsStillAudited(t *testing.T) {
	disc, _ := parseGolden(t)

	var found bool
	for _, n := range nodesByType(disc, nodeWorkload) {
		if n.GetIdProperties()["id"] != cleanRef {
			continue
		}
		found = true
		if got := n.GetProperties()["checks_failed"]; got != "0" {
			t.Errorf("clean workload checks_failed = %q, want 0", got)
		}
		if got := n.GetProperties()["audited"]; got != "true" {
			t.Errorf("clean workload audited = %q, want true", got)
		}
	}
	if !found {
		t.Errorf("the clean resource %s is absent, so it cannot be told from one never read", cleanRef)
	}
}

// TestFindingsAreAttributedPerWorkload makes sure two workloads in one report
// do not pool their findings.
func TestFindingsAreAttributedPerWorkload(t *testing.T) {
	disc, _ := parseGolden(t)

	perWorkload := map[string]int{}
	for _, f := range disc.GetFindings() {
		perWorkload[f.GetParentId()]++
	}
	if perWorkload[apiRef] != 12 {
		t.Errorf("%s has %d findings, want 12", apiRef, perWorkload[apiRef])
	}
	if perWorkload[workerRef] != 4 {
		t.Errorf("%s has %d findings, want 4", workerRef, perWorkload[workerRef])
	}

	// goat-worker is all LOW in the recording. If severity were taken per run
	// rather than per check, this would come back high.
	for _, f := range disc.GetFindings() {
		if f.GetParentId() == workerRef && f.GetSeverity() != "low" {
			t.Errorf("%s finding %s severity = %q, want low", workerRef, f.GetTitle(), f.GetSeverity())
		}
	}

	for _, n := range nodesByType(disc, nodeWorkload) {
		id := n.GetIdProperties()["id"]
		want := perWorkload[id]
		if got := n.GetProperties()["checks_failed"]; got != strconv.Itoa(want) {
			t.Errorf("%s checks_failed = %q, want %d", id, got, want)
		}
	}
}

// TestEveryFindingHasEvidence holds the one-to-one tie between a finding and
// the raw check it came from.
func TestEveryFindingHasEvidence(t *testing.T) {
	disc, _ := parseGolden(t)

	byFinding := map[string]int{}
	for _, e := range disc.GetEvidence() {
		byFinding[e.GetFindingId()]++
		if !json.Valid([]byte(e.GetContent())) {
			t.Errorf("evidence %s is not the raw check JSON", e.GetId())
		}
	}
	if len(disc.GetFindings()) == 0 {
		t.Fatal("no findings, so this test would measure nothing")
	}
	for _, f := range disc.GetFindings() {
		if byFinding[f.GetId()] != 1 {
			t.Errorf("finding %s has %d evidence rows, want 1", f.GetId(), byFinding[f.GetId()])
		}
	}
}

// TestUnknownSeverityIsRefused is the one that stops a silent downgrade. If
// trivy adds a tier, folding it into "low" would present its grading as
// something softer than it is.
func TestUnknownSeverityIsRefused(t *testing.T) {
	mutated := strings.Replace(string(loadGolden(t)), `"Severity": "HIGH"`, `"Severity": "SEVERE"`, 1)
	_, quality, err := parseReport([]byte(mutated), goldenCluster)
	if err == nil {
		t.Fatal("a severity this parser does not know was accepted")
	}
	if !strings.Contains(err.Error(), "SEVERE") {
		t.Errorf("the error does not name the unknown severity: %v", err)
	}
	if quality != registry.ParseQualityFailed {
		t.Errorf("quality = %v, want failed", quality)
	}
}

// TestEveryResourceUnreadableFails is the case that must never read as a clean
// cluster: the credential can list resources but read none of them.
func TestEveryResourceUnreadableFails(t *testing.T) {
	report := `{"ClusterName":"goat","Resources":[
      {"Namespace":"goat","Kind":"Deployment","Name":"a","Error":"forbidden"},
      {"Namespace":"goat","Kind":"Deployment","Name":"b","Error":"forbidden"}]}`
	_, quality, err := parseReport([]byte(report), goldenCluster)
	if err == nil {
		t.Fatal("a report in which nothing could be read was accepted as a result")
	}
	if !strings.Contains(err.Error(), "not a clean result") {
		t.Errorf("the error does not say this is not a clean result: %v", err)
	}
	if quality != registry.ParseQualityFailed {
		t.Errorf("quality = %v, want failed", quality)
	}
}

// TestEmptyAndShapeChangedReportsFail covers the inputs that would otherwise
// produce an empty, clean-looking result.
func TestEmptyAndShapeChangedReportsFail(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"no output", "", "no workload was audited"},
		{"whitespace", "   \n", "no workload was audited"},
		{"not json", "trivy: command not found", "unmarshal trivy k8s report"},
		{"no resources", `{"ClusterName":"goat","Resources":[]}`, "holds no resources"},
		{
			"check with no id",
			`{"ClusterName":"goat","Resources":[{"Kind":"Deployment","Name":"a",
			  "Results":[{"Misconfigurations":[{"Status":"FAIL","Severity":"HIGH"}]}]}]}`,
			"the output shape changed",
		},
		{
			"check with no status",
			`{"ClusterName":"goat","Resources":[{"Kind":"Deployment","Name":"a",
			  "Results":[{"Misconfigurations":[{"ID":"KSV-0017","Severity":"HIGH"}]}]}]}`,
			"the output shape changed",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, quality, err := parseReport([]byte(c.raw), goldenCluster)
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to contain %q", err, c.want)
			}
			if quality != registry.ParseQualityFailed {
				t.Errorf("quality = %v, want failed", quality)
			}
		})
	}
}

// TestMissingKubeconfigIsANamedError is the fourth criterion's first half, and
// what the container smoke asserts in the image.
func TestMissingKubeconfigIsANamedError(t *testing.T) {
	for _, kc := range []string{"", "   ", "\n\t"} {
		_, err := readInput(registry.ExecuteRequest{Target: "goat", Options: map[string]string{"kubeconfig": kc}})
		if !errors.Is(err, errKubeconfigMissing) {
			t.Fatalf("kubeconfig %q: err = %v, want errKubeconfigMissing", kc, err)
		}
	}
	// The message must name the field, the filler and the consequence,
	// because a mission operator sees only this string.
	msg := errKubeconfigMissing.Error()
	for _, want := range []string{`"kubeconfig"`, "daemon", "gibson#485", "not a clean result"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error message does not mention %q: %s", want, msg)
		}
	}
}

// TestKubeconfigIsCheckedBeforeTheTarget: an empty kubeconfig and a bad target
// are both wrong, and the kubeconfig must be the one reported. Otherwise the
// operator fixes the target and hits the same wall.
func TestKubeconfigIsCheckedBeforeTheTarget(t *testing.T) {
	_, err := readInput(registry.ExecuteRequest{Target: "not a dns label!", Options: map[string]string{}})
	if !errors.Is(err, errKubeconfigMissing) {
		t.Fatalf("err = %v, want errKubeconfigMissing to win", err)
	}
}

// TestKubeconfigPluginsAndFileRefsAreRefused: the kubeconfig is
// tenant-supplied. An exec plugin runs a program of their choosing.
func TestKubeconfigPluginsAndFileRefsAreRefused(t *testing.T) {
	const okCluster = `"clusters":[{"name":"c","cluster":{}}]`
	cases := []struct {
		name, raw, want string
	}{
		{
			"exec plugin",
			`{` + okCluster + `,"users":[{"name":"u","user":{"exec":{"command":"curl"}}}]}`,
			"exec credential plugin",
		},
		{
			"auth provider",
			`{` + okCluster + `,"users":[{"name":"u","user":{"auth-provider":{"name":"gcp"}}}]}`,
			"auth-provider",
		},
		{
			"token file",
			`{` + okCluster + `,"users":[{"name":"u","user":{"tokenFile":"/etc/passwd"}}]}`,
			"reads its token from a file",
		},
		{
			"client cert file",
			`{` + okCluster + `,"users":[{"name":"u","user":{"client-certificate":"/tmp/c.pem"}}]}`,
			"client certificate from a file",
		},
		{
			"ca file",
			`{"clusters":[{"name":"c","cluster":{"certificate-authority":"/tmp/ca.pem"}}],"users":[{"name":"u","user":{"token":"t"}}]}`,
			"reads its CA from a file",
		},
		{"no users", `{` + okCluster + `,"users":[]}`, "no clusters or no users"},
		{"not json", `nope`, "could not be read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := inspectKubeconfig([]byte(c.raw))
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to contain %q", err, c.want)
			}
		})
	}

	// An inline credential is the shape the daemon supplies, and must pass.
	ok := `{"clusters":[{"name":"c","cluster":{"certificate-authority-data":"aGk="}}],` +
		`"users":[{"name":"u","user":{"token":"abc"}}]}`
	if err := inspectKubeconfig([]byte(ok)); err != nil {
		t.Errorf("an inline kubeconfig was refused: %v", err)
	}
}

// TestArgsAreRefused: a caller who passes a flag expects it to act.
func TestArgsAreRefused(t *testing.T) {
	_, err := readInput(registry.ExecuteRequest{
		Target:  "goat",
		Options: map[string]string{"kubeconfig": "x"},
		Args:    []string{"--severity", "CRITICAL"},
	})
	if err == nil || !strings.Contains(err.Error(), "accepts no args") {
		t.Fatalf("err = %v, want the args to be refused", err)
	}
}

// TestNamespaceIsValidated: the value reaches an argv.
func TestNamespaceIsValidated(t *testing.T) {
	base := map[string]string{"kubeconfig": "x"}
	for _, bad := range []string{"../etc", "Goat", "a b", "-n", "ns;rm -rf /", strings.Repeat("a", 64)} {
		opts := map[string]string{"kubeconfig": base["kubeconfig"], "namespace": bad}
		if _, err := readInput(registry.ExecuteRequest{Target: "goat", Options: opts}); err == nil {
			t.Errorf("namespace %q was accepted", bad)
		}
	}
	for _, good := range []string{"goat", "kube-system", "a", "a-1-b"} {
		opts := map[string]string{"kubeconfig": base["kubeconfig"], "namespace": good}
		cfg, err := readInput(registry.ExecuteRequest{Target: "goat", Options: opts})
		if err != nil {
			t.Errorf("namespace %q was refused: %v", good, err)
		}
		if cfg.namespace != good {
			t.Errorf("namespace = %q, want %q", cfg.namespace, good)
		}
	}
}

// TestChildEnvCarriesOnlyWhatTheChildNeeds: the kubeconfig must reach the
// child through KUBECONFIG and the cache must stay inside the per-call
// directory, so a run cannot write to a shared one.
func TestChildEnvCarriesOnlyWhatTheChildNeeds(t *testing.T) {
	env := childEnv("/tmp/x/kubeconfig", "/tmp/x")
	want := map[string]string{
		"KUBECONFIG":      "/tmp/x/kubeconfig",
		"HOME":            "/tmp/x",
		"TRIVY_CACHE_DIR": "/tmp/x/cache",
		"XDG_CACHE_HOME":  "/tmp/x/cache",
	}
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// Nothing else: a scanner child has no business inheriting the runner's
	// environment, which is where a token would be.
	allowed := map[string]bool{"PATH": true, "HOME": true, "KUBECONFIG": true,
		"TRIVY_CACHE_DIR": true, "XDG_CACHE_HOME": true}
	for k := range got {
		if !allowed[k] {
			t.Errorf("childEnv leaks %s to the scanner", k)
		}
	}
}

// TestCatalogEntryIsComplete: the registry entry is the tool's whole public
// contract, and the catalog pins the image, so a missing field is invisible
// until a mission fails.
func TestCatalogEntryIsComplete(t *testing.T) {
	e := (&parser{}).Describe()
	if e.Name != toolName {
		t.Errorf("Name = %q, want %q", e.Name, toolName)
	}
	if e.Version == "" || e.Description == "" {
		t.Error("Version and Description must both be set")
	}
	if e.OutputProtoType != "gibson.graphrag.v1.DiscoveryResult" {
		t.Errorf("OutputProtoType = %q", e.OutputProtoType)
	}
	if e.DefaultTimeoutSeconds != defaultTimeout {
		t.Errorf("DefaultTimeoutSeconds = %d, want %d", e.DefaultTimeoutSeconds, defaultTimeout)
	}
	props, ok := e.InputSchema["properties"].(map[string]any)
	if !ok {
		t.Fatal("InputSchema has no properties")
	}
	for _, f := range []string{"target", "kubeconfig", "namespace"} {
		if _, ok := props[f]; !ok {
			t.Errorf("InputSchema has no %q", f)
		}
	}
	// kubeconfig must NOT be required: the daemon fills it, and a required
	// field reads as one a mission author should set.
	req, _ := e.InputSchema["required"].([]any)
	for _, r := range req {
		if r == "kubeconfig" {
			t.Error("kubeconfig is marked required, which tells a mission author to set it")
		}
	}
	kc, _ := props["kubeconfig"].(map[string]any)
	desc, _ := kc["description"].(string)
	if !strings.Contains(desc, "Do not set it in a mission definition") {
		t.Error("the kubeconfig description does not warn against setting it in a mission")
	}
}

// TestRegisteredInTheRegistry: a parser that is not registered cannot run, and
// nothing else would notice.
func TestRegisteredInTheRegistry(t *testing.T) {
	catalog := registry.Catalog()
	names := make([]string, 0, len(catalog))
	for _, e := range catalog {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	var found bool
	for _, n := range names {
		if n == toolName {
			found = true
		}
	}
	if !found {
		t.Errorf("%s is not in the registry catalog (saw %v)", toolName, names)
	}
}

// TestNoVulnerabilityScannerIsRun: without --scanners misconfig, trivy also
// pulls and scans every workload's image, duplicating parsers/trivy under a
// second tool's id and taking far longer.
func TestNoVulnerabilityScannerIsRun(t *testing.T) {
	if scanners != "misconfig" {
		t.Errorf("scanners = %q, want misconfig", scanners)
	}
}
