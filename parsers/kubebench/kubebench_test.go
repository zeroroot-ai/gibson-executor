// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package kubebench

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zeroroot-ai/sdk/secretenv"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

// declaredName is the tenant secret the tests pretend the mission
// declared. The name is arbitrary; what matters is that the input carries it
// and the environment carries the value, which is the whole contract.
// Named without "secret" on purpose: gosec's G101 matches an identifier
// against passwd|pass|secret|token|cred and then flags the literal beside it.
// Every literal in this file is a secret's NAME, which is the whole point of
// gibson#485, so the rule has nothing to find and the identifier is spelled to
// say so rather than carrying a suppression comment.
const declaredName = "goat-kubeconfig"

// handedTheKubeconfig sets up a dispatch the way the daemon does: the input
// NAMES the secret, and the value arrives in the environment under the key
// secretenv derives. Using secretenv here rather than a literal is deliberate —
// if the fold ever changed on one side only, these tests would stop passing
// instead of silently testing a variable the daemon no longer sets.
func handedTheKubeconfig(t *testing.T, value string, extra ...string) map[string]string {
	t.Helper()
	if len(extra)%2 != 0 {
		t.Fatalf("handedTheKubeconfig: %d extra values, want key/value pairs", len(extra))
	}
	t.Setenv(secretenv.Key(declaredName), value)
	opts := map[string]string{kubeconfigOption: declaredName}
	for i := 0; i < len(extra); i += 2 {
		opts[extra[i]] = extra[i+1]
	}
	return opts
}

// TestMain lets the test binary stand in for the runner: sandbox.Apply
// re-execs the current binary to set RLIMIT_AS, and RunPreExec is what
// answers that re-exec.
func TestMain(m *testing.M) {
	sandbox.RunPreExec()
	os.Exit(m.Run())
}

// testdata/policies.json is a recording, not a hand-written file. It is the
// stdout of `kube-bench run --targets policies --json` (release v0.16.0, the
// upstream linux/amd64 binary) against a throwaway kind cluster running
// Kubernetes v1.33.1, executed inside the same debian:trixie-slim base image
// the executor ships on. See README.md in tools/kubebench for the method.
//
// It is byte-for-byte what kube-bench printed, and that includes a real
// fault: Debian's /bin/sh is dash, which has no `[[`, so control 5.1.1 came
// back as WARN with the value "/bin/sh: 3: [[: not found" and no reason.
const (
	goldenPath    = "testdata/policies.json"
	goldenCluster = "kbfixture"
	goldenRun     = "kbfixture/cis-1.12"
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

func findingsByControl(disc *graphragpb.DiscoveryResult) map[string]*graphragpb.Finding {
	out := map[string]*graphragpb.Finding{}
	for _, f := range disc.Findings {
		out[strings.TrimPrefix(strings.SplitN(f.GetTitle(), ":", 2)[0], "CIS ")] = f
	}
	return out
}

func runNode(t *testing.T, disc *graphragpb.DiscoveryResult) *graphragpb.CustomNode {
	t.Helper()
	var found *graphragpb.CustomNode
	for _, n := range disc.CustomNodes {
		if n.GetNodeType() == nodeRun {
			if found != nil {
				t.Fatal("more than one BenchmarkRun node")
			}
			found = n
		}
	}
	if found == nil {
		t.Fatal("no BenchmarkRun node: an empty Finding list would read as a clean cluster")
	}
	return found
}

// TestGolden_RealCapture pins the parse of the recording. It is the test that
// fails when kube-bench changes its output shape or this parser changes what
// it does with a real result.
func TestGolden_RealCapture(t *testing.T) {
	disc, quality := parseGolden(t)

	// Control 5.1.1 errored, so the run is partial.
	if quality != registry.ParseQualityPartial {
		t.Errorf("quality = %v, want partial (control 5.1.1 errored)", quality)
	}

	got := findingsByControl(disc)
	want := []string{"5.1.3", "5.1.5", "5.1.6", "5.2.2", "5.2.5"}
	ids := make([]string, 0, len(got))
	for id := range got {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("findings for controls %v, want %v", ids, want)
	}

	f := got["5.1.5"]
	if f.GetId() != "finding:kube-bench:"+goldenRun+":5.1.5" {
		t.Errorf("finding id = %q", f.GetId())
	}
	if !strings.Contains(f.GetTitle(), "service accounts") && !strings.Contains(strings.ToLower(f.GetTitle()), "service account") {
		t.Errorf("title %q does not carry the control text", f.GetTitle())
	}
	if f.GetRemediation() == "" {
		t.Error("remediation text from kube-bench was not carried")
	}
	if f.GetCategory() != categoryCIS {
		t.Errorf("category = %q", f.GetCategory())
	}
	if f.GetParentId() != goldenRun {
		t.Errorf("finding parent = %s, want %s", f.GetParentId(), goldenRun)
	}

	run := runNode(t, disc).GetProperties()
	for k, want := range map[string]string{
		"benchmark":          "cis-1.12",
		"kubernetes_version": "1.33",
		"controls_passed":    "5",
		"controls_failed":    "5",
		"controls_errored":   "1",
		"controls_manual":    "23",
		"controls_assessed":  "10",
		"complete":           "false",
	} {
		if run[k] != want {
			t.Errorf("BenchmarkRun[%s] = %q, want %q", k, run[k], want)
		}
	}
}

// TestGolden_EvidenceIsTheRawResult pins that each Finding carries kube-bench's
// own result for that control, unmodified, as Evidence.
func TestGolden_EvidenceIsTheRawResult(t *testing.T) {
	disc, _ := parseGolden(t)
	if len(disc.Evidence) != len(disc.Findings) {
		t.Fatalf("%d evidence for %d findings, want one each", len(disc.Evidence), len(disc.Findings))
	}
	byFinding := map[string]*graphragpb.Evidence{}
	for _, e := range disc.Evidence {
		byFinding[e.GetFindingId()] = e
	}
	for _, f := range disc.Findings {
		e, ok := byFinding[f.GetId()]
		if !ok {
			t.Fatalf("finding %s has no evidence", f.GetId())
		}
		var c struct {
			TestNumber string `json:"test_number"`
			Audit      string `json:"audit"`
			Actual     string `json:"actual_value"`
		}
		if err := json.Unmarshal([]byte(e.GetContent()), &c); err != nil {
			t.Fatalf("evidence is not kube-bench JSON: %v", err)
		}
		if c.TestNumber == "" || c.Audit == "" || c.Actual == "" {
			t.Errorf("evidence for %s lost fields: %+v", f.GetId(), c)
		}
	}
}

// TestGolden_OneFindingPerFailedControlNoneForPasses checks the count both
// ways against the recording: every passing control is absent, every control
// that was assessed and did not conform is present exactly once.
func TestGolden_OneFindingPerFailedControlNoneForPasses(t *testing.T) {
	disc, _ := parseGolden(t)
	seen := map[string]int{}
	for _, f := range disc.Findings {
		seen[f.GetId()]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("finding %s emitted %d times", id, n)
		}
	}
	for _, passing := range []string{"5.1.2", "5.1.4", "5.2.3", "5.2.4", "5.2.6"} {
		if _, bad := findingsByControl(disc)[passing]; bad {
			t.Errorf("passing control %s produced a finding", passing)
		}
	}
	if len(disc.Findings) != 5 {
		t.Errorf("%d findings, want 5", len(disc.Findings))
	}
}

// TestGolden_ErroredControlIsNotAFindingAndIsNotDropped is the partial-failure
// decision. Control 5.1.1 is a real errored control in the recording. It must
// not become a Finding, because a Finding claims something about the cluster
// and this is a fact about the run. It must not vanish either.
func TestGolden_ErroredControlIsNotAFindingAndIsNotDropped(t *testing.T) {
	disc, _ := parseGolden(t)
	if _, bad := findingsByControl(disc)["5.1.1"]; bad {
		t.Error("errored control 5.1.1 became a Finding")
	}
	run := runNode(t, disc).GetProperties()
	got := run["not_assessed_errored"]
	if !strings.HasPrefix(got, "5.1.1:") || !strings.Contains(got, "[[: not found") {
		t.Errorf("not_assessed_errored = %q, want control 5.1.1 with the shell error", got)
	}
}

// TestManualControlsAreListedNotDropped: 23 of the 34 controls are manual.
// They are not findings. They must be named, so "no findings" cannot be read
// as "all 34 checked".
func TestManualControlsAreListedNotDropped(t *testing.T) {
	disc, _ := parseGolden(t)
	manual := strings.Split(runNode(t, disc).GetProperties()["not_assessed_manual"], ",")
	if len(manual) != 23 {
		t.Fatalf("%d manual controls listed, want 23: %v", len(manual), manual)
	}
	for _, id := range []string{"5.1.7", "5.6.4"} {
		found := false
		for _, m := range manual {
			found = found || m == id
		}
		if !found {
			t.Errorf("manual control %s not listed", id)
		}
	}
}

// ---- synthetic reports ------------------------------------------------------
//
// The recording has no scored FAIL, no INFO, and no control that errored
// through a `reason`: CIS section 5 is almost entirely unscored. The tests
// below build reports in kube-bench's exact shape to reach those branches.
// They are synthetic and labelled as such.

func synthReport(checks ...map[string]any) []byte {
	results := make([]any, 0, len(checks))
	for _, c := range checks {
		results = append(results, c)
	}
	rep := map[string]any{"Controls": []any{map[string]any{
		"id": "5", "version": "cis-1.12", "detected_version": "1.33",
		"tests": []any{map[string]any{"section": "5.1", "results": results}},
	}}}
	b, _ := json.Marshal(rep)
	return b
}

func chk(id, status string, scored bool, actual, reason string) map[string]any {
	return map[string]any{
		"test_number": id, "test_desc": "control " + id, "status": status, "scored": scored,
		"actual_value": actual, "reason": reason, "remediation": "fix " + id,
		"expected_result": "'x' is present", "audit": "echo x",
	}
}

func TestSeverity_ScoredFailIsMediumUnscoredIsLow(t *testing.T) {
	raw := synthReport(
		chk("1.1", "FAIL", true, "x: no", ""),
		chk("1.2", "WARN", false, "x: no", ""),
		chk("1.3", "PASS", true, "x: yes", ""),
	)
	disc, _, err := parseReport(raw, "c")
	if err != nil {
		t.Fatal(err)
	}
	got := findingsByControl(disc)
	if got["1.1"].GetSeverity() != "medium" {
		t.Errorf("scored FAIL severity = %q, want medium", got["1.1"].GetSeverity())
	}
	if got["1.2"].GetSeverity() != "low" {
		t.Errorf("unscored failure severity = %q, want low", got["1.2"].GetSeverity())
	}
	if len(got) != 2 {
		t.Errorf("%d findings, want 2 (the PASS must not produce one)", len(got))
	}
}

// TestErrored_FailWithReasonIsNotAFinding: kube-bench reports a control whose
// audit command failed as FAIL (scored) or WARN (unscored), with `reason`
// set. Counting that as a failed control would put an invented finding on the
// cluster.
func TestErrored_FailWithReasonIsNotAFinding(t *testing.T) {
	raw := synthReport(
		chk("2.1", "FAIL", true, "", `failed to run: "kubectl get x", output: "forbidden", error: exit status 1`),
		chk("2.2", "FAIL", true, "", "No tests defined"),
		chk("2.3", "PASS", true, "ok", ""),
	)
	disc, q, err := parseReport(raw, "c")
	if err != nil {
		t.Fatal(err)
	}
	if len(disc.Findings) != 0 {
		t.Errorf("%d findings from errored controls, want 0", len(disc.Findings))
	}
	if q != registry.ParseQualityPartial {
		t.Errorf("quality = %v, want partial", q)
	}
	run := runNode(t, disc).GetProperties()
	if run["controls_errored"] != "2" || run["complete"] != "false" {
		t.Errorf("run = %v, want 2 errored and complete=false", run)
	}
	if !strings.Contains(run["not_assessed_errored"], "2.1:") || !strings.Contains(run["not_assessed_errored"], "2.2:") {
		t.Errorf("errored controls not named: %q", run["not_assessed_errored"])
	}
}

// TestAuditFaultDetection covers the kubectl failure strings. Only the
// /bin/sh form appears in the recording. The others are the documented kubectl
// messages, so this table is built from kubectl's wording, not from a capture.
func TestAuditFaultDetection(t *testing.T) {
	for _, tc := range []struct {
		name, actual string
		fault        bool
	}{
		{"dash lacks [[", "/bin/sh: 3: [[: not found\n**role_name: a", true},
		{"rbac refusal", "Error from server (Forbidden): roles is forbidden", true},
		{"unauthorized", "Error from server (Unauthorized): the server has asked for the client to provide credentials", true},
		// Real line from the recording, control 5.1.6: one static pod has no
		// service account. The same value holds nine genuine
		// is_compliant:false rows, so this must NOT read as a fault.
		{"one object missing", "**namespace: kube-system is_compliant: false\nError from server (NotFound): serviceaccounts \"<none>\" not found", false},
		{"unreachable", "Unable to connect to the server: dial tcp: lookup x", true},
		{"refused", "The connection to the server x:6443 was refused", true},
		{"kubectl login", "error: You must be logged in to the server (Unauthorized)", true},
		{"ordinary value", "namespace: default, kind: ServiceAccount, automountServiceAccountToken: not set", false},
		{"empty", "", false},
		{"mentions error mid-line", "pod_name: error-handler is_compliant: true", false},
	} {
		if _, got := auditFault(tc.actual); got != tc.fault {
			t.Errorf("%s: auditFault = %v, want %v", tc.name, got, tc.fault)
		}
	}
}

func TestErrored_AuditFaultInValueIsNotAFinding(t *testing.T) {
	raw := synthReport(
		chk("3.1", "WARN", false, "Error from server (Forbidden): clusterrolebindings is forbidden", ""),
		chk("3.2", "PASS", true, "ok", ""),
	)
	disc, _, err := parseReport(raw, "c")
	if err != nil {
		t.Fatal(err)
	}
	if len(disc.Findings) != 0 {
		t.Errorf("RBAC refusal became %d findings, want 0", len(disc.Findings))
	}
}

// TestNothingAssessedIsAnErrorNotAnEmptyResult: when no control produced a
// verdict, returning an empty result would read as a clean cluster.
func TestNothingAssessedIsAnErrorNotAnEmptyResult(t *testing.T) {
	raw := synthReport(
		chk("4.1", "FAIL", true, "", `failed to run: "kubectl", output: "refused"`),
		chk("4.2", "WARN", false, "", "Test marked as a manual test"),
	)
	disc, q, err := parseReport(raw, "c")
	if err == nil {
		t.Fatal("parse of a report where nothing was assessed returned no error")
	}
	if q != registry.ParseQualityFailed {
		t.Errorf("quality = %v, want failed", q)
	}
	if !strings.Contains(err.Error(), "not a clean result") {
		t.Errorf("error %q does not say the result is not clean", err)
	}
	if len(disc.Findings) != 0 {
		t.Error("findings returned alongside the error")
	}
}

func TestEmptyOrUnknownShapeIsAnError(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":           nil,
		"no controls":     []byte(`{"Controls":[],"Totals":{}}`),
		"not json":        []byte(`kube-bench: error`),
		"renamed test_id": []byte(`{"Controls":[{"version":"cis-1.12","tests":[{"results":[{"id":"1.1","status":"PASS"}]}]}]}`),
		"renamed status":  []byte(`{"Controls":[{"version":"cis-1.12","tests":[{"results":[{"test_number":"1.1","state":"PASS"}]}]}]}`),
	} {
		if _, q, err := parseReport(raw, "c"); err == nil || q != registry.ParseQualityFailed {
			t.Errorf("%s: err=%v quality=%v, want an error and failed quality", name, err, q)
		}
	}
}

// TestGolden_FailsWhenKubeBenchRenamesAField is the shape-change guard run
// against the real recording: rename one field kube-bench emits and the parse
// must refuse the report rather than read it as having no controls.
func TestGolden_FailsWhenKubeBenchRenamesAField(t *testing.T) {
	raw := loadGolden(t)
	mutated := strings.ReplaceAll(string(raw), `"test_number"`, `"control_id"`)
	if mutated == string(raw) {
		t.Fatal("fixture has no test_number field to rename: fixture is not a kube-bench report")
	}
	if _, _, err := parseReport([]byte(mutated), goldenCluster); err == nil {
		t.Fatal("parse accepted a report whose test_number field was renamed")
	}
}

// ---- the absent-kubeconfig contract ----------------------------------------

// onlyEmptyPath makes any attempt to start kubectl or kube-bench fail with a
// different error than the one under test, so a test that passes proves the
// tool refused BEFORE it tried to run anything.
func onlyEmptyPath(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

func TestAbsentKubeconfig_FailsNamingTheField(t *testing.T) {
	onlyEmptyPath(t)
	for name, opts := range map[string]map[string]string{
		"field absent":           nil,
		"field empty":            {kubeconfigOption: ""},
		"only spaces":            {kubeconfigOption: "  \n\t "},
		"other options":          {"benchmark": "cis-1.12"},
		"named but not declared": {kubeconfigOption: "a-secret-nobody-handed-over"},
	} {
		resp, err := (&parser{}).Execute(context.Background(), registry.ExecuteRequest{
			Target: "prod-eu", Options: opts,
		})
		if err == nil {
			t.Fatalf("%s: Execute returned no error. A security tool that cannot reach the cluster must not return a result", name)
		}
		for _, must := range []string{kubeconfigOption, "has no kubeconfig"} {
			if !strings.Contains(err.Error(), must) {
				t.Errorf("%s: error %q does not mention %s", name, err, must)
			}
		}
		if resp.ParseQuality != registry.ParseQualityFailed {
			t.Errorf("%s: quality = %v, want failed", name, resp.ParseQuality)
		}
		if resp.Discovery != nil && (len(resp.Discovery.Findings) > 0 || len(resp.Discovery.CustomNodes) > 0) {
			t.Errorf("%s: a discovery result accompanied the error", name)
		}
	}
}

// A credential VALUE in the input is not a credential. The input is captured
// with the tool call, so accepting one there would make the storing path the
// working path — which is why the field holds a name.
func TestAnInlineKubeconfigInTheInputIsRefused(t *testing.T) {
	onlyEmptyPath(t)
	_, err := (&parser{}).Execute(context.Background(), registry.ExecuteRequest{
		Target:  "prod-eu",
		Options: map[string]string{kubeconfigOption: "apiVersion: v1\nclusters: []\n"},
	})
	if err == nil {
		t.Fatal("an inline kubeconfig in the input was accepted as a credential")
	}
}

// stubKubectl installs a kubectl that runs the given shell body.
func stubKubectl(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0o755); err != nil { //nolint:gosec // test stub must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
}

const goodConfigJSON = `{"clusters":[{"name":"c","cluster":{"server":"https://x"}}],"users":[{"name":"u","user":{"token":"t"}}]}`

func TestUnreachableCluster_FailsNamingTheCluster(t *testing.T) {
	stubKubectl(t, `
case "$1" in
  config) echo '`+goodConfigJSON+`' ;;
  get) echo "Unable to connect to the server: dial tcp 10.0.0.1:6443: connect: connection refused" >&2; exit 1 ;;
esac`)
	resp, err := (&parser{}).Execute(context.Background(), registry.ExecuteRequest{
		Target: "prod-eu", Options: handedTheKubeconfig(t, "apiVersion: v1\n"),
	})
	if err == nil {
		t.Fatal("unreachable cluster returned no error")
	}
	if !strings.Contains(err.Error(), "cannot reach the cluster") || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error %q does not name the unreachable cluster and the cause", err)
	}
	if resp.ParseQuality != registry.ParseQualityFailed {
		t.Errorf("quality = %v, want failed", resp.ParseQuality)
	}
}

func TestUnusableKubeconfig_IsRefusedByName(t *testing.T) {
	for name, tc := range map[string]struct{ cfg, want string }{
		"exec plugin":   {`{"clusters":[{"name":"c","cluster":{}}],"users":[{"name":"u","user":{"exec":{"command":"aws"}}}]}`, "exec credential plugin"},
		"token file":    {`{"clusters":[{"name":"c","cluster":{}}],"users":[{"name":"u","user":{"tokenFile":"/x"}}]}`, "reads its token from a file"},
		"client cert":   {`{"clusters":[{"name":"c","cluster":{}}],"users":[{"name":"u","user":{"client-certificate":"/x"}}]}`, "client certificate from a file"},
		"CA file":       {`{"clusters":[{"name":"c","cluster":{"certificate-authority":"/x"}}],"users":[{"name":"u","user":{}}]}`, "CA from a file"},
		"no users":      {`{"clusters":[{"name":"c","cluster":{}}],"users":[]}`, "no clusters or no users"},
		"auth provider": {`{"clusters":[{"name":"c","cluster":{}}],"users":[{"name":"u","user":{"auth-provider":{"name":"gcp"}}}]}`, "auth-provider"},
	} {
		err := inspectKubeconfig([]byte(tc.cfg))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want it to contain %q", name, err, tc.want)
		}
	}
	if err := inspectKubeconfig([]byte(goodConfigJSON)); err != nil {
		t.Errorf("inline-token kubeconfig refused: %v", err)
	}
}

// TestExecute_RunsAgainstTheClusterWhenTheKubeconfigIsGood drives the whole
// path with stubs: preflight, version detection, and the argv given to
// kube-bench. The stub kube-bench replays the recording.
func TestExecute_PassesTheClusterVersionAndTheFixedTarget(t *testing.T) {
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	golden, err := filepath.Abs(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil { //nolint:gosec // test stub
			t.Fatal(err)
		}
	}
	write("kubectl", `
case "$1" in
  config) echo '`+goodConfigJSON+`' ;;
  get) echo '{"major":"1","minor":"33+"}' ;;
esac`)
	write("kube-bench", `echo "$@" > `+argvFile+`; cat `+golden)
	t.Setenv("PATH", dir+":/usr/bin:/bin")

	resp, err := (&parser{}).Execute(context.Background(), registry.ExecuteRequest{
		Target: goldenCluster, Options: handedTheKubeconfig(t, "apiVersion: v1\n"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(resp.Discovery.Findings) != 5 {
		t.Errorf("%d findings, want 5", len(resp.Discovery.Findings))
	}
	// #nosec G304 -- argvFile is a path this test created under t.TempDir().
	argv, _ := os.ReadFile(argvFile)
	for _, must := range []string{"--targets policies", "--json", "--version 1.33", "--config-dir " + kubeBenchConfigDir} {
		if !strings.Contains(string(argv), must) {
			t.Errorf("kube-bench argv %q lacks %q", strings.TrimSpace(string(argv)), must)
		}
	}
}

func TestInput_RejectsArgsAndBadBenchmark(t *testing.T) {
	opts := handedTheKubeconfig(t, "x")
	if _, err := readInput(registry.ExecuteRequest{Target: "c", Args: []string{"--targets", "node"}, Options: opts}); err == nil {
		t.Error("args were accepted: --targets node would audit the sandbox, not the cluster")
	}
	if _, err := readInput(registry.ExecuteRequest{Target: "c", Options: handedTheKubeconfig(t, "x", "benchmark", "../../etc")}); err == nil {
		t.Error("a benchmark that is not cis-<major>.<minor> was accepted")
	}
	if _, err := readInput(registry.ExecuteRequest{Target: "-c", Options: opts}); err == nil {
		t.Error("a target that starts with a dash was accepted")
	}
	if _, err := readInput(registry.ExecuteRequest{Target: "c", Options: handedTheKubeconfig(t, "x", "benchmark", "cis-1.12")}); err != nil {
		t.Errorf("valid input refused: %v", err)
	}
}

func TestClusterMinor(t *testing.T) {
	for in, want := range map[string]string{
		`{"major":"1","minor":"33"}`:  "1.33",
		`{"major":"1","minor":"33+"}`: "1.33",
	} {
		if got, err := clusterMinor([]byte(in)); err != nil || got != want {
			t.Errorf("clusterMinor(%s) = %q, %v, want %q", in, got, err, want)
		}
	}
	if _, err := clusterMinor([]byte(`{"major":"","minor":""}`)); err == nil {
		t.Error("an empty version was accepted")
	}
}

func TestCatalogEntry(t *testing.T) {
	e := (&parser{}).Describe()
	if e.Name != "kube-bench" {
		t.Errorf("name = %q: it must equal the binary the Dockerfile installs", e.Name)
	}
	props := e.InputSchema["properties"].(map[string]any)
	if _, ok := props[kubeconfigOption]; !ok {
		t.Errorf("input schema does not declare the %s field", kubeconfigOption)
	}
	// And it must NOT declare a field for the value. A schema that advertises
	// one tells a mission author to put a credential where it will be stored.
	if _, ok := props["kubeconfig"]; ok {
		t.Error(`input schema still declares "kubeconfig", which would carry the value in the stored input`)
	}
	// Required, because the mission author names the secret now. An optional
	// field reads as one the daemon fills.
	if !slices.Contains(requiredFields(t, e), kubeconfigOption) {
		t.Errorf("%s is not required; a mission that omits it should fail at validate, not at dispatch", kubeconfigOption)
	}
	if _, ok := props["args"]; ok {
		t.Error("input schema exposes args, which the tool rejects")
	}
}

// requiredFields reads the schema's required list as strings. The schema is
// map[string]any, so the list arrives as []any and a direct comparison would
// never match.
func requiredFields(t *testing.T, e registry.CatalogEntry) []string {
	t.Helper()
	raw, ok := e.InputSchema["required"].([]any)
	if !ok {
		t.Fatal("InputSchema has no required list")
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		s, ok := r.(string)
		if !ok {
			t.Fatalf("required entry %v is not a string", r)
		}
		out = append(out, s)
	}
	return out
}
