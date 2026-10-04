// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package kubebench wraps Aqua Security's kube-bench, which runs the CIS
// Kubernetes Benchmark and reports one result per control.
//
// # What a run covers
//
// kube-bench has five targets: master, controlplane, etcd, node and policies.
// Four of them read the machine kube-bench runs ON: config files under
// /etc/kubernetes, the command lines of local processes, file modes. This
// tool runs inside a sandbox that is not a cluster node, so those targets
// would audit the sandbox and report its misconfigurations as if they were
// the cluster's. That is a false report, and a worse one than no report.
//
// Only "policies" (CIS section 5: RBAC, pod security, network policy,
// secrets, general policies) reads the cluster through the Kubernetes API,
// so it is the only target this tool runs. It is fixed, not an input. The
// other four need the executor to run as a Job on the node. That is a
// different tool with a different trust model.
//
// # Credential
//
// The mission declares which named tenant secrets its tools may receive
// (gibson#485). The input field "kubeconfigSecret" names one of them; the
// daemon resolves the name as itself at dispatch and puts the VALUE in this
// process's environment, under the name secretenv.Key derives.
//
// The input carries the NAME, never the value. A tool's input JSON is captured
// with the tool call, so a credential written there would be stored and
// displayed. This package therefore reads no credential value from its input,
// and no path, no ambient environment variable and no default location either.
// When the mission named nothing, or named a secret it did not declare for
// this tool, the tool fails and says which of the two happened.
//
// # Result shape
//
//	BenchmarkRun  one per run: benchmark, cluster version, counts, and the
//	              id of every control that was NOT assessed, with the reason
//	Finding       one per control that was assessed and did not conform
//	Evidence      the control's raw kube-bench result, unmodified, per Finding
//
// BenchmarkRun is what makes an empty Finding list readable. "No findings"
// with a BenchmarkRun that says 5 controls passed and 0 errored means the
// cluster conformed. "No findings" with 29 controls not assessed means
// nothing was learned about them.
package kubebench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

const (
	toolName    = "kube-bench"
	toolVersion = "0.1.0"

	// kubeconfigOption is the input field naming the tenant secret that
	// holds the cluster's kubeconfig. The field carries the name; the daemon
	// puts the value in the environment (gibson#485).
	kubeconfigOption = "kubeconfigSecret"

	// The audit scripts shell out to kubectl once per object. A cluster with
	// many roles and pods needs minutes, not seconds.
	defaultTimeout = 600

	// kubeBenchConfigDir is where the Dockerfile installs the benchmark
	// definitions. It is passed explicitly, so a stray ./cfg in the working
	// directory can never replace the controls that run.
	kubeBenchConfigDir = "/etc/kube-bench/cfg"

	// preflightTimeout bounds each kubectl call made before kube-bench runs.
	preflightTimeout = "30s"

	nodeRun = "BenchmarkRun"

	// CIS does not publish a severity, and kube-bench's JSON carries none
	// (checked against v0.16.0 output: the only grading fields are status
	// and scored). These two tiers are assigned by this package from the
	// strength of the verdict, not by CIS:
	//
	//   medium  a scored control failed. CIS marks these as automatable and
	//           expected to be satisfied.
	//   low     an unscored (advisory) control did not conform.
	//
	// There is deliberately no per-control severity table. Inventing one
	// would present a guess as if CIS had said it.
	severityScoredFail   = "medium"
	severityUnscoredFail = "low"

	categoryCIS = "cis-benchmark"
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:    toolName,
		Version: toolVersion,
		Description: "CIS Kubernetes Benchmark, policies section (RBAC, pod security, network policy, secrets), run through the Kubernetes API. " +
			"Emits one Finding per control that failed and a BenchmarkRun node that lists every control not assessed. " +
			"Needs a kubeconfig that the daemon supplies from a tenant secret.",
		Tags: []string{"kubernetes", "cis", "compliance", "configuration", "rbac"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{
					"type":        "string",
					"description": "Name of the cluster, as a DNS-style label. It names the result. It is never used to find the cluster: the kubeconfig does that.",
				},
				"kubeconfigSecret": map[string]any{
					"type": "string",
					"description": "Name of the tenant secret holding a kubeconfig for the cluster. A name, never a value: " +
						"a tool's input is stored with the tool call, so the value arrives in the environment instead. " +
						"The mission must also declare this name in its secrets block for this tool (gibson#485).",
				},
				"benchmark": map[string]any{
					"type": "string",
					"description": "Optional CIS benchmark version, for example cis-1.12. " +
						"When absent, the version is chosen from the Kubernetes version the cluster reports.",
				},
			},
			// kubeconfigSecret is required now. It used to be optional because
			// the daemon filled the value; under gibson#485 the MISSION author
			// names the secret, so a definition that omits it is incomplete and
			// should fail at validate rather than at dispatch.
			"required": []any{"target", kubeconfigOption},
		},
		OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
		DefaultParseQuality:   registry.ParseQualityStructured,
		Resources:             registry.ResourceHint{VCPU: 1, Memory: "512Mi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

func (p *parser) OutputMessage() proto.Message { return nil }

var benchmarkRe = regexp.MustCompile(`^cis-\d+\.\d+$`)

// config is the validated input.
type config struct {
	cluster    string
	kubeconfig string
	benchmark  string
}

// readInput validates everything that can be checked without running a
// process. The kubeconfig check comes first: it is the failure that must
// never be masked by another one.
func readInput(req registry.ExecuteRequest) (config, error) {
	var c config
	kubeconfig, err := registry.DeclaredSecret(req, kubeconfigOption)
	if err != nil {
		// Named first and reported as-is. It is the failure that must never be
		// masked by another one, and it is not a clean result: the cluster was
		// never contacted and no control was assessed.
		return c, fmt.Errorf("kube-bench has no kubeconfig: %w", err)
	}
	c.kubeconfig = kubeconfig
	if err := registry.ValidateTarget(toolName, req.Target); err != nil {
		return c, fmt.Errorf("kube-bench target: %w", err)
	}
	c.cluster = req.Target

	if len(req.Args) > 0 {
		// Not silently dropped: a caller who passed a flag expects it to
		// act, and "ignored" reads as "applied".
		return c, errors.New("kube-bench accepts no args: the run is fixed to the policies target with JSON output")
	}
	if b := req.Options["benchmark"]; b != "" {
		if !benchmarkRe.MatchString(b) {
			return c, fmt.Errorf("kube-bench benchmark %q is not of the form cis-<major>.<minor>", b)
		}
		c.benchmark = b
	}
	return c, nil
}

// inspectKubeconfig refuses a kubeconfig that would make kubectl run a
// program or read a file. raw is `kubectl config view --raw -o json`.
//
// The kubeconfig is tenant-supplied. An exec credential plugin runs a command
// of the tenant's choosing, and a *-file field reads a path of their choosing.
// Neither belongs in a scanner. A kubeconfig that needs them cannot be used
// here, and the message says which field to inline.
func inspectKubeconfig(raw []byte) error {
	var cfg struct {
		Users []struct {
			Name string `json:"name"`
			User struct {
				Exec                  json.RawMessage `json:"exec"`
				AuthProvider          json.RawMessage `json:"auth-provider"`
				TokenFile             string          `json:"tokenFile"`
				ClientCertificate     string          `json:"client-certificate"`
				ClientKey             string          `json:"client-key"`
				ImpersonateUser       string          `json:"as"`
				ImpersonateGroups     []string        `json:"as-groups"`
				ImpersonateUserExtras map[string]any  `json:"as-user-extra"`
			} `json:"user"`
		} `json:"users"`
		Clusters []struct {
			Name    string `json:"name"`
			Cluster struct {
				CertificateAuthority string `json:"certificate-authority"`
			} `json:"cluster"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("kubeconfig could not be read: %w", err)
	}
	if len(cfg.Clusters) == 0 || len(cfg.Users) == 0 {
		return errors.New("kubeconfig has no clusters or no users")
	}
	for _, u := range cfg.Users {
		switch {
		case len(u.User.Exec) > 0:
			return fmt.Errorf("kubeconfig user %q uses an exec credential plugin, which runs a program. Use a token or inline client certificate data", u.Name)
		case len(u.User.AuthProvider) > 0:
			return fmt.Errorf("kubeconfig user %q uses an auth-provider plugin. Use a token or inline client certificate data", u.Name)
		case u.User.TokenFile != "":
			return fmt.Errorf("kubeconfig user %q reads its token from a file. Inline the token", u.Name)
		case u.User.ClientCertificate != "" || u.User.ClientKey != "":
			return fmt.Errorf("kubeconfig user %q reads its client certificate from a file. Use client-certificate-data and client-key-data", u.Name)
		}
	}
	for _, c := range cfg.Clusters {
		if c.Cluster.CertificateAuthority != "" {
			return fmt.Errorf("kubeconfig cluster %q reads its CA from a file. Use certificate-authority-data", c.Name)
		}
	}
	return nil
}

// kubectl and kube-bench both read the kubeconfig from the file the
// KUBECONFIG variable names. That variable is the child's own interface, set
// here for the child only. This package does not read it.
func childEnv(kubeconfigPath, home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"KUBECONFIG=" + kubeconfigPath,
	}
}

type procResult struct {
	stdout, stderr []byte
	exit           int32
}

func runProc(ctx context.Context, env []string, name string, args ...string) (procResult, error) {
	sbCfg := sandbox.DefaultConfig()
	var stdout, stderr sandbox.CappedBuffer
	stdout.Init(sbCfg.OutputCapBytes)
	stderr.Init(sbCfg.OutputCapBytes)
	// The program name is one of two literals, and every arg is built in this
	// package from validated fields. No caller string reaches the argv.
	//
	//nolint:gosec // G204: program is a literal, argv is built from validated fields.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	if err := sandbox.Apply(cmd, sbCfg); err != nil {
		return procResult{}, fmt.Errorf("%s sandbox: %w", name, err)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if runErr != nil {
		// Wrapped so the error names the process. The caller decides what a
		// non-zero exit means — kube-bench exits non-zero on a failed control,
		// which is a result, not a failure to run.
		runErr = fmt.Errorf("%s: %w", name, runErr)
	}

	res := procResult{stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		// A wait status is -1 or 0..255. The guard exists because the
		// compiler cannot know that.
		if ec := cmd.ProcessState.ExitCode(); ec >= math.MinInt32 && ec <= math.MaxInt32 {
			res.exit = int32(ec)
		}
	}
	if err := stdout.Err(); err != nil {
		return res, fmt.Errorf("%s stdout: %w", name, err)
	}
	return res, runErr
}

// why explains a failed process. kubectl says why on stderr. When it never
// started (not on PATH) there is no stderr, and the Go error is the reason.
func why(res procResult, err error) string {
	if t := tail(res.stderr, 500); t != "" {
		return t
	}
	return err.Error()
}

func tail(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return strings.TrimSpace(string(b))
}

// clusterMinor extracts "1.33" from `kubectl get --raw /version`. Managed
// clusters report minor as "33+", so only the digits count.
func clusterMinor(raw []byte) (string, error) {
	var v struct {
		Major string `json:"major"`
		Minor string `json:"minor"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("cluster version response is not JSON: %w", err)
	}
	digits := func(s string) string {
		return strings.TrimFunc(s, func(r rune) bool { return r < '0' || r > '9' })
	}
	major, minor := digits(v.Major), digits(v.Minor)
	if major == "" || minor == "" {
		return "", fmt.Errorf("cluster reported no usable version (major %q, minor %q)", v.Major, v.Minor)
	}
	return major + "." + minor, nil
}

func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	failed := &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed}

	cfg, err := readInput(req)
	if err != nil {
		return failed, err
	}

	// The kubeconfig is written to a private directory that exists for this
	// call only. kubectl and kube-bench take a file, not a string.
	dir, err := os.MkdirTemp("", "kube-bench-")
	if err != nil {
		return failed, fmt.Errorf("kube-bench workdir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	kcPath := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(kcPath, []byte(cfg.kubeconfig), 0o600); err != nil {
		return failed, fmt.Errorf("kube-bench kubeconfig: %w", err)
	}
	env := childEnv(kcPath, dir)

	// Preflight 1: the kubeconfig parses and carries no plugin or file refs.
	view, err := runProc(ctx, env, "kubectl", "config", "view", "--raw", "-o", "json")
	if err != nil {
		return failed, fmt.Errorf("kube-bench kubeconfig is unusable: kubectl could not read it: %s", why(view, err))
	}
	if err := inspectKubeconfig(view.stdout); err != nil {
		return failed, fmt.Errorf("kube-bench kubeconfig is unusable: %w", err)
	}

	// Preflight 2: the cluster answers and accepts the credential. Without
	// this, an unreachable cluster makes every control error inside
	// kube-bench, and the failure arrives as 30 mysterious control results
	// rather than as one sentence.
	ver, err := runProc(ctx, env, "kubectl", "get", "--raw", "/version", "--request-timeout="+preflightTimeout)
	if err != nil {
		return failed, fmt.Errorf("kube-bench cannot reach the cluster with the supplied kubeconfig: %s", why(ver, err))
	}
	minor, err := clusterMinor(ver.stdout)
	if err != nil {
		return failed, fmt.Errorf("kube-bench cannot read the cluster version: %w", err)
	}

	// The version is always passed. kube-bench's own detection falls back to
	// a default version with only a warning on stderr, which would run the
	// wrong benchmark and read as a normal result.
	args := []string{"run", "--targets", "policies", "--json", "--config-dir", kubeBenchConfigDir}
	if cfg.benchmark != "" {
		args = append(args, "--benchmark", cfg.benchmark)
	} else {
		args = append(args, "--version", minor)
	}
	res, runErr := runProc(ctx, env, toolName, args...)

	resp := &registry.ExecuteResponse{Stdout: res.stdout, Stderr: res.stderr, ExitCode: res.exit}
	if runErr != nil && len(res.stdout) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("kube-bench exec: %w", runErr)
	}

	disc, quality, parseErr := parseReport(res.stdout, cfg.cluster)
	resp.Discovery = disc
	resp.ParseQuality = quality
	return resp, parseErr
}

// ---- parsing --------------------------------------------------------------

// report is the subset of `kube-bench run --json` this parser reads. The
// results stay as raw JSON beside their decoded form so the Evidence carries
// exactly what kube-bench printed.
type report struct {
	Controls []struct {
		Version         string `json:"version"`
		DetectedVersion string `json:"detected_version"`
		Tests           []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"tests"`
	} `json:"Controls"`
}

type check struct {
	ID             string `json:"test_number"`
	Desc           string `json:"test_desc"`
	Type           string `json:"type"`
	Remediation    string `json:"remediation"`
	Status         string `json:"status"`
	ActualValue    string `json:"actual_value"`
	Scored         bool   `json:"scored"`
	ExpectedResult string `json:"expected_result"`
	Reason         string `json:"reason"`
}

type outcome int

const (
	outcomePass outcome = iota
	// outcomeFailed means the control was assessed and did not conform.
	outcomeFailed
	// outcomeManual means kube-bench does not automate this control.
	outcomeManual
	// outcomeSkipped means the benchmark configuration turned it off.
	outcomeSkipped
	// outcomeErrored means the control did not produce a verdict because
	// something broke while assessing it.
	outcomeErrored
)

// auditFaultPrefixes are line starts that mean the audit script itself broke
// rather than reported a value. kube-bench cannot tell them apart: it merges
// the script's stderr into the value it tests, and a script whose last
// command succeeds exits 0. Real output from the shipped base image (Debian,
// where /bin/sh is dash) shows the first one: control 5.1.1 came back as
// WARN with the value "/bin/sh: 3: [[: not found" and no reason.
//
// The list is closed and deliberately narrow. A failure that matches none of
// these is reported as an ordinary result. That limit is stated in README.md.
//
// "Error from server (NotFound)" is NOT on it. The recording shows why:
// control 5.1.6 prints that line for a static pod that has no service
// account, in the middle of a run that also printed nine real
// "is_compliant: false" rows. Treating the line as a fault hid a true
// finding. A fault line belongs here only when it means the whole script
// failed to measure, not when it reports one object missing.
var auditFaultPrefixes = []string{
	"/bin/sh:",
	"Error from server (Forbidden)",
	"Error from server (Unauthorized)",
	"Unable to connect to the server",
	"The connection to the server",
	"error: You must be logged in",
}

func auditFault(actual string) (string, bool) {
	for _, line := range strings.Split(actual, "\n") {
		line = strings.TrimSpace(line)
		for _, p := range auditFaultPrefixes {
			if strings.HasPrefix(line, p) {
				return line, true
			}
		}
	}
	return "", false
}

// classify decides what a control result is. Order matters: a control that
// errored must never be counted as a failure, because a failure is a claim
// about the cluster and an error is a fact about this run.
//
// kube-bench has four states: PASS, FAIL, WARN, INFO. It folds three
// different things into FAIL and WARN:
//
//	a verdict       the test ran and the value did not match
//	not automated   the control is manual (reason "Test marked as a manual test")
//	an error        the audit command failed, or the control has no tests
//
// Only the reason field and the audit output tell them apart.
func classify(c check) (verdict outcome, reason string) {
	switch c.Status {
	case "PASS":
		return outcomePass, ""
	case "INFO":
		return outcomeSkipped, c.Reason
	case "FAIL", "WARN":
	default:
		return outcomeErrored, fmt.Sprintf("unknown status %q", c.Status)
	}
	if c.Type == "manual" || c.Reason == "Test marked as a manual test" {
		return outcomeManual, "manual control, not automated by kube-bench"
	}
	if c.Reason != "" {
		return outcomeErrored, c.Reason
	}
	if line, bad := auditFault(c.ActualValue); bad {
		return outcomeErrored, "audit script failed: " + line
	}
	return outcomeFailed, ""
}

func parseReport(raw []byte, cluster string) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return disc, registry.ParseQualityFailed, errors.New("kube-bench produced no output, so no control was assessed. This is not a clean result")
	}
	var r report
	if err := json.Unmarshal(trimmed, &r); err != nil {
		return disc, registry.ParseQualityFailed, fmt.Errorf("unmarshal kube-bench report: %w", err)
	}
	if len(r.Controls) == 0 {
		return disc, registry.ParseQualityFailed, errors.New("kube-bench report holds no controls, so no control was assessed. This is not a clean result")
	}

	benchmark, detected := r.Controls[0].Version, r.Controls[0].DetectedVersion
	runID := cluster + "/" + benchmark

	var (
		passed, failed int
		manual         []string
		skipped        []string
		errored        []string
	)

	for _, ctl := range r.Controls {
		for _, grp := range ctl.Tests {
			for _, rawCheck := range grp.Results {
				var c check
				if err := json.Unmarshal(rawCheck, &c); err != nil {
					return disc, registry.ParseQualityFailed, fmt.Errorf("unmarshal kube-bench control: %w", err)
				}
				if c.ID == "" || c.Status == "" {
					// A control with no id or no status means kube-bench
					// changed its output shape. Reading on would drop it.
					return disc, registry.ParseQualityFailed, errors.New(
						"kube-bench control has no test_number or status: the output shape changed, so the report cannot be trusted")
				}
				out, reason := classify(c)
				switch out {
				case outcomePass:
					passed++
				case outcomeManual:
					manual = append(manual, c.ID)
				case outcomeSkipped:
					skipped = append(skipped, c.ID)
				case outcomeErrored:
					errored = append(errored, c.ID+": "+oneLine(reason))
				case outcomeFailed:
					failed++
					disc.Findings = append(disc.Findings, buildFinding(runID, benchmark, detected, c))
					disc.Evidence = append(disc.Evidence, &graphragpb.Evidence{
						Id:        proto.String(findingID(runID, c.ID) + ":result"),
						FindingId: findingID(runID, c.ID),
						Type:      "kube-bench-result",
						Content:   proto.String(string(rawCheck)),
					})
				}
			}
		}
	}

	assessed := passed + failed
	if assessed == 0 {
		// Nothing produced a verdict. Returning an empty result here would
		// read as a clean cluster.
		return disc, registry.ParseQualityFailed, fmt.Errorf(
			"kube-bench assessed no control (manual %d, skipped %d, errored %d). This is not a clean result. First errors: %s",
			len(manual), len(skipped), len(errored), firstN(errored, 3))
	}

	props := map[string]string{
		"cluster":             cluster,
		"benchmark":           benchmark,
		"kubernetes_version":  detected,
		"target":              "policies",
		"controls_assessed":   strconv.Itoa(assessed),
		"controls_passed":     strconv.Itoa(passed),
		"controls_failed":     strconv.Itoa(failed),
		"controls_manual":     strconv.Itoa(len(manual)),
		"controls_skipped":    strconv.Itoa(len(skipped)),
		"controls_errored":    strconv.Itoa(len(errored)),
		"complete":            strconv.FormatBool(len(errored) == 0),
		"not_assessed_manual": strings.Join(manual, ","),
	}
	if len(skipped) > 0 {
		props["not_assessed_skipped"] = strings.Join(skipped, ",")
	}
	if len(errored) > 0 {
		props["not_assessed_errored"] = strings.Join(errored, "; ")
	}
	disc.CustomNodes = append(disc.CustomNodes, &graphragpb.CustomNode{
		NodeType:     nodeRun,
		IdProperties: map[string]string{"id": runID},
		Properties:   props,
	})

	quality := registry.ParseQualityStructured
	if len(errored) > 0 {
		// Findings are real, but the run is incomplete. Partial tells the
		// graph so, and the BenchmarkRun node names the controls.
		quality = registry.ParseQualityPartial
	}
	return disc, quality, nil
}

func findingID(runID, control string) string {
	return "finding:kube-bench:" + runID + ":" + control
}

func buildFinding(runID, benchmark, detected string, c check) *graphragpb.Finding {
	sev := severityUnscoredFail
	if c.Scored {
		sev = severityScoredFail
	}
	desc := fmt.Sprintf("CIS control %s did not conform (benchmark %s, Kubernetes %s).", c.ID, benchmark, detected)
	if c.ExpectedResult != "" {
		desc += " Expected: " + c.ExpectedResult + "."
	}
	if c.ActualValue != "" {
		desc += " Observed: " + truncate(oneLine(c.ActualValue), 400)
	}
	f := &graphragpb.Finding{
		Id:          proto.String(findingID(runID, c.ID)),
		Title:       fmt.Sprintf("CIS %s: %s", c.ID, c.Desc),
		Description: proto.String(desc),
		Severity:    sev,
		Category:    proto.String(categoryCIS),
		ParentType:  proto.String(nodeRun),
		ParentId:    proto.String(runID),
	}
	if rem := strings.TrimSpace(c.Remediation); rem != "" {
		f.Remediation = proto.String(rem)
	}
	return f
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func firstN(s []string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.Join(s, " | ")
}
