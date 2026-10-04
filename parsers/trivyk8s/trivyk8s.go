// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package trivyk8s wraps `trivy k8s`, which reads a cluster's workloads
// through the Kubernetes API and reports one misconfiguration per check that
// failed.
//
// # Why this tool and not kubeaudit
//
// gibson-executor#88 asked for kubeaudit, because kube-bench's policies target
// is CIS section 5, almost all of it unscored, so its output is broad and
// nearly all low. Shopify/kubeaudit is archived: the last release is v0.22.2
// from August 2024 and there are no commits after it. Pinning it would import
// a dependency tree that can never be patched, and the image vulnerability
// gate would block a release with no way to clear it.
//
// trivy is already pinned and already built from source in this image, and its
// Kubernetes checks cover the same ground with an upstream severity on each
// one: privileged containers (KSV-0017), host namespaces (KSV-0008 through
// KSV-0010), hostPath mounts (KSV-0023, KSV-0121), added capabilities
// (KSV-0005, KSV-0119, KSV-0022) and a missing security context (KSV-0118).
// So this tool adds no new upstream and no new vulnerability surface.
//
// # Severity
//
// Severity is trivy's own Misconfiguration.Severity, one of LOW, MEDIUM, HIGH
// or CRITICAL, lowercased. This package maps no check to a tier of its own and
// holds no per-check table. An unrecognised severity is an error, not a guess:
// silently folding it into "low" would present a scanner's CRITICAL as
// something an operator can defer.
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
//	ClusterAudit  one per run: cluster, counts, and every resource that could
//	              NOT be read, with the reason the API gave
//	Workload      one per resource that was read, whether or not it failed a
//	              check, so a clean workload is visible as audited
//	Finding       one per check that failed, parented to its Workload
//	Evidence      the check's raw trivy result, unmodified, per Finding
//
// ClusterAudit is what makes an empty Finding list readable. "No findings"
// with 40 workloads audited and 0 unreadable means the cluster conformed.
// "No findings" with 40 unreadable resources means nothing was learned.
package trivyk8s

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
	"sort"
	"strconv"
	"strings"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson-executor/internal/registry"
	"github.com/zeroroot-ai/gibson-executor/internal/sandbox"
)

const (
	toolName    = "trivy-k8s"
	toolVersion = "0.1.0"

	// kubeconfigOption is the input field naming the tenant secret that
	// holds the cluster's kubeconfig. The field carries the name; the daemon
	// puts the value in the environment (gibson#485).
	kubeconfigOption = "kubeconfigSecret"

	// trivy walks every namespace and runs the check set per resource. A
	// cluster with many workloads needs minutes, not seconds.
	defaultTimeout = 900

	// preflightTimeout bounds each kubectl call made before trivy runs.
	preflightTimeout = "30s"

	nodeAudit    = "ClusterAudit"
	nodeWorkload = "Workload"

	categoryMisconfig = "kubernetes-misconfiguration"

	// scanners limits the run to misconfiguration checks. Without it trivy
	// also pulls and scans every workload's image for vulnerabilities, which
	// is what parsers/trivy already does, with its own database and its own
	// timeout. Two tools reporting the same package CVE under two ids is a
	// duplicate finding, not more coverage.
	scanners = "misconfig"
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:    toolName,
		Version: toolVersion,
		Description: "Kubernetes workload misconfiguration checks through the Kubernetes API: privileged containers, host namespaces, hostPath mounts, added capabilities, missing security contexts. " +
			"Emits one Finding per failed check at the severity trivy reports, a Workload node per resource audited, and a ClusterAudit node listing every resource that could not be read. " +
			"Needs a kubeconfig that the daemon supplies from a tenant secret.",
		Tags: []string{"kubernetes", "misconfiguration", "workload", "configuration", "privilege"},
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
				"namespace": map[string]any{
					"type":        "string",
					"description": "Optional single namespace to audit. When absent, every namespace the credential can read is audited.",
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
		Resources:             registry.ResourceHint{VCPU: 1, Memory: "1Gi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

func (p *parser) OutputMessage() proto.Message { return nil }

// severities is the whole mapping. trivy's Severity is already a tier, so the
// map exists to lowercase it and to refuse a value this package has not seen.
//
// UNKNOWN is accepted and kept as "unknown". trivy emits it for a check whose
// metadata carries no severity, and dropping such a finding would hide a real
// failed check. Calling it "low" would be a claim trivy did not make.
var severities = map[string]string{
	"CRITICAL": "critical",
	"HIGH":     "high",
	"MEDIUM":   "medium",
	"LOW":      "low",
	"UNKNOWN":  "unknown",
}

type config struct {
	cluster    string
	kubeconfig string
	namespace  string
}

// namespaceRe is RFC 1123: what the API server accepts as a namespace name.
// The value reaches an argv, so it is validated rather than quoted.
var namespaceRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

func readInput(req registry.ExecuteRequest) (config, error) {
	var c config
	kubeconfig, err := registry.DeclaredSecret(req, kubeconfigOption)
	if err != nil {
		// Named first and reported as-is. It is the failure that must never be
		// masked by another one, and it is not a clean result: the cluster was
		// never contacted and no workload was audited.
		return c, fmt.Errorf("trivy-k8s has no kubeconfig: %w", err)
	}
	c.kubeconfig = kubeconfig
	if err := registry.ValidateTarget(toolName, req.Target); err != nil {
		return c, fmt.Errorf("trivy-k8s target: %w", err)
	}
	c.cluster = req.Target

	if len(req.Args) > 0 {
		// Not silently dropped: a caller who passed a flag expects it to act,
		// and "ignored" reads as "applied".
		return c, errors.New("trivy-k8s accepts no args: the run is fixed to misconfiguration checks with JSON output")
	}
	if ns := strings.TrimSpace(req.Options["namespace"]); ns != "" {
		if !namespaceRe.MatchString(ns) {
			return c, fmt.Errorf("trivy-k8s namespace %q is not a DNS label", ns)
		}
		c.namespace = ns
	}
	return c, nil
}

// inspectKubeconfig refuses a kubeconfig that would make a client run a
// program or read a file. raw is `kubectl config view --raw -o json`.
//
// The kubeconfig is tenant-supplied. An exec credential plugin runs a command
// of the tenant's choosing, and a *-file field reads a path of their choosing.
// Neither belongs in a scanner. The message says which field to inline.
func inspectKubeconfig(raw []byte) error {
	var cfg struct {
		Users []struct {
			Name string `json:"name"`
			User struct {
				Exec              json.RawMessage `json:"exec"`
				AuthProvider      json.RawMessage `json:"auth-provider"`
				TokenFile         string          `json:"tokenFile"`
				ClientCertificate string          `json:"client-certificate"`
				ClientKey         string          `json:"client-key"`
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

// childEnv is the child's interface. trivy and kubectl both read the
// kubeconfig from the file KUBECONFIG names. This package does not read it.
//
// TRIVY_CACHE_DIR and XDG_CACHE_HOME point inside the per-call directory so a
// run cannot write to a shared cache. trivy's misconfiguration checks are
// built into the binary, so nothing is downloaded and an unwritable default
// cache would fail the run for no reason.
func childEnv(kubeconfigPath, home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"KUBECONFIG=" + kubeconfigPath,
		"TRIVY_CACHE_DIR=" + filepath.Join(home, "cache"),
		"XDG_CACHE_HOME=" + filepath.Join(home, "cache"),
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
		// non-zero exit means.
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
// started there is no stderr, and the Go error is the reason.
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

func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	failed := &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed}

	cfg, err := readInput(req)
	if err != nil {
		return failed, err
	}

	// The kubeconfig is written to a private directory that exists for this
	// call only. trivy and kubectl take a file, not a string.
	dir, err := os.MkdirTemp("", "trivy-k8s-")
	if err != nil {
		return failed, fmt.Errorf("trivy-k8s workdir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	kcPath := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(kcPath, []byte(cfg.kubeconfig), 0o600); err != nil {
		return failed, fmt.Errorf("trivy-k8s kubeconfig: %w", err)
	}
	env := childEnv(kcPath, dir)

	// Preflight 1: the kubeconfig parses and carries no plugin or file refs.
	view, err := runProc(ctx, env, "kubectl", "config", "view", "--raw", "-o", "json")
	if err != nil {
		return failed, fmt.Errorf("trivy-k8s kubeconfig is unusable: kubectl could not read it: %s", why(view, err))
	}
	if err := inspectKubeconfig(view.stdout); err != nil {
		return failed, fmt.Errorf("trivy-k8s kubeconfig is unusable: %w", err)
	}

	// Preflight 2: the cluster answers and accepts the credential. Without
	// this, an unreachable cluster makes trivy report every resource with an
	// Error, and the failure arrives as a list of resources rather than as
	// one sentence.
	ver, err := runProc(ctx, env, "kubectl", "get", "--raw", "/version", "--request-timeout="+preflightTimeout)
	if err != nil {
		return failed, fmt.Errorf("trivy-k8s cannot reach the cluster with the supplied kubeconfig: %s", why(ver, err))
	}

	args := []string{
		"k8s",
		"--format", "json",
		"--scanners", scanners,
		// Pass rows are needed to count what was audited. Without them a
		// workload with no failed check is absent from the report and cannot
		// be told apart from one that was never read.
		"--include-non-failures",
		"--quiet",
		"--timeout", strconv.Itoa(defaultTimeout) + "s",
	}
	if cfg.namespace != "" {
		args = append(args, "--namespace", cfg.namespace)
	} else {
		args = append(args, "--all-namespaces")
	}
	res, runErr := runProc(ctx, env, "trivy", args...)

	resp := &registry.ExecuteResponse{Stdout: res.stdout, Stderr: res.stderr, ExitCode: res.exit}
	if runErr != nil && len(res.stdout) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("trivy-k8s exec: %w", runErr)
	}

	disc, quality, parseErr := parseReport(res.stdout, cfg.cluster)
	resp.Discovery = disc
	resp.ParseQuality = quality
	return resp, parseErr
}

// ---- parsing --------------------------------------------------------------

// report is the subset of `trivy k8s --format json` this parser reads. The
// shape is trivy's own pkg/k8s/report.Report at the pinned version: a
// ClusterName and a Resources list, each resource holding Results, each
// result holding Misconfigurations. Field names are trivy's Go field names,
// because its Report struct carries no json tags for them.
type report struct {
	ClusterName string `json:"ClusterName"`
	Resources   []struct {
		Namespace string `json:"Namespace"`
		Kind      string `json:"Kind"`
		Name      string `json:"Name"`
		// Error is set per resource when trivy could not read it, most often
		// because the credential is not allowed to. A resource with an Error
		// was not audited, and must never be counted as clean.
		Error   string `json:"Error"`
		Results []struct {
			Misconfigurations []json.RawMessage `json:"Misconfigurations"`
		} `json:"Results"`
	} `json:"Resources"`
}

// misconf is one check result.
type misconf struct {
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Message     string `json:"Message"`
	Resolution  string `json:"Resolution"`
	Severity    string `json:"Severity"`
	Status      string `json:"Status"`
	PrimaryURL  string `json:"PrimaryURL"`
}

func parseReport(raw []byte, cluster string) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return disc, registry.ParseQualityFailed, errors.New(
			"trivy-k8s produced no output, so no workload was audited. This is not a clean result")
	}
	var r report
	if err := json.Unmarshal(trimmed, &r); err != nil {
		return disc, registry.ParseQualityFailed, fmt.Errorf("unmarshal trivy k8s report: %w", err)
	}
	if len(r.Resources) == 0 {
		return disc, registry.ParseQualityFailed, errors.New(
			"trivy-k8s report holds no resources, so no workload was audited. This is not a clean result")
	}

	auditID := cluster + "/misconfig"
	var (
		audited  int
		passed   int
		failures int
		unread   []string
	)

	for _, res := range r.Resources {
		ref := resourceRef(res.Namespace, res.Kind, res.Name)
		if res.Error != "" {
			unread = append(unread, ref+": "+oneLine(res.Error))
			continue
		}
		audited++

		workloadFails := 0
		for _, grp := range res.Results {
			for _, rawCheck := range grp.Misconfigurations {
				var m misconf
				if err := json.Unmarshal(rawCheck, &m); err != nil {
					return disc, registry.ParseQualityFailed, fmt.Errorf("unmarshal trivy k8s check: %w", err)
				}
				if m.ID == "" || m.Status == "" {
					// Reading on would drop the check silently.
					return disc, registry.ParseQualityFailed, errors.New(
						"trivy-k8s check has no ID or Status: the output shape changed, so the report cannot be trusted")
				}
				if m.Status != "FAIL" {
					passed++
					continue
				}
				sev, ok := severities[strings.ToUpper(m.Severity)]
				if !ok {
					// An unknown tier must not be folded into low. That would
					// present a scanner's own grading as something softer.
					return disc, registry.ParseQualityFailed, fmt.Errorf(
						"trivy-k8s check %s on %s reports severity %q, which this parser does not know. "+
							"The severity vocabulary changed, so no finding can be graded", m.ID, ref, m.Severity)
				}
				workloadFails++
				failures++
				fid := findingID(auditID, ref, m.ID)
				disc.Findings = append(disc.Findings, buildFinding(fid, ref, sev, m))
				disc.Evidence = append(disc.Evidence, &graphragpb.Evidence{
					Id:        proto.String(fid + ":result"),
					FindingId: fid,
					Type:      "trivy-k8s-misconfiguration",
					Content:   proto.String(string(rawCheck)),
				})
			}
		}

		disc.CustomNodes = append(disc.CustomNodes, &graphragpb.CustomNode{
			NodeType:     nodeWorkload,
			IdProperties: map[string]string{"id": ref},
			Properties: map[string]string{
				"cluster":       cluster,
				"namespace":     res.Namespace,
				"kind":          res.Kind,
				"name":          res.Name,
				"checks_failed": strconv.Itoa(workloadFails),
				"audited":       "true",
				"parent_audit":  auditID,
			},
		})
	}

	if audited == 0 {
		// Every resource came back with an Error. An empty result here would
		// read as a clean cluster.
		return disc, registry.ParseQualityFailed, fmt.Errorf(
			"trivy-k8s read none of the %d resources it found, so nothing was audited. "+
				"This is not a clean result. First reasons: %s", len(unread), firstN(unread, 3))
	}

	sort.Strings(unread)
	props := map[string]string{
		"cluster":           cluster,
		"reported_cluster":  r.ClusterName,
		"scanners":          scanners,
		"workloads_audited": strconv.Itoa(audited),
		"checks_failed":     strconv.Itoa(failures),
		"checks_passed":     strconv.Itoa(passed),
		"resources_unread":  strconv.Itoa(len(unread)),
		"complete":          strconv.FormatBool(len(unread) == 0),
	}
	if len(unread) > 0 {
		props["not_audited"] = strings.Join(unread, "; ")
	}
	disc.CustomNodes = append(disc.CustomNodes, &graphragpb.CustomNode{
		NodeType:     nodeAudit,
		IdProperties: map[string]string{"id": auditID},
		Properties:   props,
	})

	quality := registry.ParseQualityStructured
	if len(unread) > 0 {
		// The findings are real, but the run is incomplete. Partial tells the
		// graph so, and ClusterAudit names what was missed.
		quality = registry.ParseQualityPartial
	}
	return disc, quality, nil
}

// resourceRef is the stable identity of a resource. Namespace is empty for a
// cluster-scoped object, which is why the form is not a bare join.
func resourceRef(namespace, kind, name string) string {
	if namespace == "" {
		return kind + "/" + name
	}
	return namespace + "/" + kind + "/" + name
}

func findingID(auditID, ref, check string) string {
	return "finding:trivy-k8s:" + auditID + ":" + ref + ":" + check
}

func buildFinding(id, ref, severity string, m misconf) *graphragpb.Finding {
	desc := m.Message
	if desc == "" {
		desc = m.Description
	}
	desc = fmt.Sprintf("%s on %s.", strings.TrimSuffix(oneLine(desc), "."), ref)
	if m.Description != "" && m.Description != m.Message {
		desc += " " + oneLine(m.Description)
	}
	// graphragpb.Finding carries no references field, so the check's own page
	// goes in the description. Evidence holds the raw check, which names it
	// too, but a reader sees the description first.
	if m.PrimaryURL != "" {
		desc += " See " + m.PrimaryURL
	}
	f := &graphragpb.Finding{
		Id:          proto.String(id),
		Title:       fmt.Sprintf("%s: %s", m.ID, m.Title),
		Description: proto.String(truncate(desc, 1200)),
		Severity:    severity,
		Category:    proto.String(categoryMisconfig),
		ParentType:  proto.String(nodeWorkload),
		ParentId:    proto.String(ref),
	}
	if rem := strings.TrimSpace(m.Resolution); rem != "" {
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
