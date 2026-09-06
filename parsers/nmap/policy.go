// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Per-tool args policy for nmap: OPEN, denied by capability class.
//
// nmap 7.93 documents 158 flags. The allowlist this replaces named 26, and
// the first flag a real mission asked for (--stats-every, the progress
// printer that makes a long scan watchable) was not among them — it is not
// even in `nmap -h`. Transcribing a scanner's manual is unbounded work that
// goes stale every release, and a missing entry reads as a broken product
// rather than a policy decision.
//
// So nmap now accepts anything it accepts, except the flags that reach
// outside the run. See internal/policy/deny.go for why this is safe: the
// runner execs argv (never a shell), pins -oX - itself, and appends "--"
// before the target, all inside a gVisor microVM whose egress is the
// manifest's allowlist. This policy defends against nmap's own dangerous
// features, not against the shell.

package nmap

import (
	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

// argsPolicy allows every nmap flag except the classes below.
var argsPolicy = policy.OpenPolicy{
	Denied: policy.Deny(map[policy.Class][]string{
		// Output goes where the runner says. -oX - is pinned in buildArgs;
		// a caller-named path is an arbitrary write.
		policy.ClassFileWrite: {
			"-oN", "-oX", "-oG", "-oA", "-oS",
			"--append-output", "--stylesheet", "--webxml", "--resume",
		},
		// Every one of these reads a path the caller chose.
		policy.ClassFileRead: {
			"-iL", "--excludefile", "--datadir", "--servicedb", "--versiondb",
			"--script-args-file",
		},
		// NSE is arbitrary code with nmap's privileges.
		policy.ClassCodeExec: {
			"--script", "--script-args", "--script-help",
			"--script-trace", "--script-updatedb",
		},
		// These make a machine other than the declared target a participant:
		// a forged source, a decoy, an FTP bounce, an idle zombie, or -iR,
		// which picks victims at random off the internet.
		policy.ClassThirdParty: {
			"-S", "-D", "-b", "-sI", "-iR", "--proxies", "--spoof-mac",
			"-e", "--dns-servers", "--exclude",
		},
		// Packet forging and privilege changes escape the posture the run
		// was dispatched under.
		policy.ClassRawForge: {
			"--send-eth", "--send-ip", "--scanflags", "--data", "--data-string",
			"--data-length", "--ip-options", "--ttl", "--badsum", "--mtu", "-f",
			"--privileged", "--unprivileged",
		},
	}),
	// Value-bearing flags keep their shape checks. PortSpec is what stops a
	// `-p` slot carrying a path; it also guards the "ports" option, which
	// routes through ApplyOption and still requires a validator.
	Validators: policy.ArgsPolicy{
		"-p":             policy.PortSpec,
		"--top-ports":    policy.Numeric,
		"--max-retries":  policy.Numeric,
		"--max-rate":     policy.Numeric,
		"--min-rate":     policy.Numeric,
		"--host-timeout": policy.AllowAny,
	},
}

func init() {
	registry.RegisterOpenArgsPolicy(toolName, argsPolicy)
	// nmap's documented target syntax: an IP address, a CIDR prefix, or
	// a hostname. Anything else is not a scan subject.
	registry.RegisterTargetPolicy(toolName, policy.TargetNetwork)
}
