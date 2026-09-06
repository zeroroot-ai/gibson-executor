// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package policy implements the per-tool args allowlist enforced by every
// parser before appending caller-supplied req.Args to the underlying CLI's
// argv. The threat model is multi-tenant: req.Args is potentially hostile
// because it crosses a trust boundary from the daemon's mission planner
// down to a long-running tool process running with elevated capabilities
// (raw sockets for nmap/masscan/naabu, network egress for httpx/nuclei).
//
// Without a policy, an attacker who controls the mission spec can pass
// flags like `-oN /etc/passwd` (nmap), `--templates /tmp/malicious/`
// (nuclei), or `-output /var/lib/secrets/...` to coerce the tool into
// writing to or reading from an arbitrary path inside the runner pod.
//
// The policy contract:
//
//   - Every tool registers an ArgsPolicy (a map of allowed flag names to
//     a per-flag value validator). A nil ArgsPolicy means "no flags
//     allowed" — the strictest default. Output-file flags (`-oN`, `-oX`,
//     `-output`, etc.) MUST be denied unless the validator constrains
//     the value to a tool-runner-managed tempdir.
//
//   - At dispatch, the parser calls policy.ApplyArgs(req.Args, registered)
//     which returns the filtered argv plus a slice of dropped flags. The
//     parser logs each dropped flag at the structured event "tool.flag.denied"
//     (with the offending flag and reason) and either continues with the
//     allowlisted subset (default) or fails with InvalidArgument when a
//     value-validator fails — that is a "deliberate misuse" signal worth
//     a hard error rather than a silent drop.
//
//   - Adding a new tool means adding a per-tool policy file (the parser
//     package's policy.go) that lists the safe flags from the tool's
//     official documentation and any per-flag validators. Wildcards are
//     forbidden — every allowed flag must be enumerated by name.
package policy

import (
	"fmt"
	"strings"
)

// Validator is a per-flag value validator. Return nil to accept the
// supplied value, or an error to reject it (the parser will surface this
// as InvalidArgument). A nil Validator means "any non-empty value is
// acceptable" — used for boolean-style flags whose value is implicit.
type Validator func(value string) error

// ArgsPolicy maps an allowed flag name (with the leading dash, e.g. "-sV"
// or "--templates") to its value validator. Flag presence alone is not a
// signal of intent — the validator decides whether the value is OK. A
// nil map means "deny every flag" (the safest default for tools whose
// allowlist hasn't been authored yet).
type ArgsPolicy map[string]Validator

// DroppedFlag captures one rejection event so the parser can log it.
type DroppedFlag struct {
	// Flag is the offending flag name as it appeared in req.Args.
	Flag string
	// Value is the value the caller paired with the flag. Empty when
	// the flag arrived without a paired value (boolean form).
	Value string
	// Reason explains why the flag was dropped. Always non-empty.
	Reason string
}

// ApplyArgs filters req.Args against the policy.  It walks the args
// pairwise: if the current token is a flag (begins with "-") it consults
// the policy; if the next token is the flag's value (does not itself
// begin with "-") that pair is consumed.  Unrecognised flags are dropped
// and reported via the returned []DroppedFlag.  A flag whose validator
// rejects its value is reported as a hard error: callers should surface
// this as gRPC InvalidArgument rather than silently swallow it.
//
// The first return value is the filtered args (what to actually pass to
// the underlying CLI). The second is the list of dropped flags for
// structured logging. The third is a non-nil error iff a validator
// rejected a value.
func ApplyArgs(args []string, p ArgsPolicy) ([]string, []DroppedFlag, error) {
	out := make([]string, 0, len(args))
	var dropped []DroppedFlag

	for i := 0; i < len(args); i++ {
		tok := args[i]
		if !strings.HasPrefix(tok, "-") {
			// Positional value with no preceding flag — treat as a
			// stray arg and drop it. Tools whose contract demands
			// positional args feed the target via req.Target, not
			// req.Args.
			dropped = append(dropped, DroppedFlag{
				Flag:   tok,
				Reason: "stray positional token; use req.Target for the scan subject",
			})
			continue
		}

		// Detect the paired value (if any). If the next token starts
		// with "-" we treat it as a separate flag.
		var value string
		hasValue := false
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			value = args[i+1]
			hasValue = true
		}

		// Disallow unknown flags before consulting the validator —
		// nil-policy short-circuits here so unauthored tools deny by default.
		validator, allowed := lookup(p, tok)
		if !allowed {
			dropped = append(dropped, DroppedFlag{
				Flag:   tok,
				Value:  value,
				Reason: "flag not in tool allowlist",
			})
			if hasValue {
				i++ // consume the paired value too
			}
			continue
		}

		// A nil validator means the flag is boolean: it takes no value.
		// Never pair a token with it — the token would ride onto the argv
		// unvalidated and land as a stray positional (an extra scan
		// target, an output path). Emit the flag alone and let the next
		// loop iteration drop the token as a stray positional.
		if validator == nil {
			out = append(out, tok)
			continue
		}

		if !hasValue {
			return nil, dropped, fmt.Errorf(
				"flag %q requires a value but none was provided", tok)
		}
		if err := validator(value); err != nil {
			return nil, dropped, fmt.Errorf(
				"flag %q value rejected: %w", tok, err)
		}

		// Allow the flag and its validated value.
		out = append(out, tok, value)
		i++
	}

	return out, dropped, nil
}

// ApplyOption resolves one caller-supplied req.Options entry to a
// (flag, value) argv pair, enforcing the SAME allowlist and validator the
// equivalent req.Args flag would hit.
//
// Options were the second door into the argv. A parser that writes
// `args = append(args, "-p", req.Options["ports"])` hands the caller an
// unvalidated argv slot for a flag the policy may not even allow — nuclei's
// own policy file denies `-t` while its parser piped req.Options["templates"]
// straight into `-t`. Routing every option through here means an option can
// never reach argv on softer terms than a flag would.
//
// Three rules, all fail-closed:
//
//   - The flag must be in the tool's allowlist. No allowlist entry, no argv.
//   - The flag's validator must be non-nil. A nil validator means the flag
//     is boolean; pairing a value with it would put an unvalidated token on
//     the argv, so an option targeting a boolean flag is rejected outright.
//   - The value must not begin with "-". ApplyArgs can never pair a
//     dash-leading value (it treats such a token as the next flag), so
//     accepting one here would make Options strictly weaker than Args.
func ApplyOption(p ArgsPolicy, flag, value string) ([]string, error) {
	validator, allowed := lookup(p, flag)
	if !allowed {
		return nil, fmt.Errorf("option flag %q is not in the tool allowlist", flag)
	}
	if validator == nil {
		return nil, fmt.Errorf("option flag %q is boolean and takes no value", flag)
	}
	if strings.HasPrefix(value, "-") {
		return nil, fmt.Errorf(
			"option flag %q value begins with %q, which the tool would parse as a flag", flag, "-")
	}
	if err := validator(value); err != nil {
		return nil, fmt.Errorf("option flag %q value rejected: %w", flag, err)
	}
	return []string{flag, value}, nil
}

// lookup returns the validator for a flag in the policy, plus an "allowed"
// boolean. A nil policy denies every flag.
func lookup(p ArgsPolicy, flag string) (Validator, bool) {
	if p == nil {
		return nil, false
	}
	v, ok := p[flag]
	return v, ok
}

// AllowAny is a Validator that accepts any non-empty value. Use sparingly:
// most flags should have a stricter validator constraining the value's
// shape (a port range, a hostname, a path under a tempdir).
func AllowAny(value string) error {
	if value == "" {
		return fmt.Errorf("value must be non-empty")
	}
	return nil
}

// ImageRef is a Validator that accepts one OCI image reference in the same
// syntax TargetImageRef accepts for a scan subject:
//
//	[registry[:port]/]name[/name...][:tag][@algo:hex]
//
// Use it for flags whose value names a registry artefact rather than the
// scan subject, e.g. trivy's `--db-repository`, so an air-gapped operator
// can point the scanner at a mirrored database without the flag opening a
// path, a URL or a host to the caller.
func ImageRef(value string) error {
	return validateImageRef(value)
}

// AllowEnum returns a Validator that accepts only the listed exact-match
// values. Use for flags whose values are drawn from a fixed set
// (e.g. nmap's `-T0..-T5` levels or nuclei's `-severity` enums).
func AllowEnum(allowed ...string) Validator {
	set := make(map[string]struct{}, len(allowed))
	for _, v := range allowed {
		set[v] = struct{}{}
	}
	return func(value string) error {
		if _, ok := set[value]; !ok {
			return fmt.Errorf("value %q not in allowed set", value)
		}
		return nil
	}
}

// AllowCSVEnum returns a Validator that accepts a comma-separated list
// whose every element is in the allowed set. Use for filter flags that
// take several values at once, e.g. nuclei's `-severity critical,high`.
func AllowCSVEnum(allowed ...string) Validator {
	element := AllowEnum(allowed...)
	return func(value string) error {
		if value == "" {
			return fmt.Errorf("value must be non-empty")
		}
		for _, part := range strings.Split(value, ",") {
			if err := element(strings.TrimSpace(part)); err != nil {
				return err
			}
		}
		return nil
	}
}

// PortSpec is a Validator for a port specification: digits, commas,
// hyphen ranges, and the protocol qualifiers nmap accepts (`T:`, `U:`,
// `S:`, `P:`). It exists so a `-p` value cannot smuggle a path, a shell
// metacharacter, or anything else the tool might reinterpret.
func PortSpec(value string) error {
	if value == "" {
		return fmt.Errorf("port spec must be non-empty")
	}
	if len(value) > 512 {
		return fmt.Errorf("port spec is %d bytes; limit is 512", len(value))
	}
	digits := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= '0' && c <= '9':
			digits = true
		case c == ',', c == '-', c == ':', c == 'T', c == 'U', c == 'S', c == 'P':
		default:
			return fmt.Errorf("port spec %q contains a disallowed character", value)
		}
	}
	if !digits {
		return fmt.Errorf("port spec %q contains no port number", value)
	}
	return nil
}

// Numeric is a Validator for a bare non-negative integer — rates, retry
// counts, thread counts. Anything non-numeric in such a flag is either a
// caller bug or an attempt to reach a slot the flag was never meant to
// carry.
func Numeric(value string) error {
	if value == "" {
		return fmt.Errorf("value must be non-empty")
	}
	if len(value) > 20 {
		return fmt.Errorf("numeric value is %d digits; limit is 20", len(value))
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return fmt.Errorf("value %q is not a non-negative integer", value)
		}
	}
	return nil
}

// PathUnder returns a Validator that requires the value to be a clean
// path below the supplied prefix. The prefix is typically the
// tool-runner's per-invocation tempdir, set by the runner harness in
// req.Options. Use for output-file flags (`-oN`, `-oX`, `-output`,
// `--templates`) so callers can never coerce a write or read outside
// the tempdir.
func PathUnder(prefix string) Validator {
	return func(value string) error {
		if value == "" {
			return fmt.Errorf("path must be non-empty")
		}
		// Reject path-traversal attempts and absolute paths that aren't
		// under the prefix.
		if strings.Contains(value, "..") {
			return fmt.Errorf("path %q contains '..' traversal", value)
		}
		if !strings.HasPrefix(value, prefix) {
			return fmt.Errorf("path %q is not under tempdir %q", value, prefix)
		}
		return nil
	}
}
