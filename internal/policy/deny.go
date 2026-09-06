// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Capability-class deny policy: the inverted posture.
//
// The allowlist in policy.go enumerates every permitted flag by name. That
// is sound but unbounded: a scanner has O(100) flags, the list goes stale on
// every upstream release, and a missing entry looks like a broken product
// rather than a policy decision. nmap 7.93 documents 158 flags; the authored
// allowlist covered 26, and the first flag a real mission needed
// (--stats-every, the progress printer) was not among them — nor is it even
// in `nmap -h`.
//
// The inversion: allow by default, deny by CAPABILITY CLASS. The classes are
// few, stable and tool-independent, so a tool onboards by naming which of its
// flags fall in each class rather than by transcribing its whole manual.
//
// This is safe because the flag policy was never what stopped a shell escape.
// Every parser executes its tool as exec.CommandContext(ctx, bin, args...) —
// argv, never a shell — so no argument can ever be interpreted as a command.
// The argv is further bounded by three structural guards the policy does not
// control: the runner pins its own output flag, appends "--" before the
// target so getopt cannot re-read it as a flag, and runs inside a gVisor
// microVM whose egress is the manifest's declared allowlist. The flag policy
// defends against the TOOL'S OWN dangerous features, not against the shell.

package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Class names one reason a flag is refused. The set is deliberately small:
// these are the ways a scanner flag can hurt something outside its sandbox.
type Class string

const (
	// ClassFileWrite — the flag writes a file the CALLER names. Arbitrary
	// write inside the sandbox, and the path may escape the tempdir.
	ClassFileWrite Class = "writes a caller-named file"
	// ClassFileRead — the flag reads a file the CALLER names, which turns
	// the tool into an exfiltration primitive for anything in the image.
	ClassFileRead Class = "reads a caller-named file"
	// ClassCodeExec — the flag runs scripts or plugins. Arbitrary code with
	// the tool's privileges, defeating every other argument check.
	ClassCodeExec Class = "executes caller-supplied scripts or plugins"
	// ClassThirdParty — the flag makes some machine OTHER than the declared
	// target a participant: spoofed source, decoy, bounce host, idle zombie,
	// random targets. The blast radius leaves the engagement.
	ClassThirdParty Class = "involves a machine other than the declared target"
	// ClassRawForge — the flag forges packets or changes the process's
	// privilege posture, which is how a run escapes the isolation it was
	// dispatched under.
	ClassRawForge Class = "forges packets or alters privilege"
)

// DenySet maps a flag to the class that refuses it.
type DenySet map[string]Class

// Deny builds a DenySet from per-class flag lists. Listing a flag twice in
// one call is a policy-authoring bug and panics at init, which is when a
// parser's policy file is loaded.
func Deny(byClass map[Class][]string) DenySet {
	out := DenySet{}
	for class, flags := range byClass {
		for _, f := range flags {
			if prior, dup := out[f]; dup {
				panic(fmt.Sprintf(
					"policy.Deny: flag %q listed under both %q and %q", f, prior, class))
			}
			out[f] = class
		}
	}
	return out
}

// OpenPolicy allows any flag the tool accepts except those in Denied.
// Validators still applies to the flags it names, so a value-bearing flag
// (a port spec, a rate) keeps its shape check; a flag with no entry is
// treated as boolean-or-free-form and passed through.
//
// A tool adopting OpenPolicy accepts that an unknown-but-harmful upstream
// flag is allowed until someone classifies it. That is the deliberate trade:
// the alternative is a list that silently breaks correct missions on every
// tool release, which is the failure this replaces.
type OpenPolicy struct {
	Denied     DenySet
	Validators ArgsPolicy
}

// decide reports whether a flag may reach the argv and which validator, if
// any, constrains its value. denyClass names the capability class that
// rejected the flag, and is empty when allowed is true.
func (o OpenPolicy) decide(flag string) (v Validator, allowed bool, denyClass string) {
	if class, denied := o.Denied[flag]; denied {
		return nil, false, string(class)
	}
	if val, ok := o.Validators[flag]; ok {
		return val, true, ""
	}
	return nil, true, ""
}

// DeniedFlags lists the refused flags in sorted order, for tests and docs.
func (o OpenPolicy) DeniedFlags() []string {
	out := make([]string, 0, len(o.Denied))
	for f := range o.Denied {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// ApplyOpen is ApplyArgs for the inverted posture. It shares the paired-value
// handling so an open tool and an allowlisted tool build argv the same way.
func ApplyOpen(args []string, o OpenPolicy) ([]string, []DroppedFlag, error) {
	out := make([]string, 0, len(args))
	var dropped []DroppedFlag

	for i := 0; i < len(args); i++ {
		tok := args[i]
		if !strings.HasPrefix(tok, "-") {
			dropped = append(dropped, DroppedFlag{
				Flag:   tok,
				Reason: "stray positional token; use req.Target for the scan subject",
			})
			continue
		}

		var value string
		hasValue := false
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			value = args[i+1]
			hasValue = true
		}

		validator, allowed, reason := o.decide(tok)
		if !allowed {
			dropped = append(dropped, DroppedFlag{Flag: tok, Value: value, Reason: reason})
			if hasValue {
				i++
			}
			continue
		}

		// No validator: the flag is boolean or free-form. A paired value is
		// emitted with it, because an open policy cannot know which flags
		// take values — dropping the value would silently change the run.
		if validator == nil {
			out = append(out, tok)
			if hasValue {
				out = append(out, value)
				i++
			}
			continue
		}
		if !hasValue {
			return nil, dropped, fmt.Errorf("flag %q requires a value but none was provided", tok)
		}
		if err := validator(value); err != nil {
			return nil, dropped, fmt.Errorf("flag %q value rejected: %w", tok, err)
		}
		out = append(out, tok, value)
		i++
	}
	return out, dropped, nil
}
