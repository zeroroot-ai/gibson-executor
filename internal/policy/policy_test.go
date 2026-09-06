// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package policy

import (
	"strings"
	"testing"
)

func TestApplyArgs_NilPolicy_DeniesEverything(t *testing.T) {
	args := []string{"-sV", "--scripts", "vuln"}
	out, dropped, err := ApplyArgs(args, nil)
	if err != nil {
		t.Fatalf("unexpected validator error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected zero allowed args, got %v", out)
	}
	if len(dropped) != 2 {
		t.Fatalf("expected 2 dropped flags, got %d (%v)", len(dropped), dropped)
	}
	if dropped[0].Flag != "-sV" || dropped[1].Flag != "--scripts" {
		t.Fatalf("unexpected dropped flags: %+v", dropped)
	}
}

func TestApplyArgs_AllowsListedFlag(t *testing.T) {
	policy := ArgsPolicy{"-sV": nil}
	out, dropped, err := ApplyArgs([]string{"-sV"}, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("expected 0 dropped, got %v", dropped)
	}
	if len(out) != 1 || out[0] != "-sV" {
		t.Fatalf("expected [-sV], got %v", out)
	}
}

func TestApplyArgs_DropsUnknownFlag_WithValue(t *testing.T) {
	policy := ArgsPolicy{"-sV": nil}
	out, dropped, err := ApplyArgs([]string{"-oN", "/etc/passwd", "-sV"}, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 || out[0] != "-sV" {
		t.Fatalf("expected only [-sV], got %v", out)
	}
	if len(dropped) != 1 {
		t.Fatalf("expected 1 dropped, got %d", len(dropped))
	}
	if dropped[0].Flag != "-oN" || dropped[0].Value != "/etc/passwd" {
		t.Fatalf("expected -oN /etc/passwd dropped, got %+v", dropped[0])
	}
	if !strings.Contains(dropped[0].Reason, "allowlist") {
		t.Fatalf("expected reason to mention allowlist, got %q", dropped[0].Reason)
	}
}

func TestApplyArgs_ValidatorErrorReturnsError(t *testing.T) {
	policy := ArgsPolicy{
		"--severity": AllowEnum("low", "medium", "high"),
	}
	_, _, err := ApplyArgs([]string{"--severity", "critical"}, policy)
	if err == nil {
		t.Fatal("expected validator error, got nil")
	}
	if !strings.Contains(err.Error(), "--severity") {
		t.Fatalf("expected error to mention --severity, got %v", err)
	}
}

func TestApplyArgs_StrayPositional_Dropped(t *testing.T) {
	policy := ArgsPolicy{"-sV": nil}
	_, dropped, err := ApplyArgs([]string{"hello", "-sV"}, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Flag != "hello" {
		t.Fatalf("expected hello dropped, got %v", dropped)
	}
}

func TestApplyArgs_PathUnder_RejectsTraversal(t *testing.T) {
	policy := ArgsPolicy{"-oN": PathUnder("/runner/tmp/")}
	_, _, err := ApplyArgs([]string{"-oN", "/runner/tmp/../etc/passwd"}, policy)
	if err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestApplyArgs_PathUnder_RejectsOutsidePrefix(t *testing.T) {
	policy := ArgsPolicy{"-oN": PathUnder("/runner/tmp/")}
	_, _, err := ApplyArgs([]string{"-oN", "/etc/passwd"}, policy)
	if err == nil {
		t.Fatal("expected outside-prefix rejection")
	}
}

func TestApplyArgs_PathUnder_AllowsWithinPrefix(t *testing.T) {
	policy := ArgsPolicy{"-oN": PathUnder("/runner/tmp/")}
	out, dropped, err := ApplyArgs([]string{"-oN", "/runner/tmp/output.txt"}, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("expected 0 dropped, got %v", dropped)
	}
	if len(out) != 2 || out[0] != "-oN" || out[1] != "/runner/tmp/output.txt" {
		t.Fatalf("expected -oN /runner/tmp/output.txt, got %v", out)
	}
}

func TestAllowEnum_Behavior(t *testing.T) {
	v := AllowEnum("alpha", "beta")
	if err := v("alpha"); err != nil {
		t.Fatalf("alpha should pass: %v", err)
	}
	if err := v("gamma"); err == nil {
		t.Fatal("gamma should fail")
	}
}

func TestAllowAny_RejectsEmpty(t *testing.T) {
	if err := AllowAny(""); err == nil {
		t.Fatal("empty should fail")
	}
	if err := AllowAny("anything"); err != nil {
		t.Fatalf("nonempty should pass: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Options are the second door into the argv. These pin that they cannot be
// opened on softer terms than req.Args.
// ---------------------------------------------------------------------------

func TestApplyOption(t *testing.T) {
	p := ArgsPolicy{
		"-p":        PortSpec,
		"-severity": AllowCSVEnum("low", "high"),
		"-sV":       nil, // boolean flag
	}

	cases := []struct {
		name    string
		flag    string
		value   string
		wantOK  bool
		wantOut []string
	}{
		{"allowlisted flag with valid value", "-p", "22,80,443", true, []string{"-p", "22,80,443"}},
		{"csv enum", "-severity", "low,high", true, []string{"-severity", "low,high"}},

		// The bypass the advisory names: an option reaching a flag the
		// allowlist never granted.
		{"flag absent from allowlist", "-oN", "/etc/passwd", false, nil},
		{"template flag absent from allowlist", "-t", "/tmp/evil", false, nil},

		// A value that is itself a flag. ApplyArgs can never pair one
		// (it reads a dash-leading token as the next flag), so the option
		// path must not either.
		{"value introduces a flag", "-p", "-oN", false, nil},
		{"value introduces a long flag", "-p", "--script=http-vuln", false, nil},

		// A boolean flag takes no value; pairing one puts an unvalidated
		// token on the argv.
		{"value for a boolean flag", "-sV", "/etc/passwd", false, nil},

		// The registered validator still runs.
		{"validator rejects value", "-p", "/etc/passwd", false, nil},
		{"csv enum rejects unknown element", "-severity", "low,critical", false, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ApplyOption(p, tc.flag, tc.value)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("ApplyOption(%q, %q) = %v; want accepted", tc.flag, tc.value, err)
				}
				if len(out) != len(tc.wantOut) {
					t.Fatalf("out = %v; want %v", out, tc.wantOut)
				}
				for i := range out {
					if out[i] != tc.wantOut[i] {
						t.Fatalf("out = %v; want %v", out, tc.wantOut)
					}
				}
				return
			}
			if err == nil {
				t.Fatalf("ApplyOption(%q, %q) = %v; want rejected", tc.flag, tc.value, out)
			}
		})
	}
}

// TestApplyOption_NilPolicyDeniesEverything pins the fail-closed default:
// a tool that registered no allowlist gets no options either.
func TestApplyOption_NilPolicyDeniesEverything(t *testing.T) {
	if _, err := ApplyOption(nil, "-p", "80"); err == nil {
		t.Fatal("nil policy accepted an option")
	}
}

// TestApplyArgs_BooleanFlagDoesNotConsumeValue pins that a nil-validator
// (boolean) flag never drags the following token onto the argv. Before
// this, `-sV /etc/passwd` emitted both, which handed nmap a second scan
// target through a flag that takes no value at all.
func TestApplyArgs_BooleanFlagDoesNotConsumeValue(t *testing.T) {
	p := ArgsPolicy{"-sV": nil}
	out, dropped, err := ApplyArgs([]string{"-sV", "/etc/passwd"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 || out[0] != "-sV" {
		t.Fatalf("out = %v; want [-sV] only", out)
	}
	if len(dropped) != 1 || dropped[0].Flag != "/etc/passwd" {
		t.Fatalf("expected /etc/passwd dropped as a stray positional, got %+v", dropped)
	}
}

func TestPortSpec(t *testing.T) {
	for _, ok := range []string{"80", "22,80,443", "1-1024", "U:53,T:80", "1-65535"} {
		if err := PortSpec(ok); err != nil {
			t.Errorf("PortSpec(%q) = %v; want accepted", ok, err)
		}
	}
	for _, bad := range []string{"", "/etc/passwd", "80;id", "80 443", "abc", "80\n443"} {
		if err := PortSpec(bad); err == nil {
			t.Errorf("PortSpec(%q) accepted; want rejected", bad)
		}
	}
}

func TestNumeric(t *testing.T) {
	if err := Numeric("1000"); err != nil {
		t.Errorf("Numeric(1000) = %v; want accepted", err)
	}
	for _, bad := range []string{"", "1000x", "-1", "1e3", "10.5"} {
		if err := Numeric(bad); err == nil {
			t.Errorf("Numeric(%q) accepted; want rejected", bad)
		}
	}
}
