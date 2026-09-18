// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package policy

import (
	"strings"
	"testing"
)

// The deny set is keyed on the bare flag. getopt_long accepts `--flag=value`
// and getopt accepts `-Xvalue`, so a policy that looked the whole token up
// let `--script=http-vuln` through as an unknown, allowed flag. These are
// the fixtures for that gap, on both postures.

func openFixture() OpenPolicy {
	return OpenPolicy{
		Denied: Deny(map[Class][]string{
			ClassCodeExec:   {"--script", "--script-args"},
			ClassFileWrite:  {"-oN"},
			ClassFileRead:   {"--datadir"},
			ClassThirdParty: {"-S", "-sI", "--proxies"},
		}),
		Validators: ArgsPolicy{
			"-p":          PortSpec,
			"--top-ports": Numeric,
		},
	}
}

func TestApplyOpen_AttachedValueCannotHideADeniedFlag(t *testing.T) {
	cases := []struct {
		name string
		args []string
		flag string // the flag the policy must report as dropped
	}{
		// THE FIXTURE THIS EXISTS FOR.
		{"long option with =", []string{"--script=http-vuln"}, "--script"},
		{"long option, empty value", []string{"--script="}, "--script"},
		{"file read with =", []string{"--datadir=/tmp/evil"}, "--datadir"},
		{"third party with =", []string{"--proxies=socks4://10.0.0.1:1080"}, "--proxies"},
		{"short option, attached path", []string{"-oN/etc/passwd"}, "-oN"},
		{"short option, attached address", []string{"-S10.0.0.1"}, "-S"},
		{"three-letter short option, attached", []string{"-sI10.0.0.1"}, "-sI"},
		{"spaced form still dropped", []string{"--script", "http-vuln"}, "--script"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, dropped, err := ApplyOpen(tc.args, openFixture())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(out) != 0 {
				t.Fatalf("argv must be empty, got %v", out)
			}
			if len(dropped) != 1 || dropped[0].Flag != tc.flag {
				t.Fatalf("want exactly %q dropped, got %+v", tc.flag, dropped)
			}
			if dropped[0].Reason == "" {
				t.Fatalf("a dropped flag must carry its class")
			}
		})
	}
}

func TestApplyOpen_AttachedValueIsValidatedLikeASpacedOne(t *testing.T) {
	good := [][]string{{"--top-ports=10"}, {"-p80"}, {"-p1-1024"}}
	for _, args := range good {
		out, dropped, err := ApplyOpen(args, openFixture())
		if err != nil || len(dropped) != 0 {
			t.Fatalf("%v: err=%v dropped=%+v", args, err, dropped)
		}
		if len(out) != 1 || out[0] != args[0] {
			t.Fatalf("%v: a validated attached value keeps its shape, got %v", args, out)
		}
	}
	bad := [][]string{{"--top-ports=abc"}, {"-p/etc/passwd"}, {"--top-ports="}}
	for _, args := range bad {
		if _, _, err := ApplyOpen(args, openFixture()); err == nil {
			t.Fatalf("%v: the validator must reject the attached value", args)
		}
	}
}

func TestApplyOpen_UnknownShortTokensStayWhole(t *testing.T) {
	// -sS is one flag nmap spells that way; -S is denied, -s is not a key.
	out, dropped, err := ApplyOpen([]string{"-sS", "-Pn", "--open"}, openFixture())
	if err != nil || len(dropped) != 0 {
		t.Fatalf("err=%v dropped=%+v", err, dropped)
	}
	if strings.Join(out, " ") != "-sS -Pn --open" {
		t.Fatalf("got %v", out)
	}
}

func TestApplyArgs_AttachedValueMeetsTheAllowlist(t *testing.T) {
	p := ArgsPolicy{"-p": PortSpec, "-sV": nil, "--top-ports": Numeric}

	// A flag outside the allowlist is dropped whatever its shape.
	for _, args := range [][]string{{"--script=http-vuln"}, {"-oN/tmp/x"}} {
		out, dropped, err := ApplyArgs(args, p)
		if err != nil || len(out) != 0 || len(dropped) != 1 {
			t.Fatalf("%v: out=%v dropped=%+v err=%v", args, out, dropped, err)
		}
	}
	// A boolean flag has no value slot; an attached value drops the token.
	out, dropped, err := ApplyArgs([]string{"-sV=1"}, p)
	if err != nil || len(out) != 0 || len(dropped) != 1 || dropped[0].Flag != "-sV" {
		t.Fatalf("boolean with attached value: out=%v dropped=%+v err=%v", out, dropped, err)
	}
	// A validated flag keeps its attached value when the value passes.
	out, dropped, err = ApplyArgs([]string{"--top-ports=5"}, p)
	if err != nil || len(dropped) != 0 || strings.Join(out, " ") != "--top-ports=5" {
		t.Fatalf("out=%v dropped=%+v err=%v", out, dropped, err)
	}
	// Go-style parsers spell attached values only as `-flag=value`, and the
	// allowlist never splits `-Xvalue`: an unknown token is dropped anyway.
	out, dropped, err = ApplyArgs([]string{"-p=80", "-p443"}, p)
	if err != nil || strings.Join(out, " ") != "-p=80" || len(dropped) != 1 || dropped[0].Flag != "-p443" {
		t.Fatalf("out=%v dropped=%+v err=%v", out, dropped, err)
	}
	// A single-dash long flag is one flag, never a short flag with a value.
	out, dropped, err = ApplyArgs([]string{"-severity=high"}, ArgsPolicy{"-s": AllowAny, "-severity": AllowAny})
	if err != nil || strings.Join(out, " ") != "-severity=high" || len(dropped) != 0 {
		t.Fatalf("out=%v dropped=%+v err=%v", out, dropped, err)
	}
}

func TestSplitInline(t *testing.T) {
	known := func(f string) bool { return f == "-p" || f == "-sI" || f == "-oN" }
	cases := []struct {
		tok, flag, value string
		inline           bool
		short            bool
	}{
		{"--script=x", "--script", "x", true, true},
		{"--script", "--script", "", false, true},
		{"--a=b=c", "--a", "b=c", true, true},
		{"--=x", "--=x", "", false, true},
		{"-=x", "-=x", "", false, true},
		{"-t=x", "-t", "x", true, false},
		{"-p80", "-p", "80", true, true},
		{"-p80", "-p80", "", false, false},
		{"-p", "-p", "", false, true},
		{"-sI1.2.3.4", "-sI", "1.2.3.4", true, true},
		{"-sS", "-sS", "", false, true},
		{"-severity", "-severity", "", false, false},
		{"-oN/etc/passwd", "-oN", "/etc/passwd", true, true},
	}
	for _, tc := range cases {
		f, v, in := splitInline(tc.tok, known, tc.short)
		if f != tc.flag || v != tc.value || in != tc.inline {
			t.Errorf("%q: got (%q,%q,%v) want (%q,%q,%v)", tc.tok, f, v, in, tc.flag, tc.value, tc.inline)
		}
	}
}
