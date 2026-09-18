// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package policy

import (
	"strings"
	"testing"
)

// A denied flag's value slot must not become a way to introduce a flag. The
// old rule consumed the next token only when it did not start with "-", so
// `--script -sS` dropped --script and then let -sS through as a flag of its
// own. These are the fixtures for that gap.
func TestApplyOpen_DeniedFlagTakesItsValueEvenWhenItLooksLikeAFlag(t *testing.T) {
	t.Parallel()
	p := openFixture()

	cases := []struct {
		name    string
		args    []string
		wantOut string
		wantVal string // value recorded on the first dropped flag
	}{
		{name: "value starting with dash is consumed", args: []string{"--script", "-sS", "-p", "80"}, wantOut: "-p 80", wantVal: "-sS"},
		{name: "plain value is consumed", args: []string{"--script", "http-vuln", "-p", "80"}, wantOut: "-p 80", wantVal: "http-vuln"},
		{name: "a following denied flag is not a value", args: []string{"--script", "-oN", "out", "-p", "80"}, wantOut: "-p 80", wantVal: ""},
		{name: "a following validated flag is not a value", args: []string{"--script", "-p", "80"}, wantOut: "-p 80", wantVal: ""},
		{name: "a following validated flag with attached value is not a value", args: []string{"--script", "-p80"}, wantOut: "-p80", wantVal: ""},
		{name: "inline value never consumes the next token", args: []string{"--script=x", "-sS"}, wantOut: "-sS", wantVal: "x"},
		{name: "denied flag at the end", args: []string{"-p", "80", "--script"}, wantOut: "-p 80", wantVal: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, dropped, err := ApplyOpen(tc.args, p)
			if err != nil {
				t.Fatalf("ApplyOpen: %v", err)
			}
			if got := strings.Join(out, " "); got != tc.wantOut {
				t.Fatalf("argv = %q, want %q (dropped %+v)", got, tc.wantOut, dropped)
			}
			if len(dropped) == 0 {
				t.Fatal("want at least one dropped flag")
			}
			if dropped[0].Value != tc.wantVal {
				t.Fatalf("dropped[0] = %+v, want value %q", dropped[0], tc.wantVal)
			}
			for _, o := range out {
				if o == "-sS" && tc.name != "inline value never consumes the next token" {
					t.Fatalf("-sS leaked into argv: %q", out)
				}
			}
		})
	}
}
