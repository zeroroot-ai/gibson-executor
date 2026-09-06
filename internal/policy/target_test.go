// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package policy

import (
	"strings"
	"testing"
)

func TestValidateTarget(t *testing.T) {
	cases := []struct {
		name   string
		target string
		kinds  TargetKind
		wantOK bool
	}{
		// --- the shapes this validator exists to reject ---------------
		{"leading dash reads as a flag", "-oN", TargetNetwork, false},
		{"leading dash with value", "-oN/etc/passwd", TargetNetwork, false},
		{"leading double dash", "--script=http-vuln", TargetNetwork, false},
		{"newline appends a second target", "example.com\nevil.com", TargetHost, false},
		{"carriage return", "example.com\revil.com", TargetHost, false},
		{"NUL byte", "example.com\x00", TargetHost, false},
		{"tab", "example.com\tevil.com", TargetHost, false},
		{"space splits the token", "example.com evil.com", TargetHost, false},
		{"non-breaking space", "example.com evil.com", TargetHost, false},
		{"empty", "", TargetNetwork, false},
		{"no kind permitted", "10.0.0.1", 0, false},
		{"oversized", strings.Repeat("a", maxTargetLen+1), TargetHost, false},

		// --- IP ------------------------------------------------------
		{"ipv4", "192.168.1.1", TargetNetwork, true},
		{"ipv6", "2001:db8::1", TargetNetwork, true},
		{"ipv6 with zone", "fe80::1%eth0", TargetNetwork, false},
		{"ip when only hostname permitted", "192.168.1.1", TargetHostname, false},

		// --- CIDR ----------------------------------------------------
		{"ipv4 cidr", "10.0.0.0/24", TargetNetwork, true},
		{"ipv6 cidr", "2001:db8::/32", TargetNetwork, true},
		{"cidr when not permitted", "10.0.0.0/24", TargetHost, false},
		{"bad prefix length", "10.0.0.0/64", TargetNetwork, false},
		{"path masquerading as cidr", "10.0.0.0/etc/passwd", TargetNetwork, false},

		// --- hostname ------------------------------------------------
		{"hostname", "scanme.nmap.org", TargetNetwork, true},
		{"single label", "localhost", TargetHost, true},
		{"trailing dot", "example.com.", TargetHost, true},
		{"leading hyphen label", "example.-evil.com", TargetHost, false},
		{"trailing hyphen label", "evil-.example.com", TargetHost, false},
		{"empty label", "example..com", TargetHost, false},
		{"underscore", "ex_ample.com", TargetHost, false},
		{"shell metacharacter", "example.com;id", TargetHost, false},
		{"all-numeric final label", "1.2.3.4.5", TargetHost, false},
		{"oversized label", strings.Repeat("a", 64) + ".com", TargetHost, false},

		// --- URL -----------------------------------------------------
		{"https url", "https://example.com/api", TargetWeb, true},
		{"http url with port", "http://example.com:8443/", TargetWeb, true},
		{"url to ip", "http://10.0.0.1/", TargetWeb, true},
		{"url when not permitted", "https://example.com", TargetNetwork, false},
		{"file scheme", "file:///etc/passwd", TargetWeb, false},
		{"gopher scheme", "gopher://example.com", TargetWeb, false},
		{"userinfo", "https://user:pass@example.com/", TargetWeb, false},
		{"bad url host", "https://ex_ample.com/", TargetWeb, false},
		{"port out of range", "http://example.com:99999/", TargetWeb, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTarget(tc.target, tc.kinds)
			if tc.wantOK && err != nil {
				t.Fatalf("ValidateTarget(%q) = %v; want accepted", tc.target, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("ValidateTarget(%q) accepted; want rejected", tc.target)
			}
		})
	}
}

// TestValidateTarget_LeadingDashRejectedForEveryKind pins the property
// across the whole kind matrix: no target syntax may ever begin with a
// dash, because the tool would read it as a flag rather than a subject.
func TestValidateTarget_LeadingDashRejectedForEveryKind(t *testing.T) {
	kinds := []TargetKind{TargetIP, TargetCIDR, TargetHostname, TargetURL, TargetHost, TargetNetwork, TargetWeb}
	for _, k := range kinds {
		for _, target := range []string{"-sV", "-oN", "--script", "-"} {
			if err := ValidateTarget(target, k); err == nil {
				t.Fatalf("ValidateTarget(%q, kind %d) accepted; want rejected", target, k)
			}
		}
	}
}

func TestValidateHostname(t *testing.T) {
	if err := ValidateHostname("a.b.example.com"); err != nil {
		t.Fatalf("valid hostname rejected: %v", err)
	}
	if err := ValidateHostname(strings.Repeat("a.", 130) + "com"); err == nil {
		t.Fatal("oversized hostname accepted")
	}
	if err := ValidateHostname(""); err == nil {
		t.Fatal("empty hostname accepted")
	}
}
