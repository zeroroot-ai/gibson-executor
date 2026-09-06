// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Target validation. req.Target crosses the same trust boundary as
// req.Args but historically bypassed the args allowlist entirely: every
// parser splices it into the argv (or, for dnsx, into stdin) after
// ApplyArgs has already run. A target is therefore an unpoliced write
// into the tool's argument vector, and the two shapes that matter are:
//
//   - A target that begins with "-" is parsed by the tool as a FLAG, not
//     as a scan subject. That defeats the whole allowlist: the caller
//     picks any flag the policy denies and smuggles it in through the
//     target field instead.
//
//   - A target carrying a newline is a line-oriented injection for tools
//     that read their subject list from stdin or a file (dnsx reads
//     `-l /dev/stdin`), so one newline becomes N additional scan targets.
//
// ValidateTarget closes both by requiring the target to actually parse as
// one of the syntaxes the tool documents — an IP, a CIDR prefix, a
// hostname, or an http(s) URL. Anything that is not one of those is not a
// scan subject and has no business on the argv.
package policy

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// TargetKind is a bitmask of the target syntaxes a tool accepts. A tool
// registers exactly the forms its own documentation lists, so a URL never
// reaches a raw-socket port scanner and a CIDR never reaches a subdomain
// enumerator.
type TargetKind uint8

const (
	// TargetIP permits a bare IPv4 or IPv6 address.
	TargetIP TargetKind = 1 << iota
	// TargetCIDR permits an IPv4/IPv6 prefix such as 10.0.0.0/24.
	TargetCIDR
	// TargetHostname permits an RFC-1123 DNS name.
	TargetHostname
	// TargetURL permits an absolute http:// or https:// URL.
	TargetURL
	// TargetImageRef permits an OCI image reference such as
	// ghcr.io/zeroroot-ai/gibson-executor:1.2.3 or alpine@sha256:<hex>.
	// It is its own syntax, not a URL and not a host: the slashes are
	// repository path separators, the colon is a tag (or a registry
	// port), and nothing here is ever dialled.
	TargetImageRef
)

// Convenience sets naming the three shapes the current parsers need.
const (
	// TargetHost is "an address or a name" — resolvers and DNS tools.
	TargetHost = TargetIP | TargetHostname
	// TargetNetwork adds prefixes — port scanners that sweep ranges.
	TargetNetwork = TargetIP | TargetCIDR | TargetHostname
	// TargetWeb adds absolute URLs — HTTP probes and template scanners.
	TargetWeb = TargetIP | TargetHostname | TargetURL
)

const (
	// maxTargetLen caps the whole target. Generous enough for a URL with
	// a path, far below anything that could stress a tool's arg parser.
	maxTargetLen = 2048
	// maxHostnameLen is the RFC-1035 wire limit for a DNS name.
	maxHostnameLen = 253
	// maxLabelLen is the RFC-1035 per-label limit.
	maxLabelLen = 63
)

// ValidateTarget checks that target is a well-formed scan subject in one
// of the syntaxes named by kinds. It is the single gate every parser runs
// before splicing req.Target into an argv or into a tool's stdin.
//
// The universal checks run first and apply to every kind: non-empty,
// length-capped, no leading "-", and no control characters or whitespace.
// Then the target must parse as one of the permitted forms.
func ValidateTarget(target string, kinds TargetKind) error {
	if kinds == 0 {
		return fmt.Errorf("no target syntax permitted for this tool")
	}
	if target == "" {
		return fmt.Errorf("target is required")
	}
	if len(target) > maxTargetLen {
		return fmt.Errorf("target is %d bytes; limit is %d", len(target), maxTargetLen)
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("target begins with %q, which the tool would parse as a flag", "-")
	}
	if i := strings.IndexFunc(target, forbiddenInTarget); i >= 0 {
		return fmt.Errorf("target contains a disallowed character at byte offset %d", i)
	}

	// An image reference is checked before the URL and CIDR branches below.
	// It is the only kind whose slashes are repository path separators, so
	// `ghcr.io/zeroroot-ai/foo:1.2.3` would otherwise be read as a CIDR and
	// rejected on a syntax it was never claiming to be. A tool that accepts
	// image references accepts nothing else, so this branch is exclusive.
	if kinds&TargetImageRef != 0 {
		return validateImageRef(target)
	}

	// Most specific form first: a scheme means it can only be a URL.
	if strings.Contains(target, "://") {
		if kinds&TargetURL == 0 {
			return fmt.Errorf("target looks like a URL; this tool accepts %s", describeKinds(kinds))
		}
		return validateURL(target)
	}

	if strings.Contains(target, "/") {
		if kinds&TargetCIDR == 0 {
			return fmt.Errorf("target looks like a CIDR prefix; this tool accepts %s", describeKinds(kinds))
		}
		return validateCIDR(target)
	}

	if addr, err := netip.ParseAddr(target); err == nil {
		if kinds&TargetIP == 0 {
			return fmt.Errorf("target is an IP address; this tool accepts %s", describeKinds(kinds))
		}
		if addr.Zone() != "" {
			return fmt.Errorf("target carries a link-local zone; zones are not permitted")
		}
		return nil
	}

	if kinds&TargetHostname != 0 {
		return ValidateHostname(target)
	}
	return fmt.Errorf("target is not a valid IP address; this tool accepts %s", describeKinds(kinds))
}

// ValidateHostname checks an RFC-1123 DNS name: 1..253 bytes, dot-separated
// labels of 1..63 bytes drawn from [A-Za-z0-9-], no label starting or
// ending with a hyphen, and a non-numeric final label (an all-numeric tail
// means the caller meant an IP address and mistyped one).
func ValidateHostname(host string) error {
	h := strings.TrimSuffix(host, ".")
	if h == "" {
		return fmt.Errorf("hostname is empty")
	}
	if len(h) > maxHostnameLen {
		return fmt.Errorf("hostname is %d bytes; limit is %d", len(h), maxHostnameLen)
	}
	labels := strings.Split(h, ".")
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("hostname has an empty label")
		}
		if len(label) > maxLabelLen {
			return fmt.Errorf("hostname label %q is %d bytes; limit is %d", label, len(label), maxLabelLen)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("hostname label %q starts or ends with a hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			if !isHostByte(label[i]) {
				return fmt.Errorf("hostname label %q contains a disallowed character", label)
			}
		}
	}
	if last := labels[len(labels)-1]; isAllDigits(last) {
		return fmt.Errorf("hostname ends in the all-numeric label %q; use a valid IP address instead", last)
	}
	return nil
}

// validateCIDR requires a parseable prefix. netip rejects a masked-bit
// count outside the address family's range, so no extra bounds check is
// needed here.
func validateCIDR(target string) error {
	prefix, err := netip.ParsePrefix(target)
	if err != nil {
		return fmt.Errorf("target is not a valid CIDR prefix: %w", err)
	}
	if prefix.Addr().Zone() != "" {
		return fmt.Errorf("target carries a link-local zone; zones are not permitted")
	}
	return nil
}

// validateURL requires an absolute http(s) URL whose host is itself a
// valid IP or hostname. Userinfo is rejected: it is never needed for a
// scan subject and is a classic parser-confusion vector between the
// runner's view of the host and the tool's.
func validateURL(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("target is not a valid URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("URL scheme %q is not permitted; use http or https", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("URL carries userinfo, which is not permitted in a target")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}
	if _, err := netip.ParseAddr(host); err != nil {
		if err := ValidateHostname(host); err != nil {
			return fmt.Errorf("URL host is invalid: %w", err)
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("URL port %q is not in 1..65535", port)
		}
	}
	return nil
}

// forbiddenInTarget reports whether r must never appear in a target.
// Control characters cover NUL, newline, carriage return and tab — the
// line-oriented injection vector for stdin-fed tools. Whitespace is
// rejected because a space would split one argv token into two for any
// tool that re-parses its own input.
func forbiddenInTarget(r rune) bool {
	return !unicode.IsPrint(r) || unicode.IsSpace(r)
}

func isHostByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-':
		return true
	default:
		return false
	}
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// describeKinds renders a kind set for error messages so an operator
// reading a rejection knows what the tool would have accepted.
func describeKinds(kinds TargetKind) string {
	var parts []string
	if kinds&TargetIP != 0 {
		parts = append(parts, "an IP address")
	}
	if kinds&TargetCIDR != 0 {
		parts = append(parts, "a CIDR prefix")
	}
	if kinds&TargetHostname != 0 {
		parts = append(parts, "a hostname")
	}
	if kinds&TargetURL != 0 {
		parts = append(parts, "an http(s) URL")
	}
	if len(parts) == 0 {
		return "no target syntax"
	}
	return strings.Join(parts, ", ")
}

// validateImageRef checks an OCI image reference:
//
//	[registry[:port]/]name[/name...][:tag][@algo:hex]
//
// The reference is passed to a scanner that resolves it against a registry;
// it is never dialled here, so this is a syntax gate, not a reachability
// one. Repository paths are lowercase by OCI rule, which is enforced: an
// uppercase path is a reference the registry would reject anyway, and
// accepting it here would only move the error somewhere less legible.
func validateImageRef(ref string) error {
	rest, err := splitImageDigest(ref)
	if err != nil {
		return err
	}
	rest, err = splitImageTag(ref, rest)
	if err != nil {
		return err
	}
	return validateImageName(ref, rest)
}

// splitImageDigest strips and checks a trailing @algo:hex, returning the
// name-and-tag portion. A digest is the one part of a reference that pins
// content, so a malformed one must not degrade silently to a tag lookup.
func splitImageDigest(ref string) (string, error) {
	at := strings.LastIndex(ref, "@")
	if at < 0 {
		return ref, nil
	}
	digest := ref[at+1:]
	rest := ref[:at]
	algo, hex, ok := strings.Cut(digest, ":")
	if !ok {
		return "", fmt.Errorf("image digest %q is missing its algorithm", digest)
	}
	want, known := map[string]int{"sha256": 64, "sha512": 128}[algo]
	if !known {
		return "", fmt.Errorf("image digest algorithm %q is not sha256 or sha512", algo)
	}
	if len(hex) != want {
		return "", fmt.Errorf("image digest %q is %d hex characters; %s takes %d", digest, len(hex), algo, want)
	}
	for _, r := range hex {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
		if !isHex {
			return "", fmt.Errorf("image digest %q contains a non-hex character", digest)
		}
	}
	if rest == "" {
		return "", fmt.Errorf("image reference %q has a digest but no name", ref)
	}
	return rest, nil
}

// splitImageTag strips and checks a trailing :tag, returning the name. The
// tag is the segment after the last colon that follows the last slash —
// an earlier colon belongs to a registry host:port.
func splitImageTag(ref, rest string) (string, error) {
	lastSlash := strings.LastIndex(rest, "/")
	colon := strings.LastIndex(rest, ":")
	if colon <= lastSlash {
		return rest, nil
	}
	tag := rest[colon+1:]
	if tag == "" {
		return "", fmt.Errorf("image reference %q has an empty tag", ref)
	}
	if len(tag) > 128 {
		return "", fmt.Errorf("image tag is %d characters; limit is 128", len(tag))
	}
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return "", fmt.Errorf("image tag %q contains a disallowed character", tag)
		}
	}
	return rest[:colon], nil
}

// validateImageName checks the registry-and-repository path. OCI repository
// names are lowercase, which is enforced rather than normalised: an
// uppercase path is a reference the registry would reject anyway, and
// accepting it here would only move the error somewhere less legible.
func validateImageName(ref, name string) error {
	if name == "" {
		return fmt.Errorf("image reference %q has no name", ref)
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" {
			return fmt.Errorf("image reference %q has an empty path component", ref)
		}
		// The first component may be a registry host carrying a port.
		if host, port, hasPort := strings.Cut(part, ":"); hasPort {
			if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("image registry port %q is not a port number", port)
			}
			part = host
		}
		if part == "" {
			return fmt.Errorf("image reference %q has an empty registry host", ref)
		}
		if err := validateImageNameComponent(ref, part); err != nil {
			return err
		}
	}
	return nil
}

func validateImageNameComponent(ref, part string) error {
	for _, r := range part {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		case r >= 'A' && r <= 'Z':
			return fmt.Errorf("image reference %q contains an uppercase character; OCI repository names are lowercase", ref)
		default:
			return fmt.Errorf("image reference %q contains a disallowed character", ref)
		}
	}
	return nil
}
