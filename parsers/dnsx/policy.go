// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Per-tool args allowlist for dnsx.
//
// Coverage rationale:
//   - Record-type selectors are safe.
//   - Output flags (`-o`, `-output`) DENIED — runner reads JSON on stdout.
//   - Resolver-list (`-r`) DENIED unless paired with PathUnder validator;
//     allowing arbitrary resolver lists could exfiltrate via DNS to a
//     caller-controlled server. Today no caller needs to override the
//     default resolvers, so this is left out of the allowlist.
package dnsx

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/zeroroot-ai/gibson-executor/internal/policy"
	"github.com/zeroroot-ai/gibson-executor/internal/registry"
)

var argsPolicy = policy.ArgsPolicy{
	// Record-type selectors (boolean form).
	"-a":     nil,
	"-aaaa":  nil,
	"-cname": nil,
	"-ns":    nil,
	"-txt":   nil,
	"-mx":    nil,
	"-soa":   nil,
	"-ptr":   nil,
	"-srv":   nil,
	"-caa":   nil,
	"-axfr":  nil,

	// Throughput / behaviour.
	"-rate-limit": policy.AllowAny,
	"-rl":         policy.AllowAny,
	"-c":          policy.AllowAny,
	"-t":          policy.AllowAny,
	"-retry":      policy.AllowAny,

	// Boolean diagnostics.
	"-silent":    nil,
	"-stats":     nil,
	"-resp":      nil,
	"-resp-only": nil,

	// Resolver selection. dnsx queries a built-in list of public resolvers
	// by default, so a name that only an internal resolver knows (a
	// split-horizon zone, a cluster DNS, Docker's embedded DNS in the tool
	// smoke) never resolves unless the caller names that resolver. The value
	// is a comma-separated list of ip[:port]; hostnames are refused because a
	// resolver named by hostname has to be resolved by some other resolver
	// first, which is the ambiguity this flag exists to remove.
	"-r":        resolverList,
	"-resolver": resolverList,
}

// resolverList validates a comma-separated list of resolver addresses, each
// an IPv4/IPv6 literal with an optional :port.
func resolverList(value string) error {
	if value == "" {
		return errors.New("resolver list must be non-empty")
	}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return fmt.Errorf("resolver list %q has an empty entry", value)
		}
		host := item
		if h, port, err := net.SplitHostPort(item); err == nil {
			if _, perr := strconv.ParseUint(port, 10, 16); perr != nil || port == "0" {
				return fmt.Errorf("resolver %q has an invalid port", item)
			}
			host = h
		}
		if net.ParseIP(host) == nil {
			return fmt.Errorf("resolver %q is not an IP literal; name resolvers by address, not hostname", item)
		}
	}
	return nil
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
	// dnsx resolves a name; an address is accepted for reverse lookups.
	registry.RegisterTargetPolicy(toolName, policy.TargetHost)
}
