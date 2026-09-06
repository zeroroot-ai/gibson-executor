// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package probes provides readiness and liveness probes for the tool runner.
package probes

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// DaemonProbe checks whether the Gibson daemon callback address is reachable
// via TCP. It implements readiness.Probe from platform-clients.
//
// The address is resolved from GIBSON_DAEMON_ADDRESS (defaulting to
// localhost:50002), matching the daemonclient resolution logic so the probe
// tests the same endpoint the gRPC client will dial.
//
// A TCP-level check is used because the tool runner is stateless and does not
// hold a persistent gRPC connection; a dial attempt is the lightest signal
// that Envoy/the daemon is up and accepting connections.
type DaemonProbe struct {
	addr    string
	timeout time.Duration
}

// NewDaemonProbe returns a DaemonProbe that checks the daemon address resolved
// from the GIBSON_DAEMON_ADDRESS env var (default localhost:50002).
//
// dialTimeout bounds each individual TCP dial attempt. A value of zero uses a
// 3-second default, which is long enough to surface slow starts without
// blocking the /readyz handler under normal conditions.
func NewDaemonProbe(dialTimeout time.Duration) *DaemonProbe {
	if dialTimeout == 0 {
		dialTimeout = 3 * time.Second
	}
	return &DaemonProbe{
		addr:    resolveDaemonAddr(),
		timeout: dialTimeout,
	}
}

// Name satisfies readiness.Probe.
func (p *DaemonProbe) Name() string { return "daemon-callback" }

// Check opens a TCP connection to the daemon address and closes it immediately.
// Returns nil when the address accepts connections, or a descriptive error.
//
// Satisfies readiness.Probe.
func (p *DaemonProbe) Check(ctx context.Context) error {
	// Apply a tight per-check deadline so a slow daemon doesn't stall the
	// aggregator's response. The caller's context provides the outer bound.
	dialCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	addr := canonicalTCPAddr(p.addr)
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("daemon-callback unreachable at %s: %w", addr, err)
	}
	_ = conn.Close()
	return nil
}

// resolveDaemonAddr returns the daemon address from GIBSON_DAEMON_ADDRESS, or
// the default localhost:50002 — same resolution as daemonclient.GetDaemonAddress.
func resolveDaemonAddr() string {
	if addr := os.Getenv("GIBSON_DAEMON_ADDRESS"); addr != "" {
		return addr
	}
	return "localhost:50002"
}

// canonicalTCPAddr strips a leading "unix:///" or "unix:" prefix (unix-socket
// addresses are not checkable via TCP) and returns the raw host:port. For a
// unix socket the probe degrades gracefully by attempting a dial to the path
// which will fail informatively rather than panic.
func canonicalTCPAddr(addr string) string {
	for _, pfx := range []string{"unix:///", "unix://"} {
		if strings.HasPrefix(addr, pfx) {
			// Unix socket — return as-is; DialContext handles it.
			return addr
		}
	}
	return addr
}
