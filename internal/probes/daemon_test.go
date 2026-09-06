// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package probes

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDaemonProbe_Name(t *testing.T) {
	p := NewDaemonProbe(0)
	if got := p.Name(); got != "daemon-callback" {
		t.Errorf("Name() = %q, want daemon-callback", got)
	}
}

func TestDaemonProbe_CheckPass(t *testing.T) {
	// Start a real TCP listener so the probe has something to connect to.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	p := &DaemonProbe{addr: ln.Addr().String(), timeout: 1 * time.Second}
	if err := p.Check(context.Background()); err != nil {
		t.Errorf("Check returned error for reachable address: %v", err)
	}
}

func TestDaemonProbe_CheckFail_UnreachablePort(t *testing.T) {
	// Point the probe at a port nothing is listening on.
	p := &DaemonProbe{addr: "127.0.0.1:1", timeout: 500 * time.Millisecond}
	err := p.Check(context.Background())
	if err == nil {
		t.Error("Check returned nil for unreachable address; expected error")
	}
}

func TestDaemonProbe_CheckFail_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	p := &DaemonProbe{addr: "127.0.0.1:1", timeout: 1 * time.Second}
	err := p.Check(ctx)
	if err == nil {
		t.Error("Check returned nil for cancelled context; expected error")
	}
}

func TestResolveDaemonAddr_Default(t *testing.T) {
	t.Setenv("GIBSON_DAEMON_ADDRESS", "")
	if got := resolveDaemonAddr(); got != "localhost:50002" {
		t.Errorf("resolveDaemonAddr() = %q, want localhost:50002", got)
	}
}

func TestResolveDaemonAddr_EnvOverride(t *testing.T) {
	t.Setenv("GIBSON_DAEMON_ADDRESS", "envoy.gibson.svc:8080")
	if got := resolveDaemonAddr(); got != "envoy.gibson.svc:8080" {
		t.Errorf("resolveDaemonAddr() = %q, want envoy.gibson.svc:8080", got)
	}
}

func TestCanonicalTCPAddr_Plain(t *testing.T) {
	if got := canonicalTCPAddr("host:1234"); got != "host:1234" {
		t.Errorf("canonicalTCPAddr(plain) = %q, want host:1234", got)
	}
}

func TestCanonicalTCPAddr_UnixPrefix(t *testing.T) {
	// unix paths should pass through unchanged (not stripped to empty).
	got := canonicalTCPAddr("unix:///run/spire/sockets/agent.sock")
	if got == "" {
		t.Error("canonicalTCPAddr stripped unix path to empty")
	}
}
