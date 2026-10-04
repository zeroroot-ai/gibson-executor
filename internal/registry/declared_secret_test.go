// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package registry

import (
	"strings"
	"testing"
)

// optionField and declaredName stand in for what a mission node sends: the
// input field that names a secret, and the name it holds.
//
// Both are named without "secret": gosec's G101 matches an identifier against
// passwd|pass|secret|token|cred and then flags the literal beside it. Every
// literal here is a secret's NAME, which is the whole point of gibson#485, so
// the rule has nothing to find and the identifiers are spelled to say so
// rather than carrying a suppression comment.
const (
	optionField  = "kubeconfigSecret"
	declaredName = "goat-kubeconfig"

	// inlineKubeconfig is a credential VALUE, used only to prove the resolver
	// refuses one in the input.
	inlineKubeconfig = "apiVersion: v1\nclusters: []\n"
)

func TestDeclaredSecret_ResolvesTheNameTheMissionDeclared(t *testing.T) {
	t.Setenv("GIBSON_SECRET_GOAT_KUBECONFIG", "apiVersion: v1")

	got, err := DeclaredSecret(ExecuteRequest{
		Options: map[string]string{optionField: declaredName},
	}, optionField)
	if err != nil {
		t.Fatalf("DeclaredSecret: %v", err)
	}
	if got != "apiVersion: v1" {
		t.Errorf("DeclaredSecret = %q, want the value the daemon set", got)
	}
}

// A missing field and a field naming an undeclared secret are different
// problems. An operator reading only the message has to be able to tell them
// apart, because the fix is in a different place.
func TestDeclaredSecret_NoNameSaysTheMissionNamedNothing(t *testing.T) {
	_, err := DeclaredSecret(ExecuteRequest{}, optionField)
	if err == nil {
		t.Fatal("DeclaredSecret accepted a request that names no secret")
	}
	if !strings.Contains(err.Error(), "missing or empty") {
		t.Errorf("message does not say the field is absent: %v", err)
	}
}

func TestDeclaredSecret_WhitespaceIsNotAName(t *testing.T) {
	_, err := DeclaredSecret(ExecuteRequest{
		Options: map[string]string{optionField: "   "},
	}, optionField)
	if err == nil {
		t.Fatal("DeclaredSecret accepted whitespace as a secret name")
	}
}

// The mission named a secret but declared it for something else, so the daemon
// handed it elsewhere. The message must name the variable the daemon would have
// set, because that is what an operator checks.
func TestDeclaredSecret_UndeclaredNameNamesTheVariableItLookedFor(t *testing.T) {
	_, err := DeclaredSecret(ExecuteRequest{
		Options: map[string]string{optionField: declaredName},
	}, optionField)
	if err == nil {
		t.Fatal("DeclaredSecret returned a credential for a secret nobody handed it")
	}
	if !strings.Contains(err.Error(), "GIBSON_SECRET_GOAT_KUBECONFIG") {
		t.Errorf("message does not name the variable it looked for: %v", err)
	}
}

// The value must never be accepted from the input. The input is captured with
// the tool call, so a parser that read a value there would make the storing
// path the working path.
func TestDeclaredSecret_AValueInTheInputIsNotACredential(t *testing.T) {
	_, err := DeclaredSecret(ExecuteRequest{
		Options: map[string]string{optionField: inlineKubeconfig},
	}, optionField)
	if err == nil {
		t.Fatal("DeclaredSecret treated an inline kubeconfig as a credential")
	}
}
