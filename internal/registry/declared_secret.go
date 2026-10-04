// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package registry

import (
	"fmt"
	"strings"

	"github.com/zeroroot-ai/sdk/secretenv"
)

// DeclaredSecret resolves a secret the MISSION declared for this tool.
//
// A mission declares which named tenant secrets its components may receive
// (gibson#485). The daemon resolves each name as itself at dispatch and puts
// the VALUE in the tool's environment, under the name secretenv.Key derives.
// The tool's INPUT carries only the secret's name.
//
// The environment is the channel because a tool's input JSON is captured with
// the tool call, so a credential written into the input would be stored and
// displayed. That is why no tool here reads a credential VALUE from its input,
// and why a parser must never accept one there as a fallback: a fallback would
// make the storing path work, which is the path that leaks.
//
// option is the input field holding the NAME, for example "kubeconfigSecret".
// The two errors are different problems and say so:
//
//   - the field is absent: the mission did not name a secret for this field.
//   - the field names a secret the environment does not carry: the mission
//     named it but did not declare it for THIS tool, so the daemon handed it to
//     something else or to nothing.
func DeclaredSecret(req ExecuteRequest, option string) (string, error) {
	name := strings.TrimSpace(req.Options[option])
	if name == "" {
		return "", fmt.Errorf(
			"input field %q is missing or empty: it must name the tenant secret this tool needs, "+
				"and the mission must declare that name under its secrets block so the daemon hands the value over",
			option)
	}
	value, ok := secretenv.Lookup(name)
	if !ok {
		return "", fmt.Errorf(
			"input field %q names the secret %q, which this tool was not handed: the daemon sets %s at dispatch "+
				"and it is absent here. Declare %q in the mission's secrets block for this tool. "+
				"The value is never read from the input, because a tool's input is stored with the tool call",
			option, name, secretenv.Key(name), name)
	}
	return value, nil
}
