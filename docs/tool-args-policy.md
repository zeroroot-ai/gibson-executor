# Tool argument policy: open by default, denied by capability class

This is the rule for every tool the runner executes. Read it before you
author or change a `parsers/<tool>/policy.go`.

## The rule

**Allow every flag the tool accepts. Deny only the flags that reach outside
the run, and name the class that refuses each one.**

Do NOT inventory a tool's flags and transcribe them into an allowlist.

## Why the allowlist was wrong

nmap 7.93 documents 158 flags. The authored allowlist named 26. The first
flag a real mission needed was `--stats-every`, the progress printer that
makes a long scan watchable, and it was missing — it is not even in
`nmap -h`, so an author checking the short help would never have found it.

The mission failed. The tool logged `flag not in tool allowlist`, which
reads as "you asked for something forbidden" when the truth was "nobody has
transcribed this flag yet". That failure mode returns on every upstream
release, for every tool, forever. The maintenance is unbounded and the
product breaks quietly.

## Why open is safe

The flag policy was never what stopped a shell escape. Four structural
guards do that, and none of them depend on enumerating flags:

1. **argv, never a shell.** Every parser runs
   `exec.CommandContext(ctx, bin, args...)` with a Go slice. No string is
   concatenated into a command line, so `;`, `$(…)` and backticks are inert
   bytes in an argv element. Deleting the flag policy entirely would not
   create a shell escape.
2. **The runner pins its own output flag.** `buildArgs` prepends `-oX -`;
   the caller never names an output path.
3. **`--` before the target.** getopt stops interpreting flags there, so a
   target can never be re-read as a flag.
4. **The sandbox is the boundary.** A gVisor microVM, egress limited to the
   manifest's declared allowlist, no platform credentials in the image.

So the policy defends against the TOOL'S OWN dangerous features, not the
shell. Those features fall into five classes, and the classes are stable
across tools and releases in a way flag names are not.

## The five classes

| class | what it does | nmap examples |
|---|---|---|
| `ClassFileWrite` | writes a file the caller names | `-oN -oA --append-output --stylesheet` |
| `ClassFileRead` | reads a file the caller names | `-iL --excludefile --datadir` |
| `ClassCodeExec` | runs caller-supplied scripts or plugins | `--script --script-args` |
| `ClassThirdParty` | involves a machine other than the declared target | `-S -D -b -sI -iR --proxies` |
| `ClassRawForge` | forges packets or alters privilege | `--send-eth --scanflags --data -f --privileged` |

## Onboarding a tool

1. Read the tool's manual for the five classes only. You are looking for
   flags that write a path, read a path, execute code, drag in a third
   party, or change privilege. That is a short list for any scanner.
2. Declare `policy.OpenPolicy{Denied: policy.Deny(...), Validators: ...}`
   and register it with `registry.RegisterOpenArgsPolicy`.
3. Add a `Validators` entry for every flag whose VALUE has a shape worth
   checking (a port spec, a rate, a duration). Options route through
   `ApplyOption`, which still requires a validator, so this is also what
   keeps the options door as strict as the args door.
4. Add a test asserting one representative flag per class is refused, and
   one asserting an unenumerated flag is allowed.

## The trade, stated plainly

An unknown-but-harmful upstream flag is allowed until someone classifies
it. Under the allowlist it would have been denied. Given argv exec, the
pinned output flag, the `--` guard and the microVM, the residual risk is
small and bounded by the sandbox — and it buys a policy that does not
break correct missions on every tool release.

`internal/policy/deny.go` is the implementation and carries the same
reasoning next to the code.
