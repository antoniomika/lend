---
title: Credentials and environment
description: Inject local credentials into an approved command.
---

## Local command environment

Commands inherit the laptop daemon's environment, including its `PATH` and any environment variables present when it started. Lend sets `SSH_AUTH_SOCK` to its own proxy socket so commands use the configured SSH key policy. The default working directory is the laptop user's home directory; choose another with `--dir` on `lend agent` or `lend ssh`.

Remote requests cannot provide environment overrides. Requester-reported fields such as `SSH_CONNECTION` are display metadata and are not injected into the local command. There is currently no clean-environment mode or environment allowlist. An approved program can read or print its inherited environment.

## Secret injection

Command rules can inject secrets from a local reader into the approved process. `secret_reader` is the absolute path to a program that prints a secret, and `secret_reader_args` are the arguments placed before the reference. For each variable, lend runs the reader with those arguments followed by the configured reference, and uses its stdout as the value. Without `secret_reader_args`, the reference is the only argument.

For 1Password, run [`op read --no-newline`](https://developer.1password.com/docs/cli/reference/commands/read/):

```json
{
  "secret_reader": "/opt/homebrew/bin/op",
  "secret_reader_args": ["read", "--no-newline"],
  "commands": [
    {
      "executable": "/opt/homebrew/bin/gh",
      "args_prefix": ["pr", "view"],
      "approval": "biometric",
      "secrets": {"GH_TOKEN": "op://Development/github/token"}
    }
  ]
}
```

Other readers work the same way when they take the secret's name last, such as `pass show`, `gopass show -o`, or `security find-generic-password -w -s` on macOS. lend keeps the reader's output exactly, including a trailing newline, so use a no-newline option where the reader has one.

lend reads credentials after the request is admitted and approved, and passes the values through the command environment. The remote request cannot choose environment variables or secret references. The prompt shows variable names and references; values remain hidden. Credential reads use the same command timeout and proxy socket. Failures refuse execution without returning the reader's output. Values are fetched again for each command, including leased requests, with a 64 KiB limit per value and 32 variables per rule.

The command can use the credential to perform an operation and return its result. Its output still goes to the requester, so an executable or arguments that print the environment can disclose injected values. Select arguments and executables accordingly. Credential values are never added to approval summaries or history. Existing explicit `op read` command grants still return their output to the requester.

The longest matching command prefix selects the whole rule, including its credentials and lease. Rules do not combine their settings.
