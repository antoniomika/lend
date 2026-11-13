---
title: Credentials and environment
description: Inject local credentials into an approved command.
---

## Local command environment

Commands inherit the laptop daemon's environment, including its `PATH` and any environment variables present when it started. Lend sets `SSH_AUTH_SOCK` to its own proxy socket so commands use the configured SSH key policy. The default working directory is the laptop user's home directory; choose another with `--dir` on `lend agent` or `lend ssh`.

Remote requests cannot provide environment overrides. Requester-reported fields such as `SSH_CONNECTION` are display metadata and are not injected into the local command. There is currently no clean-environment mode or environment allowlist. An approved program can read or print its inherited environment.

## 1Password injection

Command rules can inject selected 1Password values into the approved local process:

```json
{
  "secret_reader": "/opt/homebrew/bin/op",
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

`secret_reader` is the absolute path to the local `op` executable. After approval, lend uses [`op read --no-newline`](https://developer.1password.com/docs/cli/reference/commands/read/) for each locally configured reference. It passes values through the command environment. The remote request cannot choose environment variables or secret references. The prompt shows variable names and references; values remain hidden. Credential reads use the same command timeout and proxy socket. Failures refuse execution without returning the reader's output. Values are fetched again for each command, including leased requests, with a 64 KiB limit per value and 32 variables per rule.

The command can use the credential to perform an operation and return its result. Its output still goes to the requester, so an executable or arguments that print the environment can disclose injected values. Select arguments and executables accordingly. Credential values are never added to approval summaries or history. Existing explicit `op read` command grants still return their output to the requester.

The longest matching command prefix selects the whole rule, including its credentials and lease. Rules do not combine their settings.
