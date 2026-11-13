---
title: Getting started
description: Run your first locally approved command from a remote shell.
toc: true
---

## Install on both machines

Install `lend` on the laptop and the remote host with Homebrew or the release installer. The [installation guide](/installation.html) also covers pinned versions, manual downloads, and source builds.

```sh
brew install antoniomika/tap/lend
# or
curl -fsSL https://github.com/antoniomika/lend/releases/latest/download/install.sh | sh
```

The remote host needs Lend and SSH access. Configure tools such as `gh`, `op`, and your existing SSH agent on the laptop.

## Write a local policy

On the laptop, find the executable and key you want to allow:

```sh
command -v gh
lend keys --socket "$SSH_AUTH_SOCK"
```

Create `policy.json` on the laptop. Replace the executable path and fingerprint with the values from those commands:

```json
{
  "default": "deny",
  "require_reason": true,
  "commands": [
    {
      "executable": "/opt/homebrew/bin/gh",
      "args_prefix": ["pr", "view"],
      "approval": "prompt"
    }
  ],
  "ssh": {
    "default": "deny",
    "keys": [
      {
        "fingerprint": "SHA256:REPLACE_WITH_YOUR_KEY_FINGERPRINT",
        "label": "Remote login",
        "approval": "prompt",
        "purposes": ["ssh"]
      }
    ]
  }
}
```

Linux often installs `gh` at `/usr/bin/gh`. Use the path reported on your laptop. The SSH key rule also permits the initial login through Lend. If the host accepts a different authentication method, configure that in `~/.ssh/config`.

This policy permits `gh pr view` with additional arguments and SSH authentication with one key. Agent management and other commands remain denied. Use `"approval": "biometric"` on macOS to require biometrics without a password fallback. [Approval modes](/command-policy.html) describe the platform requirements.

Download the fuller [policy example](/examples/policy.json) or [profile example](/examples/profiles.json) for more options.

## Check the laptop

Keep `SSH_AUTH_SOCK` pointed at your original agent when starting Lend:

```sh
lend doctor --config ./policy.json
```

Doctor checks the policy, executables, upstream agent, and approval backend. A warning that the local proxy is stopped is expected before opening a session. Resolve any errors before continuing.

## Open a session

From the laptop:

```sh
lend ssh --config ./policy.json -- agent-vm
```

Replace `agent-vm` with your SSH host or an alias from `~/.ssh/config`. Put options such as the user, port, identity, and jump host in that file. Lend starts a separate local proxy, forwards its socket, and keeps it alive for this SSH connection. Your login may prompt for local key approval.

## Request a command

Inside the remote shell:

```sh
lend doctor --remote
lend exec --reason "Inspect the pull request before reviewing it" -- \
  gh pr view 123 --repo example/project
```

Replace the repository and pull request with ones you can access. Lend checks your laptop's policy and opens the local approval prompt. Review the executable, arguments, reason, and caller context. Approve the request to run `gh` on the laptop. Its stdout, stderr, and exit code return to the remote process.

Caller context is requester supplied and can be spoofed. It helps you review a request; authorization comes from the local policy and approval.

## Watch or stop access

In another laptop terminal:

```sh
lend status --all --watch
lend pause --all
lend resume --all
```

Closing the SSH session stops its proxy, cancels its pending and running requests, and discards its leases. A paused session refuses new requests until resumed. [Activity and history](/activity.html) covers individual revocation and persistent logging.

For a coding agent, configure the [MCP bridge](/mcp.html) inside the remote SSH environment. For an existing SSH workflow, use a [manually managed proxy](/commands.html).
