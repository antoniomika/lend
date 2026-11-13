---
title: Cheatsheet
description: Common laptop and remote commands.
---

## On the laptop

Check setup and connect:

```sh
lend keys --socket "$SSH_AUTH_SOCK"
lend doctor --config ./policy.json
lend ssh --config ./policy.json -- agent-vm
lend ssh --config ./profiles.json --profile development -- agent-vm
```

Inspect sessions from another terminal:

```sh
lend status --all --watch
lend history --all
lend pause --all
lend resume --all
lend clear-leases --all
```

Control one session with the socket path printed by `lend ssh`:

```sh
lend status --socket /path/to/agent.sock --json
lend revoke --socket /path/to/agent.sock REQUEST_ID
lend clear-leases --socket /path/to/agent.sock LEASE_ID
```

Explain a rule without requesting access:

```sh
lend explain --config ./policy.json --reason "Inspect the pull request" -- \
  gh pr view 123 --repo example/project
lend explain --config ./policy.json \
  --key SHA256:KEY_FINGERPRINT --purpose sshsig --namespace git
```

## On the remote host

Check forwarding and request a local command:

```sh
lend doctor --remote
lend exec --reason "Inspect the pull request" -- \
  gh pr view 123 --repo example/project
lend keys
```

Start the stdio MCP bridge from a client that inherits the forwarded socket:

```sh
lend mcp
```

## Manually managed proxy

Keep this running in a laptop terminal:

```sh
lend agent --config ./policy.json --socket "$HOME/.lend/agent.sock"
```

Connect from a second laptop terminal:

```sh
SSH_AUTH_SOCK="$HOME/.lend/agent.sock" ssh -A agent-vm
```

The manually managed proxy stays running until you stop it. Use `lend ssh` for per-connection lifetime management and approval leases.
