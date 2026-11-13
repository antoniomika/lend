---
title: Running commands
description: Request local execution from a remote shell.
toc: true
---

## From laptop to remote host

Start a session with a dedicated proxy and policy profile:

```sh
lend ssh --config ./profiles.json --profile development -- agent-vm
```

For a manually managed proxy, keep this agent running in a local terminal. Its upstream defaults to the current `SSH_AUTH_SOCK`, which can point to OpenSSH, 1Password, or another compatible agent.

```sh
lend agent --config ./policy.json --socket "$HOME/.lend/agent.sock"
```

From another laptop terminal, forward the proxy socket:

```sh
SSH_AUTH_SOCK="$HOME/.lend/agent.sock" ssh -A remote-host
```

Agent-based authentication for this connection also goes through the proxy. Its login key needs permission in the `ssh` policy.

On the remote host:

```sh
lend exec --reason "Inspect the pull request before reviewing it" -- \
  gh pr view 123 --repo example/project

lend exec --reason "Fetch the credential needed by this task" -- \
  op read op://vault/item/field
```

Commands run with the laptop user's privileges, environment, and `PATH`, with `SSH_AUTH_SOCK` set to lend's socket so their SSH operations also use its key policy. Their working directory defaults to the laptop user's home directory and can be set with `lend agent --dir /local/directory`. Relative executable paths containing `/` resolve against that directory. Arguments pass directly to the executable. To use shell syntax, explicitly request a shell allowed by your policy.

With a laptop policy allowing those requests, `gh` performs the operation using its local authentication. `op read` sends the requested secret back to the remote caller. Keep the tools and their desktop integrations configured on the laptop. The VM can make requests while your SSH session exposes the forwarded socket.

For unrestricted command, key, and supported management selection with approval, start `lend agent --allow-all --socket "$HOME/.lend/agent.sock"`. You can then run examples such as `lend exec -- hostname` or, with a Mac laptop, `printf 'clipboard content' | lend exec -- pbcopy`.

The remote process receives streamed stdout and stderr and the command's exit code. A command terminated by a signal returns `128 + signal`. Approval, transport, and startup failures return 125.
