---
title: How it works
description: An SSH agent proxy carries requests back to your laptop for local policy and approval.
---

## One forwarded socket

Lend runs between your SSH connection and your existing laptop SSH agent. OpenSSH forwards Lend's socket to the remote host through agent forwarding. Ordinary SSH tools use the agent protocol for key listing and signing. `lend exec` and `lend mcp` use a custom agent extension for local command requests.

```text
REMOTE HOST                         LAPTOP

lend exec / lend mcp ─┐              lend proxy
                     ├─ SSH socket ──┤
ssh / git / ssh-add ─┘               ├─ local policy
                                    ├─ local approval
                                    ├─ local command → output and exit code
                                    └─ upstream agent → signatures
```

The remote host needs the Lend binary for command execution and MCP. Standard SSH agent clients can use the forwarded socket directly. Tools such as `gh` and `op` stay installed and authenticated on the laptop.

## Command requests

1. The remote client sends an executable, argument array, optional reason, and reported caller context.
2. The laptop resolves the executable locally and checks the longest matching command rule.
3. The request waits for its required local approval, or uses an explicitly approved matching lease.
4. Lend reads any locally configured credential references and starts the executable as the laptop user.
5. Stdin, stdout, stderr, and the exit status travel over the same SSH agent channel.

Arguments go directly to the executable. A shell must be explicitly requested and allowed. The remote request cannot set the working directory, environment, profile, approval mode, or credential references.

## SSH agent requests

Identity listings are filtered by the key policy. For signing, Lend checks the key fingerprint, signing purpose, namespace, and quota before local approval. It then forwards the original request to the upstream agent on a persistent connection.

Your original agent retains the keys and enforces its own restrictions. It may show another approval prompt or refuse an operation Lend approved. Lend does not change its approval policy. Agent management has separate permissions for operations such as loading, removing, locking, or unlocking keys.

## Per-connection sessions

`lend ssh` starts a dedicated laptop proxy for one SSH process. It selects the local policy or profile before connecting, prints the control socket path, and stops the proxy when SSH exits. Approval leases belong to that session and also require available desktop lock tracking.

`lend agent` provides a manually managed proxy for other SSH workflows. It requires individual approvals and does not offer session leases.

## Trust and caller context

Prompts distinguish requester-supplied caller details, the local Unix socket peer, and session-binding hints accepted by the upstream agent. Remote caller fields are unverified. The laptop's kernel peer identifies the connected local process, typically SSH. Lend does not verify the remote process or map binding hints to destination hostnames.

Commands execute with the local user's file and environment access. Their output goes to the requester. Read [scope and trust](/security.html) when choosing executable and argument rules.

## Prior art

- [ssh-rev-exec](https://github.com/KOBA789/ssh-rev-exec) carries local execution requests through an SSH agent proxy.
- [op-forward](https://github.com/ekovshilovsky/op-forward) forwards 1Password CLI commands to a machine with desktop authentication.

Lend is an independent implementation that adds local policy, approval, key restrictions, and session controls. The [protocol reference](/protocol.html) documents its experimental wire format.
