---
title: Sessions and leases
description: Use independent profiles and bounded approval grants for each SSH connection.
---

## Profiles and SSH sessions

The top-level `profiles` object contains independent policies. Selecting `--profile development` uses that policy in full, including commands, keys, management, credential reader, and history settings. Profiles inherit no permissions from the root policy and cannot contain other profiles. `lend agent --config FILE --profile NAME` also selects a profile.

[examples/profiles.json](/examples/profiles.json) provides development and cluster profiles. Replace executable paths, fingerprints, the history path, and credential references for your laptop. On Linux, use `prompt` approval in place of the example's macOS biometric requirement.

`lend ssh` starts a separate local daemon and a private socket for each connection. The wrapper labels prompts with the locally selected profile and SSH target. SSH uses that proxy for authentication and forwarding by default. Pass SSH options directly or set them in `~/.ssh/config`. Arguments for the remote command pass through unchanged.

```sh
lend ssh --config ./profiles.json --profile development -- agent-vm
lend ssh --config ./profiles.json --profile cluster -- rack
lend ssh --config ./profiles.json --profile development -p 2222 -J bastion agent-vm
lend ssh --config ./profiles.json --profile development --system-agent agent-vm
```

`--system-agent` uses the original agent for initial login and forwards lend's proxy to the remote host. The login key or certificate only needs to be available in the original agent. Its socket defaults to the original `SSH_AUTH_SOCK`, with `--upstream` or `LEND_UPSTREAM` as overrides. Set `LEND_SYSTEM_AGENT=true` to make this the default.

Set `LEND_CONFIG` to the policy path and optionally `LEND_PROFILE` to select a profile. With those defaults, `alias ssh='lend ssh'` accepts ordinary SSH arguments. Set `LEND_SILENT=true` or pass `--silent` to hide lend's startup messages while keeping errors, approval prompts, and SSH output visible. Lend flags must precede SSH arguments. An optional `--` ends SSH option parsing; put SSH options before it. See the [CLI reference](/cli.html) for all environment defaults.

The supervised wrapper requires OpenSSH 8.7 or later. It disables connection sharing, persistence, and backgrounding so the proxy's lifetime follows SSH. It rejects `-f`, `-M`, `-O`, and `-S`. Its selected authentication socket, forwarding socket, and lifetime settings take precedence over `-o` options and SSH config for the destination connection. Use a [manually managed proxy](/commands.html) for background connections or multiplexing. Informational invocations such as `ssh -G`, `ssh -V`, and `ssh -Q`, and invalid SSH arguments run directly without a proxy or policy file.

ProxyJump (`-J` or `ProxyJump` in SSH config) starts separate SSH processes that use their own host configuration. To make a jump host use lend's selected authentication socket and avoid persistent jump connections, configure that host:

```sshconfig
Host bastion
    IdentityAgent SSH_AUTH_SOCK
    ForwardAgent no
    ControlMaster no
    ControlPath none
    ControlPersist no
    ForkAfterAuthentication no
```

A jump host with another `IdentityAgent` setting authenticates through that agent. Existing shared jump connections use their original authentication. The destination still receives lend's proxy socket.

Each session prints its local socket path unless silent mode is enabled. Closing SSH stops its daemon, cancels pending and running requests, and discards its leases and signature counters. A parent lifetime pipe also stops the daemon if the wrapper exits unexpectedly. The local session label describes the connection selected on the laptop. It does not establish the identity of a remote process or prevent socket relaying on the remote machine.

## Approval leases

Add `lease` to a command rule or SSH key rule to offer an optional grant:

```json
"lease": {"duration": "5m", "uses": 3}
```

The prompt offers Allow once and Allow lease. Terminal approval accepts separate request-specific `allow` and `lease` phrases. The lease choice requires the rule's configured authentication. Allow once leaves caching disabled for that approval.

Leases are offered only inside supervised `lend ssh` sessions with available desktop lock tracking. Standalone agents and unavailable lock tracking fall back to individual approvals. A lease lasts until its duration or use limit is reached, the session ends, lend observes a device lock or loses lock tracking, or you revoke it. Configurations allow up to one hour and 100 uses. The initial approved request counts as one use. Attempts consume lease uses even if execution or upstream signing later fails.

Command leases match the resolved executable, exact argv, local working directory, credential references, and approval requirement. Stdin can vary between uses. Signing leases match the key, purpose, namespace, signature flags, and approval requirement. Local socket peer details and accepted binding hints further restrict reuse. Caller-supplied metadata never grants access. Signing leases do not establish a destination identity. Signature quotas and upstream restrictions apply to every use. Management operations never use leases. They require fresh approval unless their rule sets `none`, and they clear existing leases when the upstream operation succeeds.

On Linux, lock tracking checks the active X11 or Wayland session's logind `LockedHint` through `loginctl`. It polls once per second and checks again before using a grant. A lock and unlock entirely between polls can be missed. On macOS, the cgo build checks console state and screen lock notifications. macOS builds without cgo cannot offer leases. Use individual approvals when your desktop cannot report its lock state reliably.
