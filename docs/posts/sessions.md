---
title: Sessions and leases
description: Use independent profiles and bounded approval grants for each SSH connection.
---

## Profiles and SSH sessions

The top-level `profiles` object contains independent policies. Selecting `--profile development` uses that policy in full, including commands, keys, management, credential reader, and history settings. Profiles inherit no permissions from the root policy and cannot contain other profiles. `lend agent --config FILE --profile NAME` also selects a profile.

[examples/profiles.json](/examples/profiles.json) provides development and cluster profiles. Replace executable paths, fingerprints, the history path, and credential references for your laptop. On Linux, use `prompt` approval in place of the example's macOS biometric requirement.

`lend ssh` starts a separate local daemon and a private socket for each connection. The wrapper labels prompts with the locally selected profile and SSH target. SSH uses that proxy for authentication and forwarding. The wrapper disables connection sharing, persistence, and backgrounding so its lifetime follows the SSH process. Ports, users, jump hosts, and other SSH settings come from `~/.ssh/config`. Optional arguments after the host become the remote command.

```sh
lend ssh --config ./profiles.json --profile development -- agent-vm
lend ssh --config ./profiles.json --profile cluster -- rack
```

Each session prints its local socket path. Closing SSH stops its daemon, cancels pending and running requests, and discards its leases and signature counters. A parent lifetime pipe also stops the daemon if the wrapper exits unexpectedly. The local session label describes the connection selected on the laptop. It does not establish the identity of a remote process or prevent socket relaying on the remote machine.

## Approval leases

Add `lease` to a command rule or SSH key rule to offer an optional grant:

```json
"lease": {"duration": "5m", "uses": 3}
```

The prompt offers Allow once and Allow lease. Terminal approval accepts separate request-specific `allow` and `lease` phrases. The lease choice requires the rule's configured authentication. Allow once leaves caching disabled for that approval.

Leases are offered only inside supervised `lend ssh` sessions with available desktop lock tracking. Standalone agents and unavailable lock tracking fall back to individual approvals. A lease lasts until its duration or use limit is reached, the session ends, lend observes a device lock or loses lock tracking, or you revoke it. Configurations allow up to one hour and 100 uses. The initial approved request counts as one use. Attempts consume lease uses even if execution or upstream signing later fails.

Command leases match the resolved executable, exact argv, local working directory, credential references, and approval requirement. Stdin can vary between uses. Signing leases match the key, purpose, namespace, signature flags, and approval requirement. Local socket peer details and accepted binding hints further restrict reuse. Caller-supplied metadata never grants access. Signing leases do not establish a destination identity. Signature quotas and upstream restrictions apply to every use. Management operations always require fresh approval and clear existing leases when the upstream operation succeeds.

On Linux, lock tracking checks the active X11 or Wayland session's logind `LockedHint` through `loginctl`. It polls once per second and checks again before using a grant. A lock and unlock entirely between polls can be missed. On macOS, the cgo build checks console state and screen lock notifications. macOS builds without cgo cannot offer leases. Use individual approvals when your desktop cannot report its lock state reliably.
