---
title: Activity and history
description: Inspect sessions, revoke requests, and record completed activity.
---

## Activity and revocation

Inspect local sessions and requests:

```sh
lend status --all --watch
lend status --all --json
lend pause --all
lend resume --all
```

The live terminal view shows socket connections, queued and active requests, caller context when available, running commands, leases, lock tracking availability, and used or reserved signature quota. `--json` includes the full active approval summaries. Active summaries can contain sensitive command arguments. Completed history has separate logging settings.

Pause cancels active and queued work, clears leases, and refuses new connections until resume. `--all` visits the default agent and supervised sessions under lend's runtime directory. Use `--socket PATH` for an individual session or a custom agent location. Newly started daemons begin unpaused.

```sh
lend pause --socket /path/printed/by/lend/agent.sock
lend revoke --socket /path/printed/by/lend/agent.sock REQUEST_ID
lend clear-leases --socket /path/printed/by/lend/agent.sock
lend clear-leases --socket /path/printed/by/lend/agent.sock LEASE_ID
```

Revoking a request cancels that request and clears the daemon's leases. Revoking a socket connection also cancels its current request. A remote process can open another channel while its session remains enabled; pause that session to refuse further requests. Revocation cannot undo an operation already completed by an upstream agent or command.

Controls use a separate private Unix socket beside the proxy. The agent forwarding protocol does not expose these operations. Local control commands use the local default socket or an explicit path and never select the remote `SSH_AUTH_SOCK` automatically.

## Policy explanations and history

Check a local rule without running the command, fetching credentials, or opening an approval prompt:

```sh
lend explain --config ./profiles.json --profile development \
  --reason "Inspect the pull request" -- gh pr view 123 --repo example/project
lend explain --config ./profiles.json --profile development \
  --key SHA256:KEY_FINGERPRINT --purpose sshsig --namespace git
lend explain --config ./profiles.json --profile development --operation lock
```

The JSON result reports admission, the resolved executable and matching argument prefix for commands, approval requirement, lease configuration, and credential variable names. It evaluates the config on disk. It does not inspect live quotas, lease availability, or the upstream agent. A running agent keeps its loaded policy until restarted.

```sh
lend history --all
lend history --all --json
lend history --file /absolute/private/directory/history.jsonl
```

Each daemon keeps the latest 256 completed request records in memory. Records include local session and request IDs, executable or key fingerprint, operation, approval decision, completion state, duration, and command exit status. Caller text, reasons, stdin, stdout, stderr, credential references, and credential values are omitted.

Enable persistent JSON Lines history in a policy or profile:

```json
"history": {"path": "/absolute/private/directory/history.jsonl"}
```

The history directory must belong to the laptop user with mode `0700`; files use `0600`. The journal rotates at 8 MiB and retains one previous file. Shared writers coordinate through a local file lock. Each daemon reloads the latest records from the current file at startup and adds its own completions to its history view. `lend history --file PATH` reads completed records from the file after the session ends and can also inspect the rotated `.1` file. A history write failure appears in status. Persistent history is disabled by default.

Arguments are omitted by default. `"log_arguments": true` inside `history` opts into storing complete command arguments. Those arguments can contain secrets; lend does not infer which arguments are safe. This setting never enables output, environment, or stdin logging.
