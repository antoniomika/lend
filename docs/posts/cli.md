---
title: CLI reference
description: Commands for the laptop, remote shell, and MCP client.
---

## Start and connect

```text
lend agent (--config FILE | --allow-all) [OPTIONS]
lend ssh --config FILE [OPTIONS] -- HOST [COMMAND...]
```

Run these on the laptop. `agent` stays in the foreground. `ssh` starts a supervised proxy for the connection. Options must precede the host or command arguments.

| Option | Applies to | Default or purpose |
| --- | --- | --- |
| --config FILE | agent, ssh | Local JSON policy |
| --profile NAME | agent, ssh | Select an independent named policy |
| --upstream PATH | agent, ssh | Original SSH_AUTH_SOCK |
| --dir PATH | agent, ssh | Laptop user's home directory |
| --approval auto | agent, ssh | Platform approval backend |
| --approval terminal | agent, ssh | Use the laptop's controlling terminal |
| --approval-timeout DURATION | agent, ssh | 1m, includes queue time |
| --command-timeout DURATION | agent, ssh | 5m, includes credential retrieval |
| --socket PATH | agent | Override the default proxy socket |
| --session LABEL | agent | Local prompt label |
| --allow-all | agent | Admit all supported requests, with approval |

`--allow-all` and `--config` are mutually exclusive. SSH connection options come from `~/.ssh/config`. The wrapper disables connection sharing, persistence, and backgrounding.

## Request local execution

```text
lend exec [--socket PATH] [--reason TEXT] -- COMMAND [ARG...]
lend mcp [--socket PATH]
lend keys [--socket PATH]
```

These commands select `SSH_AUTH_SOCK` by default. On a remote host, it must point at the forwarded Lend proxy. `keys` can also inspect your original local agent while preparing a policy. `exec` returns the local command's exit status. A signal returns `128 + signal`. Approval, transport, and startup failures return 125.

The MCP command serves JSON-RPC over stdio and exposes `run_local_command`. See the [MCP guide](/mcp.html) for configuration and output limits.

## Inspect and control local sessions

```text
lend status [--socket PATH | --all] [--watch] [--json]
lend history [--socket PATH | --all | --file PATH] [--json]
lend pause [--socket PATH | --all]
lend resume [--socket PATH | --all]
lend revoke [--socket PATH | --all] ID
lend clear-leases [--socket PATH | --all] [LEASE_ID]
```

Run control commands on the laptop. They use the local default proxy socket or an explicit path. They do not select `SSH_AUTH_SOCK`. `--all` discovers the default proxy and supervised sessions in Lend's runtime directory. Use `--socket` for a custom location. `history --file` reads a persistent journal after a session ends.

## Explain policy

```text
lend explain --config FILE [--profile NAME] [--dir PATH] [--reason TEXT] -- COMMAND [ARG...]
lend explain --config FILE [--profile NAME] --key FINGERPRINT [--purpose ssh|sshsig|raw] [--namespace NAME]
lend explain --config FILE [--profile NAME] --operation NAME [--key FINGERPRINT] [--provider ID]
```

The JSON result evaluates the config on disk without running a command, reading credentials, or requesting approval. It does not inspect live signature quotas or grants.

## Diagnose setup

```text
lend doctor [--config FILE] [--profile NAME] [--json]
lend doctor --remote [--socket PATH] [--json]
```

Local mode also accepts `--socket`, `--upstream`, `--dir`, `--approval auto|terminal`, and `--timeout`. The timeout defaults to 5s per probe. Exit status is 0 with no errors, 1 for a failing check, and 2 for invalid arguments. See [Doctor](/doctor.html) for the checks performed.

## Version and help

```sh
lend version
lend version --json
lend --version
lend --help
lend agent --help
```

Each subcommand accepts `--help`. Version output includes the version, commit, build date, platform, and Go version in JSON form.
