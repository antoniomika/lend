---
title: CLI reference
description: Commands for the laptop, remote shell, and MCP client.
---

## Start and connect

```text
lend agent (--config FILE | --allow-all) [OPTIONS]
lend ssh [--config FILE] [LEND OPTIONS] [SSH OPTIONS] [--] HOST [COMMAND...]
```

Run these on the laptop. `agent` stays in the foreground. `ssh` starts a supervised proxy for the connection and requires OpenSSH 8.7 or later. Lend options must precede SSH arguments. An optional `--` ends SSH option parsing, including options after the host. Put SSH options before `--`. SSH options and remote command arguments pass through to the SSH executable on `PATH`.

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
| --silent | agent, ssh | Hide lend startup messages |
| --system-agent | ssh | Use the original agent for login |
| --socket PATH | agent | Override the default proxy socket |
| --session LABEL | agent | Local prompt label |
| --allow-all | agent | Admit all supported requests, with approval |

`--allow-all` and an explicit `--config` are mutually exclusive. `--allow-all` ignores environment policy defaults. Silent mode keeps errors, approval prompts, and SSH output visible. Pass SSH's `-q` to control SSH output.

The wrapper uses its proxy socket for authentication and forwarding by default. `--system-agent` uses the upstream socket for login while forwarding the proxy. The login key or certificate then only needs to be available in the upstream agent. SSH's environment points at the selected authentication socket; `ForwardAgent` explicitly selects the proxy socket.

The selected sockets and settings that disable connection sharing, persistence, and backgrounding take precedence over `-o` options and SSH config for the destination connection. ProxyJump connections use their own SSH configuration; see [Sessions and profiles](/sessions.html) to route jump-host authentication through lend. The wrapper rejects `-f`, `-M`, `-O`, and `-S`; use a [manually managed proxy](/commands.html) for those workflows. SSH's `-a` can disable forwarding. Informational invocations such as `-G`, `-V`, and `-Q`, and invalid SSH arguments run directly without a proxy or policy file.

## Environment defaults

Explicit lend flags override these values, including `--profile=` and `--silent=false`. Empty environment values use the built-in defaults. An empty `--dir=` selects the laptop user's home directory for every local subcommand. Boolean values accept `true`, `false`, `1`, or `0`. Durations use Go duration syntax such as `90s` or `10m`. Invalid values return an error.

| Variable | Applies to | Flag |
| --- | --- | --- |
| LEND_CONFIG | agent, ssh, explain, local doctor | --config |
| LEND_PROFILE | agent, ssh, explain, local doctor | --profile |
| LEND_UPSTREAM | agent, ssh, local doctor | --upstream |
| LEND_DIR | agent, ssh, explain, local doctor | --dir |
| LEND_APPROVAL | agent, ssh, local doctor | --approval |
| LEND_APPROVAL_TIMEOUT | agent, ssh | --approval-timeout |
| LEND_COMMAND_TIMEOUT | agent, ssh | --command-timeout |
| LEND_SILENT | agent, ssh | --silent |
| LEND_SYSTEM_AGENT | ssh | --system-agent |

The upstream socket defaults to `SSH_AUTH_SOCK` when `LEND_UPSTREAM` is empty. `doctor --remote` ignores these local environment defaults. Remote commands such as `exec`, `approve`, and `mcp` continue to select `SSH_AUTH_SOCK`.

```sh
export LEND_CONFIG="$HOME/.config/lend/policy.json"
export LEND_SILENT=true
alias ssh='lend ssh'

ssh -p 2222 -J bastion agent-vm
```

Set `LEND_PROFILE` to select a named policy. Use `command ssh` to bypass the alias.

## Request local execution

```text
lend exec [--socket PATH] [--reason TEXT] -- COMMAND [ARG...]
lend mcp [--socket PATH]
lend keys [--socket PATH]
```

These commands select `SSH_AUTH_SOCK` by default. On a remote host, it must point at the forwarded Lend proxy. `keys` can also inspect your original local agent while preparing a policy. `exec` returns the local command's exit status. A signal returns `128 + signal`. Approval, transport, and startup failures return 125.

The MCP command serves JSON-RPC over stdio and exposes `run_local_command`. See the [MCP guide](/mcp.html) for configuration and output limits.

## Request approval

```text
lend approve [--socket PATH] --topic NAME --title TEXT [--details TEXT | --details-file PATH] [--reason TEXT]
lend approve [--socket PATH] [--topic NAME] --hook claude-code|codex|agy|pi
lend approve [--socket PATH] --topic NAME --hook claude-compatible|json
```

`approve` asks the laptop for a decision and runs nothing there. It exits 0 when approved, 1 when refused, and 125 when it cannot reach a lend agent. `--hook` reads an agent's hook event from stdin and writes that agent's decision format. See [Agent approvals](/agent-approvals.html).

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
lend explain --config FILE [--profile NAME] --topic NAME
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
