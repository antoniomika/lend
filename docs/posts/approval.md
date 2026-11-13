---
title: Approval and callers
description: Review requests on your laptop and understand the caller information shown.
toc: true
---

## Review each request

| Platform | auto approval |
| --- | --- |
| macOS | Native request review, then Touch ID or another method accepted by macOS device owner authentication |
| Linux desktop with Zenity | Local Allow once / Deny dialog |
| Linux without Zenity | Prompt in the agent's controlling terminal |

Command prompts show the resolved executable, every argument, and the local directory. SSH signing prompts show the key fingerprint, local label, key type, signing format, namespace, payload size, SHA256 payload digest, and signature flags. Management prompts show the operation and its target. SSH requests do not carry a requester-supplied reason or a verified destination name.

CLI and MCP command requests automatically include caller context. The remote lend process reports its hostname, user and UID, working directory, executable path, PID, parent PID, parent executable when available, and `SSH_CONNECTION` when set. MCP requests also include the client name and version from initialization, the tool name, and the request ID. Working directory and process details describe the remote lend process, including the MCP bridge when using MCP.

An example of the caller portion of an MCP approval prompt:

```text
Caller (requester supplied, unverified):
  Interface: "mcp"
  Host: "agent-vm"
  User: "user"
  Working directory: "/work/project"
  MCP client: "example-agent"
  MCP client version: "1"
  Tool: "run_local_command"
  Request ID: "7"
  PID: 123
  Parent PID: 12
```

Caller context is informational and cannot change command or key authorization. A remote process can spoof these fields, including the MCP client name. lend escapes their contents and labels them as requester supplied. Older clients and ordinary SSH signing requests show caller details as unavailable when no metadata is present. Process context collection reads selected metadata; it does not collect parent command arguments or a complete environment.

The laptop also inspects its connected Unix socket peer. Linux provides a connection-time PID and UID; macOS provides a PID. The prompt labels those as local kernel-reported credentials and shows a best-effort local process lookup separately. With SSH forwarding, this identifies the laptop's SSH process. It does not identify the remote process. Failed or unsupported peer inspection leaves the details unavailable.

For both commands and SSH signatures, up to eight session-binding host-key fingerprints are shown when the upstream agent accepted those bindings on that connection. They are labeled as session hints unverified by lend. They do not establish a destination name or authorize the caller. Refused bindings are omitted, and metadata is scoped to its connection.

Desktop prompts let you scroll through long requests. The Linux dialog requires checking the approval box before Allow once is enabled. Control characters and non-ASCII text are escaped so request fields cannot insert terminal controls or change the prompt's layout. Terminal approval requires typing the displayed `allow` phrase with its request code. Each request gets a different code to prevent stale input from approving another request.

macOS authentication uses a fresh `LAContext` for each request. Cancellation, authentication failure, and unavailable authentication deny the request. A macOS binary built without cgo requires `--approval=terminal` for `auto` or `prompt` rules. Linux biometric integration is outside this first version.

Use `lend agent --config ./policy.json --approval=terminal` to select terminal approval explicitly on either platform for `auto` or `prompt` rules. Approval reads the laptop's `/dev/tty`. The remote session cannot answer the prompt. Without a usable local desktop or controlling terminal, approval fails.

Each daemon queues commands, SSH signatures, and management requests behind one local approval dialog. The approval timeout includes queue time. Cancelled or disconnected requests leave the queue, and expired requests cannot reach the prompt. The server admits up to 32 socket connections; excess connections are refused. Approved commands can run concurrently while another request waits for approval. Approval expires after one minute and commands time out after five minutes. Both `lend agent` and `lend ssh` accept timeout overrides:

```sh
lend agent --config ./policy.json --approval-timeout=90s --command-timeout=10m
```

The socket lives in a directory owned by the laptop user with mode `0700`, and the socket has mode `0600`. The default is `$XDG_RUNTIME_DIR/lend/agent.sock` when `XDG_RUNTIME_DIR` is set, otherwise `~/.lend/agent.sock`. lend removes its socket on normal shutdown and refuses to replace any existing path. After a crash, verify the old agent has stopped before removing its stale socket.
