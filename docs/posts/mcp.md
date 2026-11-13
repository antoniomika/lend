---
title: MCP
description: Give a remote coding agent a tool for requesting local commands.
toc: true
---

## Connect a client

Run `lend mcp` as a stdio MCP server inside the remote SSH session. It reads `SSH_AUTH_SOCK` from its environment, or accepts `--socket PATH`. The agent client must launch it with access to the current forwarded socket.

For an MCP client using a `mcpServers` configuration:

```json
{
  "mcpServers": {
    "laptop": {
      "command": "lend",
      "args": ["mcp"]
    }
  }
}
```

The server exposes one tool, `run_local_command`:

```json
{
  "args": ["gh", "pr", "view", "123", "--repo", "example/project"],
  "reason": "Inspect this pull request before preparing a review"
}
```

The reason is required for MCP calls and appears in the laptop approval prompt beside caller context. The bridge attaches caller information from its process and the MCP handshake; caller fields are not tool arguments. Optional `stdin` accepts up to 64 KiB of UTF-8 input. Results include the exit code and separate stdout and stderr, each capped at 64 KiB with an explicit truncation flag. Binary output uses base64. Command failure or refusal sets the MCP result's `isError` field. Cancelling the tool or closing the MCP session closes its command channel.

The MCP adapter supports the initialization-based stdio protocol revisions `2025-11-25` and `2025-06-18`. It does not implement the newer per-request metadata protocol, HTTP transports, resources, or prompts. It emits JSON-RPC exclusively on stdout. CLI and MCP requests use the same laptop policy and approval path.
