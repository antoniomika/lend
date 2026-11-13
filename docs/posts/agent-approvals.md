---
title: Agent approvals
description: Answer coding agent permission prompts and script gates from your laptop.
---

## Approval requests

An approval request asks the laptop for a decision and runs nothing there. The remote side sends a topic, a title, optional details, and an optional reason. lend shows them in the same dialog as other requests, with the approval the topic requires, and returns approved or refused.

Topics are listed in the policy's `approvals` section. Unlisted topics are refused without a prompt unless `default` is `allow`:

```json
{
  "approvals": {
    "topics": [
      {"name": "claude-code", "approval": "biometric:inline"},
      {"name": "codex", "approval": "biometric:inline"},
      {"name": "agy", "approval": "biometric:inline"},
      {"name": "pi", "approval": "biometric:inline"},
      {"name": "deploy", "approval": "biometric"}
    ]
  }
}
```

`default_approval` sets the approval for unlisted topics when `default` is `allow`. Topic names use letters, digits, `-`, and `_`, up to 64 characters. `--allow-all` admits every topic with platform-default approval. `lend explain --config ./policy.json --topic deploy` shows what a topic requires.

## Scripts

`lend approve` exits 0 when approved, 1 when refused, denied, or expired, and 125 when it cannot reach a lend agent:

```sh
lend approve --topic deploy --title "terraform apply (staging)" --details-file plan.txt && terraform apply plan.out
```

`--details` takes text and `--details-file` takes a path, or `-` for stdin. Titles are limited to 256 bytes and details to 32 KiB.

## Coding agent hooks

`lend approve --hook NAME` reads a hook event on stdin, asks the laptop, and writes the decision in that agent's format. The topic defaults to the hook name; `--topic` overrides it. The dialog shows the working directory, the full command when the tool has one, and the rest of the tool input as JSON. Single-line values such as paths and URLs are always shown in full. Multi-line strings longer than 2 KiB, such as file contents and patches, are shortened and marked with the number of bytes left out. A command longer than 16 KiB, or input that is still over 32 KiB after shortening, is denied without a prompt.

If lend cannot reach the laptop, the hook makes no decision and the agent's own permission flow applies. A refused topic, a denial, an expired prompt, a request revoked or paused with `lend revoke` or `lend pause`, and malformed hook input all deny the tool call.

### Claude Code

The `PermissionRequest` hook runs only when Claude Code would otherwise ask you. Add it to `~/.claude/settings.json` or a project's `.claude/settings.json`:

```json
{
  "hooks": {
    "PermissionRequest": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "lend approve --hook claude-code"}]}
    ]
  }
}
```

The adapter also accepts `PreToolUse`, which asks for every matching tool call.

### Codex

Codex uses the same `PermissionRequest` event. Add it to `~/.codex/hooks.json` with hooks enabled, then review and trust it in `/hooks`:

```json
{
  "hooks": {
    "PermissionRequest": [
      {"hooks": [{"type": "command", "command": "lend approve --hook codex", "timeout": 120}]}
    ]
  }
}
```

With `PreToolUse`, an approval returns no output because Codex does not accept an allow decision there, and the tool call continues through Codex's normal permission checks.

### Antigravity

agy has no permission request event, so the adapter uses `PreToolUse` and asks for every tool call its matcher selects. Add it to `~/.gemini/config/hooks.json` or a workspace's `.agents/hooks.json`. agy's default hook timeout is 30 seconds, which is shorter than lend's approval timeout:

```json
{
  "lend": {
    "PreToolUse": [
      {"matcher": "run_command", "hooks": [{"type": "command", "command": "lend approve --hook agy", "timeout": 90}]}
    ]
  }
}
```

An approval returns `auto_approve`, which skips agy's prompt and still honors your explicit agy deny rules. A denial returns `deny`. When lend cannot decide, the adapter returns `ask`. Older agy releases that predate `auto_approve` treat `allow` as approval; update agy before using this adapter.

### pi

pi has no permission prompt, so [examples/pi/lend-approval.ts](/examples/pi/lend-approval.ts) is an extension that asks lend before `bash`, `write`, and `edit` calls. It sends lend's JSON hook format with the topic `pi`. Copy it to `~/.pi/agent/extensions/` and edit `GATED_TOOLS` to choose tools. When lend cannot reach the laptop, the extension asks in pi's own UI, or blocks the call when pi has no UI.

### Other agents

`--hook claude-compatible` reads and writes the Claude Code hook format for agents that copy it. `--hook json` reads lend's own format and answers with the exit status: 0 approved, 1 denied, and 125 when lend cannot reach the laptop. Both need `--topic`.

```json
{"agent": "my-agent", "tool": "deploy", "input": {"service": "api"}, "cwd": "/work"}
```

`tool` is required. `agent` names the agent in the dialog title and defaults to the topic. `input` is any JSON value and is shown like other tool input. Unknown fields deny the request, so a misspelled field fails visibly. An agent with a scriptable hook can reshape its own input into this format, for example with `jq`, and map the exit status to its decision:

```sh
jq '{agent: "my-agent", tool: .tool_name, input: .arguments, cwd: .cwd}' | lend approve --hook json --topic my-agent
```

## Trust

The answer only decides what the requester does with it. A hook is only as strong as the agent's hook configuration: an agent that can edit its settings or start processes without hooks can bypass it. Use command rules when an action should run on the laptop under its policy.

Hooks run in the agent's environment and use its `SSH_AUTH_SOCK`. An agent started under an earlier SSH session can hold a stale socket path; point `--socket` at a stable path in that case. Titles, details, and reasons are requester supplied. The dialog labels them and escapes control and non-ASCII characters. History records the topic and outcome, never the title or details.
