---
title: Command policy
description: Choose local executables, argument prefixes, and approval requirements.
---

## Allow selected commands

Start the laptop agent with either `--config FILE` or `--allow-all`. A config defaults to denying unlisted commands, SSH keys, and management operations. `--allow-all` permits any executable, SSH key, and supported management operation while keeping approval for each request.

[examples/policy.json](/examples/policy.json) allows `op read` with biometric approval and `gh pr view` with a confirmation prompt. It includes rules for SSH authentication, Git signing, adding or removing the selected key, and locking or unlocking the agent. Copy it to a local policy file, set the executable paths for your laptop, and replace the key fingerprint. Inspect executable paths with `command -v op` and `command -v gh`, and list fingerprints with `lend keys` while `SSH_AUTH_SOCK` points at the original agent.

```json
{
  "default": "deny",
  "require_reason": true,
  "commands": [
    {
      "executable": "/opt/homebrew/bin/op",
      "args_prefix": ["read"],
      "approval": "biometric"
    },
    {
      "executable": "/opt/homebrew/bin/gh",
      "args_prefix": ["pr", "view"],
      "approval": "prompt"
    }
  ],
  "ssh": {
    "default": "deny",
    "keys": [
      {
        "fingerprint": "SHA256:REPLACE_WITH_FINGERPRINT_FROM_LEND_KEYS",
        "label": "SSH login and Git signing",
        "approval": "biometric",
        "purposes": ["ssh", "sshsig"],
        "namespaces": ["git"],
        "max_signatures": 10
      }
    ]
  }
}
```

Executable paths are absolute and resolved through symlinks when loading the policy and when receiving a request. A matched rule runs the program with its configured path as `argv[0]`, so a multi-call binary behaves as the alias you allowed. Prefixes match complete arguments: `["pr", "view"]` allows further arguments after those two. The longest matching prefix determines approval. An omitted prefix permits every argument to that executable. Duplicate rules and unknown config fields are rejected. Policy changes take effect after restarting the agent.

| Approval | Requirement |
| --- | --- |
| auto | Platform default: macOS device authentication or a Linux prompt |
| prompt | Explicit local confirmation |
| authenticate | macOS device owner authentication, which can use a password |
| biometric | macOS biometric authentication with no password fallback |

`authenticate` and `biometric` requests fail on Linux, in macOS builds without cgo, and when using `--approval=terminal`. A biometric request also fails when biometry is unavailable, unenrolled, or locked out. The remote caller cannot select a weaker approval requirement. Every command needs local approval or an explicitly approved lease for its scope.

Set `"default": "allow"` and `"default_approval": "biometric"` to permit every command with biometric approval. `require_reason` requires a nonempty requester-supplied reason for both CLI and MCP calls. Reasons are displayed as untrusted text and do not establish identity or change policy.

Argument prefixes control which command requests are admitted. They do not restrict the capabilities of an approved executable. Further arguments, configuration files, plugins, and stdin can affect what it does. Every admitted request still receives its required approval.
