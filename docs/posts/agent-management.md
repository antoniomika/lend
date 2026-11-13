---
title: Agent management
description: Approve changes to your upstream SSH agent.
toc: true
---

## Management policy

The `ssh.management` section controls changes to the original agent. It defaults to `deny` independently of command and signing defaults. Each permitted operation requires the same local approval modes used for commands and signatures.

```json
{
  "ssh": {
    "management": {
      "default": "deny",
      "operations": [
        {"operation": "add-key", "approval": "biometric"},
        {"operation": "remove-key", "approval": "biometric"},
        {"operation": "remove-all-keys", "approval": "biometric"},
        {"operation": "lock", "approval": "prompt"},
        {"operation": "unlock", "approval": "biometric"},
        {
          "operation": "add-provider",
          "approval": "biometric",
          "providers": ["/example/provider.so"]
        },
        {
          "operation": "remove-provider",
          "approval": "biometric",
          "providers": ["/example/provider.so"]
        }
      ]
    }
  }
}
```

Add this section to your local policy and use provider identifiers appropriate for your upstream agent. `providers` matches exact identifiers; it does not expand globs or resolve filesystem aliases. For OpenSSH these identifiers usually name provider libraries. Provider loading can load local code and expose multiple keys.

| Operation | Effect on the upstream agent |
| --- | --- |
| add-key | Add a key or replace its existing constraints |
| remove-key | Remove the selected key |
| remove-all-keys | Remove every key, including keys hidden by lend |
| lock | Lock the shared agent with a requester-supplied passphrase |
| unlock | Unlock the shared agent with a requester-supplied passphrase |
| add-provider | Load a provider or token's keys |
| remove-provider | Remove keys associated with a provider or token |

`add-key` and `remove-key` rules can include a `fingerprints` array to select exact keys. The example policy demonstrates this. An omitted array permits any target for that operation, subject to approval. Fingerprint selectors are rejected on operations such as `remove-all-keys` because those operations affect the entire agent. Add-key rules can also restrict requested security-key provider identifiers with `providers`. Provider selectors apply when a request explicitly specifies a provider; plain key imports remain eligible for the rule.

One rule is allowed per operation. A rule that rejects a fingerprint or provider does not fall back to the management default. To allow all supported management operations with biometric approval, set `"management": {"default": "allow", "default_approval": "biometric"}` inside `ssh`. The `--allow-all` flag also enables management with platform-default approval.

Management prompts show the operation, target key fingerprint or provider identifier, requested lifetime, confirmation requirement, and recognized constraint extension names. Private keys, passphrases, PINs, and security-key handles are omitted from the approval context. Processed management packet buffers are cleared after forwarding or refusal. Caller and connection context appear when available.

Management permissions are separate from key-use permissions. Adding a key does not admit it for listing or signing through lend; its `ssh.keys` rule or signing default still applies. Removing and re-adding a key does not reset lend's signature counters. Changes affect the actual upstream agent and its other local or forwarded users.

Key loading supports RSA, Ed25519, the NIST P-256/P-384/P-521 ECDSA curves, DSA, OpenSSH security-key formats, and their certificate variants. Software private keys are checked against their public components before selecting a fingerprint. Security-key handles remain opaque and are passed to the upstream agent. RSA integers are limited to 16384 bits, DSA moduli to 3072 bits, and DSA subgroup orders to 256 bits. Unsupported encodings and unknown constraint extensions are refused before approval. Supported constraints include lifetime, confirmation, `sk-provider@openssh.com`, `restrict-destination-v00@openssh.com`, and provider-associated certificates. Destination constraint contents and certificate signatures are validated by the upstream agent. Requests are forwarded unchanged after local approval.

The upstream agent remains responsible for supporting or rejecting management operations. Its own restrictions can refuse an approved request, including remote provider-loading restrictions. Use standard tools such as `ssh-add` through the proxy:

```sh
SSH_AUTH_SOCK="$HOME/.lend/agent.sock" ssh-add -t 1h /local/key
SSH_AUTH_SOCK="$HOME/.lend/agent.sock" ssh-add -d /local/key.pub
SSH_AUTH_SOCK="$HOME/.lend/agent.sock" ssh-add -x
```
