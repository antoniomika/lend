---
title: SSH keys
description: Filter upstream identities and approve signing with individual key rules.
toc: true
---

## Allow selected keys

The `ssh` section uses the same approval modes as command rules. Its default is `deny`, independently of the command policy's default. A missing `ssh` section exposes no keys and refuses all signatures. Each allowed signature needs fresh lend approval or a valid local lease. Upstream approval caching does not satisfy lend approval.

Before starting the proxy, inspect the original agent:

```sh
lend keys --socket "$SSH_AUTH_SOCK"
```

Each line shows a fingerprint, key type, and escaped upstream comment. Copy the fingerprint into a key rule. Key selection uses the fingerprint of the exact public key blob supplied by the agent. Comments are not used for authorization. Plain key fingerprints match OpenSSH SHA256 fingerprints. Certificate blobs have their own fingerprints and require separate rules, so use `lend keys` for certificates too.

| Key field | Meaning |
| --- | --- |
| fingerprint | Exact SHA256 fingerprint to expose and authorize |
| label | Local name displayed during approval |
| approval | Required local approval mode |
| purposes | Allowed signing formats, defaults to SSH authentication |
| namespaces | Allowed SSHSIG namespaces, defaults to all |
| max_signatures | Successful signatures allowed per daemon run, zero means unlimited |
| lease | Optional duration and use limit offered during local approval |

Purposes are `ssh` for a structurally valid SSH user authentication payload, `sshsig` for an SSHSIG signing payload, and `raw` for other data. An SSH authentication payload must contain the same key as the signing request. A Git-only signing key can use `"purposes": ["sshsig"]` and `"namespaces": ["git"]`. A namespace restriction requires the `sshsig` purpose and applies to those signatures. The namespace alone does not restrict other explicitly enabled purposes.

The signature cap is shared across connections and reserves capacity while approval is pending. Local denials and upstream signing failures release the reservation. A valid signature returned by the upstream agent consumes one use, even if the remote client disconnects before receiving it. Restarting lend resets the counters. These counters are held in memory.

Unlisted keys are removed from identity listings, and direct signing requests for their blobs are refused. Management operations require their own permissions described below. Legacy agent operations and unknown extensions are refused. OpenSSH session binding messages continue on the same upstream connection as listing, signing, and management requests, preserving its existing restrictions.

To allow every upstream key with biometric approval, use `"ssh": {"default": "allow", "default_approval": "biometric"}`. Explicit key rules still apply to matching fingerprints. Key policies govern requests made through this proxy. They do not change the original agent's socket or the restrictions it enforces.
