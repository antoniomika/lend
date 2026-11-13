---
title: Doctor
description: Check local setup and forwarded sockets without requesting access.
---

## Local and remote checks

On the laptop:

```sh
lend doctor --config ./policy.json
lend doctor --config ./profiles.json --profile development
lend doctor --config ./policy.json --approval terminal --json
```

Doctor checks policy parsing, configured executables, the local working directory, upstream socket access, available upstream identities, proxy extension support, socket permissions, the local approval backend, required device authentication or biometrics, and history paths. If the policy enables leases, it also checks desktop lock tracking. `--upstream PATH`, `--socket PATH`, and `--dir PATH` select the locations to inspect. `--timeout` bounds each socket or desktop probe.

On a remote host:

```sh
lend doctor --remote
```

Remote mode reads `SSH_AUTH_SOCK`, or an explicit `--socket PATH`, and checks that the forwarded agent advertises the lend execution extension. It skips laptop policy and desktop checks, so it works on a headless VM without local credentials or a desktop session.

Doctor does not execute configured tools, fetch credential values, request signatures, open lend approval dialogs, create directories, or change agent state. Backend detection cannot prove that a future approval will succeed. Config checks use the file on disk; a running daemon keeps its loaded policy until restarted. Text and JSON reports use `ok`, `warn`, and `error`. Exit status is 0 with no errors, 1 when a check fails, and 2 for invalid command-line arguments. A stopped local proxy is a warning so you can check setup before starting it.
