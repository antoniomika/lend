---
title: Development
description: Build and check Lend and its documentation.
toc: true
---

## Checks

```sh
go test -race ./...
go vet ./...
```

`make check` also checks formatting and runs the installer and release packaging tests. GitHub CI runs on Linux and macOS, on both amd64 and arm64, and checks the minimum Go version on Linux. macOS CI builds the cgo backend against the native SDK. See [releasing](/releasing.html) for draft releases and the Homebrew tap workflow.

Tests cover profile isolation, exact lease scope, expiry and revocation, unavailable lock tracking, approval queue cancellation, credential injection and failures, persistent history and rotation, local controls, management permissions, secret redaction, private-key identity checks, packet clearing, caller display, spoofed metadata, binding hints, key filtering, signing policy and quotas, upstream denial, command policies, reason forwarding, MCP lifecycle and cancellation, output limits, streaming, argv handling, timeouts, framing limits, and socket directory checks. Plain key fingerprints are checked against `ssh-keygen`. Unix socket, peer credential, and OpenSSH agent integration tests skip when the environment denies socket creation. Native macOS dialogs, authentication, and lock notifications need validation on a Mac with an interactive desktop session. Desktop lock integration and the complete SSH wrapper lifecycle also need validation on unrestricted desktop hosts.

The transport and execution packages have in-memory tests, so the core tests can also run in restricted environments. See [the protocol](/protocol.html) for the experimental wire format.

## Documentation

```sh
make docs-check
make docs-serve
```

The site uses pdocs, as the sish docs do. Markdown guides live in `docs/posts`, Go templates in `docs/tmpl`, and local assets in `docs/static`. The generator also reads `docs/protocol.md`, `docs/releasing.md`, and the JSON examples. The separate `docs/go.mod` keeps documentation dependencies out of Lend's CLI module.

`make ssg` builds static output in `docs/public`. `make docs-serve` builds and serves it at `http://127.0.0.1:3000`. Restart the command after editing a source file. `make docs-check` builds the site, vets the generator, and checks local links, fragments, assets, and example JSON. The documentation workflow runs these checks separately from binary CI and uploads the output as an artifact.

The [docs authoring guide](https://github.com/antoniomika/lend/blob/main/docs/README.md) describes navigation and the manual pgs.sh publishing workflow.
