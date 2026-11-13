---
title: Installation
description: Install Lend on your laptop and remote hosts.
---

## Install

Homebrew on macOS or Linux:

```sh
brew install antoniomika/tap/lend
```

Install the latest binary into `~/.local/bin`:

```sh
curl -fsSL https://github.com/antoniomika/lend/releases/latest/download/install.sh | sh
```

Choose a version and installation directory:

```sh
curl -fsSL https://github.com/antoniomika/lend/releases/latest/download/install.sh \
  | sh -s -- --version v0.0.2 --dir "$HOME/.local/bin"
```

The installer selects macOS or Linux and amd64 or arm64, verifies the archive's SHA256 checksum, and replaces the binary only after verification. It requires curl, tar, and either `sha256sum` or `shasum`. It uses no sudo and does not edit shell configuration. Add `~/.local/bin` to your `PATH` if needed. Run the same installer to upgrade, or use `brew upgrade antoniomika/tap/lend` for a Homebrew installation.

Release archives and `checksums.txt` are also available on the GitHub release page for manual installation. macOS release binaries include native approval and require macOS 13 or later. Linux binaries have no Go runtime dependency. Install the binary on both the laptop and remote hosts, then check it:

```sh
lend version
lend doctor --remote
```

Use `doctor --remote` on a remote host after forwarding the laptop's lend proxy. Use the local checks below on the laptop.

## Build from source

Requires Go 1.24 or later. There are no Go module dependencies.

```sh
go build -buildvcs=false -o bin/lend ./cmd/lend
```

Build on macOS with cgo enabled and the Xcode Command Line Tools installed to include native approval:

```sh
CGO_ENABLED=1 go build -buildvcs=false -o bin/lend ./cmd/lend
```

Build the same program on the remote host, or cross-compile a Linux client:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -o bin/lend-linux-amd64 ./cmd/lend
```

Use `GOARCH=arm64` for an ARM Linux host. Put the corresponding binary on each machine's `PATH`.

`make build` builds the local binary. Go is needed only to build from source. Python 3 is used by the maintainer's packaging and installer tests.
