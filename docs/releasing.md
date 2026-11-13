# Releasing

CI and publishing are separate workflows. Nothing has been published by preparing these files.

## CI

`.github/workflows/ci.yml` checks pull requests and pushes to `main`. It runs formatting, vet, race tests, a binary build, and installer and packaging tests on Linux and macOS, on amd64 and arm64. A Linux job also checks Go 1.24, the module's minimum version. `make check` runs the local equivalent with Go, Python 3, and a POSIX shell.

The installer tests use local download fixtures. They exercise platform selection, pinned versions, checksum failures, duplicate entries, and installation paths with spaces. Packaging tests build a local release archive and verify its embedded version. These tests contact no release endpoints.

## Release artifacts

`.github/workflows/release.yml` runs when a `v*` tag is pushed, or when manually dispatched for an existing tag. Tags must use `vMAJOR.MINOR.PATCH` with an optional prerelease suffix. The workflow validates the tag and builds the same commit on four native runners:

| Platform | Architecture | Build |
| --- | --- | --- |
| macOS | arm64 | Native SDK with cgo |
| macOS | amd64 | Native SDK with cgo |
| Linux | arm64 | Static Go binary |
| Linux | amd64 | Static Go binary |

The macOS deployment target is 13.0. Developer ID signing and notarization are not configured. CI can compile and test the backend; Touch ID and desktop lock integration still need an interactive desktop validation run.

Each archive is named `lend_VERSION_OS_ARCH.tar.gz` and contains the binary, README, and policy examples. The binary reports the version, commit, and build date through `lend version --json`. The workflow also generates:

- `checksums.txt` with SHA256 digests.
- `install.sh` for user-directory installation with curl.
- `lend.rb` with pinned release URLs and checksums for the Homebrew tap.

The final job creates a draft release with the text in [release-notes.md](release-notes.md). Tags with prerelease suffixes are also marked as prereleases. Review the text and assets, then publish the draft in GitHub. The workflow does not publish the draft or modify an existing release. A rerun for an existing draft fails at release creation; review or remove the old draft before retrying. Build artifacts remain available in Actions for seven days.

The built-in `GITHUB_TOKEN` is enough to create a draft in this repository. Only the draft job requests contents write permission. The source repository must be public for the documented anonymous curl installer to download releases.

## Homebrew setup

The default tap is `antoniomika/homebrew-tap`. Create that public repository with an initial default branch. If using another tap, set this repository's `HOMEBREW_TAP` Actions variable to the full repository name, including its `homebrew-` prefix.

Set `HOMEBREW_TAP_TOKEN` as an Actions secret in this repository. Use a fine-grained token with contents write access to the tap repository. The default `GITHUB_TOKEN` cannot write to a separate tap repository. See GitHub's [Actions secrets documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets) and Homebrew's [tap documentation](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap).

After publishing a stable release, review its `lend.rb` asset. Manually run **Update Homebrew tap** with that release tag. This workflow downloads the published formula, checks its checksum and Ruby syntax, then pushes one commit updating `Formula/lend.rb` in the tap. The commit subject is `chore(homebrew): update lend TAG`. Drafts and prereleases are refused. The workflow does not create the tap or a pull request.

After that first update, users can run:

```sh
brew install antoniomika/tap/lend
brew upgrade antoniomika/tap/lend
```

To update the tap manually, copy the reviewed `lend.rb` asset to `Formula/lend.rb` in the tap checkout. No token is needed in this repository when maintaining the tap manually.

## Local packaging

Build an archive for the current platform:

```sh
python3 scripts/release.py build --version v0.1.0 \
  --os "$(go env GOOS)" --arch "$(go env GOARCH)"
```

macOS archives require a Mac with the Xcode Command Line Tools. Linux archives can also be cross-built. Once all four archives are in `dist/`, generate the formula, installer, and checksums:

```sh
python3 scripts/release.py finalize --version v0.1.0
```

`LEND_COMMIT` and `LEND_DATE` optionally set build metadata. The release workflow supplies them from the validated tag commit. Local builds use `unknown` for the commit and the current UTC time for the date.
