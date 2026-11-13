# Releasing

CI and publishing are separate workflows.

## CI

`.github/workflows/ci.yml` checks pull requests and pushes to `main`. It runs formatting, vet, race tests, a binary build, and installer and packaging tests on Linux and macOS, on amd64 and arm64. A Linux job also checks Go 1.24, the module's minimum version. `make check` runs the local equivalent with Go, Python 3, and a POSIX shell.

The installer tests use local download fixtures. They exercise platform selection, pinned versions, checksum failures, duplicate entries, and installation paths with spaces. Packaging tests build a local release archive and verify its embedded version. These tests contact no release endpoints.

## Release artifacts

Publishing a GitHub release starts `.github/workflows/release.yml`. `gh release create` publishes the release and creates its tag in one step:

```sh
gh release create v0.1.0 --target main --title v0.1.0 --notes-file docs/release-notes.md
```

Tags must use `vMAJOR.MINOR.PATCH` with an optional prerelease suffix. The workflow validates the tag and builds the tagged commit on four native runners:

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

The upload job attaches these files to the published release, replacing any assets with the same names. A release published without notes gets the text in [release-notes.md](release-notes.md). The release exists before its assets do, so the curl installer and Homebrew fail for that release until the upload finishes. To rebuild a published release, run the Release workflow manually with its tag. Build artifacts remain available in Actions for seven days.

The built-in `GITHUB_TOKEN` is enough to upload assets in this repository. Only the upload job requests contents write permission. A release created by another workflow's `GITHUB_TOKEN` does not start this workflow, so publish releases with your own credentials. The source repository must be public for the documented anonymous curl installer to download releases.

## Homebrew setup

The default tap is `antoniomika/homebrew-tap`. Create that public repository with an initial default branch. If using another tap, set this repository's `HOMEBREW_TAP` Actions variable to the full repository name, including its `homebrew-` prefix.

Set `HOMEBREW_TAP_TOKEN` as an Actions secret in this repository. Use a fine-grained token with contents write access to the tap repository. The default `GITHUB_TOKEN` cannot write to a separate tap repository. See GitHub's [Actions secrets documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets) and Homebrew's [tap documentation](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap).

After uploading a stable release's assets, the Release workflow calls `.github/workflows/homebrew.yml`. It downloads the published formula, checks its checksum and Ruby syntax, then pushes one commit updating `Formula/lend.rb` in the tap. The commit subject is `chore(homebrew): update lend TAG`. Prereleases skip this step, and the Homebrew workflow refuses drafts and prereleases. To update the tap again for an existing release, run **Update Homebrew tap** manually with its tag. The workflow does not create the tap or a pull request.

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
