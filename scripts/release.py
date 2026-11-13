#!/usr/bin/env python3
"""Build release archives and generate their checksums and Homebrew formula."""

import argparse
import datetime
import gzip
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "antoniomika/lend"
PLATFORMS = (("darwin", "amd64"), ("darwin", "arm64"), ("linux", "amd64"), ("linux", "arm64"))


def release_version(value):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?", value):
        raise ValueError("version must be a release tag such as v0.1.0")
    return value


def archive_name(version, system, architecture):
    release_version(version)
    if (system, architecture) not in PLATFORMS:
        raise ValueError("unsupported release platform")
    return f"lend_{version[1:]}_{system}_{architecture}.tar.gz"


def build(version, system, architecture, destination):
    name = archive_name(version, system, architecture)
    if system == "darwin" and os.uname().sysname != "Darwin":
        raise ValueError("macOS releases must be built on macOS with its native SDK")
    commit = os.environ.get("LEND_COMMIT", "unknown")
    if not re.fullmatch(r"(?:unknown|[0-9a-f]{7,64})", commit):
        raise ValueError("LEND_COMMIT must be a hexadecimal commit ID")
    date = os.environ.get("LEND_DATE", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    if not re.fullmatch(r"[0-9T:Z+.-]+", date):
        raise ValueError("LEND_DATE must be an ISO timestamp")
    destination.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, GOOS=system, GOARCH=architecture, CGO_ENABLED="1" if system == "darwin" else "0")
    if system == "darwin":
        environment["MACOSX_DEPLOYMENT_TARGET"] = "13.0"
    info = "github.com/antoniomika/lend/internal/buildinfo"
    flags = f"-s -w -X {info}.Version={version} -X {info}.Commit={commit} -X {info}.Date={date}"
    with tempfile.TemporaryDirectory(prefix="lend-release-") as directory:
        binary = Path(directory) / "lend"
        subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags", flags, "-o", str(binary), "./cmd/lend"], cwd=ROOT, env=environment, check=True)
        files = [(binary, "lend"), (ROOT / "README.md", "README.md")]
        files += [(ROOT / "examples" / name, f"examples/{name}") for name in ("policy.json", "profiles.json")]
        with (destination / name).open("wb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w") as archive:
                    for path, member in files:
                        entry = tarfile.TarInfo(member)
                        entry.size = path.stat().st_size
                        entry.mode = 0o755 if member == "lend" else 0o644
                        with path.open("rb") as content:
                            archive.addfile(entry, content)
    return destination / name


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def formula(version, digests):
    release_version(version)
    lines = ["class Lend < Formula", '  desc "Approve remote requests for local commands and SSH keys"',
             f'  homepage "https://github.com/{REPOSITORY}"', f'  version "{version[1:]}"', ""]
    for system in ("darwin", "linux"):
        lines.append(f"  on_{'macos' if system == 'darwin' else 'linux'} do")
        if system == "darwin":
            lines.append("    depends_on macos: :ventura")
        for architecture, condition in (("arm64", "arm"), ("amd64", "intel")):
            name = archive_name(version, system, architecture)
            lines += [f"    on_{condition} do", f'      url "https://github.com/{REPOSITORY}/releases/download/{version}/{name}"',
                      f'      sha256 "{digests[name]}"', "    end"]
        lines += ["  end", ""]
    lines += ["  def install", '    bin.install "lend"', '    (pkgshare/"examples").install Dir["examples/*"]', "  end", "",
              "  test do", f'    assert_match "{version}", shell_output("#{{bin}}/lend version")', "  end", "end", ""]
    return "\n".join(lines)


def finalize(version, destination):
    names = [archive_name(version, *platform) for platform in PLATFORMS]
    missing = [name for name in names if not (destination / name).is_file()]
    if missing:
        raise ValueError("missing release archives: " + ", ".join(missing))
    digests = {name: checksum(destination / name) for name in names}
    (destination / "lend.rb").write_text(formula(version, digests))
    shutil.copyfile(ROOT / "install.sh", destination / "install.sh")
    names += ["lend.rb", "install.sh"]
    (destination / "checksums.txt").write_text("".join(f"{checksum(destination / name)}  {name}\n" for name in sorted(names)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "finalize"))
    parser.add_argument("--version", required=True, type=release_version)
    parser.add_argument("--os", choices=("darwin", "linux"))
    parser.add_argument("--arch", choices=("amd64", "arm64"))
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    arguments = parser.parse_args()
    try:
        if arguments.action == "build":
            if not arguments.os or not arguments.arch:
                parser.error("build requires --os and --arch")
            print(build(arguments.version, arguments.os, arguments.arch, arguments.dist.resolve()))
        else:
            finalize(arguments.version, arguments.dist.resolve())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"release: {error}\n")


if __name__ == "__main__":
    main()
