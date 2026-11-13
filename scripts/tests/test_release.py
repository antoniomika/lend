import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("release", ROOT / "scripts/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_formula_and_manifest_reference_all_four_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            for system, architecture in release.PLATFORMS:
                (destination / release.archive_name("v1.2.3", system, architecture)).write_bytes(f"{system}/{architecture}".encode())
            release.finalize("v1.2.3", destination)
            formula = (destination / "lend.rb").read_text()
            for system, architecture in release.PLATFORMS:
                name = release.archive_name("v1.2.3", system, architecture)
                self.assertIn(f"/releases/download/v1.2.3/{name}", formula)
                self.assertIn(release.checksum(destination / name), formula)
            self.assertNotIn("no_check", formula)
            entries = (destination / "checksums.txt").read_text().splitlines()
            self.assertEqual(len(entries), 6)
            for line in entries:
                digest, name = line.split()
                self.assertEqual(digest, release.checksum(destination / name))
            if shutil.which("ruby"):
                subprocess.run(["ruby", "-c", str(destination / "lend.rb")], check=True, capture_output=True)

    def test_missing_archives_and_invalid_versions_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                release.finalize("v1.2.3", Path(directory))
        for version in ("latest", "../v1.2.3", "v1.2.3\nunsafe", "v1.2.3;false", "v1.2"):
            with self.assertRaises(ValueError):
                release.release_version(version)

    def test_release_archive_runs_with_embedded_version(self):
        system = "darwin" if sys.platform == "darwin" else "linux"
        architecture = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine()]
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"LEND_COMMIT": "a" * 40, "LEND_DATE": "2026-01-01T00:00:00Z"}):
            archive = release.build("v1.2.3", system, architecture, Path(directory))
            with tarfile.open(archive, "r:gz") as source:
                self.assertEqual(source.getnames().count("lend"), 1)
                self.assertEqual(source.getmember("lend").mode, 0o755)
                self.assertTrue(all(member.isfile() for member in source.getmembers()))
                binary = Path(directory) / "lend"
                binary.write_bytes(source.extractfile("lend").read())
            binary.chmod(0o755)
            info = json.loads(subprocess.check_output([str(binary), "version", "--json"], text=True))
            self.assertEqual(info["version"], "v1.2.3")
            self.assertEqual(info["commit"], "a" * 40)
            self.assertEqual(info["os"], system)
            self.assertEqual(info["arch"], architecture)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.tools = self.directory / "tools"
        self.tools.mkdir()
        self.destination = self.directory / "installation with spaces"
        self.environment = dict(os.environ, PATH=str(self.tools) + os.pathsep + os.environ["PATH"], FIXTURE_DIRECTORY=str(self.directory), FIXTURE_SYSTEM="Linux", FIXTURE_ARCH="x86_64")
        self.executable("uname", "#!/bin/sh\ncase \"$1\" in -s) printf '%s' \"$FIXTURE_SYSTEM\" ;; -m) printf '%s' \"$FIXTURE_ARCH\" ;; esac\n")
        self.executable("curl", f"#!{sys.executable}\n" + '''import os, pathlib, shutil, sys
args = sys.argv[1:]
assert "--proto" in args and "=https" in args and "--tlsv1.2" in args
url = args[-1]
root = pathlib.Path(os.environ["FIXTURE_DIRECTORY"])
if url.endswith("/latest"):
    print("https://github.com/antoniomika/lend/releases/tag/v1.2.3", end="")
else:
    source = root / url.rsplit("/", 1)[-1]
    if not source.is_file():
        sys.exit(22)
    shutil.copyfile(source, args[args.index("--output") + 1])
''')
        self.archive = self.directory / "lend_1.2.3_linux_amd64.tar.gz"
        self.write_archive()

    def executable(self, name, content):
        path = self.tools / name
        path.write_text(content)
        path.chmod(0o755)

    def write_archive(self, duplicate=False):
        with tarfile.open(self.archive, "w:gz") as archive:
            for _ in range(2 if duplicate else 1):
                binary = b"#!/bin/sh\nprintf 'fixture binary\\n'\n"
                info = tarfile.TarInfo("lend")
                info.size = len(binary)
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(binary))
        self.manifest = self.directory / "checksums.txt"
        self.manifest.write_text(f"{hashlib.sha256(self.archive.read_bytes()).hexdigest()}  {self.archive.name}\n")

    def install(self, *arguments):
        return subprocess.run(["sh", str(ROOT / "install.sh"), "--dir", str(self.destination), *arguments], env=self.environment, text=True, capture_output=True, timeout=10)

    def old_installation(self):
        self.destination.mkdir()
        (self.destination / "lend").write_bytes(b"existing installation")

    def assert_old_installation_unchanged(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.destination / "lend").read_bytes(), b"existing installation")

    def test_latest_and_pinned_installation(self):
        for arguments in ((), ("--version", "v1.2.3")):
            result = self.install(*arguments)
            self.assertEqual(result.returncode, 0, result.stderr)
            binary = self.destination / "lend"
            self.assertTrue(os.access(binary, os.X_OK))
            self.assertIn("fixture binary", subprocess.check_output([str(binary)], text=True))
            self.assertEqual(list(self.destination.glob(".lend.*")), [])

    def test_checksum_mismatch_does_not_replace_existing_binary(self):
        self.old_installation()
        self.archive.write_bytes(b"corrupt download")
        self.assert_old_installation_unchanged(self.install())

    def test_missing_and_duplicate_checksums_are_refused(self):
        self.old_installation()
        valid = self.manifest.read_text()
        for content in ("", valid + valid):
            self.manifest.write_text(content)
            self.assert_old_installation_unchanged(self.install())

    def test_duplicate_archive_members_are_refused(self):
        self.old_installation()
        self.write_archive(duplicate=True)
        self.assert_old_installation_unchanged(self.install())

    def test_macos_arm64_asset_selection(self):
        self.environment.update(FIXTURE_SYSTEM="Darwin", FIXTURE_ARCH="arm64")
        target = self.directory / "lend_1.2.3_darwin_arm64.tar.gz"
        self.archive.rename(target)
        self.manifest.write_text(f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {target.name}\n")
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_explicit_prerelease_installation(self):
        target = self.directory / "lend_1.2.3-rc.1_linux_amd64.tar.gz"
        self.archive.rename(target)
        self.manifest.write_text(f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {target.name}\n")
        result = self.install("--version", "v1.2.3-rc.1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unsupported_platform_and_invalid_version_are_refused(self):
        self.environment["FIXTURE_ARCH"] = "mips"
        self.assertNotEqual(self.install().returncode, 0)
        self.environment["FIXTURE_ARCH"] = "x86_64"
        self.assertNotEqual(self.install("--version", "../../untrusted").returncode, 0)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
