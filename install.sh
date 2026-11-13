#!/bin/sh
set -eu

fail() { printf 'lend install: %s\n' "$*" >&2; exit 1; }
usage() {
  printf '%s\n' 'Usage: sh install.sh [--version vX.Y.Z] [--dir PATH]' \
    'Installs a checksum-verified release into ~/.local/bin by default.'
}

version=latest
destination=${LEND_INSTALL_DIR:-${HOME:?HOME is unset}/.local/bin}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) [ "$#" -ge 2 ] || fail '--version needs a value'; version=$2; shift 2 ;;
    --dir) [ "$#" -ge 2 ] || fail '--dir needs a value'; destination=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done
[ -n "$destination" ] || fail 'install directory is empty'
for tool in curl tar awk grep mktemp chmod mv; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
case "$(uname -s)" in
  Darwin) system=darwin ;;
  Linux) system=linux ;;
  *) fail 'only macOS and Linux are supported' ;;
esac
case "$(uname -m)" in
  x86_64|amd64) architecture=amd64 ;;
  aarch64|arm64) architecture=arm64 ;;
  *) fail 'only amd64 and arm64 are supported' ;;
esac
if [ "$system" = darwin ] && [ "$architecture" = amd64 ]; then
  if [ "$(/usr/sbin/sysctl -in sysctl.proc_translated 2>/dev/null || :)" = 1 ]; then
    architecture=arm64
  fi
fi
if command -v sha256sum >/dev/null 2>&1; then
  checksum_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  checksum_tool=shasum
else
  fail 'sha256sum or shasum is required'
fi

base=https://github.com/antoniomika/lend/releases
download() {
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --retry 3 --connect-timeout 10 --max-time 120 "$@"
}
if [ "$version" = latest ]; then
  effective=$(download --output /dev/null --write-out '%{url_effective}' "$base/latest") || fail 'could not find a published release'
  case "$effective" in "$base/tag/"*) version=${effective##*/} ;; *) fail 'latest release did not resolve to a release tag' ;; esac
fi
printf '%s\n' "$version" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$' || fail 'version must be a release tag such as v0.1.0'
archive=lend_${version#v}_${system}_${architecture}.tar.gz
umask 077
workdir=$(mktemp -d "${TMPDIR:-/tmp}/lend-install.XXXXXXXX") || fail 'could not create a temporary directory'
staged=
cleanup() {
  [ -z "$staged" ] || rm -f "$staged"
  rm -rf "$workdir"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
download --output "$workdir/$archive" "$base/download/$version/$archive" || fail "could not download $archive"
download --output "$workdir/checksums.txt" "$base/download/$version/checksums.txt" || fail 'could not download checksums'
expected=$(awk -v name="$archive" '$2 == name && NF == 2 { digest = $1; count++ } END { if (count != 1) exit 1; print digest }' "$workdir/checksums.txt") || fail 'archive must have exactly one checksum entry'
printf '%s\n' "$expected" | LC_ALL=C grep -Eq '^[0-9a-f]{64}$' || fail 'invalid checksum entry'
if [ "$checksum_tool" = sha256sum ]; then
  actual=$(sha256sum "$workdir/$archive" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$workdir/$archive" | awk '{print $1}')
fi
[ "$actual" = "$expected" ] || fail 'checksum mismatch; existing installation was left unchanged'
tar -tzf "$workdir/$archive" > "$workdir/members" || fail 'could not inspect archive'
awk '$0 == "lend" { count++ } END { if (count != 1) exit 1 }' "$workdir/members" || fail 'archive must contain exactly one lend binary'
tar -xOzf "$workdir/$archive" lend > "$workdir/lend" || fail 'could not read the lend binary'
[ -s "$workdir/lend" ] || fail 'archive contains an empty binary'
mkdir -p "$destination" || fail "could not create $destination"
[ ! -d "$destination/lend" ] || fail 'destination lend is a directory'
staged=$(mktemp "$destination/.lend.XXXXXXXX") || fail 'could not stage the binary in the install directory'
cat "$workdir/lend" > "$staged"
chmod 755 "$staged"
mv -f "$staged" "$destination/lend"
staged=
printf 'Installed lend %s to %s/lend\n' "$version" "$destination"
case ":${PATH:-}:" in *":$destination:"*) ;; *) printf 'Add %s to PATH to run lend.\n' "$destination" ;; esac
