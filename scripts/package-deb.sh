#!/bin/sh
# Build a Debian package for piddigger. Derives the real glibc floor from the
# binary instead of claiming broader compatibility than was tested.
set -eu

binary=${1:-target/release/piddigger}
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)

case $(LC_ALL=C readelf -h "$binary" | sed -n 's/.*Machine: *//p') in
  *X86-64*) arch=amd64 ;;
  AArch64)  arch=arm64 ;;
  *) echo 'Unsupported ELF architecture' >&2; exit 1 ;;
esac

mkdir -p dist
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM

install -Dm755 "$binary" "$stage/usr/bin/piddigger"
install -Dm644 README.md "$stage/usr/share/doc/piddigger/README.md"
install -Dm644 docs/GUIDE.md "$stage/usr/share/doc/piddigger/GUIDE.md"
install -Dm644 LICENSE "$stage/usr/share/doc/piddigger/copyright"
install -Dm644 assets/piddigger_banner.png "$stage/usr/share/doc/piddigger/piddigger_banner.png" 2>/dev/null || true

# Minimal man page.
mkdir -p "$stage/usr/share/man/man1"
if [ -f docs/piddigger.1 ]; then
  gzip -9n < docs/piddigger.1 > "$stage/usr/share/man/man1/piddigger.1.gz"
fi

# Derive the actual glibc symbol floor.
glibc=$(objdump -T "$binary" 2>/dev/null | sed -n 's/.*GLIBC_\([0-9][0-9.]*\).*/\1/p' | sort -V | tail -n 1)
: "${glibc:=2.36}"

mkdir -p "$stage/DEBIAN"
cat > "$stage/DEBIAN/control" <<CONTROL
Package: piddigger
Version: $version
Homepage: https://thugs.red
Section: admin
Priority: optional
Architecture: $arch
Maintainer: THUGS(red) <maintainers@thugs.red>
Depends: libc6 (>= $glibc), libgcc-s1
Recommends: strace, gdb
Suggests: ltrace, linux-perf, bpftrace, tcpdump
Description: Live PID forensics TUI for blue teams
 piddigger is a read-only /proc investigator for a single running process.
 It captures identity, open files and deleted-but-open files, sockets,
 memory maps, namespaces, capabilities and seccomp, threads and environment,
 runs triage heuristics, and watches a live activity timeline.
 .
 Optional, opt-in live capture wraps strace, ltrace, perf, bpftrace, tcpdump,
 gdb and gcore. Every artifact is copied into a write-once evidence case with
 SHA-256 hashes and an append-only chain-of-custody log.
CONTROL

dpkg-deb --root-owner-group --build "$stage" "dist/piddigger_${version}_${arch}.deb"
echo "dist/piddigger_${version}_${arch}.deb  (libc6 >= $glibc)"
